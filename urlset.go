// Copyright (c) 2017 The Go Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package safehtml

import (
	"bytes"
	"strconv"
)

// https://infra.spec.whatwg.org/#ascii-whitespace
// ASCII whitespace is U+0009 TAB, U+000A LF, U+000C FF, U+000D CR, or U+0020 SPACE.
var asciiWhitespace [256]bool

// srcsetSeparators are the code points that separate image candidate strings
// while splitting a srcset attribute: ASCII whitespace and U+002C COMMA.
//
// https://html.spec.whatwg.org/multipage/images.html#parsing-a-srcset-attribute
var srcsetSeparators [256]bool

func init() {
	asciiWhitespace['\t'] = true
	asciiWhitespace[' '] = true
	asciiWhitespace['\n'] = true
	asciiWhitespace['\f'] = true
	asciiWhitespace['\r'] = true

	srcsetSeparators = asciiWhitespace
	srcsetSeparators[','] = true
}

// URLSetSanitized returns a safe srcset by individually vetting each
// substring that specifies a URL.
//
// https://html.spec.whatwg.org/multipage/images.html#srcset-attributes
func URLSetSanitized(str string) URLSet {
	var buffer bytes.Buffer

	// Parse the input into image candidates exactly as a browser would, then
	// independently vet each candidate.  A candidate is only emitted verbatim,
	// so re-parsing the sanitized value binds each surviving URL to the same
	// URL and descriptor that were vetted: vetted URLs are never rewritten and
	// a rejected candidate can never alter an adjacent candidate.
	for _, candidate := range parseSrcsetCandidates(str) {
		if candidate.url == "" || candidate.hadTrailingComma || !isSafeSrcsetURL(candidate.url) ||
			!isOptionalSrcMetadataWellFormed(candidate.descriptor) {
			continue
		}
		if buffer.Len() != 0 {
			// The space after the comma is required so that the comma is not
			// mistaken for part of the preceding URL.  The space before it is
			// harmless ASCII whitespace within the previous descriptor.
			buffer.WriteString(", ")
		}
		buffer.WriteString(candidate.url)
		if candidate.descriptor != "" {
			buffer.WriteByte(' ')
			buffer.WriteString(candidate.descriptor)
		}
	}

	if buffer.Len() == 0 {
		return URLSet{InnocuousURL}
	}

	return URLSet{buffer.String()}
}

// srcsetCandidate is one image candidate string: a URL and an optional
// descriptor, both captured verbatim from the input so that emitting them
// preserves the exact identity vetted here.
//
// https://html.spec.whatwg.org/multipage/images.html#srcset-attributes
type srcsetCandidate struct {
	url string
	// descriptor is the optional image candidate descriptor, captured
	// verbatim so re-parsing the output binds it to the same URL.
	descriptor string
	// hadTrailingComma reports that the URL run ended in one or more commas,
	// which a browser would strip.  Such a candidate cannot be emitted
	// verbatim and is rejected to preserve round-trip identity.
	hadTrailingComma bool
}

// parseSrcsetCandidates splits a srcset attribute value into image candidate
// strings following
// https://html.spec.whatwg.org/multipage/images.html#parsing-a-srcset-attribute.
// Candidates are delimited by ASCII whitespace and U+002C COMMA characters, so
// a comma can never separate a URL from its descriptor: any comma attached to
// a URL is a trailing part of that URL.
func parseSrcsetCandidates(str string) []srcsetCandidate {
	var candidates []srcsetCandidate
	pos := 0
	for pos < len(str) {
		// Splitting loop: consume the ASCII whitespace and commas separating
		// candidates.
		for pos < len(str) && srcsetSeparators[str[pos]] {
			pos++
		}
		if pos == len(str) {
			break
		}

		// The URL is the maximal run of non-whitespace code points.  Any
		// commas it contains are part of the URL run, not candidate
		// separators; only commas at the very end of the run are trailing.
		urlStart := pos
		for pos < len(str) && !asciiWhitespace[str[pos]] {
			pos++
		}
		rawURL := str[urlStart:pos]
		url := rawURL
		hadTrailingComma := false
		for len(url) != 0 && url[len(url)-1] == ',' {
			url = url[:len(url)-1]
			hadTrailingComma = true
		}

		var descriptor string
		if !hadTrailingComma {
			// Skip the whitespace following the URL, then take the first
			// descriptor token up to the separating comma.
			for pos < len(str) && asciiWhitespace[str[pos]] {
				pos++
			}
			if pos < len(str) && str[pos] != ',' {
				descStart := pos
				for pos < len(str) && !asciiWhitespace[str[pos]] && str[pos] != ',' {
					pos++
				}
				descriptor = str[descStart:pos]
			}
			// Skip any remaining descriptor tokens and whitespace up to the
			// separating comma; the next splitting iteration consumes it.
			for pos < len(str) && str[pos] != ',' {
				pos++
			}
		}
		// When hadTrailingComma is true, pos already points at the first
		// trailing comma, which the next splitting iteration will consume.

		candidates = append(candidates, srcsetCandidate{
			url:              url,
			descriptor:       descriptor,
			hadTrailingComma: hadTrailingComma,
		})
	}
	return candidates
}

// isSafeSrcsetURL reports whether url is a safe image-candidate URL.  The
// srcset-specific comma rules are handled by parseSrcsetCandidates: leading
// commas are candidate separators and never reach the URL, while a URL with
// trailing commas is flagged via hadTrailingComma and rejected.  Here only the
// generic safe-URL policy applies.
func isSafeSrcsetURL(url string) bool {
	return isSafeURL(url)
}

// isOptionalSrcMetadataWellFormed is true when its input is empty and
// when it is a floating point number optionally followed by an ASCII letter.
func isOptionalSrcMetadataWellFormed(metadata string) bool {
	// srcset for both image candidates (<img srcset>) and
	// the proposal for script allow a number and an optional letter
	// afterwards.
	n := len(metadata)
	if n == 0 {
		// Metadata is optional
		return true
	}
	metadataPrefix := metadata
	if last := metadata[n-1] | 32; 'a' <= last && last <= 'z' {
		metadataPrefix = metadata[0 : n-1]
	}
	// This overmatches
	// html.spec.whatwg.org/multipage/common-microsyntaxes.html#valid-floating-point-number
	// but is sufficient.
	_, err := strconv.ParseFloat(metadataPrefix, 64)
	return err == nil
}

// URLSet corresponds to the value of a srcset attribute outside a
// TrustedResourceURL context.
type URLSet struct {
	// We declare a URLSet not as a string but as a struct wrapping a string
	// to prevent construction of URL values through string conversion.
	str string
}

// String returns the string content of a URLSet
func (s URLSet) String() string {
	return s.str
}
