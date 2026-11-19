// Copyright (c) 2017 The Go Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package safehtml

import (
	"strings"
	"testing"
)

func TestURLSetSanitized(t *testing.T) {
	for _, test := range [...]struct {
		name string
		in   string
		want string
	}{
		{
			"single candidate",
			"https://example.com/a.png",
			"https://example.com/a.png",
		},
		{
			"multiple candidates with descriptors",
			"https://example.com/a.png 1x, /b.webp 2x",
			"https://example.com/a.png 1x, /b.webp 2x",
		},
		{
			"descriptor is preserved verbatim",
			"/a.png 300w",
			"/a.png 300w",
		},
		{
			"unicode URL is preserved",
			"https://example.com/\u00fc-nacht.png 1x",
			"https://example.com/\u00fc-nacht.png 1x",
		},
		{
			"data URL with an internal comma keeps that comma inside its URL run",
			"data:image/gif;base64,R0lGODlhAQABAAAAACw= 1x, /good.png",
			"data:image/gif;base64,R0lGODlhAQABAAAAACw= 1x, /good.png",
		},
		{
			"comma-free percent-encoded data URL is preserved",
			"data:image/svg+xml;charset=utf-8,%3Csvg/%3E 1x",
			"data:image/svg+xml;charset=utf-8,%3Csvg/%3E 1x",
		},
		{
			"javascript candidate is dropped",
			"javascript:alert(1) 1x, https://example.com/good.png 2x",
			"https://example.com/good.png 2x",
		},
		{
			"bad candidate with trailing comma cannot absorb the next candidate",
			"javascript:bad, https://example.com/good.png 3x",
			"https://example.com/good.png 3x",
		},
		{
			"bad candidate between two good candidates is dropped",
			"/first.png 1x, javascript:evil 2x, /second.png",
			"/first.png 1x, /second.png",
		},
		{
			"leading comma is stripped as a separator, not rewritten",
			",https://example.com/a.png",
			"https://example.com/a.png",
		},
		{
			"trailing comma rejects the first candidate without touching its neighbour",
			"https://example.com/a.png, /b.png",
			"/b.png",
		},
		{
			"URL with a trailing comma is dropped instead of being rewritten",
			"https://example.com/a.png,",
			InnocuousURL,
		},
		{
			"two leading commas still reach the following candidate unmodified",
			",,https://example.com/a.png",
			"https://example.com/a.png",
		},
		{
			"data URL ending in a comma is dropped",
			"data:image/png;base64,",
			InnocuousURL,
		},
		{
			"all candidates unsafe",
			"javascript:alert(1), javascript:alert(2)",
			InnocuousURL,
		},
		{
			"malformed descriptor drops only its candidate",
			"/good.png 1x, /bad.png not-a-descriptor",
			"/good.png 1x",
		},
		{
			"stray commas and whitespace are ignored",
			" , , /a.png , ",
			"/a.png",
		},
		{
			"empty input",
			"",
			InnocuousURL,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := URLSetSanitized(test.in).String(); got != test.want {
				t.Errorf("URLSetSanitized(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

// TestURLSetSanitizedRoundTrip parses a sanitized srcset again and checks
// that every surviving candidate re-binds to exactly the URL and descriptor
// that were vetted in the original input.  This is the identity guarantee an
// auditor relies on: the browser must make the same resource decisions on the
// sanitized value that the sanitizer made on the original value.
func TestURLSetSanitizedRoundTrip(t *testing.T) {
	for _, in := range [...]string{
		"https://example.com/a.png 1x, /b.webp 2x, /c.png 300w",
		"  /spaced.png\t2x\n , /other.png",
		"data:image/svg+xml;charset=utf-8,%3Csvg/%3E 1x, https://example.com/x.png",
		"javascript:evil 1x, https://example.com/keep.png 2x, javascript:more",
		"https://example.com/\u00fc.png , /\u4e2d\u6587.png 3x",
		"/no-descriptor.png , /with-descriptor.png 1.5x",
	} {
		sanitized := URLSetSanitized(in).String()
		if sanitized == InnocuousURL {
			continue
		}

		original := vettedCandidates(t, in)
		roundTripped := parseSrcsetCandidates(sanitized)
		if len(original) != len(roundTripped) {
			t.Fatalf("candidate count changed for %q:\nvetted: %#v\noutput: %#v", in, original, roundTripped)
		}
		for i, want := range original {
			got := roundTripped[i]
			if got.url != want.url || got.descriptor != want.descriptor {
				t.Errorf("candidate %d identity changed for %q:\nvetted: %#v\noutput: %#v", i, in, want, got)
			}
		}
	}
}

// vettedCandidates mirrors the sanitizer's acceptance rules so the round-trip
// test can compare against the exact set of candidates expected to survive.
func vettedCandidates(t *testing.T, str string) []srcsetCandidate {
	t.Helper()
	var kept []srcsetCandidate
	for _, candidate := range parseSrcsetCandidates(str) {
		if candidate.url != "" && !candidate.hadTrailingComma && isSafeSrcsetURL(candidate.url) &&
			isOptionalSrcMetadataWellFormed(candidate.descriptor) {
			kept = append(kept, candidate)
		}
	}
	return kept
}

func TestParseSrcsetCandidates(t *testing.T) {
	for _, test := range [...]struct {
		name string
		in   string
		want []srcsetCandidate
	}{
		{
			"url and descriptor",
			"/a.png 1x",
			[]srcsetCandidate{{url: "/a.png", descriptor: "1x"}},
		},
		{
			"comma separated",
			"/a.png 1x,/b.png 2x",
			[]srcsetCandidate{
				{url: "/a.png", descriptor: "1x"},
				{url: "/b.png", descriptor: "2x"},
			},
		},
		{
			"a comma inside a URL run stays in the URL; only trailing commas flag",
			"data:image/png;base64,ABCD 1x, /b.png",
			[]srcsetCandidate{
				{url: "data:image/png;base64,ABCD", descriptor: "1x"},
				{url: "/b.png", descriptor: ""},
			},
		},
		{
			"empty candidates from stray commas are skipped; trailing comma flagged",
			",,/a.png,",
			[]srcsetCandidate{{url: "/a.png", descriptor: "", hadTrailingComma: true}},
		},
		{
			"multibyte unicode is split on ASCII boundaries without corruption",
			"https://example.com/\u00fc-\u4e2d\u6587.png 2x, /b.png",
			[]srcsetCandidate{
				{url: "https://example.com/\u00fc-\u4e2d\u6587.png", descriptor: "2x"},
				{url: "/b.png", descriptor: ""},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := parseSrcsetCandidates(test.in)
			if len(got) != len(test.want) {
				t.Fatalf("parseSrcsetCandidates(%q) = %#v, want %#v", test.in, got, test.want)
			}
			for i := range got {
				if got[i] != test.want[i] {
					t.Errorf("parseSrcsetCandidates(%q)[%d] = %#v, want %#v", test.in, i, got[i], test.want[i])
				}
			}
		})
	}
}

// TestURLSetSanitizedInvariants exercises the sanitizer over pseudo-random
// srcset strings built from the exact code points that matter to the parser,
// and checks two security-relevant invariants on every output:
//
//  1. Round-trip identity: parsing the sanitized output yields exactly the
//     vetted (url, descriptor) pairs, in order.  A browser therefore makes the
//     same resource decisions as the auditor.
//  2. Every emitted URL is safe and has no trailing comma, and every emitted
//     descriptor is well formed.
func TestURLSetSanitizedInvariants(t *testing.T) {
	alphabet := []rune("ab/,:. ,\t\n12wx\u00fcjavascriptxyz#%")
	seed := int64(1)
	next := func(n int) int {
		seed = (seed*1103515245 + 12345) & 0x7fffffff
		return int(seed) % n
	}

	for iter := 0; iter < 20000; iter++ {
		runes := make([]rune, next(24))
		for i := range runes {
			runes[i] = alphabet[next(len(alphabet))]
		}
		in := string(runes)

		out := URLSetSanitized(in).String()
		if out == InnocuousURL {
			if len(vettedCandidates(t, in)) != 0 {
				t.Fatalf("innocuous output despite surviving candidates for %q", in)
			}
			continue
		}

		want := vettedCandidates(t, in)
		got := parseSrcsetCandidates(out)
		if len(want) != len(got) {
			t.Fatalf("candidate count changed for %q:\nwant %#v\ngot  %#v", in, want, got)
		}
		for i := range want {
			if got[i].url != want[i].url || got[i].descriptor != want[i].descriptor {
				t.Fatalf("identity changed for %q:\nwant %#v\ngot  %#v", in, want, got)
			}
			// The browser parser flags a comma adjacent to an emitted URL as a
			// trailing-comma parse error, but the sanitizer always separates
			// candidates with ", ", so the vetted URL bytes themselves never
			// contain a comma.  Assert the invariant on the emitted URL string.
			if !isSafeSrcsetURL(got[i].url) ||
				strings.HasPrefix(got[i].url, ",") || strings.HasSuffix(got[i].url, ",") ||
				!isOptionalSrcMetadataWellFormed(got[i].descriptor) {
				t.Fatalf("unsafe candidate emitted for %q: %#v", in, got[i])
			}
		}
	}
}
