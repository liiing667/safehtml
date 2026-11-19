// Copyright 2024 The Go Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package template

import "strings"

// validFormMethods contains the submission methods allowed by the form
// submission policy (see
// https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#attr-fs-method).
var validFormMethods = map[string]bool{
	"get":  true,
	"post": true,
}

// validFormTargets contains the browsing-context names allowed by the form
// submission policy. The only named targets allowed are the safe keywords
// "_blank" and "_self"; arbitrary named targets are rejected so that a
// submission cannot be redirected to an attacker-controlled frame.
var validFormTargets = map[string]bool{
	"_blank": true,
	"_self":  true,
}

// normalizeFormMethod normalizes an HTML form method value. Empty values and
// the missing-value default resolve to "get", matching browser behavior.
func normalizeFormMethod(value string) string {
	method := strings.ToLower(strings.TrimSpace(value))
	if method == "" {
		return "get"
	}
	return method
}

// captureFormSubmissionPolicy inspects the attribute that has just finished
// parsing in context c and returns an updated context whose form submission
// policy fields reflect the attribute. It enforces that:
//
//   - the form's own "method" and "target" attributes only use values the
//     submission policy permits,
//   - "button" and "input" elements cannot use "formmethod", "formtarget",
//     "formaction" or "formenctype" to override the enclosing form's
//     submission policy, and
//   - any policy that cannot be statically determined because a value comes
//     from an action or context joining fails closed.
func captureFormSubmissionPolicy(c context, rawValue string) context {
	attrValue := strings.TrimSpace(rawValue)
	switch c.element.name {
	case "form":
		switch c.attr.name {
		case "method":
			if c.ambiguousFormPolicy || c.attrHasAction || c.attr.ambiguousValue {
				// The actual value is constrained by the FormMethodEnum sanitizer at
				// execution time, but the policy is not statically known, so any
				// override cannot be validated and must fail closed.
				c.inForm = true
				c.ambiguousFormPolicy = true
				return c
			}
			method := normalizeFormMethod(attrValue)
			if !validFormMethods[method] {
				return formPolicyError(c, `the "method" attribute of a "form" element must be one of "get" or "post", but got %q`, attrValue)
			}
			c.inForm = true
			c.formMethod = method
			return c
		case "target":
			if c.ambiguousFormPolicy || c.attrHasAction || c.attr.ambiguousValue {
				// The actual value is constrained by the TargetEnum sanitizer at
				// execution time, but the policy is not statically known, so any
				// override cannot be validated and must fail closed.
				c.inForm = true
				c.ambiguousFormPolicy = true
				return c
			}
			if !validFormTargets[attrValue] {
				return formPolicyError(c, `the "target" attribute of a "form" element must be one of "_blank" or "_self", but got %q`, attrValue)
			}
			c.inForm = true
			c.formTarget = attrValue
			return c
		case "enctype":
			if c.attrHasAction || c.attr.ambiguousValue || c.ambiguousFormEncoding {
				// The runtime FormEncodingEnum sanitizer constrains the value; the
				// encoding is not part of the method/target conflict policy.
				return c
			}
			if !sanitizeFormEncodingEnumValues[strings.ToLower(attrValue)] {
				return formPolicyError(c, `the "enctype" attribute of a "form" element must be one of "application/x-www-form-urlencoded", "multipart/form-data" or "text/plain", but got %q`, attrValue)
			}
		}
	case "button", "input":
		if !c.inForm {
			return c
		}
		switch c.attr.name {
		case "formmethod":
			if c.ambiguousFormPolicy {
				return formPolicyError(c, `the "formmethod" attribute of a %q element cannot be validated against the enclosing "form" element because its submission policy is not statically known`, c.element.name)
			}
			if c.attrHasAction {
				return formPolicyError(c, `actions must not determine the "formmethod" attribute of a %q element; use a constant value matching the "method" attribute of the enclosing "form" element`, c.element.name)
			}
			method := normalizeFormMethod(attrValue)
			if !validFormMethods[method] {
				return formPolicyError(c, `the "formmethod" attribute of a %q element must be one of "get" or "post", but got %q`, c.element.name, attrValue)
			}
			if method != c.formMethod {
				return formPolicyError(c, `the "formmethod" attribute of a %q element is %q, which conflicts with the enclosing form's method %q; form submission overrides must not change the submission method`, c.element.name, method, c.formMethod)
			}
		case "formtarget":
			if c.ambiguousFormPolicy {
				return formPolicyError(c, `the "formtarget" attribute of a %q element cannot be validated against the enclosing "form" element because its submission policy is not statically known`, c.element.name)
			}
			if c.attrHasAction {
				return formPolicyError(c, `actions must not determine the "formtarget" attribute of a %q element; use a constant value matching the "target" attribute of the enclosing "form" element`, c.element.name)
			}
			if !validFormTargets[attrValue] {
				return formPolicyError(c, `the "formtarget" attribute of a %q element must be one of "_blank" or "_self", but got %q`, c.element.name, attrValue)
			}
			if c.formTarget != "" && attrValue != c.formTarget {
				return formPolicyError(c, `the "formtarget" attribute of a %q element is %q, which conflicts with the enclosing form's target %q; form submission overrides must not change the submission target`, c.element.name, attrValue, c.formTarget)
			}
		case "formaction", "formenctype":
			if c.ambiguousFormPolicy {
				return formPolicyError(c, `the %q attribute of a %q element cannot be validated against the enclosing "form" element because its submission policy is not statically known`, c.attr.name, c.element.name)
			}
			if c.attrHasAction {
				return formPolicyError(c, `actions must not determine the %q attribute of a %q element; form submission overrides must keep the enclosing form's submission policy`, c.attr.name, c.element.name)
			}
			if attrValue != "" {
				return formPolicyError(c, `the %q attribute of a %q element overrides the enclosing form's submission policy; remove it and let the form's own attributes determine the request`, c.attr.name, c.element.name)
			}
		}
	}
	return c
}

// formPolicyError returns an error context carrying a form submission policy
// violation described by format and its arguments.
func formPolicyError(c context, format string, args ...interface{}) context {
	return context{
		state: stateError,
		err:   errorf(ErrBadHTML, nil, 0, format, args...),
	}
}
