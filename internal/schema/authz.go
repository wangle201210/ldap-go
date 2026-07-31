package schema

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
)

func validateAuthzSyntax(value []byte) error {
	if len(value) == 0 || !utf8.Valid(value) {
		return errors.New("value is not a valid OpenLDAP authz rule")
	}
	rule, err := authzRuleWithoutOrder(string(value))
	if err != nil || rule == "" {
		return errors.New("value is not a valid OpenLDAP authz rule")
	}
	lower := strings.ToLower(rule)

	for _, prefix := range []string{
		"dn:",
		"dn.exact:",
		"dn.onelevel:",
		"dn.children:",
		"dn.subtree:",
	} {
		if !strings.HasPrefix(lower, prefix) {
			continue
		}
		pattern := strings.TrimLeft(rule[len(prefix):], " ")
		if pattern == "*" {
			return nil
		}
		if _, err := directory.ParseDN(pattern); err != nil {
			return errors.New("value has an invalid authorization DN")
		}
		return nil
	}
	if strings.HasPrefix(lower, "dn.regex:") {
		return nil
	}
	if rule == "*" {
		return nil
	}

	if strings.HasPrefix(lower, "u:") ||
		strings.HasPrefix(lower, "u.") {
		return validateAuthzUserRule(rule)
	}
	if strings.HasPrefix(lower, "group") {
		return validateAuthzGroupRule(rule)
	}
	if strings.HasPrefix(lower, "ldap:") {
		return validateAuthzLDAPURL(rule)
	}
	if _, err := directory.ParseDN(rule); err != nil {
		return errors.New("value is not an authorization DN")
	}
	return nil
}

func authzRuleWithoutOrder(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{") {
		return value, nil
	}
	end := strings.IndexByte(value, '}')
	if end < 2 {
		return "", errors.New("invalid ordered value prefix")
	}
	order, err := strconv.Atoi(value[1:end])
	if err != nil || order < 0 {
		return "", errors.New("invalid ordered value prefix")
	}
	return strings.TrimSpace(value[end+1:]), nil
}

func validateAuthzUserRule(rule string) error {
	separator := strings.IndexByte(rule, ':')
	if separator < 1 {
		return errors.New("authorization user rule has no identity")
	}
	qualifier := rule[:separator]
	if len(qualifier) == 1 {
		return nil
	}
	if qualifier[1] != '.' {
		return errors.New("authorization user rule has an invalid qualifier")
	}
	mechanism := qualifier[2:]
	if slash := strings.IndexByte(mechanism, '/'); slash >= 0 {
		if strings.Contains(mechanism[slash+1:], "/") {
			return errors.New("authorization user rule has too many qualifiers")
		}
		mechanism = mechanism[:slash]
	}
	if mechanism == "" {
		return errors.New("authorization user rule has no mechanism")
	}
	return nil
}

func validateAuthzGroupRule(rule string) error {
	separator := strings.IndexByte(rule, ':')
	if separator < 0 {
		return errors.New("authorization group rule has no DN")
	}
	selector := strings.Split(rule[:separator], "/")
	if !strings.EqualFold(selector[0], "group") ||
		len(selector) > 3 {
		return errors.New("authorization group rule has an invalid selector")
	}
	for _, component := range selector[1:] {
		if component == "" {
			return errors.New("authorization group rule has an empty selector")
		}
	}
	if _, err := directory.ParseDN(rule[separator+1:]); err != nil {
		return errors.New("authorization group rule has an invalid DN")
	}
	return nil
}

func validateAuthzLDAPURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil ||
		!strings.EqualFold(parsed.Scheme, "ldap") ||
		parsed.Host != "" ||
		parsed.User != nil ||
		parsed.Fragment != "" {
		return errors.New("authorization URL is not local")
	}
	baseText, err := url.PathUnescape(
		strings.TrimPrefix(parsed.EscapedPath(), "/"),
	)
	if err != nil {
		return errors.New("authorization URL has an invalid base")
	}
	if _, err := directory.ParseDN(baseText); err != nil {
		return errors.New("authorization URL has an invalid base")
	}

	components := strings.Split(parsed.RawQuery, "?")
	if len(components) > 4 {
		return errors.New("authorization URL has too many components")
	}
	for len(components) < 4 {
		components = append(components, "")
	}
	if components[0] != "" || components[3] != "" {
		return errors.New(
			"authorization URL attributes and extensions must be absent",
		)
	}
	scope, err := url.PathUnescape(components[1])
	if err != nil {
		return errors.New("authorization URL has an invalid scope")
	}
	switch strings.ToLower(scope) {
	case "", "base", "one", "sub", "children":
	default:
		return fmt.Errorf("authorization URL has unknown scope %q", scope)
	}
	filter, err := url.PathUnescape(components[2])
	if err != nil {
		return errors.New("authorization URL has an invalid filter")
	}
	if filter != "" {
		if _, err := ldap.CompileFilter(filter); err != nil {
			return errors.New("authorization URL has an invalid filter")
		}
	}
	return nil
}
