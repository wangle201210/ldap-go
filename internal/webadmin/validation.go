package webadmin

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"
)

const (
	maximumAttributeLength    = 256
	maximumValuesPerAttribute = 4096
	maximumPageCookieBytes    = 4096
)

var (
	attributeDescriptorPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)
	attributeOIDPattern        = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)+$`)
)

type entryResponse struct {
	DN               string              `json:"dn"`
	Attributes       map[string][]string `json:"attributes"`
	BinaryAttributes map[string][]string `json:"binary_attributes,omitempty"`
}

func validateDN(value string, allowEmpty bool) error {
	if value == "" && allowEmpty {
		return nil
	}
	if value == "" {
		return errors.New("DN is required")
	}
	if _, err := ldap.ParseDN(value); err != nil {
		return fmt.Errorf("invalid DN: %w", err)
	}
	return nil
}

func validateRDN(value string) error {
	if value == "" {
		return errors.New("new_rdn is required")
	}
	parsed, err := ldap.ParseDN(value)
	if err != nil || len(parsed.RDNs) != 1 {
		return errors.New("new_rdn must contain exactly one valid RDN")
	}
	return nil
}

func validateAttribute(value string, allowSelectors bool) error {
	if allowSelectors && (value == "*" || value == "+" || value == "1.1") {
		return nil
	}
	if value == "" || len(value) > maximumAttributeLength {
		return fmt.Errorf("invalid attribute description %q", value)
	}
	parts := strings.Split(value, ";")
	if !attributeDescriptorPattern.MatchString(parts[0]) && !attributeOIDPattern.MatchString(parts[0]) {
		return fmt.Errorf("invalid attribute description %q", value)
	}
	for _, option := range parts[1:] {
		if option == "" || !attributeDescriptorPattern.MatchString(option) {
			return fmt.Errorf("invalid attribute option in %q", value)
		}
	}
	return nil
}

func validateAttributes(attributes []string, maximum int, allowSelectors bool) error {
	if len(attributes) > maximum {
		return fmt.Errorf("at most %d attributes may be requested", maximum)
	}
	seen := make(map[string]struct{}, len(attributes))
	for _, attribute := range attributes {
		if err := validateAttribute(attribute, allowSelectors); err != nil {
			return err
		}
		key := strings.ToLower(attribute)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate attribute %q", attribute)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateAttributeMap(attributes map[string][]string, maximum int) error {
	if len(attributes) == 0 {
		return errors.New("at least one attribute is required")
	}
	if len(attributes) > maximum {
		return fmt.Errorf("at most %d attributes are allowed", maximum)
	}
	for attribute, values := range attributes {
		if err := validateAttribute(attribute, false); err != nil {
			return err
		}
		if len(values) == 0 {
			return fmt.Errorf("attribute %q requires at least one value", attribute)
		}
		if len(values) > maximumValuesPerAttribute {
			return fmt.Errorf("attribute %q has too many values", attribute)
		}
	}
	return nil
}

func validateFilter(filter string, config normalizedConfig) error {
	if filter == "" {
		return errors.New("filter is required")
	}
	if len(filter) > config.MaxFilterLength {
		return fmt.Errorf("filter exceeds %d bytes", config.MaxFilterLength)
	}
	depth := 0
	nodes := 0
	for _, character := range filter {
		switch character {
		case '(':
			depth++
			nodes++
			if depth > config.MaxFilterDepth {
				return fmt.Errorf("filter exceeds maximum depth %d", config.MaxFilterDepth)
			}
			if nodes > config.MaxFilterDepth*8 {
				return errors.New("filter contains too many components")
			}
		case ')':
			depth--
			if depth < 0 {
				return errors.New("invalid filter parentheses")
			}
		}
	}
	if depth != 0 {
		return errors.New("invalid filter parentheses")
	}
	if _, err := ldap.CompileFilter(filter); err != nil {
		return fmt.Errorf("invalid LDAP filter: %w", err)
	}
	return nil
}

func decodePageCookie(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	cookie, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, errors.New("invalid page_cookie")
	}
	if len(cookie) > maximumPageCookieBytes {
		return nil, errors.New("page_cookie is too large")
	}
	return cookie, nil
}

func encodePageCookie(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func convertEntry(entry *ldap.Entry) entryResponse {
	converted := entryResponse{
		DN: entry.DN, Attributes: make(map[string][]string, len(entry.Attributes)),
	}
	for _, attribute := range entry.Attributes {
		if attribute == nil {
			continue
		}
		for _, raw := range attribute.ByteValues {
			if utf8.Valid(raw) && !containsZero(raw) {
				converted.Attributes[attribute.Name] = append(
					converted.Attributes[attribute.Name], string(raw),
				)
				continue
			}
			if converted.BinaryAttributes == nil {
				converted.BinaryAttributes = make(map[string][]string)
			}
			converted.BinaryAttributes[attribute.Name] = append(
				converted.BinaryAttributes[attribute.Name],
				base64.StdEncoding.EncodeToString(raw),
			)
		}
		if len(attribute.ByteValues) == 0 {
			converted.Attributes[attribute.Name] = append(
				converted.Attributes[attribute.Name], attribute.Values...,
			)
		}
	}
	return converted
}

func containsZero(value []byte) bool {
	for _, current := range value {
		if current == 0 {
			return true
		}
	}
	return false
}
