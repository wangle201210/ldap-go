package directory

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"
)

type FilterKind uint8

const (
	FilterAnd FilterKind = iota
	FilterOr
	FilterNot
	FilterEquality
	FilterSubstrings
	FilterGreaterOrEqual
	FilterLessOrEqual
	FilterPresent
	FilterApprox
	FilterExtensible
	FilterComputed
)

type Substring struct {
	Initial []byte
	Any     [][]byte
	Final   []byte
}

type Filter struct {
	Kind         FilterKind
	Children     []Filter
	Attribute    string
	Assertion    []byte
	Substring    Substring
	MatchingRule string
	DNAttributes bool
}

type ValueMatcher interface {
	Compare(attribute, matchingRule string, left, right []byte) (int, error)
	MatchSubstring(attribute string, value []byte, substring Substring) (bool, error)
}

// ApproximateMatcher lets schema-aware matchers provide the approximate rule
// associated with an attribute's equality rule. Matchers without this optional
// interface retain the LDAP equality fallback used when no approximate rule is
// associated with an attribute type.
type ApproximateMatcher interface {
	MatchApproximate(attribute string, value, assertion []byte) (bool, error)
}

type AttributeResolver interface {
	AttributeValues(entry Entry, description string) [][]byte
	HasAttributeDescription(entry Entry, description string) bool
}

func (filter Filter) Match(entry Entry) (bool, error) {
	return filter.MatchWith(entry, BasicMatcher{})
}

func (filter Filter) MatchWith(entry Entry, matcher ValueMatcher) (bool, error) {
	switch filter.Kind {
	case FilterAnd:
		for _, child := range filter.Children {
			matches, err := child.MatchWith(entry, matcher)
			if err != nil || !matches {
				return matches, err
			}
		}
		return true, nil

	case FilterOr:
		for _, child := range filter.Children {
			matches, err := child.MatchWith(entry, matcher)
			if err != nil {
				return false, err
			}
			if matches {
				return true, nil
			}
		}
		return false, nil

	case FilterNot:
		if len(filter.Children) != 1 {
			return false, fmt.Errorf("not filter requires exactly one child")
		}
		matches, err := filter.Children[0].MatchWith(entry, matcher)
		return !matches, err

	case FilterPresent:
		return resolvedHasAttribute(matcher, entry, filter.Attribute), nil

	case FilterApprox:
		values := resolvedAttributeValues(matcher, entry, filter.Attribute)
		approximate, hasApproximateMatcher := matcher.(ApproximateMatcher)
		for _, value := range values {
			if hasApproximateMatcher {
				matches, err := approximate.MatchApproximate(
					filter.Attribute,
					value,
					filter.Assertion,
				)
				if err != nil {
					return false, err
				}
				if matches {
					return true, nil
				}
				continue
			}
			comparison, err := matcher.Compare(filter.Attribute, "", value, filter.Assertion)
			if err != nil {
				return false, err
			}
			if comparison == 0 {
				return true, nil
			}
		}
		return false, nil

	case FilterEquality, FilterGreaterOrEqual, FilterLessOrEqual:
		values := resolvedAttributeValues(matcher, entry, filter.Attribute)
		for _, value := range values {
			comparison, err := matcher.Compare(filter.Attribute, "", value, filter.Assertion)
			if err != nil {
				return false, err
			}
			switch filter.Kind {
			case FilterEquality:
				if comparison == 0 {
					return true, nil
				}
			case FilterGreaterOrEqual:
				if comparison >= 0 {
					return true, nil
				}
			case FilterLessOrEqual:
				if comparison <= 0 {
					return true, nil
				}
			}
		}
		return false, nil

	case FilterSubstrings:
		for _, value := range resolvedAttributeValues(matcher, entry, filter.Attribute) {
			matches, err := matcher.MatchSubstring(filter.Attribute, value, filter.Substring)
			if err != nil {
				return false, err
			}
			if matches {
				return true, nil
			}
		}
		return false, nil

	case FilterExtensible:
		if filter.Attribute != "" {
			for _, value := range resolvedAttributeValues(matcher, entry, filter.Attribute) {
				comparison, err := matcher.Compare(
					filter.Attribute,
					filter.MatchingRule,
					value,
					filter.Assertion,
				)
				if err != nil {
					return false, err
				}
				if comparison == 0 {
					return true, nil
				}
			}
			return false, nil
		}
		for _, attribute := range entry.Attributes {
			for _, value := range attribute.Values {
				comparison, err := matcher.Compare(
					attribute.Description,
					filter.MatchingRule,
					value,
					filter.Assertion,
				)
				if err != nil {
					continue
				}
				if comparison == 0 {
					return true, nil
				}
			}
		}
		return false, nil

	default:
		return false, fmt.Errorf("unknown filter kind %d", filter.Kind)
	}
}

func resolvedAttributeValues(
	matcher ValueMatcher,
	entry Entry,
	description string,
) [][]byte {
	if resolver, ok := matcher.(AttributeResolver); ok {
		return resolver.AttributeValues(entry, description)
	}
	return entry.Values(description)
}

func resolvedHasAttribute(
	matcher ValueMatcher,
	entry Entry,
	description string,
) bool {
	if resolver, ok := matcher.(AttributeResolver); ok {
		return resolver.HasAttributeDescription(entry, description)
	}
	return entry.HasAttribute(description)
}

type BasicMatcher struct{}

func (BasicMatcher) Compare(_, matchingRule string, left, right []byte) (int, error) {
	if matchingRule != "" {
		return 0, fmt.Errorf("matching rule %q is not registered", matchingRule)
	}
	return compareDirectoryValue(left, right), nil
}

func (BasicMatcher) MatchSubstring(_ string, value []byte, substring Substring) (bool, error) {
	return matchSubstring(value, substring), nil
}

func compareDirectoryValue(left, right []byte) int {
	return bytes.Compare(normalizeDirectoryValue(left), normalizeDirectoryValue(right))
}

func normalizeDirectoryValue(value []byte) []byte {
	fields := strings.FieldsFunc(string(value), unicode.IsSpace)
	return []byte(strings.ToLower(strings.Join(fields, " ")))
}

func matchSubstring(value []byte, substring Substring) bool {
	candidate := normalizeDirectoryValue(value)
	initial := normalizeDirectoryValue(substring.Initial)
	final := normalizeDirectoryValue(substring.Final)

	position := 0
	if substring.Initial != nil {
		if !bytes.HasPrefix(candidate, initial) {
			return false
		}
		position = len(initial)
	}

	for _, part := range substring.Any {
		normalized := normalizeDirectoryValue(part)
		index := bytes.Index(candidate[position:], normalized)
		if index < 0 {
			return false
		}
		position += index + len(normalized)
	}

	if substring.Final != nil {
		return bytes.HasSuffix(candidate[position:], final)
	}
	return true
}
