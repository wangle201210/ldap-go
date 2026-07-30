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

func (filter Filter) Match(entry Entry) (bool, error) {
	switch filter.Kind {
	case FilterAnd:
		for _, child := range filter.Children {
			matches, err := child.Match(entry)
			if err != nil || !matches {
				return matches, err
			}
		}
		return true, nil

	case FilterOr:
		for _, child := range filter.Children {
			matches, err := child.Match(entry)
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
		matches, err := filter.Children[0].Match(entry)
		return !matches, err

	case FilterPresent:
		return entry.HasAttribute(filter.Attribute), nil

	case FilterEquality, FilterApprox, FilterGreaterOrEqual, FilterLessOrEqual:
		values := entry.Values(filter.Attribute)
		for _, value := range values {
			comparison := compareDirectoryValue(value, filter.Assertion)
			switch filter.Kind {
			case FilterEquality, FilterApprox:
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
		for _, value := range entry.Values(filter.Attribute) {
			if matchSubstring(value, filter.Substring) {
				return true, nil
			}
		}
		return false, nil

	case FilterExtensible:
		if filter.MatchingRule != "" {
			return false, fmt.Errorf("matching rule %q is not registered", filter.MatchingRule)
		}
		if filter.Attribute != "" {
			for _, value := range entry.Values(filter.Attribute) {
				if compareDirectoryValue(value, filter.Assertion) == 0 {
					return true, nil
				}
			}
			return false, nil
		}
		for _, attribute := range entry.Attributes {
			for _, value := range attribute.Values {
				if compareDirectoryValue(value, filter.Assertion) == 0 {
					return true, nil
				}
			}
		}
		return false, nil

	default:
		return false, fmt.Errorf("unknown filter kind %d", filter.Kind)
	}
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
