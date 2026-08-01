package server

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
)

type valueSortKind uint8

const (
	valueSortNone valueSortKind = iota
	valueSortAlpha
	valueSortNumeric
)

type valueSortRule struct {
	attribute  string
	base       directory.DN
	kind       valueSortKind
	descending bool
	weighted   bool
	ignored    bool
}

type valueSortRuntimeConfiguration struct {
	rules []valueSortRule
}

func loadValueSortRuntimeConfiguration(
	entry directory.Entry,
) (valueSortRuntimeConfiguration, error) {
	values := entry.Values("olcValSortAttr")
	if len(values) == 0 {
		return valueSortRuntimeConfiguration{}, fmt.Errorf(
			"%s olcValSortAttr is required",
			entry.DN,
		)
	}
	configuration := valueSortRuntimeConfiguration{
		rules: make([]valueSortRule, 0, len(values)),
	}
	for _, raw := range values {
		value, err := stripValueSortOrderingPrefix(string(raw))
		if err != nil {
			return valueSortRuntimeConfiguration{}, fmt.Errorf(
				"%s olcValSortAttr: %w",
				entry.DN,
				err,
			)
		}
		arguments, err := tokenizeOpenLDAPConfig(value)
		if err != nil {
			return valueSortRuntimeConfiguration{}, fmt.Errorf(
				"%s olcValSortAttr: %w",
				entry.DN,
				err,
			)
		}
		if len(arguments) < 3 || len(arguments) > 4 {
			return valueSortRuntimeConfiguration{}, fmt.Errorf(
				"%s olcValSortAttr must contain attribute, DN, and sort type",
				entry.DN,
			)
		}
		base, err := directory.ParseDN(arguments[1])
		if err != nil {
			return valueSortRuntimeConfiguration{}, fmt.Errorf(
				"%s olcValSortAttr unable to normalize DN %q: %w",
				entry.DN,
				arguments[1],
				err,
			)
		}
		rule := valueSortRule{attribute: arguments[0], base: base}
		if err := applyValueSortMode(&rule, arguments[2], true); err != nil {
			return valueSortRuntimeConfiguration{}, fmt.Errorf(
				"%s olcValSortAttr: %w",
				entry.DN,
				err,
			)
		}
		if rule.weighted && len(arguments) == 4 {
			if err := applyValueSortMode(&rule, arguments[3], false); err != nil {
				return valueSortRuntimeConfiguration{}, fmt.Errorf(
					"%s olcValSortAttr: %w",
					entry.DN,
					err,
				)
			}
		}
		configuration.rules = append(configuration.rules, rule)
	}
	return configuration, nil
}

func applyValueSortMode(rule *valueSortRule, value string, primary bool) error {
	switch strings.ToLower(value) {
	case "alpha-ascend":
		rule.kind = valueSortAlpha
		rule.descending = false
	case "alpha-descend":
		rule.kind = valueSortAlpha
		rule.descending = true
	case "numeric-ascend":
		rule.kind = valueSortNumeric
		rule.descending = false
	case "numeric-descend":
		rule.kind = valueSortNumeric
		rule.descending = true
	case "weighted":
		rule.weighted = true
		if primary {
			rule.kind = valueSortNone
			rule.descending = false
		}
	default:
		return fmt.Errorf("unrecognized sort type %q", value)
	}
	return nil
}

func stripValueSortOrderingPrefix(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{") {
		return value, nil
	}
	end := strings.IndexByte(value, '}')
	if end < 2 {
		return "", errors.New("invalid ordered valsort prefix")
	}
	order, err := strconv.Atoi(value[1:end])
	if err != nil || order < 0 {
		return "", fmt.Errorf(
			"invalid ordered valsort prefix %q",
			value[:end+1],
		)
	}
	return strings.TrimSpace(value[end+1:]), nil
}

func validateValueSortSchema(
	registry *schema.Registry,
	configuration *valueSortRuntimeConfiguration,
) error {
	if configuration == nil {
		return nil
	}
	for index := range configuration.rules {
		rule := &configuration.rules[index]
		if err := validateConstraintAttributeDescription(rule.attribute); err != nil {
			return fmt.Errorf("olcValSortAttr: %w", err)
		}
		attribute, found, err := registry.EffectiveAttributeType(rule.attribute)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf(
				"olcValSortAttr references undefined attribute type %q",
				rule.attribute,
			)
		}
		if attribute.SingleValue {
			rule.ignored = true
			continue
		}
		if rule.kind == valueSortNumeric &&
			attribute.Syntax != schema.SyntaxNumericString &&
			attribute.Syntax != schema.SyntaxInteger {
			return fmt.Errorf(
				"numeric sort specified for non-numeric attribute %q",
				rule.attribute,
			)
		}
	}
	return nil
}

func valueSortRulesForDatabase(
	databases []runtimeDatabase,
	database runtimeDatabase,
) []valueSortRule {
	var rules []valueSortRule
	for index := range databases {
		candidate := &databases[index]
		if databaseType(candidate.name) != "frontend" || candidate.valueSort == nil {
			continue
		}
		rules = append(rules, candidate.valueSort.rules...)
	}
	if databaseType(database.name) != "frontend" && database.valueSort != nil {
		rules = append(rules, database.valueSort.rules...)
	}
	return rules
}

func runtimeSupportsValueSort(databases []runtimeDatabase) bool {
	for index := range databases {
		if databases[index].valueSort != nil {
			return true
		}
	}
	return false
}

func valueSortEnabledForDatabase(
	databases []runtimeDatabase,
	database runtimeDatabase,
) bool {
	return len(valueSortRulesForDatabase(databases, database)) > 0
}

func validateValueSortAdd(
	runtime *runtimeState,
	database runtimeDatabase,
	entry directory.Entry,
) error {
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return err
	}
	for _, rule := range valueSortRulesForDatabase(runtime.databases, database) {
		if rule.ignored || !rule.weighted ||
			(!rule.base.Equal(dn) && !rule.base.AncestorOf(dn)) {
			continue
		}
		for _, attribute := range entry.Attributes {
			if !constraintAttributeDescriptionsEqual(
				runtime.schema,
				attribute.Description,
				rule.attribute,
			) {
				continue
			}
			if err := validateValueSortWeights(attribute.Values); err != nil {
				return err
			}
			break
		}
	}
	return nil
}

func validateValueSortModify(
	runtime *runtimeState,
	database runtimeDatabase,
	dn directory.DN,
	changes []ldapwire.Modification,
) error {
	for _, rule := range valueSortRulesForDatabase(runtime.databases, database) {
		if rule.ignored || !rule.weighted ||
			(!rule.base.Equal(dn) && !rule.base.AncestorOf(dn)) {
			continue
		}
		for _, change := range changes {
			if len(change.Attribute.Values) == 0 ||
				!constraintAttributeDescriptionsEqual(
					runtime.schema,
					change.Attribute.Description,
					rule.attribute,
				) {
				continue
			}
			if err := validateValueSortWeights(change.Attribute.Values); err != nil {
				return err
			}
			break
		}
	}
	return nil
}

func validateValueSortWeights(values [][]byte) error {
	for _, value := range values {
		_, _, found, valid := parseValueSortWeight(value)
		switch {
		case !found:
			return operationFailed(
				ldapwire.ResultConstraintViolation,
				"weight missing from attribute",
			)
		case !valid:
			return operationFailed(
				ldapwire.ResultConstraintViolation,
				"weight is misformatted",
			)
		}
	}
	return nil
}

func parseValueSortWeight(value []byte) (
	weight int64,
	closing int,
	found,
	valid bool,
) {
	opening := bytes.IndexByte(value, '{')
	if opening < 0 {
		return 0, -1, false, false
	}
	weight, consumed := parseCLongPrefix(value[opening+1:])
	closing = opening + 1 + consumed
	if closing >= len(value) || value[closing] != '}' {
		return 0, closing, true, false
	}
	return weight, closing, true, true
}

func parseCLongPrefix(value []byte) (int64, int) {
	position := 0
	for position < len(value) && isASCIIWhitespace(value[position]) {
		position++
	}
	negative := false
	if position < len(value) && (value[position] == '+' || value[position] == '-') {
		negative = value[position] == '-'
		position++
	}
	digitStart := position
	base := uint64(10)
	if position < len(value) && value[position] == '0' {
		base = 8
		position++
		if position+1 < len(value) &&
			(value[position] == 'x' || value[position] == 'X') &&
			hexDigitValue(value[position+1]) >= 0 {
			base = 16
			position++
			digitStart = position
		} else {
			digitStart = position - 1
		}
	}
	digitCount := 0
	var magnitude uint64
	limit := uint64(math.MaxInt64)
	if negative {
		limit++
	}
	for position < len(value) {
		digit := digitValueForBase(value[position], base)
		if digit < 0 {
			break
		}
		digitCount++
		if magnitude > (limit-uint64(digit))/base {
			magnitude = limit
		} else {
			magnitude = magnitude*base + uint64(digit)
		}
		position++
	}
	if digitCount == 0 && !(base == 8 && digitStart < position) {
		return 0, 0
	}
	if negative {
		if magnitude >= uint64(math.MaxInt64)+1 {
			return math.MinInt64, position
		}
		return -int64(magnitude), position
	}
	if magnitude > uint64(math.MaxInt64) {
		return math.MaxInt64, position
	}
	return int64(magnitude), position
}

func digitValueForBase(value byte, base uint64) int {
	digit := hexDigitValue(value)
	if digit < 0 || uint64(digit) >= base {
		return -1
	}
	return digit
}

func hexDigitValue(value byte) int {
	switch {
	case value >= '0' && value <= '9':
		return int(value - '0')
	case value >= 'a' && value <= 'f':
		return int(value-'a') + 10
	case value >= 'A' && value <= 'F':
		return int(value-'A') + 10
	default:
		return -1
	}
}

func isASCIIWhitespace(value byte) bool {
	switch value {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	default:
		return false
	}
}

type sortableAttributeValue struct {
	value      []byte
	normalized []byte
	number     int64
	weight     int64
}

func applyValueSort(
	registry *schema.Registry,
	rules []valueSortRule,
	entry *directory.Entry,
) {
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return
	}
	for _, rule := range rules {
		if rule.ignored || (!rule.base.Equal(dn) && !rule.base.AncestorOf(dn)) {
			continue
		}
		for index := range entry.Attributes {
			attribute := &entry.Attributes[index]
			if len(attribute.Values) == 0 ||
				!constraintAttributeDescriptionsEqual(
					registry,
					attribute.Description,
					rule.attribute,
				) {
				continue
			}
			values, ok := prepareSortableAttributeValues(
				registry,
				attribute.Description,
				attribute.Values,
				rule,
			)
			if !ok {
				if rule.weighted {
					for valueIndex := range values {
						attribute.Values[valueIndex] = values[valueIndex].value
					}
				}
				continue
			}
			sort.SliceStable(values, func(left, right int) bool {
				comparison := compareSortableAttributeValues(
					values[left],
					values[right],
					rule,
				)
				return comparison < 0
			})
			for valueIndex := range values {
				attribute.Values[valueIndex] = values[valueIndex].value
			}
		}
	}
}

func prepareSortableAttributeValues(
	registry *schema.Registry,
	description string,
	values [][]byte,
	rule valueSortRule,
) ([]sortableAttributeValue, bool) {
	result := make([]sortableAttributeValue, len(values))
	for index, raw := range values {
		normalized, err := registry.NormalizeEqualityValue(description, raw)
		if err != nil {
			return result[:index], false
		}
		value := bytes.Clone(raw)
		if rule.weighted {
			weight, normalizedClosing, found, valid := parseValueSortWeight(normalized)
			if !found || !valid {
				return result[:index], false
			}
			rawClosing := bytes.IndexByte(value, '}')
			if rawClosing < 0 {
				return result[:index], false
			}
			value = bytes.Clone(value[rawClosing+1:])
			normalized = bytes.Clone(normalized[normalizedClosing+1:])
			result[index].weight = weight
		}
		result[index].value = value
		result[index].normalized = normalized
		if rule.kind == valueSortNumeric {
			result[index].number, _ = parseCLongPrefix(normalized)
		}
	}
	return result, true
}

func compareSortableAttributeValues(
	left,
	right sortableAttributeValue,
	rule valueSortRule,
) int {
	if rule.weighted {
		switch {
		case left.weight < right.weight:
			return -1
		case left.weight > right.weight:
			return 1
		}
	}
	var comparison int
	switch rule.kind {
	case valueSortAlpha:
		comparison = bytes.Compare(left.normalized, right.normalized)
	case valueSortNumeric:
		switch {
		case left.number < right.number:
			comparison = -1
		case left.number > right.number:
			comparison = 1
		}
	}
	if rule.descending {
		comparison = -comparison
	}
	return comparison
}
