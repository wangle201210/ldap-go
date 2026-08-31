package server

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type constraintKind uint8

const (
	constraintRegex constraintKind = iota
	constraintNegativeRegex
	constraintSize
	constraintCount
	constraintURI
	constraintSet
)

type constraintRuntimeConfiguration struct {
	rules []constraintRule
}

type constraintRule struct {
	attributes []string
	kind       constraintKind
	value      string
	limit      uint64
	regular    *regexp.Regexp
	uri        *constraintLDAPURL
	set        *constraintSetNode
	restrict   *constraintRestriction
}

type constraintLDAPURL struct {
	base       *directory.DN
	scope      directory.Scope
	attributes []string
	filter     directory.Filter
}

type constraintRestriction struct {
	base   *directory.DN
	scope  directory.Scope
	filter *directory.Filter
}

type parsedConstraintLDAPURL struct {
	base       *directory.DN
	scope      directory.Scope
	attributes []string
	filter     *directory.Filter
	filterText string
	extensions string
}

func loadConstraintRuntimeConfiguration(
	entry directory.Entry,
	database runtimeDatabase,
) (constraintRuntimeConfiguration, error) {
	if databaseType(database.name) == "frontend" {
		return constraintRuntimeConfiguration{}, fmt.Errorf(
			"%s constraint overlay cannot be global",
			entry.DN,
		)
	}
	configuration := constraintRuntimeConfiguration{}
	for _, raw := range entry.Values("olcConstraintAttribute") {
		rule, err := parseConstraintRule(string(raw), database)
		if err != nil {
			return constraintRuntimeConfiguration{}, fmt.Errorf(
				"%s olcConstraintAttribute: %w",
				entry.DN,
				err,
			)
		}
		configuration.rules = append(configuration.rules, rule)
	}
	return configuration, nil
}

func parseConstraintRule(
	raw string,
	database runtimeDatabase,
) (constraintRule, error) {
	value, err := stripConstraintOrderingPrefix(raw)
	if err != nil {
		return constraintRule{}, err
	}
	arguments, err := tokenizeOpenLDAPConfig(value)
	if err != nil {
		return constraintRule{}, err
	}
	if len(arguments) < 3 {
		return constraintRule{}, errors.New(
			"constraint requires attributes, type, and value",
		)
	}

	attributes := strings.Split(arguments[0], ",")
	seenAttributes := make(map[string]struct{}, len(attributes))
	for index := range attributes {
		attributes[index] = strings.TrimSpace(attributes[index])
		key := strings.ToLower(attributes[index])
		if key == "" {
			return constraintRule{}, errors.New("constraint attribute is empty")
		}
		if _, duplicate := seenAttributes[key]; duplicate {
			return constraintRule{}, fmt.Errorf(
				"constraint repeats attribute %q",
				attributes[index],
			)
		}
		seenAttributes[key] = struct{}{}
	}

	rule := constraintRule{
		attributes: attributes,
		value:      arguments[2],
	}
	switch strings.ToLower(arguments[1]) {
	case "regex", "negregex":
		rule.kind = constraintRegex
		if strings.EqualFold(arguments[1], "negregex") {
			rule.kind = constraintNegativeRegex
		}
		rule.regular, err = regexp.CompilePOSIX(arguments[2])
		if err != nil {
			return constraintRule{}, fmt.Errorf(
				"illegal regular expression %q: %w",
				arguments[2],
				err,
			)
		}
	case "size", "count":
		rule.kind = constraintSize
		if strings.EqualFold(arguments[1], "count") {
			rule.kind = constraintCount
		}
		rule.limit, err = strconv.ParseUint(arguments[2], 10, 64)
		if err != nil {
			return constraintRule{}, fmt.Errorf(
				"%s constraint requires a non-negative integer",
				arguments[1],
			)
		}
	case "uri":
		rule.kind = constraintURI
		parsed, parseErr := parseConstraintLDAPURLWithNormalizer(
			arguments[2],
			database.dnNormalizer,
		)
		if parseErr != nil {
			return constraintRule{}, fmt.Errorf("URI constraint: %w", parseErr)
		}
		if len(parsed.attributes) == 0 {
			return constraintRule{}, errors.New(
				"URI constraint requires at least one attribute",
			)
		}
		if parsed.extensions != "" {
			return constraintRule{}, errors.New(
				"URI constraint does not support URL extensions",
			)
		}
		filter := parsed.filter
		if filter == nil {
			defaultFilter, filterErr := compileSyncConsumerFilter(
				"(objectClass=*)",
			)
			if filterErr != nil {
				return constraintRule{}, filterErr
			}
			filter = &defaultFilter
		}
		rule.uri = &constraintLDAPURL{
			base:       parsed.base,
			scope:      parsed.scope,
			attributes: parsed.attributes,
			filter:     *filter,
		}
	case "set":
		rule.kind = constraintSet
		if strings.TrimSpace(arguments[2]) == "" {
			return constraintRule{}, errors.New("set constraint is empty")
		}
		rule.set, err = parseConstraintSetExpression(arguments[2])
		if err != nil {
			return constraintRule{}, fmt.Errorf(
				"invalid set constraint: %w",
				err,
			)
		}
	default:
		return constraintRule{}, fmt.Errorf(
			"unknown constraint type %q",
			arguments[1],
		)
	}

	for _, extra := range arguments[3:] {
		if !strings.HasPrefix(strings.ToLower(extra), "restrict=") {
			return constraintRule{}, fmt.Errorf(
				"unrecognized constraint argument %q",
				extra,
			)
		}
		if rule.restrict != nil {
			return constraintRule{}, errors.New(
				"constraint specifies restrict more than once",
			)
		}
		restriction, restrictionErr := parseConstraintRestriction(
			extra[len("restrict="):],
			database,
		)
		if restrictionErr != nil {
			return constraintRule{}, restrictionErr
		}
		rule.restrict = restriction
	}
	return rule, nil
}

func parseConstraintRestriction(
	raw string,
	database runtimeDatabase,
) (*constraintRestriction, error) {
	parsed, err := parseConstraintLDAPURLWithNormalizer(
		raw,
		database.dnNormalizer,
	)
	if err != nil {
		return nil, fmt.Errorf("restrict URI: %w", err)
	}
	if len(parsed.attributes) != 0 {
		return nil, errors.New("restrict URI must not contain attributes")
	}
	if parsed.extensions != "" {
		return nil, errors.New("restrict URI must not contain extensions")
	}
	if parsed.base != nil {
		if !uniqueBaseWithinDatabase(database, *parsed.base) {
			return nil, fmt.Errorf(
				"restrict URI DN %q is outside database naming contexts",
				parsed.base.String(),
			)
		}
	}
	return &constraintRestriction{
		base:   parsed.base,
		scope:  parsed.scope,
		filter: parsed.filter,
	}, nil
}

func parseConstraintLDAPURLWithNormalizer(
	raw string,
	normalizer directory.DNAttributeNormalizer,
) (parsedConstraintLDAPURL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return parsedConstraintLDAPURL{}, fmt.Errorf("parse LDAP URL: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "ldap") ||
		parsed.Host != "" ||
		parsed.User != nil ||
		parsed.Fragment != "" {
		return parsedConstraintLDAPURL{}, errors.New(
			"constraint URL must be a local ldap:/// URL",
		)
	}

	result := parsedConstraintLDAPURL{scope: directory.ScopeBase}
	rawBase := strings.TrimPrefix(parsed.EscapedPath(), "/")
	baseText, err := url.PathUnescape(rawBase)
	if err != nil {
		return parsedConstraintLDAPURL{}, fmt.Errorf("decode LDAP URL base: %w", err)
	}
	if baseText != "" {
		base, parseErr := parseRuntimeDN(baseText, normalizer)
		if parseErr != nil {
			return parsedConstraintLDAPURL{}, fmt.Errorf(
				"LDAP URL base: %w",
				parseErr,
			)
		}
		result.base = &base
	}

	components := strings.Split(parsed.RawQuery, "?")
	if parsed.RawQuery == "" {
		components = nil
	}
	if len(components) > 4 {
		return parsedConstraintLDAPURL{}, errors.New(
			"LDAP URL has too many components",
		)
	}
	for len(components) < 4 {
		components = append(components, "")
	}
	attributesText, err := url.PathUnescape(components[0])
	if err != nil {
		return parsedConstraintLDAPURL{}, fmt.Errorf(
			"decode LDAP URL attributes: %w",
			err,
		)
	}
	if attributesText != "" {
		for _, attribute := range strings.Split(attributesText, ",") {
			attribute = strings.TrimSpace(attribute)
			if attribute == "" {
				return parsedConstraintLDAPURL{}, errors.New(
					"LDAP URL contains an empty attribute",
				)
			}
			result.attributes = append(result.attributes, attribute)
		}
	}

	scopeText, err := url.PathUnescape(components[1])
	if err != nil {
		return parsedConstraintLDAPURL{}, fmt.Errorf("decode LDAP URL scope: %w", err)
	}
	switch strings.ToLower(scopeText) {
	case "", "base":
	case "one":
		result.scope = directory.ScopeSingleLevel
	case "sub":
		result.scope = directory.ScopeWholeSubtree
	case "children":
		result.scope = directory.ScopeChildren
	default:
		return parsedConstraintLDAPURL{}, fmt.Errorf(
			"LDAP URL has unknown scope %q",
			scopeText,
		)
	}

	filterText, err := url.PathUnescape(components[2])
	if err != nil {
		return parsedConstraintLDAPURL{}, fmt.Errorf("decode LDAP URL filter: %w", err)
	}
	if filterText != "" {
		filter, filterErr := compileSyncConsumerFilter(filterText)
		if filterErr != nil {
			return parsedConstraintLDAPURL{}, fmt.Errorf(
				"LDAP URL filter: %w",
				filterErr,
			)
		}
		result.filter = &filter
		result.filterText = filterText
	}
	result.extensions, err = url.PathUnescape(components[3])
	if err != nil {
		return parsedConstraintLDAPURL{}, fmt.Errorf(
			"decode LDAP URL extensions: %w",
			err,
		)
	}
	return result, nil
}

func stripConstraintOrderingPrefix(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{") {
		return value, nil
	}
	end := strings.IndexByte(value, '}')
	if end < 2 {
		return "", errors.New("invalid ordered constraint prefix")
	}
	order, err := strconv.Atoi(value[1:end])
	if err != nil || order < 0 {
		return "", fmt.Errorf(
			"invalid ordered constraint prefix %q",
			value[:end+1],
		)
	}
	return strings.TrimSpace(value[end+1:]), nil
}

func validateConstraintSchema(
	registry *schema.Registry,
	configuration *constraintRuntimeConfiguration,
) error {
	if configuration == nil {
		return nil
	}
	for index := range configuration.rules {
		rule := &configuration.rules[index]
		for _, attribute := range rule.attributes {
			if err := validateConstraintAttributeDescription(attribute); err != nil {
				return err
			}
			if _, found := registry.AttributeType(attribute); !found {
				return fmt.Errorf(
					"constraint references undefined attribute type %q",
					attribute,
				)
			}
		}
		if rule.uri != nil {
			for _, attribute := range rule.uri.attributes {
				if err := validateConstraintAttributeDescription(attribute); err != nil {
					return fmt.Errorf("constraint URI: %w", err)
				}
				if _, found := registry.AttributeType(attribute); !found {
					return fmt.Errorf(
						"constraint URI references undefined attribute type %q",
						attribute,
					)
				}
			}
			if chainFilterHasUndefined(registry, rule.uri.filter) {
				return errors.New(
					"constraint URI filter references an undefined attribute type",
				)
			}
		}
		if rule.restrict != nil && rule.restrict.filter != nil &&
			chainFilterHasUndefined(registry, *rule.restrict.filter) {
			return errors.New(
				"constraint restrict filter references an undefined attribute type",
			)
		}
		if err := validateConstraintSetSchema(registry, rule.set); err != nil {
			return err
		}
	}
	return nil
}

func validateConstraintAttributeDescription(description string) error {
	parts := strings.Split(strings.TrimSpace(description), ";")
	if !validConstraintAttributeType(parts[0]) {
		return fmt.Errorf("invalid attribute description %q", description)
	}
	seen := make(map[string]struct{}, len(parts)-1)
	for _, option := range parts[1:] {
		if !validConstraintKeyString(option) {
			return fmt.Errorf("invalid attribute description %q", description)
		}
		key := strings.ToLower(option)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf(
				"attribute description %q repeats option %q",
				description,
				option,
			)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validConstraintAttributeType(value string) bool {
	if value == "" {
		return false
	}
	if value[0] >= '0' && value[0] <= '9' {
		arcs := strings.Split(value, ".")
		if len(arcs) < 2 {
			return false
		}
		for _, arc := range arcs {
			if arc == "" || len(arc) > 1 && arc[0] == '0' {
				return false
			}
			for index := range arc {
				if arc[index] < '0' || arc[index] > '9' {
					return false
				}
			}
		}
		return true
	}
	return validConstraintKeyString(value)
}

func validConstraintKeyString(value string) bool {
	if value == "" || value[len(value)-1] == '-' ||
		!(value[0] >= 'A' && value[0] <= 'Z' ||
			value[0] >= 'a' && value[0] <= 'z') {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !(character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '-') {
			return false
		}
	}
	return true
}

func (server *Server) validateConstraintAdd(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	database runtimeDatabase,
	entry directory.Entry,
	relax bool,
) error {
	if relax || database.constraint == nil {
		return nil
	}
	for _, attribute := range entry.Attributes {
		if runtime.schema.IsOperational(attribute.Description) {
			continue
		}
		for _, rule := range database.constraint.rules {
			if !constraintRuleMatchesAttribute(
				runtime.schema,
				rule,
				attribute.Description,
			) {
				continue
			}
			applies, err := constraintRuleApplies(runtime, rule, entry)
			if err != nil {
				return err
			}
			if !applies {
				continue
			}

			switch rule.kind {
			case constraintCount:
				constrained := constraintMatchingAttribute(
					runtime.schema,
					rule,
					attribute.Description,
				)
				if uint64(len(constraintAttributeValues(
					runtime.schema,
					entry,
					constrained,
				))) > rule.limit {
					return constraintViolation("add", attribute.Description)
				}
			case constraintSet:
				matches, err := evaluateConstraintSet(
					runtime,
					reader,
					boundDN,
					entry,
					rule,
				)
				if err != nil {
					return err
				}
				if !matches {
					return constraintViolation("add", attribute.Description)
				}
			default:
				for _, value := range attribute.Values {
					matches, err := server.constraintValueMatches(
						runtime,
						reader,
						boundDN,
						database,
						rule,
						value,
					)
					if err != nil {
						return err
					}
					if !matches {
						return constraintViolation("add", attribute.Description)
					}
				}
			}
		}
	}
	return nil
}

func (server *Server) validateConstraintModify(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	database runtimeDatabase,
	before directory.Entry,
	after directory.Entry,
	changes []ldapwire.Modification,
	relax bool,
) error {
	if relax || database.constraint == nil {
		return nil
	}

	for _, rule := range database.constraint.rules {
		if rule.kind != constraintCount {
			continue
		}
		applies, err := constraintRuleApplies(runtime, rule, before)
		if err != nil {
			return err
		}
		if !applies {
			continue
		}
		for _, constrained := range rule.attributes {
			for _, change := range changes {
				if constraintAttributeDescriptionsEqual(
					runtime.schema,
					change.Attribute.Description,
					constrained,
				) && change.Operation == ldapwire.ModificationIncrement {
					return constraintViolation(
						"modify",
						change.Attribute.Description,
					)
				}
			}
			if uint64(len(constraintAttributeValues(
				runtime.schema,
				after,
				constrained,
			))) > rule.limit {
				return constraintViolation(
					"modify",
					constraintViolationAttribute(changes, constrained),
				)
			}
		}
	}

	for _, change := range changes {
		if runtime.schema.IsOperational(change.Attribute.Description) ||
			(change.Operation != ldapwire.ModificationAdd &&
				change.Operation != ldapwire.ModificationReplace &&
				change.Operation != ldapwire.ModificationDelete) ||
			len(change.Attribute.Values) == 0 {
			continue
		}
		for _, rule := range database.constraint.rules {
			if rule.kind == constraintCount ||
				!constraintRuleMatchesAttribute(
					runtime.schema,
					rule,
					change.Attribute.Description,
				) {
				continue
			}
			applies, err := constraintRuleApplies(runtime, rule, before)
			if err != nil {
				return err
			}
			if !applies || change.Operation == ldapwire.ModificationDelete {
				continue
			}

			if rule.kind == constraintSet {
				matches, err := evaluateConstraintSet(
					runtime,
					reader,
					boundDN,
					after,
					rule,
				)
				if err != nil {
					return err
				}
				if !matches {
					return constraintViolation(
						"modify",
						change.Attribute.Description,
					)
				}
				continue
			}

			for _, value := range change.Attribute.Values {
				matches, err := server.constraintValueMatches(
					runtime,
					reader,
					boundDN,
					database,
					rule,
					value,
				)
				if err != nil {
					return err
				}
				if !matches {
					return constraintViolation(
						"modify",
						change.Attribute.Description,
					)
				}
			}
		}
	}
	return nil
}

func constraintViolation(operation, attribute string) error {
	return operationFailed(
		ldapwire.ResultConstraintViolation,
		operation+" breaks constraint on "+attribute,
	)
}

func constraintViolationAttribute(
	changes []ldapwire.Modification,
	fallback string,
) string {
	if len(changes) > 0 {
		return changes[0].Attribute.Description
	}
	return fallback
}

func constraintRuleMatchesAttribute(
	registry *schema.Registry,
	rule constraintRule,
	description string,
) bool {
	for _, constrained := range rule.attributes {
		if constraintAttributeDescriptionsEqual(
			registry,
			description,
			constrained,
		) {
			return true
		}
	}
	return false
}

func constraintMatchingAttribute(
	registry *schema.Registry,
	rule constraintRule,
	description string,
) string {
	for _, constrained := range rule.attributes {
		if constraintAttributeDescriptionsEqual(
			registry,
			description,
			constrained,
		) {
			return constrained
		}
	}
	return description
}

func constraintAttributeDescriptionsEqual(
	registry *schema.Registry,
	left,
	right string,
) bool {
	leftBase, leftOptions := splitConstraintAttributeDescription(left)
	rightBase, rightOptions := splitConstraintAttributeDescription(right)
	if len(leftOptions) != len(rightOptions) {
		return false
	}
	for option := range leftOptions {
		if _, found := rightOptions[option]; !found {
			return false
		}
	}
	leftType, leftKnown := registry.AttributeType(leftBase)
	rightType, rightKnown := registry.AttributeType(rightBase)
	if leftKnown && rightKnown {
		return strings.EqualFold(leftType.OID, rightType.OID)
	}
	return strings.EqualFold(leftBase, rightBase)
}

func splitConstraintAttributeDescription(
	description string,
) (string, map[string]struct{}) {
	parts := strings.Split(strings.TrimSpace(description), ";")
	options := make(map[string]struct{}, len(parts)-1)
	for _, option := range parts[1:] {
		options[strings.ToLower(strings.TrimSpace(option))] = struct{}{}
	}
	return parts[0], options
}

func constraintAttributeValues(
	registry *schema.Registry,
	entry directory.Entry,
	description string,
) [][]byte {
	var values [][]byte
	for _, attribute := range entry.Attributes {
		if !constraintAttributeDescriptionsEqual(
			registry,
			attribute.Description,
			description,
		) {
			continue
		}
		for _, value := range attribute.Values {
			values = append(values, bytes.Clone(value))
		}
	}
	return values
}

func constraintRuleApplies(
	runtime *runtimeState,
	rule constraintRule,
	entry directory.Entry,
) (bool, error) {
	if rule.restrict == nil {
		return true, nil
	}
	if rule.restrict.base != nil {
		dn, err := directory.ParseDNWithNormalizer(entry.DN, runtime.schema)
		if err != nil {
			return false, err
		}
		base, err := directory.ParseDNWithNormalizer(
			rule.restrict.base.String(),
			runtime.schema,
		)
		if err != nil {
			return false, err
		}
		if !directory.InScope(base, dn, rule.restrict.scope) {
			return false, nil
		}
	}
	if rule.restrict.filter == nil {
		return true, nil
	}
	return rule.restrict.filter.MatchWith(entry, runtime.schema)
}

func evaluateConstraintSet(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	entry directory.Entry,
	rule constraintRule,
) (bool, error) {
	values, err := (constraintSetEvaluation{
		runtime: runtime,
		reader:  reader,
		target:  entry,
		userDN:  boundDN,
	}).evaluate(rule.set)
	return len(values) > 0, err
}

func (server *Server) constraintValueMatches(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	database runtimeDatabase,
	rule constraintRule,
	value []byte,
) (bool, error) {
	switch rule.kind {
	case constraintRegex:
		return rule.regular.Match(value), nil
	case constraintNegativeRegex:
		return !rule.regular.Match(value), nil
	case constraintSize:
		return uint64(len(value)) <= rule.limit, nil
	case constraintURI:
		return server.constraintURIMatches(
			runtime,
			reader,
			boundDN,
			database,
			*rule.uri,
			value,
		)
	case constraintCount, constraintSet:
		return true, nil
	default:
		return false, fmt.Errorf("unknown constraint kind %d", rule.kind)
	}
}

func (server *Server) constraintURIMatches(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	database runtimeDatabase,
	uri constraintLDAPURL,
	value []byte,
) (bool, error) {
	var base directory.DN
	if uri.base != nil {
		base = *uri.base
	} else {
		if len(database.suffixes) == 0 {
			return false, errors.New("constraint URI database has no naming context")
		}
		base = database.suffixes[0]
	}
	targetDatabase := databaseForDN(runtime, base)
	if targetDatabase == nil {
		return false, operationFailed(ldapwire.ResultNoSuchObject, "")
	}
	targetReader := readerForDatabase(reader, *targetDatabase)
	base, err := storage.NormalizeReaderDN(targetReader, base)
	if err != nil {
		return false, err
	}
	equalities := make([]directory.Filter, 0, len(uri.attributes))
	for _, attribute := range uri.attributes {
		equalities = append(equalities, directory.Filter{
			Kind:      directory.FilterEquality,
			Attribute: attribute,
			Assertion: bytes.Clone(value),
		})
	}
	filter := directory.Filter{
		Kind: directory.FilterAnd,
		Children: []directory.Filter{
			uri.filter,
			{Kind: directory.FilterOr, Children: equalities},
		},
	}

	found := false
	err = targetReader.ForEach(func(entry directory.Entry) error {
		if found || runtime.schema.EntryHasObjectClass(entry, "referral") {
			return nil
		}
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		dn, err = storage.NormalizeReaderDN(targetReader, dn)
		if err != nil {
			return err
		}
		if !directory.InScope(base, dn, uri.scope) {
			return nil
		}
		if !subentrySearchVisible(runtime, entry, uri.scope, nil) {
			return nil
		}
		matches, err := server.filterMatches(
			runtime,
			targetReader,
			boundDN,
			entry,
			filter,
		)
		if err != nil || !matches {
			return err
		}
		if !server.allowed(
			runtime,
			targetReader,
			boundDN,
			entry,
			"entry",
			nil,
			acl.Read,
		) {
			return nil
		}
		found = true
		return nil
	})
	return found, err
}
