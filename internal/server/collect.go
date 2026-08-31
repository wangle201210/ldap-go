package server

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type collectRuntimeConfiguration struct {
	rules []collectRule
}

type collectRule struct {
	base       directory.DN
	normalized string
	attributes []collectAttribute
}

type collectAttribute struct {
	raw         string
	description string
	key         string
	baseKey     string
}

type collectConfigurationError struct {
	code       ldapwire.ResultCode
	diagnostic string
}

func (failure *collectConfigurationError) Error() string {
	return failure.diagnostic
}

func collectConfigurationFailure(
	code ldapwire.ResultCode,
	format string,
	arguments ...any,
) error {
	return &collectConfigurationError{
		code:       code,
		diagnostic: fmt.Sprintf(format, arguments...),
	}
}

func collectConfigurationResult(err error) (ldapwire.Result, bool) {
	var failure *collectConfigurationError
	if !errors.As(err, &failure) {
		return ldapwire.Result{}, false
	}
	return ldapwire.ResultError(failure.code, failure.diagnostic), true
}

func loadCollectRuntimeConfiguration(
	entry directory.Entry,
) (collectRuntimeConfiguration, error) {
	if err := validateCollectConfigurationAttributes(entry); err != nil {
		return collectRuntimeConfiguration{}, err
	}

	values := entry.Values("olcCollectInfo")
	configuration := collectRuntimeConfiguration{
		rules: make([]collectRule, 0, len(values)),
	}
	for _, raw := range values {
		arguments, err := tokenizeOpenLDAPConfig(string(raw))
		if err != nil {
			return collectRuntimeConfiguration{}, collectConfigurationFailure(
				ldapwire.ResultConstraintViolation,
				"%s olcCollectInfo: %v",
				entry.DN,
				err,
			)
		}
		if len(arguments) != 2 {
			return collectRuntimeConfiguration{}, collectConfigurationFailure(
				ldapwire.ResultConstraintViolation,
				"%s olcCollectInfo requires a DN and one comma-separated attribute list",
				entry.DN,
			)
		}

		base, err := directory.ParseDN(arguments[0])
		if err != nil {
			return collectRuntimeConfiguration{}, collectConfigurationFailure(
				ldapwire.ResultOther,
				"%s olcCollectInfo invalid DN %q: %v",
				entry.DN,
				arguments[0],
				err,
			)
		}
		attributeValues := strings.Split(arguments[1], ",")
		attributes := make([]collectAttribute, 0, len(attributeValues))
		for _, attribute := range attributeValues {
			if attribute == "" || strings.TrimSpace(attribute) != attribute ||
				strings.IndexFunc(attribute, func(character rune) bool {
					return character == ' ' || character == '\t' ||
						character == '\r' || character == '\n'
				}) >= 0 {
				return collectRuntimeConfiguration{}, collectConfigurationFailure(
					ldapwire.ResultConstraintViolation,
					"%s olcCollectInfo has an empty or whitespace-containing attribute description",
					entry.DN,
				)
			}
			if err := validateConstraintAttributeDescription(attribute); err != nil {
				return collectRuntimeConfiguration{}, collectConfigurationFailure(
					ldapwire.ResultConstraintViolation,
					"%s olcCollectInfo: %v",
					entry.DN,
					err,
				)
			}
			attributes = append(attributes, collectAttribute{raw: attribute})
		}

		configuration.rules = append(configuration.rules, collectRule{
			base:       base,
			normalized: base.Key(),
			attributes: attributes,
		})
	}

	sort.SliceStable(configuration.rules, func(left, right int) bool {
		return configuration.rules[left].base.Depth() >
			configuration.rules[right].base.Depth()
	})
	return configuration, nil
}

func validateCollectConfigurationAttributes(entry directory.Entry) error {
	allowed := map[string]struct{}{
		"objectclass":           {},
		"olcoverlay":            {},
		"olccollectinfo":        {},
		"olcdisabled":           {},
		"entryuuid":             {},
		"entrycsn":              {},
		"createtimestamp":       {},
		"modifytimestamp":       {},
		"creatorsname":          {},
		"modifiersname":         {},
		"structuralobjectclass": {},
		"subschemasubentry":     {},
	}
	for _, attribute := range entry.Attributes {
		if _, ok := allowed[strings.ToLower(attribute.Description)]; ok {
			continue
		}
		return collectConfigurationFailure(
			ldapwire.ResultUndefinedAttributeType,
			"%s has undefined collect configuration attribute %q",
			entry.DN,
			attribute.Description,
		)
	}
	return nil
}

func validateCollectSchema(
	registry *schema.Registry,
	configuration *collectRuntimeConfiguration,
) error {
	if configuration == nil {
		return nil
	}
	seenBases := make(map[string]struct{}, len(configuration.rules))
	for ruleIndex := range configuration.rules {
		rule := &configuration.rules[ruleIndex]
		base, err := registry.NormalizeDN(rule.base.String())
		if err != nil {
			return collectConfigurationFailure(
				ldapwire.ResultOther,
				"olcCollectInfo unable to normalize DN %q: %v",
				rule.base.String(),
				err,
			)
		}
		if _, duplicate := seenBases[base.Key()]; duplicate {
			return collectConfigurationFailure(
				ldapwire.ResultOther,
				"olcCollectInfo DN already configured: %q",
				rule.base.String(),
			)
		}
		seenBases[base.Key()] = struct{}{}
		rule.base = base
		rule.normalized = base.Key()
		for attributeIndex := range rule.attributes {
			attribute := &rule.attributes[attributeIndex]
			description, key, baseKey, err := resolveCollectAttributeDescription(
				registry,
				attribute.raw,
			)
			if err != nil {
				return collectConfigurationFailure(
					ldapwire.ResultOther,
					"olcCollectInfo attribute description unknown: %q",
					attribute.raw,
				)
			}
			attribute.description = description
			attribute.key = key
			attribute.baseKey = baseKey
		}
	}
	return nil
}

func resolveCollectAttributeDescription(
	registry *schema.Registry,
	description string,
) (string, string, string, error) {
	parts := strings.Split(description, ";")
	attributeType, found := registry.AttributeType(parts[0])
	if !found {
		return "", "", "", fmt.Errorf("undefined attribute type %q", parts[0])
	}
	options := make([]string, 0, len(parts)-1)
	for _, option := range parts[1:] {
		options = append(options, strings.ToLower(option))
	}
	sort.Strings(options)

	canonical := attributeType.Name()
	baseKey := strings.ToLower(attributeType.OID)
	key := baseKey
	if len(options) > 0 {
		suffix := ";" + strings.Join(options, ";")
		canonical += suffix
		key += suffix
	}
	return canonical, key, baseKey, nil
}

func collectConfigurationsForDatabase(
	databases []runtimeDatabase,
	database runtimeDatabase,
) []*collectRuntimeConfiguration {
	var configurations []*collectRuntimeConfiguration
	if databaseType(database.name) != "frontend" && database.collect != nil {
		configurations = append(configurations, database.collect)
	}
	for index := range databases {
		candidate := &databases[index]
		if databaseType(candidate.name) == "frontend" && candidate.collect != nil {
			configurations = append(configurations, candidate.collect)
		}
	}
	if databaseType(database.name) == "frontend" && database.collect != nil &&
		len(configurations) == 0 {
		configurations = append(configurations, database.collect)
	}
	return configurations
}

type collectProjectionCache struct {
	server    *Server
	runtime   *runtimeState
	reader    storage.Reader
	subjectDN string
	templates map[string]collectTemplate
	enabled   bool
}

type collectTemplate struct {
	entry  directory.Entry
	reader storage.Reader
	found  bool
	err    error
}

func newCollectProjectionCache(
	server *Server,
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
) *collectProjectionCache {
	enabled := false
	if runtime != nil {
		for index := range runtime.databases {
			if runtime.databases[index].collect != nil {
				enabled = true
				break
			}
		}
	}
	var templates map[string]collectTemplate
	if enabled {
		templates = make(map[string]collectTemplate)
	}
	return &collectProjectionCache{
		server:    server,
		runtime:   runtime,
		reader:    reader,
		subjectDN: subjectDN,
		templates: templates,
		enabled:   enabled,
	}
}

func (cache *collectProjectionCache) apply(
	database runtimeDatabase,
	entry directory.Entry,
) (directory.Entry, error) {
	if cache == nil || !cache.enabled {
		return entry, nil
	}
	configurations := collectConfigurationsForDatabase(
		cache.runtime.databases,
		database,
	)
	if len(configurations) == 0 {
		return entry, nil
	}
	target, err := directory.ParseDN(entry.DN)
	if err != nil {
		return directory.Entry{}, err
	}
	target, err = cache.runtime.schema.NormalizeDN(target.String())
	if err != nil {
		return directory.Entry{}, err
	}

	projected := entry
	cloned := false
	for _, configuration := range configurations {
		for _, rule := range configuration.rules {
			if rule.base.Equal(target) || !rule.base.AncestorOf(target) {
				continue
			}
			template := cache.template(rule.base)
			if template.err != nil {
				return directory.Entry{}, template.err
			}
			if !template.found {
				continue
			}
			for _, attribute := range rule.attributes {
				values, err := cache.readTemplateAttribute(template, attribute)
				if err != nil {
					return directory.Entry{}, err
				}
				if len(values) == 0 {
					continue
				}
				if !cloned {
					projected = entry.Clone()
					cloned = true
				}
				appendCollectValues(
					cache.runtime.schema,
					&projected,
					attribute,
					values,
				)
			}
		}
	}
	return projected, nil
}

func (cache *collectProjectionCache) template(base directory.DN) collectTemplate {
	if cached, ok := cache.templates[base.Key()]; ok {
		return cached
	}
	template := collectTemplate{}
	database := databaseForDN(cache.runtime, base)
	if database == nil || database.partition == "" {
		cache.templates[base.Key()] = template
		return template
	}
	template.reader = readerForDatabase(cache.reader, *database)
	entry, err := template.reader.Get(base)
	switch {
	case err == nil:
		template.entry = entry
		template.found = true
	case errors.Is(err, storage.ErrEntryNotFound):
	default:
		template.err = err
	}
	cache.templates[base.Key()] = template
	return template
}

func (cache *collectProjectionCache) readTemplateAttribute(
	template collectTemplate,
	attribute collectAttribute,
) ([][]byte, error) {
	if !cache.server.allowed(
		cache.runtime,
		template.reader,
		cache.subjectDN,
		template.entry,
		"entry",
		nil,
		acl.Read,
	) {
		return nil, nil
	}
	if !cache.server.allowed(
		cache.runtime,
		template.reader,
		cache.subjectDN,
		template.entry,
		attribute.description,
		nil,
		acl.Read,
	) {
		return nil, nil
	}

	var projected [][]byte
	for _, candidate := range template.entry.Attributes {
		_, key, _, err := resolveCollectAttributeDescription(
			cache.runtime.schema,
			candidate.Description,
		)
		if err != nil || key != attribute.key {
			continue
		}
		for _, rawValue := range candidate.Values {
			value, err := cache.runtime.schema.NormalizeEqualityValue(
				attribute.description,
				rawValue,
			)
			if err != nil {
				return nil, err
			}
			if cache.server.allowed(
				cache.runtime,
				template.reader,
				cache.subjectDN,
				template.entry,
				attribute.description,
				value,
				acl.Read,
			) {
				projected = append(projected, value)
			}
		}
	}
	return projected, nil
}

func appendCollectValues(
	registry *schema.Registry,
	entry *directory.Entry,
	attribute collectAttribute,
	values [][]byte,
) {
	for index := range entry.Attributes {
		_, key, _, err := resolveCollectAttributeDescription(
			registry,
			entry.Attributes[index].Description,
		)
		if err != nil || key != attribute.key {
			continue
		}
		entry.Attributes[index].Values = append(entry.Attributes[index].Values, values...)
		return
	}
	entry.Attributes = append(entry.Attributes, directory.Attribute{
		Description: attribute.description,
		Values:      append([][]byte(nil), values...),
	})
}

func validateCollectModify(
	runtime *runtimeState,
	database runtimeDatabase,
	target directory.DN,
	changes []ldapwire.Modification,
) error {
	configurations := collectConfigurationsForDatabase(runtime.databases, database)
	if len(configurations) == 0 {
		return nil
	}
	target, err := runtime.schema.NormalizeDN(target.String())
	if err != nil {
		return err
	}
	for _, change := range changes {
		_, _, baseKey, err := resolveCollectAttributeDescription(
			runtime.schema,
			change.Attribute.Description,
		)
		if err != nil {
			baseKey = strings.ToLower(strings.SplitN(
				change.Attribute.Description,
				";",
				2,
			)[0])
		}
		for _, configuration := range configurations {
			for _, rule := range configuration.rules {
				if rule.base.Equal(target) || !rule.base.AncestorOf(target) {
					continue
				}
				for _, attribute := range rule.attributes {
					if attribute.baseKey != baseKey {
						continue
					}
					return operationFailed(
						ldapwire.ResultUnwillingToPerform,
						fmt.Sprintf(
							"cannot change virtual attribute '%s'",
							attribute.description,
						),
					)
				}
			}
		}
	}
	return nil
}
