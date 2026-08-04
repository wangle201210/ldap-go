package server

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type uniqueRuntimeConfiguration struct {
	domains []uniqueDomain
}

type uniqueDomain struct {
	strict    bool
	ignore    bool
	serialize bool
	uris      []uniqueURI
}

type uniqueURI struct {
	base       *directory.DN
	attributes []string
	scope      directory.Scope
	filter     *directory.Filter
}

func loadUniqueRuntimeConfiguration(
	entry directory.Entry,
	database runtimeDatabase,
) (uniqueRuntimeConfiguration, error) {
	if databaseType(database.name) == "frontend" {
		return uniqueRuntimeConfiguration{}, fmt.Errorf(
			"%s unique overlay cannot be global",
			entry.DN,
		)
	}
	if len(database.suffixes) == 0 {
		return uniqueRuntimeConfiguration{}, fmt.Errorf(
			"%s unique overlay requires a database suffix",
			entry.DN,
		)
	}

	uriValues := entry.Values("olcUniqueURI")
	legacyAttributes := entry.Values("olcUniqueAttribute")
	legacyIgnore := entry.Values("olcUniqueIgnore")
	legacyBase := entry.Values("olcUniqueBase")
	legacyStrict := entry.Values("olcUniqueStrict")
	legacyPresent := len(legacyAttributes) > 0 || len(legacyIgnore) > 0 ||
		len(legacyBase) > 0 || len(legacyStrict) > 0
	if len(uriValues) > 0 && legacyPresent {
		return uniqueRuntimeConfiguration{}, fmt.Errorf(
			"%s cannot mix olcUniqueURI with legacy unique configuration",
			entry.DN,
		)
	}

	configuration := uniqueRuntimeConfiguration{}
	if len(uriValues) > 0 {
		for _, raw := range uriValues {
			domain, err := parseUniqueDomain(string(raw), database)
			if err != nil {
				return uniqueRuntimeConfiguration{}, fmt.Errorf(
					"%s olcUniqueURI: %w",
					entry.DN,
					err,
				)
			}
			configuration.domains = append(configuration.domains, domain)
		}
		return configuration, nil
	}
	if !legacyPresent {
		return configuration, nil
	}

	domain, err := parseLegacyUniqueDomain(
		entry,
		database,
		legacyAttributes,
		legacyIgnore,
		legacyBase,
		legacyStrict,
	)
	if err != nil {
		return uniqueRuntimeConfiguration{}, err
	}
	configuration.domains = append(configuration.domains, domain)
	return configuration, nil
}

func parseUniqueDomain(raw string, database runtimeDatabase) (uniqueDomain, error) {
	value, err := stripUniqueOrderingPrefix(raw)
	if err != nil {
		return uniqueDomain{}, err
	}
	arguments, err := tokenizeOpenLDAPConfig(value)
	if err != nil {
		return uniqueDomain{}, err
	}
	if len(arguments) == 0 {
		return uniqueDomain{}, errors.New("uniqueness domain is empty")
	}

	domain := uniqueDomain{}
	position := 0
	if position < len(arguments) && strings.EqualFold(arguments[position], "ignore") {
		domain.ignore = true
		position++
	}
	if position < len(arguments) && strings.EqualFold(arguments[position], "serialize") {
		domain.serialize = true
		position++
	}
	if position < len(arguments) && strings.EqualFold(arguments[position], "strict") {
		domain.strict = true
		position++
		if !domain.ignore && position < len(arguments) &&
			strings.EqualFold(arguments[position], "ignore") {
			domain.ignore = true
			position++
		}
	}
	if position == len(arguments) {
		return uniqueDomain{}, errors.New("uniqueness domain has no LDAP URI")
	}
	for _, argument := range arguments[position:] {
		uri, err := parseUniqueURI(argument, database)
		if err != nil {
			return uniqueDomain{}, err
		}
		domain.uris = append(domain.uris, uri)
	}
	return domain, nil
}

func parseLegacyUniqueDomain(
	entry directory.Entry,
	database runtimeDatabase,
	attributeValues,
	ignoreValues,
	baseValues,
	strictValues [][]byte,
) (uniqueDomain, error) {
	if len(attributeValues) > 0 && len(ignoreValues) > 0 {
		return uniqueDomain{}, fmt.Errorf(
			"%s cannot set both olcUniqueAttribute and olcUniqueIgnore",
			entry.DN,
		)
	}
	if len(baseValues) > 1 {
		return uniqueDomain{}, fmt.Errorf(
			"%s olcUniqueBase must be single-valued",
			entry.DN,
		)
	}
	if len(strictValues) > 1 {
		return uniqueDomain{}, fmt.Errorf(
			"%s olcUniqueStrict must be single-valued",
			entry.DN,
		)
	}

	domain := uniqueDomain{ignore: len(ignoreValues) > 0}
	if len(strictValues) == 1 {
		switch {
		case strings.EqualFold(string(strictValues[0]), "TRUE"):
			domain.strict = true
		case strings.EqualFold(string(strictValues[0]), "FALSE"):
		default:
			return uniqueDomain{}, fmt.Errorf(
				"%s olcUniqueStrict has invalid value %q",
				entry.DN,
				strictValues[0],
			)
		}
	}

	uri := uniqueURI{scope: directory.ScopeWholeSubtree}
	if len(baseValues) == 1 {
		base, err := directory.ParseDN(string(baseValues[0]))
		if err != nil {
			return uniqueDomain{}, fmt.Errorf("%s olcUniqueBase: %w", entry.DN, err)
		}
		if !uniqueBaseWithinDatabase(database, base) {
			return uniqueDomain{}, fmt.Errorf(
				"%s olcUniqueBase %q is outside database naming contexts",
				entry.DN,
				base.String(),
			)
		}
		uri.base = &base
	}
	selected := attributeValues
	if domain.ignore {
		selected = ignoreValues
	}
	for _, raw := range selected {
		arguments, err := tokenizeOpenLDAPConfig(string(raw))
		if err != nil {
			return uniqueDomain{}, fmt.Errorf("%s legacy unique attributes: %w", entry.DN, err)
		}
		if len(arguments) == 0 {
			return uniqueDomain{}, fmt.Errorf(
				"%s legacy unique attribute value is empty",
				entry.DN,
			)
		}
		uri.attributes = append(uri.attributes, arguments...)
	}
	domain.uris = []uniqueURI{uri}
	return domain, nil
}

func parseUniqueURI(raw string, database runtimeDatabase) (uniqueURI, error) {
	parsed, err := parseConstraintLDAPURL(raw)
	if err != nil {
		return uniqueURI{}, err
	}
	if parsed.scope == directory.ScopeBase {
		return uniqueURI{}, errors.New(
			"unique URI requires one, sub, or children scope",
		)
	}
	if parsed.base != nil && !uniqueBaseWithinDatabase(database, *parsed.base) {
		return uniqueURI{}, fmt.Errorf(
			"unique URI DN %q is outside database naming contexts",
			parsed.base.String(),
		)
	}
	if parsed.filter != nil &&
		!uniqueFilterIsCanonical(parsed.filterText, *parsed.filter) {
		return uniqueURI{}, errors.New("unique URI has a noncanonical filter")
	}
	return uniqueURI{
		base:       parsed.base,
		attributes: parsed.attributes,
		scope:      parsed.scope,
		filter:     parsed.filter,
	}, nil
}

func uniqueFilterIsCanonical(raw string, filter directory.Filter) bool {
	open := 0
	escaped := false
	for index := 0; index < len(raw); index++ {
		if escaped {
			escaped = false
			continue
		}
		if raw[index] == '\\' {
			escaped = true
			continue
		}
		if raw[index] == '(' {
			open++
		}
	}
	return open == uniqueFilterNodeCount(filter)
}

func uniqueFilterNodeCount(filter directory.Filter) int {
	count := 1
	for _, child := range filter.Children {
		count += uniqueFilterNodeCount(child)
	}
	return count
}

func uniqueBaseWithinDatabase(database runtimeDatabase, base directory.DN) bool {
	for _, suffix := range database.suffixes {
		if suffix.Equal(base) || suffix.AncestorOf(base) {
			return true
		}
	}
	return false
}

func stripUniqueOrderingPrefix(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{") {
		return value, nil
	}
	end := strings.IndexByte(value, '}')
	if end < 2 {
		return "", errors.New("invalid ordered unique prefix")
	}
	order, err := strconv.Atoi(value[1:end])
	if err != nil || order < 0 {
		return "", fmt.Errorf("invalid ordered unique prefix %q", value[:end+1])
	}
	return strings.TrimSpace(value[end+1:]), nil
}

func validateUniqueSchema(
	registry *schema.Registry,
	configuration *uniqueRuntimeConfiguration,
) error {
	if configuration == nil {
		return nil
	}
	for _, domain := range configuration.domains {
		for _, uri := range domain.uris {
			for _, attribute := range uri.attributes {
				if err := validateConstraintAttributeDescription(attribute); err != nil {
					return fmt.Errorf("unique URI: %w", err)
				}
				if _, found := registry.AttributeType(attribute); !found {
					return fmt.Errorf(
						"unique URI references undefined attribute type %q",
						attribute,
					)
				}
			}
			if uri.filter != nil && chainFilterHasUndefined(registry, *uri.filter) {
				return errors.New(
					"unique URI filter references an undefined attribute type",
				)
			}
		}
	}
	return nil
}

func (server *Server) validateUniqueAdd(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	database runtimeDatabase,
	entry directory.Entry,
	relax bool,
) error {
	if database.unique == nil || server.uniqueRelaxAuthorized(
		runtime,
		reader,
		boundDN,
		entry,
		relax,
	) {
		return nil
	}
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return err
	}
	return server.validateUniqueAttributes(
		runtime,
		reader,
		database,
		dn,
		entry.Attributes,
		&entry,
		func(base directory.DN) bool {
			return base.Equal(dn) || base.AncestorOf(dn)
		},
	)
}

func (server *Server) validateUniqueModify(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	database runtimeDatabase,
	before directory.Entry,
	changes []ldapwire.Modification,
	relax bool,
) error {
	if database.unique == nil || server.uniqueRelaxAuthorized(
		runtime,
		reader,
		boundDN,
		before,
		relax,
	) {
		return nil
	}
	dn, err := directory.ParseDN(before.DN)
	if err != nil {
		return err
	}
	attributes := make([]directory.Attribute, 0, len(changes))
	for _, change := range changes {
		if change.Operation == ldapwire.ModificationDelete {
			continue
		}
		attributes = append(attributes, change.Attribute)
	}
	return server.validateUniqueAttributes(
		runtime,
		reader,
		database,
		dn,
		attributes,
		nil,
		func(base directory.DN) bool {
			return base.Equal(dn) || base.AncestorOf(dn)
		},
	)
}

func (server *Server) validateUniqueModifyDN(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	database runtimeDatabase,
	before directory.Entry,
	newSuperior *directory.DN,
	newRDNAttributes []directory.Attribute,
	relax bool,
) error {
	if database.unique == nil || server.uniqueRelaxAuthorized(
		runtime,
		reader,
		boundDN,
		before,
		relax,
	) {
		return nil
	}
	oldDN, err := directory.ParseDN(before.DN)
	if err != nil {
		return err
	}
	return server.validateUniqueAttributes(
		runtime,
		reader,
		database,
		oldDN,
		newRDNAttributes,
		nil,
		func(base directory.DN) bool {
			if base.Equal(oldDN) || base.AncestorOf(oldDN) {
				return true
			}
			return newSuperior != nil &&
				(base.Equal(*newSuperior) || base.AncestorOf(*newSuperior))
		},
	)
}

func (server *Server) uniqueRelaxAuthorized(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	entry directory.Entry,
	relax bool,
) bool {
	return relax && server.allowed(
		runtime,
		reader,
		boundDN,
		entry,
		"entry",
		nil,
		acl.Manage,
	)
}

func (server *Server) validateUniqueAttributes(
	runtime *runtimeState,
	reader storage.Reader,
	database runtimeDatabase,
	ignoredDN directory.DN,
	attributes []directory.Attribute,
	candidate *directory.Entry,
	inDomain func(directory.DN) bool,
) error {
	for _, domain := range database.unique.domains {
		for _, uri := range domain.uris {
			base := database.suffixes[0]
			if uri.base != nil {
				base = *uri.base
			}
			if !inDomain(base) {
				continue
			}
			if candidate != nil && uri.filter != nil {
				matches, err := uri.filter.MatchWith(*candidate, runtime.schema)
				if err != nil {
					return operationFailed(
						ldapwire.ResultInappropriateMatching,
						"unique candidate filter failed",
					)
				}
				if !matches {
					continue
				}
			}

			assertions := uniqueAssertions(
				runtime.schema,
				domain,
				uri,
				attributes,
			)
			if len(assertions) == 0 {
				continue
			}
			filter := directory.Filter{Kind: directory.FilterOr, Children: assertions}
			if uri.filter != nil {
				filter = directory.Filter{
					Kind: directory.FilterAnd,
					Children: []directory.Filter{
						*uri.filter,
						filter,
					},
				}
			}
			duplicate, err := uniqueSearch(
				runtime,
				readerForDatabase(reader, database),
				ignoredDN,
				base,
				uri.scope,
				filter,
			)
			if err != nil {
				return err
			}
			if duplicate {
				return operationFailed(
					ldapwire.ResultConstraintViolation,
					"some attributes not unique",
				)
			}
		}
	}
	return nil
}

func uniqueAssertions(
	registry *schema.Registry,
	domain uniqueDomain,
	uri uniqueURI,
	attributes []directory.Attribute,
) []directory.Filter {
	var assertions []directory.Filter
	for _, attribute := range attributes {
		if registry.IsOperational(attribute.Description) ||
			!uniqueDomainIncludesAttribute(
				registry,
				domain,
				uri,
				attribute.Description,
			) {
			continue
		}
		if len(attribute.Values) == 0 {
			if domain.strict {
				assertions = append(assertions, directory.Filter{
					Kind:      directory.FilterPresent,
					Attribute: attribute.Description,
				})
			}
			continue
		}
		for _, value := range attribute.Values {
			assertions = append(assertions, directory.Filter{
				Kind:      directory.FilterEquality,
				Attribute: attribute.Description,
				Assertion: value,
			})
		}
	}
	return assertions
}

func uniqueDomainIncludesAttribute(
	registry *schema.Registry,
	domain uniqueDomain,
	uri uniqueURI,
	description string,
) bool {
	if len(uri.attributes) == 0 {
		return true
	}
	listed := false
	for _, attribute := range uri.attributes {
		if constraintAttributeDescriptionsEqual(registry, description, attribute) {
			listed = true
			break
		}
	}
	if domain.ignore {
		return !listed
	}
	return listed
}

func uniqueSearch(
	runtime *runtimeState,
	reader storage.Reader,
	ignoredDN,
	base directory.DN,
	scope directory.Scope,
	filter directory.Filter,
) (bool, error) {
	found := false
	err := reader.ForEach(func(entry directory.Entry) error {
		if found || runtime.schema.EntryHasObjectClass(entry, "referral") {
			return nil
		}
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		if dn.Equal(ignoredDN) || !directory.InScope(base, dn, scope) ||
			!subentrySearchVisible(runtime, entry, scope, nil) {
			return nil
		}
		matches, err := filter.MatchWith(entry, runtime.schema)
		if err != nil {
			return operationFailed(
				ldapwire.ResultInappropriateMatching,
				"unique_search failed",
			)
		}
		found = matches
		return nil
	})
	return found, err
}
