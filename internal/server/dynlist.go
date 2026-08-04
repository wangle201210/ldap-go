package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type dynlistRuntimeConfiguration struct {
	attributeSets []dynlistAttributeSet
	simple        bool
}

type dynlistAttributeSet struct {
	objectClass  string
	restriction  *dynlistLDAPURL
	urlAttribute string
	mappings     []dynlistAttributeMapping
}

type dynlistAttributeMapping struct {
	mappedAttribute   string
	memberAttribute   string
	memberOfAttribute string
	staticObjectClass string
	nested            bool
}

func (mapping dynlistAttributeMapping) outputAttribute() string {
	if mapping.mappedAttribute != "" {
		return mapping.mappedAttribute
	}
	return mapping.memberAttribute
}

type dynamicGroupRuntimeConfiguration struct {
	pairs []dynamicGroupAttributePair
}

type dynamicGroupAttributePair struct {
	memberAttribute string
	urlAttribute    string
}

type dynlistLDAPURL struct {
	base       directory.DN
	baseSet    bool
	scope      directory.Scope
	attributes []string
	filter     directory.Filter
	filterSet  bool
	filterErr  error
	extensions string
}

func loadDynlistRuntimeConfiguration(
	entry directory.Entry,
	database runtimeDatabase,
) (dynlistRuntimeConfiguration, error) {
	if databaseType(database.name) == "frontend" {
		return dynlistRuntimeConfiguration{}, fmt.Errorf(
			"%s dynlist overlay cannot be global",
			entry.DN,
		)
	}
	simple, _, err := singleBoolean(entry, "olcDynListSimple")
	if err != nil {
		return dynlistRuntimeConfiguration{}, err
	}
	configuration := dynlistRuntimeConfiguration{simple: simple}
	values := valuesForAttributeAliases(
		entry,
		"olcDynListAttrSet",
		"olcDlAttrSet",
	)
	if len(values) == 0 {
		configuration.attributeSets = []dynlistAttributeSet{{
			objectClass:  "groupOfURLs",
			urlAttribute: "memberURL",
		}}
		return configuration, nil
	}
	orderedValues, err := orderedDynlistAttributeSetValues(values)
	if err != nil {
		return dynlistRuntimeConfiguration{}, fmt.Errorf(
			"%s olcDynListAttrSet: %w",
			entry.DN,
			err,
		)
	}
	for _, value := range orderedValues {
		arguments, err := tokenizeOpenLDAPConfig(value)
		if err != nil {
			return dynlistRuntimeConfiguration{}, fmt.Errorf(
				"%s olcDynListAttrSet: %w",
				entry.DN,
				err,
			)
		}
		attributeSet, err := parseDynlistAttributeSet(arguments)
		if err != nil {
			return dynlistRuntimeConfiguration{}, fmt.Errorf(
				"%s olcDynListAttrSet: %w",
				entry.DN,
				err,
			)
		}
		configuration.attributeSets = append(
			configuration.attributeSets,
			attributeSet,
		)
	}
	return configuration, nil
}

func parseDynlistAttributeSet(arguments []string) (dynlistAttributeSet, error) {
	if len(arguments) < 2 {
		return dynlistAttributeSet{}, errors.New(
			"requires a group objectClass and URL attribute",
		)
	}
	attributeSet := dynlistAttributeSet{objectClass: arguments[0]}
	index := 1
	if dynlistLDAPURLArgument(arguments[index]) {
		restriction, err := parseDynlistLDAPURL(arguments[index])
		if err != nil {
			return dynlistAttributeSet{}, fmt.Errorf(
				"unable to parse URI %q: %w",
				arguments[index],
				err,
			)
		}
		if restriction.filterErr != nil {
			return dynlistAttributeSet{}, fmt.Errorf(
				"unable to parse URI %q: %w",
				arguments[index],
				restriction.filterErr,
			)
		}
		if len(restriction.attributes) != 0 {
			return dynlistAttributeSet{}, errors.New(
				"attrset URI must not contain attributes",
			)
		}
		if restriction.extensions != "" {
			return dynlistAttributeSet{}, errors.New(
				"attrset URI must not contain extensions",
			)
		}
		attributeSet.restriction = &restriction
		index++
	}
	if index >= len(arguments) {
		return dynlistAttributeSet{}, errors.New("URL attribute is missing")
	}
	attributeSet.urlAttribute = arguments[index]
	index++
	for ; index < len(arguments); index++ {
		mapping, err := parseDynlistAttributeMapping(arguments[index])
		if err != nil {
			return dynlistAttributeSet{}, fmt.Errorf(
				"attribute mapping %q: %w",
				arguments[index],
				err,
			)
		}
		attributeSet.mappings = append(attributeSet.mappings, mapping)
	}
	return attributeSet, nil
}

func parseDynlistAttributeMapping(raw string) (dynlistAttributeMapping, error) {
	mapping := dynlistAttributeMapping{}
	memberPart := raw
	if plus := strings.IndexByte(memberPart, '+'); plus >= 0 {
		memberOfPart := memberPart[plus+1:]
		memberPart = memberPart[:plus]
		if strings.HasSuffix(memberOfPart, "*") {
			mapping.nested = true
			memberOfPart = strings.TrimSuffix(memberOfPart, "*")
		}
		if strings.Contains(memberOfPart, "*") {
			return dynlistAttributeMapping{}, errors.New(
				"nested marker must be the final character",
			)
		}
		if at := strings.IndexByte(memberOfPart, '@'); at >= 0 {
			mapping.staticObjectClass = memberOfPart[at+1:]
			memberOfPart = memberOfPart[:at]
			if mapping.staticObjectClass == "" {
				return dynlistAttributeMapping{}, errors.New(
					"static objectClass is empty",
				)
			}
		}
		mapping.memberOfAttribute = memberOfPart
		if mapping.memberOfAttribute == "" {
			return dynlistAttributeMapping{}, errors.New(
				"memberOf attribute is empty",
			)
		}
	}
	if colon := strings.IndexByte(memberPart, ':'); colon >= 0 {
		mapping.mappedAttribute = memberPart[:colon]
		mapping.memberAttribute = memberPart[colon+1:]
		if mapping.mappedAttribute == "" {
			return dynlistAttributeMapping{}, errors.New(
				"mapped attribute is empty",
			)
		}
	} else {
		mapping.memberAttribute = memberPart
	}
	if mapping.memberAttribute == "" {
		return dynlistAttributeMapping{}, errors.New("member attribute is empty")
	}
	return mapping, nil
}

func loadDynamicGroupRuntimeConfiguration(
	entry directory.Entry,
	database runtimeDatabase,
) (dynamicGroupRuntimeConfiguration, error) {
	if databaseType(database.name) == "frontend" {
		return dynamicGroupRuntimeConfiguration{}, fmt.Errorf(
			"%s dyngroup overlay cannot be global",
			entry.DN,
		)
	}
	configuration := dynamicGroupRuntimeConfiguration{}
	for _, raw := range valuesForAttributeAliases(
		entry,
		"olcDynGroupAttrPair",
		"olcDGAttrPair",
	) {
		arguments, err := tokenizeOpenLDAPConfig(string(raw))
		if err != nil {
			return dynamicGroupRuntimeConfiguration{}, fmt.Errorf(
				"%s olcDynGroupAttrPair: %w",
				entry.DN,
				err,
			)
		}
		if len(arguments) != 2 {
			return dynamicGroupRuntimeConfiguration{}, fmt.Errorf(
				"%s olcDynGroupAttrPair requires member and URL attributes",
				entry.DN,
			)
		}
		configuration.pairs = append(configuration.pairs, dynamicGroupAttributePair{
			memberAttribute: arguments[0],
			urlAttribute:    arguments[1],
		})
	}
	return configuration, nil
}

func valuesForAttributeAliases(entry directory.Entry, names ...string) [][]byte {
	var values [][]byte
	for _, name := range names {
		values = append(values, entry.Values(name)...)
	}
	return values
}

func stripDynlistOrderingPrefix(value string) (string, error) {
	value, _, _, err := parseDynlistOrderingPrefix(value)
	return value, err
}

func parseDynlistOrderingPrefix(value string) (string, int, bool, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{") {
		return value, 0, false, nil
	}
	end := strings.IndexByte(value, '}')
	if end < 2 {
		return "", 0, false, errors.New("invalid ordered dynlist prefix")
	}
	order, err := strconv.Atoi(value[1:end])
	if err != nil || order < 0 {
		return "", 0, false, fmt.Errorf(
			"invalid ordered dynlist prefix %q",
			value[:end+1],
		)
	}
	return strings.TrimSpace(value[end+1:]), order, true, nil
}

func orderedDynlistAttributeSetValues(values [][]byte) ([]string, error) {
	type orderedValue struct {
		value    string
		order    int
		ordered  bool
		sequence int
	}
	parsed := make([]orderedValue, 0, len(values))
	maxOrder := -1
	for sequence, raw := range values {
		value, order, ordered, err := parseDynlistOrderingPrefix(string(raw))
		if err != nil {
			return nil, err
		}
		if ordered && order > maxOrder {
			maxOrder = order
		}
		parsed = append(parsed, orderedValue{
			value:    value,
			order:    order,
			ordered:  ordered,
			sequence: sequence,
		})
	}
	for index := range parsed {
		if parsed[index].ordered {
			continue
		}
		maxOrder++
		parsed[index].order = maxOrder
	}
	sort.SliceStable(parsed, func(left, right int) bool {
		if parsed[left].order == parsed[right].order {
			return parsed[left].sequence < parsed[right].sequence
		}
		return parsed[left].order < parsed[right].order
	})
	result := make([]string, len(parsed))
	for index := range parsed {
		result[index] = parsed[index].value
	}
	return result, nil
}

func validateDynlistSchema(
	registry *schema.Registry,
	configuration *dynlistRuntimeConfiguration,
) error {
	if configuration == nil {
		return nil
	}
	for index := range configuration.attributeSets {
		attributeSet := &configuration.attributeSets[index]
		if _, found := registry.ObjectClass(attributeSet.objectClass); !found {
			return fmt.Errorf(
				"olcDynListAttrSet references undefined objectClass %q",
				attributeSet.objectClass,
			)
		}
		if err := validateDynlistAttribute(registry, attributeSet.urlAttribute); err != nil {
			return err
		}
		if !registry.AttributeDescriptionSubtype(
			attributeSet.urlAttribute,
			"labeledURI",
		) {
			return fmt.Errorf(
				"dynlist URL attribute %q is not a subtype of labeledURI",
				attributeSet.urlAttribute,
			)
		}
		for _, mapping := range attributeSet.mappings {
			for _, attribute := range []string{
				mapping.memberAttribute,
				mapping.mappedAttribute,
				mapping.memberOfAttribute,
			} {
				if attribute == "" {
					continue
				}
				if err := validateDynlistAttribute(registry, attribute); err != nil {
					return err
				}
			}
			if mapping.staticObjectClass != "" {
				if _, found := registry.ObjectClass(mapping.staticObjectClass); !found {
					return fmt.Errorf(
						"dynlist references undefined static objectClass %q",
						mapping.staticObjectClass,
					)
				}
			}
		}
	}
	return nil
}

func validateDynamicGroupSchema(
	registry *schema.Registry,
	configuration *dynamicGroupRuntimeConfiguration,
) error {
	if configuration == nil {
		return nil
	}
	for _, pair := range configuration.pairs {
		if err := validateDynlistAttribute(registry, pair.memberAttribute); err != nil {
			return err
		}
		if err := validateDynlistAttribute(registry, pair.urlAttribute); err != nil {
			return err
		}
		if !registry.AttributeDescriptionSubtype(pair.urlAttribute, "labeledURI") {
			return fmt.Errorf(
				"dyngroup URL attribute %q is not a subtype of labeledURI",
				pair.urlAttribute,
			)
		}
	}
	return nil
}

func validateDynlistAttribute(registry *schema.Registry, attribute string) error {
	if _, found := registry.AttributeType(attribute); !found {
		return fmt.Errorf("dynlist references undefined attribute type %q", attribute)
	}
	return nil
}

func parseDynlistLDAPURL(raw string) (dynlistLDAPURL, error) {
	raw, err := normalizeDynlistLDAPURL(raw)
	if err != nil {
		return dynlistLDAPURL{}, err
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return dynlistLDAPURL{}, fmt.Errorf("parse LDAP URL: %w", err)
	}
	if !dynlistLocalLDAPScheme(parsed.Scheme) ||
		parsed.Hostname() != "" ||
		parsed.User != nil ||
		parsed.Fragment != "" {
		return dynlistLDAPURL{}, errors.New("URL must be a local LDAP URL")
	}
	result := dynlistLDAPURL{scope: directory.ScopeBase}
	rawBase := strings.TrimPrefix(parsed.EscapedPath(), "/")
	baseText, err := url.PathUnescape(rawBase)
	if err != nil {
		return dynlistLDAPURL{}, fmt.Errorf("decode LDAP URL base: %w", err)
	}
	base, err := directory.ParseDN(baseText)
	if err != nil {
		return dynlistLDAPURL{}, fmt.Errorf("LDAP URL base: %w", err)
	}
	result.base = base
	result.baseSet = baseText != ""

	components := strings.Split(parsed.RawQuery, "?")
	if parsed.RawQuery == "" {
		components = nil
	}
	if len(components) > 4 {
		return dynlistLDAPURL{}, errors.New("LDAP URL has too many components")
	}
	hasExtensions := len(components) == 4
	for len(components) < 4 {
		components = append(components, "")
	}
	attributesText, err := url.PathUnescape(components[0])
	if err != nil {
		return dynlistLDAPURL{}, fmt.Errorf("decode LDAP URL attributes: %w", err)
	}
	if attributesText != "" {
		for _, attribute := range strings.Split(attributesText, ",") {
			attribute = strings.TrimSpace(attribute)
			if attribute == "" {
				return dynlistLDAPURL{}, errors.New("LDAP URL contains an empty attribute")
			}
			result.attributes = append(result.attributes, attribute)
		}
	}
	scopeText, err := url.PathUnescape(components[1])
	if err != nil {
		return dynlistLDAPURL{}, fmt.Errorf("decode LDAP URL scope: %w", err)
	}
	switch strings.ToLower(scopeText) {
	case "", "base":
	case "one", "onelevel":
		result.scope = directory.ScopeSingleLevel
	case "sub", "subtree":
		result.scope = directory.ScopeWholeSubtree
	case "children", "subord", "subordinate":
		result.scope = directory.ScopeChildren
	default:
		return dynlistLDAPURL{}, fmt.Errorf("LDAP URL has unknown scope %q", scopeText)
	}
	filterText, err := url.PathUnescape(components[2])
	if err != nil {
		return dynlistLDAPURL{}, fmt.Errorf("decode LDAP URL filter: %w", err)
	}
	if filterText != "" {
		result.filter, err = compileSyncConsumerFilter(filterText)
		if err != nil {
			result.filterErr = fmt.Errorf("LDAP URL filter: %w", err)
		} else {
			result.filterSet = true
		}
	}
	result.extensions, err = url.PathUnescape(components[3])
	if err != nil {
		return dynlistLDAPURL{}, fmt.Errorf("decode LDAP URL extensions: %w", err)
	}
	if hasExtensions && result.extensions == "" {
		return dynlistLDAPURL{}, errors.New("LDAP URL contains an empty extension")
	}
	return result, nil
}

func dynlistLDAPURLArgument(raw string) bool {
	return len(raw) >= len("ldap://") &&
		strings.EqualFold(raw[:len("ldap://")], "ldap://")
}

func normalizeDynlistLDAPURL(raw string) (string, error) {
	if strings.HasPrefix(raw, "<") {
		if !strings.HasSuffix(raw, ">") {
			return "", errors.New("LDAP URL has an invalid enclosure")
		}
		raw = strings.TrimSuffix(strings.TrimPrefix(raw, "<"), ">")
	}
	if len(raw) >= len("URL:") && strings.EqualFold(raw[:len("URL:")], "URL:") {
		raw = raw[len("URL:"):]
	}
	return raw, nil
}

func dynlistLocalLDAPScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "ldap", "ldaps", "ldapi", "pldap", "pldaps":
		return true
	default:
		return false
	}
}

type dynlistProjectionCache struct {
	ctx       context.Context
	server    *Server
	runtime   *runtimeState
	reader    storage.Reader
	subjectDN string
	request   dynlistProjectionRequest
	plans     map[string]*dynlistProjectionPlan
}

type dynlistProjectionRequest struct {
	attributes       []string
	filter           *directory.Filter
	compareAttribute string
}

type dynlistProjectionPlan struct {
	entries           map[string]directory.Entry
	projections       map[string]directory.Entry
	filterProjections map[string]directory.Entry
}

func newDynlistProjectionCache(
	ctx context.Context,
	server *Server,
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
	request dynlistProjectionRequest,
) *dynlistProjectionCache {
	return &dynlistProjectionCache{
		ctx:       ctx,
		server:    server,
		runtime:   runtime,
		reader:    reader,
		subjectDN: subjectDN,
		request:   request,
		plans:     make(map[string]*dynlistProjectionPlan),
	}
}

func (cache *dynlistProjectionCache) apply(
	database runtimeDatabase,
	entry directory.Entry,
) (directory.Entry, directory.Entry, error) {
	if database.dynlist == nil {
		return entry, entry, nil
	}
	plan, err := cache.plan(database)
	if err != nil {
		return directory.Entry{}, directory.Entry{}, err
	}
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return directory.Entry{}, directory.Entry{}, err
	}
	projected, found := plan.projections[dn.Key()]
	if !found {
		return entry, entry, nil
	}
	filterEntry := entry
	if !database.dynlist.simple {
		if filtered, found := plan.filterProjections[dn.Key()]; found {
			filterEntry = filtered.Clone()
		}
	}
	return projected.Clone(), filterEntry, nil
}

func (cache *dynlistProjectionCache) plan(
	database runtimeDatabase,
) (*dynlistProjectionPlan, error) {
	if plan, found := cache.plans[database.partition]; found {
		return plan, nil
	}
	plan := &dynlistProjectionPlan{
		entries:           make(map[string]directory.Entry),
		projections:       make(map[string]directory.Entry),
		filterProjections: make(map[string]directory.Entry),
	}
	cache.plans[database.partition] = plan
	reader := readerForDatabase(cache.reader, database)
	if err := reader.ForEach(func(entry directory.Entry) error {
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		plan.entries[dn.Key()] = entry
		return nil
	}); err != nil {
		delete(cache.plans, database.partition)
		return nil, err
	}

	for setIndex := range database.dynlist.attributeSets {
		attributeSet := &database.dynlist.attributeSets[setIndex]
		for key, entry := range plan.entries {
			applies, err := dynlistAttributeSetApplies(
				cache.runtime.schema,
				*attributeSet,
				entry,
			)
			if err != nil {
				return nil, err
			}
			if !applies {
				continue
			}
			projected := plan.projectedEntry(key, entry)
			if err := cache.expandEntry(database, *attributeSet, &projected); err != nil {
				return nil, err
			}
			plan.projections[key] = projected
			if !database.dynlist.simple && len(attributeSet.mappings) > 0 {
				filterProjected := plan.filterProjectedEntry(key, entry)
				for _, mapping := range attributeSet.mappings {
					if err := copyDynlistAttributeValues(
						cache.runtime.schema,
						projected,
						&filterProjected,
						mapping.outputAttribute(),
					); err != nil {
						return nil, err
					}
				}
				plan.filterProjections[key] = filterProjected
			}
		}
		if !database.dynlist.simple {
			for mappingIndex := range attributeSet.mappings {
				mapping := attributeSet.mappings[mappingIndex]
				if mapping.memberOfAttribute == "" {
					continue
				}
				wantMemberOf := cache.attributeWanted(mapping.memberOfAttribute)
				wantNestedMember := mapping.nested &&
					cache.request.compareAttribute == "" &&
					cache.attributeRequested(mapping.memberOfAttribute) &&
					cache.attributeRequested(mapping.outputAttribute())
				if !wantMemberOf && !wantNestedMember {
					continue
				}
				if err := cache.applyMembershipModel(
					database,
					plan,
					*attributeSet,
					mapping,
					wantMemberOf,
					wantNestedMember,
				); err != nil {
					return nil, err
				}
			}
		}
	}
	return plan, nil
}

func (plan *dynlistProjectionPlan) projectedEntry(
	key string,
	fallback directory.Entry,
) directory.Entry {
	if entry, found := plan.projections[key]; found {
		return entry.Clone()
	}
	return fallback.Clone()
}

func (plan *dynlistProjectionPlan) filterProjectedEntry(
	key string,
	fallback directory.Entry,
) directory.Entry {
	if entry, found := plan.filterProjections[key]; found {
		return entry.Clone()
	}
	return fallback.Clone()
}

func dynlistAttributeSetApplies(
	registry *schema.Registry,
	attributeSet dynlistAttributeSet,
	entry directory.Entry,
) (bool, error) {
	if !registry.EntryHasObjectClass(entry, attributeSet.objectClass) {
		return false, nil
	}
	if attributeSet.restriction == nil {
		return true, nil
	}
	restriction := attributeSet.restriction
	if restriction.baseSet {
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return false, err
		}
		if !directory.InScope(restriction.base, dn, restriction.scope) {
			return false, nil
		}
	}
	if !restriction.filterSet {
		return true, nil
	}
	return restriction.filter.MatchWith(entry, registry)
}

func (cache *dynlistProjectionCache) expandEntry(
	database runtimeDatabase,
	attributeSet dynlistAttributeSet,
	entry *directory.Entry,
) error {
	subjectDN, authorized, err := cache.expansionIdentity(database, *entry)
	if err != nil || !authorized {
		return err
	}
	urls := cache.runtime.schema.AttributeValues(*entry, attributeSet.urlAttribute)
	for _, rawURL := range urls {
		parsed, err := parseDynlistLDAPURL(string(rawURL))
		if err != nil || parsed.filterErr != nil {
			continue
		}
		results, err := cache.searchURL(parsed, attributeSet, subjectDN)
		if err != nil {
			return err
		}
		oldStyleGroup := len(attributeSet.mappings) == 1 &&
			attributeSet.mappings[0].mappedAttribute == "" &&
			len(parsed.attributes) == 0
		if oldStyleGroup {
			for _, result := range results {
				if err := addDynlistValue(
					cache.runtime.schema,
					entry,
					attributeSet.mappings[0].memberAttribute,
					[]byte(result.DN),
				); err != nil {
					return err
				}
			}
			continue
		}
		if len(attributeSet.mappings) > 0 &&
			!dynlistHasMappedAttribute(attributeSet.mappings) {
			continue
		}
		for _, result := range results {
			for _, attribute := range result.Attributes {
				if len(parsed.attributes) == 0 &&
					!cache.attributeRequested(attribute.Description) {
					continue
				}
				destination := dynlistMappedAttribute(
					cache.runtime.schema,
					attributeSet.mappings,
					attribute.Description,
				)
				for _, value := range attribute.Values {
					if strings.EqualFold(attribute.Description, "objectClass") &&
						dynlistStructuralObjectClass(cache.runtime.schema, value) {
						continue
					}
					if err := addDynlistValue(
						cache.runtime.schema,
						entry,
						destination,
						value,
					); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func dynlistHasMappedAttribute(mappings []dynlistAttributeMapping) bool {
	for _, mapping := range mappings {
		if mapping.mappedAttribute != "" {
			return true
		}
	}
	return false
}

func dynlistMappedAttribute(
	registry *schema.Registry,
	mappings []dynlistAttributeMapping,
	source string,
) string {
	for _, mapping := range mappings {
		if dynlistAttributeDescriptionsEqual(registry, source, mapping.memberAttribute) &&
			mapping.mappedAttribute != "" {
			return mapping.mappedAttribute
		}
	}
	return source
}

func dynlistStructuralObjectClass(registry *schema.Registry, value []byte) bool {
	objectClass, found := registry.ObjectClass(string(value))
	return found && objectClass.Kind == schema.ObjectClassStructural
}

func (cache *dynlistProjectionCache) expansionIdentity(
	database runtimeDatabase,
	entry directory.Entry,
) (string, bool, error) {
	identities := cache.runtime.schema.AttributeValues(entry, "dgIdentity")
	if len(identities) == 0 {
		return cache.subjectDN, true, nil
	}
	identity, err := directory.ParseDN(string(identities[0]))
	if err != nil {
		return "", false, nil
	}
	authorizations := cache.runtime.schema.AttributeValues(entry, "dgAuthz")
	if identity.Depth() != 0 && len(authorizations) > 0 &&
		!cache.server.isRoot(cache.runtime, cache.subjectDN, entry.DN, "") {
		authenticationDN, err := directory.ParseDN(cache.subjectDN)
		if err != nil {
			return "", false, nil
		}
		authorized := false
		for _, authorization := range authorizations {
			matched, matchErr := cache.server.authorizationRuleMatches(
				cache.ctx,
				cache.runtime,
				authenticationDN,
				string(authorization),
				authenticationDN,
			)
			if matchErr != nil {
				continue
			}
			if matched {
				authorized = true
				break
			}
		}
		if !authorized {
			return "", false, nil
		}
	}
	return identity.String(), true, nil
}

func (cache *dynlistProjectionCache) searchURL(
	parsed dynlistLDAPURL,
	attributeSet dynlistAttributeSet,
	subjectDN string,
) ([]directory.Entry, error) {
	routes := databaseSearchRoutes(cache.runtime.databases, parsed.base, parsed.scope)
	if len(routes) == 0 {
		return nil, nil
	}
	primary := &cache.runtime.databases[routes[0].databaseIndex]
	primaryReader := readerForDatabase(cache.reader, *primary)
	baseEntry, err := primaryReader.Get(parsed.base)
	if err != nil {
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if !cache.server.allowed(
		cache.runtime,
		primaryReader,
		subjectDN,
		baseEntry,
		"entry",
		nil,
		acl.Search,
	) {
		return nil, nil
	}

	var results []directory.Entry
	collectivePlans := newCollectiveAttributePlanCache(cache.runtime.schema)
	for _, route := range routes {
		database := &cache.runtime.databases[route.databaseIndex]
		reader := readerForDatabase(cache.reader, *database)
		err := reader.ForEach(func(entry directory.Entry) error {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			if !directory.InScope(route.base, dn, route.scope) {
				return nil
			}
			entry, err = collectivePlans.apply(database.partition, reader, entry)
			if err != nil {
				return err
			}
			if !subentrySearchVisible(cache.runtime, entry, parsed.scope, nil) {
				return nil
			}
			if (!parsed.filterSet || len(parsed.attributes) > 0) &&
				cache.runtime.schema.EntryHasObjectClass(entry, attributeSet.objectClass) {
				return nil
			}
			if parsed.filterSet {
				matches, err := cache.server.filterMatches(
					cache.runtime,
					reader,
					subjectDN,
					entry,
					parsed.filter,
				)
				if err != nil || !matches {
					return err
				}
			}
			if !cache.server.allowed(
				cache.runtime,
				reader,
				subjectDN,
				entry,
				"entry",
				nil,
				acl.Read,
			) {
				return nil
			}
			readable := cache.server.attributesWithPrivilege(
				cache.runtime,
				reader,
				subjectDN,
				entry,
				acl.Read,
				false,
			)
			if len(parsed.attributes) > 0 {
				readable = readable.SelectWithMatcher(
					parsed.attributes,
					false,
					cache.runtime.schema.IsOperational,
					cache.runtime.schema.AttributeDescriptionSubtype,
				)
			} else {
				readable = readable.SelectWithMatcher(
					nil,
					false,
					cache.runtime.schema.IsOperational,
					cache.runtime.schema.AttributeDescriptionSubtype,
				)
			}
			results = append(results, readable)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.SliceStable(results, func(i, j int) bool {
		left, leftErr := directory.ParseDN(results[i].DN)
		right, rightErr := directory.ParseDN(results[j].DN)
		if leftErr != nil || rightErr != nil {
			return results[i].DN < results[j].DN
		}
		return left.Key() < right.Key()
	})
	return results, nil
}

type dynlistMembershipNode struct {
	entry   directory.Entry
	direct  []directory.DN
	dynamic bool
}

func (cache *dynlistProjectionCache) applyMembershipModel(
	database runtimeDatabase,
	plan *dynlistProjectionPlan,
	attributeSet dynlistAttributeSet,
	mapping dynlistAttributeMapping,
	wantMemberOf bool,
	wantNestedMember bool,
) error {
	nodes := make(map[string]*dynlistMembershipNode)
	reader := readerForDatabase(cache.reader, database)
	for key, rawEntry := range plan.entries {
		dynamic, err := dynlistAttributeSetApplies(
			cache.runtime.schema,
			attributeSet,
			rawEntry,
		)
		if err != nil {
			return err
		}
		static := mapping.staticObjectClass != "" &&
			cache.runtime.schema.EntryHasObjectClass(
				rawEntry,
				mapping.staticObjectClass,
			)
		if !dynamic && !static {
			continue
		}
		if !cache.server.allowed(
			cache.runtime,
			reader,
			cache.subjectDN,
			rawEntry,
			"entry",
			nil,
			acl.Read,
		) {
			continue
		}
		logical := rawEntry
		memberAttribute := mapping.memberAttribute
		node := &dynlistMembershipNode{entry: rawEntry, dynamic: dynamic}
		if dynamic {
			for _, rawURL := range cache.runtime.schema.AttributeValues(
				rawEntry,
				attributeSet.urlAttribute,
			) {
				parsed, err := parseDynlistLDAPURL(string(rawURL))
				if err != nil || parsed.filterErr != nil ||
					len(parsed.attributes) > 0 || parsed.extensions != "" {
					continue
				}
				results, err := cache.searchURL(
					parsed,
					dynlistAttributeSet{},
					cache.subjectDN,
				)
				if err != nil {
					return err
				}
				for _, result := range results {
					memberDN, err := directory.ParseDN(result.DN)
					if err == nil {
						node.direct = appendDynlistDN(node.direct, memberDN)
					}
				}
			}
			nodes[key] = node
			continue
		}
		for _, value := range cache.runtime.schema.AttributeValues(
			logical,
			memberAttribute,
		) {
			if !cache.server.allowed(
				cache.runtime,
				reader,
				cache.subjectDN,
				logical,
				memberAttribute,
				value,
				acl.Read,
			) {
				continue
			}
			memberDN, err := directory.ParseDN(string(value))
			if err == nil {
				node.direct = appendDynlistDN(node.direct, memberDN)
			}
		}
		nodes[key] = node
	}

	for key, node := range nodes {
		members := append([]directory.DN(nil), node.direct...)
		if mapping.nested && wantMemberOf {
			members = dynlistNestedMembers(key, nodes, make(map[string]bool))
		}
		if wantNestedMember {
			nestedMembers := dynlistNestedMembers(key, nodes, make(map[string]bool))
			projected := plan.projectedEntry(key, node.entry)
			for _, member := range nestedMembers {
				if err := addDynlistValue(
					cache.runtime.schema,
					&projected,
					mapping.outputAttribute(),
					[]byte(member.String()),
				); err != nil {
					return err
				}
			}
			plan.projections[key] = projected
			filterProjected := plan.filterProjectedEntry(key, node.entry)
			if err := copyDynlistAttributeValues(
				cache.runtime.schema,
				projected,
				&filterProjected,
				mapping.outputAttribute(),
			); err != nil {
				return err
			}
			plan.filterProjections[key] = filterProjected
		}
		if !wantMemberOf {
			continue
		}
		groupDN, err := directory.ParseDN(node.entry.DN)
		if err != nil {
			return err
		}
		for _, member := range members {
			memberKey := member.Key()
			memberEntry, found := plan.entries[memberKey]
			if !found {
				continue
			}
			projected := plan.projectedEntry(memberKey, memberEntry)
			if err := addDynlistValue(
				cache.runtime.schema,
				&projected,
				mapping.memberOfAttribute,
				[]byte(groupDN.String()),
			); err != nil {
				return err
			}
			plan.projections[memberKey] = projected
			filterProjected := plan.filterProjectedEntry(memberKey, memberEntry)
			if err := addDynlistValue(
				cache.runtime.schema,
				&filterProjected,
				mapping.memberOfAttribute,
				[]byte(groupDN.String()),
			); err != nil {
				return err
			}
			plan.filterProjections[memberKey] = filterProjected
		}
	}
	return nil
}

func copyDynlistAttributeValues(
	registry *schema.Registry,
	source directory.Entry,
	target *directory.Entry,
	description string,
) error {
	for _, value := range registry.AttributeValues(source, description) {
		if err := addDynlistValue(registry, target, description, value); err != nil {
			return err
		}
	}
	return nil
}

func (cache *dynlistProjectionCache) attributeWanted(attribute string) bool {
	return cache.attributeRequested(attribute) || cache.filterReferences(attribute)
}

func (cache *dynlistProjectionCache) attributeRequested(attribute string) bool {
	if cache.request.compareAttribute != "" {
		return dynlistAttributeDescriptionsEqual(
			cache.runtime.schema,
			cache.request.compareAttribute,
			attribute,
		)
	}
	allUserAttributes := len(cache.request.attributes) == 0
	allOperationalAttributes := false
	for _, requested := range cache.request.attributes {
		switch {
		case strings.EqualFold(requested, "*"):
			allUserAttributes = true
		case strings.EqualFold(requested, "+"):
			allOperationalAttributes = true
		case dynlistAttributeDescriptionsEqual(
			cache.runtime.schema,
			requested,
			attribute,
		):
			return true
		}
	}
	if cache.runtime.schema.IsOperational(attribute) {
		return allOperationalAttributes
	}
	return allUserAttributes
}

func (cache *dynlistProjectionCache) filterReferences(attribute string) bool {
	if cache.request.filter == nil {
		return false
	}
	return dynlistFilterReferencesAttribute(
		cache.runtime.schema,
		*cache.request.filter,
		attribute,
	)
}

func dynlistFilterReferencesAttribute(
	registry *schema.Registry,
	filter directory.Filter,
	attribute string,
) bool {
	if filter.Attribute != "" && dynlistAttributeDescriptionsEqual(
		registry,
		filter.Attribute,
		attribute,
	) {
		return true
	}
	for _, child := range filter.Children {
		if dynlistFilterReferencesAttribute(registry, child, attribute) {
			return true
		}
	}
	return false
}

func dynlistFilterReferencesMemberOf(
	registry *schema.Registry,
	database runtimeDatabase,
	filter directory.Filter,
) bool {
	if database.dynlist == nil || database.dynlist.simple {
		return false
	}
	for _, attributeSet := range database.dynlist.attributeSets {
		for _, mapping := range attributeSet.mappings {
			if mapping.memberOfAttribute != "" &&
				dynlistFilterReferencesAttribute(
					registry,
					filter,
					mapping.memberOfAttribute,
				) {
				return true
			}
		}
	}
	return false
}

func dynlistNestedMembers(
	key string,
	nodes map[string]*dynlistMembershipNode,
	visiting map[string]bool,
) []directory.DN {
	if visiting[key] {
		return nil
	}
	visiting[key] = true
	node := nodes[key]
	if node == nil {
		delete(visiting, key)
		return nil
	}
	var members []directory.DN
	for _, member := range node.direct {
		members = appendDynlistDN(members, member)
		if _, isGroup := nodes[member.Key()]; isGroup {
			for _, nested := range dynlistNestedMembers(
				member.Key(),
				nodes,
				visiting,
			) {
				members = appendDynlistDN(members, nested)
			}
		}
	}
	delete(visiting, key)
	return members
}

func appendDynlistDN(values []directory.DN, value directory.DN) []directory.DN {
	for _, existing := range values {
		if existing.Equal(value) {
			return values
		}
	}
	return append(values, value)
}

func addDynlistValue(
	registry *schema.Registry,
	entry *directory.Entry,
	description string,
	value []byte,
) error {
	attributeType, found, err := registry.EffectiveAttributeType(description)
	if err != nil {
		return err
	}
	index := -1
	for candidate := range entry.Attributes {
		if dynlistAttributeDescriptionsEqual(
			registry,
			entry.Attributes[candidate].Description,
			description,
		) {
			index = candidate
			break
		}
	}
	if index >= 0 {
		if found && attributeType.SingleValue &&
			len(entry.Attributes[index].Values) > 0 {
			return nil
		}
		for _, existing := range entry.Attributes[index].Values {
			equal := bytes.Equal(existing, value)
			if comparison, compareErr := registry.Compare(
				description,
				"",
				existing,
				value,
			); compareErr == nil {
				equal = comparison == 0
			}
			if equal {
				return nil
			}
		}
		entry.Attributes[index].Values = append(
			entry.Attributes[index].Values,
			bytes.Clone(value),
		)
		return nil
	}
	entry.Attributes = append(entry.Attributes, directory.Attribute{
		Description: description,
		Values:      [][]byte{bytes.Clone(value)},
	})
	return nil
}

func dynlistAttributeDescriptionsEqual(
	registry *schema.Registry,
	left,
	right string,
) bool {
	return registry.AttributeDescriptionSubtype(left, right) &&
		registry.AttributeDescriptionSubtype(right, left)
}

func (cache *dynlistProjectionCache) dynamicListDNCompare(
	database runtimeDatabase,
	entry directory.Entry,
	attribute string,
	assertion []byte,
) (bool, bool, error) {
	if database.dynlist == nil {
		return false, false, nil
	}
	for _, attributeSet := range database.dynlist.attributeSets {
		applies, err := dynlistAttributeSetApplies(
			cache.runtime.schema,
			attributeSet,
			entry,
		)
		if err != nil {
			return false, false, err
		}
		if !applies {
			continue
		}
		for _, mapping := range attributeSet.mappings {
			if !cache.runtime.schema.IsDNValued(mapping.outputAttribute()) ||
				!dynlistAttributeDescriptionsEqual(
					cache.runtime.schema,
					mapping.outputAttribute(),
					attribute,
				) {
				continue
			}
			assertedDN, err := directory.ParseDN(string(assertion))
			if err != nil {
				return true, false, nil
			}
			_, authorized, err := cache.expansionIdentity(database, entry)
			if err != nil {
				return true, false, err
			}
			if !authorized {
				return true, false, operationFailed(
					ldapwire.ResultInappropriateAuthentication,
					"dynamic group identity is not authorized",
				)
			}
			urls := cache.runtime.schema.AttributeValues(
				entry,
				attributeSet.urlAttribute,
			)
			if len(urls) == 0 {
				return false, false, nil
			}
			for _, rawURL := range urls {
				parsed, err := parseDynlistLDAPURL(string(rawURL))
				if err != nil || len(parsed.attributes) > 0 || parsed.extensions != "" {
					continue
				}
				if parsed.filterErr != nil {
					return true, false, operationFailed(
						ldapwire.ResultOther,
						parsed.filterErr.Error(),
					)
				}
				if !directory.InScope(parsed.base, assertedDN, parsed.scope) {
					continue
				}
				targetDatabase := databaseForDN(cache.runtime, assertedDN)
				if targetDatabase == nil {
					continue
				}
				reader := readerForDatabase(cache.reader, *targetDatabase)
				target, err := reader.Get(assertedDN)
				if errors.Is(err, storage.ErrEntryNotFound) {
					continue
				}
				if err != nil {
					return true, false, err
				}
				if parsed.filterSet {
					matched, err := parsed.filter.MatchWith(target, cache.runtime.schema)
					if err != nil {
						return true, false, err
					}
					if !matched {
						continue
					}
				}
				return true, true, nil
			}
			return true, false, nil
		}
	}
	return false, false, nil
}

func (cache *dynlistProjectionCache) dynamicGroupCompare(
	database runtimeDatabase,
	entry directory.Entry,
	attribute string,
	assertion []byte,
) (bool, bool, error) {
	if database.dyngroup == nil ||
		cache.runtime.schema.HasAttributeDescription(entry, attribute) {
		return false, false, nil
	}
	for _, pair := range database.dyngroup.pairs {
		if !dynlistAttributeDescriptionsEqual(
			cache.runtime.schema,
			attribute,
			pair.memberAttribute,
		) {
			continue
		}
		memberDN, err := directory.ParseDN(string(assertion))
		if err != nil {
			return true, false, nil
		}
		urls := cache.runtime.schema.AttributeValues(
			entry,
			pair.urlAttribute,
		)
		if len(urls) == 0 {
			return false, false, nil
		}
		for _, rawURL := range urls {
			parsed, err := parseDynlistLDAPURL(string(rawURL))
			if err != nil || len(parsed.attributes) > 0 || parsed.extensions != "" {
				continue
			}
			if parsed.filterErr != nil {
				return true, false, operationFailed(
					ldapwire.ResultOther,
					parsed.filterErr.Error(),
				)
			}
			if !directory.InScope(parsed.base, memberDN, parsed.scope) {
				continue
			}
			targetDatabase := databaseForDN(cache.runtime, memberDN)
			if targetDatabase == nil {
				continue
			}
			reader := readerForDatabase(cache.reader, *targetDatabase)
			member, err := reader.Get(memberDN)
			if errors.Is(err, storage.ErrEntryNotFound) {
				continue
			}
			if err != nil {
				return true, false, err
			}
			if parsed.filterSet {
				matches, err := parsed.filter.MatchWith(
					member,
					cache.runtime.schema,
				)
				if err != nil || !matches {
					if err != nil {
						return true, false, err
					}
					continue
				}
			}
			return true, true, nil
		}
		return true, false, nil
	}
	return false, false, nil
}
