package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	nestGroupMaxEntries        = 100000
	nestGroupMaxEdges          = 500000
	nestGroupMaxTraversalDepth = 256
	nestGroupMaxExpandedValues = 100000
)

type nestGroupFlags uint8

const (
	nestGroupMemberValues nestGroupFlags = 1 << iota
	nestGroupMemberFilter
	nestGroupMemberOfValues
	nestGroupMemberOfFilter
)

type nestGroupRuntimeConfiguration struct {
	id                string
	memberAttribute   string
	memberOfAttribute string
	bases             []directory.DN
	flags             nestGroupFlags
	disabled          bool
}

type nestGroupConfigurationError struct {
	code       ldapwire.ResultCode
	diagnostic string
}

func (failure *nestGroupConfigurationError) Error() string {
	return failure.diagnostic
}

func nestGroupConfigurationFailure(
	code ldapwire.ResultCode,
	format string,
	arguments ...any,
) error {
	return &nestGroupConfigurationError{
		code:       code,
		diagnostic: fmt.Sprintf(format, arguments...),
	}
}

func nestGroupConfigurationResult(err error) (ldapwire.Result, bool) {
	var failure *nestGroupConfigurationError
	if !errors.As(err, &failure) {
		return ldapwire.Result{}, false
	}
	return ldapwire.ResultError(failure.code, failure.diagnostic), true
}

func loadNestGroupRuntimeConfiguration(
	entry directory.Entry,
) (nestGroupRuntimeConfiguration, error) {
	if err := validateNestGroupConfigurationAttributes(entry); err != nil {
		return nestGroupRuntimeConfiguration{}, err
	}
	configuration := nestGroupRuntimeConfiguration{
		id:                entry.DN,
		memberAttribute:   "member",
		memberOfAttribute: "memberOf",
	}
	var err error
	configuration.disabled, _, err = singleBoolean(entry, "olcDisabled")
	if err != nil {
		return nestGroupRuntimeConfiguration{}, nestGroupConfigurationFailure(
			ldapwire.ResultConstraintViolation,
			"%v",
			err,
		)
	}

	configuration.memberAttribute, err = nestGroupSingleAttribute(
		entry,
		"olcNestGroupMember",
		configuration.memberAttribute,
	)
	if err != nil {
		return nestGroupRuntimeConfiguration{}, err
	}
	configuration.memberOfAttribute, err = nestGroupSingleAttribute(
		entry,
		"olcNestGroupMemberOf",
		configuration.memberOfAttribute,
	)
	if err != nil {
		return nestGroupRuntimeConfiguration{}, err
	}

	for index, raw := range entry.Values("olcNestGroupBase") {
		base, parseErr := directory.ParseDN(string(raw))
		if parseErr != nil {
			return nestGroupRuntimeConfiguration{}, nestGroupConfigurationFailure(
				ldapwire.ResultInvalidAttributeSyntax,
				"%s olcNestGroupBase: value #%d invalid per syntax",
				entry.DN,
				index,
			)
		}
		configuration.bases = append(configuration.bases, base)
	}

	for _, raw := range entry.Values("olcNestGroupFlags") {
		value := strings.TrimSpace(string(raw))
		if strings.HasPrefix(value, "{") {
			if end := strings.IndexByte(value, '}'); end >= 0 {
				value = value[end+1:]
			}
		}
		if len(strings.Fields(value)) != 1 {
			return nestGroupRuntimeConfiguration{}, nestGroupConfigurationFailure(
				ldapwire.ResultOther,
				"Please insert multiple names as separate olcNestGroupFlags values",
			)
		}
		switch strings.ToLower(value) {
		case "member-values":
			configuration.flags |= nestGroupMemberValues
		case "member-filter":
			configuration.flags |= nestGroupMemberFilter
		case "memberof-values":
			configuration.flags |= nestGroupMemberOfValues
		case "memberof-filter":
			configuration.flags |= nestGroupMemberOfFilter
		default:
			return nestGroupRuntimeConfiguration{}, nestGroupConfigurationFailure(
				ldapwire.ResultOther,
				"<olcNestGroupFlags> unknown option %q",
				value,
			)
		}
	}
	return configuration, nil
}

func nestGroupSingleAttribute(
	entry directory.Entry,
	description,
	fallback string,
) (string, error) {
	values := entry.Values(description)
	if len(values) == 0 {
		return fallback, nil
	}
	if len(values) != 1 {
		return "", nestGroupConfigurationFailure(
			ldapwire.ResultConstraintViolation,
			"%s %s must be single-valued",
			entry.DN,
			description,
		)
	}
	value := strings.TrimSpace(string(values[0]))
	if value == "" || len(strings.Fields(value)) != 1 {
		return "", nestGroupConfigurationFailure(
			ldapwire.ResultConstraintViolation,
			"%s %s must contain one AttributeDescription",
			entry.DN,
			description,
		)
	}
	return value, nil
}

func validateNestGroupConfigurationAttributes(entry directory.Entry) error {
	allowed := map[string]struct{}{
		"objectclass":           {},
		"olcoverlay":            {},
		"olcnestgroupmember":    {},
		"olcnestgroupmemberof":  {},
		"olcnestgroupbase":      {},
		"olcnestgroupflags":     {},
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
		return nestGroupConfigurationFailure(
			ldapwire.ResultUndefinedAttributeType,
			"%s has undefined nestgroup configuration attribute %q",
			entry.DN,
			attribute.Description,
		)
	}
	return nil
}

func validateNestGroupSchema(
	registry *schema.Registry,
	configurations []nestGroupRuntimeConfiguration,
) error {
	for index := range configurations {
		configuration := &configurations[index]
		seenBases := make(map[string]struct{}, len(configuration.bases))
		for baseIndex := range configuration.bases {
			base, err := registry.NormalizeDN(configuration.bases[baseIndex].String())
			if err != nil {
				return nestGroupConfigurationFailure(
					ldapwire.ResultInvalidAttributeSyntax,
					"%s olcNestGroupBase contains invalid DN %q",
					configuration.id,
					configuration.bases[baseIndex].String(),
				)
			}
			if _, duplicate := seenBases[base.Key()]; duplicate {
				return nestGroupConfigurationFailure(
					ldapwire.ResultAttributeOrValueExists,
					"%s olcNestGroupBase contains duplicate DN %q",
					configuration.id,
					configuration.bases[baseIndex].String(),
				)
			}
			seenBases[base.Key()] = struct{}{}
			configuration.bases[baseIndex] = base
		}
		for _, item := range []struct {
			label             string
			configurationName string
			attribute         *string
		}{
			{
				label:             "member",
				configurationName: "olcNestGroupMember",
				attribute:         &configuration.memberAttribute,
			},
			{
				label:             "memberOf",
				configurationName: "olcNestGroupMemberOf",
				attribute:         &configuration.memberOfAttribute,
			},
		} {
			attributeType, found := registry.AttributeType(*item.attribute)
			if !found {
				return nestGroupConfigurationFailure(
					ldapwire.ResultConstraintViolation,
					"<%s> invalid AttributeDescription 17 (attribute type undefined): %q",
					item.configurationName,
					*item.attribute,
				)
			}
			if !registry.IsDNReferenceValued(*item.attribute) {
				return nestGroupConfigurationFailure(
					ldapwire.ResultOther,
					"%s attribute=%q must use DN (%s) or NAMEUID (%s) syntax",
					item.label,
					*item.attribute,
					schema.SyntaxDistinguishedName,
					schema.SyntaxNameAndOptionalUID,
				)
			}
			*item.attribute = attributeType.Name()
		}
	}
	return nil
}

func nestGroupConfigurationsForDatabase(
	databases []runtimeDatabase,
	database runtimeDatabase,
) []nestGroupRuntimeConfiguration {
	var configurations []nestGroupRuntimeConfiguration
	if databaseType(database.name) != "frontend" {
		for _, configuration := range database.nestGroups {
			if !configuration.disabled {
				configurations = append(configurations, configuration)
			}
		}
	}
	for index := range databases {
		if databaseType(databases[index].name) == "frontend" {
			for _, configuration := range databases[index].nestGroups {
				if !configuration.disabled {
					configurations = append(configurations, configuration)
				}
			}
		}
	}
	if databaseType(database.name) == "frontend" && len(configurations) == 0 {
		for _, configuration := range database.nestGroups {
			if !configuration.disabled {
				configurations = append(configurations, configuration)
			}
		}
	}
	return configurations
}

type nestGroupProjectionRequest struct {
	attributes []string
	typesOnly  bool
	filter     directory.Filter
}

type nestGroupProjectionCache struct {
	ctx       context.Context
	server    *Server
	runtime   *runtimeState
	reader    storage.Reader
	subjectDN string
	request   nestGroupProjectionRequest
	plans     map[string]*nestGroupDatabasePlan
	enabled   bool
}

type nestGroupDatabasePlan struct {
	database       runtimeDatabase
	reader         storage.Reader
	entries        map[string]nestGroupGraphEntry
	instances      []nestGroupInstanceGraph
	filter         directory.Filter
	filterPrepared bool
	recheckFilter  bool
}

type nestGroupGraphEntry struct {
	dn    directory.DN
	entry directory.Entry
}

type nestGroupInstanceGraph struct {
	configuration nestGroupRuntimeConfiguration
	direct        map[string][]nestGroupReference
	parents       map[string][]string
}

type nestGroupReference struct {
	raw        []byte
	normalized []byte
	dn         directory.DN
}

type nestGroupResourceLimitError struct {
	resource string
	limit    int
}

func (failure *nestGroupResourceLimitError) Error() string {
	return fmt.Sprintf("nestgroup %s limit %d exceeded", failure.resource, failure.limit)
}

func nestGroupResourceLimitResult(err error) (ldapwire.Result, bool) {
	var failure *nestGroupResourceLimitError
	if !errors.As(err, &failure) {
		return ldapwire.Result{}, false
	}
	return ldapwire.ResultError(
		ldapwire.ResultAdminLimitExceeded,
		failure.Error(),
	), true
}

func newNestGroupProjectionCache(
	ctx context.Context,
	server *Server,
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
	request nestGroupProjectionRequest,
) *nestGroupProjectionCache {
	enabled := false
	if runtime != nil {
		for index := range runtime.databases {
			if len(runtime.databases[index].nestGroups) != 0 {
				enabled = true
				break
			}
		}
	}
	var plans map[string]*nestGroupDatabasePlan
	if enabled {
		plans = make(map[string]*nestGroupDatabasePlan)
	}
	return &nestGroupProjectionCache{
		ctx:       ctx,
		server:    server,
		runtime:   runtime,
		reader:    reader,
		subjectDN: subjectDN,
		request:   request,
		plans:     plans,
		enabled:   enabled,
	}
}

func (cache *nestGroupProjectionCache) plan(
	database runtimeDatabase,
) (*nestGroupDatabasePlan, error) {
	if !cache.enabled {
		return &nestGroupDatabasePlan{}, nil
	}
	cacheKey := database.partition + "\x00" + database.configDNKey
	if plan, found := cache.plans[cacheKey]; found {
		return plan, nil
	}
	plan := &nestGroupDatabasePlan{
		database: database,
		reader:   readerForDatabase(cache.reader, database),
		entries:  make(map[string]nestGroupGraphEntry),
	}
	cache.plans[cacheKey] = plan
	configurations := nestGroupConfigurationsForDatabase(cache.runtime.databases, database)
	for _, configuration := range configurations {
		if len(configuration.bases) == 0 || configuration.flags == 0 {
			continue
		}
		plan.instances = append(plan.instances, nestGroupInstanceGraph{
			configuration: configuration,
			direct:        make(map[string][]nestGroupReference),
			parents:       make(map[string][]string),
		})
	}
	if len(plan.instances) == 0 {
		return plan, nil
	}
	if err := plan.reader.ForEach(func(entry directory.Entry) error {
		if err := cache.ctx.Err(); err != nil {
			return err
		}
		if len(plan.entries) >= nestGroupMaxEntries {
			return &nestGroupResourceLimitError{"entries", nestGroupMaxEntries}
		}
		dn, err := cache.runtime.schema.NormalizeDN(entry.DN)
		if err != nil {
			return err
		}
		plan.entries[dn.Key()] = nestGroupGraphEntry{dn: dn, entry: entry}
		return nil
	}); err != nil {
		delete(cache.plans, cacheKey)
		return nil, err
	}

	edges := 0
	for instanceIndex := range plan.instances {
		instance := &plan.instances[instanceIndex]
		for key, node := range plan.entries {
			values := cache.runtime.schema.AttributeValues(
				node.entry,
				instance.configuration.memberAttribute,
			)
			for _, raw := range values {
				if edges >= nestGroupMaxEdges {
					delete(cache.plans, cacheKey)
					return nil, &nestGroupResourceLimitError{"edges", nestGroupMaxEdges}
				}
				reference, err := nestGroupParseReference(
					cache.runtime.schema,
					instance.configuration.memberAttribute,
					raw,
				)
				if err != nil {
					return nil, err
				}
				instance.direct[key] = append(instance.direct[key], reference)
				if nestGroupDNInBases(node.dn, instance.configuration.bases) {
					valueKey := string(reference.normalized)
					instance.parents[valueKey] = appendUniqueString(
						instance.parents[valueKey],
						key,
					)
				}
				edges++
			}
		}
	}
	return plan, nil
}

func (cache *nestGroupProjectionCache) project(
	database runtimeDatabase,
	entry directory.Entry,
) (directory.Entry, error) {
	if !cache.enabled {
		return entry, nil
	}
	plan, err := cache.plan(database)
	if err != nil || len(plan.instances) == 0 {
		return entry, err
	}
	return cache.projectWithPlan(plan, entry)
}

func (cache *nestGroupProjectionCache) projectWithPlan(
	plan *nestGroupDatabasePlan,
	entry directory.Entry,
) (directory.Entry, error) {
	var err error
	projected := entry
	for index := range plan.instances {
		instance := &plan.instances[index]
		configuration := instance.configuration
		if configuration.flags&nestGroupMemberValues != 0 &&
			cache.attributeRequested(configuration.memberAttribute) {
			projected, err = cache.projectMemberValues(plan, instance, projected)
			if err != nil {
				return directory.Entry{}, err
			}
		}
		if configuration.flags&nestGroupMemberOfValues != 0 &&
			cache.attributeRequested(configuration.memberOfAttribute) {
			projected, err = cache.projectMemberOfValues(plan, instance, projected)
			if err != nil {
				return directory.Entry{}, err
			}
		}
	}
	return projected, nil
}

func (cache *nestGroupProjectionCache) apply(
	database runtimeDatabase,
	entry,
	filterEntry directory.Entry,
) (directory.Entry, directory.Entry, directory.Filter, error) {
	if !cache.enabled {
		return entry, filterEntry, cache.request.filter, nil
	}
	plan, err := cache.plan(database)
	if err != nil {
		return directory.Entry{}, directory.Entry{}, directory.Filter{}, err
	}
	if len(plan.instances) == 0 {
		return entry, filterEntry, cache.request.filter, nil
	}
	if err := cache.prepareFilter(plan); err != nil {
		return directory.Entry{}, directory.Entry{}, directory.Filter{}, err
	}
	projected, err := cache.projectWithPlan(plan, entry)
	if err != nil {
		return directory.Entry{}, directory.Entry{}, directory.Filter{}, err
	}
	if plan.recheckFilter {
		filterEntry = projected
	}
	return projected, filterEntry, plan.filter, nil
}

func (cache *nestGroupProjectionCache) prepareFilter(
	plan *nestGroupDatabasePlan,
) error {
	if plan.filterPrepared {
		return nil
	}
	filter := cloneNestGroupFilter(cache.request.filter)
	for index := range plan.instances {
		instance := &plan.instances[index]
		rewritten, negated, err := cache.rewriteFilter(
			plan,
			instance,
			filter,
			false,
		)
		if err != nil {
			return err
		}
		filter = rewritten
		if negated && cache.instanceProjectsRequestedValues(instance) {
			plan.recheckFilter = true
		}
	}
	plan.filter = filter
	plan.filterPrepared = true
	return nil
}

func (cache *nestGroupProjectionCache) rewriteFilter(
	plan *nestGroupDatabasePlan,
	instance *nestGroupInstanceGraph,
	filter directory.Filter,
	negated bool,
) (directory.Filter, bool, error) {
	switch filter.Kind {
	case directory.FilterAnd, directory.FilterOr:
		negativeEquality := false
		for index := range filter.Children {
			child, childNegative, err := cache.rewriteFilter(
				plan,
				instance,
				filter.Children[index],
				negated,
			)
			if err != nil {
				return directory.Filter{}, false, err
			}
			filter.Children[index] = child
			negativeEquality = negativeEquality || childNegative
		}
		return filter, negativeEquality, nil
	case directory.FilterNot:
		negativeEquality := false
		for index := range filter.Children {
			child, childNegative, err := cache.rewriteFilter(
				plan,
				instance,
				filter.Children[index],
				!negated,
			)
			if err != nil {
				return directory.Filter{}, false, err
			}
			filter.Children[index] = child
			negativeEquality = negativeEquality || childNegative
		}
		return filter, negativeEquality, nil
	case directory.FilterEquality:
		configuration := instance.configuration
		member := configuration.flags&nestGroupMemberFilter != 0 &&
			nestGroupFilterAttributeMatches(
				cache.runtime.schema,
				filter.Attribute,
				configuration.memberAttribute,
			)
		memberOf := configuration.flags&nestGroupMemberOfFilter != 0 &&
			nestGroupFilterAttributeMatches(
				cache.runtime.schema,
				filter.Attribute,
				configuration.memberOfAttribute,
			)
		if !member && !memberOf {
			return filter, false, nil
		}
		if negated {
			return filter, true, nil
		}

		var alternatives [][]byte
		var err error
		if member {
			alternatives, err = cache.memberFilterAlternatives(
				plan,
				instance,
				filter.Assertion,
			)
		} else {
			alternatives, err = cache.memberOfFilterAlternatives(
				plan,
				instance,
				filter.Assertion,
			)
		}
		if err != nil {
			return directory.Filter{}, false, err
		}
		if len(alternatives) == 0 {
			return filter, false, nil
		}
		children := make([]directory.Filter, 0, len(alternatives)+1)
		children = append(children, cloneNestGroupFilter(filter))
		seen := make(map[string]struct{}, len(alternatives)+1)
		normalized, err := cache.runtime.schema.NormalizeEqualityValue(
			filter.Attribute,
			filter.Assertion,
		)
		if err != nil {
			return directory.Filter{}, false, err
		}
		seen[string(normalized)] = struct{}{}
		for _, alternative := range alternatives {
			normalized, err = cache.runtime.schema.NormalizeEqualityValue(
				filter.Attribute,
				alternative,
			)
			if err != nil {
				return directory.Filter{}, false, err
			}
			if _, duplicate := seen[string(normalized)]; duplicate {
				continue
			}
			seen[string(normalized)] = struct{}{}
			children = append(children, directory.Filter{
				Kind:      directory.FilterEquality,
				Attribute: filter.Attribute,
				Assertion: bytes.Clone(alternative),
			})
		}
		if len(children) == 1 {
			return filter, false, nil
		}
		return directory.Filter{
			Kind:     directory.FilterOr,
			Children: children,
		}, false, nil
	case directory.FilterSubstrings:
		configuration := instance.configuration
		if configuration.flags&nestGroupMemberFilter != 0 &&
			nestGroupFilterAttributeMatches(
				cache.runtime.schema,
				filter.Attribute,
				configuration.memberAttribute,
			) || configuration.flags&nestGroupMemberOfFilter != 0 &&
			nestGroupFilterAttributeMatches(
				cache.runtime.schema,
				filter.Attribute,
				configuration.memberOfAttribute,
			) {
			// slapd treats substring assertions on DN-valued attributes as
			// undefined/non-matching instead of failing the Search operation.
			return directory.Filter{Kind: directory.FilterOr}, false, nil
		}
		return filter, false, nil
	default:
		return filter, false, nil
	}
}

func (cache *nestGroupProjectionCache) instanceProjectsRequestedValues(
	instance *nestGroupInstanceGraph,
) bool {
	configuration := instance.configuration
	return configuration.flags&nestGroupMemberValues != 0 &&
		cache.attributeRequested(configuration.memberAttribute) ||
		configuration.flags&nestGroupMemberOfValues != 0 &&
			cache.attributeRequested(configuration.memberOfAttribute)
}

func (cache *nestGroupProjectionCache) memberFilterAlternatives(
	plan *nestGroupDatabasePlan,
	instance *nestGroupInstanceGraph,
	assertion []byte,
) ([][]byte, error) {
	type pendingParent struct {
		key   string
		depth int
	}
	parentKeys, err := cache.visibleParentKeys(plan, instance, assertion)
	if err != nil {
		return nil, err
	}
	discovered := make(map[string]struct{}, len(parentKeys))
	queue := make([]pendingParent, 0, len(parentKeys))
	for _, key := range parentKeys {
		discovered[key] = struct{}{}
		queue = append(queue, pendingParent{key: key, depth: 1})
	}
	var alternatives [][]byte
	for len(queue) > 0 {
		if err := cache.ctx.Err(); err != nil {
			return nil, err
		}
		item := queue[0]
		queue = queue[1:]
		if item.depth > nestGroupMaxTraversalDepth {
			return nil, &nestGroupResourceLimitError{
				resource: "traversal depth",
				limit:    nestGroupMaxTraversalDepth,
			}
		}
		parent, found := plan.entries[item.key]
		if !found {
			continue
		}
		next, err := cache.visibleParentKeys(
			plan,
			instance,
			[]byte(parent.entry.DN),
		)
		if err != nil {
			return nil, err
		}
		hasNewParent := false
		for _, key := range next {
			if _, found := discovered[key]; found {
				continue
			}
			discovered[key] = struct{}{}
			hasNewParent = true
			queue = append(queue, pendingParent{key: key, depth: item.depth + 1})
		}
		if hasNewParent {
			alternatives = append(alternatives, []byte(parent.entry.DN))
			if len(alternatives) > nestGroupMaxExpandedValues {
				return nil, &nestGroupResourceLimitError{
					resource: "expanded values",
					limit:    nestGroupMaxExpandedValues,
				}
			}
		}
	}
	return alternatives, nil
}

func (cache *nestGroupProjectionCache) memberOfFilterAlternatives(
	plan *nestGroupDatabasePlan,
	instance *nestGroupInstanceGraph,
	assertion []byte,
) ([][]byte, error) {
	root, err := nestGroupParseReference(
		cache.runtime.schema,
		instance.configuration.memberOfAttribute,
		assertion,
	)
	if err != nil {
		return nil, err
	}
	type pendingGroup struct {
		dn    directory.DN
		depth int
	}
	queue := []pendingGroup{{dn: root.dn, depth: 1}}
	visited := make(map[string]struct{})
	seenValues := make(map[string]struct{})
	var alternatives [][]byte
	for len(queue) > 0 {
		if err := cache.ctx.Err(); err != nil {
			return nil, err
		}
		item := queue[0]
		queue = queue[1:]
		if item.depth > nestGroupMaxTraversalDepth {
			return nil, &nestGroupResourceLimitError{
				resource: "traversal depth",
				limit:    nestGroupMaxTraversalDepth,
			}
		}
		key := item.dn.Key()
		if _, found := visited[key]; found {
			continue
		}
		visited[key] = struct{}{}
		if _, found := plan.entries[key]; !found {
			continue
		}
		for _, child := range instance.direct[key] {
			if !nestGroupDNInBases(child.dn, instance.configuration.bases) {
				continue
			}
			value := []byte(child.dn.String())
			normalized, err := cache.runtime.schema.NormalizeEqualityValue(
				instance.configuration.memberOfAttribute,
				value,
			)
			if err != nil {
				return nil, err
			}
			if _, found := seenValues[string(normalized)]; !found {
				seenValues[string(normalized)] = struct{}{}
				alternatives = append(alternatives, value)
				if len(alternatives) > nestGroupMaxExpandedValues {
					return nil, &nestGroupResourceLimitError{
						resource: "expanded values",
						limit:    nestGroupMaxExpandedValues,
					}
				}
			}
			queue = append(queue, pendingGroup{
				dn:    child.dn,
				depth: item.depth + 1,
			})
		}
	}
	return alternatives, nil
}

func (cache *nestGroupProjectionCache) visibleParentKeys(
	plan *nestGroupDatabasePlan,
	instance *nestGroupInstanceGraph,
	assertion []byte,
) ([]string, error) {
	normalized, err := cache.runtime.schema.NormalizeEqualityValue(
		instance.configuration.memberAttribute,
		assertion,
	)
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, parentKey := range instance.parents[string(normalized)] {
		parent, found := plan.entries[parentKey]
		if !found {
			continue
		}
		matches, err := cache.server.filterMatches(
			cache.runtime,
			plan.reader,
			cache.subjectDN,
			parent.entry,
			directory.Filter{
				Kind:      directory.FilterEquality,
				Attribute: instance.configuration.memberAttribute,
				Assertion: bytes.Clone(assertion),
			},
		)
		if err != nil {
			return nil, err
		}
		if matches {
			keys = append(keys, parentKey)
		}
	}
	return keys, nil
}

func nestGroupFilterAttributeMatches(
	registry *schema.Registry,
	candidate,
	configured string,
) bool {
	if strings.Contains(candidate, ";") || strings.Contains(configured, ";") {
		return strings.EqualFold(candidate, configured)
	}
	candidateType, candidateFound := registry.AttributeType(candidate)
	configuredType, configuredFound := registry.AttributeType(configured)
	if !candidateFound || !configuredFound {
		return strings.EqualFold(candidate, configured)
	}
	return strings.EqualFold(candidateType.OID, configuredType.OID)
}

func cloneNestGroupFilter(filter directory.Filter) directory.Filter {
	cloned := filter
	cloned.Assertion = bytes.Clone(filter.Assertion)
	cloned.Substring.Initial = bytes.Clone(filter.Substring.Initial)
	cloned.Substring.Final = bytes.Clone(filter.Substring.Final)
	cloned.Substring.Any = make([][]byte, len(filter.Substring.Any))
	for index := range filter.Substring.Any {
		cloned.Substring.Any[index] = bytes.Clone(filter.Substring.Any[index])
	}
	cloned.Children = make([]directory.Filter, len(filter.Children))
	for index := range filter.Children {
		cloned.Children[index] = cloneNestGroupFilter(filter.Children[index])
	}
	return cloned
}

func (cache *nestGroupProjectionCache) attributeRequested(attribute string) bool {
	requested := cache.request.attributes
	if len(requested) == 1 && requested[0] == "1.1" {
		return false
	}
	operational := cache.runtime.schema.IsOperational(attribute)
	if len(requested) == 0 && !operational {
		return true
	}
	for _, candidate := range requested {
		switch {
		case candidate == "1.1":
			continue
		case candidate == "*" && !operational:
			return true
		case candidate == "+" && operational:
			return true
		case cache.runtime.schema.AttributeDescriptionSubtype(attribute, candidate),
			cache.runtime.schema.AttributeDescriptionSubtype(candidate, attribute):
			return true
		}
	}
	return false
}

func (cache *nestGroupProjectionCache) projectMemberValues(
	plan *nestGroupDatabasePlan,
	instance *nestGroupInstanceGraph,
	entry directory.Entry,
) (directory.Entry, error) {
	attribute := instance.configuration.memberAttribute
	if !cache.runtime.schema.HasAttributeDescription(entry, attribute) {
		return entry, nil
	}
	type pendingReference struct {
		reference nestGroupReference
		depth     int
	}
	var queue []pendingReference
	for _, raw := range cache.runtime.schema.AttributeValues(entry, attribute) {
		reference, err := nestGroupParseReference(cache.runtime.schema, attribute, raw)
		if err != nil {
			return directory.Entry{}, err
		}
		if nestGroupDNInBases(reference.dn, instance.configuration.bases) {
			queue = append(queue, pendingReference{reference: reference, depth: 1})
		}
	}
	visited := make(map[string]struct{})
	var additional [][]byte
	for len(queue) > 0 {
		if err := cache.ctx.Err(); err != nil {
			return directory.Entry{}, err
		}
		item := queue[0]
		queue = queue[1:]
		if item.depth > nestGroupMaxTraversalDepth {
			return directory.Entry{}, &nestGroupResourceLimitError{
				resource: "traversal depth",
				limit:    nestGroupMaxTraversalDepth,
			}
		}
		key := item.reference.dn.Key()
		if _, found := visited[key]; found {
			continue
		}
		visited[key] = struct{}{}
		node, found := plan.entries[key]
		if !found {
			continue
		}
		for _, child := range instance.direct[node.dn.Key()] {
			additional = append(additional, bytes.Clone(child.raw))
			if len(additional) > nestGroupMaxExpandedValues {
				return directory.Entry{}, &nestGroupResourceLimitError{
					resource: "expanded values",
					limit:    nestGroupMaxExpandedValues,
				}
			}
			if nestGroupDNInBases(child.dn, instance.configuration.bases) {
				queue = append(queue, pendingReference{
					reference: child,
					depth:     item.depth + 1,
				})
			}
		}
	}
	return appendNestGroupAttributeValues(
		cache.runtime.schema,
		entry,
		attribute,
		additional,
	)
}

func (cache *nestGroupProjectionCache) projectMemberOfValues(
	plan *nestGroupDatabasePlan,
	instance *nestGroupInstanceGraph,
	entry directory.Entry,
) (directory.Entry, error) {
	attribute := instance.configuration.memberOfAttribute
	if !cache.runtime.schema.HasAttributeDescription(entry, attribute) {
		return entry, nil
	}
	type pendingAssertion struct {
		value []byte
		depth int
	}
	queue := make([]pendingAssertion, 0)
	for _, value := range cache.runtime.schema.AttributeValues(entry, attribute) {
		queue = append(queue, pendingAssertion{value: bytes.Clone(value), depth: 1})
	}
	visited := make(map[string]struct{})
	var additional [][]byte
	for len(queue) > 0 {
		if err := cache.ctx.Err(); err != nil {
			return directory.Entry{}, err
		}
		item := queue[0]
		queue = queue[1:]
		if item.depth > nestGroupMaxTraversalDepth {
			return directory.Entry{}, &nestGroupResourceLimitError{
				resource: "traversal depth",
				limit:    nestGroupMaxTraversalDepth,
			}
		}
		normalized, err := cache.runtime.schema.NormalizeEqualityValue(
			instance.configuration.memberAttribute,
			item.value,
		)
		if err != nil {
			return directory.Entry{}, err
		}
		for _, parentKey := range instance.parents[string(normalized)] {
			parent, found := plan.entries[parentKey]
			if !found {
				continue
			}
			matches, err := cache.server.filterMatches(
				cache.runtime,
				plan.reader,
				cache.subjectDN,
				parent.entry,
				directory.Filter{
					Kind:      directory.FilterEquality,
					Attribute: instance.configuration.memberAttribute,
					Assertion: bytes.Clone(item.value),
				},
			)
			if err != nil {
				return directory.Entry{}, err
			}
			if !matches {
				continue
			}
			if _, found := visited[parentKey]; found {
				continue
			}
			visited[parentKey] = struct{}{}
			value := []byte(parent.entry.DN)
			additional = append(additional, value)
			if len(additional) > nestGroupMaxExpandedValues {
				return directory.Entry{}, &nestGroupResourceLimitError{
					resource: "expanded values",
					limit:    nestGroupMaxExpandedValues,
				}
			}
			queue = append(queue, pendingAssertion{
				value: value,
				depth: item.depth + 1,
			})
		}
	}
	return appendNestGroupAttributeValues(
		cache.runtime.schema,
		entry,
		attribute,
		additional,
	)
}

func appendNestGroupAttributeValues(
	registry *schema.Registry,
	entry directory.Entry,
	attribute string,
	additional [][]byte,
) (directory.Entry, error) {
	if len(additional) == 0 {
		return entry, nil
	}
	seen := make(map[string]struct{})
	targetIndex := -1
	for index, existing := range entry.Attributes {
		if !registry.AttributeDescriptionSubtype(existing.Description, attribute) &&
			!registry.AttributeDescriptionSubtype(attribute, existing.Description) {
			continue
		}
		if targetIndex < 0 {
			targetIndex = index
		}
		for _, raw := range existing.Values {
			normalized, err := registry.NormalizeEqualityValue(attribute, raw)
			if err != nil {
				return directory.Entry{}, err
			}
			seen[string(normalized)] = struct{}{}
		}
	}
	if targetIndex < 0 {
		return entry, nil
	}
	projected := entry.Clone()
	for _, raw := range additional {
		normalized, err := registry.NormalizeEqualityValue(attribute, raw)
		if err != nil {
			return directory.Entry{}, err
		}
		if _, duplicate := seen[string(normalized)]; duplicate {
			continue
		}
		seen[string(normalized)] = struct{}{}
		projected.Attributes[targetIndex].Values = append(
			projected.Attributes[targetIndex].Values,
			bytes.Clone(raw),
		)
	}
	return projected, nil
}

func nestGroupParseReference(
	registry *schema.Registry,
	attribute string,
	raw []byte,
) (nestGroupReference, error) {
	normalized, err := registry.NormalizeEqualityValue(attribute, raw)
	if err != nil {
		return nestGroupReference{}, err
	}
	dnValue := raw
	if index := nestGroupOptionalUIDSeparator(dnValue); index >= 0 {
		dnValue = dnValue[:index]
	}
	dn, err := registry.NormalizeDN(string(dnValue))
	if err != nil {
		return nestGroupReference{}, err
	}
	return nestGroupReference{
		raw:        bytes.Clone(raw),
		normalized: normalized,
		dn:         dn,
	}, nil
}

func nestGroupOptionalUIDSeparator(value []byte) int {
	separator := bytes.LastIndexByte(value, '#')
	if separator < 0 {
		return -1
	}
	uid := value[separator+1:]
	if len(uid) < 3 || uid[0] != '\'' || uid[len(uid)-2] != '\'' || uid[len(uid)-1] != 'B' {
		return -1
	}
	for _, character := range uid[1 : len(uid)-2] {
		if character != '0' && character != '1' {
			return -1
		}
	}
	return separator
}

func nestGroupDNInBases(dn directory.DN, bases []directory.DN) bool {
	for _, base := range bases {
		if base.Equal(dn) || base.AncestorOf(dn) {
			return true
		}
	}
	return false
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
