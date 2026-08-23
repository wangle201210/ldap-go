package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
)

const (
	pcacheMaxAttributeSets  = 500
	pcacheDefaultMaxQueries = 10000
	pcachePrivateDBControl  = "1.3.6.1.4.1.4203.666.11.9.5.1"
	pcacheQueryDeleteOID    = "1.3.6.1.4.1.4203.666.11.9.6.1"
)

type pcacheRuntimeConfiguration struct {
	configDNKey string
	disabled    bool
	// Delegated back-ldap databases reject every local overlay except pcache
	// and bypass the local response pipeline. Head and tail are therefore
	// observably equivalent until ordered delegated-overlay chains exist.
	position          pcacheResponsePosition
	validate          bool
	maxEntries        int
	maxQueries        int
	entryLimit        int
	consistencyPeriod time.Duration
	offline           bool
	persist           bool
	attributeSets     []pcacheAttributeSet
	templates         []pcacheTemplate
	binds             []pcacheBindRuntimeConfiguration
	fingerprint       string
	state             *pcacheState
}

type pcacheResponsePosition uint8

const (
	pcacheResponseHead pcacheResponsePosition = iota
	pcacheResponseTail
)

func (position pcacheResponsePosition) String() string {
	if position == pcacheResponseHead {
		return "head"
	}
	return "tail"
}

type pcacheAttributeSet struct {
	index      int
	attributes []string
}

type pcacheTemplate struct {
	filter      directory.Filter
	attrset     int
	ttl         time.Duration
	negativeTTL time.Duration
	limitTTL    time.Duration
	ttr         time.Duration
}

type pcacheBindRuntimeConfiguration struct {
	filter  directory.Filter
	attrset int
	ttl     time.Duration
	scope   directory.Scope
	baseDN  string
}

type pcacheState struct {
	mu          sync.Mutex
	epoch       time.Time
	clock       func() time.Time
	queries     map[string]pcacheCachedQuery
	binds       map[string]pcacheCachedBind
	entries     int
	sequence    uint64
	generation  uint64
	persistence *pcachePersistence
}

type pcacheCachedBind struct {
	passwordHash []byte
	purgeAt      time.Time
	lastUsed     uint64
	generation   uint64
}

type pcacheCachedQuery struct {
	identifier string
	attrset    int
	response   pcacheSearchResponse
	replay     ldapwire.Message
	remote     pcacheRemoteContext
	policy     pcacheRefreshPolicy
	purgeAt    time.Time
	refreshAt  time.Time
	entries    int
	lastUsed   uint64
	generation uint64
	referenced bool
	refreshing bool
}

type pcacheRefreshPolicy struct {
	positiveTTL       time.Duration
	negativeTTL       time.Duration
	ttr               time.Duration
	consistencyPeriod time.Duration
	entryLimit        int
	attrset           int
}

type pcacheRefreshLease struct {
	key        string
	generation uint64
	replay     ldapwire.Message
	remote     pcacheRemoteContext
	policy     pcacheRefreshPolicy
}

type pcacheRemoteContext struct {
	connectionID     uint64
	boundDN          string
	operationRealDN  string
	authMechanism    string
	bindCredentialDN string
	bindCredentials  []byte
	secure           bool
	externalSSF      uint32
	saslSSF          uint32
	externalDN       string
}

type pcacheSearchItem struct {
	entry      *directory.Entry
	references []string
	controls   []ldapwire.Control
}

type pcacheSearchResponse struct {
	items        []pcacheSearchItem
	result       ldapwire.Result
	doneControls []ldapwire.Control
}

type pcacheRequestMatch struct {
	key      string
	template pcacheTemplate
	attrset  pcacheAttributeSet
}

func loadPcacheRuntimeConfiguration(
	overlay directory.Entry,
) (pcacheRuntimeConfiguration, error) {
	configuration := pcacheRuntimeConfiguration{
		configDNKey: mustRuntimeDNKey(overlay.DN),
		maxQueries:  pcacheDefaultMaxQueries,
		position:    pcacheResponseTail,
	}
	if !pcacheHasObjectClass(overlay, "olcPcacheConfig") {
		return configuration, fmt.Errorf(
			"%s pcache overlay requires objectClass olcPcacheConfig",
			overlay.DN,
		)
	}
	disabled, _, err := singleBoolean(overlay, "olcDisabled")
	if err != nil {
		return configuration, err
	}
	configuration.disabled = disabled

	positionValues := overlay.Values("olcPcachePosition")
	if len(positionValues) > 1 {
		return configuration, fmt.Errorf(
			"%s olcPcachePosition must be single-valued",
			overlay.DN,
		)
	}
	if len(positionValues) == 1 {
		switch strings.ToLower(strings.TrimSpace(string(positionValues[0]))) {
		case "head":
			configuration.position = pcacheResponseHead
		case "tail":
			configuration.position = pcacheResponseTail
		default:
			return configuration, fmt.Errorf(
				"%s olcPcachePosition has unknown specifier %q",
				overlay.DN,
				positionValues[0],
			)
		}
	}
	configuration.validate, _, err = pcacheAliasedBoolean(
		overlay,
		"olcPcacheValidate",
		"olcProxyCheckCacheability",
	)
	if err != nil {
		return configuration, err
	}

	maxQueryValues, err := pcacheAliasedValues(
		overlay,
		"olcPcacheMaxQueries",
		"olcProxyCacheQueries",
	)
	if err != nil {
		return configuration, err
	}
	if len(maxQueryValues) > 1 {
		return configuration, fmt.Errorf(
			"%s olcPcacheMaxQueries must be single-valued",
			overlay.DN,
		)
	}
	if len(maxQueryValues) == 1 {
		configuration.maxQueries, err = pcachePositiveInteger(
			strings.TrimSpace(string(maxQueryValues[0])),
			"max queries",
		)
		if err != nil {
			return configuration, fmt.Errorf("%s olcPcacheMaxQueries: %w", overlay.DN, err)
		}
	}
	configuration.persist, _, err = pcacheAliasedBoolean(
		overlay,
		"olcPcachePersist",
		"olcProxySaveQueries",
	)
	if err != nil {
		return configuration, err
	}
	configuration.offline, _, err = singleBoolean(overlay, "olcPcacheOffline")
	if err != nil {
		return configuration, err
	}

	mainValues, err := pcacheAliasedValues(overlay, "olcPcache", "olcProxyCache")
	if err != nil {
		return configuration, err
	}
	if len(mainValues) != 1 {
		return configuration, fmt.Errorf("%s olcPcache must be single-valued", overlay.DN)
	}
	main, err := tokenizeOpenLDAPConfig(string(mainValues[0]))
	if err != nil || len(main) != 5 {
		return configuration, fmt.Errorf(
			"%s olcPcache requires backend, max entries, attrset count, entry limit, and consistency period",
			overlay.DN,
		)
	}
	if !strings.EqualFold(main[0], "mdb") {
		return configuration, fmt.Errorf(
			"%s olcPcache backend %q is unsupported",
			overlay.DN,
			main[0],
		)
	}
	configuration.maxEntries, err = pcachePositiveInteger(main[1], "max entries")
	if err != nil {
		return configuration, fmt.Errorf("%s olcPcache: %w", overlay.DN, err)
	}
	attributeSetCount, err := pcachePositiveInteger(main[2], "attrset count")
	if err != nil || attributeSetCount > pcacheMaxAttributeSets {
		return configuration, fmt.Errorf(
			"%s olcPcache attrset count must be between 1 and %d",
			overlay.DN,
			pcacheMaxAttributeSets,
		)
	}
	configuration.entryLimit, err = pcachePositiveInteger(main[3], "entry limit")
	if err != nil || configuration.entryLimit > configuration.maxEntries {
		return configuration, fmt.Errorf(
			"%s olcPcache entry limit must be between 1 and max entries",
			overlay.DN,
		)
	}
	configuration.consistencyPeriod, err = parseOpenLDAPTimeInterval(main[4])
	if err != nil {
		return configuration, fmt.Errorf("%s olcPcache consistency period: %w", overlay.DN, err)
	}

	attrsetValues, err := pcacheAliasedValues(
		overlay,
		"olcPcacheAttrset",
		"olcProxyAttrset",
	)
	if err != nil {
		return configuration, err
	}
	sets := make(map[int]pcacheAttributeSet, attributeSetCount)
	for _, raw := range attrsetValues {
		value, err := pcacheStripOrderedPrefix(string(raw))
		if err != nil {
			return configuration, fmt.Errorf("%s olcPcacheAttrset: %w", overlay.DN, err)
		}
		arguments, err := tokenizeOpenLDAPConfig(value)
		if err != nil || len(arguments) < 2 {
			return configuration, fmt.Errorf(
				"%s olcPcacheAttrset requires an index and attributes",
				overlay.DN,
			)
		}
		index, err := strconv.Atoi(arguments[0])
		if err != nil || index < 0 || index >= attributeSetCount {
			return configuration, fmt.Errorf(
				"%s olcPcacheAttrset index %q is out of range",
				overlay.DN,
				arguments[0],
			)
		}
		if _, duplicate := sets[index]; duplicate {
			return configuration, fmt.Errorf(
				"%s configures duplicate olcPcacheAttrset index %d",
				overlay.DN,
				index,
			)
		}
		attributes, err := pcacheNormalizeAttributeSet(arguments[1:])
		if err != nil {
			return configuration, fmt.Errorf("%s olcPcacheAttrset %d: %w", overlay.DN, index, err)
		}
		sets[index] = pcacheAttributeSet{index: index, attributes: attributes}
	}
	if len(sets) != attributeSetCount {
		return configuration, fmt.Errorf(
			"%s configures %d pcache attrsets, want %d",
			overlay.DN,
			len(sets),
			attributeSetCount,
		)
	}
	configuration.attributeSets = make([]pcacheAttributeSet, attributeSetCount)
	for index := 0; index < attributeSetCount; index++ {
		configuration.attributeSets[index] = sets[index]
	}

	templateValues, err := pcacheAliasedValues(
		overlay,
		"olcPcacheTemplate",
		"olcProxyCacheTemplate",
	)
	if err != nil {
		return configuration, err
	}
	if len(templateValues) == 0 {
		return configuration, fmt.Errorf("%s requires olcPcacheTemplate", overlay.DN)
	}
	configuredTemplates := make(map[string]struct{}, len(templateValues))
	for _, raw := range templateValues {
		value, err := pcacheStripOrderedPrefix(string(raw))
		if err != nil {
			return configuration, fmt.Errorf("%s olcPcacheTemplate: %w", overlay.DN, err)
		}
		arguments, err := tokenizeOpenLDAPConfig(value)
		if err != nil || len(arguments) < 3 || len(arguments) > 6 {
			return configuration, fmt.Errorf(
				"%s olcPcacheTemplate requires filter, attrset, TTL, and up to negTTL/limitTTL",
				overlay.DN,
			)
		}
		filter, err := ldapwire.CompileFilter(arguments[0])
		if err != nil || !pcacheTemplateFilterSupported(filter) {
			return configuration, fmt.Errorf(
				"%s olcPcacheTemplate filter %q is unsupported",
				overlay.DN,
				arguments[0],
			)
		}
		attrset, err := strconv.Atoi(arguments[1])
		if err != nil || attrset < 0 || attrset >= attributeSetCount {
			return configuration, fmt.Errorf(
				"%s olcPcacheTemplate attrset %q is out of range",
				overlay.DN,
				arguments[1],
			)
		}
		template := pcacheTemplate{filter: filter, attrset: attrset}
		templateKey := pcacheFilterKey(filter) + "\x00" + strconv.Itoa(attrset)
		if _, duplicate := configuredTemplates[templateKey]; duplicate {
			return configuration, fmt.Errorf(
				"%s configures a duplicate pcache template for attrset %d",
				overlay.DN,
				attrset,
			)
		}
		configuredTemplates[templateKey] = struct{}{}
		template.ttl, err = parseOpenLDAPTimeInterval(arguments[2])
		if err != nil {
			return configuration, fmt.Errorf("%s pcache TTL: %w", overlay.DN, err)
		}
		if len(arguments) >= 4 {
			template.negativeTTL, err = parseOpenLDAPTimeInterval(arguments[3])
			if err != nil {
				return configuration, fmt.Errorf("%s pcache negative TTL: %w", overlay.DN, err)
			}
		}
		if len(arguments) >= 5 {
			template.limitTTL, err = parseOpenLDAPTimeInterval(arguments[4])
			if err != nil {
				return configuration, fmt.Errorf("%s pcache limit TTL: %w", overlay.DN, err)
			}
		}
		if len(arguments) == 6 {
			template.ttr, err = parseOpenLDAPTimeInterval(arguments[5])
			if err != nil {
				return configuration, fmt.Errorf("%s pcache TTR: %w", overlay.DN, err)
			}
		}
		configuration.templates = append(configuration.templates, template)
	}
	configuration.binds, err = loadPcacheBindRuntimeConfigurations(
		overlay,
		configuration.templates,
		configuration.attributeSets,
	)
	if err != nil {
		return configuration, err
	}
	configuration.fingerprint = pcacheConfigurationFingerprint(configuration)
	configuration.state = newPcacheState()
	return configuration, nil
}

func mustRuntimeDNKey(raw string) string {
	dn, err := directory.ParseDN(raw)
	if err != nil {
		return strings.ToLower(raw)
	}
	return dn.Key()
}

func pcacheHasObjectClass(entry directory.Entry, expected string) bool {
	for _, value := range entry.Values("objectClass") {
		if strings.EqualFold(string(value), expected) {
			return true
		}
	}
	return false
}

func pcacheAliasedValues(entry directory.Entry, names ...string) ([][]byte, error) {
	var values [][]byte
	var present string
	for _, name := range names {
		candidate := entry.Values(name)
		if len(candidate) == 0 {
			continue
		}
		if present != "" {
			return nil, fmt.Errorf(
				"%s configures both %s and alias %s",
				entry.DN,
				present,
				name,
			)
		}
		present = name
		values = candidate
	}
	return values, nil
}

func pcacheAliasedBoolean(
	entry directory.Entry,
	names ...string,
) (value, present bool, err error) {
	values, err := pcacheAliasedValues(entry, names...)
	if err != nil {
		return false, false, err
	}
	if len(values) == 0 {
		return false, false, nil
	}
	if len(values) != 1 {
		return false, false, fmt.Errorf("%s %s must be single-valued", entry.DN, names[0])
	}
	switch {
	case strings.EqualFold(strings.TrimSpace(string(values[0])), "TRUE"):
		return true, true, nil
	case strings.EqualFold(strings.TrimSpace(string(values[0])), "FALSE"):
		return false, true, nil
	default:
		return false, false, fmt.Errorf(
			"%s %s has invalid value %q",
			entry.DN,
			names[0],
			values[0],
		)
	}
}

func pcachePositiveInteger(value, name string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func pcacheStripOrderedPrefix(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{") {
		return value, nil
	}
	end := strings.IndexByte(value, '}')
	if end <= 1 {
		return "", errors.New("invalid ordered value prefix")
	}
	if _, err := strconv.Atoi(value[1:end]); err != nil {
		return "", errors.New("invalid ordered value prefix")
	}
	return strings.TrimSpace(value[end+1:]), nil
}

func pcacheNormalizeAttributeSet(attributes []string) ([]string, error) {
	seen := make(map[string]struct{}, len(attributes))
	normalized := make([]string, 0, len(attributes))
	for _, raw := range attributes {
		attribute := strings.ToLower(strings.TrimSpace(raw))
		if attribute == "" || strings.HasPrefix(attribute, "undef:") {
			return nil, fmt.Errorf("attribute %q is unsupported", raw)
		}
		if _, duplicate := seen[attribute]; duplicate {
			return nil, fmt.Errorf("attribute %q is duplicated", raw)
		}
		seen[attribute] = struct{}{}
		normalized = append(normalized, attribute)
	}
	if _, noAttributes := seen["1.1"]; noAttributes && len(normalized) != 1 {
		return nil, errors.New("1.1 cannot be combined with other attributes")
	}
	return normalized, nil
}

func pcacheTemplateFilterSupported(filter directory.Filter) bool {
	switch filter.Kind {
	case directory.FilterAnd, directory.FilterOr:
		for _, child := range filter.Children {
			if !pcacheTemplateFilterSupported(child) {
				return false
			}
		}
		return true
	case directory.FilterEquality,
		directory.FilterSubstrings,
		directory.FilterGreaterOrEqual,
		directory.FilterLessOrEqual,
		directory.FilterPresent:
		return filter.Attribute != ""
	case directory.FilterExtensible:
		return filter.Attribute != "" || filter.MatchingRule != ""
	default:
		return false
	}
}

func loadPcacheBindRuntimeConfigurations(
	overlay directory.Entry,
	templates []pcacheTemplate,
	attributeSets []pcacheAttributeSet,
) ([]pcacheBindRuntimeConfiguration, error) {
	values := overlay.Values("olcPcacheBind")
	configured := make(map[string]struct{}, len(values))
	result := make([]pcacheBindRuntimeConfiguration, 0, len(values))
	for _, raw := range values {
		value, err := pcacheStripOrderedPrefix(string(raw))
		if err != nil {
			return nil, fmt.Errorf("%s olcPcacheBind: %w", overlay.DN, err)
		}
		arguments, err := tokenizeOpenLDAPConfig(value)
		if err != nil || len(arguments) != 5 {
			return nil, fmt.Errorf(
				"%s olcPcacheBind requires filter, attrset, TTR, scope, and base DN",
				overlay.DN,
			)
		}
		filter, err := ldapwire.CompileFilter(arguments[0])
		if err != nil || !pcacheBindFilterSupported(filter) ||
			!pcacheBindFilterHasPlaceholder(filter) {
			return nil, fmt.Errorf(
				"%s olcPcacheBind filter %q is outside the supported safe subset",
				overlay.DN,
				arguments[0],
			)
		}
		attrset, err := strconv.Atoi(arguments[1])
		if err != nil || attrset < 0 || attrset >= len(attributeSets) {
			return nil, fmt.Errorf(
				"%s olcPcacheBind attrset %q is out of range",
				overlay.DN,
				arguments[1],
			)
		}
		if !pcacheBindTemplateExists(filter, attrset, templates) {
			return nil, fmt.Errorf(
				"%s olcPcacheBind filter %q has no matching pcache template for attrset %d",
				overlay.DN,
				arguments[0],
				attrset,
			)
		}
		ttl, err := parseOpenLDAPTimeInterval(arguments[2])
		if err != nil || ttl <= 0 {
			return nil, fmt.Errorf(
				"%s olcPcacheBind TTR must be a positive time interval",
				overlay.DN,
			)
		}
		scope, err := pcacheBindScope(arguments[3])
		if err != nil {
			return nil, fmt.Errorf("%s olcPcacheBind: %w", overlay.DN, err)
		}
		base, err := directory.ParseDN(arguments[4])
		if err != nil {
			return nil, fmt.Errorf(
				"%s olcPcacheBind base DN %q is invalid",
				overlay.DN,
				arguments[4],
			)
		}
		configuration := pcacheBindRuntimeConfiguration{
			filter:  filter,
			attrset: attrset,
			ttl:     ttl,
			scope:   scope,
			baseDN:  base.String(),
		}
		key := strings.Join([]string{
			pcacheFilterKey(filter),
			strconv.Itoa(attrset),
			strconv.Itoa(int(scope)),
			base.Key(),
		}, "\x00")
		if _, duplicate := configured[key]; duplicate {
			return nil, fmt.Errorf("%s configures duplicate olcPcacheBind values", overlay.DN)
		}
		configured[key] = struct{}{}
		result = append(result, configuration)
	}
	return result, nil
}

func pcacheBindFilterSupported(filter directory.Filter) bool {
	switch filter.Kind {
	case directory.FilterAnd:
		if len(filter.Children) == 0 {
			return false
		}
		empty := false
		for _, child := range filter.Children {
			if !pcacheBindFilterSupported(child) {
				return false
			}
			empty = empty || pcacheBindFilterHasPlaceholder(child)
		}
		return empty
	case directory.FilterEquality:
		return filter.Attribute != ""
	default:
		return false
	}
}

func pcacheBindFilterHasPlaceholder(filter directory.Filter) bool {
	if filter.Kind == directory.FilterEquality {
		return len(filter.Assertion) == 0
	}
	for _, child := range filter.Children {
		if pcacheBindFilterHasPlaceholder(child) {
			return true
		}
	}
	return false
}

func pcacheBindTemplateExists(
	filter directory.Filter,
	attrset int,
	templates []pcacheTemplate,
) bool {
	key := pcacheFilterKey(filter)
	for _, template := range templates {
		if template.attrset == attrset && pcacheFilterKey(template.filter) == key {
			return true
		}
	}
	return false
}

func pcacheBindScope(value string) (directory.Scope, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "base":
		return directory.ScopeBase, nil
	case "one", "onelevel", "singlelevel":
		return directory.ScopeSingleLevel, nil
	case "sub", "subtree":
		return directory.ScopeWholeSubtree, nil
	case "children", "subord", "subordinate":
		return directory.ScopeChildren, nil
	default:
		return 0, fmt.Errorf("unknown Bind scope %q", value)
	}
}

func pcacheConfigurationFingerprint(configuration pcacheRuntimeConfiguration) string {
	var value strings.Builder
	fmt.Fprintf(
		&value,
		"%d/%d/%d/%d/%t/%t/%s/%t/",
		configuration.maxEntries,
		configuration.maxQueries,
		configuration.entryLimit,
		configuration.consistencyPeriod,
		configuration.offline,
		configuration.persist,
		configuration.position,
		configuration.validate,
	)
	for _, set := range configuration.attributeSets {
		fmt.Fprintf(&value, "%d:%s;", set.index, strings.Join(set.attributes, ","))
	}
	for _, template := range configuration.templates {
		fmt.Fprintf(
			&value,
			"%s:%d:%d:%d:%d:%d;",
			pcacheFilterKey(template.filter),
			template.attrset,
			template.ttl,
			template.negativeTTL,
			template.limitTTL,
			template.ttr,
		)
	}
	for _, bind := range configuration.binds {
		fmt.Fprintf(
			&value,
			"bind:%s:%d:%d:%d:%s;",
			pcacheFilterKey(bind.filter),
			bind.attrset,
			bind.ttl,
			bind.scope,
			bind.baseDN,
		)
	}
	return value.String()
}

func newPcacheState() *pcacheState {
	return newPcacheStateWithClock(time.Now)
}

func newPcacheStateWithClock(clock func() time.Time) *pcacheState {
	if clock == nil {
		clock = time.Now
	}
	return &pcacheState{
		epoch:   clock(),
		clock:   clock,
		queries: make(map[string]pcacheCachedQuery),
		binds:   make(map[string]pcacheCachedBind),
	}
}

func reusePcacheStates(previous, next *runtimeState) {
	if previous == nil || next == nil {
		return
	}
	states := make(map[string]*pcacheRuntimeConfiguration)
	for index := range previous.databases {
		configuration := previous.databases[index].pcache
		if configuration != nil {
			states[configuration.configDNKey] = configuration
		}
	}
	for index := range next.databases {
		configuration := next.databases[index].pcache
		previousConfiguration := states[configurationKey(configuration)]
		if configuration != nil && previousConfiguration != nil &&
			configuration.fingerprint == previousConfiguration.fingerprint {
			configuration.state = previousConfiguration.state
		}
	}
}

func clearPcacheBindStates(runtime *runtimeState) {
	if runtime == nil {
		return
	}
	for index := range runtime.databases {
		configuration := runtime.databases[index].pcache
		if configuration != nil && configuration.state != nil {
			configuration.state.clearBinds()
		}
	}
}

func runtimeSupportsPcachePrivateDatabase(databases []runtimeDatabase) bool {
	for index := range databases {
		configuration := databases[index].pcache
		if configuration != nil && !configuration.disabled {
			return true
		}
	}
	return false
}

func configurationKey(configuration *pcacheRuntimeConfiguration) string {
	if configuration == nil {
		return ""
	}
	return configuration.configDNKey
}

func (server *Server) tryPcacheBind(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.BindRequest,
	requestDN directory.DN,
) (bool, error) {
	if state == nil || state.runtime == nil || request.Version != 3 ||
		request.Authentication.IsSASL || len(request.Authentication.Simple) == 0 ||
		len(message.Controls) != 0 {
		return false, nil
	}
	database := databaseForDN(state.runtime, requestDN)
	if database == nil || database.ldapBackend == nil || database.pcache == nil ||
		database.pcache.disabled || len(database.pcache.binds) == 0 {
		return false, nil
	}
	if _, localRoot := databaseAuthenticationRoot(
		state.runtime,
		*database,
		requestDN,
	); localRoot {
		return false, nil
	}
	bind, key, matched := matchPcacheBindRequest(
		state.runtime,
		*database.pcache,
		requestDN,
	)
	if !matched {
		return false, nil
	}
	now := database.pcache.state.clock()
	if database.pcache.state.lookupBind(
		key,
		request.Authentication.Simple,
		now,
		database.pcache.offline,
	) {
		pcacheEstablishBindIdentity(state, requestDN, request.Authentication.Simple)
		return true, ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		))
	}

	attempt := server.executeLDAPBackendBind(
		ctx,
		state,
		database.ldapBackend,
		message,
	)
	if attempt.hasResult && attempt.result.Code == ldapwire.ResultSuccess {
		database.pcache.state.rememberBind(
			key,
			request.Authentication.Simple,
			database.pcache.state.clock(),
			bind.ttl,
			database.pcache.maxEntries,
			database.pcache.maxQueries,
		)
		pcacheEstablishBindIdentity(state, requestDN, request.Authentication.Simple)
	}
	return true, server.writeLDAPBackendAttempt(connection, message, attempt)
}

func matchPcacheBindRequest(
	runtime *runtimeState,
	configuration pcacheRuntimeConfiguration,
	requestDN directory.DN,
) (pcacheBindRuntimeConfiguration, string, bool) {
	if runtime == nil || runtime.schema == nil || configuration.state == nil {
		return pcacheBindRuntimeConfiguration{}, "", false
	}
	for _, bind := range configuration.binds {
		base, err := runtime.schema.NormalizeDN(bind.baseDN)
		if err != nil || !directory.InScope(base, requestDN, bind.scope) {
			continue
		}
		return bind, requestDN.Key(), true
	}
	return pcacheBindRuntimeConfiguration{}, "", false
}

func pcacheEstablishBindIdentity(
	state *connectionState,
	dn directory.DN,
	password []byte,
) {
	canonical := dn.String()
	state.boundDN = canonical
	state.authMechanism = "SIMPLE"
	state.bindCredentialDN = canonical
	clear(state.bindCredentials)
	state.bindCredentials = append(state.bindCredentials[:0], password...)
}

func (server *Server) tryPcacheSearch(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	database runtimeDatabase,
) (bool, error) {
	request, ok := message.Request.(ldapwire.SearchRequest)
	if !ok || database.pcache == nil || database.pcache.disabled {
		return false, nil
	}
	match, ok := server.matchPcacheRequest(state.runtime, *database.pcache, request)
	if !ok {
		return false, nil
	}

	forwarded := message
	forwarded.Controls = cloneLDAPControls(message.Controls)
	for _, control := range forwarded.Controls {
		if control.OID == pcachePrivateDBControl {
			return true, server.writeSearchDone(
				connection,
				message.ID,
				ldapwire.ResultError(
					ldapwire.ResultUnavailableCriticalExtension,
					"pcache private database control is unsupported",
				),
			)
		}
		if control.OID == pagedResultsControlOID && control.Critical {
			return true, server.writeSearchDone(
				connection,
				message.ID,
				ldapwire.Result{Code: ldapwire.ResultUnavailableCriticalExtension},
			)
		}
	}
	forwarded.Controls = pcacheWithoutPagingControls(forwarded.Controls)

	now := database.pcache.state.clock()
	lookup := database.pcache.state.lookup
	if database.pcache.validate {
		lookup = func(
			key string,
			now time.Time,
			offline bool,
		) (pcacheSearchResponse, bool, *pcacheRefreshLease) {
			return database.pcache.state.lookupValidated(
				key,
				now,
				offline,
				func(response pcacheSearchResponse) bool {
					return pcacheResponseCacheable(
						state.runtime.schema,
						request.Filter,
						response,
						true,
					)
				},
			)
		}
	}
	if cached, found, refresh := lookup(match.key, now, database.pcache.offline); found {
		if refresh != nil {
			if refreshed, ok := server.refreshPcacheSearch(
				ctx,
				state,
				database,
				*refresh,
			); ok {
				cached = refreshed
			}
		}
		return true, server.writePcacheResponse(
			connection,
			message.ID,
			state.runtime,
			request,
			cached,
			true,
		)
	}
	if request.TypesOnly {
		return false, nil
	}

	remoteRequest := request
	remoteRequest.TypesOnly = false
	remoteRequest.Attributes = append([]string(nil), match.attrset.attributes...)
	forwarded.Request = remoteRequest
	attempt, _, failure := server.executeLDAPBackendOperation(
		ctx,
		state,
		database,
		forwarded,
	)
	if failure != nil {
		return true, writeResultForMessage(connection, message, *failure)
	}
	if !attempt.hasResult {
		return true, server.writeLDAPBackendAttempt(connection, message, attempt)
	}
	response, err := decodePcacheSearchAttempt(attempt)
	if err != nil {
		return true, server.writeLDAPBackendAttempt(connection, message, attempt)
	}
	entryCount := response.entryCount()
	if response.result.Code == ldapwire.ResultSuccess &&
		entryCount <= database.pcache.entryLimit &&
		pcacheResponseCacheable(
			state.runtime.schema,
			request.Filter,
			response,
			database.pcache.validate,
		) {
		ttl := match.template.ttl
		if entryCount == 0 {
			ttl = match.template.negativeTTL
		}
		if ttl > 0 {
			database.pcache.state.commit(
				match.key,
				response,
				forwarded,
				capturePcacheRemoteContext(state),
				database.pcache.state.clock(),
				pcacheRefreshPolicy{
					positiveTTL:       match.template.ttl,
					negativeTTL:       match.template.negativeTTL,
					ttr:               match.template.ttr,
					consistencyPeriod: database.pcache.consistencyPeriod,
					entryLimit:        database.pcache.entryLimit,
					attrset:           match.attrset.index,
				},
				database.pcache.maxEntries,
				database.pcache.maxQueries,
				database.pcache.offline,
			)
		}
	}
	return true, server.writePcacheResponse(
		connection,
		message.ID,
		state.runtime,
		request,
		response,
		false,
	)
}

func (server *Server) refreshPcacheSearch(
	ctx context.Context,
	connectionState *connectionState,
	database runtimeDatabase,
	refresh pcacheRefreshLease,
) (pcacheSearchResponse, bool) {
	refreshState := refresh.remote.connectionState(connectionState)
	defer clear(refreshState.bindCredentials)
	attempt, _, failure := server.executeLDAPBackendOperation(
		ctx,
		refreshState,
		database,
		clonePcacheMessage(refresh.replay),
	)
	now := database.pcache.state.clock()
	if failure != nil || !attempt.hasResult {
		database.pcache.state.abortRefresh(refresh, now)
		return pcacheSearchResponse{}, false
	}
	response, err := decodePcacheSearchAttempt(attempt)
	if err != nil || response.result.Code != ldapwire.ResultSuccess ||
		response.entryCount() > refresh.policy.entryLimit {
		database.pcache.state.abortRefresh(refresh, now)
		return pcacheSearchResponse{}, false
	}
	request, ok := refresh.replay.Request.(ldapwire.SearchRequest)
	if !ok || !pcacheResponseCacheable(
		connectionState.runtime.schema,
		request.Filter,
		response,
		database.pcache.validate,
	) {
		if database.pcache.state.invalidateRefresh(refresh) {
			// OpenLDAP returns provider entries even when validation makes the
			// query non-cacheable. The synchronous TTR path does the same for
			// this request while atomically discarding the stale cached query.
			return response, true
		}
		return pcacheSearchResponse{}, false
	}
	if !database.pcache.state.completeRefresh(refresh, response, now) {
		return pcacheSearchResponse{}, false
	}
	return response, true
}

func (server *Server) matchPcacheRequest(
	runtime *runtimeState,
	configuration pcacheRuntimeConfiguration,
	request ldapwire.SearchRequest,
) (pcacheRequestMatch, bool) {
	if runtime == nil || runtime.schema == nil {
		return pcacheRequestMatch{}, false
	}
	base, err := runtime.schema.NormalizeDN(request.BaseDN)
	if err != nil {
		return pcacheRequestMatch{}, false
	}
	for _, template := range configuration.templates {
		if !pcacheFilterMatchesTemplate(runtime.schema, template.filter, request.Filter) {
			continue
		}
		set := configuration.attributeSets[template.attrset]
		if !pcacheAttributeSetAnswers(runtime, set, request.Attributes) {
			continue
		}
		filterKey, ok := pcacheSchemaFilterKey(runtime.schema, request.Filter)
		if !ok {
			continue
		}
		return pcacheRequestMatch{
			key: strings.Join([]string{
				base.Key(),
				strconv.Itoa(int(request.Scope)),
				filterKey,
				strconv.Itoa(set.index),
			}, "\x00"),
			template: template,
			attrset:  set,
		}, true
	}
	return pcacheRequestMatch{}, false
}

func pcacheAttributeSetAnswers(
	runtime *runtimeState,
	set pcacheAttributeSet,
	requested []string,
) bool {
	available := make(map[string]struct{}, len(set.attributes))
	for _, attribute := range set.attributes {
		available[attribute] = struct{}{}
	}
	if len(requested) == 0 {
		requested = []string{"*"}
	}
	for _, raw := range requested {
		attribute := strings.ToLower(strings.TrimSpace(raw))
		if attribute == "1.1" {
			continue
		}
		if _, found := available[attribute]; found {
			continue
		}
		if attribute == "*" || attribute == "+" {
			return false
		}
		base := strings.SplitN(attribute, ";", 2)[0]
		if _, known := runtime.schema.AttributeType(base); !known {
			continue
		}
		wildcard := "*"
		if runtime.schema.IsOperational(base) {
			wildcard = "+"
		}
		if _, found := available[wildcard]; !found {
			return false
		}
	}
	return true
}

func pcacheFilterMatchesTemplate(
	registry *schema.Registry,
	template,
	request directory.Filter,
) bool {
	if registry == nil {
		return false
	}
	if template.Kind == directory.FilterAnd || template.Kind == directory.FilterOr {
		return template.Kind == request.Kind &&
			pcacheUnorderedChildrenMatch(registry, template.Children, request.Children)
	}
	if template.Kind == directory.FilterEquality &&
		len(template.Assertion) == 0 && request.Kind == directory.FilterSubstrings {
		return pcacheAttributesEqual(registry, template.Attribute, request.Attribute) &&
			pcacheSubstringValid(registry, request.Attribute, request.Substring)
	}
	if template.Kind == directory.FilterSubstrings {
		if !pcacheAttributesEqual(registry, template.Attribute, request.Attribute) {
			return false
		}
		switch request.Kind {
		case directory.FilterEquality:
			matches, err := registry.MatchSubstring(
				request.Attribute,
				request.Assertion,
				template.Substring,
			)
			return err == nil && matches
		case directory.FilterSubstrings:
			return pcacheSubstringContains(
				registry,
				request.Attribute,
				template.Substring,
				request.Substring,
			)
		default:
			return false
		}
	}
	if template.Kind != request.Kind {
		return false
	}
	if template.Kind != directory.FilterExtensible &&
		!pcacheAttributesEqual(registry, template.Attribute, request.Attribute) {
		return false
	}
	switch template.Kind {
	case directory.FilterEquality:
		return pcacheEqualityTemplateMatches(
			registry,
			request.Attribute,
			template.Assertion,
			request.Assertion,
		)
	case directory.FilterGreaterOrEqual, directory.FilterLessOrEqual:
		if len(template.Assertion) == 0 {
			_, err := registry.CompareOrdering(
				request.Attribute,
				"",
				request.Assertion,
				request.Assertion,
			)
			return err == nil
		}
		comparison, err := registry.CompareOrdering(
			request.Attribute,
			"",
			request.Assertion,
			template.Assertion,
		)
		return err == nil && comparison == 0
	case directory.FilterPresent:
		return true
	case directory.FilterExtensible:
		return pcacheExtensibleTemplateMatches(registry, template, request)
	default:
		return false
	}
}

func pcacheUnorderedChildrenMatch(
	registry *schema.Registry,
	template,
	request []directory.Filter,
) bool {
	if len(template) != len(request) {
		return false
	}
	matched := make([]int, len(request))
	for index := range matched {
		matched[index] = -1
	}
	var assign func(int, []bool) bool
	assign = func(templateIndex int, seen []bool) bool {
		for requestIndex := range request {
			if seen[requestIndex] || !pcacheFilterMatchesTemplate(
				registry,
				template[templateIndex],
				request[requestIndex],
			) {
				continue
			}
			seen[requestIndex] = true
			if matched[requestIndex] < 0 || assign(matched[requestIndex], seen) {
				matched[requestIndex] = templateIndex
				return true
			}
		}
		return false
	}
	for templateIndex := range template {
		if !assign(templateIndex, make([]bool, len(request))) {
			return false
		}
	}
	return true
}

func pcacheAttributesEqual(registry *schema.Registry, left, right string) bool {
	leftKey, leftOK := pcacheAttributeKey(registry, left)
	rightKey, rightOK := pcacheAttributeKey(registry, right)
	return leftOK && rightOK && leftKey == rightKey
}

func pcacheAttributeKey(registry *schema.Registry, description string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(description), ";")
	if len(parts) == 0 || parts[0] == "" {
		return "", false
	}
	attribute, found := registry.AttributeType(parts[0])
	if !found {
		return "", false
	}
	options := make([]string, 0, len(parts)-1)
	seen := make(map[string]struct{}, len(parts)-1)
	for _, raw := range parts[1:] {
		option := strings.ToLower(strings.TrimSpace(raw))
		if option == "" {
			return "", false
		}
		if _, duplicate := seen[option]; duplicate {
			continue
		}
		seen[option] = struct{}{}
		options = append(options, option)
	}
	sort.Strings(options)
	return strings.ToLower(attribute.OID) + ";" + strings.Join(options, ";"), true
}

func pcacheEqualityTemplateMatches(
	registry *schema.Registry,
	attribute string,
	template,
	request []byte,
) bool {
	if _, err := registry.NormalizeEqualityAssertion(attribute, request); err != nil {
		return false
	}
	if len(template) == 0 {
		return true
	}
	if _, err := registry.NormalizeEqualityAssertion(attribute, template); err != nil {
		return false
	}
	comparison, err := registry.Compare(attribute, "", request, template)
	return err == nil && comparison == 0
}

func pcacheSubstringValid(
	registry *schema.Registry,
	attribute string,
	value directory.Substring,
) bool {
	_, ok := pcacheNormalizeSubstring(registry, attribute, value)
	return ok
}

// pcacheSubstringContains follows OpenLDAP's stored-vs-incoming direction:
// every value selected by incoming must also be selected by stored.
func pcacheSubstringContains(
	registry *schema.Registry,
	attribute string,
	stored,
	incoming directory.Substring,
) bool {
	stored, storedOK := pcacheNormalizeSubstring(registry, attribute, stored)
	incoming, incomingOK := pcacheNormalizeSubstring(registry, attribute, incoming)
	if !storedOK || !incomingOK ||
		(incoming.Initial == nil && stored.Initial != nil) ||
		(incoming.Final == nil && stored.Final != nil) {
		return false
	}
	initial, ok := pcacheTrimPrefix(incoming.Initial, stored.Initial)
	if !ok {
		return false
	}
	final, ok := pcacheTrimSuffix(incoming.Final, stored.Final)
	if !ok {
		return false
	}
	if len(stored.Any) == 0 {
		return true
	}
	remaining := make([][]byte, 0, len(incoming.Any)+2)
	if incoming.Initial != nil {
		remaining = append(remaining, initial)
	}
	remaining = append(remaining, incoming.Any...)
	if incoming.Final != nil {
		remaining = append(remaining, final)
	}
	position := 0
	for _, part := range stored.Any {
		found := false
		for index := position; index < len(remaining); index++ {
			offset := bytes.Index(remaining[index], part)
			if offset < 0 {
				continue
			}
			remaining[index] = append(
				remaining[index][:offset:offset],
				remaining[index][offset+len(part):]...,
			)
			position = index
			found = true
			break
		}
		if !found {
			return false
		}
	}
	return true
}

func pcacheTrimPrefix(value, prefix []byte) ([]byte, bool) {
	if prefix == nil {
		return bytes.Clone(value), true
	}
	if value == nil || !bytes.HasPrefix(value, prefix) {
		return nil, false
	}
	return bytes.Clone(value[len(prefix):]), true
}

func pcacheTrimSuffix(value, suffix []byte) ([]byte, bool) {
	if suffix == nil {
		return bytes.Clone(value), true
	}
	if value == nil || !bytes.HasSuffix(value, suffix) {
		return nil, false
	}
	return bytes.Clone(value[:len(value)-len(suffix)]), true
}

func pcacheNormalizeSubstring(
	registry *schema.Registry,
	attribute string,
	value directory.Substring,
) (directory.Substring, bool) {
	if value.Initial == nil && len(value.Any) == 0 && value.Final == nil {
		return directory.Substring{}, false
	}
	effective, found, err := registry.EffectiveAttributeType(attribute)
	if err != nil || !found || effective.Substring == "" {
		return directory.Substring{}, false
	}
	normalize, ok := pcacheSubstringNormalizer(effective.Substring)
	if !ok {
		return directory.Substring{}, false
	}
	normalized := directory.Substring{
		Initial: pcacheNormalizeOptionalSubstringPart(value.Initial, normalize),
		Any:     make([][]byte, len(value.Any)),
		Final:   pcacheNormalizeOptionalSubstringPart(value.Final, normalize),
	}
	for index := range value.Any {
		normalized.Any[index] = normalize(value.Any[index])
	}
	return normalized, true
}

func pcacheNormalizeOptionalSubstringPart(
	value []byte,
	normalize func([]byte) []byte,
) []byte {
	if value == nil {
		return nil
	}
	return normalize(value)
}

func pcacheSubstringNormalizer(rule string) (func([]byte) []byte, bool) {
	switch strings.ToLower(strings.TrimSpace(rule)) {
	case "caseignoresubstringsmatch", "caseignoreia5substringsmatch",
		"caseignorelistsubstringsmatch", "2.5.13.4", "1.3.6.1.4.1.1466.109.114.3",
		"2.5.13.12":
		return func(value []byte) []byte {
			return bytes.ToLower([]byte(strings.Join(strings.Fields(string(value)), " ")))
		}, true
	case "caseexactsubstringsmatch", "caseexactia5substringsmatch",
		"2.5.13.7", "1.3.6.1.4.1.1466.109.114.4":
		return func(value []byte) []byte {
			return []byte(strings.Join(strings.Fields(string(value)), " "))
		}, true
	case "telephonenumbersubstringsmatch", "2.5.13.21":
		return func(value []byte) []byte {
			normalized := make([]byte, 0, len(value))
			for _, character := range bytes.ToLower(value) {
				if character != ' ' && character != '-' {
					normalized = append(normalized, character)
				}
			}
			return normalized
		}, true
	case "numericstringsubstringsmatch", "2.5.13.10":
		return func(value []byte) []byte {
			normalized := make([]byte, 0, len(value))
			for _, character := range value {
				if character != ' ' {
					normalized = append(normalized, character)
				}
			}
			return normalized
		}, true
	default:
		return nil, false
	}
}

func pcacheExtensibleTemplateMatches(
	registry *schema.Registry,
	template,
	request directory.Filter,
) bool {
	if template.DNAttributes != request.DNAttributes ||
		(template.Attribute == "") != (request.Attribute == "") {
		return false
	}
	attribute := request.Attribute
	if attribute != "" &&
		!pcacheAttributesEqual(registry, template.Attribute, request.Attribute) {
		return false
	}
	templateRule, templateOK := pcacheExtensibleRule(registry, template)
	requestRule, requestOK := pcacheExtensibleRule(registry, request)
	if !templateOK || !requestOK || templateRule != requestRule {
		return false
	}
	anchor := attribute
	if anchor == "" {
		anchor = "objectClass"
	}
	if len(template.Assertion) == 0 {
		_, err := registry.Compare(
			anchor,
			requestRule,
			request.Assertion,
			request.Assertion,
		)
		return err == nil
	}
	comparison, err := registry.Compare(
		anchor,
		requestRule,
		request.Assertion,
		template.Assertion,
	)
	return err == nil && comparison == 0
}

func pcacheExtensibleRule(
	registry *schema.Registry,
	filter directory.Filter,
) (string, bool) {
	rule := filter.MatchingRule
	anchor := filter.Attribute
	if rule == "" {
		if anchor == "" {
			return "", false
		}
		effective, found, err := registry.EffectiveAttributeType(anchor)
		if err != nil || !found || effective.Equality == "" {
			return "", false
		}
		rule = effective.Equality
	}
	if anchor == "" {
		anchor = "objectClass"
	}
	canonical, err := registry.OrderingRule(anchor, rule)
	return canonical, err == nil
}

func pcacheSchemaFilterKey(
	registry *schema.Registry,
	filter directory.Filter,
) (string, bool) {
	var value strings.Builder
	if !pcacheAppendSchemaFilterKey(&value, registry, filter) {
		return "", false
	}
	return value.String(), true
}

func pcacheAppendSchemaFilterKey(
	value *strings.Builder,
	registry *schema.Registry,
	filter directory.Filter,
) bool {
	attribute := ""
	if filter.Attribute != "" {
		var ok bool
		attribute, ok = pcacheAttributeKey(registry, filter.Attribute)
		if !ok {
			return false
		}
	}
	rule := ""
	if filter.Kind == directory.FilterExtensible {
		var ok bool
		rule, ok = pcacheExtensibleRule(registry, filter)
		if !ok {
			return false
		}
	}
	assertion := filter.Assertion
	substring := filter.Substring
	var err error
	switch filter.Kind {
	case directory.FilterEquality:
		assertion, err = registry.NormalizeEqualityAssertion(filter.Attribute, assertion)
		if err != nil {
			return false
		}
	case directory.FilterSubstrings:
		var ok bool
		substring, ok = pcacheNormalizeSubstring(registry, filter.Attribute, substring)
		if !ok {
			return false
		}
	case directory.FilterGreaterOrEqual, directory.FilterLessOrEqual:
		if _, err := registry.CompareOrdering(
			filter.Attribute,
			"",
			filter.Assertion,
			filter.Assertion,
		); err != nil {
			return false
		}
	case directory.FilterPresent:
	case directory.FilterAnd, directory.FilterOr:
	case directory.FilterExtensible:
		anchor := filter.Attribute
		if anchor == "" {
			anchor = "objectClass"
		}
		if _, err := registry.Compare(anchor, rule, assertion, assertion); err != nil {
			return false
		}
	default:
		return false
	}
	fmt.Fprintf(
		value,
		"%d[%s|%s|%t|%s|",
		filter.Kind,
		attribute,
		rule,
		filter.DNAttributes,
		hex.EncodeToString(assertion),
	)
	if substring.Initial != nil {
		value.WriteString("i" + hex.EncodeToString(substring.Initial))
	}
	for _, part := range substring.Any {
		value.WriteString("a" + hex.EncodeToString(part))
	}
	if substring.Final != nil {
		value.WriteString("f" + hex.EncodeToString(substring.Final))
	}
	value.WriteByte('|')
	children := make([]string, len(filter.Children))
	for index := range filter.Children {
		var child strings.Builder
		if !pcacheAppendSchemaFilterKey(&child, registry, filter.Children[index]) {
			return false
		}
		children[index] = child.String()
	}
	if filter.Kind == directory.FilterAnd || filter.Kind == directory.FilterOr {
		sort.Strings(children)
	}
	for _, child := range children {
		value.WriteString(child)
	}
	value.WriteByte(']')
	return true
}

func pcacheFilterKey(filter directory.Filter) string {
	var value strings.Builder
	pcacheAppendFilterKey(&value, filter)
	return value.String()
}

func pcacheAppendFilterKey(value *strings.Builder, filter directory.Filter) {
	fmt.Fprintf(
		value,
		"%d[%s|%s|%t|%s|",
		filter.Kind,
		strings.ToLower(filter.Attribute),
		strings.ToLower(filter.MatchingRule),
		filter.DNAttributes,
		hex.EncodeToString(filter.Assertion),
	)
	if filter.Substring.Initial != nil {
		value.WriteString("i" + hex.EncodeToString(filter.Substring.Initial))
	}
	for _, part := range filter.Substring.Any {
		value.WriteString("a" + hex.EncodeToString(part))
	}
	if filter.Substring.Final != nil {
		value.WriteString("f" + hex.EncodeToString(filter.Substring.Final))
	}
	value.WriteByte('|')
	for _, child := range filter.Children {
		pcacheAppendFilterKey(value, child)
	}
	value.WriteByte(']')
}

func pcacheWithoutPagingControls(controls []ldapwire.Control) []ldapwire.Control {
	filtered := make([]ldapwire.Control, 0, len(controls))
	for _, control := range controls {
		if control.OID != pagedResultsControlOID {
			filtered = append(filtered, control)
		}
	}
	return filtered
}

func decodePcacheSearchAttempt(attempt chainAttempt) (pcacheSearchResponse, error) {
	if !attempt.hasResult {
		return pcacheSearchResponse{}, errors.New("pcache search has no final result")
	}
	response := pcacheSearchResponse{result: attempt.result}
	done := false
	for _, packet := range attempt.packets {
		if packet == nil || len(packet.Children) < 2 {
			return pcacheSearchResponse{}, errors.New("malformed pcache search response")
		}
		controls, err := decodePBindResponseControls(packet)
		if err != nil {
			return pcacheSearchResponse{}, err
		}
		switch uint64(packet.Children[1].Tag) {
		case ldapwire.ApplicationSearchResultEntry:
			entry, err := decodeTranslucentSearchEntry(packet)
			if err != nil {
				return pcacheSearchResponse{}, err
			}
			response.items = append(response.items, pcacheSearchItem{
				entry:    &entry,
				controls: cloneLDAPControls(controls),
			})
		case ldapwire.ApplicationSearchResultReference:
			references, err := chainSearchReferences(packet)
			if err != nil {
				return pcacheSearchResponse{}, err
			}
			response.items = append(response.items, pcacheSearchItem{
				references: append([]string(nil), references...),
				controls:   cloneLDAPControls(controls),
			})
		case ldapwire.ApplicationSearchResultDone:
			response.doneControls = pcacheWithoutPagingControls(controls)
			done = true
		default:
			return pcacheSearchResponse{}, fmt.Errorf(
				"pcache cannot stage response tag %d",
				packet.Children[1].Tag,
			)
		}
	}
	if !done {
		return pcacheSearchResponse{}, errors.New("pcache search response has no SearchResultDone")
	}
	return response, nil
}

func (response pcacheSearchResponse) entryCount() int {
	count := 0
	for _, item := range response.items {
		if item.entry != nil {
			count++
		}
	}
	return count
}

func pcacheResponseCacheable(
	registry *schema.Registry,
	filter directory.Filter,
	response pcacheSearchResponse,
	validateFilter bool,
) bool {
	if validateFilter && registry == nil {
		return false
	}
	for _, item := range response.items {
		if item.entry == nil {
			continue
		}
		for _, attribute := range item.entry.Attributes {
			// OpenLDAP rejects malformed response attributes even when
			// pcacheValidate is disabled.
			if len(attribute.Values) == 0 {
				return false
			}
		}
		if !validateFilter {
			continue
		}
		matches, err := pcacheResponseFilterMatches(
			registry,
			filter,
			*item.entry,
		)
		if err != nil || !matches {
			return false
		}
	}
	return true
}

func pcacheResponseFilterMatches(
	registry *schema.Registry,
	filter directory.Filter,
	entry directory.Entry,
) (bool, error) {
	switch filter.Kind {
	case directory.FilterAnd:
		for _, child := range filter.Children {
			matches, err := pcacheResponseFilterMatches(registry, child, entry)
			if err != nil || !matches {
				return matches, err
			}
		}
		return true, nil
	case directory.FilterOr:
		for _, child := range filter.Children {
			matches, err := pcacheResponseFilterMatches(registry, child, entry)
			if err != nil {
				return false, err
			}
			if matches {
				return true, nil
			}
		}
		return false, nil
	case directory.FilterNot:
		if len(filter.Children) != 1 {
			return false, errors.New("not filter requires exactly one child")
		}
		matches, err := pcacheResponseFilterMatches(
			registry,
			filter.Children[0],
			entry,
		)
		return !matches, err
	case directory.FilterExtensible:
		if !filter.DNAttributes {
			return filter.MatchWith(entry, registry)
		}
		withDNAttributes, err := pcacheEntryWithDNAttributes(registry, entry)
		if err != nil {
			return false, err
		}
		filter.DNAttributes = false
		return filter.MatchWith(withDNAttributes, registry)
	default:
		return filter.MatchWith(entry, registry)
	}
}

func pcacheEntryWithDNAttributes(
	registry *schema.Registry,
	entry directory.Entry,
) (directory.Entry, error) {
	dn, err := registry.NormalizeDN(entry.DN)
	if err != nil {
		return directory.Entry{}, err
	}
	result := entry.Clone()
	for dn.Depth() > 0 {
		for _, value := range dn.RDNValues() {
			result.Attributes = append(result.Attributes, directory.Attribute{
				Description: value.Type,
				Values:      [][]byte{bytes.Clone(value.Value)},
			})
		}
		parent, ok := dn.Parent()
		if !ok {
			break
		}
		dn = parent
	}
	return result, nil
}

func (server *Server) writePcacheResponse(
	connection net.Conn,
	messageID int64,
	runtime *runtimeState,
	request ldapwire.SearchRequest,
	response pcacheSearchResponse,
	cacheHit bool,
) error {
	for _, item := range response.items {
		switch {
		case item.entry != nil:
			selected := server.selectEntry(
				runtime,
				item.entry.Clone(),
				request.Attributes,
				request.TypesOnly,
			)
			if err := ldapwire.Write(
				connection,
				ldapwire.EncodeSearchResultEntry(messageID, selected, item.controls),
			); err != nil {
				return err
			}
		case len(item.references) != 0:
			if err := ldapwire.Write(
				connection,
				ldapwire.EncodeSearchResultReference(
					messageID,
					item.references,
					item.controls,
				),
			); err != nil {
				return err
			}
		}
	}
	result := response.result
	controls := response.doneControls
	if cacheHit {
		result.Code = ldapwire.ResultSuccess
	}
	return server.writeSearchDoneWithControls(
		connection,
		messageID,
		result,
		pcacheWithoutPagingControls(controls),
	)
}

func (state *pcacheState) lookup(
	key string,
	now time.Time,
	offline bool,
) (pcacheSearchResponse, bool, *pcacheRefreshLease) {
	return state.lookupValidated(key, now, offline, nil)
}

func (state *pcacheState) lookupValidated(
	key string,
	now time.Time,
	offline bool,
	validate func(pcacheSearchResponse) bool,
) (pcacheSearchResponse, bool, *pcacheRefreshLease) {
	state.mu.Lock()
	defer state.mu.Unlock()
	var backup pcacheStateBackup
	if !offline {
		backup = state.backupLocked()
		if state.purgeExpired(now) {
			if !state.finishMutationLocked(backup) {
				return pcacheSearchResponse{}, false, nil
			}
		} else {
			clearPcacheBackup(backup)
		}
	}
	query, found := state.queries[key]
	if !found {
		return pcacheSearchResponse{}, false, nil
	}
	if validate != nil && !validate(query.response) {
		backup := state.backupLocked()
		state.removeQueryLocked(key, query)
		state.generation++
		state.finishMutationLocked(backup)
		return pcacheSearchResponse{}, false, nil
	}
	state.sequence++
	query.lastUsed = state.sequence
	query.referenced = true
	var refresh *pcacheRefreshLease
	if !offline && !query.refreshAt.IsZero() && now.After(query.refreshAt) &&
		!query.refreshing {
		ttl := query.policy.positiveTTL
		if query.entries == 0 {
			ttl = query.policy.negativeTTL
		}
		if ttl > 0 {
			query.purgeAt = state.expirationTime(
				now,
				ttl,
				query.policy.consistencyPeriod,
			)
		}
		query.referenced = false
		query.refreshing = true
		refresh = &pcacheRefreshLease{
			key:        key,
			generation: query.generation,
			replay:     clonePcacheMessage(query.replay),
			remote:     clonePcacheRemoteContext(query.remote),
			policy:     query.policy,
		}
	}
	state.queries[key] = query
	return clonePcacheSearchResponse(query.response), true, refresh
}

func (state *pcacheState) rememberBind(
	key string,
	password []byte,
	now time.Time,
	ttl time.Duration,
	maxEntries,
	maxQueries int,
) bool {
	if key == "" || len(password) == 0 || ttl <= 0 ||
		maxEntries <= 0 || maxQueries <= 0 {
		return false
	}
	passwordHash, err := auth.HashPasswordSMPBKDF2(
		password,
		auth.DefaultSMPBKDF2Iterations,
		nil,
	)
	if err != nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	backup := state.backupLocked()
	state.purgeExpired(now)
	if existing, found := state.binds[key]; found {
		clear(existing.passwordHash)
		state.sequence++
		state.generation++
		state.binds[key] = pcacheCachedBind{
			passwordHash: passwordHash,
			purgeAt:      now.Add(ttl),
			lastUsed:     state.sequence,
			generation:   state.generation,
		}
		return state.finishMutationLocked(backup)
	}
	if len(state.queries)+len(state.binds) >= maxQueries {
		clear(passwordHash)
		state.restoreBackupLocked(backup)
		return false
	}
	for state.entries > maxEntries {
		if !state.evictLeastRecentlyUsed() {
			clear(passwordHash)
			state.restoreBackupLocked(backup)
			return false
		}
	}
	state.sequence++
	state.generation++
	state.binds[key] = pcacheCachedBind{
		passwordHash: passwordHash,
		purgeAt:      now.Add(ttl),
		lastUsed:     state.sequence,
		generation:   state.generation,
	}
	state.entries++
	return state.finishMutationLocked(backup)
}

func (state *pcacheState) lookupBind(
	key string,
	password []byte,
	now time.Time,
	offline bool,
) bool {
	if key == "" || len(password) == 0 {
		return false
	}
	state.mu.Lock()
	if !offline {
		state.purgeExpired(now)
	}
	cached, found := state.binds[key]
	if !found {
		state.mu.Unlock()
		return false
	}
	passwordHash := bytes.Clone(cached.passwordHash)
	generation := cached.generation
	state.mu.Unlock()

	matches := auth.VerifyPassword(passwordHash, password)
	clear(passwordHash)
	if !matches {
		return false
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	cached, found = state.binds[key]
	if !found || cached.generation != generation ||
		(!offline && !now.Before(cached.purgeAt)) {
		return false
	}
	state.sequence++
	cached.lastUsed = state.sequence
	state.binds[key] = cached
	return true
}

func (state *pcacheState) clearBinds() {
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	backup := state.backupLocked()
	for key, bind := range state.binds {
		clear(bind.passwordHash)
		delete(state.binds, key)
		state.entries--
	}
	if state.entries < 0 {
		state.entries = 0
	}
	state.generation++
	state.finishMutationLocked(backup)
}

func (state *pcacheState) commit(
	key string,
	response pcacheSearchResponse,
	replay ldapwire.Message,
	remote pcacheRemoteContext,
	now time.Time,
	policy pcacheRefreshPolicy,
	maxEntries int,
	maxQueries int,
	offline bool,
) bool {
	entries := response.entryCount()
	ttl := policy.positiveTTL
	if entries == 0 {
		ttl = policy.negativeTTL
	}
	if ttl <= 0 {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	backup := state.backupLocked()
	if !offline {
		state.purgeExpired(now)
	}
	if _, duplicate := state.queries[key]; duplicate {
		state.restoreBackupLocked(backup)
		return false
	}
	if maxQueries <= 0 || len(state.queries)+len(state.binds) >= maxQueries {
		state.restoreBackupLocked(backup)
		return false
	}
	for index := 0; index < entries; index++ {
		for state.entries > maxEntries {
			if !state.evictLeastRecentlyUsed() {
				state.restoreBackupLocked(backup)
				return false
			}
		}
		state.entries++
	}
	state.sequence++
	state.generation++
	query := pcacheCachedQuery{
		identifier: newPcacheQueryIdentifier(entries),
		attrset:    policy.attrset,
		response:   clonePcacheSearchResponse(response),
		replay:     clonePcacheMessage(replay),
		remote:     clonePcacheRemoteContext(remote),
		policy:     policy,
		purgeAt:    state.expirationTime(now, ttl, policy.consistencyPeriod),
		entries:    entries,
		lastUsed:   state.sequence,
		generation: state.generation,
		referenced: true,
	}
	if policy.ttr > 0 {
		query.refreshAt = now.Add(policy.ttr)
	}
	state.queries[key] = query
	return state.finishMutationLocked(backup)
}

func (state *pcacheState) completeRefresh(
	refresh pcacheRefreshLease,
	response pcacheSearchResponse,
	now time.Time,
) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	backup := state.backupLocked()
	query, found := state.queries[refresh.key]
	if !found || query.generation != refresh.generation || !query.refreshing {
		clearPcacheBackup(backup)
		return false
	}
	entries := response.entryCount()
	ttl := refresh.policy.positiveTTL
	if entries == 0 {
		ttl = refresh.policy.negativeTTL
	}
	state.entries -= query.entries
	if ttl <= 0 {
		clear(query.remote.bindCredentials)
		delete(state.queries, refresh.key)
		state.generation++
		return state.finishMutationLocked(backup)
	}
	state.entries += entries
	query.response = clonePcacheSearchResponse(response)
	query.entries = entries
	if entries == 0 {
		query.identifier = ""
	} else if query.identifier == "" {
		query.identifier = newPcacheQueryIdentifier(entries)
	}
	query.purgeAt = state.expirationTime(
		now,
		ttl,
		refresh.policy.consistencyPeriod,
	)
	query.refreshing = false
	if refresh.policy.ttr > 0 {
		query.refreshAt = now.Add(refresh.policy.ttr)
	} else {
		query.refreshAt = time.Time{}
	}
	state.queries[refresh.key] = query
	state.generation++
	return state.finishMutationLocked(backup)
}

func (state *pcacheState) invalidateRefresh(refresh pcacheRefreshLease) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	backup := state.backupLocked()
	query, found := state.queries[refresh.key]
	if !found || query.generation != refresh.generation || !query.refreshing {
		clearPcacheBackup(backup)
		return false
	}
	state.removeQueryLocked(refresh.key, query)
	state.generation++
	return state.finishMutationLocked(backup)
}

func (state *pcacheState) abortRefresh(refresh pcacheRefreshLease, now time.Time) {
	state.mu.Lock()
	defer state.mu.Unlock()
	query, found := state.queries[refresh.key]
	if !found || query.generation != refresh.generation || !query.refreshing {
		return
	}
	query.refreshing = false
	if refresh.policy.ttr > 0 {
		query.refreshAt = now.Add(refresh.policy.ttr)
	} else {
		query.refreshAt = time.Time{}
	}
	state.queries[refresh.key] = query
}

func (state *pcacheState) expirationTime(
	now time.Time,
	ttl time.Duration,
	consistencyPeriod time.Duration,
) time.Time {
	purgeAt := now.Add(ttl)
	if consistencyPeriod <= 0 {
		return purgeAt
	}
	elapsed := purgeAt.Sub(state.epoch)
	if elapsed <= 0 {
		return purgeAt
	}
	ticks := (elapsed + consistencyPeriod - 1) / consistencyPeriod
	return state.epoch.Add(ticks * consistencyPeriod)
}

func (state *pcacheState) evictLeastRecentlyUsed() bool {
	var (
		candidateKey string
		candidate    pcacheCachedQuery
		found        bool
	)
	for key, query := range state.queries {
		if !found || query.lastUsed < candidate.lastUsed {
			candidateKey = key
			candidate = query
			found = true
		}
	}
	var (
		bindKey       string
		bindCandidate pcacheCachedBind
		bindFound     bool
	)
	for key, bind := range state.binds {
		if !bindFound || bind.lastUsed < bindCandidate.lastUsed {
			bindKey = key
			bindCandidate = bind
			bindFound = true
		}
	}
	if bindFound && (!found || bindCandidate.lastUsed < candidate.lastUsed) {
		state.entries--
		clear(bindCandidate.passwordHash)
		delete(state.binds, bindKey)
		return true
	}
	if !found {
		return false
	}
	state.removeQueryLocked(candidateKey, candidate)
	return true
}

func (state *pcacheState) purgeExpired(now time.Time) bool {
	changed := false
	for key, query := range state.queries {
		if now.Before(query.purgeAt) {
			continue
		}
		state.removeQueryLocked(key, query)
		changed = true
	}
	for key, bind := range state.binds {
		if now.Before(bind.purgeAt) {
			continue
		}
		state.entries--
		clear(bind.passwordHash)
		delete(state.binds, key)
		changed = true
	}
	if changed {
		state.generation++
	}
	return changed
}

func (state *pcacheState) removeQueryLocked(
	key string,
	query pcacheCachedQuery,
) {
	state.entries -= query.entries
	if state.entries < 0 {
		state.entries = 0
	}
	clear(query.remote.bindCredentials)
	delete(state.queries, key)
}

func clonePcacheMessage(message ldapwire.Message) ldapwire.Message {
	cloned := message
	cloned.Controls = cloneLDAPControls(message.Controls)
	request, ok := message.Request.(ldapwire.SearchRequest)
	if !ok {
		return cloned
	}
	request.Attributes = append([]string(nil), request.Attributes...)
	request.Filter = clonePcacheFilter(request.Filter)
	cloned.Request = request
	return cloned
}

func capturePcacheRemoteContext(state *connectionState) pcacheRemoteContext {
	return pcacheRemoteContext{
		connectionID:     state.connectionID,
		boundDN:          state.boundDN,
		operationRealDN:  state.operationRealDN,
		authMechanism:    state.authMechanism,
		bindCredentialDN: state.bindCredentialDN,
		bindCredentials:  bytes.Clone(state.bindCredentials),
		secure:           state.secure,
		externalSSF:      state.externalSSF,
		saslSSF:          state.saslSSF,
		externalDN:       state.externalDN,
	}
}

func clonePcacheRemoteContext(remote pcacheRemoteContext) pcacheRemoteContext {
	remote.bindCredentials = bytes.Clone(remote.bindCredentials)
	return remote
}

func (remote pcacheRemoteContext) connectionState(current *connectionState) *connectionState {
	state := *current
	state.connectionID = remote.connectionID
	state.boundDN = remote.boundDN
	state.operationRealDN = remote.operationRealDN
	state.authMechanism = remote.authMechanism
	state.bindCredentialDN = remote.bindCredentialDN
	state.bindCredentials = bytes.Clone(remote.bindCredentials)
	state.secure = remote.secure
	state.externalSSF = remote.externalSSF
	state.saslSSF = remote.saslSSF
	state.externalDN = remote.externalDN
	state.saslSession = nil
	state.pagedSearch = nil
	state.virtualListViews = nil
	state.sortSessionCounts = nil
	state.transaction = nil
	state.monitor = nil
	return &state
}

func clonePcacheFilter(filter directory.Filter) directory.Filter {
	cloned := filter
	cloned.Assertion = bytes.Clone(filter.Assertion)
	cloned.Substring.Initial = bytes.Clone(filter.Substring.Initial)
	cloned.Substring.Any = cloneByteValues(filter.Substring.Any)
	cloned.Substring.Final = bytes.Clone(filter.Substring.Final)
	cloned.Children = make([]directory.Filter, len(filter.Children))
	for index := range filter.Children {
		cloned.Children[index] = clonePcacheFilter(filter.Children[index])
	}
	return cloned
}

func clonePcacheSearchResponse(response pcacheSearchResponse) pcacheSearchResponse {
	cloned := pcacheSearchResponse{
		result: ldapwire.Result{
			Code:              response.result.Code,
			MatchedDN:         response.result.MatchedDN,
			DiagnosticMessage: response.result.DiagnosticMessage,
			Referrals:         append([]string(nil), response.result.Referrals...),
		},
		doneControls: cloneLDAPControls(response.doneControls),
		items:        make([]pcacheSearchItem, 0, len(response.items)),
	}
	for _, item := range response.items {
		copy := pcacheSearchItem{
			references: append([]string(nil), item.references...),
			controls:   cloneLDAPControls(item.controls),
		}
		if item.entry != nil {
			entry := item.entry.Clone()
			copy.entry = &entry
		}
		cloned.items = append(cloned.items, copy)
	}
	return cloned
}
