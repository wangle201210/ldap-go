package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	pcacheMaxAttributeSets  = 500
	pcacheDefaultMaxQueries = 10000
)

type pcacheRuntimeConfiguration struct {
	configDNKey       string
	disabled          bool
	maxEntries        int
	maxQueries        int
	entryLimit        int
	consistencyPeriod time.Duration
	offline           bool
	persist           bool // Accepted and fingerprinted; query state is intentionally not restored.
	attributeSets     []pcacheAttributeSet
	templates         []pcacheTemplate
	fingerprint       string
	state             *pcacheState
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

type pcacheState struct {
	mu         sync.Mutex
	epoch      time.Time
	clock      func() time.Time
	queries    map[string]pcacheCachedQuery
	entries    int
	sequence   uint64
	generation uint64
}

type pcacheCachedQuery struct {
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

	for _, name := range []string{
		"olcPcachePosition",
		"olcPcacheValidate", "olcProxyCheckCacheability",
		"olcPcacheBind",
	} {
		if len(overlay.Values(name)) != 0 {
			return configuration, fmt.Errorf(
				"%s %s is not implemented by pcache",
				overlay.DN,
				name,
			)
		}
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
	default:
		return false
	}
}

func pcacheConfigurationFingerprint(configuration pcacheRuntimeConfiguration) string {
	var value strings.Builder
	fmt.Fprintf(
		&value,
		"%d/%d/%d/%d/%t/%t/",
		configuration.maxEntries,
		configuration.maxQueries,
		configuration.entryLimit,
		configuration.consistencyPeriod,
		configuration.offline,
		configuration.persist,
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

func configurationKey(configuration *pcacheRuntimeConfiguration) string {
	if configuration == nil {
		return ""
	}
	return configuration.configDNKey
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
	if cached, found, refresh := database.pcache.state.lookup(
		match.key,
		now,
		database.pcache.offline,
	); found {
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
	if response.result.Code == ldapwire.ResultSuccess && entryCount <= database.pcache.entryLimit {
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
	base, err := directory.ParseDN(request.BaseDN)
	if err != nil {
		return pcacheRequestMatch{}, false
	}
	for _, template := range configuration.templates {
		if !pcacheFilterMatchesTemplate(template.filter, request.Filter) {
			continue
		}
		set := configuration.attributeSets[template.attrset]
		if !pcacheAttributeSetAnswers(runtime, set, request.Attributes) {
			continue
		}
		return pcacheRequestMatch{
			key: strings.Join([]string{
				base.Key(),
				strconv.Itoa(int(request.Scope)),
				pcacheFilterKey(request.Filter),
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

func pcacheFilterMatchesTemplate(template, request directory.Filter) bool {
	if template.Kind != request.Kind ||
		!strings.EqualFold(template.Attribute, request.Attribute) ||
		!strings.EqualFold(template.MatchingRule, request.MatchingRule) ||
		template.DNAttributes != request.DNAttributes ||
		len(template.Children) != len(request.Children) {
		return false
	}
	for index := range template.Children {
		if !pcacheFilterMatchesTemplate(template.Children[index], request.Children[index]) {
			return false
		}
	}
	switch template.Kind {
	case directory.FilterEquality,
		directory.FilterGreaterOrEqual,
		directory.FilterLessOrEqual:
		return len(template.Assertion) == 0 || bytes.EqualFold(template.Assertion, request.Assertion)
	case directory.FilterSubstrings:
		return pcacheSubstringPrototypeMatches(template.Substring, request.Substring)
	default:
		return true
	}
}

func pcacheSubstringPrototypeMatches(template, request directory.Substring) bool {
	if (template.Initial == nil) != (request.Initial == nil) ||
		(template.Final == nil) != (request.Final == nil) ||
		len(template.Any) != len(request.Any) {
		return false
	}
	if len(template.Initial) != 0 && !bytes.EqualFold(template.Initial, request.Initial) {
		return false
	}
	if len(template.Final) != 0 && !bytes.EqualFold(template.Final, request.Final) {
		return false
	}
	for index := range template.Any {
		if len(template.Any[index]) != 0 &&
			!bytes.EqualFold(template.Any[index], request.Any[index]) {
			return false
		}
	}
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
	state.mu.Lock()
	defer state.mu.Unlock()
	if !offline {
		state.purgeExpired(now)
	}
	query, found := state.queries[key]
	if !found {
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
	if !offline {
		state.purgeExpired(now)
	}
	if _, duplicate := state.queries[key]; duplicate {
		return false
	}
	if maxQueries <= 0 || len(state.queries) >= maxQueries {
		return false
	}
	for index := 0; index < entries; index++ {
		for state.entries > maxEntries {
			if !state.evictLeastRecentlyUsed() {
				return false
			}
		}
		state.entries++
	}
	state.sequence++
	state.generation++
	query := pcacheCachedQuery{
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
	return true
}

func (state *pcacheState) completeRefresh(
	refresh pcacheRefreshLease,
	response pcacheSearchResponse,
	now time.Time,
) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	query, found := state.queries[refresh.key]
	if !found || query.generation != refresh.generation || !query.refreshing {
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
		return true
	}
	state.entries += entries
	query.response = clonePcacheSearchResponse(response)
	query.entries = entries
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
	return true
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
	if !found {
		return false
	}
	state.entries -= candidate.entries
	clear(candidate.remote.bindCredentials)
	delete(state.queries, candidateKey)
	return true
}

func (state *pcacheState) purgeExpired(now time.Time) {
	for key, query := range state.queries {
		if now.Before(query.purgeAt) {
			continue
		}
		state.entries -= query.entries
		clear(query.remote.bindCredentials)
		delete(state.queries, key)
	}
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
