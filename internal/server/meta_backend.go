package server

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const metaBackendNoDefaultTarget = -1

// metaBackendRuntimeConfiguration is an immutable snapshot of one back-meta
// database and its directly-owned olcMetaSub target entries.
type metaBackendRuntimeConfiguration struct {
	configDNKey         string
	suffixes            []directory.DN
	targets             []metaBackendTargetRuntimeConfiguration
	defaultTarget       int
	onError             string
	dnCacheTTL          time.Duration
	pseudoRootBindDefer bool
}

type metaBackendTargetRuntimeConfiguration struct {
	configDNKey         string
	transportGeneration uint64
	// OpenLDAP 2.6.13 leaves an online URI replacement unroutable until restart.
	onlineURIUnavailable bool
	order                int
	suffix               directory.DN
	scope                directory.Scope
	clientPr             int
	ldapBackend          *ldapBackendRuntimeConfiguration
	rwm                  *rwmRuntimeConfiguration
	subtrees             []metaBackendSubtreeRule
	exclude              bool
	filters              []*regexp.Regexp
	health               *pbindQuarantineState
	preferred            *proxyPreferredRemoteState
}

type metaBackendSubtreeRule struct {
	kind    string
	dn      directory.DN
	pattern *regexp.Regexp
}

func loadMetaBackendRuntimeConfiguration(
	reader storage.Reader,
	databaseEntry directory.Entry,
) (*metaBackendRuntimeConfiguration, error) {
	databaseDN, suffixes, err := validateMetaBackendDatabase(databaseEntry)
	if err != nil {
		return nil, err
	}
	if err := validateMetaBackendCompatibilitySettings(databaseEntry); err != nil {
		return nil, err
	}

	type orderedTarget struct {
		entry directory.Entry
		order int
		key   string
	}
	var children []orderedTarget
	if err := reader.ForEach(func(entry directory.Entry) error {
		entryDN, parseErr := directory.ParseDN(entry.DN)
		if parseErr != nil {
			return fmt.Errorf("parse entry DN %q: %w", entry.DN, parseErr)
		}
		parent, ok := entryDN.Parent()
		if !ok || !parent.Equal(databaseDN) || !metaBackendTargetEntry(entry, entryDN) {
			return nil
		}
		order, validateErr := validateMetaBackendTargetIdentity(entry, entryDN)
		if validateErr != nil {
			return validateErr
		}
		children = append(children, orderedTarget{
			entry: entry.Clone(),
			order: order,
			key:   entryDN.Key(),
		})
		return nil
	}); err != nil {
		return nil, fmt.Errorf("load %s back-meta targets: %w", databaseEntry.DN, err)
	}
	sort.SliceStable(children, func(left, right int) bool {
		if children[left].order != children[right].order {
			return children[left].order < children[right].order
		}
		return children[left].key < children[right].key
	})
	for index := 1; index < len(children); index++ {
		if children[index-1].order == children[index].order {
			return nil, fmt.Errorf(
				"%s and %s use duplicate olcMetaSub order %d",
				children[index-1].entry.DN,
				children[index].entry.DN,
				children[index].order,
			)
		}
	}

	configuration := &metaBackendRuntimeConfiguration{
		configDNKey:         databaseDN.Key(),
		suffixes:            append([]directory.DN(nil), suffixes...),
		targets:             make([]metaBackendTargetRuntimeConfiguration, 0, len(children)),
		defaultTarget:       metaBackendNoDefaultTarget,
		pseudoRootBindDefer: true,
	}
	for _, child := range children {
		target, loadErr := loadMetaBackendTarget(
			databaseEntry,
			child.entry,
			child.order,
			suffixes,
		)
		if loadErr != nil {
			return nil, loadErr
		}
		configuration.targets = append(configuration.targets, target)
	}
	configuration.defaultTarget, err = loadMetaBackendDefaultTarget(
		databaseEntry,
		len(configuration.targets),
	)
	if err != nil {
		return nil, err
	}
	configuration.onError, err = loadMetaBackendOnError(databaseEntry)
	if err != nil {
		return nil, err
	}
	configuration.dnCacheTTL, err = loadMetaBackendDNCacheTTL(databaseEntry)
	if err != nil {
		return nil, err
	}
	if value, present, parseErr := singleBoolean(
		databaseEntry,
		"olcDbPseudoRootBindDefer",
	); parseErr != nil {
		return nil, parseErr
	} else if present {
		configuration.pseudoRootBindDefer = value
	}
	return configuration, nil
}

func loadMetaBackendOnError(entry directory.Entry) (string, error) {
	values := entry.Values("olcDbOnErr")
	if len(values) == 0 {
		return "continue", nil
	}
	if len(values) != 1 {
		return "", fmt.Errorf("%s olcDbOnErr must be single-valued", entry.DN)
	}
	value := strings.ToLower(strings.TrimSpace(string(values[0])))
	switch value {
	case "continue", "report", "stop":
		return value, nil
	default:
		return "", fmt.Errorf("%s olcDbOnErr has invalid value %q", entry.DN, values[0])
	}
}

func loadMetaBackendDNCacheTTL(entry directory.Entry) (time.Duration, error) {
	values := entry.Values("olcDbDnCacheTtl")
	if len(values) == 0 {
		return 0, nil
	}
	if len(values) != 1 {
		return 0, fmt.Errorf("%s olcDbDnCacheTtl must be single-valued", entry.DN)
	}
	value := strings.ToLower(strings.TrimSpace(string(values[0])))
	switch value {
	case "disabled":
		return 0, nil
	case "forever":
		return -1, nil
	default:
		ttl, err := parseOpenLDAPTimeInterval(value)
		if err != nil {
			return 0, fmt.Errorf("%s olcDbDnCacheTtl: %w", entry.DN, err)
		}
		return ttl, nil
	}
}

func validateMetaBackendDatabase(
	entry directory.Entry,
) (directory.DN, []directory.DN, error) {
	entryDN, err := directory.ParseDN(entry.DN)
	if err != nil {
		return directory.DN{}, nil, fmt.Errorf("parse meta database DN %q: %w", entry.DN, err)
	}
	configDN, err := directory.ParseDN("cn=config")
	if err != nil {
		return directory.DN{}, nil, err
	}
	parent, ok := entryDN.Parent()
	if !ok || !parent.Equal(configDN) {
		return directory.DN{}, nil, fmt.Errorf(
			"%s meta database must be a direct child of cn=config",
			entry.DN,
		)
	}
	values := entry.Values("olcDatabase")
	if len(values) != 1 {
		return directory.DN{}, nil, fmt.Errorf("%s olcDatabase must be single-valued", entry.DN)
	}
	if databaseType(string(values[0])) != "meta" {
		return directory.DN{}, nil, fmt.Errorf("%s must use the meta backend", entry.DN)
	}
	rdn := entryDN.RDNValues()
	if len(rdn) != 1 || !strings.EqualFold(rdn[0].Type, "olcDatabase") ||
		!strings.EqualFold(strings.TrimSpace(string(rdn[0].Value)), strings.TrimSpace(string(values[0]))) {
		return directory.DN{}, nil, fmt.Errorf(
			"%s RDN must match its single olcDatabase value",
			entry.DN,
		)
	}
	if len(entry.Values("olcDbURI")) != 0 {
		return directory.DN{}, nil, fmt.Errorf(
			"%s meta parent must configure olcDbURI on olcMetaSub targets",
			entry.DN,
		)
	}

	rawSuffixes := entry.Values("olcSuffix")
	if len(rawSuffixes) == 0 {
		return directory.DN{}, nil, fmt.Errorf("%s meta backend requires olcSuffix", entry.DN)
	}
	suffixes := make([]directory.DN, 0, len(rawSuffixes))
	seen := make(map[string]struct{}, len(rawSuffixes))
	for _, raw := range rawSuffixes {
		suffix, parseErr := directory.ParseDN(string(raw))
		if parseErr != nil {
			return directory.DN{}, nil, fmt.Errorf("%s olcSuffix: %w", entry.DN, parseErr)
		}
		if _, duplicate := seen[suffix.Key()]; duplicate {
			return directory.DN{}, nil, fmt.Errorf(
				"%s has duplicate olcSuffix %q",
				entry.DN,
				suffix.String(),
			)
		}
		seen[suffix.Key()] = struct{}{}
		suffixes = append(suffixes, suffix)
	}
	return entryDN, suffixes, nil
}

func metaBackendTargetEntry(entry directory.Entry, entryDN directory.DN) bool {
	if entry.HasAttribute("olcMetaSub") {
		return true
	}
	for _, value := range entry.Values("objectClass") {
		if strings.EqualFold(strings.TrimSpace(string(value)), "olcMetaTargetConfig") {
			return true
		}
	}
	rdn := entryDN.RDNValues()
	return len(rdn) == 1 && strings.EqualFold(rdn[0].Type, "olcMetaSub")
}

func validateMetaBackendTargetIdentity(
	entry directory.Entry,
	entryDN directory.DN,
) (int, error) {
	values := entry.Values("olcMetaSub")
	if len(values) != 1 {
		return 0, fmt.Errorf("%s olcMetaSub must be single-valued", entry.DN)
	}
	raw := strings.TrimSpace(string(values[0]))
	rdn := entryDN.RDNValues()
	if len(rdn) != 1 || !strings.EqualFold(rdn[0].Type, "olcMetaSub") ||
		!strings.EqualFold(strings.TrimSpace(string(rdn[0].Value)), raw) {
		return 0, fmt.Errorf("%s RDN must match its single olcMetaSub value", entry.DN)
	}
	order, name, err := parseMetaBackendOrderedName(raw)
	if err != nil {
		return 0, fmt.Errorf("%s olcMetaSub: %w", entry.DN, err)
	}
	if !strings.EqualFold(name, "uri") {
		return 0, fmt.Errorf("%s olcMetaSub must name uri, got %q", entry.DN, name)
	}
	return order, nil
}

func parseMetaBackendOrderedName(value string) (int, string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{") {
		return 0, "", fmt.Errorf("must use the ordered form {n}uri")
	}
	end := strings.IndexByte(value, '}')
	if end < 2 {
		return 0, "", fmt.Errorf("invalid ordered prefix")
	}
	order, err := strconv.Atoi(value[1:end])
	if err != nil || order < 0 {
		return 0, "", fmt.Errorf("invalid ordered prefix %q", value[:end+1])
	}
	name := strings.TrimSpace(value[end+1:])
	if name == "" {
		return 0, "", fmt.Errorf("ordered target name is empty")
	}
	return order, name, nil
}

func loadMetaBackendTarget(
	parent directory.Entry,
	entry directory.Entry,
	order int,
	databaseSuffixes []directory.DN,
) (metaBackendTargetRuntimeConfiguration, error) {
	if err := validateMetaBackendCompatibilitySettings(entry); err != nil {
		return metaBackendTargetRuntimeConfiguration{}, err
	}
	if len(entry.Values("olcDbDefaultTarget")) != 0 {
		return metaBackendTargetRuntimeConfiguration{}, fmt.Errorf(
			"%s olcDbDefaultTarget belongs on the meta parent",
			entry.DN,
		)
	}
	if len(entry.Values("olcDbDnCacheTtl")) != 0 {
		return metaBackendTargetRuntimeConfiguration{}, fmt.Errorf(
			"%s olcDbDnCacheTtl belongs on the meta parent",
			entry.DN,
		)
	}
	if len(entry.Values("olcDbPseudoRootBindDefer")) != 0 {
		return metaBackendTargetRuntimeConfiguration{}, fmt.Errorf(
			"%s olcDbPseudoRootBindDefer belongs on the meta parent",
			entry.DN,
		)
	}
	if len(entry.Values("olcDbConnectionPoolMax")) != 0 {
		return metaBackendTargetRuntimeConfiguration{}, fmt.Errorf(
			"%s olcDbConnectionPoolMax belongs on the meta parent",
			entry.DN,
		)
	}
	uriValues := entry.Values("olcDbURI")
	if len(uriValues) != 1 {
		return metaBackendTargetRuntimeConfiguration{}, fmt.Errorf(
			"%s olcDbURI must be single-valued",
			entry.DN,
		)
	}
	suffix, scope, endpoints, err := parseMetaBackendURIs(entry.DN, string(uriValues[0]))
	if err != nil {
		return metaBackendTargetRuntimeConfiguration{}, err
	}
	if !metaBackendDNWithinSuffixes(suffix, databaseSuffixes) {
		return metaBackendTargetRuntimeConfiguration{}, fmt.Errorf(
			"%s target suffix %q is outside the meta database naming contexts",
			entry.DN,
			suffix.String(),
		)
	}

	ldapEntry := entry.Clone()
	for _, attribute := range parent.Attributes {
		if !metaBackendInheritedLDAPAttribute(attribute.Description) ||
			ldapEntry.HasAttribute(attribute.Description) {
			continue
		}
		ldapEntry.ReplaceValues(attribute.Description, attribute.Values)
	}
	ldapEntry.ReplaceValues("olcDbURI", [][]byte{[]byte(strings.Join(endpoints, " "))})
	backend, err := loadLDAPBackendRuntimeConfiguration(ldapEntry)
	if err != nil {
		return metaBackendTargetRuntimeConfiguration{}, fmt.Errorf(
			"load %s back-meta LDAP target: %w",
			entry.DN,
			err,
		)
	}
	bindPollRetries, bindPollTimeout, err := loadMetaBackendBindPolling(parent, entry)
	if err != nil {
		return metaBackendTargetRuntimeConfiguration{}, err
	}
	for index := range backend.remotes {
		backend.remotes[index].bindPollRetries = bindPollRetries
		backend.remotes[index].bindPollTimeout = bindPollTimeout
	}
	rwm, err := loadMetaBackendSuffixRewrite(entry, databaseSuffixes)
	if err != nil {
		return metaBackendTargetRuntimeConfiguration{}, err
	}
	subtrees, exclude, err := loadMetaBackendSubtreeRules(entry, suffix)
	if err != nil {
		return metaBackendTargetRuntimeConfiguration{}, err
	}
	filters, err := loadMetaBackendFilterRules(entry)
	if err != nil {
		return metaBackendTargetRuntimeConfiguration{}, err
	}
	clientPr, err := loadMetaBackendClientPr(parent, entry)
	if err != nil {
		return metaBackendTargetRuntimeConfiguration{}, err
	}
	entryDN, err := directory.ParseDN(entry.DN)
	if err != nil {
		return metaBackendTargetRuntimeConfiguration{}, err
	}
	target := metaBackendTargetRuntimeConfiguration{
		configDNKey: entryDN.Key(),
		order:       order,
		suffix:      suffix,
		scope:       scope,
		clientPr:    clientPr,
		ldapBackend: backend,
		rwm:         rwm,
		subtrees:    subtrees,
		exclude:     exclude,
		filters:     filters,
		preferred:   &proxyPreferredRemoteState{},
	}
	if len(backend.remotes) > 0 && len(backend.remotes[0].quarantine) > 0 {
		target.health = &pbindQuarantineState{now: time.Now}
	}
	return target, nil
}

func loadMetaBackendBindPolling(
	parent directory.Entry,
	target directory.Entry,
) (int, time.Duration, error) {
	retries := 10
	timeout := 100 * time.Millisecond

	retryEntry := parent
	if len(target.Values("olcDbNretries")) > 0 {
		retryEntry = target
	}
	if values := retryEntry.Values("olcDbNretries"); len(values) == 1 {
		value := strings.ToLower(strings.TrimSpace(string(values[0])))
		switch value {
		case "never":
			retries = 0
		case "forever":
			retries = -1
		default:
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 {
				return 0, 0, fmt.Errorf(
					"%s olcDbNretries has invalid value %q",
					retryEntry.DN,
					values[0],
				)
			}
			retries = parsed
		}
	} else if len(values) > 1 {
		return 0, 0, fmt.Errorf("%s olcDbNretries must be single-valued", retryEntry.DN)
	}

	timeoutEntry := parent
	if len(target.Values("olcDbBindTimeout")) > 0 {
		timeoutEntry = target
	}
	if values := timeoutEntry.Values("olcDbBindTimeout"); len(values) == 1 {
		microseconds, err := strconv.ParseUint(strings.TrimSpace(string(values[0])), 10, 64)
		if err != nil || microseconds > uint64(math.MaxInt64/int64(time.Microsecond)) {
			return 0, 0, fmt.Errorf(
				"%s olcDbBindTimeout has invalid value %q",
				timeoutEntry.DN,
				values[0],
			)
		}
		timeout = time.Duration(microseconds) * time.Microsecond
	} else if len(values) > 1 {
		return 0, 0, fmt.Errorf(
			"%s olcDbBindTimeout must be single-valued",
			timeoutEntry.DN,
		)
	}
	return retries, timeout, nil
}

func loadMetaBackendClientPr(parent, target directory.Entry) (int, error) {
	entry := parent
	if len(target.Values("olcDbClientPr")) > 0 {
		entry = target
	}
	values := entry.Values("olcDbClientPr")
	if len(values) == 0 {
		return 0, nil
	}
	if len(values) != 1 {
		return 0, fmt.Errorf("%s olcDbClientPr must be single-valued", entry.DN)
	}
	value := strings.ToLower(strings.TrimSpace(string(values[0])))
	switch value {
	case "disable":
		return 0, nil
	case "accept-unsolicited":
		return -1, nil
	default:
		pageSize, err := strconv.Atoi(value)
		if err != nil || pageSize < 0 {
			return 0, fmt.Errorf(
				"%s olcDbClientPr has invalid value %q",
				entry.DN,
				values[0],
			)
		}
		return pageSize, nil
	}
}

func loadMetaBackendSubtreeRules(
	entry directory.Entry,
	targetSuffix directory.DN,
) ([]metaBackendSubtreeRule, bool, error) {
	include := entry.Values("olcDbSubtreeInclude")
	exclude := entry.Values("olcDbSubtreeExclude")
	if len(include) > 0 && len(exclude) > 0 {
		return nil, false, fmt.Errorf(
			"%s olcDbSubtreeInclude and olcDbSubtreeExclude are mutually exclusive",
			entry.DN,
		)
	}
	values := include
	isExclude := false
	if len(exclude) > 0 {
		values = exclude
		isExclude = true
	}
	rules := make([]metaBackendSubtreeRule, 0, len(values))
	for _, raw := range values {
		value, err := stripRWMOrderingPrefix(string(raw))
		if err != nil {
			return nil, false, fmt.Errorf("%s back-meta subtree rule: %w", entry.DN, err)
		}
		kind := "subtree"
		pattern := strings.TrimSpace(value)
		lower := strings.ToLower(pattern)
		for _, prefix := range []struct {
			value string
			kind  string
		}{
			{"dn.subtree:", "subtree"},
			{"dn.sub:", "subtree"},
			{"dn.children:", "children"},
			{"dn.regex:", "regex"},
			{"dn:", "subtree"},
		} {
			if strings.HasPrefix(lower, prefix.value) {
				kind = prefix.kind
				pattern = pattern[len(prefix.value):]
				break
			}
		}
		rule := metaBackendSubtreeRule{kind: kind}
		if kind == "regex" {
			compiled, compileErr := regexp.Compile("(?i)" + pattern)
			if compileErr != nil {
				return nil, false, fmt.Errorf(
					"%s back-meta subtree regex %q: %w",
					entry.DN,
					pattern,
					compileErr,
				)
			}
			rule.pattern = compiled
		} else {
			dn, parseErr := directory.ParseDN(pattern)
			if parseErr != nil ||
				(!targetSuffix.Equal(dn) && !targetSuffix.AncestorOf(dn)) {
				return nil, false, fmt.Errorf(
					"%s back-meta subtree DN %q is invalid or outside target %q",
					entry.DN,
					pattern,
					targetSuffix.String(),
				)
			}
			rule.dn = dn
		}
		rules = append(rules, rule)
	}
	return rules, isExclude, nil
}

func loadMetaBackendFilterRules(entry directory.Entry) ([]*regexp.Regexp, error) {
	values := entry.Values("olcDbFilter")
	filters := make([]*regexp.Regexp, 0, len(values))
	for _, raw := range values {
		value, err := stripRWMOrderingPrefix(string(raw))
		if err != nil {
			return nil, fmt.Errorf("%s olcDbFilter: %w", entry.DN, err)
		}
		compiled, err := regexp.Compile(value)
		if err != nil {
			return nil, fmt.Errorf("%s olcDbFilter %q: %w", entry.DN, value, err)
		}
		filters = append(filters, compiled)
	}
	return filters, nil
}

func parseMetaBackendURIs(
	entryDN string,
	value string,
) (directory.DN, directory.Scope, []string, error) {
	values, err := tokenizeOpenLDAPConfig(value)
	if err != nil {
		return directory.DN{}, 0, nil, fmt.Errorf("%s olcDbURI: %w", entryDN, err)
	}
	if len(values) == 0 {
		return directory.DN{}, 0, nil, fmt.Errorf("%s olcDbURI contains no LDAP URLs", entryDN)
	}

	var suffix directory.DN
	scope := directory.ScopeWholeSubtree
	endpoints := make([]string, 0, len(values))
	seenEndpoints := make(map[string]struct{}, len(values))
	for index, raw := range values {
		parsed, parseErr := parseSyncConsumerProviderURL(raw)
		if parseErr != nil {
			return directory.DN{}, 0, nil, fmt.Errorf(
				"%s olcDbURI URL %d: %w",
				entryDN,
				index,
				parseErr,
			)
		}
		if parsed.Fragment != "" {
			return directory.DN{}, 0, nil, fmt.Errorf(
				"%s olcDbURI URL %d must not contain a fragment",
				entryDN,
				index,
			)
		}
		if index == 0 {
			if parsed.Path == "" || parsed.Path == "/" {
				return directory.DN{}, 0, nil, fmt.Errorf(
					"%s first olcDbURI URL requires a target DN",
					entryDN,
				)
			}
			rawDN := strings.TrimPrefix(parsed.Path, "/")
			suffix, parseErr = directory.ParseDN(rawDN)
			if parseErr != nil || suffix.Depth() == 0 {
				return directory.DN{}, 0, nil, fmt.Errorf(
					"%s first olcDbURI URL has invalid target DN %q",
					entryDN,
					rawDN,
				)
			}
			scope, parseErr = parseMetaBackendURLScope(parsed.RawQuery, parsed.ForceQuery)
			if parseErr != nil {
				return directory.DN{}, 0, nil, fmt.Errorf(
					"%s first olcDbURI URL: %w",
					entryDN,
					parseErr,
				)
			}
		} else {
			if parsed.Path != "" && parsed.Path != "/" {
				return directory.DN{}, 0, nil, fmt.Errorf(
					"%s additional olcDbURI URL %d must not contain a target DN",
					entryDN,
					index,
				)
			}
			if parsed.RawQuery != "" || parsed.ForceQuery {
				return directory.DN{}, 0, nil, fmt.Errorf(
					"%s additional olcDbURI URL %d must not contain LDAP URL fields",
					entryDN,
					index,
				)
			}
		}

		endpointURL := *parsed
		endpointURL.Path = ""
		endpointURL.RawPath = ""
		endpointURL.RawQuery = ""
		endpointURL.ForceQuery = false
		endpointURL.Fragment = ""
		endpoint, endpointKey, parseErr := parseChainConfiguredURI(endpointURL.String())
		if parseErr != nil {
			return directory.DN{}, 0, nil, fmt.Errorf(
				"%s olcDbURI URL %d: %w",
				entryDN,
				index,
				parseErr,
			)
		}
		if _, duplicate := seenEndpoints[endpointKey]; duplicate {
			return directory.DN{}, 0, nil, fmt.Errorf(
				"%s olcDbURI duplicates endpoint %q",
				entryDN,
				endpoint,
			)
		}
		seenEndpoints[endpointKey] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}
	return suffix, scope, endpoints, nil
}

func parseMetaBackendURLScope(rawQuery string, forceQuery bool) (directory.Scope, error) {
	if rawQuery == "" && !forceQuery {
		return directory.ScopeWholeSubtree, nil
	}
	fields := strings.Split(rawQuery, "?")
	if len(fields) > 4 {
		return 0, fmt.Errorf("LDAP URL contains too many fields")
	}
	for len(fields) < 4 {
		fields = append(fields, "")
	}
	if fields[0] != "" || fields[2] != "" || fields[3] != "" {
		return 0, fmt.Errorf("only an LDAP URL scope is supported")
	}
	switch strings.ToLower(strings.TrimSpace(fields[1])) {
	case "", "sub", "subtree":
		return directory.ScopeWholeSubtree, nil
	case "children", "subord", "subordinate":
		return directory.ScopeChildren, nil
	default:
		return 0, fmt.Errorf("unsupported target scope %q", fields[1])
	}
}

func loadMetaBackendSuffixRewrite(
	entry directory.Entry,
	databaseSuffixes []directory.DN,
) (*rwmRuntimeConfiguration, error) {
	configuration := &rwmRuntimeConfiguration{
		attributesToRemote: make(map[string]string),
		attributesToLocal:  make(map[string]string),
		classesToRemote:    make(map[string]string),
		classesToLocal:     make(map[string]string),
	}
	var mapping *rwmSuffixMapping
	for _, raw := range entry.Values("olcDbRewrite") {
		value, err := stripRWMOrderingPrefix(string(raw))
		if err != nil {
			return nil, fmt.Errorf("%s olcDbRewrite: %w", entry.DN, err)
		}
		words, err := splitRWMConfigurationWords(value)
		if err != nil {
			return nil, fmt.Errorf("%s olcDbRewrite: %w", entry.DN, err)
		}
		if len(words) == 0 ||
			(!strings.EqualFold(words[0], "suffixmassage") &&
				!strings.EqualFold(words[0], "rwm-suffixmassage")) {
			continue
		}
		if len(words) != 3 {
			return nil, fmt.Errorf(
				"%s olcDbRewrite suffixmassage expects local and remote DNs",
				entry.DN,
			)
		}
		if mapping != nil {
			return nil, fmt.Errorf("%s configures multiple suffixmassage directives", entry.DN)
		}
		local, parseErr := directory.ParseDN(words[1])
		if parseErr != nil || local.Depth() == 0 {
			return nil, fmt.Errorf(
				"%s suffixmassage has invalid local DN %q",
				entry.DN,
				words[1],
			)
		}
		if !metaBackendDNWithinSuffixes(local, databaseSuffixes) {
			return nil, fmt.Errorf(
				"%s suffixmassage local DN %q is outside the meta database naming contexts",
				entry.DN,
				words[1],
			)
		}
		remote, parseErr := directory.ParseDN(words[2])
		if parseErr != nil {
			return nil, fmt.Errorf(
				"%s suffixmassage has invalid remote DN %q",
				entry.DN,
				words[2],
			)
		}
		mapping = &rwmSuffixMapping{local: local, remote: remote}
	}
	for _, raw := range entry.Values("olcDbMap") {
		value, err := stripRWMOrderingPrefix(string(raw))
		if err != nil {
			return nil, fmt.Errorf("%s olcDbMap: %w", entry.DN, err)
		}
		words, err := splitRWMConfigurationWords(value)
		if err != nil {
			return nil, fmt.Errorf("%s olcDbMap: %w", entry.DN, err)
		}
		if err := applyRWMMapDirective(configuration, words); err != nil {
			return nil, fmt.Errorf("%s olcDbMap: %w", entry.DN, err)
		}
	}
	if mapping == nil {
		return configuration, nil
	}
	configuration.suffix = mapping
	return configuration, nil
}

func loadMetaBackendDefaultTarget(entry directory.Entry, targetCount int) (int, error) {
	values := entry.Values("olcDbDefaultTarget")
	if len(values) == 0 {
		return metaBackendNoDefaultTarget, nil
	}
	if len(values) != 1 {
		return 0, fmt.Errorf("%s olcDbDefaultTarget must be single-valued", entry.DN)
	}
	value := strings.TrimSpace(string(values[0]))
	if strings.EqualFold(value, "none") {
		return metaBackendNoDefaultTarget, nil
	}
	index, err := strconv.Atoi(value)
	if err != nil || index < 0 || index >= targetCount {
		return 0, fmt.Errorf("%s olcDbDefaultTarget has invalid target index %q", entry.DN, value)
	}
	return index, nil
}

func validateMetaBackendCompatibilitySettings(entry directory.Entry) error {
	for _, description := range []string{
		"olcDbBindTimeout",
		"olcDbClientPr",
		"olcDbDnCacheTtl",
		"olcDbNretries",
		"olcDbPseudoRootBindDefer",
	} {
		if len(entry.Values(description)) > 1 {
			return fmt.Errorf("%s %s must be single-valued", entry.DN, description)
		}
	}
	if values := entry.Values("olcDbBindTimeout"); len(values) == 1 {
		if _, err := strconv.ParseUint(strings.TrimSpace(string(values[0])), 10, 64); err != nil {
			return fmt.Errorf("%s olcDbBindTimeout has invalid value %q", entry.DN, values[0])
		}
	}
	if values := entry.Values("olcDbNretries"); len(values) == 1 {
		value := strings.ToLower(strings.TrimSpace(string(values[0])))
		if value != "never" && value != "forever" {
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 {
				return fmt.Errorf("%s olcDbNretries has invalid value %q", entry.DN, values[0])
			}
		}
	}
	if values := entry.Values("olcDbClientPr"); len(values) == 1 {
		value := strings.ToLower(strings.TrimSpace(string(values[0])))
		if value != "disable" && value != "accept-unsolicited" {
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 {
				return fmt.Errorf("%s olcDbClientPr has invalid value %q", entry.DN, values[0])
			}
		}
	}
	if _, _, err := singleBoolean(entry, "olcDbPseudoRootBindDefer"); err != nil {
		return err
	}
	return nil
}

func metaBackendInheritedLDAPAttribute(description string) bool {
	switch strings.ToLower(strings.TrimSpace(description)) {
	case "olcdbstarttls",
		"olcdbnetworktimeout",
		"olcdbprotocolversion",
		"olcdbrebindasuser",
		"olcdbchasereferrals",
		"olcdbnorefs",
		"olcdbnoundeffilter",
		"olcdbsessiontrackingrequest",
		"olcdbtimeout",
		"olcdbidletimeout",
		"olcdbconnttl",
		"olcdbsingleconn",
		"olcdbusetemporaryconn",
		"olcdbconnectionpoolmax",
		"olcdbquarantine",
		"olcdbcancel",
		"olcdbonerr",
		"olcdbtfsupport":
		return true
	default:
		return false
	}
}

func metaBackendDNWithinSuffixes(dn directory.DN, suffixes []directory.DN) bool {
	for _, suffix := range suffixes {
		if suffix.Equal(dn) || suffix.AncestorOf(dn) {
			return true
		}
	}
	return false
}

func (configuration *metaBackendRuntimeConfiguration) targetsForDN(
	dn directory.DN,
) []metaBackendTargetRuntimeConfiguration {
	if configuration == nil {
		return nil
	}
	bestDepth := -1
	indices := make([]int, 0, 1)
	for index := range configuration.targets {
		target := configuration.targets[index]
		if !target.matchesDN(dn, directory.ScopeBase) {
			continue
		}
		depth := target.suffix.Depth()
		switch {
		case depth > bestDepth:
			bestDepth = depth
			indices = indices[:0]
			indices = append(indices, index)
		case depth == bestDepth:
			indices = append(indices, index)
		}
	}
	if len(indices) == 0 {
		return nil
	}
	if configuration.defaultTarget >= 0 {
		for index, candidate := range indices {
			if candidate != configuration.defaultTarget || index == 0 {
				continue
			}
			copy(indices[1:index+1], indices[:index])
			indices[0] = candidate
			break
		}
	}
	result := make([]metaBackendTargetRuntimeConfiguration, len(indices))
	for index, targetIndex := range indices {
		result[index] = configuration.targets[targetIndex].clone()
	}
	return result
}

func (configuration *metaBackendRuntimeConfiguration) candidateTargetsForDN(
	dn directory.DN,
) []metaBackendTargetRuntimeConfiguration {
	if configuration == nil {
		return nil
	}
	result := make([]metaBackendTargetRuntimeConfiguration, 0, len(configuration.targets))
	for _, target := range configuration.targets {
		if !target.matchesDN(dn, directory.ScopeBase) {
			continue
		}
		result = append(result, target.clone())
	}
	return result
}

func (configuration *metaBackendRuntimeConfiguration) defaultTargetKey() string {
	if configuration == nil || configuration.defaultTarget < 0 ||
		configuration.defaultTarget >= len(configuration.targets) {
		return ""
	}
	return configuration.targets[configuration.defaultTarget].configDNKey
}

func (configuration *metaBackendRuntimeConfiguration) targetForDN(
	dn directory.DN,
) (*metaBackendTargetRuntimeConfiguration, bool) {
	targets := configuration.targetsForDN(dn)
	if len(targets) == 0 {
		return nil, false
	}
	return &targets[0], true
}

func (target metaBackendTargetRuntimeConfiguration) mapDNToRemote(
	dn directory.DN,
) (directory.DN, error) {
	if target.rwm == nil {
		return dn, nil
	}
	return target.rwm.mapDNToRemote(dn)
}

func (target metaBackendTargetRuntimeConfiguration) mapDNToLocal(
	dn directory.DN,
) (directory.DN, error) {
	if target.rwm == nil {
		return dn, nil
	}
	return target.rwm.mapDNToLocal(dn)
}

func (configuration *metaBackendRuntimeConfiguration) clone() *metaBackendRuntimeConfiguration {
	if configuration == nil {
		return nil
	}
	clone := &metaBackendRuntimeConfiguration{
		configDNKey:         configuration.configDNKey,
		suffixes:            append([]directory.DN(nil), configuration.suffixes...),
		targets:             make([]metaBackendTargetRuntimeConfiguration, len(configuration.targets)),
		defaultTarget:       configuration.defaultTarget,
		onError:             configuration.onError,
		dnCacheTTL:          configuration.dnCacheTTL,
		pseudoRootBindDefer: configuration.pseudoRootBindDefer,
	}
	for index := range configuration.targets {
		clone.targets[index] = configuration.targets[index].clone()
	}
	return clone
}

func (target metaBackendTargetRuntimeConfiguration) clone() metaBackendTargetRuntimeConfiguration {
	clone := target
	clone.ldapBackend = cloneMetaLDAPBackendRuntimeConfiguration(target.ldapBackend)
	clone.rwm = cloneMetaRWMRuntimeConfiguration(target.rwm)
	clone.subtrees = append([]metaBackendSubtreeRule(nil), target.subtrees...)
	clone.filters = append([]*regexp.Regexp(nil), target.filters...)
	return clone
}

func (target metaBackendTargetRuntimeConfiguration) beginAttempt() bool {
	return beginProxyQuarantineAttempt(target.health, target.quarantine())
}

func (target metaBackendTargetRuntimeConfiguration) finishAttempt(code ldapwire.ResultCode) {
	finishProxyQuarantineAttempt(target.health, target.quarantine(), code)
}

func (target metaBackendTargetRuntimeConfiguration) quarantine() []syncConsumerRetry {
	if target.ldapBackend == nil || len(target.ldapBackend.remotes) == 0 {
		return nil
	}
	return target.ldapBackend.remotes[0].quarantine
}

func (target metaBackendTargetRuntimeConfiguration) matchesDN(
	dn directory.DN,
	scope directory.Scope,
) bool {
	if target.onlineURIUnavailable ||
		(!target.suffix.Equal(dn) && !target.suffix.AncestorOf(dn)) ||
		(target.scope == directory.ScopeChildren && target.suffix.Equal(dn)) {
		return false
	}
	if len(target.subtrees) == 0 {
		return true
	}
	matched := false
	for _, rule := range target.subtrees {
		switch rule.kind {
		case "subtree":
			matched = rule.dn.Equal(dn) || rule.dn.AncestorOf(dn)
		case "children":
			matched = (rule.dn.Equal(dn) || rule.dn.AncestorOf(dn)) &&
				(!rule.dn.Equal(dn) || scope != directory.ScopeBase)
		case "regex":
			matched = rule.pattern != nil && rule.pattern.MatchString(dn.String())
		}
		if matched {
			break
		}
	}
	if target.exclude {
		return !matched
	}
	return matched
}

func applyMetaBackendOnlineConfigurationState(previous, next *runtimeState) {
	if previous == nil || next == nil {
		return
	}
	previousDatabases := make(map[string]*metaBackendRuntimeConfiguration)
	for index := range previous.databases {
		database := &previous.databases[index]
		if database.metaBackend != nil {
			previousDatabases[database.configDNKey] = database.metaBackend
		}
	}
	for databaseIndex := range next.databases {
		database := &next.databases[databaseIndex]
		if database.metaBackend == nil {
			continue
		}
		previousConfiguration := previousDatabases[database.configDNKey]
		if previousConfiguration == nil {
			continue
		}
		previousTargets := make(map[string]metaBackendTargetRuntimeConfiguration)
		for _, target := range previousConfiguration.targets {
			previousTargets[target.configDNKey] = target
		}
		for targetIndex := range database.metaBackend.targets {
			target := &database.metaBackend.targets[targetIndex]
			previousTarget, found := previousTargets[target.configDNKey]
			if !found {
				continue
			}
			if previousTarget.onlineURIUnavailable {
				target.onlineURIUnavailable = true
			}
		}
	}
}

func applyMetaBackendOnlineURIModification(
	runtime *runtimeState,
	targetDN directory.DN,
	changes []ldapwire.Modification,
) {
	if runtime == nil || runtime.schema == nil {
		return
	}
	touchesURI := false
	for _, change := range changes {
		if runtime.schema.AttributeDescriptionSubtype(
			change.Attribute.Description,
			"olcDbURI",
		) {
			touchesURI = true
			break
		}
	}
	if !touchesURI {
		return
	}

	targetKey := targetDN.Key()
	for databaseIndex := range runtime.databases {
		configuration := runtime.databases[databaseIndex].metaBackend
		if configuration == nil {
			continue
		}
		for targetIndex := range configuration.targets {
			target := &configuration.targets[targetIndex]
			if target.configDNKey == targetKey {
				target.onlineURIUnavailable = true
				return
			}
		}
	}
}

func isConfiguredMetaBackendTarget(
	runtime *runtimeState,
	entry directory.Entry,
	dn directory.DN,
) bool {
	if runtime == nil || !metaBackendTargetEntry(entry, dn) {
		return false
	}
	parent, ok := dn.Parent()
	if !ok {
		return false
	}
	for index := range runtime.databases {
		database := &runtime.databases[index]
		if database.metaBackend != nil && database.configDNKey == parent.Key() {
			return true
		}
	}
	return false
}

func (target metaBackendTargetRuntimeConfiguration) matchesFilter(raw string) bool {
	if len(target.filters) == 0 {
		return true
	}
	for _, filter := range target.filters {
		if filter.MatchString(raw) {
			return true
		}
	}
	return false
}

func cloneMetaLDAPBackendRuntimeConfiguration(
	configuration *ldapBackendRuntimeConfiguration,
) *ldapBackendRuntimeConfiguration {
	if configuration == nil {
		return nil
	}
	clone := &ldapBackendRuntimeConfiguration{
		remotes:   make([]chainRemoteConfiguration, len(configuration.remotes)),
		preferred: &proxyPreferredRemoteState{},
	}
	for index := range configuration.remotes {
		clone.remotes[index] = configuration.remotes[index].clone()
	}
	return clone
}

func cloneMetaRWMRuntimeConfiguration(
	configuration *rwmRuntimeConfiguration,
) *rwmRuntimeConfiguration {
	if configuration == nil {
		return nil
	}
	clone := &rwmRuntimeConfiguration{
		attributesToRemote:    cloneMetaStringMap(configuration.attributesToRemote),
		attributesToLocal:     cloneMetaStringMap(configuration.attributesToLocal),
		attributesDropMissing: configuration.attributesDropMissing,
		classesToRemote:       cloneMetaStringMap(configuration.classesToRemote),
		classesToLocal:        cloneMetaStringMap(configuration.classesToLocal),
		classesDropMissing:    configuration.classesDropMissing,
		schema:                configuration.schema,
	}
	if configuration.suffix != nil {
		mapping := *configuration.suffix
		clone.suffix = &mapping
	}
	return clone
}

func cloneMetaStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}
