package server

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const maxSyncConsumerRID = 999

type syncConsumerMode uint8

const (
	syncConsumerRefreshOnly syncConsumerMode = iota
	syncConsumerRefreshAndPersist
)

type syncConsumerStartTLS uint8

const (
	syncConsumerStartTLSOff syncConsumerStartTLS = iota
	syncConsumerStartTLSYes
	syncConsumerStartTLSCritical
)

type syncConsumerRetry struct {
	interval time.Duration
	attempts int
}

type syncConsumerKeepalive struct {
	idle     int
	probes   int
	interval int
	set      bool
}

type syncConsumerTLSConfig struct {
	certificateFile           string
	keyFile                   string
	tlcpEncryptionCertificate string
	tlcpEncryptionKey         string
	caCertificate             string
	caDirectory               string
	requireCert               string
	requireSAN                string
	cipherSuite               string
	ecName                    string
	crlCheck                  string
	protocolMinimum           string
}

type syncConsumerConfig struct {
	order     int
	rid       int
	partition string

	providerURLs   []string
	searchBase     directory.DN
	localBase      directory.DN
	suffixMap      *directory.DN
	filterText     string
	filter         directory.Filter
	scope          directory.Scope
	attributes     []string
	exAttributes   []string
	attributesOnly bool
	schemaChecking bool

	mode          syncConsumerMode
	interval      time.Duration
	retry         []syncConsumerRetry
	sizeLimit     int
	timeLimit     int
	manageDSAit   bool
	strictRefresh bool
	lazyCommit    bool
	syncData      string
	logBase       *directory.DN
	logFilterText string
	logFilter     *directory.Filter

	bindMethod         string
	bindDN             string
	credentials        []byte
	saslMechanism      string
	authenticationID   string
	authorizationID    string
	realm              string
	securityProperties string

	startTLS         syncConsumerStartTLS
	tls              syncConsumerTLSConfig
	networkTimeout   time.Duration
	operationTimeout time.Duration
	tcpUserTimeout   time.Duration
	keepalive        syncConsumerKeepalive
}

func parseSyncConsumerConfig(
	raw string,
	partition string,
	suffixes []directory.DN,
) (syncConsumerConfig, error) {
	order, value, err := orderedSyncConsumerValue(raw)
	if err != nil {
		return syncConsumerConfig{}, err
	}
	arguments, err := tokenizeOpenLDAPConfig(value)
	if err != nil {
		return syncConsumerConfig{}, err
	}

	defaultFilter := "(objectclass=*)"
	parsedDefaultFilter, err := compileSyncConsumerFilter(defaultFilter)
	if err != nil {
		return syncConsumerConfig{}, err
	}
	config := syncConsumerConfig{
		order:      order,
		rid:        -1,
		partition:  partition,
		filterText: defaultFilter,
		filter:     parsedDefaultFilter,
		scope:      directory.ScopeWholeSubtree,
		attributes: []string{"*", "+"},
		mode:       syncConsumerRefreshOnly,
		interval:   24 * time.Hour,
		retry:      []syncConsumerRetry{{interval: time.Hour, attempts: -1}},
		bindMethod: "simple",
		syncData:   "default",
	}

	var (
		hasRID        bool
		hasProvider   bool
		hasSearchBase bool
	)
	for _, argument := range arguments {
		key, rawValue, hasValue := strings.Cut(argument, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !hasValue {
			switch key {
			case "attrsonly":
				config.attributesOnly = true
			case "strictrefresh":
				config.strictRefresh = true
			case "lazycommit":
				config.lazyCommit = true
			default:
				return syncConsumerConfig{}, fmt.Errorf(
					"unknown syncrepl argument %q",
					argument,
				)
			}
			continue
		}
		if key == "" {
			return syncConsumerConfig{}, fmt.Errorf(
				"invalid syncrepl argument %q",
				argument,
			)
		}

		switch key {
		case "rid":
			rid, parseErr := strconv.Atoi(rawValue)
			if parseErr != nil || rid < 0 || rid > maxSyncConsumerRID {
				return syncConsumerConfig{}, fmt.Errorf(
					"rid %q is outside [0..%d]",
					rawValue,
					maxSyncConsumerRID,
				)
			}
			config.rid = rid
			hasRID = true
		case "provider":
			providers, parseErr := parseSyncConsumerProviders(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, parseErr
			}
			config.providerURLs = providers
			hasProvider = true
		case "searchbase":
			base, parseErr := directory.ParseDN(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"searchbase: %w",
					parseErr,
				)
			}
			config.searchBase = base
			hasSearchBase = true
		case "suffixmassage":
			base, parseErr := directory.ParseDN(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"suffixmassage: %w",
					parseErr,
				)
			}
			config.suffixMap = &base
		case "filter":
			filter, parseErr := compileSyncConsumerFilter(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"filter %q: %w",
					rawValue,
					parseErr,
				)
			}
			config.filterText = rawValue
			config.filter = filter
		case "logfilter":
			filter, parseErr := compileSyncConsumerFilter(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"logfilter %q: %w",
					rawValue,
					parseErr,
				)
			}
			config.logFilterText = rawValue
			config.logFilter = &filter
		case "logbase":
			base, parseErr := directory.ParseDN(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"logbase: %w",
					parseErr,
				)
			}
			config.logBase = &base
		case "scope":
			scope, parseErr := parseSyncConsumerScope(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, parseErr
			}
			config.scope = scope
		case "attrs":
			attributes, parseErr := parseSyncConsumerAttributes(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"attrs: %w",
					parseErr,
				)
			}
			config.attributes = attributes
		case "exattrs":
			attributes, parseErr := parseSyncConsumerAttributes(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"exattrs: %w",
					parseErr,
				)
			}
			config.exAttributes = attributes
		case "attrsonly":
			enabled, parseErr := parseSyncConsumerBoolean(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"attrsonly: %w",
					parseErr,
				)
			}
			config.attributesOnly = enabled
		case "schemachecking":
			enabled, parseErr := parseSyncConsumerBoolean(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"schemachecking: %w",
					parseErr,
				)
			}
			config.schemaChecking = enabled
		case "type":
			switch strings.ToLower(rawValue) {
			case "refreshonly":
				config.mode = syncConsumerRefreshOnly
			case "refreshandpersist":
				config.mode = syncConsumerRefreshAndPersist
			default:
				return syncConsumerConfig{}, fmt.Errorf(
					"unknown syncrepl type %q",
					rawValue,
				)
			}
		case "interval":
			interval, parseErr := parseSyncConsumerInterval(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, parseErr
			}
			config.interval = interval
		case "retry":
			retry, parseErr := parseSyncConsumerRetry(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, parseErr
			}
			config.retry = retry
		case "sizelimit":
			limit, parseErr := parseSyncConsumerLimit(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"sizelimit: %w",
					parseErr,
				)
			}
			config.sizeLimit = limit
		case "timelimit":
			limit, parseErr := parseSyncConsumerLimit(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"timelimit: %w",
					parseErr,
				)
			}
			config.timeLimit = limit
		case "managedsait":
			enabled, parseErr := parseSyncConsumerZeroOne(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"manageDSAit: %w",
					parseErr,
				)
			}
			config.manageDSAit = enabled
		case "strictrefresh":
			enabled, parseErr := parseSyncConsumerBoolean(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"strictrefresh: %w",
					parseErr,
				)
			}
			config.strictRefresh = enabled
		case "lazycommit":
			enabled, parseErr := parseSyncConsumerBoolean(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"lazycommit: %w",
					parseErr,
				)
			}
			config.lazyCommit = enabled
		case "syncdata":
			switch strings.ToLower(rawValue) {
			case "default", "accesslog", "changelog":
				config.syncData = strings.ToLower(rawValue)
			default:
				return syncConsumerConfig{}, fmt.Errorf(
					"unknown syncdata mode %q",
					rawValue,
				)
			}
		case "bindmethod":
			switch strings.ToLower(rawValue) {
			case "simple", "sasl":
				config.bindMethod = strings.ToLower(rawValue)
			default:
				return syncConsumerConfig{}, fmt.Errorf(
					"unknown bindmethod %q",
					rawValue,
				)
			}
		case "binddn":
			if rawValue != "" {
				if _, parseErr := directory.ParseDN(rawValue); parseErr != nil {
					return syncConsumerConfig{}, fmt.Errorf(
						"binddn: %w",
						parseErr,
					)
				}
			}
			config.bindDN = rawValue
		case "credentials":
			config.credentials = []byte(rawValue)
		case "saslmech":
			config.saslMechanism = rawValue
		case "authcid":
			config.authenticationID = rawValue
		case "authzid":
			config.authorizationID = rawValue
		case "realm":
			config.realm = rawValue
		case "secprops":
			config.securityProperties = rawValue
		case "starttls":
			startTLS, parseErr := parseSyncConsumerStartTLS(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, parseErr
			}
			config.startTLS = startTLS
		case "tls_cert":
			config.tls.certificateFile = rawValue
		case "tls_key":
			config.tls.keyFile = rawValue
		case "tlcp_enc_cert":
			config.tls.tlcpEncryptionCertificate = rawValue
		case "tlcp_enc_key":
			config.tls.tlcpEncryptionKey = rawValue
		case "tls_cacert":
			config.tls.caCertificate = rawValue
		case "tls_cacertdir":
			config.tls.caDirectory = rawValue
		case "tls_reqcert":
			requirement, parseErr := parseSyncConsumerTLSRequirement(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"tls_reqcert: %w",
					parseErr,
				)
			}
			config.tls.requireCert = requirement
		case "tls_reqsan":
			requirement, parseErr := parseSyncConsumerTLSRequirement(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"tls_reqsan: %w",
					parseErr,
				)
			}
			config.tls.requireSAN = requirement
		case "tls_cipher_suite":
			config.tls.cipherSuite = rawValue
		case "tls_ecname":
			config.tls.ecName = rawValue
		case "tls_crlcheck":
			switch strings.ToLower(rawValue) {
			case "none", "peer", "all":
				config.tls.crlCheck = strings.ToLower(rawValue)
			default:
				return syncConsumerConfig{}, fmt.Errorf(
					"unknown tls_crlcheck value %q",
					rawValue,
				)
			}
		case "tls_protocol_min":
			if rawValue == "" {
				return syncConsumerConfig{}, errors.New(
					"tls_protocol_min is empty",
				)
			}
			config.tls.protocolMinimum = rawValue
		case "network-timeout":
			timeout, parseErr := parseSyncConsumerTimeout(rawValue, time.Second)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"network-timeout: %w",
					parseErr,
				)
			}
			config.networkTimeout = timeout
		case "timeout":
			timeout, parseErr := parseSyncConsumerTimeout(rawValue, time.Second)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"timeout: %w",
					parseErr,
				)
			}
			config.operationTimeout = timeout
		case "tcp-user-timeout":
			timeout, parseErr := parseSyncConsumerTimeout(
				rawValue,
				time.Millisecond,
			)
			if parseErr != nil {
				return syncConsumerConfig{}, fmt.Errorf(
					"tcp-user-timeout: %w",
					parseErr,
				)
			}
			config.tcpUserTimeout = timeout
		case "keepalive":
			keepalive, parseErr := parseSyncConsumerKeepalive(rawValue)
			if parseErr != nil {
				return syncConsumerConfig{}, parseErr
			}
			config.keepalive = keepalive
		case "version":
			if rawValue != "3" {
				return syncConsumerConfig{}, fmt.Errorf(
					"syncrepl requires LDAP version 3, got %q",
					rawValue,
				)
			}
		default:
			return syncConsumerConfig{}, fmt.Errorf(
				"unknown syncrepl argument %q",
				argument,
			)
		}
	}

	var missing []string
	if !hasRID {
		missing = append(missing, "rid")
	}
	if !hasProvider {
		missing = append(missing, "provider")
	}
	if !hasSearchBase {
		missing = append(missing, "searchbase")
	}
	if len(missing) > 0 {
		return syncConsumerConfig{}, fmt.Errorf(
			"syncrepl is missing %s",
			strings.Join(missing, ", "),
		)
	}

	config.localBase = config.searchBase
	if config.suffixMap != nil {
		config.localBase = *config.suffixMap
	}
	if !syncConsumerBaseWithinSuffixes(config.localBase, suffixes) {
		return syncConsumerConfig{}, fmt.Errorf(
			"local replication base %q is outside the database suffixes",
			config.localBase.String(),
		)
	}
	if config.bindMethod == "simple" &&
		(config.saslMechanism != "" ||
			config.authenticationID != "" ||
			config.authorizationID != "" ||
			config.realm != "" ||
			config.securityProperties != "") {
		return syncConsumerConfig{}, errors.New(
			"SASL parameters require bindmethod=sasl",
		)
	}
	if config.syncData != "default" &&
		(config.logBase == nil || config.logFilter == nil) {
		return syncConsumerConfig{}, fmt.Errorf(
			"syncdata=%s requires logbase and logfilter",
			config.syncData,
		)
	}
	config.credentials = bytes.Clone(config.credentials)
	return config, nil
}

func orderedSyncConsumerValue(value string) (int, string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{") {
		return int(^uint(0) >> 1), value, nil
	}
	end := strings.IndexByte(value, '}')
	if end < 2 {
		return 0, "", errors.New("invalid ordered olcSyncrepl prefix")
	}
	order, err := strconv.Atoi(value[1:end])
	if err != nil || order < 0 {
		return 0, "", fmt.Errorf(
			"invalid ordered olcSyncrepl prefix %q",
			value[:end+1],
		)
	}
	return order, strings.TrimSpace(value[end+1:]), nil
}

func tokenizeOpenLDAPConfig(value string) ([]string, error) {
	var tokens []string
	for position := 0; position < len(value); {
		for position < len(value) &&
			unicode.IsSpace(rune(value[position])) {
			position++
		}
		if position == len(value) {
			break
		}

		var token strings.Builder
		var quote byte
		started := false
		for position < len(value) {
			character := value[position]
			if quote == 0 && unicode.IsSpace(rune(character)) {
				break
			}
			if character == '\'' || character == '"' {
				if quote == 0 {
					quote = character
					started = true
					position++
					continue
				}
				if quote == character {
					quote = 0
					position++
					continue
				}
			}
			if character == '\\' && position+1 < len(value) {
				next := value[position+1]
				if next == '\\' ||
					next == quote ||
					(quote == 0 &&
						(unicode.IsSpace(rune(next)) ||
							next == '\'' ||
							next == '"')) {
					token.WriteByte(next)
					started = true
					position += 2
					continue
				}
			}
			token.WriteByte(character)
			started = true
			position++
		}
		if quote != 0 {
			return nil, errors.New("unterminated quoted syncrepl value")
		}
		if started {
			tokens = append(tokens, token.String())
		}
	}
	return tokens, nil
}

func parseSyncConsumerProviders(value string) ([]string, error) {
	providers := strings.Fields(value)
	if len(providers) == 0 {
		return nil, errors.New("provider is empty")
	}
	for _, provider := range providers {
		parsed, err := url.Parse(provider)
		if err != nil {
			return nil, fmt.Errorf("provider %q: %w", provider, err)
		}
		switch strings.ToLower(parsed.Scheme) {
		case "ldap", "ldaps", "ldapi", "ldap+tlcp":
		default:
			return nil, fmt.Errorf(
				"provider %q uses unsupported scheme %q",
				provider,
				parsed.Scheme,
			)
		}
		if parsed.User != nil {
			return nil, fmt.Errorf(
				"provider %q must not contain URL user information",
				provider,
			)
		}
	}
	return providers, nil
}

func compileSyncConsumerFilter(value string) (directory.Filter, error) {
	packet, err := ldap.CompileFilter(value)
	if err != nil {
		return directory.Filter{}, err
	}
	return ldapwire.DecodeFilter(packet.Bytes())
}

func parseSyncConsumerScope(value string) (directory.Scope, error) {
	switch strings.ToLower(value) {
	case "base":
		return directory.ScopeBase, nil
	case "one", "onelevel", "singlelevel":
		return directory.ScopeSingleLevel, nil
	case "sub", "subtree":
		return directory.ScopeWholeSubtree, nil
	case "children", "subord", "subordinate":
		return directory.ScopeChildren, nil
	default:
		return 0, fmt.Errorf("unknown syncrepl scope %q", value)
	}
}

func parseSyncConsumerAttributes(value string) ([]string, error) {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), ":include:") {
		return nil, errors.New("attribute include files are not supported")
	}
	attributes := strings.FieldsFunc(value, func(character rune) bool {
		return character == ',' || unicode.IsSpace(character)
	})
	if len(attributes) == 0 {
		return nil, errors.New("attribute list is empty")
	}
	return attributes, nil
}

func parseSyncConsumerBoolean(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "on", "true", "yes", "1":
		return true, nil
	case "off", "false", "no", "0":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean %q", value)
	}
}

func parseSyncConsumerZeroOne(value string) (bool, error) {
	switch value {
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("expected 0 or 1, got %q", value)
	}
}

func parseSyncConsumerInterval(value string) (time.Duration, error) {
	if strings.Contains(value, ":") {
		parts := strings.Split(value, ":")
		if len(parts) != 4 {
			return 0, fmt.Errorf("invalid syncrepl interval %q", value)
		}
		values := make([]uint64, len(parts))
		for index, part := range parts {
			parsed, err := strconv.ParseUint(part, 10, 31)
			if err != nil {
				return 0, fmt.Errorf("invalid syncrepl interval %q", value)
			}
			values[index] = parsed
		}
		if values[1] > 24 || values[2] > 60 || values[3] > 60 {
			return 0, fmt.Errorf("invalid syncrepl interval %q", value)
		}
		seconds := ((values[0]*24+values[1])*60+values[2])*60 +
			values[3]
		return durationFromUnsigned(seconds, time.Second, "interval")
	}

	var seconds uint64
	remaining := value
	lastUnit := -1
	for remaining != "" {
		digits := 0
		for digits < len(remaining) &&
			remaining[digits] >= '0' &&
			remaining[digits] <= '9' {
			digits++
		}
		if digits == 0 {
			return 0, fmt.Errorf("invalid syncrepl interval %q", value)
		}
		number, err := strconv.ParseUint(remaining[:digits], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid syncrepl interval %q", value)
		}
		remaining = remaining[digits:]
		if remaining == "" {
			if lastUnit >= 3 {
				return 0, fmt.Errorf("invalid syncrepl interval %q", value)
			}
			seconds += number
			break
		}
		unit := strings.IndexByte("dhms", remaining[0])
		if unit < 0 || unit <= lastUnit {
			return 0, fmt.Errorf("invalid syncrepl interval %q", value)
		}
		scale := [...]uint64{86400, 3600, 60, 1}
		seconds += number * scale[unit]
		lastUnit = unit
		remaining = remaining[1:]
	}
	return durationFromUnsigned(seconds, time.Second, "interval")
}

func parseSyncConsumerRetry(value string) ([]syncConsumerRetry, error) {
	if strings.EqualFold(strings.TrimSpace(value), "undefined") {
		return []syncConsumerRetry{{interval: time.Hour, attempts: -1}}, nil
	}
	fields := strings.FieldsFunc(value, func(character rune) bool {
		return character == ',' || unicode.IsSpace(character)
	})
	if len(fields) == 0 || len(fields)%2 != 0 {
		return nil, fmt.Errorf("incomplete syncrepl retry list %q", value)
	}
	retry := make([]syncConsumerRetry, 0, len(fields)/2)
	for index := 0; index < len(fields); index += 2 {
		seconds, err := strconv.ParseUint(fields[index], 10, 63)
		if err != nil || seconds == 0 {
			return nil, fmt.Errorf(
				"invalid syncrepl retry interval %q",
				fields[index],
			)
		}
		interval, err := durationFromUnsigned(
			seconds,
			time.Second,
			"retry interval",
		)
		if err != nil {
			return nil, err
		}
		attempts := -1
		if fields[index+1] != "+" {
			attempts, err = strconv.Atoi(fields[index+1])
			if err != nil || attempts <= 0 {
				return nil, fmt.Errorf(
					"invalid syncrepl retry count %q",
					fields[index+1],
				)
			}
		}
		retry = append(retry, syncConsumerRetry{
			interval: interval,
			attempts: attempts,
		})
		if attempts < 0 && index+2 < len(fields) {
			return nil, errors.New(
				"permanent syncrepl retry must be the final retry pair",
			)
		}
	}
	return retry, nil
}

func parseSyncConsumerLimit(value string) (int, error) {
	if strings.EqualFold(value, "unlimited") {
		return 0, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit < 0 {
		return 0, fmt.Errorf("invalid limit %q", value)
	}
	return limit, nil
}

func parseSyncConsumerStartTLS(value string) (syncConsumerStartTLS, error) {
	switch strings.ToLower(value) {
	case "no", "off", "false":
		return syncConsumerStartTLSOff, nil
	case "yes", "on", "true":
		return syncConsumerStartTLSYes, nil
	case "critical":
		return syncConsumerStartTLSCritical, nil
	default:
		return 0, fmt.Errorf("unknown starttls value %q", value)
	}
}

func parseSyncConsumerTLSRequirement(value string) (string, error) {
	switch strings.ToLower(value) {
	case "never", "allow", "try", "demand", "hard":
		return strings.ToLower(value), nil
	default:
		return "", fmt.Errorf("unknown TLS requirement %q", value)
	}
}

func parseSyncConsumerTimeout(
	value string,
	unit time.Duration,
) (time.Duration, error) {
	if strings.EqualFold(value, "none") ||
		strings.EqualFold(value, "unlimited") {
		return 0, nil
	}
	amount, err := strconv.ParseUint(value, 10, 63)
	if err != nil {
		return 0, fmt.Errorf("invalid timeout %q", value)
	}
	return durationFromUnsigned(amount, unit, "timeout")
}

func parseSyncConsumerKeepalive(value string) (syncConsumerKeepalive, error) {
	fields := strings.Split(value, ":")
	if len(fields) != 3 {
		return syncConsumerKeepalive{}, fmt.Errorf(
			"invalid keepalive value %q",
			value,
		)
	}
	values := make([]int, 3)
	for index, field := range fields {
		parsed, err := strconv.Atoi(field)
		if err != nil || parsed < 0 {
			return syncConsumerKeepalive{}, fmt.Errorf(
				"invalid keepalive value %q",
				value,
			)
		}
		values[index] = parsed
	}
	return syncConsumerKeepalive{
		idle:     values[0],
		probes:   values[1],
		interval: values[2],
		set:      true,
	}, nil
}

func durationFromUnsigned(
	value uint64,
	unit time.Duration,
	name string,
) (time.Duration, error) {
	maximum := uint64(^uint64(0)>>1) / uint64(unit)
	if value > maximum {
		return 0, fmt.Errorf("%s is too large", name)
	}
	return time.Duration(value) * unit, nil
}

func syncConsumerBaseWithinSuffixes(
	base directory.DN,
	suffixes []directory.DN,
) bool {
	for _, suffix := range suffixes {
		if suffix.Equal(base) || suffix.AncestorOf(base) {
			return true
		}
	}
	return false
}

func loadSyncConsumerConfigs(
	entry directory.Entry,
	database runtimeDatabase,
) ([]syncConsumerConfig, error) {
	values := entry.Values("olcSyncrepl")
	configs := make([]syncConsumerConfig, 0, len(values))
	orders := make(map[int]struct{})
	for _, value := range values {
		config, err := parseSyncConsumerConfig(
			string(value),
			database.partition,
			database.suffixes,
		)
		if err != nil {
			return nil, fmt.Errorf("%s olcSyncrepl: %w", entry.DN, err)
		}
		if config.order != int(^uint(0)>>1) {
			if _, exists := orders[config.order]; exists {
				return nil, fmt.Errorf(
					"%s olcSyncrepl has duplicate ordered index %d",
					entry.DN,
					config.order,
				)
			}
			orders[config.order] = struct{}{}
		}
		configs = append(configs, config)
	}
	sort.SliceStable(configs, func(left, right int) bool {
		if configs[left].order != configs[right].order {
			return configs[left].order < configs[right].order
		}
		return configs[left].rid < configs[right].rid
	})
	return configs, nil
}

func validateSyncConsumerRIDs(databases []runtimeDatabase) error {
	owners := make(map[int]string)
	for _, database := range databases {
		for _, config := range database.syncConsumers {
			if owner, exists := owners[config.rid]; exists {
				return fmt.Errorf(
					"syncrepl rid %03d is configured by both %s and %s",
					config.rid,
					owner,
					database.name,
				)
			}
			owners[config.rid] = database.name
		}
	}
	return nil
}
