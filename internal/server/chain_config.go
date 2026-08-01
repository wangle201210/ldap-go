package server

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type chainIdentityMode uint8

const (
	chainIdentityLegacy chainIdentityMode = iota
	chainIdentitySelf
	chainIdentityAnonymous
	chainIdentityNone
	chainIdentityOtherDN
	chainIdentityOtherID
)

type chainFeatureMode uint8

const (
	chainFeatureDisabled chainFeatureMode = iota
	chainFeatureEnabled
	chainFeatureDiscover
)

type chainIdentityAssertion struct {
	configured         bool
	mode               chainIdentityMode
	native             bool
	override           bool
	prescriptive       bool
	proxyAuthzCritical bool
	assertedID         string
	authzFrom          []string
	passThru           []string
}

type chainRemoteConfiguration struct {
	order               int
	uri                 string
	endpointKey         string
	bind                syncConsumerConfig
	aclBind             syncConsumerConfig
	identity            chainIdentityAssertion
	startTLSMode        string
	rebindAsUser        bool
	chaseReferrals      bool
	protocolVersion     int
	operationTimeouts   map[uint64]time.Duration
	idleTimeout         time.Duration
	connectionTTL       time.Duration
	singleConnection    bool
	useTemporary        bool
	connectionPoolMax   int
	quarantine          []syncConsumerRetry
	cancelMode          string
	stopOnError         bool
	absoluteFilters     chainFeatureMode
	noRefs              bool
	noUndefinedFilter   bool
	removeUnknownSchema bool
	proxyWhoAmI         bool
	sessionTracking     bool
}

type chainRuntimeConfiguration struct {
	configDNKey      string
	cacheURI         bool
	maxReferralDepth int
	returnError      bool
	outboundChaining *ldapwire.Control
	common           chainRemoteConfiguration
	remotes          []chainRemoteConfiguration
}

func defaultChainRemoteConfiguration() chainRemoteConfiguration {
	return chainRemoteConfiguration{
		order: math.MaxInt,
		bind: syncConsumerConfig{
			securityProperties: defaultSyncConsumerSASLSecurityProperties(),
		},
		aclBind: syncConsumerConfig{
			securityProperties: defaultSyncConsumerSASLSecurityProperties(),
		},
		identity: chainIdentityAssertion{
			mode:         chainIdentityLegacy,
			prescriptive: true,
		},
		chaseReferrals:    true,
		protocolVersion:   3,
		connectionPoolMax: 16,
		operationTimeouts: make(map[uint64]time.Duration),
	}
}

func (configuration chainRemoteConfiguration) clone() chainRemoteConfiguration {
	clone := configuration
	clone.bind.credentials = bytes.Clone(configuration.bind.credentials)
	clone.aclBind.credentials = bytes.Clone(configuration.aclBind.credentials)
	clone.identity.authzFrom = append([]string(nil), configuration.identity.authzFrom...)
	clone.identity.passThru = append([]string(nil), configuration.identity.passThru...)
	clone.operationTimeouts = make(map[uint64]time.Duration, len(configuration.operationTimeouts))
	for operation, timeout := range configuration.operationTimeouts {
		clone.operationTimeouts[operation] = timeout
	}
	clone.quarantine = append([]syncConsumerRetry(nil), configuration.quarantine...)
	return clone
}

func loadChainRuntimeConfiguration(
	reader storage.Reader,
	overlay directory.Entry,
) (chainRuntimeConfiguration, error) {
	overlayDN, err := directory.ParseDN(overlay.DN)
	if err != nil {
		return chainRuntimeConfiguration{}, err
	}
	configuration := chainRuntimeConfiguration{
		configDNKey:      overlayDN.Key(),
		maxReferralDepth: 1,
		common:           defaultChainRemoteConfiguration(),
	}
	configuration.cacheURI, _, err = singleBoolean(overlay, "olcChainCacheURI")
	if err != nil {
		return chainRuntimeConfiguration{}, err
	}
	configuration.returnError, _, err = singleBoolean(overlay, "olcChainReturnError")
	if err != nil {
		return chainRuntimeConfiguration{}, err
	}
	configuration.maxReferralDepth, err = singleNonnegativeInteger(
		overlay,
		"olcChainMaxReferralDepth",
		1,
	)
	if err != nil {
		return chainRuntimeConfiguration{}, err
	}
	if values := overlay.Values("olcChainingBehavior"); len(values) > 1 {
		return chainRuntimeConfiguration{}, fmt.Errorf(
			"%s olcChainingBehavior must be single-valued",
			overlay.DN,
		)
	} else if len(values) == 1 {
		control, parseErr := parseConfiguredChainingBehavior(string(values[0]))
		if parseErr != nil {
			return chainRuntimeConfiguration{}, fmt.Errorf(
				"%s olcChainingBehavior: %w",
				overlay.DN,
				parseErr,
			)
		}
		configuration.outboundChaining = &control
	}

	var children []directory.Entry
	if err := reader.ForEach(func(entry directory.Entry) error {
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return fmt.Errorf("parse entry DN %q: %w", entry.DN, err)
		}
		parent, ok := dn.Parent()
		if !ok || !parent.Equal(overlayDN) {
			return nil
		}
		values := entry.Values("olcDatabase")
		if len(values) == 0 {
			return nil
		}
		if len(values) != 1 {
			return fmt.Errorf("%s olcDatabase must be single-valued", entry.DN)
		}
		if databaseType(string(values[0])) != "ldap" {
			return fmt.Errorf(
				"%s chain child database must use the ldap backend",
				entry.DN,
			)
		}
		children = append(children, entry)
		return nil
	}); err != nil {
		return chainRuntimeConfiguration{}, err
	}
	sort.SliceStable(children, func(left, right int) bool {
		leftOrder := chainDatabaseOrder(children[left])
		rightOrder := chainDatabaseOrder(children[right])
		if leftOrder != rightOrder {
			return leftOrder < rightOrder
		}
		return children[left].DN < children[right].DN
	})

	commonSeen := false
	seenEndpoints := make(map[string]string)
	for index, child := range children {
		remote := configuration.common.clone()
		remote.order = chainDatabaseOrder(child)
		if err := loadChainRemoteConfiguration(child, &remote); err != nil {
			return chainRuntimeConfiguration{}, err
		}
		if remote.uri == "" {
			if commonSeen || index != 0 {
				return chainRuntimeConfiguration{}, fmt.Errorf(
					"%s only the first chain child may omit olcDbURI",
					child.DN,
				)
			}
			commonSeen = true
			configuration.common = remote
			continue
		}
		if previous, exists := seenEndpoints[remote.endpointKey]; exists {
			return chainRuntimeConfiguration{}, fmt.Errorf(
				"%s duplicates chain URI configured by %s",
				child.DN,
				previous,
			)
		}
		seenEndpoints[remote.endpointKey] = child.DN
		configuration.remotes = append(configuration.remotes, remote)
	}
	return configuration, nil
}

func loadChainRemoteConfiguration(
	entry directory.Entry,
	configuration *chainRemoteConfiguration,
) error {
	uri, present, err := singleChainString(entry, "olcDbURI")
	if err != nil {
		return err
	}
	if present {
		configuration.uri, configuration.endpointKey, err = parseChainConfiguredURI(uri)
		if err != nil {
			return fmt.Errorf("%s olcDbURI: %w", entry.DN, err)
		}
	}

	if value, present, err := singleChainString(entry, "olcDbACLBind"); err != nil {
		return err
	} else if present {
		temporary := defaultChainRemoteConfiguration()
		temporary.bind = configuration.aclBind
		if err := parseChainIdentityAssertion(value, &temporary); err != nil {
			return fmt.Errorf("%s olcDbACLBind: %w", entry.DN, err)
		}
		configuration.aclBind = temporary.bind
	}

	startTLS, present, err := singleChainString(entry, "olcDbStartTLS")
	if err != nil {
		return err
	}
	if present {
		configuration.startTLSMode = strings.ToLower(startTLS)
		configuration.bind.startTLS, err = parseChainStartTLS(startTLS)
		if err != nil {
			return fmt.Errorf("%s olcDbStartTLS: %w", entry.DN, err)
		}
	}

	networkTimeout, present, err := singleChainString(entry, "olcDbNetworkTimeout")
	if err != nil {
		return err
	}
	if present {
		configuration.bind.networkTimeout, err = parseChainTimeInterval(networkTimeout)
		if err != nil {
			return fmt.Errorf("%s olcDbNetworkTimeout: %w", entry.DN, err)
		}
	}

	keepalive, present, err := singleChainString(entry, "olcDbKeepalive")
	if err != nil {
		return err
	}
	if present {
		configuration.bind.keepalive, err = parseSyncConsumerKeepalive(keepalive)
		if err != nil {
			return fmt.Errorf("%s olcDbKeepalive: %w", entry.DN, err)
		}
	}
	tcpTimeout, present, err := singleChainString(entry, "olcDbTcpUserTimeout")
	if err != nil {
		return err
	}
	if present {
		configuration.bind.tcpUserTimeout, err = parseSyncConsumerTimeout(
			tcpTimeout,
			time.Millisecond,
		)
		if err != nil {
			return fmt.Errorf("%s olcDbTcpUserTimeout: %w", entry.DN, err)
		}
	}

	if value, present, err := singleChainString(entry, "olcDbProtocolVersion"); err != nil {
		return err
	} else if present {
		version, parseErr := strconv.Atoi(value)
		if parseErr != nil || (version != 0 && version != 2 && version != 3) {
			return fmt.Errorf("%s olcDbProtocolVersion has invalid value %q", entry.DN, value)
		}
		configuration.protocolVersion = version
	}

	if value, present, parseErr := optionalChainBoolean(entry, "olcDbRebindAsUser"); parseErr != nil {
		return parseErr
	} else if present {
		configuration.rebindAsUser = value
	}
	if value, present, parseErr := optionalChainBoolean(entry, "olcDbChaseReferrals"); parseErr != nil {
		return parseErr
	} else if present {
		configuration.chaseReferrals = value
	}
	optionalBooleans := []struct {
		description string
		target      *bool
	}{
		{description: "olcDbNoRefs", target: &configuration.noRefs},
		{description: "olcDbNoUndefFilter", target: &configuration.noUndefinedFilter},
		{description: "olcDbRemoveUnknownSchema", target: &configuration.removeUnknownSchema},
		{description: "olcDbProxyWhoAmI", target: &configuration.proxyWhoAmI},
		{description: "olcDbSessionTrackingRequest", target: &configuration.sessionTracking},
	}
	for _, setting := range optionalBooleans {
		value, present, parseErr := optionalChainBoolean(entry, setting.description)
		if parseErr != nil {
			return parseErr
		}
		if present {
			*setting.target = value
		}
	}

	if value, present, err := singleChainString(entry, "olcDbTimeout"); err != nil {
		return err
	} else if present {
		configuration.operationTimeouts, err = parseChainOperationTimeouts(value)
		if err != nil {
			return fmt.Errorf("%s olcDbTimeout: %w", entry.DN, err)
		}
	}
	for _, setting := range []struct {
		description string
		target      *time.Duration
	}{
		{description: "olcDbIdleTimeout", target: &configuration.idleTimeout},
		{description: "olcDbConnTtl", target: &configuration.connectionTTL},
	} {
		value, present, parseErr := singleChainString(entry, setting.description)
		if parseErr != nil {
			return parseErr
		}
		if !present {
			continue
		}
		*setting.target, parseErr = parseOpenLDAPTimeInterval(value)
		if parseErr != nil {
			return fmt.Errorf("%s %s: %w", entry.DN, setting.description, parseErr)
		}
	}
	for _, setting := range []struct {
		description string
		target      *bool
	}{
		{description: "olcDbSingleConn", target: &configuration.singleConnection},
		{description: "olcDbUseTemporaryConn", target: &configuration.useTemporary},
	} {
		value, present, parseErr := optionalChainBoolean(entry, setting.description)
		if parseErr != nil {
			return parseErr
		}
		if present {
			*setting.target = value
		}
	}
	if value, present, err := singleChainString(entry, "olcDbConnectionPoolMax"); err != nil {
		return err
	} else if present {
		maximum, parseErr := strconv.Atoi(value)
		if parseErr != nil || maximum < 1 || maximum > 256 {
			return fmt.Errorf(
				"%s olcDbConnectionPoolMax must be between 1 and 256",
				entry.DN,
			)
		}
		configuration.connectionPoolMax = maximum
	}
	if value, present, err := singleChainString(entry, "olcDbQuarantine"); err != nil {
		return err
	} else if present {
		configuration.quarantine, err = parseChainQuarantine(value)
		if err != nil {
			return fmt.Errorf("%s olcDbQuarantine: %w", entry.DN, err)
		}
	}
	if value, present, err := singleChainString(entry, "olcDbCancel"); err != nil {
		return err
	} else if present {
		switch strings.ToLower(value) {
		case "abandon", "ignore", "exop", "discover", "exop-discover":
			configuration.cancelMode = strings.ToLower(value)
		default:
			return fmt.Errorf("%s olcDbCancel has invalid value %q", entry.DN, value)
		}
	}
	if value, present, err := singleChainString(entry, "olcDbOnErr"); err != nil {
		return err
	} else if present {
		switch strings.ToLower(value) {
		case "continue":
			configuration.stopOnError = false
		case "report", "stop":
			configuration.stopOnError = true
		default:
			return fmt.Errorf("%s olcDbOnErr has invalid value %q", entry.DN, value)
		}
	}
	if value, present, err := singleChainString(entry, "olcDbTFSupport"); err != nil {
		return err
	} else if present {
		configuration.absoluteFilters, err = parseChainFeatureMode(value)
		if err != nil {
			return fmt.Errorf("%s olcDbTFSupport: %w", entry.DN, err)
		}
	}

	idAssert, present, err := singleChainString(entry, "olcDbIDAssertBind")
	if err != nil {
		return err
	}
	if present {
		if err := parseChainIdentityAssertion(idAssert, configuration); err != nil {
			return fmt.Errorf("%s olcDbIDAssertBind: %w", entry.DN, err)
		}
	}
	if values := entry.Values("olcDbIDAssertAuthzFrom"); len(values) > 0 {
		configuration.identity.authzFrom = chainStringValues(values)
	}
	if values := entry.Values("olcDbIDAssertPassThru"); len(values) > 0 {
		configuration.identity.passThru = chainStringValues(values)
	}
	return nil
}

func parseChainIdentityAssertion(
	value string,
	configuration *chainRemoteConfiguration,
) error {
	arguments, err := tokenizeOpenLDAPConfig(value)
	if err != nil {
		return err
	}
	if len(arguments) == 0 {
		return fmt.Errorf("empty identity assertion configuration")
	}
	identity := configuration.identity
	identity.configured = true
	bind := configuration.bind
	bindDNSet := false
	credentialsSet := false
	modeSet := false
	for _, argument := range arguments {
		key, rawValue, hasValue := strings.Cut(argument, "=")
		if !hasValue {
			return fmt.Errorf("invalid field %q", argument)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		switch key {
		case "mode":
			modeSet = true
			switch strings.ToLower(rawValue) {
			case "legacy":
				identity.mode = chainIdentityLegacy
			case "self":
				identity.mode = chainIdentitySelf
			case "anonymous":
				identity.mode = chainIdentityAnonymous
			case "none":
				identity.mode = chainIdentityNone
			default:
				return fmt.Errorf("unknown mode %q", rawValue)
			}
		case "authz":
			switch strings.ToLower(rawValue) {
			case "native":
				identity.native = true
			case "proxyauthz":
				identity.native = false
			default:
				return fmt.Errorf("unknown authz mode %q", rawValue)
			}
		case "flags":
			for _, flag := range strings.Split(rawValue, ",") {
				switch strings.ToLower(strings.TrimSpace(flag)) {
				case "override":
					identity.override = true
				case "prescriptive":
					identity.prescriptive = true
				case "non-prescriptive":
					identity.prescriptive = false
				case "proxy-authz-critical":
					identity.proxyAuthzCritical = true
				case "proxy-authz-non-critical", "dn-none", "dn-authzid", "dn-whoami", "obsolete-proxy-authz", "obsolete-encoding-workaround":
				default:
					return fmt.Errorf("unknown identity assertion flag %q", flag)
				}
			}
		case "bindmethod":
			switch strings.ToLower(rawValue) {
			case "none":
				bind.bindMethod = ""
			case "simple", "sasl":
				bind.bindMethod = strings.ToLower(rawValue)
			default:
				return fmt.Errorf("unknown bind method %q", rawValue)
			}
		case "binddn":
			if _, err := directory.ParseDN(rawValue); err != nil {
				return fmt.Errorf("invalid bind DN %q: %w", rawValue, err)
			}
			bind.bindDN = rawValue
			bindDNSet = true
		case "credentials":
			bind.credentials = []byte(rawValue)
			bind.credentialsSet = true
			credentialsSet = true
		case "saslmech":
			bind.saslMechanism = rawValue
		case "authcid":
			bind.authenticationID = rawValue
		case "authzid":
			bind.authorizationID = rawValue
		case "realm":
			bind.realm = rawValue
		case "secprops":
			bind.securityPropertiesText = rawValue
			bind.securityProperties, err = parseSyncConsumerSASLSecurityProperties(rawValue)
			if err != nil {
				return err
			}
		case "timeout":
			bind.operationTimeout, err = parseChainTimeInterval(rawValue)
			if err != nil {
				return err
			}
		case "network-timeout":
			bind.networkTimeout, err = parseChainTimeInterval(rawValue)
			if err != nil {
				return err
			}
		case "keepalive":
			bind.keepalive, err = parseSyncConsumerKeepalive(rawValue)
			if err != nil {
				return err
			}
		case "tcp-user-timeout":
			bind.tcpUserTimeout, err = parseSyncConsumerTimeout(rawValue, time.Millisecond)
			if err != nil {
				return err
			}
		case "starttls":
			bind.startTLS, err = parseSyncConsumerStartTLS(rawValue)
			if err != nil {
				return err
			}
		case "tls_cert":
			bind.tls.certificateFile = rawValue
		case "tls_key":
			bind.tls.keyFile = rawValue
		case "tls_cacert":
			bind.tls.caCertificate = rawValue
		case "tls_cacertdir":
			bind.tls.caDirectory = rawValue
		case "tls_reqcert":
			bind.tls.requireCert, err = parseSyncConsumerTLSRequirement(rawValue)
			if err != nil {
				return err
			}
		case "tls_reqsan":
			bind.tls.requireSAN = strings.ToLower(rawValue)
		case "tls_cipher_suite":
			bind.tls.cipherSuite = rawValue
		case "tls_protocol_min":
			bind.tls.protocolMinimum = rawValue
		case "tls_ecname":
			bind.tls.ecName = rawValue
		case "tls_crlcheck":
			bind.tls.crlCheck = strings.ToLower(rawValue)
		case "version":
			if rawValue != "3" {
				return fmt.Errorf("unsupported LDAP version %q", rawValue)
			}
		default:
			return fmt.Errorf("unknown field %q", argument)
		}
	}
	if bind.bindMethod == "simple" && (!bindDNSet || !credentialsSet) {
		return fmt.Errorf("simple bind requires binddn and credentials")
	}
	if bind.bindMethod == "sasl" && bind.saslMechanism == "" {
		return fmt.Errorf("SASL bind requires saslmech")
	}
	if identity.native && bind.bindMethod != "sasl" {
		return fmt.Errorf("native authorization requires SASL bind")
	}
	if !modeSet && bind.authorizationID != "" {
		authorizationID := strings.TrimSpace(bind.authorizationID)
		if strings.HasPrefix(strings.ToLower(authorizationID), "u:") {
			identity.mode = chainIdentityOtherID
			identity.assertedID = authorizationID
		} else {
			rawDN := authorizationID
			if strings.HasPrefix(strings.ToLower(rawDN), "dn:") {
				rawDN = rawDN[3:]
			}
			dn, err := directory.ParseDN(rawDN)
			if err != nil {
				return fmt.Errorf("invalid authorization ID %q: %w", authorizationID, err)
			}
			identity.mode = chainIdentityOtherDN
			identity.assertedID = "dn:" + dn.String()
		}
	}
	configuration.identity = identity
	configuration.bind = bind
	return nil
}

func parseChainConfiguredURI(value string) (string, string, error) {
	parts := strings.FieldsFunc(value, func(character rune) bool {
		return character == ',' || unicode.IsSpace(character)
	})
	if len(parts) != 1 {
		return "", "", fmt.Errorf("must contain exactly one LDAP URL")
	}
	parsed, err := parseSyncConsumerProviderURL(parts[0])
	if err != nil {
		return "", "", err
	}
	if _, err := chainEndpointKey(parsed); err != nil {
		return "", "", err
	}
	key, _ := chainEndpointKey(parsed)
	return parts[0], key, nil
}

func chainEndpointKey(parsed *url.URL) (string, error) {
	if parsed == nil {
		return "", fmt.Errorf("URL is nil")
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "ldap", "ldaps", "ldapi", "ldap+tlcp":
	default:
		return "", fmt.Errorf("unsupported LDAP URL scheme %q", parsed.Scheme)
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.ForceQuery {
		return "", fmt.Errorf("configured chain URL must contain only an endpoint")
	}
	if scheme != "ldapi" && parsed.Host == "" {
		return "", fmt.Errorf("configured chain URL has no host")
	}
	if scheme != "ldapi" && parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("configured chain URL must not contain a DN")
	}
	if scheme == "ldapi" {
		if parsed.Host != "" && parsed.Path != "" && parsed.Path != "/" {
			return "", fmt.Errorf("configured chain URL must not contain a DN")
		}
		return scheme + "://" + chainLDAPISocket(parsed), nil
	}
	return scheme + "://" + strings.ToLower(parsed.Host), nil
}

func chainLDAPISocket(parsed *url.URL) string {
	socket := parsed.Host
	if socket == "" {
		socket = parsed.Path
	}
	if socket == "" || socket == "/" {
		return "/var/run/slapd/ldapi"
	}
	return socket
}

func parseChainStartTLS(value string) (syncConsumerStartTLS, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "none":
		return syncConsumerStartTLSOff, nil
	case "try-start", "try-propagate":
		return syncConsumerStartTLSYes, nil
	case "start", "propagate":
		return syncConsumerStartTLSCritical, nil
	case "ldaps":
		return syncConsumerStartTLSOff, nil
	default:
		return 0, fmt.Errorf("unknown TLS mode %q", value)
	}
}

func parseChainFeatureMode(value string) (chainFeatureMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on":
		return chainFeatureEnabled, nil
	case "false", "no", "off":
		return chainFeatureDisabled, nil
	case "discover":
		return chainFeatureDiscover, nil
	default:
		return 0, fmt.Errorf("invalid feature mode %q", value)
	}
}

func parseChainOperationTimeouts(value string) (map[uint64]time.Duration, error) {
	result := make(map[uint64]time.Duration)
	operationTags := map[string]uint64{
		"bind":    0,
		"search":  3,
		"modify":  6,
		"add":     8,
		"delete":  10,
		"modrdn":  12,
		"compare": 14,
	}
	allOperations := []uint64{0, 3, 6, 8, 10, 12, 14, 23}
	fields := strings.FieldsFunc(value, func(character rune) bool {
		return character == ',' || unicode.IsSpace(character)
	})
	for _, field := range fields {
		name, rawTimeout, found := strings.Cut(field, "=")
		if !found {
			timeout, err := parseSyncConsumerTimeout(field, time.Second)
			if err != nil {
				return nil, fmt.Errorf("invalid operation timeout %q", field)
			}
			for _, operation := range allOperations {
				result[operation] = timeout
			}
			continue
		}
		tag, known := operationTags[strings.ToLower(name)]
		if !known {
			return nil, fmt.Errorf("unknown operation %q", name)
		}
		timeout, err := parseSyncConsumerTimeout(rawTimeout, time.Second)
		if err != nil {
			return nil, err
		}
		result[tag] = timeout
	}
	return result, nil
}

func parseChainTimeInterval(value string) (time.Duration, error) {
	if strings.EqualFold(strings.TrimSpace(value), "none") ||
		strings.EqualFold(strings.TrimSpace(value), "unlimited") {
		return 0, nil
	}
	return parseOpenLDAPTimeInterval(strings.TrimSpace(value))
}

func parseChainQuarantine(value string) ([]syncConsumerRetry, error) {
	patterns := strings.FieldsFunc(value, func(character rune) bool {
		return character == ';' || unicode.IsSpace(character)
	})
	if len(patterns) == 0 {
		return nil, errors.New("empty retry pattern")
	}
	result := make([]syncConsumerRetry, 0, len(patterns))
	for index, pattern := range patterns {
		rawInterval, rawAttempts, found := strings.Cut(pattern, ",")
		if !found || strings.Contains(rawAttempts, ",") {
			return nil, fmt.Errorf("invalid retry pattern %q", pattern)
		}
		interval, err := parseOpenLDAPTimeInterval(rawInterval)
		if err != nil {
			return nil, err
		}
		attempts := -1
		if rawAttempts == "+" {
			if index != len(patterns)-1 {
				return nil, errors.New("permanent retry must be the final pattern")
			}
		} else {
			attempts, err = strconv.Atoi(rawAttempts)
			if err != nil || attempts <= 0 {
				return nil, fmt.Errorf("invalid retry count %q", rawAttempts)
			}
		}
		result = append(result, syncConsumerRetry{
			interval: interval,
			attempts: attempts,
		})
	}
	return result, nil
}

func parseConfiguredChainingBehavior(value string) (ldapwire.Control, error) {
	arguments, err := tokenizeOpenLDAPConfig(value)
	if err != nil {
		return ldapwire.Control{}, err
	}
	control := ldapwire.Control{OID: chainingBehaviorControlOID}
	resolve := chainBehaviorChainingPreferred
	continuation := chainBehaviorChainingPreferred
	hasResolve := false
	hasContinuation := false
	for _, argument := range arguments {
		if strings.EqualFold(argument, "critical") {
			if control.Critical {
				return ldapwire.Control{}, errors.New("critical specified multiple times")
			}
			control.Critical = true
			continue
		}
		key, behavior, found := strings.Cut(argument, "=")
		if !found {
			return ldapwire.Control{}, fmt.Errorf("invalid behavior %q", argument)
		}
		parsed, parseErr := parseChainBehaviorName(behavior)
		if parseErr != nil {
			return ldapwire.Control{}, parseErr
		}
		switch strings.ToLower(key) {
		case "resolve":
			if hasResolve {
				return ldapwire.Control{}, errors.New("resolve specified multiple times")
			}
			resolve = parsed
			hasResolve = true
		case "continuation":
			if hasContinuation {
				return ldapwire.Control{}, errors.New("continuation specified multiple times")
			}
			continuation = parsed
			hasContinuation = true
		default:
			return ldapwire.Control{}, fmt.Errorf("invalid behavior %q", argument)
		}
	}
	if !hasResolve && !hasContinuation {
		return control, nil
	}
	encodedValue := ber.NewSequence("ChainingBehavior")
	encodedValue.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(resolve),
		"resolveBehavior",
	))
	if hasContinuation {
		encodedValue.AppendChild(ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagEnumerated,
			int64(continuation),
			"continuationBehavior",
		))
	}
	control.Value = encodedValue.Bytes()
	control.HasValue = true
	return control, nil
}

func parseChainBehaviorName(value string) (chainBehavior, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "chainingpreferred":
		return chainBehaviorChainingPreferred, nil
	case "chainingrequired":
		return chainBehaviorChainingRequired, nil
	case "referralspreferred":
		return chainBehaviorReferralsPreferred, nil
	case "referralsrequired":
		return chainBehaviorReferralsRequired, nil
	default:
		return 0, fmt.Errorf("unknown behavior %q", value)
	}
}

func chainDatabaseOrder(entry directory.Entry) int {
	values := entry.Values("olcDatabase")
	if len(values) != 1 {
		return math.MaxInt
	}
	value := strings.TrimSpace(string(values[0]))
	if !strings.HasPrefix(value, "{") {
		return math.MaxInt
	}
	end := strings.IndexByte(value, '}')
	if end <= 1 {
		return math.MaxInt
	}
	order, err := strconv.Atoi(value[1:end])
	if err != nil || order < 0 {
		return math.MaxInt
	}
	return order
}

func singleChainString(
	entry directory.Entry,
	description string,
) (string, bool, error) {
	values := entry.Values(description)
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 {
		return "", false, fmt.Errorf(
			"%s %s must be single-valued",
			entry.DN,
			description,
		)
	}
	return strings.TrimSpace(string(values[0])), true, nil
}

func optionalChainBoolean(
	entry directory.Entry,
	description string,
) (bool, bool, error) {
	return singleBoolean(entry, description)
}

func chainStringValues(values [][]byte) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = string(values[index])
	}
	return result
}
