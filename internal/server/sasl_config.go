package server

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/storage"
)

type saslAuthzRegexp struct {
	order       int
	indexed     bool
	expression  *regexp.Regexp
	replacement string
}

type saslRuntimeConfiguration struct {
	host               string
	realm              string
	securityProperties saslSecurityProperties
	authzRegexps       []saslAuthzRegexp
}

func loadSASLRuntimeConfiguration(
	reader storage.Reader,
) (saslRuntimeConfiguration, error) {
	configuration := saslRuntimeConfiguration{
		host:               defaultSASLHost(),
		securityProperties: defaultSASLSecurityProperties(),
	}
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return configuration, nil
	}
	if err != nil {
		return saslRuntimeConfiguration{}, fmt.Errorf(
			"load global SASL configuration: %w",
			err,
		)
	}

	hostValues := entry.Values("olcSaslHost")
	if len(hostValues) > 1 {
		return saslRuntimeConfiguration{}, fmt.Errorf(
			"%s olcSaslHost has multiple values",
			entry.DN,
		)
	}
	if len(hostValues) == 1 {
		host := strings.TrimSpace(string(hostValues[0]))
		if host == "" {
			return saslRuntimeConfiguration{}, fmt.Errorf(
				"%s olcSaslHost is empty",
				entry.DN,
			)
		}
		configuration.host = host
	}

	realmValues := entry.Values("olcSaslRealm")
	if len(realmValues) > 1 {
		return saslRuntimeConfiguration{}, fmt.Errorf(
			"%s olcSaslRealm has multiple values",
			entry.DN,
		)
	}
	if len(realmValues) == 1 {
		configuration.realm = string(realmValues[0])
	}

	securityValues := entry.Values("olcSaslSecProps")
	if len(securityValues) > 1 {
		return saslRuntimeConfiguration{}, fmt.Errorf(
			"%s olcSaslSecProps has multiple values",
			entry.DN,
		)
	}
	if len(securityValues) == 1 {
		properties, parseErr := parseSASLSecurityProperties(
			string(securityValues[0]),
		)
		if parseErr != nil {
			return saslRuntimeConfiguration{}, fmt.Errorf(
				"%s olcSaslSecProps: %w",
				entry.DN,
				parseErr,
			)
		}
		configuration.securityProperties = properties
	}

	var indexedValues, unindexedValues bool
	for _, rawValue := range entry.Values("olcAuthzRegexp") {
		rule, parseErr := parseSASLAuthzRegexp(string(rawValue))
		if parseErr != nil {
			return saslRuntimeConfiguration{}, fmt.Errorf(
				"%s olcAuthzRegexp: %w",
				entry.DN,
				parseErr,
			)
		}
		if rule.indexed {
			indexedValues = true
		} else {
			unindexedValues = true
		}
		if indexedValues && unindexedValues {
			return saslRuntimeConfiguration{}, fmt.Errorf(
				"%s olcAuthzRegexp mixes indexed and unindexed values",
				entry.DN,
			)
		}
		configuration.authzRegexps = append(
			configuration.authzRegexps,
			rule,
		)
	}
	if indexedValues {
		sort.SliceStable(configuration.authzRegexps, func(i, j int) bool {
			return configuration.authzRegexps[i].order <
				configuration.authzRegexps[j].order
		})
	}
	return configuration, nil
}

func defaultSASLHost() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		return "localhost"
	}
	return host
}

func parseSASLAuthzRegexp(value string) (saslAuthzRegexp, error) {
	order, indexed, description, err := orderedSASLConfigurationValue(value)
	if err != nil {
		return saslAuthzRegexp{}, err
	}
	arguments, err := tokenizeOpenLDAPConfig(description)
	if err != nil {
		return saslAuthzRegexp{}, err
	}
	if len(arguments) != 2 {
		return saslAuthzRegexp{}, errors.New(
			"expected a match expression and replacement",
		)
	}
	if _, err := regexp.CompilePOSIX(arguments[0]); err != nil {
		return saslAuthzRegexp{}, fmt.Errorf(
			"compile match expression %q: %w",
			arguments[0],
			err,
		)
	}
	expression, err := regexp.Compile("(?i:" + arguments[0] + ")")
	if err != nil {
		return saslAuthzRegexp{}, fmt.Errorf(
			"compile match expression %q: %w",
			arguments[0],
			err,
		)
	}
	expression.Longest()
	return saslAuthzRegexp{
		order:       order,
		indexed:     indexed,
		expression:  expression,
		replacement: arguments[1],
	}, nil
}

func orderedSASLConfigurationValue(
	value string,
) (int, bool, string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{") {
		return 0, false, value, nil
	}
	end := strings.IndexByte(value, '}')
	if end < 2 {
		return 0, false, "", errors.New(
			"invalid ordered SASL configuration prefix",
		)
	}
	order, err := strconv.Atoi(value[1:end])
	if err != nil || order < 0 {
		return 0, false, "", fmt.Errorf(
			"invalid ordered SASL configuration prefix %q",
			value[:end+1],
		)
	}
	return order, true, strings.TrimSpace(value[end+1:]), nil
}
