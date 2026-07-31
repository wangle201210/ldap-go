package server

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/storage"
)

const openLDAPServerIDMax = 0x0fff

type serverIDValue struct {
	id  uint16
	uri string
}

func loadServerID(
	reader storage.Reader,
	listenerURLs []string,
) (uint16, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("load global configuration: %w", err)
	}

	rawValues := entry.Values("olcServerID")
	if len(rawValues) == 0 {
		return 0, nil
	}
	values := make([]serverIDValue, 0, len(rawValues))
	seenIDs := make(map[uint16]struct{}, len(rawValues))
	for _, rawValue := range rawValues {
		value, parseErr := parseServerIDValue(string(rawValue))
		if parseErr != nil {
			return 0, fmt.Errorf("%s olcServerID: %w", entry.DN, parseErr)
		}
		if _, duplicate := seenIDs[value.id]; duplicate {
			return 0, fmt.Errorf(
				"%s olcServerID contains duplicate server ID %03x",
				entry.DN,
				value.id,
			)
		}
		seenIDs[value.id] = struct{}{}
		values = append(values, value)
	}

	if values[0].uri == "" {
		if len(values) != 1 {
			return 0, fmt.Errorf(
				"%s olcServerID permits only one value without a URL",
				entry.DN,
			)
		}
		return values[0].id, nil
	}
	for _, value := range values {
		if value.uri == "" {
			return 0, fmt.Errorf(
				"%s olcServerID cannot mix URL-qualified and unqualified values",
				entry.DN,
			)
		}
	}

	var (
		selected uint16
		matched  bool
	)
	for _, value := range values {
		valueMatches := false
		for _, listenerURL := range listenerURLs {
			same, matchErr := serverIDURLMatches(value.uri, listenerURL)
			if matchErr != nil {
				return 0, fmt.Errorf("%s olcServerID: %w", entry.DN, matchErr)
			}
			if same {
				valueMatches = true
				break
			}
		}
		if valueMatches {
			if matched {
				return 0, fmt.Errorf(
					"%s olcServerID has multiple URLs matching local listeners",
					entry.DN,
				)
			}
			selected = value.id
			matched = true
		}
	}
	if !matched {
		return 0, fmt.Errorf(
			"%s olcServerID has no URL matching a local listener",
			entry.DN,
		)
	}
	return selected, nil
}

func parseServerIDValue(raw string) (serverIDValue, error) {
	_, value, err := orderedSyncConsumerValue(raw)
	if err != nil {
		return serverIDValue{}, errors.New("invalid ordered value")
	}
	fields := strings.Fields(value)
	if len(fields) < 1 || len(fields) > 2 {
		return serverIDValue{}, fmt.Errorf("invalid value %q", raw)
	}

	base := 10
	number := fields[0]
	if strings.HasPrefix(strings.ToLower(number), "0x") {
		base = 16
		number = number[2:]
	}
	parsed, err := strconv.ParseUint(number, base, 12)
	if err != nil || parsed > openLDAPServerIDMax {
		return serverIDValue{}, fmt.Errorf("illegal server ID %q", fields[0])
	}
	result := serverIDValue{id: uint16(parsed)}
	if len(fields) == 2 {
		if _, err := parseServerIDURL(fields[1]); err != nil {
			return serverIDValue{}, err
		}
		result.uri = fields[1]
	}
	return result, nil
}

func serverIDURLMatches(configured, listener string) (bool, error) {
	if strings.EqualFold(
		strings.TrimSuffix(configured, "/"),
		strings.TrimSuffix(listener, "/"),
	) {
		return true, nil
	}
	candidate, err := parseServerIDURL(configured)
	if err != nil {
		return false, err
	}
	local, err := parseServerIDURL(listener)
	if err != nil {
		return false, fmt.Errorf("invalid local listener URL %q: %w", listener, err)
	}
	if !strings.EqualFold(candidate.Scheme, local.Scheme) ||
		serverIDURLPort(candidate) != serverIDURLPort(local) {
		return false, nil
	}
	if strings.EqualFold(candidate.Scheme, "ldapi") {
		return candidate.Host == local.Host && candidate.Path == local.Path, nil
	}

	candidateHost := candidate.Hostname()
	listenerHost := local.Hostname()
	if strings.EqualFold(candidateHost, listenerHost) {
		return true, nil
	}
	if !serverIDLocalHost(candidateHost) {
		return false, nil
	}
	return serverIDWildcardHost(candidateHost) ||
		serverIDWildcardHost(listenerHost), nil
}

func parseServerIDURL(raw string) (*url.URL, error) {
	parsed, err := parseSyncConsumerProviderURL(raw)
	if err != nil || parsed.Scheme == "" || parsed.Opaque != "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("invalid listener URL %q", raw)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "ldap", "ldaps", "ldapi", "ldap+tlcp":
	default:
		return nil, fmt.Errorf("invalid listener URL %q", raw)
	}
	if !strings.EqualFold(parsed.Scheme, "ldapi") &&
		parsed.Path != "" && parsed.Path != "/" {
		return nil, fmt.Errorf("listener URL %q contains an LDAP DN", raw)
	}
	return parsed, nil
}

func serverIDURLPort(parsed *url.URL) string {
	if port := parsed.Port(); port != "" {
		return port
	}
	switch strings.ToLower(parsed.Scheme) {
	case "ldap":
		return "389"
	case "ldaps":
		return "636"
	case "ldap+tlcp":
		return "1636"
	default:
		return ""
	}
}

func serverIDLocalHost(host string) bool {
	if serverIDWildcardHost(host) ||
		strings.EqualFold(host, "localhost") {
		return true
	}
	hostname, err := os.Hostname()
	return err == nil && strings.EqualFold(host, hostname)
}

func serverIDWildcardHost(host string) bool {
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}
