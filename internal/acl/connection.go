package acl

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

type stringStyles struct {
	regex    bool
	subtree  bool
	ip       bool
	ipv6     bool
	path     bool
	modifier bool
}

func parseStringMatcher(
	key,
	prefix,
	value string,
	allowed stringStyles,
) (StringMatcher, error) {
	if value == "" {
		return StringMatcher{}, fmt.Errorf("%s requires a value", prefix)
	}
	style := "exact"
	if key != prefix {
		style = strings.TrimPrefix(key, prefix+".")
	}
	modifier := ""
	if comma := strings.IndexByte(style, ','); comma >= 0 {
		modifier = style[comma+1:]
		style = style[:comma]
		if !allowed.modifier || modifier != "expand" {
			return StringMatcher{}, fmt.Errorf("unsupported %s modifier %q", prefix, modifier)
		}
	}
	matcher := StringMatcher{Style: StringExact, Value: value, Expand: modifier == "expand"}
	switch style {
	case "exact", "base", "baseobject":
	case "expand":
		matcher.Expand = true
	case "regex":
		if !allowed.regex {
			return StringMatcher{}, fmt.Errorf("unsupported %s style %q", prefix, style)
		}
		matcher.Style = StringRegex
		matcher.Expand = hasACLExpansion(value)
		if !matcher.Expand {
			pattern, err := regexp.Compile("(?i)" + value)
			if err != nil {
				return StringMatcher{}, fmt.Errorf("compile %s regular expression: %w", prefix, err)
			}
			matcher.Pattern = pattern
		}
	case "sub", "subtree":
		if !allowed.subtree {
			return StringMatcher{}, fmt.Errorf("unsupported %s style %q", prefix, style)
		}
		matcher.Style = StringSubtree
	case "ip":
		if !allowed.ip {
			return StringMatcher{}, fmt.Errorf("unsupported %s style %q", prefix, style)
		}
		matcher.Style = StringIP
		if _, _, _, err := parsePeerPattern(value, false); err != nil {
			return StringMatcher{}, err
		}
	case "ipv6":
		if !allowed.ipv6 {
			return StringMatcher{}, fmt.Errorf("unsupported %s style %q", prefix, style)
		}
		matcher.Style = StringIPv6
		if _, _, _, err := parsePeerPattern(value, true); err != nil {
			return StringMatcher{}, err
		}
	case "path":
		if !allowed.path {
			return StringMatcher{}, fmt.Errorf("unsupported %s style %q", prefix, style)
		}
		matcher.Style = StringPath
	default:
		return StringMatcher{}, fmt.Errorf("unsupported %s style %q", prefix, style)
	}
	if matcher.Expand && !hasACLExpansion(value) {
		return StringMatcher{}, fmt.Errorf("%s expansion pattern contains no substitutions", prefix)
	}
	if matcher.Expand && (matcher.Style == StringIP || matcher.Style == StringIPv6 || matcher.Style == StringPath) {
		return StringMatcher{}, fmt.Errorf("%s style does not support expansion", style)
	}
	return matcher, nil
}

func matchesStringMatcher(
	matcher StringMatcher,
	candidate string,
	context matchContext,
) bool {
	if matcher.Value == "*" {
		return true
	}
	if candidate == "" {
		return false
	}
	value := matcher.Value
	if matcher.Expand {
		expanded, ok := expandACLPattern(value, context)
		if !ok {
			return false
		}
		value = expanded
	}
	switch matcher.Style {
	case StringExact:
		return strings.EqualFold(value, candidate)
	case StringRegex:
		pattern := matcher.Pattern
		if pattern == nil {
			compiled, err := regexp.Compile("(?i)" + value)
			if err != nil {
				return false
			}
			pattern = compiled
		}
		return pattern.MatchString(candidate)
	case StringSubtree:
		candidate = strings.TrimSuffix(strings.ToLower(candidate), ".")
		value = strings.TrimSuffix(strings.ToLower(value), ".")
		return candidate == value || strings.HasSuffix(candidate, "."+value)
	case StringIP:
		return matchesPeerAddress(value, candidate, false)
	case StringIPv6:
		return matchesPeerAddress(value, candidate, true)
	case StringPath:
		return strings.HasPrefix(candidate, "PATH=") && candidate[len("PATH="):] == value
	default:
		return false
	}
}

func parsePeerPattern(value string, ipv6 bool) (net.IP, net.IPMask, int, error) {
	port := -1
	if opening := strings.LastIndexByte(value, '{'); opening >= 0 {
		if !strings.HasSuffix(value, "}") || opening == len(value)-2 {
			return nil, nil, 0, fmt.Errorf("invalid peername port in %q", value)
		}
		parsed, err := strconv.Atoi(value[opening+1 : len(value)-1])
		if err != nil || parsed < 0 || parsed > 65535 {
			return nil, nil, 0, fmt.Errorf("invalid peername port in %q", value)
		}
		port = parsed
		value = value[:opening]
	}
	addressText, maskText, hasMask := strings.Cut(value, "%")
	address := net.ParseIP(addressText)
	if address == nil {
		return nil, nil, 0, fmt.Errorf("invalid peername address %q", addressText)
	}
	bits := 32
	address = address.To4()
	if ipv6 {
		bits = 128
		address = net.ParseIP(addressText).To16()
		if net.ParseIP(addressText).To4() != nil {
			address = nil
		}
	}
	if address == nil {
		return nil, nil, 0, fmt.Errorf("peername address %q has the wrong family", addressText)
	}
	mask := net.CIDRMask(bits, bits)
	if hasMask {
		parsedMask := net.ParseIP(maskText)
		if parsedMask == nil {
			return nil, nil, 0, fmt.Errorf("invalid peername mask %q", maskText)
		}
		if ipv6 {
			parsedMask = parsedMask.To16()
		} else {
			parsedMask = parsedMask.To4()
		}
		if parsedMask == nil {
			return nil, nil, 0, fmt.Errorf("peername mask %q has the wrong family", maskText)
		}
		mask = net.IPMask(parsedMask)
	}
	return address, mask, port, nil
}

func matchesPeerAddress(pattern, candidate string, ipv6 bool) bool {
	wanted, mask, wantedPort, err := parsePeerPattern(pattern, ipv6)
	if err != nil {
		return false
	}
	actual, actualPort, err := parseOpenLDAPPeerName(candidate)
	if err != nil || (wantedPort >= 0 && actualPort != wantedPort) {
		return false
	}
	if ipv6 {
		if actual.To4() != nil {
			return false
		}
		actual = actual.To16()
	} else {
		actual = actual.To4()
	}
	if actual == nil || len(actual) != len(wanted) || len(mask) != len(wanted) {
		return false
	}
	for index := range wanted {
		if actual[index]&mask[index] != wanted[index] {
			return false
		}
	}
	return true
}

func parseOpenLDAPPeerName(value string) (net.IP, int, error) {
	if len(value) < len("IP=") || !strings.EqualFold(value[:len("IP=")], "IP=") {
		return nil, 0, errors.New("peername is not an IP address")
	}
	host, portText, err := net.SplitHostPort(value[len("IP="):])
	if err != nil {
		return nil, 0, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, 0, err
	}
	address := net.ParseIP(host)
	if address == nil {
		return nil, 0, errors.New("invalid peername IP address")
	}
	return address, port, nil
}
