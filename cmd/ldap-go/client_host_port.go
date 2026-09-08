package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// OpenLDAP removed the common -h/-p options in ITS#8618 (before 2.6.13).
// These historical extensions use the existing URI transport and validation.
func (options *ldapClientOptions) parse(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(normalizeLDAPClientHostPortArgs(flags, args)); err != nil {
		return err
	}
	for _, option := range []struct {
		name   string
		values repeatedStringFlag
	}{
		{"h", options.hostSpecs},
		{"p", options.portSpecs},
	} {
		if len(option.values) > 1 {
			return fmt.Errorf("%s: -%s previously specified", flags.Name(), option.name)
		}
		if len(option.values) != 0 && flagWasSet(flags, "H") {
			return fmt.Errorf("%s: -H incompatible with -%s", flags.Name(), option.name)
		}
	}
	if len(options.hostSpecs) == 0 {
		if len(options.portSpecs) != 0 {
			return fmt.Errorf("%s: -p without -h is invalid", flags.Name())
		}
		return nil
	}
	uri, err := ldapClientHostPortURI(options.hostSpecs[0], options.portSpecs)
	if err != nil {
		return err
	}
	options.uri = uri
	return nil
}

// Only split attached -h/-p values in option positions. In particular, password
// values, command operands and existing long flags must remain untouched.
func normalizeLDAPClientHostPortArgs(flags *flag.FlagSet, args []string) []string {
	normalized := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" || argument == "-" || !strings.HasPrefix(argument, "-") {
			return append(normalized, args[index:]...)
		}
		name, _, assigned := strings.Cut(strings.TrimPrefix(argument[1:], "-"), "=")
		option := flags.Lookup(name)
		if option == nil && argument != "-help" && len(argument) > 2 &&
			(argument[:2] == "-h" || argument[:2] == "-p") {
			normalized = append(normalized, argument[:2], argument[2:])
			continue
		}
		normalized = append(normalized, argument)
		if option == nil || assigned {
			continue
		}
		if boolean, ok := option.Value.(interface{ IsBoolFlag() bool }); ok && boolean.IsBoolFlag() {
			continue
		}
		if index+1 < len(args) {
			index++
			normalized = append(normalized, args[index])
		}
	}
	return normalized
}

func ldapClientHostPortURI(host string, ports repeatedStringFlag) (string, error) {
	// Do not include rejected values in diagnostics: they can contain credentials
	// accidentally supplied as an address. Reject URI/list delimiters before parsing.
	if host == "" || len(host) > maxLDAPClientURIListLength ||
		strings.ContainsAny(host, "/\\,?#@%\"<>{}|^`") ||
		strings.ContainsFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return "", errors.New("-h requires a single non-empty host; use -H for LDAP URIs or URI lists")
	}
	port := 389
	inlinePort := ""
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
		if !strings.Contains(host, ":") || net.ParseIP(host) == nil {
			return "", errors.New("-h requires a valid bracketed IPv6 address")
		}
	} else if strings.ContainsAny(host, ":[]") && net.ParseIP(host) == nil {
		bracketed := strings.HasPrefix(host, "[")
		var err error
		host, inlinePort, err = net.SplitHostPort(host)
		if err != nil || host == "" || inlinePort == "" ||
			strings.ContainsAny(host, "[]") {
			return "", errors.New("-h requires a hostname, IPv4 address, or IPv6 address with an optional port")
		}
		if (bracketed || strings.Contains(host, ":")) && (!strings.Contains(host, ":") || net.ParseIP(host) == nil) {
			return "", errors.New("-h requires a valid IPv6 address")
		}
	}
	if inlinePort != "" && len(ports) != 0 {
		return "", errors.New("-p cannot be combined with a port in -h")
	}
	if inlinePort != "" {
		value, err := parseLDAPClientPort(inlinePort, "h")
		if err != nil {
			return "", err
		}
		port = value
	}
	if len(ports) != 0 {
		value, err := parseLDAPClientPort(ports[0], "p")
		if err != nil {
			return "", err
		}
		port = value
	}
	uri := (&url.URL{Scheme: "ldap", Host: net.JoinHostPort(host, strconv.Itoa(port))}).String()
	if _, err := url.Parse(uri); err != nil {
		return "", errors.New("-h requires a valid network host")
	}
	return uri, nil
}

func parseLDAPClientPort(raw, option string) (int, error) {
	// Historical common.c uses strtol(..., 10): allow a sign, leading C whitespace
	// and decimal leading zeroes, but never integer wraparound or trailing garbage.
	value, err := strconv.ParseInt(strings.TrimLeft(raw, " \t\r\n\v\f"), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("unable to parse port number for -%s", option)
	}
	if value < 0 || value > 65535 {
		return 0, fmt.Errorf("-%s port must be between 0 and 65535 (0 uses 389)", option)
	}
	if value == 0 {
		return 389, nil
	}
	return int(value), nil
}
