package main

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
)

const (
	maxLDAPURLToolInputBytes = 64 << 10
	maxLDAPURLToolArgs       = 256
	maxLDAPURLToolExtensions = 64
)

// Compatibility reference: OpenLDAP d172686d3d270bc961b78f3ff00d7019c8dfb094,
// clients/tools/ldapurl.c and libraries/libldap/{url,charray}.c. This offline
// tool deliberately does not use the stricter network-client URL parser.
const ldapURLToolUsage = `usage: ldapurl [options]

generates RFC 4516 LDAP URL with extensions

URL options:
  -a attrs   comma separated list of attributes
  -b base    (RFC 4514 LDAP DN)
  -E ext     (format: "ext=value"; multiple occurrences allowed)
  -f filter  (RFC 4515 LDAP filter)
  -h host` + "    \n" + `  -p port    (default: 389 for ldap, 636 for ldaps)
  -s scope   (RFC 4511 searchScope and extensions)
  -S scheme  (RFC 4516 LDAP URL scheme and extensions)
`

type ldapURLToolDesc struct {
	scheme, host, base, scope, filter string
	port                              int
	attrs, extensions                 []string
	filterSet                         bool
}

func runLDAPURL(args []string, stdout, stderr io.Writer) error {
	// Validate the callable API before interpreting flags, including ignored
	// operands. Raw NUL cannot occur in argv; percent-encoded NUL can.
	if len(args) > maxLDAPURLToolArgs {
		return ldapURLToolError(stderr, false, "ldapurl: at most %d arguments are supported", maxLDAPURLToolArgs)
	}
	totalBytes := 0
	for _, arg := range args {
		if len(arg) > maxLDAPURLToolInputBytes-totalBytes {
			return ldapURLToolError(stderr, false, "ldapurl: total input exceeds %d bytes", maxLDAPURLToolInputBytes)
		}
		totalBytes += len(arg)
		if strings.ContainsRune(arg, 0) {
			return ldapURLToolError(stderr, false, "ldapurl: arguments must not contain NUL bytes")
		}
	}
	desc := ldapURLToolDesc{scheme: "ldap", port: -1}
	names := map[byte]string{
		'S': "scheme", 'h': "host", 'p': "port", 'b': "base",
		'a': "attrs", 's': "scope", 'f': "filter", 'E': "extensions", 'H': "URI",
	}
	seen := make(map[byte]bool)
	var uri string
	construct := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		// All supported getopt options take values. Stop at operands or --,
		// and retain attached values verbatim (including a leading '=').
		if arg == "--" || len(arg) < 2 || arg[0] != '-' {
			break
		}
		option := arg[1]
		if _, ok := names[option]; !ok {
			return ldapURLToolError(stderr, true, "ldapurl: illegal option -- %c", option)
		}
		value := arg[2:]
		if value == "" {
			i++
			if i == len(args) {
				return ldapURLToolError(stderr, true, "ldapurl: option requires an argument -- %c", option)
			}
			value = args[i]
		}
		if option == 'H' {
			if construct {
				return ldapURLToolError(stderr, true, "option -H incompatible with previous options")
			}
		} else {
			if seen['H'] {
				return ldapURLToolError(stderr, true, "option -%c incompatible with -H", option)
			}
			construct = true
		}
		// OpenLDAP uses -1 as both the initial port and the unset sentinel.
		if seen[option] && option != 'E' && !(option == 'p' && desc.port == -1) {
			return ldapURLToolError(stderr, true, "%s already provided", names[option])
		}
		seen[option] = true
		switch option {
		case 'H':
			uri = value
		case 'S':
			desc.scheme = value
		case 'h':
			desc.host = value
		case 'p':
			port, err := strconv.ParseInt(strings.TrimLeft(value, " \t\r\n\v\f"), 10, 32)
			if err != nil {
				return ldapURLToolError(stderr, true, "unable to parse port \"%s\"", value)
			}
			desc.port = int(port)
		case 'b':
			desc.base = value
		case 'a':
			desc.attrs = ldapURLToolList(value)
		case 's':
			desc.scope = ldapURLToolScope(value)
			if desc.scope == "" {
				return ldapURLToolError(stderr, true, "unable to parse scope \"%s\"", value)
			}
		case 'f':
			desc.filter, desc.filterSet = value, true
		case 'E':
			if len(desc.extensions) == maxLDAPURLToolExtensions {
				return ldapURLToolError(stderr, false, "ldapurl: at most %d extensions are supported", maxLDAPURLToolExtensions)
			}
			desc.extensions = append(desc.extensions, value)
		}
	}
	if seen['H'] {
		parsed, ok := parseLDAPURLTool(uri)
		if !ok {
			return ldapURLToolError(stderr, false, "unable to parse URI \"%s\"", uri)
		}
		if len(parsed.extensions) > maxLDAPURLToolExtensions {
			return ldapURLToolError(stderr, false, "ldapurl: at most %d extensions are supported", maxLDAPURLToolExtensions)
		}
		_, err := io.WriteString(stdout, parsed.explode())
		return err
	}
	if desc.port == -1 {
		switch strings.ToLower(desc.scheme) {
		case "ldap":
			desc.port = 389
		case "ldaps":
			desc.port = 636
		default:
			desc.port = 0
		}
	}
	output, ok := desc.construct()
	if !ok {
		return ldapURLToolError(stderr, false, "unable to generate URI")
	}
	_, err := fmt.Fprintln(stdout, output)
	return err
}

func ldapURLToolError(stderr io.Writer, usage bool, format string, args ...any) error {
	if _, err := fmt.Fprintf(stderr, format+"\n", args...); err != nil {
		return err
	}
	if usage {
		if _, err := io.WriteString(stderr, ldapURLToolUsage); err != nil {
			return err
		}
	}
	return &ldapClientExitError{code: 1}
}

func ldapURLToolScope(value string) string {
	switch strings.ToLower(value) {
	case "base":
		return "base"
	case "one", "onelevel":
		return "one"
	case "sub", "subtree":
		return "sub"
	case "subord", "subordinate", "children":
		return "subordinate"
	}
	return ""
}

func ldapURLToolList(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool { return r == ',' })
}

func ldapURLToolEscape(value string, extra byte) string {
	const hex = "0123456789ABCDEF"
	var output strings.Builder
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b != extra && (b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' ||
			b >= '0' && b <= '9' || strings.IndexByte(";:/@&=+$,-_.!~*'()", b) >= 0) {
			output.WriteByte(b)
		} else {
			output.WriteByte('%')
			output.WriteByte(hex[b>>4])
			output.WriteByte(hex[b&15])
		}
	}
	return output.String()
}

func (desc ldapURLToolDesc) construct() (string, bool) {
	if desc.port < 0 || desc.port > 65535 {
		return "", false
	}
	host := ldapURLToolEscape(desc.host, '/')
	// desc2str writes a raw host with a nonzero port, but sizes its buffer
	// for an escaped host. OpenLDAP rejects the resulting length mismatch.
	if desc.port != 0 && host != desc.host {
		return "", false
	}
	if desc.scheme != "ldapi" && strings.Count(desc.host, ":") >= 2 {
		host = "[" + host + "]"
	}
	var output strings.Builder
	output.WriteString(desc.scheme + "://" + host)
	if desc.port != 0 {
		fmt.Fprintf(&output, ":%d", desc.port)
	}
	fields := []string{
		ldapURLToolEscape(desc.base, 0),
		ldapURLToolEscape(strings.Join(desc.attrs, ","), 0),
		desc.scope,
		ldapURLToolEscape(desc.filter, 0),
	}
	last := -1
	switch {
	case desc.extensions != nil:
		last = 4
	case desc.filterSet:
		last = 3
	case desc.scope != "":
		last = 2
	case desc.attrs != nil:
		last = 1
	case desc.base != "":
		last = 0
	}
	if last == 4 {
		extensions := make([]string, len(desc.extensions))
		for i, extension := range desc.extensions {
			extensions[i] = ldapURLToolEscape(extension, ',')
		}
		fields = append(fields, strings.Join(extensions, ","))
	}
	if last >= 0 {
		output.WriteByte('/')
		output.WriteString(strings.Join(fields[:last+1], "?"))
	}
	return output.String(), true
}

// The reference clears a component on a malformed escape and exposes only the
// prefix before a decoded NUL. PathUnescape preserves literal '+' and bytes.
func ldapURLToolUnescape(value string) string {
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return ""
	}
	decoded, _, _ = strings.Cut(decoded, "\x00")
	return decoded
}

func parseLDAPURLTool(raw string) (ldapURLToolDesc, bool) {
	desc := ldapURLToolDesc{scope: "base"}
	enclosed := strings.HasPrefix(raw, "<")
	if enclosed {
		raw = raw[1:]
	}
	if len(raw) >= 4 && strings.EqualFold(raw[:4], "URL:") {
		raw = raw[4:]
	}
	scheme, remainder, ok := strings.Cut(raw, "://")
	desc.scheme = strings.ToLower(scheme)
	if !ok {
		return desc, false
	}
	switch desc.scheme {
	case "ldap", "ldaps", "ldapi", "pldap", "pldaps":
	default:
		return desc, false
	}
	if enclosed {
		if !strings.HasSuffix(remainder, ">") {
			return desc, false
		}
		remainder = strings.TrimSuffix(remainder, ">")
	}
	host, query, hasSlash := strings.Cut(remainder, "/")
	if !hasSlash {
		var suffix string
		host, suffix, _ = strings.Cut(host, "?")
		if desc.scheme == "ldapi" && strings.HasPrefix(suffix, "?") {
			desc.base = ldapURLToolUnescape(suffix[1:])
		}
	}
	if desc.scheme != "ldapi" {
		var port string
		var hasPort bool
		if strings.HasPrefix(host, "[") {
			var tail string
			host, tail, ok = strings.Cut(host[1:], "]")
			if !ok || strings.Contains(tail, ":") && !strings.HasPrefix(tail, ":") {
				return desc, false
			}
			port, hasPort = strings.CutPrefix(tail, ":")
		} else {
			host, port, hasPort = strings.Cut(host, ":")
		}
		if hasPort {
			port = strings.TrimLeft(ldapURLToolUnescape(port), " \t\r\n\v\f")
			value, err := strconv.ParseInt(port, 10, 64)
			if err != nil && !errors.Is(err, strconv.ErrRange) {
				return desc, false
			}
			if errors.Is(err, strconv.ErrRange) {
				// ParseInt can report overflow before seeing trailing garbage;
				// strtol still checks the end of the entire numeric token.
				for _, digit := range strings.TrimLeft(port, "+-") {
					if digit < '0' || digit > '9' {
						return desc, false
					}
				}
			}
			// ldap_url_parse assigns strtol's result to a C int without a
			// port-range check; keep that behavior local to this offline tool.
			desc.port = int(int32(value))
		}
		if desc.port == 0 {
			desc.port = 389
			if desc.scheme == "ldaps" {
				desc.port = 636
			}
		}
	}
	desc.host = ldapURLToolUnescape(host)
	if !hasSlash {
		return desc, true
	}
	fields := strings.SplitN(query, "?", 6)
	if len(fields) > 5 {
		return desc, false
	}
	desc.base = ldapURLToolUnescape(fields[0])
	if len(fields) > 1 && fields[1] != "" {
		// Attributes decode before splitting; extensions split before decoding.
		desc.attrs = ldapURLToolList(ldapURLToolUnescape(fields[1]))
	}
	if len(fields) > 2 && fields[2] != "" {
		desc.scope = ldapURLToolScope(ldapURLToolUnescape(fields[2]))
		if desc.scope == "" {
			return desc, false
		}
	}
	if len(fields) > 3 && fields[3] != "" {
		desc.filter = ldapURLToolUnescape(fields[3])
		if desc.filter == "" {
			return desc, false
		}
	}
	if len(fields) > 4 {
		desc.extensions = ldapURLToolList(fields[4])
		if len(desc.extensions) == 0 {
			return desc, false
		}
		for i := range desc.extensions {
			desc.extensions[i] = ldapURLToolUnescape(desc.extensions[i])
		}
	}
	return desc, true
}

func (desc ldapURLToolDesc) explode() string {
	var output strings.Builder
	fmt.Fprintf(&output, "scheme: %s\n", desc.scheme)
	if desc.host != "" {
		fmt.Fprintf(&output, "host: %s\n", desc.host)
	}
	if desc.port != 0 {
		fmt.Fprintf(&output, "port: %d\n", desc.port)
	}
	if desc.base != "" {
		fmt.Fprintf(&output, "dn: %s\n", desc.base)
	}
	for _, attr := range desc.attrs {
		fmt.Fprintf(&output, "selector: %s\n", attr)
	}
	fmt.Fprintf(&output, "scope: %s\n", desc.scope)
	if desc.filter != "" {
		fmt.Fprintf(&output, "filter: %s\n", desc.filter)
	}
	for _, extension := range desc.extensions {
		fmt.Fprintf(&output, "extension: %s\n", extension)
	}
	return output.String()
}
