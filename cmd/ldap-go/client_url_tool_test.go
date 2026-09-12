package main

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// Expected C-locale output from the pinned OpenLDAP ldapurl.c and Homebrew
// OpenLDAP 2.6.13. Keep this independent of the implementation's usage string.
const ldapURLToolWantUsage = "usage: ldapurl [options]\n\n" +
	"generates RFC 4516 LDAP URL with extensions\n\n" +
	"URL options:\n" +
	"  -a attrs   comma separated list of attributes\n" +
	"  -b base    (RFC 4514 LDAP DN)\n" +
	"  -E ext     (format: \"ext=value\"; multiple occurrences allowed)\n" +
	"  -f filter  (RFC 4515 LDAP filter)\n" +
	"  -h host    \n" +
	"  -p port    (default: 389 for ldap, 636 for ldaps)\n" +
	"  -s scope   (RFC 4511 searchScope and extensions)\n" +
	"  -S scheme  (RFC 4516 LDAP URL scheme and extensions)\n"

type ldapURLToolCase struct {
	name   string
	args   []string
	stdout string
	stderr string
	code   int
}

func ldapURLToolCases() []ldapURLToolCase {
	cases := []ldapURLToolCase{
		{name: "default construction", stdout: "ldap://:389\n"},
		{name: "host", args: []string{"-h", "directory.example"}, stdout: "ldap://directory.example:389\n"},
		{name: "attached flags", args: []string{"-Sldaps", "-h127.0.0.1", "-p1636", "-bdc=x", "-acn,sn", "-ssub", "-f(cn=*)", "-Ex=a"}, stdout: "ldaps://127.0.0.1:1636/dc=x?cn,sn?sub?(cn=*)?x=a\n"},
		{name: "attached equals is literal", args: []string{"-h=example"}, stdout: "ldap://=example:389\n"},
		{name: "empty host", args: []string{"-h", ""}, stdout: "ldap://:389\n"},
		{name: "IPv6", args: []string{"-h", "2001:db8::1"}, stdout: "ldap://[2001:db8::1]:389\n"},
		{name: "IPv6 without port", args: []string{"-h", "::1", "-p", "0"}, stdout: "ldap://[::1]\n"},
		{name: "host colon is literal", args: []string{"-h", "h:123"}, stdout: "ldap://h:123:389\n"},
		{name: "LDAPS default", args: []string{"-S", "ldaps"}, stdout: "ldaps://:636\n"},
		{name: "scheme case preserved", args: []string{"-S", "LDAPS"}, stdout: "LDAPS://:636\n"},
		{name: "LDAPI socket", args: []string{"-S", "ldapi", "-h", "/tmp/ldap socket", "-b", "dc=x"}, stdout: "ldapi://%2Ftmp%2Fldap%20socket/dc=x\n"},
		{name: "LDAPI colons", args: []string{"-S", "ldapi", "-h", "::1"}, stdout: "ldapi://::1\n"},
		{name: "uppercase LDAPI colons", args: []string{"-S", "LDAPI", "-h", "::1"}, stdout: "LDAPI://[::1]\n"},
		{name: "custom scheme", args: []string{"-S", "custom", "-h", "h"}, stdout: "custom://h\n"},
		{name: "empty scheme", args: []string{"-S", ""}, stdout: "://\n"},
		{name: "empty base", args: []string{"-b", ""}, stdout: "ldap://:389\n"},
		{name: "empty attrs", args: []string{"-a", ""}, stdout: "ldap://:389/?\n"},
		{name: "empty attr elements", args: []string{"-a", ",,,"}, stdout: "ldap://:389/?\n"},
		{name: "empty filter", args: []string{"-f", ""}, stdout: "ldap://:389/???\n"},
		{name: "empty extension", args: []string{"-E", ""}, stdout: "ldap://:389/????\n"},
		{name: "repeated extensions", args: []string{"-E", "x=1", "-E", "", "-E", "x=1"}, stdout: "ldap://:389/????x=1,,x=1\n"},
		{name: "attrs escaping", args: []string{"-a", " cn,,sn ,cn;lang-en,%2C,+,*"}, stdout: "ldap://:389/?%20cn,sn%20,cn;lang-en,%252C,+,*\n"},
		{name: "base escaping", args: []string{"-b", "cn=a \\#%?[]\"<>^`{|}\t\n;:/@&=+$,-_.!~*'()"}, stdout: "ldap://:389/cn=a%20%5C%23%25%3F%5B%5D%22%3C%3E%5E%60%7B%7C%7D%09%0A;:/@&=+$,-_.!~*'()\n"},
		{name: "extension escaping", args: []string{"-E", "!bindname=cn=a,dc=b", "-E", "x=/a+b?%#[]"}, stdout: "ldap://:389/????!bindname=cn=a%2Cdc=b,x=/a+b%3F%25%23%5B%5D\n"},
		{name: "all fields and UTF-8", args: []string{"-S", "ldaps", "-h", "2001:db8::1", "-b", "cn=J\u00f6rg + Doe,dc=example", "-a", "cn,,sn,*,+", "-s", "CHILDREN", "-f", "(&(cn=A?B)(path=/a,b))", "-E", "!bindname=cn=a,dc=b", "-E", "x=a?b%#"}, stdout: "ldaps://[2001:db8::1]:636/cn=J%C3%B6rg%20+%20Doe,dc=example?cn,sn,*,+?subordinate?(&(cn=A%3FB)(path=/a,b))?!bindname=cn=a%2Cdc=b,x=a%3Fb%25%23\n"},
		{name: "zero port", args: []string{"-p", "0"}, stdout: "ldap://\n"},
		{name: "minimum port", args: []string{"-p", "1"}, stdout: "ldap://:1\n"},
		{name: "maximum port", args: []string{"-p", "65535"}, stdout: "ldap://:65535\n"},
		{name: "signed padded port", args: []string{"-p", " \t+00389"}, stdout: "ldap://:389\n"},
		{name: "unset port sentinel", args: []string{"-S", "ldaps", "-p", "-1"}, stdout: "ldaps://:636\n"},
		{name: "sentinel allows replacement", args: []string{"-p", "-1", "-p", "1389"}, stdout: "ldap://:1389\n"},
		{name: "no port host escaping", args: []string{"-h", "a b/%", "-p", "0"}, stdout: "ldap://a%20b%2F%25\n"},
		{name: "operands ignored", args: []string{"operand", "-s", "bad"}, stdout: "ldap://:389\n"},
		{name: "option terminator", args: []string{"-h", "h", "--", "-H", "invalid"}, stdout: "ldap://h:389\n"},
		{name: "dash operand", args: []string{"-", "-s", "bad"}, stdout: "ldap://:389\n"},
		{name: "flag-like value", args: []string{"-f", "-H"}, stdout: "ldap://:389/???-H\n"},
		{name: "parse default", args: []string{"-H", "ldap://"}, stdout: "scheme: ldap\nport: 389\nscope: base\n"},
		{name: "parse LDAPS", args: []string{"-Hldaps://h"}, stdout: "scheme: ldaps\nhost: h\nport: 636\nscope: base\n"},
		{name: "parse enclosed", args: []string{"-H", "<URL:LDAPS://h/>"}, stdout: "scheme: ldaps\nhost: h\nport: 636\nscope: base\n"},
		{name: "parse URL prefix", args: []string{"-H", "uRl:LDAP://h"}, stdout: "scheme: ldap\nhost: h\nport: 389\nscope: base\n"},
		{name: "parse LDAPI", args: []string{"-H", "ldapi://%2Ftmp%2Fldapi"}, stdout: "scheme: ldapi\nhost: /tmp/ldapi\nscope: base\n"},
		{name: "parse empty LDAPI", args: []string{"-H", "ldapi:///"}, stdout: "scheme: ldapi\nscope: base\n"},
		{name: "parse proxy scheme", args: []string{"-H", "pldap://h"}, stdout: "scheme: pldap\nhost: h\nport: 389\nscope: base\n"},
		{name: "parse proxy TLS default", args: []string{"-H", "pldaps://h"}, stdout: "scheme: pldaps\nhost: h\nport: 389\nscope: base\n"},
		{name: "parse all fields", args: []string{"-H", "LDAP://[::1]:0/cn=a+b?cn%2Csn,,mail?children?(cn=a+b)?!bindname=cn%3Da%2Cdc%3Db,x=test%3F"}, stdout: "scheme: ldap\nhost: ::1\nport: 389\ndn: cn=a+b\nselector: cn\nselector: sn\nselector: mail\nscope: subordinate\nfilter: (cn=a+b)\nextension: !bindname=cn=a,dc=b\nextension: x=test?\n"},
		{name: "parse empty query fields", args: []string{"-H", "ldap://h/???"}, stdout: "scheme: ldap\nhost: h\nport: 389\nscope: base\n"},
		{name: "parse UTF-8 and plus", args: []string{"-H", "ldap://h/cn=%C3%B6+%2B%20x"}, stdout: "scheme: ldap\nhost: h\nport: 389\ndn: cn=\u00f6++ x\nscope: base\n"},
		{name: "parse raw slash and fragment", args: []string{"-H", "ldap://h/cn=a/b#c"}, stdout: "scheme: ldap\nhost: h\nport: 389\ndn: cn=a/b#c\nscope: base\n"},
		{name: "parse does not validate LDAP syntax", args: []string{"-H", "ldap://h/invalid DN?bad attr,+?onelevel?not a filter?!not-an-oid"}, stdout: "scheme: ldap\nhost: h\nport: 389\ndn: invalid DN\nselector: bad attr\nselector: +\nscope: one\nfilter: not a filter\nextension: !not-an-oid\n"},
		{name: "parse extension splitting", args: []string{"-H", "ldap://h/????,x=a%2Cb,,x=a+b,"}, stdout: "scheme: ldap\nhost: h\nport: 389\nscope: base\nextension: x=a,b\nextension: x=a+b\n"},
		{name: "parse encoded port", args: []string{"-H", "ldap://h:%20%09%2B00389/"}, stdout: "scheme: ldap\nhost: h\nport: 389\nscope: base\n"},
		{name: "parse zero TLS port", args: []string{"-H", "ldaps://h:0"}, stdout: "scheme: ldaps\nhost: h\nport: 636\nscope: base\n"},
		{name: "parse negative port", args: []string{"-H", "ldap://h:-2"}, stdout: "scheme: ldap\nhost: h\nport: -2\nscope: base\n"},
		{name: "parse port above TCP range", args: []string{"-H", "ldap://h:65536"}, stdout: "scheme: ldap\nhost: h\nport: 65536\nscope: base\n"},
		{name: "parse C int conversion", args: []string{"-H", "ldap://h:2147483648"}, stdout: "scheme: ldap\nhost: h\nport: -2147483648\nscope: base\n"},
		{name: "parse C long overflow", args: []string{"-H", "ldap://h:9223372036854775808"}, stdout: "scheme: ldap\nhost: h\nport: -1\nscope: base\n"},
		{name: "parse question without slash", args: []string{"-H", "ldap://h:389??cn=abc,o=company"}, stdout: "scheme: ldap\nhost: h\nport: 389\nscope: base\n"},
		{name: "parse malformed host escape", args: []string{"-H", "ldap://%ZZ/dc=x"}, stdout: "scheme: ldap\nport: 389\ndn: dc=x\nscope: base\n"},
		{name: "parse malformed base escape", args: []string{"-H", "ldap://h/cn=x%ZZ"}, stdout: "scheme: ldap\nhost: h\nport: 389\nscope: base\n"},
		{name: "parse truncated escape", args: []string{"-H", "ldap://h/%"}, stdout: "scheme: ldap\nhost: h\nport: 389\nscope: base\n"},
		{name: "parse NUL truncation", args: []string{"-H", "ldap://h/cn=x%00ignored"}, stdout: "scheme: ldap\nhost: h\nport: 389\ndn: cn=x\nscope: base\n"},
		{name: "parse malformed attrs", args: []string{"-H", "ldap://h/?cn,%ZZ"}, stdout: "scheme: ldap\nhost: h\nport: 389\nscope: base\n"},
		{name: "parse malformed extensions", args: []string{"-H", "ldap://h/????%00x,x=%ZZ"}, stdout: "scheme: ldap\nhost: h\nport: 389\nscope: base\nextension: \nextension: \n"},
	}
	for _, scope := range []struct{ input, output string }{
		{"base", "base"}, {"one", "one"}, {"ONELEVEL", "one"},
		{"sub", "sub"}, {"SubTree", "sub"}, {"subord", "subordinate"},
		{"subordinate", "subordinate"}, {"CHILDREN", "subordinate"},
	} {
		cases = append(cases,
			ldapURLToolCase{name: "construct scope " + scope.input, args: []string{"-s", scope.input}, stdout: "ldap://:389/??" + scope.output + "\n"},
			ldapURLToolCase{name: "parse scope " + scope.input, args: []string{"-H", "ldap:///??" + scope.input}, stdout: "scheme: ldap\nport: 389\nscope: " + scope.output + "\n"},
		)
	}
	for _, option := range []struct{ flag, value, label string }{
		{"-S", "ldap", "scheme"}, {"-h", "h", "host"}, {"-p", "0", "port"},
		{"-b", "", "base"}, {"-a", "", "attrs"}, {"-s", "base", "scope"},
		{"-f", "", "filter"}, {"-H", "", "URI"}, {"-E", "", "extensions"},
	} {
		cases = append(cases, ldapURLToolCase{
			name: "missing argument " + option.flag, args: []string{option.flag}, code: 1,
			stderr: "ldapurl: option requires an argument -- " + option.flag[1:] + "\n" + ldapURLToolWantUsage,
		})
		if option.flag != "-E" {
			cases = append(cases, ldapURLToolCase{
				name: "duplicate " + option.flag, args: []string{option.flag, option.value, option.flag, option.value}, code: 1,
				stderr: option.label + " already provided\n" + ldapURLToolWantUsage,
			})
		}
		if option.flag != "-H" {
			cases = append(cases,
				ldapURLToolCase{name: "H before " + option.flag, args: []string{"-H", "ldap://h", option.flag, option.value}, code: 1, stderr: "option " + option.flag + " incompatible with -H\n" + ldapURLToolWantUsage},
				ldapURLToolCase{name: "H after " + option.flag, args: []string{option.flag, option.value, "-H", "ldap://h"}, code: 1, stderr: "option -H incompatible with previous options\n" + ldapURLToolWantUsage},
			)
		}
	}
	for _, option := range []string{"-x", "-V", "-d", "-e", "-o", "-Z", "-?", "--help"} {
		cases = append(cases, ldapURLToolCase{name: "unsupported " + option, args: []string{option}, code: 1, stderr: "ldapurl: illegal option -- " + option[1:2] + "\n" + ldapURLToolWantUsage})
	}
	for _, port := range []string{"", " ", "389 ", "1x", "0x185", "2147483648", "-2147483649"} {
		cases = append(cases, ldapURLToolCase{name: "invalid port " + port, args: []string{"-p", port}, code: 1, stderr: "unable to parse port \"" + port + "\"\n" + ldapURLToolWantUsage})
	}
	for _, scope := range []string{"", "default", "bad", "base "} {
		cases = append(cases, ldapURLToolCase{name: "invalid scope " + scope, args: []string{"-s", scope}, code: 1, stderr: "unable to parse scope \"" + scope + "\"\n" + ldapURLToolWantUsage})
	}
	for _, args := range [][]string{{"-p", "-2"}, {"-p", "65536"}, {"-h", "[::1]"}, {"-h", "a b"}, {"-h", "/tmp/a"}} {
		cases = append(cases, ldapURLToolCase{name: "generation failure " + strings.Join(args, " "), args: args, code: 1, stderr: "unable to generate URI\n"})
	}
	for _, uri := range []string{
		"", "http://h", "cldap://h", "ldap:/h", "<ldap://h", "ldap://[::1", "ldap://[::1]junk:389",
		"ldap://h:", "ldap://h:389x", "ldap://h:389%20", "ldap://h:%ZZ", "ldap://::1",
		"ldap://h:999999999999999999999x",
		"ldap://h/??invalid", "ldap://h/??%ZZ", "ldap://h/???%ZZ", "ldap://h/???%00x",
		"ldap://h/????", "ldap://h/????,,,", "ldap://h/????x=1?extra",
	} {
		cases = append(cases, ldapURLToolCase{name: "parse failure " + uri, args: []string{"-H", uri}, code: 1, stderr: "unable to parse URI \"" + uri + "\"\n"})
	}
	return cases
}

func TestLDAPURLTool(t *testing.T) {
	for _, test := range ldapURLToolCases() {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, code := runLDAPClientCommand(append([]string{"ldapurl"}, test.args...), "")
			if stdout != test.stdout || stderr != test.stderr || code != test.code {
				t.Fatalf("args=%q\ngot  exit=%d stdout=%q stderr=%q\nwant exit=%d stdout=%q stderr=%q", test.args, code, stdout, stderr, test.code, test.stdout, test.stderr)
			}
		})
	}
}

type ldapURLToolFailWriter struct{ err error }

func (w ldapURLToolFailWriter) Write([]byte) (int, error) { return 0, w.err }

func TestLDAPURLToolWriterErrors(t *testing.T) {
	failure := errors.New("write failed")
	for _, args := range [][]string{nil, {"-H", "ldap://h"}, {"-s", "bad"}} {
		if err := runLDAPURL(args, ldapURLToolFailWriter{failure}, ldapURLToolFailWriter{failure}); !errors.Is(err, failure) {
			t.Fatalf("args=%q error=%v", args, err)
		}
	}
}

func TestLDAPURLToolLimits(t *testing.T) {
	maxBase := strings.Repeat("a", maxLDAPURLToolInputBytes-len("-b"))
	maxArgs := make([]string, maxLDAPURLToolArgs)
	maxArgs[0] = "--"
	maxExtensions := make([]string, maxLDAPURLToolExtensions)
	for i := range maxExtensions {
		maxExtensions[i] = "-Ex=a"
	}
	for _, test := range []ldapURLToolCase{
		{name: "bytes at limit", args: []string{"-b", maxBase}, stdout: "ldap://:389/" + maxBase + "\n"},
		{name: "bytes above limit", args: []string{"-b", maxBase + "a"}, code: 1, stderr: "ldapurl: total input exceeds 65536 bytes\n"},
		{name: "bytes include ignored operands", args: []string{"--", maxBase, "a"}, code: 1, stderr: "ldapurl: total input exceeds 65536 bytes\n"},
		{name: "args at limit", args: maxArgs, stdout: "ldap://:389\n"},
		{name: "args above limit", args: append(append([]string(nil), maxArgs...), ""), code: 1, stderr: "ldapurl: at most 256 arguments are supported\n"},
		{name: "extensions at limit", args: maxExtensions, stdout: "ldap://:389/????" + strings.TrimSuffix(strings.Repeat("x=a,", maxLDAPURLToolExtensions), ",") + "\n"},
		{name: "extensions above limit", args: append(append([]string(nil), maxExtensions...), "-E", "x=b"), code: 1, stderr: "ldapurl: at most 64 extensions are supported\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, code := runLDAPClientCommand(append([]string{"ldapurl"}, test.args...), "")
			if stdout != test.stdout || stderr != test.stderr || code != test.code {
				t.Fatalf("exit=%d stdout bytes=%d stderr=%q; want exit=%d stdout bytes=%d stderr=%q", code, len(stdout), stderr, test.code, len(test.stdout), test.stderr)
			}
		})
	}
}

func TestLDAPURLToolRejectsRawNUL(t *testing.T) {
	for _, args := range [][]string{
		{"-H", "ldap://h/cn=a\x00ignored"}, {"-Hldap://h\x00"},
		{"-S", "ldap\x00"}, {"-h", "h\x00"}, {"-p", "389\x00"},
		{"-b", "cn=a\x00"}, {"-a", "cn\x00,sn"}, {"-s", "base\x00"},
		{"-f", "(cn=a)\x00"}, {"-E", "x=a\x00"}, {"-E!x=\x00"},
		{"--", "\x00"}, {"\x00"}, {"operand", "\x00"},
	} {
		stdout, stderr, code := runLDAPClientCommand(append([]string{"ldapurl"}, args...), "")
		if code != 1 || stdout != "" || stderr != "ldapurl: arguments must not contain NUL bytes\n" {
			t.Fatalf("args=%q exit=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
}

func TestLDAPURLToolParsedExtensionLimit(t *testing.T) {
	for _, count := range []int{maxLDAPURLToolExtensions, maxLDAPURLToolExtensions + 1} {
		uri := "ldap://h/????" + strings.TrimSuffix(strings.Repeat("x=a,", count), ",")
		stdout, stderr, code := runLDAPClientCommand([]string{"ldapurl", "-H", uri}, "")
		if count == maxLDAPURLToolExtensions {
			if code != 0 || stderr != "" || strings.Count(stdout, "extension: x=a\n") != count {
				t.Fatalf("limit boundary: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		} else if code != 1 || stdout != "" || stderr != "ldapurl: at most 64 extensions are supported\n" {
			t.Fatalf("over limit: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	}
}

func TestLDAPURLToolDispatchAndHelp(t *testing.T) {
	var stdout, stderr strings.Builder
	// No configuration, credentials, stdin, LDAP server, or external tool is used.
	code := run([]string{"ldapurl"}, nil, &stdout, &stderr, func(string) string {
		t.Fatal("ldapurl read an environment setting")
		return ""
	})
	if code != 0 || stdout.String() != "ldap://:389\n" || stderr.Len() != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := run([]string{"help"}, nil, &stdout, io.Discard, nil); code != 0 ||
		!strings.Contains(stdout.String(), "ldapurl  construct an LDAP URL or parse one with -H (offline)") {
		t.Fatalf("help exit=%d stdout=%q", code, stdout.String())
	}
}
