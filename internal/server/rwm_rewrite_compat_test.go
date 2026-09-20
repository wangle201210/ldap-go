package server

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type rwmRewriteCompatibilityCase struct {
	name       string
	directives [][]string
	input      string
	want       string
	code       ldapwire.ResultCode
}

func rwmRewriteCompatibilityCases() []rwmRewriteCompatibilityCase {
	longestCapture, nestedCapture := "aa/", "aa/aa/"
	absentRepeated, absentAlternative, evenRepeated := "b/", "b//b", "aa/"
	if runtime.GOOS == "linux" {
		// Verified against glibc's regexec; BSD chooses different submatches.
		longestCapture, nestedCapture = "a/a", "aa/a/"
		absentRepeated, absentAlternative, evenRepeated = "b/a", "b/a/b", "a/"
	}
	rule := func(pattern, substitution, flags string) []string {
		return []string{"rewriteRule", pattern, substitution, flags}
	}
	return []rwmRewriteCompatibilityCase{
		{name: "longest whole match", directives: [][]string{rule(`a|aa`, `$0`, ":")}, input: "zaaz", want: "aa"},
		{name: "longest capture", directives: [][]string{rule(`^(a|aa)(a?)$`, `$1/$2`, ":")}, input: "aa", want: longestCapture},
		{name: "nested capture", directives: [][]string{rule(`^((a|aa)*)(a?)$`, `$1/$2/$3`, ":")}, input: "aa", want: nestedCapture},
		{name: "repeated nested capture reset", directives: [][]string{rule(`^((a)?b)*$`, `$1/$2`, ":C")}, input: "abb", want: absentRepeated},
		{name: "repeated alternative capture reset", directives: [][]string{rule(`^((a)|(b))*$`, `$1/$2/$3`, ":C")}, input: "ab", want: absentAlternative},
		{name: "uncaptured final alternative reset", directives: [][]string{rule(`^((a)|b)*$`, `$1/$2`, ":C")}, input: "ab", want: absentRepeated},
		{name: "odd capture iteration priority", directives: [][]string{rule(`^(a|aa)*(a?)$`, `$1/$2`, ":C")}, input: "aaa", want: "a/"},
		{name: "even capture iteration priority", directives: [][]string{rule(`^(a|aa)*(a?)$`, `$1/$2`, ":C")}, input: "aaaa", want: evenRepeated},
		{name: "optional absent capture", directives: [][]string{rule(`^(a)?(b)$`, `$1:$2:$9`, ":")}, input: "b", want: ":b:"},
		{name: "whole match and percent", directives: [][]string{rule(`^(a)(b)$`, `%0:$2:%1`, ":")}, input: "ab", want: "ab:b:a"},
		{name: "mixed escapes", directives: [][]string{rule(`.*`, `$$:%%:$%:%$`, ":")}, input: "a", want: "$:%:%:$"},
		{name: "capture ten is one then zero", directives: [][]string{rule(`(a)`, `$10`, ":")}, input: "a", want: "a0"},
		{name: "case insensitive", directives: [][]string{rule(`^(ab)$`, `$1x`, ":")}, input: "AB", want: "ABx"},
		{name: "case sensitive", directives: [][]string{rule(`^ab$`, `x`, ":C")}, input: "AB", want: "AB"},
		{name: "empty substitution", directives: [][]string{rule(`.*`, ``, ":")}, input: "a", want: ""},
		{name: "engine off", directives: [][]string{rule(`.*`, `x`, ":"), {"rewriteEngine", "off"}}, input: "a", want: "a"},
		{name: "recursive", directives: [][]string{rule(`^x(.*)$`, `$1`, "")}, input: "xxxend", want: "end"},
		{name: "stop after recursion", directives: [][]string{rule(`^x(.*)$`, `$1`, "@"), rule(`.*`, `wrong`, ":")}, input: "xxxend", want: "end"},
		{name: "per rule limit", directives: [][]string{{"rewriteMaxPasses", "8", "2"}, rule(`^x(.*)$`, `$1`, "")}, input: "xxxend", want: "xend"},
		{name: "hex rule limit", directives: [][]string{rule(`^x(.*)$`, `$1`, "M{0x2}")}, input: "xxxend", want: "xend"},
		{name: "operation counts context advance", directives: [][]string{{"rewriteMaxPasses", "2"}, rule(`^a$`, `b`, ":"), rule(`^b$`, `c`, ":")}, input: "a", want: "b"},
		{name: "operation counts nonmatch", directives: [][]string{{"rewriteMaxPasses", "2"}, rule(`^x$`, `b`, ":"), rule(`^a$`, `c`, ":")}, input: "a", want: "a"},
		{name: "goto skips", directives: [][]string{rule(`^a$`, `b`, ":G{2}"), rule(`.*`, `wrong`, ":"), rule(`^b$`, `c`, ":")}, input: "a", want: "c"},
		{name: "goto end", directives: [][]string{rule(`.*`, `b`, ":G{1}")}, input: "a", want: "b"},
		{name: "goto too far", directives: [][]string{rule(`.*`, `b`, ":G{2}")}, input: "a", code: ldapwire.ResultOther},
		{name: "goto self bounded", directives: [][]string{{"rewriteMaxPasses", "6"}, rule(`^(.*)$`, `$1x`, ":G{0}")}, input: "a", want: "axxx"},
		{name: "goto back bounded", directives: [][]string{{"rewriteMaxPasses", "6"}, rule(`^(.*)$`, `$1x`, ":"), rule(`^(.*)$`, `$1y`, ":G{-1}")}, input: "a", want: "axyx"},
		{name: "ordered stop before reject", directives: [][]string{rule(`.*`, `b`, "@#")}, input: "a", want: "b"},
		{name: "ordered reject before stop", directives: [][]string{rule(`.*`, `b`, "#@")}, input: "a", code: ldapwire.ResultUnwillingToPerform},
		{name: "user result", directives: [][]string{rule(`.*`, `$0`, ":U{0x33}")}, input: "a", code: ldapwire.ResultBusy},
		{name: "ignore does not stop", directives: [][]string{rule(`.*`, `${*missing}`, ":I@#U{51}"), rule(`.*`, `b`, ":")}, input: "a", want: "b"},
		{name: "goto before ignore", directives: [][]string{rule(`.*`, `${*missing}`, ":G{2}I"), rule(`.*`, `b`, ":@"), rule(`.*`, `wrong`, ":")}, input: "a", want: "b"},
		{name: "goto after ignore", directives: [][]string{rule(`.*`, `${*missing}`, ":IG{2}"), rule(`.*`, `wrong`, ":"), rule(`.*`, `b`, ":")}, input: "a", want: "b"},
		{name: "multiple gotos", directives: [][]string{rule(`.*`, `b`, ":G{2}G{2}"), rule(`.*`, `wrong`, ":"), rule(`.*`, `wrong`, ":"), rule(`.*`, `c`, ":")}, input: "a", want: "c"},
		{name: "store and substitute", directives: [][]string{rule(`^(.*)$`, `${&*value($1)}:${*VALUE}`, ":")}, input: "a", want: "a:a"},
		{name: "empty subcontext", directives: [][]string{{"rewriteContext", "empty"}, {"rewriteContext", "default"}, rule(`.*`, `a${>empty(x)}b`, ":")}, input: "x", want: "ab"},
		{name: "nonmatching subcontext", directives: [][]string{{"rewriteContext", "sub"}, rule(`^z$`, `x`, ":"), {"rewriteContext", "default"}, rule(`.*`, `a${>sub(x)}b`, ":")}, input: "x", want: "axb"},
		{name: "subcontext rejection is expansion error", directives: [][]string{{"rewriteContext", "sub"}, rule(`.*`, ``, "#"), {"rewriteContext", "default"}, rule(`.*`, `${>sub(x)}`, ":")}, input: "x", code: ldapwire.ResultOther},
		{name: "subcontext rejection ignored", directives: [][]string{{"rewriteContext", "sub"}, rule(`.*`, ``, "#"), {"rewriteContext", "default"}, rule(`.*`, `${>sub(x)}`, ":I"), rule(`.*`, `b`, ":")}, input: "x", want: "b"},
		{name: "shared subcontext budget", directives: [][]string{{"rewriteMaxPasses", "1"}, {"rewriteContext", "sub"}, rule(`.*`, `wrong`, ":"), {"rewriteContext", "default"}, rule(`.*`, `a${>sub(x)}b`, ":")}, input: "x", want: "ab"},
	}
}

func TestRWMRewriteCompatibility(t *testing.T) {
	for _, test := range rwmRewriteCompatibilityCases() {
		t.Run(test.name, func(t *testing.T) {
			engine := mustRWMRewriteEngine(t, append([][]string{{"rewriteEngine", "on"}}, test.directives...)...)
			got, _, err := engine.rewrite("default", test.input)
			if test.code != 0 {
				failure := asOperationFailure(err)
				if failure == nil || failure.result.Code != test.code {
					t.Fatalf("rewrite error = %v, want %d", err, test.code)
				}
			} else if err != nil || got != test.want {
				t.Fatalf("rewrite = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestOpenLDAPReferenceRWMRewrite(t *testing.T) {
	path := os.Getenv("LDAP_GO_OPENLDAP_REWRITE")
	if path == "" {
		if os.Getenv(openLDAPReferenceTestsEnv) != "1" || os.Getenv("OPENLDAP_BUILD") == "" {
			t.Skip("set LDAP_GO_OPENLDAP_REWRITE to the OpenLDAP 2.6.13 rewrite executable")
		}
		path = filepath.Join(os.Getenv("OPENLDAP_BUILD"), "libraries", "librewrite", "rewrite")
	}
	for _, test := range rwmRewriteCompatibilityCases() {
		t.Run(test.name, func(t *testing.T) {
			var configuration strings.Builder
			configuration.WriteString("rewriteEngine on\n")
			for _, directive := range test.directives {
				for index, word := range directive {
					if index > 0 {
						configuration.WriteByte(' ')
					}
					fmt.Fprintf(&configuration, "\"%s\"", word)
				}
				configuration.WriteByte('\n')
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, path, test.input)
			command.Stdin = strings.NewReader(configuration.String())
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("reference rewrite: %v\n%s", err, output)
			}
			want := fmt.Sprintf(" -> %s [0:ok]\n", test.want)
			switch test.code {
			case ldapwire.ResultOther:
				want = " -> (null) [-1:error]\n"
			case ldapwire.ResultUnwillingToPerform:
				want = " -> (null) [-3:unwilling to perform]\n"
			case ldapwire.ResultBusy:
				want = " [51:user-defined]\n"
			}
			if test.name == "engine off" {
				want = " -> (null) [0:ok]\n"
			}
			if test.name == "operation counts nonmatch" {
				want = " -> (null) [0:ok]\n"
			}
			if !strings.HasSuffix(string(output), want) {
				t.Fatalf("reference output = %s; want suffix %q", output, want)
			}
		})
	}
}

func TestOpenLDAPReferenceRWMRewriteRelay(t *testing.T) {
	tools := requireOpenLDAPRelayReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)
	configuration := "overlay sssvlv\ndatabase relay\nsuffix dc=virtual,dc=test\nrelay dc=example,dc=com\noverlay rwm\n"
	for _, value := range rwmRewriteOverlayDirectives("dc=virtual,dc=test", "dc=example,dc=com") {
		directive, err := stripRWMOrderingPrefix(value)
		if err != nil {
			t.Fatal(err)
		}
		configuration += "rwm-" + directive + "\n"
	}
	configuration += "rwm-map objectClass groupOfNames groupOfUniqueNames\nrwm-map attribute member uniqueMember\n"
	uri, stop := startOpenLDAPReferenceServerWithConfig(t, tools, nil, "", configuration, `
dn: ou=groups,dc=example,dc=com
objectClass: organizationalUnit
ou: groups

dn: cn=staff,ou=groups,dc=example,dc=com
objectClass: groupOfUniqueNames
cn: staff
uniqueMember: uid=alice,ou=people,dc=example,dc=com
`)
	defer stop()
	fixture := startRWMRewriteFixture(t, "relay", false)
	want := runRelayReferenceScenario(t, uri)
	got := runRelayReferenceScenario(t, "ldap://"+fixture.address)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DSL relay = %#v; OpenLDAP = %#v", got, want)
	}
}
