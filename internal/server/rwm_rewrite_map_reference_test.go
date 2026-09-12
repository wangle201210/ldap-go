package server

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func rwmRewriteMapReferenceCLI(t *testing.T) string {
	t.Helper()
	path := os.Getenv("LDAP_GO_OPENLDAP_REWRITE")
	if path == "" {
		if os.Getenv(openLDAPReferenceTestsEnv) != "1" || os.Getenv("OPENLDAP_BUILD") == "" {
			t.Skip("set LDAP_GO_OPENLDAP_REWRITE to the pinned OpenLDAP 2.6.13 rewrite CLI")
		}
		path = filepath.Join(os.Getenv("OPENLDAP_BUILD"), "libraries", "librewrite", "rewrite")
	}
	return path
}

func runRWMRewriteMapReference(t *testing.T, path string, directives [][]string, input string) (string, error) {
	t.Helper()
	var configuration strings.Builder
	for _, words := range directives {
		for index, word := range words {
			if index > 0 {
				configuration.WriteByte(' ')
			}
			// The CLI's rewrite_read strips outer quotes but preserves escapes.
			fmt.Fprintf(&configuration, "\"%s\"", word)
		}
		configuration.WriteByte('\n')
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, "--", input)
	command.Env = append(os.Environ(), "LC_ALL=C")
	command.Stdin = strings.NewReader(configuration.String())
	output, err := command.CombinedOutput()
	return string(output), err
}

func TestOpenLDAPReferenceRWMRewriteMapSubstitution(t *testing.T) {
	path := rwmRewriteMapReferenceCLI(t)
	for _, test := range rwmRewriteMapSubstitutionCases() {
		t.Run(test.name, func(t *testing.T) {
			output, err := runRWMRewriteMapReference(t, path, rwmRewriteMapSubstitutionDirectives(test), "a*b")
			want := fmt.Sprintf(" -> %s [0:ok]\n", test.want)
			if test.fails {
				want = " -> (null) [-1:error]\n"
			}
			if err != nil || !strings.HasSuffix(output, want) {
				t.Fatalf("reference = %q, %v; want suffix %q", output, err, want)
			}
		})
	}
}

func rwmRewriteMapBindingCases() []struct {
	name       string
	directives [][]string
	reject     bool
} {
	definition := []string{"rewriteMap", "escape", "m", "escape2filter"}
	rule := []string{"rewriteRule", ".*", "${m($0)}", ":"}
	return []struct {
		name       string
		directives [][]string
		reject     bool
	}{
		{name: "defined before use", directives: [][]string{definition, rule}},
		{name: "case insensitive names and type", directives: [][]string{{"rewriteMap", "EsCaPe", "M", "Escape2Filter"}, rule}},
		{name: "forward reference", directives: [][]string{rule, definition}, reject: true},
		{name: "nested forward reference", directives: [][]string{definition, {"rewriteRule", ".*", "${m(${later($0)})}", ":"}, {"rewriteMap", "escape", "later", "escape2dn"}}, reject: true},
		{name: "duplicate", directives: [][]string{definition, definition}, reject: true},
		{name: "redefinition after binding", directives: [][]string{definition, rule, {"rewriteMap", "escape", "m", "escape2dn"}}, reject: true},
		{name: "case insensitive duplicate", directives: [][]string{definition, {"rewriteMap", "escape", "M", "escape2dn"}}, reject: true},
		{name: "unknown mapper", directives: [][]string{{"rewriteMap", "toupper", "m"}}, reject: true},
	}
}

func TestRWMRewriteMapBinding(t *testing.T) {
	for _, test := range rwmRewriteMapBindingCases() {
		t.Run(test.name, func(t *testing.T) {
			engine := mustRWMRewriteEngine(t, []string{"rewriteEngine", "on"})
			var err error
			for _, words := range test.directives {
				if err = engine.parseDirective(words); err != nil {
					break
				}
			}
			if (err != nil) != test.reject {
				t.Fatalf("parse = %v; want reject=%v", err, test.reject)
			}
			if !test.reject || test.name == "redefinition after binding" {
				if output, _, err := engine.rewrite("default", "*"); err != nil || output != `\2A` {
					t.Fatalf("bound map = %q, %v", output, err)
				}
			}
		})
	}
}

func TestOpenLDAPReferenceRWMRewriteMapBinding(t *testing.T) {
	path := rwmRewriteMapReferenceCLI(t)
	for _, test := range rwmRewriteMapBindingCases() {
		t.Run(test.name, func(t *testing.T) {
			directives := append([][]string{{"rewriteEngine", "on"}}, test.directives...)
			output, err := runRWMRewriteMapReference(t, path, directives, "*")
			if (err != nil) != test.reject {
				t.Fatalf("reference = %q, %v; want reject=%v", output, err, test.reject)
			}
			if !test.reject && !strings.HasSuffix(output, " -> \\2A [0:ok]\n") {
				t.Fatalf("reference = %q", output)
			}
		})
	}
}

func TestOpenLDAPReferenceRWMRewriteMapDNBytes(t *testing.T) {
	path := rwmRewriteMapReferenceCLI(t)
	inputs := []string{`a\\ `, `a\\  `, `a\  `, `\20 `, `,cn=x`, `+cn=x`, `a,cn=`, `a,cn=#`, `a,cn=#,dc=x`, `a,cn;=x`, `a,1=x`, `a,1.=x`, "a,cn=x, ", "a,#=x", "a,cn=\"x\""}
	for c := 1; c <= 255; c++ {
		inputs = append(inputs, "a"+string(byte(c))+"b", "a\\"+string(byte(c))+"b")
	}
	for index, input := range inputs {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			directives := rwmRewriteMapDirectives(rwmRewriteMapCase{operations: "unescapedn"})
			engine := mustRWMRewriteEngine(t, directives...)
			got, _, goErr := engine.rewrite("default", input)
			output, err := runRWMRewriteMapReference(t, path, directives, input)
			want := fmt.Sprintf(" -> %s [0:ok]\n", got)
			if goErr != nil {
				want = " -> (null) [-1:error]\n"
			}
			if err != nil || !strings.HasSuffix(output, want) {
				t.Fatalf("input=%q Go=%q,%v reference=%q,%v", input, got, goErr, output, err)
			}
		})
	}
}
