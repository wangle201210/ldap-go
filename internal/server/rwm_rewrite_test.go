package server

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestRWMRewriteEngineCommonDSL(t *testing.T) {
	engine := mustRWMRewriteEngine(t,
		[]string{"rewriteEngine", "on"},
		[]string{"rewriteContext", "trim"},
		[]string{"rewriteRule", `(.*),[ ](.*)`, `$1,$2`, ""},
		[]string{"rewriteContext", "default"},
		[]string{"rewriteRule", `^uid=([^,]+),(.*)$`, `${&user($1)}cn=$1,$2`, ":"},
		[]string{"rewriteRule", `^cn=([^,]+),(.*)$`, `cn=${*user},${>trim($2)}`, ":@"},
	)
	got, changed, err := engine.rewrite("bindDN", "uid=Alice,ou=People, dc=example, dc=com")
	if err != nil {
		t.Fatalf("rewrite common DSL: %v", err)
	}
	if !changed || got != "cn=Alice,ou=People,dc=example,dc=com" {
		t.Fatalf("rewrite common DSL = %q, %v", got, changed)
	}
}

func TestRWMRewriteContextAliasParameterAndCaseFlags(t *testing.T) {
	engine := mustRWMRewriteEngine(t,
		[]string{"rewriteEngine", "on"},
		[]string{"rewriteParam", "suffix", "dc=remote,dc=test"},
		[]string{"rewriteContext", "default"},
		[]string{"rewriteRule", `^(.*),dc=LOCAL,dc=TEST$`, `$1,${$suffix}`, ":"},
		[]string{"rewriteContext", "searchDN", "alias", "default"},
	)
	got, changed, err := engine.rewrite("searchDN", "uid=alice,dc=local,dc=test")
	if err != nil || !changed || got != "uid=alice,dc=remote,dc=test" {
		t.Fatalf("aliased rewrite = %q, %v, %v", got, changed, err)
	}

	caseSensitive := mustRWMRewriteEngine(t,
		[]string{"rewriteEngine", "on"},
		[]string{"rewriteRule", `^UID=(.*)$`, `cn=$1`, ":C"},
	)
	got, changed, err = caseSensitive.rewrite("default", "uid=alice")
	if err != nil || changed || got != "uid=alice" {
		t.Fatalf("case-sensitive non-match = %q, %v, %v", got, changed, err)
	}
}

func TestRWMRewriteRuleControlFlow(t *testing.T) {
	t.Run("recursive and bounded", func(t *testing.T) {
		engine := mustRWMRewriteEngine(t,
			[]string{"rewriteEngine", "on"},
			[]string{"rewriteMaxPasses", "6", "4"},
			[]string{"rewriteRule", `^x(.*)$`, `$1`, "M{3}"},
		)
		got, changed, err := engine.rewrite("default", "xxxxvalue")
		if err != nil || !changed || got != "xvalue" {
			t.Fatalf("bounded recursive rewrite = %q, %v, %v", got, changed, err)
		}
	})

	t.Run("stop", func(t *testing.T) {
		engine := mustRWMRewriteEngine(t,
			[]string{"rewriteEngine", "on"},
			[]string{"rewriteRule", `^a$`, `b`, ":@"},
			[]string{"rewriteRule", `^b$`, `c`, ":"},
		)
		got, _, err := engine.rewrite("default", "a")
		if err != nil || got != "b" {
			t.Fatalf("stop rewrite = %q, %v", got, err)
		}
	})

	t.Run("goto", func(t *testing.T) {
		engine := mustRWMRewriteEngine(t,
			[]string{"rewriteEngine", "on"},
			[]string{"rewriteRule", `^a$`, `b`, ":G{2}"},
			[]string{"rewriteRule", `^b$`, `wrong`, ":"},
			[]string{"rewriteRule", `^b$`, `c`, ":"},
		)
		got, _, err := engine.rewrite("default", "a")
		if err != nil || got != "c" {
			t.Fatalf("goto rewrite = %q, %v", got, err)
		}
	})

	t.Run("ignore expansion error", func(t *testing.T) {
		engine := mustRWMRewriteEngine(t,
			[]string{"rewriteEngine", "on"},
			[]string{"rewriteRule", `^a$`, `${*missing}`, ":I"},
			[]string{"rewriteRule", `^a$`, `b`, ":"},
		)
		got, _, err := engine.rewrite("default", "a")
		if err != nil || got != "b" {
			t.Fatalf("ignore-error rewrite = %q, %v", got, err)
		}
	})
}

func TestRWMRewriteRejectionAndConfiguredResult(t *testing.T) {
	rejected := mustRWMRewriteEngine(t,
		[]string{"rewriteEngine", "on"},
		[]string{"rewriteRule", `^blocked$`, ``, "#"},
	)
	_, _, err := rejected.rewrite("default", "blocked")
	failure := asOperationFailure(err)
	if failure == nil || failure.result.Code != ldapwire.ResultUnwillingToPerform {
		t.Fatalf("rejection error = %#v", err)
	}

	configured := mustRWMRewriteEngine(t,
		[]string{"rewriteEngine", "on"},
		[]string{"rewriteRule", `^busy$`, `$0`, ":U{51}"},
	)
	_, _, err = configured.rewrite("default", "busy")
	failure = asOperationFailure(err)
	if failure == nil || failure.result.Code != ldapwire.ResultBusy {
		t.Fatalf("configured result error = %#v", err)
	}
}

func TestRWMRewriteUndefinedAndEmptyContextSemantics(t *testing.T) {
	engine := mustRWMRewriteEngine(t,
		[]string{"rewriteEngine", "on"},
		[]string{"rewriteRule", `^local$`, `remote`, ":"},
	)
	got, changed, err := engine.rewrite("bindDN", "local")
	if err != nil || !changed || got != "remote" {
		t.Fatalf("undefined context fallback = %q, %v, %v", got, changed, err)
	}
	got, changed, err = engine.rewrite("searchFilter", "local")
	if err != nil || changed || got != "local" {
		t.Fatalf("explicit empty searchFilter = %q, %v, %v", got, changed, err)
	}
}

func TestRWMRewriteUnsupportedSyntaxFailsClosed(t *testing.T) {
	tests := []struct {
		name      string
		directive []string
		contains  string
	}{
		{name: "map", directive: []string{"rewriteMap", "ldap", "lookup"}, contains: "not implemented"},
		{name: "session variable", directive: []string{"rewriteRule", `.*`, `${&&binddn($0)}$0`, ":"}, contains: "session variables"},
		{name: "basic regex", directive: []string{"rewriteRule", `.*`, `$0`, "R"}, contains: "POSIX basic"},
		{name: "unknown flag", directive: []string{"rewriteRule", `.*`, `$0`, "Z"}, contains: "unsupported flag"},
		{name: "bad regex", directive: []string{"rewriteRule", `(`, `$0`, ":"}, contains: "pattern"},
		{name: "bad alias", directive: []string{"rewriteContext", "x", "alias", "missing"}, contains: "not defined"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine := newRWMRewriteEngine()
			err := engine.parseDirective(test.directive)
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("parse error = %v, want substring %q", err, test.contains)
			}
		})
	}
}

func TestRWMRewriteResourceLimits(t *testing.T) {
	engine := mustRWMRewriteEngine(t, []string{"rewriteEngine", "on"})
	_, _, err := engine.rewrite("default", strings.Repeat("x", rwmRewriteMaximumInputBytes+1))
	failure := asOperationFailure(err)
	if failure == nil || failure.result.Code != ldapwire.ResultOther {
		t.Fatalf("oversized input error = %#v", err)
	}

	depthEngine := newRWMRewriteEngine()
	if err := depthEngine.parseDirective([]string{"rewriteEngine", "on"}); err != nil {
		t.Fatal(err)
	}
	for index := rwmRewriteMaximumDepth; index >= 0; index-- {
		name := "context" + string(rune('a'+index))
		if err := depthEngine.parseDirective([]string{"rewriteContext", name}); err != nil {
			t.Fatal(err)
		}
		next := name
		if index < rwmRewriteMaximumDepth {
			next = "context" + string(rune('a'+index+1))
		}
		if err := depthEngine.parseDirective([]string{"rewriteRule", `.*`, `${>` + next + `($0)}`, ":"}); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err = depthEngine.rewrite("contexta", "value")
	failure = asOperationFailure(err)
	if failure == nil || failure.result.Code != ldapwire.ResultOther ||
		!strings.Contains(failure.result.DiagnosticMessage, "depth") {
		t.Fatalf("depth error = %v", err)
	}
}

func mustRWMRewriteEngine(t *testing.T, directives ...[]string) *rwmRewriteEngine {
	t.Helper()
	engine := newRWMRewriteEngine()
	for _, directive := range directives {
		if err := engine.parseDirective(directive); err != nil {
			t.Fatalf("parse %q: %v", directive, err)
		}
	}
	return engine
}

func TestRWMRewriteAdditionalBoundsAndIsolation(t *testing.T) {
	t.Run("defined context input", func(t *testing.T) {
		engine := mustRWMRewriteEngine(t, []string{"rewriteEngine", "on"})
		if _, _, err := engine.rewriteDefinedContext("default", strings.Repeat("x", rwmRewriteMaximumInputBytes+1)); err == nil {
			t.Fatal("defined context bypassed input bound")
		}
	})
	t.Run("nested template compilation", func(t *testing.T) {
		value := strings.Repeat("${&value(", rwmRewriteMaximumDepth+1) + "x" + strings.Repeat(")}", rwmRewriteMaximumDepth+1)
		if _, err := compileRWMRewriteRule(".*", value, ":", 100); err == nil {
			t.Fatal("accepted excessive template nesting")
		}
	})
	t.Run("output growth", func(t *testing.T) {
		engine := mustRWMRewriteEngine(t, []string{"rewriteEngine", "on"}, []string{"rewriteRule", `.*`, strings.Repeat("$0", 32), ":"})
		if _, _, err := engine.rewrite("default", strings.Repeat("x", rwmRewriteMaximumInputBytes/16)); err == nil {
			t.Fatal("accepted oversized expansion")
		}
	})
	t.Run("ambiguous regex work", func(t *testing.T) {
		engine := mustRWMRewriteEngine(t, []string{"rewriteEngine", "on"}, []string{"rewriteRule", `^((a|aa)*)$`, `$1`, ":"})
		got, _, err := engine.rewrite("default", strings.Repeat("a", 32))
		if runtime.GOOS == "linux" {
			// The linear matcher does not enumerate exponentially many captures.
			if err != nil || got != strings.Repeat("a", 32) {
				t.Fatalf("linear ambiguous match = %q, %v", got, err)
			}
			return
		}
		failure := asOperationFailure(err)
		if failure == nil || !strings.Contains(failure.result.DiagnosticMessage, "regex work") {
			t.Fatalf("unbounded ambiguous regex: %v", err)
		}
	})
	t.Run("shared regex work budget", func(t *testing.T) {
		rule, err := compileRWMRewriteRule(`^(a)$`, "$1", ":", 100)
		if err != nil {
			t.Fatal(err)
		}
		operation := &rwmRewriteOperation{regexSteps: rwmRewriteMaximumRegexSteps - 1}
		if _, err := rule.match("a", operation); err == nil || !strings.Contains(err.Error(), "regex work") {
			t.Fatalf("shared regex work budget bypassed: %v", err)
		}
	})
	t.Run("variables isolated between concurrent operations", func(t *testing.T) {
		engine := mustRWMRewriteEngine(t,
			[]string{"rewriteEngine", "on"},
			[]string{"rewriteContext", "read"},
			[]string{"rewriteRule", `.*`, `${*value}`, ":"},
			[]string{"rewriteContext", "default"},
			[]string{"rewriteRule", `.*`, `${&value($0)}${>read(x)}`, ":"},
		)
		for index := 0; index < 32; index++ {
			t.Run(fmt.Sprint(index), func(t *testing.T) {
				t.Parallel()
				input := fmt.Sprintf("value%d", index)
				got, _, err := engine.rewrite("default", input)
				if err != nil || got != input {
					t.Fatalf("isolated expansion = %q, %v", got, err)
				}
				if _, _, err := engine.rewrite("read", "x"); err == nil {
					t.Fatal("operation variable leaked")
				}
			})
		}
	})
	for _, test := range []struct {
		name  string
		words []string
	}{
		{"nul", []string{"rewriteRule", ".*", "a\x00b", ":"}},
		{"undefined subcontext", []string{"rewriteRule", ".*", "${>missing($0)}", ":"}},
		{"legacy map", []string{"rewriteRule", ".*", "$0{missing}", ":"}},
		{"perl regex", []string{"rewriteRule", "(?i:a)", "b", ":"}},
		{"regex escape", []string{"rewriteRule", `\d+`, "b", ":"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := newRWMRewriteEngine().parseDirective(test.words); err == nil {
				t.Fatalf("accepted unsupported syntax: %q", test.words)
			}
		})
	}
}

func FuzzRWMRewrite(f *testing.F) {
	for _, seed := range [][3]string{
		{"^(a|aa)(a?)$", "$1/$2", "aa"}, {".*", "${&*value($0)}", "x"},
		{"(.*)", "${>default($0)}", "x"}, {".*", "$0{bad}", ""},
		{`^((a)|b)*$`, "$1/$2", "ab"},
		{`^[][()]((a)|b)*$`, "$1/$2", "]ab"},
		{`^[[:alpha:]]((a)|b)*$`, "$1/$2", "xab"},
		{`^\(((a)|b)*\)$`, "$1/$2", "(ab)"},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}
	f.Fuzz(func(t *testing.T, pattern, replacement, input string) {
		if len(pattern)+len(replacement)+len(input) > 4096 {
			return
		}
		engine := newRWMRewriteEngine()
		if err := engine.parseDirective([]string{"rewriteRule", pattern, replacement, ":"}); err != nil {
			return
		}
		engine.enabled = true
		output, _, err := engine.rewrite("default", input)
		if err == nil && len(output) > rwmRewriteMaximumOutputBytes {
			t.Fatal("output exceeds bound")
		}
	})
}

func TestRWMRewriteSuffixMassageOrderingAndDisable(t *testing.T) {
	local, _ := directory.ParseDN("dc=local,dc=test")
	remote, _ := directory.ParseDN("dc=remote,dc=test")
	mapping := &rwmSuffixMapping{local: local, remote: remote}
	engine := mustRWMRewriteEngine(t,
		[]string{"rewriteEngine", "on"},
		[]string{"rewriteRule", `^uid=blocked,.*$`, "", "#"},
	)
	if err := engine.addSuffixMapping(mapping, "searchEntryDN"); err != nil {
		t.Fatal(err)
	}
	configuration := &rwmRuntimeConfiguration{rewrite: engine, suffix: mapping}
	dn, _ := directory.ParseDN("uid=alice,dc=local,dc=test")
	got, err := configuration.mapDNToRemote(dn)
	if err != nil || got.String() != "uid=alice,dc=remote,dc=test" {
		t.Fatalf("generated suffix rule = %s, %v", got.String(), err)
	}
	blocked, _ := directory.ParseDN("uid=blocked,dc=local,dc=test")
	if _, err := configuration.mapDNToRemote(blocked); err == nil {
		t.Fatal("suffixmassage bypassed preceding rejection")
	}
	if err := engine.parseDirective([]string{"rewriteContext", "searchDN"}); err != nil {
		t.Fatal(err)
	}
	got, err = configuration.mapDNContext("searchDN", dn, true)
	if err != nil || got.String() != dn.String() {
		t.Fatalf("explicit empty context did not suppress suffix rules: %s, %v", got.String(), err)
	}
	if err := engine.parseDirective([]string{"rewriteEngine", "off"}); err != nil {
		t.Fatal(err)
	}
	got, err = configuration.mapDNToRemote(dn)
	if err != nil || got.String() != dn.String() {
		t.Fatalf("disabled engine still rewrote suffix: %s, %v", got.String(), err)
	}
}

func TestRWMRewriteDNAndFilterFailures(t *testing.T) {
	for _, test := range []struct{ context, replacement string }{
		{"searchDN", "invalid DN"},
		{"searchFilter", "invalid filter"},
		{"referralDN", "invalid DN"},
	} {
		t.Run(test.context, func(t *testing.T) {
			configuration := &rwmRuntimeConfiguration{rewrite: mustRWMRewriteEngine(t,
				[]string{"rewriteEngine", "on"}, []string{"rewriteContext", test.context},
				[]string{"rewriteRule", ".*", test.replacement, ":"})}
			var err error
			switch test.context {
			case "searchDN":
				dn, _ := directory.ParseDN("dc=example,dc=com")
				_, err = configuration.mapDNContext("searchDN", dn, true)
			case "searchFilter":
				filter, _ := ldapwire.CompileFilter("(uid=alice)")
				_, err = configuration.rewriteFilter(filter)
			case "referralDN":
				_, err = configuration.mapLDAPURLValue([]byte("ldap://example.test/dc=example,dc=com"), false, "referralDN")
			}
			if err == nil {
				t.Fatal("invalid rewrite result did not fail closed")
			}
		})
	}
}
