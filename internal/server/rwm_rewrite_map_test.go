package server

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

type rwmRewriteMapCase struct {
	name       string
	operations string
	input      string
	want       string
	fails      bool
}

// Fixtures follow libraries/librewrite/escapemap.c and libldap/{getdn,search,
// filter,utf-8}.c at OpenLDAP 2.6.13 d172686d3d270bc961b78f3ff00d7019c8dfb094.
// TestOpenLDAPReferenceRWMRewriteMaps also runs them through the external CLI.
func rwmRewriteMapCases() []rwmRewriteMapCase {
	return []rwmRewriteMapCase{
		{name: "filter plain", operations: "escape2filter", input: "a=b #,+", want: "a=b #,+"},
		{name: "filter metacharacters", operations: "escape2filter", input: `a*(b)\c`, want: `a\2A\28b\29\5Cc`},
		{name: "filter controls", operations: "escape2filter", input: "a\t\n\r\x01\x7fb", want: `a\09\0A\0D\01\7Fb`},
		{name: "filter UTF8", operations: "escape2filter", input: "caf\xc3\xa9", want: `caf\C3\A9`},
		{name: "filter arbitrary bytes", operations: "escape2filter", input: "\xff\x80", want: `\FF\80`},
		{name: "filter empty", operations: "escape2filter"},
		{name: "filter hex case", operations: "unescapefilter", input: `\2a\2A\5C`, want: "**\\"},
		{name: "filter v2 escapes", operations: "unescapefilter", input: `\(a\*b\)\\`, want: `(a*b)\`},
		{name: "filter decoded UTF8", operations: "unescapefilter", input: `caf\c3\a9`, want: "caf\xc3\xa9"},
		{name: "filter decode plain controls", operations: "unescapefilter", input: "a\tb", want: "a\tb"},
		{name: "filter decode arbitrary bytes", operations: "unescapefilter", input: `\FF`, want: "\xff"},
		{name: "filter raw star", operations: "unescapefilter", input: "a*b", fails: true},
		{name: "filter raw open", operations: "unescapefilter", input: "a(b", fails: true},
		{name: "filter raw close", operations: "unescapefilter", input: "a)b", fails: true},
		{name: "filter dangling escape", operations: "unescapefilter", input: `abc\`, fails: true},
		{name: "filter short hex", operations: "unescapefilter", input: `\2`, fails: true},
		{name: "filter invalid hex", operations: "unescapefilter", input: `\2z`, fails: true},
		{name: "filter invalid v2", operations: "unescapefilter", input: `\q`, fails: true},
		{name: "filter empty decode", operations: "unescapefilter"},
		{name: "DN punctuation", operations: "escape2dn", input: `a,b+c=d;e<f>g"h\`, want: `a\2Cb\2Bc\3Dd\3Be\3Cf\3Eg\22h\5C`},
		{name: "DN edge spaces", operations: "escape2dn", input: "  a  ", want: `\20 a \20`},
		{name: "DN leading hash", operations: "escape2dn", input: "#hash#", want: `\23hash#`},
		{name: "DN edge controls", operations: "escape2dn", input: "\ta\n", want: `\09a\0A`},
		{name: "DN inner controls", operations: "escape2dn", input: "a\t\n\r\x01\x7fb", want: "a\t\n\r\x01\x7fb"},
		{name: "DN UTF8", operations: "escape2dn", input: "caf\xc3\xa9", want: `caf\C3\A9`},
		{name: "DN historic UTF8", operations: "escape2dn", input: "\xf8\x88\x80\x80\x80", want: `\F8\88\80\80\80`},
		{name: "DN surrogate UTF8", operations: "escape2dn", input: "\xed\xa0\x80", want: `\ED\A0\80`},
		{name: "DN invalid UTF8", operations: "escape2dn", input: "\xff", fails: true},
		{name: "DN overlong UTF8", operations: "escape2dn", input: "\xe0\x80\x80", fails: true},
		{name: "DN truncated UTF8", operations: "escape2dn", input: "\xe2\x82", fails: true},
		{name: "DN empty", operations: "escape2dn"},
		{name: "DN unescape punctuation", operations: "unescapedn", input: `a\,b\+c\=d\;e\<f\>g\"h\\`, want: `a,b+c=d;e<f>g"h\`},
		{name: "DN trim whitespace", operations: "unescapedn", input: " \t a\r\n ", want: "a"},
		{name: "DN escaped whitespace", operations: "unescapedn", input: `\ a\ `, want: " a "},
		{name: "DN escaped tab", operations: "unescapedn", input: "a\\\tb", want: "a\tb"},
		{name: "DN hex whitespace", operations: "unescapedn", input: `\20a\20`, want: " a "},
		{name: "DN unescape hex", operations: "unescapedn", input: `caf\c3\A9`, want: "caf\xc3\xa9"},
		{name: "DN unescape raw bytes", operations: "unescapedn", input: "\xff", want: "\xff"},
		{name: "DN full suffix", operations: "unescapedn", input: "first+cn=second,dc=example,dc=com", want: "first"},
		{name: "DN duplicate AVAs", operations: "unescapedn", input: "first+uid=second", want: "first"},
		{name: "DN numeric attribute", operations: "unescapedn", input: "first,01.02=x", want: "first"},
		{name: "DN options", operations: "unescapedn", input: "first,cn;lang-en=x", want: "first"},
		{name: "DN trailing comma", operations: "unescapedn", input: "first,", fails: true},
		{name: "DN binary bytes", operations: "unescapedn", input: "#0403616263", want: "\x04\x03abc"},
		{name: "DN binary no BER validation", operations: "unescapedn", input: "#ff", want: "\xff"},
		{name: "DN binary suffix", operations: "unescapedn", input: "#4142,dc=example", want: "AB"},
		{name: "DN binary whitespace tail", operations: "unescapedn", input: "#4142 ignored,dc=example", want: "AB"},
		{name: "DN empty hex before suffix", operations: "unescapedn", input: "#,dc=example"},
		{name: "DN empty decode", operations: "unescapedn"},
		{name: "DN blank decode", operations: "unescapedn", input: " \t\r\n"},
		{name: "DN incomplete hex", operations: "unescapedn", input: "#", fails: true},
		{name: "DN odd hex", operations: "unescapedn", input: "#123", fails: true},
		{name: "DN quoted value", operations: "unescapedn", input: `"quoted"`, fails: true},
		{name: "DN raw semicolon", operations: "unescapedn", input: "a;b", fails: true},
		{name: "DN raw less than", operations: "unescapedn", input: "a<b", fails: true},
		{name: "DN raw greater than", operations: "unescapedn", input: "a>b", fails: true},
		{name: "DN short escape", operations: "unescapedn", input: `\2`, fails: true},
		{name: "DN unknown escape", operations: "unescapedn", input: `\q`, fails: true},
		{name: "DN dangling escape", operations: "unescapedn", input: `a\`, fails: true},
		{name: "DN incomplete suffix", operations: "unescapedn", input: "first,broken", fails: true},
		{name: "DN invalid later value", operations: "unescapedn", input: `first,cn=\q`, fails: true},
		{name: "DN invalid suffix type", operations: "unescapedn", input: "first,cn_name=x", fails: true},
		{name: "DN trailing plus", operations: "unescapedn", input: "first+", fails: true},
		{name: "filter roundtrip", operations: "escape2filter unescapefilter", input: `a*(b)\c`, want: `a*(b)\c`},
		{name: "DN roundtrip", operations: "escape2dn unescapedn", input: " # a,b\xc3\xa9 ", want: " # a,b\xc3\xa9 "},
		{name: "DN to filter", operations: "unescapedn escape2filter", input: `a\2ab\28c\29`, want: `a\2Ab\28c\29`},
		{name: "filter to DN", operations: "unescapefilter escape2dn", input: `a\2cb`, want: `a\2Cb`},
		{name: "pipeline case", operations: "UnEscapeDN ESCAPE2FILTER", input: `a\2a`, want: `a\2A`},
		{name: "NUL within pipeline", operations: "unescapefilter escape2filter", input: `a\00b`, want: `a\00b`},
		{name: "NUL to DN", operations: "unescapefilter escape2dn", input: `a\00b`, want: `a\00b`},
		{name: "NUL rejects DN parse", operations: "unescapefilter unescapedn", input: `a\00b`, fails: true},
		{name: "NUL truncates filter parse", operations: "unescapefilter unescapefilter", input: `a\00b`, want: "a"},
		{name: "NUL truncates final rule", operations: "unescapefilter", input: `a\00b`, want: "a"},
	}
}

func rwmRewriteMapDirectives(test rwmRewriteMapCase) [][]string {
	return [][]string{
		{"rewriteEngine", "on"},
		append([]string{"rewriteMap", "escape", "testMap"}, strings.Fields(test.operations)...),
		{"rewriteRule", ".*", "${TESTMAP($0)}", ":"},
	}
}

func TestRWMRewriteMaps(t *testing.T) {
	for _, test := range rwmRewriteMapCases() {
		t.Run(test.name, func(t *testing.T) {
			engine := mustRWMRewriteEngine(t, rwmRewriteMapDirectives(test)...)
			got, _, err := engine.rewrite("default", test.input)
			if test.fails {
				failure := asOperationFailure(err)
				if failure == nil || failure.result.Code != ldapwire.ResultOther || got != "" {
					t.Fatalf("rewrite = %q, %v; want ResultOther", got, err)
				}
			} else if err != nil || got != test.want {
				t.Fatalf("rewrite = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestOpenLDAPReferenceRWMRewriteMaps(t *testing.T) {
	path := rwmRewriteMapReferenceCLI(t)
	for _, test := range rwmRewriteMapCases() {
		t.Run(test.name, func(t *testing.T) {
			output, err := runRWMRewriteMapReference(t, path, rwmRewriteMapDirectives(test), test.input)
			if err != nil {
				t.Fatalf("reference: %v: %s", err, output)
			}
			want := fmt.Sprintf(" -> %s [0:ok]\n", test.want)
			if test.fails {
				want = " -> (null) [-1:error]\n"
			}
			if !strings.HasSuffix(output, want) {
				t.Fatalf("reference output = %q; want suffix %q", output, want)
			}
		})
	}
}

type rwmRewriteMapSubstitutionCase struct {
	name, substitution, flags, want string
	fails                           bool
}

func rwmRewriteMapSubstitutionCases() []rwmRewriteMapSubstitutionCase {
	return []rwmRewriteMapSubstitutionCase{
		{name: "capture percent", substitution: `x%{filter(%1)}y`, flags: ":", want: `xa\2Aby`},
		{name: "empty argument", substitution: `x${filter()}y`, flags: ":", want: "xy"},
		{name: "nested calls", substitution: `${filter(${dn($1)})}`, flags: ":", want: `a\2Ab`},
		{name: "literal escapes", substitution: `${filter($$1%%1)}`, flags: ":", want: "$1%1"},
		{name: "trailing map text", substitution: `${filter($1)ignored}`, flags: ":", want: `a\2Ab`},
		{name: "operation variable", substitution: `${&v(${filter($1)})}${*v}`, flags: ":", want: `a\2Ab`},
		{name: "subcontext", substitution: `${>sub(${filter($1)})}`, flags: ":", want: `a\2Ab`},
		{name: "parameter", substitution: `${filter(${$value})}`, flags: ":", want: `\2A`},
		{name: "failure", substitution: `prefix${decode($1)}suffix`, flags: ":", fails: true},
		{name: "ignore failure", substitution: `prefix${decode($1)}suffix`, flags: ":I", want: "a*b"},
		{name: "ignore suppresses stop", substitution: `${decode($1)}`, flags: ":I@", want: "a*b"},
		{name: "NUL nested map", substitution: `p${filter(${decode(a\00b)})}s`, flags: ":", want: "pas"},
		{name: "NUL final substitution", substitution: `p${decode(a\00b)}s`, flags: ":", want: "pa"},
		{name: "NUL subcontext", substitution: `p${>sub(${decode(a\00b)})}s`, flags: ":", want: "pas"},
		{name: "NUL variable", substitution: `${&v(${decode(a\00b)})}p${*v}s`, flags: ":", want: "pas"},
		{name: "NUL set and get", substitution: `p${&*v(${decode(a\00b)})}s`, flags: ":", want: "pa"},
		{name: "ignored error suppresses rejection", substitution: `${decode($1)}`, flags: ":#I", want: "a*b"},
		{name: "map error precedes custom result", substitution: `${decode($1)}`, flags: ":U{51}", fails: true},
	}
}

func rwmRewriteMapSubstitutionDirectives(test rwmRewriteMapSubstitutionCase) [][]string {
	return [][]string{
		{"rewriteEngine", "on"},
		{"rewriteMap", "escape", "filter", "escape2filter"},
		{"rewriteMap", "escape", "dn", "escape2dn"},
		{"rewriteMap", "escape", "decode", "unescapefilter"},
		{"rewriteParam", "value", "*"},
		{"rewriteContext", "sub"},
		{"rewriteRule", ".*", "$0", ":"},
		{"rewriteContext", "default"},
		{"rewriteRule", "(.*)", test.substitution, test.flags},
	}
}

func TestRWMRewriteMapSubstitution(t *testing.T) {
	for _, test := range rwmRewriteMapSubstitutionCases() {
		t.Run(test.name, func(t *testing.T) {
			engine := mustRWMRewriteEngine(t, rwmRewriteMapSubstitutionDirectives(test)...)
			got, _, err := engine.rewrite("default", "a*b")
			if (err != nil) != test.fails || !test.fails && got != test.want {
				t.Fatalf("rewrite = %q, %v; want %q, failure=%v", got, err, test.want, test.fails)
			}
		})
	}
}

func TestRWMRewriteMapConfiguration(t *testing.T) {
	for _, words := range [][]string{
		{"rewriteMap"}, {"rewriteMap", "escape"}, {"rewriteMap", "escape", "m"},
		{"rewriteMap", "escape", "m", "lower"}, {"rewriteMap", "escape", "m", "escape2filter", "unknown"},
		{"rewriteMap", "escape", "m_x", "escape2filter"}, {"rewriteMap", "escape", "1m", "escape2dn"},
		{"rewriteMap", "ldap", "m", "ldap:///dc=test"}, {"rewriteMap", "toupper", "m"},
		{"rewriteMap", "file", "m", "/tmp/map"}, {"rewriteMap", "exec", "m", "id"},
		{"rewriteRule", ".*", "${missing($0)}", ":"},
		{"rewriteRule", ".*", "${|m($0)}", ":"},
		append([]string{"rewriteMap", "escape", "m"}, strings.Fields(strings.Repeat("escape2dn ", rwmRewriteMaximumMapOperations+1))...),
	} {
		t.Run(strings.Join(words, " "), func(t *testing.T) {
			engine := newRWMRewriteEngine()
			if err := engine.parseDirective(words); err == nil {
				t.Fatal("accepted invalid directive")
			}
			if engine.configured || len(engine.maps) != 0 || engine.ruleCount != 0 {
				t.Fatal("failed directive changed engine")
			}
		})
	}
	engine := mustRWMRewriteEngine(t, []string{"rwm-rewriteMap", "ESCAPE", "Map1", "ESCAPE2FILTER"})
	mapper := engine.maps["map1"]
	if err := engine.parseDirective([]string{"rewriteMap", "escape", "mAP1", "escape2dn"}); err == nil || engine.maps["map1"] != mapper {
		t.Fatal("duplicate map replaced the original")
	}
	for index := 1; index < rwmRewriteMaximumMaps; index++ {
		if err := engine.parseDirective([]string{"rewriteMap", "escape", fmt.Sprintf("m%d", index), "escape2dn"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := engine.parseDirective([]string{"rewriteMap", "escape", "overflow", "escape2dn"}); err == nil {
		t.Fatal("accepted excess map count")
	}
}

func TestRWMRewriteMapBounds(t *testing.T) {
	mapper := &rwmRewriteMap{operations: []string{"escape2filter"}}
	for _, test := range []struct {
		name, input string
		fails       bool
	}{
		{name: "input limit", input: strings.Repeat("a", rwmRewriteMaximumInputBytes)},
		{name: "oversized input", input: strings.Repeat("a", rwmRewriteMaximumInputBytes+1), fails: true},
		{name: "output fits", input: strings.Repeat("*", rwmRewriteMaximumOutputBytes/3)},
		{name: "output overflow", input: strings.Repeat("*", rwmRewriteMaximumOutputBytes/3+1), fails: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, err := mapper.apply(test.input, &rwmRewriteOperation{})
			if (err != nil) != test.fails || len(output) > rwmRewriteMaximumOutputBytes {
				t.Fatalf("output length=%d error=%v", len(output), err)
			}
		})
	}
	t.Run("intermediate overflow", func(t *testing.T) {
		mapper := &rwmRewriteMap{operations: []string{"escape2filter", "unescapefilter"}}
		if _, err := mapper.apply(strings.Repeat("*", rwmRewriteMaximumOutputBytes/3+1), &rwmRewriteOperation{}); err == nil {
			t.Fatal("unescape hid intermediate overflow")
		}
	})
	t.Run("shared work", func(t *testing.T) {
		operation := &rwmRewriteOperation{}
		input := strings.Repeat("a", rwmRewriteMaximumInputBytes)
		for index := 0; index < 3; index++ {
			if _, err := mapper.apply(input, operation); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := mapper.apply(input, operation); err == nil {
			t.Fatal("separate invocations reset the work budget")
		}
	})
	t.Run("empty stage work", func(t *testing.T) {
		operation := &rwmRewriteOperation{expansionSteps: rwmRewriteMaximumExpansionSteps}
		if _, err := mapper.apply("", operation); err == nil {
			t.Fatal("empty stage bypassed expansion budget")
		}
	})
	t.Run("combined substitution output", func(t *testing.T) {
		engine := mustRWMRewriteEngine(t,
			[]string{"rewriteEngine", "on"},
			[]string{"rewriteMap", "escape", "m", "escape2filter"},
			[]string{"rewriteParam", "large", strings.Repeat("a", rwmRewriteMaximumOutputBytes)},
			[]string{"rewriteRule", ".*", "${m(${$large})}x", ":"},
		)
		if _, _, err := engine.rewrite("default", "x"); err == nil {
			t.Fatal("combined output bypassed the substitution limit")
		}
	})
	t.Run("NUL input still rejected", func(t *testing.T) {
		engine := mustRWMRewriteEngine(t, rwmRewriteMapDirectives(rwmRewriteMapCase{operations: "escape2filter"})...)
		if _, _, err := engine.rewrite("default", "a\x00b"); err == nil {
			t.Fatal("map accepted NUL in public input")
		}
	})
	t.Run("work survives ignored error", func(t *testing.T) {
		engine := mustRWMRewriteEngine(t,
			[]string{"rewriteEngine", "on"},
			[]string{"rewriteMap", "escape", "m", "escape2filter"},
			[]string{"rewriteRule", ".*", "${m($0)}", ":I"},
			[]string{"rewriteRule", ".*", "${m($0)}", ":"},
		)
		operation := &rwmRewriteOperation{mapSteps: rwmRewriteMaximumMapSteps}
		if _, _, err := engine.applyContext(engine.contexts["default"], "x", operation); err == nil {
			t.Fatal("ignored map failure reset the work budget")
		}
	})
}

func TestRWMRewriteMapOnlineRollback(t *testing.T) {
	for _, backend := range []string{"relay", "ldap", "meta"} {
		t.Run(backend, func(t *testing.T) {
			fixture := startRWMRewriteFixture(t, backend, false)
			config := bindConstraintClient(t, fixture.address, "cn=config", "config-secret")
			defer config.Close()
			client := bindConstraintClient(t, fixture.address, fixture.userDN, fixture.password)
			defer client.Close()
			values := byteValuesToStrings(readStoredEntry(t, fixture.store, fixture.configDN).Values(fixture.attribute))
			for _, directive := range []string{
				`rewriteMap escape filter escape2filter`,
				`rewriteContext searchFilter`,
				`rewriteRule "^[(]uid=alias[)]$" "(uid=${filter(alice)})" :`,
			} {
				values = append(values, fmt.Sprintf("{%d}%s", len(values), directive))
			}
			modify := ldap.NewModifyRequest(fixture.configDN, nil)
			modify.Replace(fixture.attribute, values)
			if err := config.Modify(modify); err != nil {
				t.Fatal(err)
			}
			active := fixture.server.runtime.Load()
			stored := byteValuesToStrings(readStoredEntry(t, fixture.store, fixture.configDN).Values(fixture.attribute))
			for _, invalid := range []string{
				`rewriteMap escape broken`,
				`rewriteMap escape broken escape2filter unknown`,
				`rewriteMap escape FILTER escape2dn`,
				`rewriteMap ldap remote ldap:///dc=test`,
				`rewriteRule ".*" "${undefined($0)}" :`,
			} {
				bad := append(slices.Clone(stored), fmt.Sprintf("{%d}%s", len(stored), invalid))
				modify := ldap.NewModifyRequest(fixture.configDN, nil)
				modify.Replace(fixture.attribute, bad)
				if err := config.Modify(modify); err == nil {
					t.Fatalf("accepted %s", invalid)
				}
				if fixture.server.runtime.Load() != active || !slices.Equal(stored, byteValuesToStrings(readStoredEntry(t, fixture.store, fixture.configDN).Values(fixture.attribute))) {
					t.Fatalf("failed replacement changed active or persisted configuration: %s", invalid)
				}
				result, err := client.Search(ldap.NewSearchRequest(fixture.userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(uid=alias)", []string{"uid"}, nil))
				if err != nil || len(result.Entries) != 1 || result.Entries[0].DN != fixture.userDN {
					t.Fatalf("map after rollback = %#v, %v", result, err)
				}
			}
		})
	}
}
