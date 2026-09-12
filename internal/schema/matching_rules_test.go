package schema

import (
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestBuiltinMatchingRuleCatalog(t *testing.T) {
	registry := NewRegistry()
	rules, uses, err := registry.MatchingRuleSchema()
	if err != nil || len(rules) != 33 || len(uses) != 0 {
		t.Fatalf("empty registry publication: rules=%d uses=%d err=%v", len(rules), len(uses), err)
	}
	seen := make(map[string]bool)
	for _, description := range rules {
		rule, err := ParseMatchingRule(description)
		if err != nil {
			t.Fatal(err)
		}
		if seen[rule.OID] {
			t.Fatalf("duplicate rule %q", rule.OID)
		}
		seen[rule.OID] = true
		for _, key := range []string{rule.OID, rule.Names[0], strings.ToUpper(rule.Names[0])} {
			found, ok := BuiltinMatchingRule(key)
			if !ok || FormatMatchingRule(found) != FormatMatchingRule(rule) {
				t.Fatalf("lookup %q = %#v, %t; want %#v", key, found, ok, rule)
			}
			found.Names[0] = "changed"
		}
		if !implementedCatalogRule(rule.Names[0]) {
			t.Errorf("published rule has no implemented matcher: %s", description)
		}
	}
	for _, hidden := range []string{
		"authzMatch", "OpenLDAPaciMatch", "CSNMatch", "CSNOrderingMatch",
		"directoryStringApproxMatch", "IA5StringApproxMatch",
	} {
		rule, ok := BuiltinMatchingRule(hidden)
		if !ok || seen[rule.OID] {
			t.Errorf("hidden rule %q: lookup=%t published=%t", hidden, ok, seen[rule.OID])
		}
	}
	for _, unknown := range []string{
		"caseIgnoreIA5OrderingMatch", "caseExactIA5OrderingMatch",
		"certificateExactMatch", "1.2.3.999", "", " caseIgnoreMatch", "caseIgnoreMatch;lang-en",
	} {
		if rule, ok := BuiltinMatchingRule(unknown); ok {
			t.Errorf("unexpected rule %q: %#v", unknown, rule)
		}
	}
	rules[0] = "changed"
	if !reflect.DeepEqual(registry.MatchingRuleDescriptions(), NewRegistry().MatchingRuleDescriptions()) {
		t.Fatal("publication shares mutable catalog state")
	}
}

func implementedCatalogRule(name string) bool {
	if supportedMatchingRule(name) {
		return true
	}
	if _, err := matchSubstringWithRule(name, []byte("alpha"), directory.Substring{Initial: []byte("a")}); err == nil {
		return true
	}
	return name == "directoryStringApproxMatch" || name == "IA5StringApproxMatch"
}

func TestMatchingRuleUseNativeApplicability(t *testing.T) {
	attributes := []AttributeType{
		{OID: "1.2.3.1", Names: []string{"directoryValue", "directoryAlias"}, Syntax: SyntaxDirectoryString, Equality: "caseIgnoreMatch", Substring: "caseIgnoreSubstringsMatch"},
		{OID: "1.2.3.2", Names: []string{"printableValue"}, Syntax: SyntaxPrintableString},
		{OID: "1.2.3.3", Names: []string{"telephoneValue"}, Syntax: SyntaxTelephoneNumber},
		{OID: "1.2.3.4", Names: []string{"countryValue"}, Syntax: matchingRuleCountrySyntax},
		{OID: "1.2.3.5", Names: []string{"ia5Value"}, Syntax: SyntaxIA5String, Substring: "caseIgnoreIA5SubstringsMatch"},
		{OID: "1.2.3.6", Names: []string{"inheritedValue"}, Superior: "DIRECTORYALIAS"},
		{OID: "1.2.3.7", Names: []string{"hiddenValue", "hiddenAlias"}, Syntax: SyntaxDirectoryString, Hidden: true},
		{OID: "1.2.3.8", Names: []string{"hiddenDescendant"}, Superior: "hiddenAlias"},
		{OID: "1.2.3.9", Names: []string{"uuidValue"}, Syntax: SyntaxUUID, Equality: "UUIDMatch", Ordering: "UUIDOrderingMatch"},
		{OID: "1.2.3.10", Names: []string{"schemaValue"}, Syntax: SyntaxAttributeType, Equality: "2.5.13.30"},
		{OID: "1.2.3.11", Names: []string{"noEqualitySchema"}, Syntax: SyntaxNameForm},
		{OID: "1.2.3.12", Names: []string{"integerValue"}, Syntax: SyntaxInteger},
		{OID: "1.2.3.13", Names: []string{"structureValue"}, Syntax: SyntaxDITStructureRule},
		{OID: "1.2.3.14", Names: []string{"postalValue"}, Syntax: SyntaxPostalAddress, Substring: "caseIgnoreListSubstringsMatch"},
		{OID: "1.2.3.15", Names: []string{"numericValue"}, Syntax: SyntaxNumericString, Substring: "numericStringSubstringsMatch"},
		{OID: "1.2.3.16", Names: []string{"assertionValue"}, Syntax: matchingRuleSubstringSyntax},
		{OID: "1.2.3.17", Syntax: SyntaxBoolean},
		{OID: "1.2.3.18", Names: []string{"obsoleteValue"}, Syntax: SyntaxDirectoryString, Obsolete: true},
		{OID: "1.2.3.19", Names: []string{"matchingRulesValue"}, Syntax: "1.3.6.1.4.1.1466.115.121.1.30"},
		{OID: "1.2.3.20", Names: []string{"matchingUsesValue"}, Syntax: "1.3.6.1.4.1.1466.115.121.1.31"},
		{OID: "1.2.3.21", Names: []string{"syntaxDescriptionValue"}, Syntax: "1.3.6.1.4.1.1466.115.121.1.54"},
	}
	registry := NewRegistry()
	for _, attribute := range attributes {
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	before := registry.AttributeTypeDescriptions()
	rules, uses, err := registry.MatchingRuleSchema()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"caseIgnoreMatch":                     {"countryValue", "directoryValue", "hiddenDescendant", "inheritedValue", "obsoleteValue", "printableValue", "telephoneValue"},
		"caseExactMatch":                      {"countryValue", "directoryValue", "hiddenDescendant", "inheritedValue", "obsoleteValue", "printableValue", "telephoneValue"},
		"caseIgnoreOrderingMatch":             {"countryValue", "directoryValue", "hiddenDescendant", "inheritedValue", "obsoleteValue", "printableValue", "telephoneValue"},
		"caseExactOrderingMatch":              {"countryValue", "directoryValue", "hiddenDescendant", "inheritedValue", "obsoleteValue", "printableValue", "telephoneValue"},
		"caseIgnoreSubstringsMatch":           {"countryValue", "printableValue", "telephoneValue"},
		"caseExactSubstringsMatch":            {"countryValue", "printableValue", "telephoneValue"},
		"caseIgnoreIA5Match":                  {"countryValue", "ia5Value"},
		"caseExactIA5Match":                   {"countryValue", "ia5Value"},
		"telephoneNumberMatch":                {"telephoneValue"},
		"objectIdentifierFirstComponentMatch": {"matchingRulesValue", "matchingUsesValue", "noEqualitySchema", "schemaValue", "syntaxDescriptionValue"},
		"integerFirstComponentMatch":          {"integerValue", "structureValue"},
		"integerMatch":                        {"integerValue"},
		"integerOrderingMatch":                {"integerValue"},
		"caseIgnoreListMatch":                 {"postalValue"},
		"numericStringMatch":                  {"numericValue"},
		"numericStringOrderingMatch":          {"numericValue"},
		"booleanMatch":                        {"1.2.3.17"},
	}
	got := matchingRuleUseMap(t, uses)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("APPLIES = %#v; want %#v", got, want)
	}
	if !reflect.DeepEqual(before, registry.AttributeTypeDescriptions()) {
		t.Fatal("publication modified attribute declarations")
	}
	if !reflect.DeepEqual(rules, registry.MatchingRuleDescriptions()) ||
		!reflect.DeepEqual(uses, registry.MatchingRuleUseDescriptions()) {
		t.Fatal("combined publication differs from wrappers")
	}
	slices.Reverse(attributes)
	reversed := NewRegistry()
	for _, attribute := range attributes {
		if err := reversed.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(uses, reversed.MatchingRuleUseDescriptions()) {
		t.Fatal("publication depends on registration order")
	}
}

func TestMatchingRuleUseSubstitutionIsNotInheritance(t *testing.T) {
	registry := NewRegistry()
	for _, syntax := range []LDAPSyntax{
		{OID: "1.2.3.100", Extensions: map[string][]string{"X-SUBST": {SyntaxDirectoryString}}},
		{OID: "1.2.3.101", Extensions: map[string][]string{"X-SUBST": {"1.2.3.100"}}},
	} {
		if err := registry.registerLDAPSyntax(syntax); err != nil {
			t.Fatal(err)
		}
	}
	for _, attribute := range []AttributeType{
		{OID: "1.2.3.1", Names: []string{"substituteWithoutRule"}, Syntax: "1.2.3.100"},
		{OID: "1.2.3.2", Names: []string{"substituteWithRule"}, Syntax: "1.2.3.101", Equality: "2.5.13.2"},
		{OID: "1.2.3.3", Names: []string{"substituteDescendant"}, Superior: "substituteWithRule"},
		{OID: "1.2.3.4", Names: []string{"overriddenRule"}, Superior: "substituteWithRule", Equality: "CASEEXACTMATCH"},
		{OID: "1.2.3.5", Names: []string{"orderingOnly"}, Syntax: "1.2.3.100", Ordering: "caseIgnoreOrderingMatch"},
	} {
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	_, descriptions, err := registry.MatchingRuleSchema()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"caseIgnoreMatch": {"substituteDescendant", "substituteWithRule"},
		"caseExactMatch":  {"overriddenRule"},
	}
	if got := matchingRuleUseMap(t, descriptions); !reflect.DeepEqual(got, want) {
		t.Fatalf("X-SUBST APPLIES = %#v; want %#v", got, want)
	}
}

func matchingRuleUseMap(t *testing.T, descriptions []string) map[string][]string {
	t.Helper()
	result := make(map[string][]string)
	for _, description := range descriptions {
		use, err := ParseMatchingRuleUse(description)
		if err != nil {
			t.Fatal(err)
		}
		if len(use.Applies) == 0 || len(use.Names) != 1 {
			t.Fatalf("invalid use: %#v", use)
		}
		slices.Sort(use.Applies)
		if _, duplicate := result[use.Names[0]]; duplicate || len(slices.Compact(slices.Clone(use.Applies))) != len(use.Applies) {
			t.Fatalf("duplicate declaration or APPLIES in %s", description)
		}
		result[use.Names[0]] = use.Applies
	}
	return result
}

func TestMatchingRuleSchemaInvalidInheritanceIsAtomic(t *testing.T) {
	for _, test := range []struct {
		name       string
		attributes []AttributeType
	}{
		{"missing", []AttributeType{{OID: "1.2.3.1", Names: []string{"broken"}, Superior: "absent"}}},
		{"self cycle", []AttributeType{{OID: "1.2.3.1", Names: []string{"broken", "alias"}, Superior: "ALIAS"}}},
		{"mutual cycle", []AttributeType{
			{OID: "1.2.3.1", Names: []string{"broken"}, Superior: "parent"},
			{OID: "1.2.3.2", Names: []string{"parent"}, Superior: "1.2.3.1", Hidden: true},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry := NewRegistry()
			for _, attribute := range test.attributes {
				if err := registry.RegisterAttributeType(attribute); err != nil {
					t.Fatal(err)
				}
			}
			before := registry.AttributeTypeDescriptions()
			rules, uses, err := registry.MatchingRuleSchema()
			if err == nil || rules != nil || uses != nil || registry.MatchingRuleUseDescriptions() != nil {
				t.Fatalf("invalid schema publication: %v %v %v", rules, uses, err)
			}
			if !reflect.DeepEqual(before, registry.AttributeTypeDescriptions()) {
				t.Fatal("failed publication mutated registry")
			}
		})
	}
}

func TestMatchingRuleSchemaOutputLimitIsAtomic(t *testing.T) {
	registry := NewRegistry()
	// Four directory-string rules together exceed the aggregate budget.
	if err := registry.RegisterAttributeType(AttributeType{
		OID: "1.2.3.1", Names: []string{strings.Repeat("a", maxMatchingRuleSchemaBytes/4)}, Syntax: SyntaxDirectoryString,
	}); err != nil {
		t.Fatal(err)
	}
	rules, uses, err := registry.MatchingRuleSchema()
	if err == nil || !strings.Contains(err.Error(), "bytes") || rules != nil || uses != nil {
		t.Fatalf("oversized publication: rules=%d uses=%d err=%v", len(rules), len(uses), err)
	}
}

func TestMatchingRuleSchemaRelationshipLimitIsAtomic(t *testing.T) {
	registry := NewRegistry()
	// Telephone syntax applies to four string rules, two substring rules,
	// and telephoneNumberMatch. Short names keep byte limits independent.
	for index := range maxMatchingRuleApplies/7 + 1 {
		if err := registry.RegisterAttributeType(AttributeType{
			OID: "1.2.3." + strconv.Itoa(index), Names: []string{"v" + strconv.FormatInt(int64(index), 36)},
			Syntax: SyntaxTelephoneNumber,
		}); err != nil {
			t.Fatal(err)
		}
	}
	rules, uses, err := registry.MatchingRuleSchema()
	if err == nil || !strings.Contains(err.Error(), "APPLIES relationships") || rules != nil || uses != nil {
		t.Fatalf("too many relationships: rules=%d uses=%d err=%v", len(rules), len(uses), err)
	}
}

func TestMatchingRuleSchemaDeepInheritance(t *testing.T) {
	registry := NewRegistry()
	const depth = 10000
	for index := range depth {
		attribute := AttributeType{OID: fmt.Sprintf("1.2.3.%d", index), Hidden: index != 0}
		if index+1 < depth {
			attribute.Superior = fmt.Sprintf("1.2.3.%d", index+1)
		} else {
			attribute.Syntax = SyntaxDirectoryString
		}
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	_, uses, err := registry.MatchingRuleSchema()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"caseIgnoreMatch": {"1.2.3.0"}, "caseExactMatch": {"1.2.3.0"},
		"caseIgnoreOrderingMatch": {"1.2.3.0"}, "caseExactOrderingMatch": {"1.2.3.0"},
	}
	if got := matchingRuleUseMap(t, uses); !reflect.DeepEqual(got, want) {
		t.Fatalf("deep inherited APPLIES: %#v; want %#v", got, want)
	}
}

func TestMatchingRuleSchemaSnapshotAndConcurrentRegistration(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	rules, uses, err := registry.MatchingRuleSchema()
	if err != nil || len(rules) != 33 || len(uses) == 0 {
		t.Fatalf("builtin publication: rules=%d uses=%d err=%v", len(rules), len(uses), err)
	}
	cloned := registry.Clone()
	want := slices.Clone(uses)
	uses[0] = "changed"
	if !reflect.DeepEqual(want, registry.MatchingRuleUseDescriptions()) {
		t.Fatal("publication slice shares state")
	}
	var workers sync.WaitGroup
	for worker := range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range 20 {
				if worker == 0 {
					if err := registry.RegisterAttributeType(AttributeType{
						OID: fmt.Sprintf("1.2.3.900.%d", index), Syntax: SyntaxInteger,
					}); err != nil {
						t.Error(err)
					}
				} else if _, _, err := registry.MatchingRuleSchema(); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	workers.Wait()
	if !reflect.DeepEqual(want, cloned.MatchingRuleUseDescriptions()) {
		t.Fatal("registration changed an earlier registry clone")
	}
}

func TestBuiltinMatchingRulePinnedSource(t *testing.T) {
	root := os.Getenv("OPENLDAP_SOURCE")
	if root == "" {
		t.Skip("set OPENLDAP_SOURCE to an OpenLDAP Git checkout containing the 2.6.13 pin")
	}
	const pin = "d172686d3d270bc961b78f3ff00d7019c8dfb094"
	read := func(path string) string {
		t.Helper()
		data, err := exec.Command("git", "-C", root, "show", pin+":"+path).CombinedOutput()
		if err != nil {
			t.Fatalf("read pinned %s: %v: %s", path, err, data)
		}
		return string(data)
	}
	schemaSource := read("servers/slapd/schema_init.c")
	source := schemaSource + read("servers/slapd/aci.c")
	// Resolve the two OID macros in hidden approximate declarations. Every
	// published declaration has literal metadata in this pinned source.
	for _, name := range []string{"directoryStringApproxMatchOID", "IA5StringApproxMatchOID"} {
		match := regexp.MustCompile(`#define\s+` + name + `\s+("[^"]+")`).FindStringSubmatch(source)
		if len(match) != 2 {
			t.Fatalf("missing native macro %s", name)
		}
		source = strings.ReplaceAll(source, name, match[1])
	}
	source = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(source, "")
	declarations := regexp.MustCompile(`(?s)\{\s*((?:"(?:\\.|[^"\\])*"\s*)+),\s*(SLAP_MR[^,]*),\s*(\w+)\s*,\s*([^,]+),\s*([^,]+),\s*([^,]+),`)
	quoted := regexp.MustCompile(`"(?:\\.|[^"\\])*"`)
	type nativeRule struct {
		rule                   MatchingRule
		extensible, hidden     bool
		compatibility, matcher string
	}
	native := make(map[string]nativeRule)
	for _, match := range declarations.FindAllStringSubmatch(source, -1) {
		var description strings.Builder
		for _, literal := range quoted.FindAllString(match[1], -1) {
			value, err := strconv.Unquote(literal)
			if err != nil {
				t.Fatal(err)
			}
			description.WriteString(value)
		}
		rule, err := ParseMatchingRule(description.String())
		if err != nil {
			t.Fatal(err)
		}
		compatibility := match[3]
		if compatibility == "NULL" {
			compatibility = ""
		}
		native[rule.OID] = nativeRule{rule, strings.Contains(match[2], "SLAP_MR_EXT"), strings.Contains(match[2], "SLAP_MR_HIDE"), compatibility, strings.TrimSpace(match[6])}
	}
	if len(native) < 40 {
		t.Fatalf("source extraction incomplete: %d rules", len(native))
	}
	for _, definition := range builtinMatchingRuleDefinitions() {
		entry, found := native[definition.oid]
		if !found || FormatMatchingRule(entry.rule) != FormatMatchingRule(definition.matchingRule()) || entry.matcher == "NULL" ||
			entry.extensible != definition.extensible || entry.hidden != definition.hidden || entry.compatibility != definition.compatibility {
			t.Errorf("catalog differs from pinned native definition: %#v versus %#v (found %t)", definition, entry, found)
		}
	}
	for _, entry := range native {
		if implementedCatalogRule(entry.rule.Names[0]) {
			if _, found := BuiltinMatchingRule(entry.rule.OID); !found {
				t.Errorf("implemented native rule missing from catalog: %#v", entry.rule)
			}
		}
	}
	for _, name := range []string{"directoryStringSyntaxes", "integerFirstComponentMatchSyntaxes", "objectIdentifierFirstComponentMatchSyntaxes", "country_gen_syn"} {
		match := regexp.MustCompile(`(?s)char\s+\*` + name + `\[\]\s*=\s*\{([^}]+)\}`).FindStringSubmatch(schemaSource)
		if len(match) != 2 {
			t.Fatalf("missing native syntax list %s", name)
		}
		var syntaxOIDs []string
		for _, literal := range quoted.FindAllString(match[1], -1) {
			oid, err := strconv.Unquote(literal)
			if err != nil {
				t.Fatal(err)
			}
			syntaxOIDs = append(syntaxOIDs, oid)
		}
		if name == "country_gen_syn" {
			if !reflect.DeepEqual(syntaxOIDs, []string{SyntaxDirectoryString, SyntaxIA5String, SyntaxPrintableString}) {
				t.Fatalf("native country syntax superiors changed: %v", syntaxOIDs)
			}
			for _, oid := range syntaxOIDs {
				if !matchingRuleSyntaxSuperior(matchingRuleCountrySyntax, oid) {
					t.Errorf("missing native syntax superior: %s", oid)
				}
			}
		} else if !reflect.DeepEqual(syntaxOIDs, matchingRuleCompatibleSyntaxes(name)) {
			t.Errorf("native compatible syntax list %s differs: %v", name, syntaxOIDs)
		}
	}
	for path, fragments := range map[string][]string{
		"servers/slapd/mr.c":     {"mr->smr_syntax == at->sat_syntax", "mr == at->sat_equality", "mr == at->sat_approx", "syn_is_sup( at->sat_syntax, mr->smr_syntax )", "at->sat_syntax == mr->smr_compat_syntaxes[i]", "if( at->sat_flags & SLAP_AT_HIDE ) continue;"},
		"servers/slapd/syntax.c": {"if ( subst != NULL )", "ssyn->ssyn_sups = NULL;", "ssyn->ssyn_validate = subst->ssyn_validate;"},
	} {
		source := read(path)
		for _, fragment := range fragments {
			if !strings.Contains(source, fragment) {
				t.Errorf("missing source contract %q in %s", fragment, path)
			}
		}
	}
}
