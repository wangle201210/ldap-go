package schema

import (
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func syntaxPublicationMap(t *testing.T, registry *Registry) map[string]string {
	t.Helper()
	descriptions, err := registry.LDAPSyntaxDescriptions()
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]string, len(descriptions))
	var previous string
	for _, description := range descriptions {
		syntax, err := ParseLDAPSyntax(description)
		if err != nil {
			t.Fatal(err)
		}
		if syntax.OID <= previous {
			t.Fatalf("unordered or duplicate OID: %q after %q", syntax.OID, previous)
		}
		result[syntax.OID] = description
		previous = syntax.OID
	}
	return result
}

func registerPublicationSyntax(t *testing.T, registry *Registry, description string) LDAPSyntax {
	t.Helper()
	syntax, err := ParseLDAPSyntax(description)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.registerLDAPSyntax(syntax); err != nil {
		t.Fatal(err)
	}
	return syntax
}

func TestLDAPSyntaxDescriptionsMetadata(t *testing.T) {
	registry := NewRegistry()
	before := len(registry.syntaxes)
	got := syntaxPublicationMap(t, registry)
	for oid, want := range map[string]string{
		SyntaxBoolean:              "( " + SyntaxBoolean + " DESC 'Boolean' )",
		SyntaxCertificate:          "( " + SyntaxCertificate + " DESC 'Certificate' X-BINARY-TRANSFER-REQUIRED 'TRUE' X-NOT-HUMAN-READABLE 'TRUE' )",
		SyntaxAttributeCertificate: "( " + SyntaxAttributeCertificate + " DESC 'X.509 AttributeCertificate' X-BINARY-TRANSFER-REQUIRED 'TRUE' X-NOT-HUMAN-READABLE 'TRUE' )",
		SyntaxPKCS8PrivateKey:      "( " + SyntaxPKCS8PrivateKey + " DESC 'PKCS#8 PrivateKeyInfo' )",
		SyntaxSubtreeSpecification: "( " + SyntaxSubtreeSpecification + " DESC 'SubtreeSpecification' )",
	} {
		if got[oid] != want {
			t.Errorf("%s: got %q, want %q", oid, got[oid], want)
		}
	}
	for _, oid := range []string{
		SyntaxACIItem, SyntaxAttributeType, SyntaxDITContentRule, SyntaxDITStructureRule,
		SyntaxMatchingRule, SyntaxMatchingRuleUse, SyntaxNameForm, SyntaxObjectClass,
		SyntaxLDAPSyntaxDescription, SyntaxCSN, SyntaxAuthz, SyntaxOpenLDAPVoid,
		SyntaxOpenLDAPACI, SyntaxAuthenticationPassword,
	} {
		if _, published := got[oid]; published {
			t.Errorf("published hidden, native NULL-validator, or unknown syntax %s", oid)
		}
	}
	for _, definition := range builtinSyntaxPublicationDefinitions() {
		syntax, found := registry.LDAPSyntax(definition.oid)
		_, published := got[definition.oid]
		if want := found && syntax.HasValidator() && definition.public(); published != want {
			t.Errorf("%s: published %t, want %t", definition.oid, published, want)
		}
	}
	boolean, _ := registry.LDAPSyntax(SyntaxBoolean)
	key, _ := registry.LDAPSyntax(SyntaxPKCS8PrivateKey)
	if len(registry.syntaxes) != before || boolean.Description != "" ||
		!key.BinaryTransferRequired || !key.BEREncoded || len(key.Extensions) != 0 {
		t.Fatal("publication changed executable syntax metadata")
	}
	// Even a known public OID must be installed with an actual Go validator.
	registry.syntaxes[SyntaxBoolean].validator = nil
	delete(registry.syntaxes, SyntaxCertificate)
	got = syntaxPublicationMap(t, registry)
	if got[SyntaxBoolean] != "" || got[SyntaxCertificate] != "" {
		t.Fatal("publication advertised an unavailable validator")
	}
}

func TestLDAPSyntaxDescriptionsSubstitutes(t *testing.T) {
	registry := NewRegistry()
	visible := registerPublicationSyntax(t, registry,
		"( 1.2.3.1 DESC 'custom \\27quoted\\27 \\5C text' X-SUBST '"+SyntaxDirectoryString+"' X-ORIGIN ( 'first' 'second' ) )")
	chain := registerPublicationSyntax(t, registry,
		"( 1.2.3.2 DESC 'chain' X-SUBST '1.2.3.1' X-NOT-HUMAN-READABLE 'FALSE' )")
	binary := registerPublicationSyntax(t, registry,
		"( 1.2.3.3 DESC 'binary alias' X-SUBST '"+SyntaxCertificate+"' X-BINARY-TRANSFER-REQUIRED 'FALSE' )")
	noMetadata := registerPublicationSyntax(t, registry,
		"( 1.2.3.4 X-SUBST '"+SyntaxPKCS8PrivateKey+"' )")
	for index, substitute := range []string{
		SyntaxCSN, SyntaxOpenLDAPVoid, SyntaxAuthz, SyntaxOpenLDAPACI,
		SyntaxAttributeType, SyntaxDITContentRule, SyntaxDITStructureRule,
		SyntaxMatchingRule, SyntaxMatchingRuleUse, SyntaxNameForm, SyntaxObjectClass, SyntaxLDAPSyntaxDescription,
		SyntaxACIItem, SyntaxAuthenticationPassword,
	} {
		oid := fmt.Sprintf("1.2.4.%d", index)
		registerPublicationSyntax(t, registry, "( "+oid+" X-SUBST '"+substitute+"' )")
		registerPublicationSyntax(t, registry, "( "+oid+".1 X-SUBST '"+oid+"' )")
	}
	registerPublicationSyntax(t, registry, "( 1.2.5.1 DESC 'unvalidated' )")
	registerPublicationSyntax(t, registry, "( 1.2.5.2 X-SUBST '1.2.5.1' )")
	got := syntaxPublicationMap(t, registry)
	for _, syntax := range []LDAPSyntax{visible, chain, binary, noMetadata} {
		if got[syntax.OID] != FormatLDAPSyntax(syntax) {
			t.Errorf("custom metadata lost: got %q, want %q", got[syntax.OID], FormatLDAPSyntax(syntax))
		}
	}
	for oid := range got {
		if strings.HasPrefix(oid, "1.2.4.") || strings.HasPrefix(oid, "1.2.5.") {
			t.Errorf("substitute exposed hidden or unvalidated syntax %s", oid)
		}
	}
	stored, _ := registry.LDAPSyntax(binary.OID)
	if !stored.BinaryTransferRequired || !stored.BEREncoded {
		t.Fatal("publication changed the substitute's executable binary flags")
	}
	// A compatible declaration cannot replace a builtin's publication metadata.
	registerPublicationSyntax(t, registry,
		"( "+SyntaxBoolean+" DESC 'replacement' X-SUBST '"+SyntaxBoolean+"' X-ORIGIN 'custom' )")
	if after := syntaxPublicationMap(t, registry); !reflect.DeepEqual(got, after) {
		t.Fatal("compatible builtin declaration changed published schema")
	}
	visible.Extensions["X-ORIGIN"][0] = "caller mutation"
	if after := syntaxPublicationMap(t, registry); !reflect.DeepEqual(got, after) {
		t.Fatal("caller metadata aliases registry state")
	}
}

func TestLDAPSyntaxDescriptionsSnapshotDoesNotExecuteValidators(t *testing.T) {
	registry := NewRegistry()
	registerPublicationSyntax(t, registry, "( 1.2.3.1 X-SUBST '"+SyntaxCertificate+"' )")
	for _, syntax := range registry.syntaxes {
		if syntax.validator != nil {
			syntax.validator = func([]byte) error { panic("publication executed a validator") }
		}
	}
	want, err := registry.LDAPSyntaxDescriptions()
	if err != nil {
		t.Fatal(err)
	}
	cloned := registry.Clone()
	copy, err := registry.LDAPSyntaxDescriptions()
	if err != nil {
		t.Fatal(err)
	}
	copy[0] = "changed by caller"
	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for index := 0; index < 20; index++ {
				if worker == 0 {
					err := registry.registerLDAPSyntax(LDAPSyntax{
						OID:        fmt.Sprintf("1.2.6.%d", index),
						Extensions: map[string][]string{"X-SUBST": {SyntaxBoolean}},
					})
					if err != nil {
						t.Error(err)
					}
				} else if _, err := registry.LDAPSyntaxDescriptions(); err != nil {
					t.Error(err)
				}
			}
		}(worker)
	}
	workers.Wait()
	got, err := cloned.LDAPSyntaxDescriptions()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot changed: err=%v", err)
	}
}

func TestLDAPSyntaxDescriptionsLimits(t *testing.T) {
	t.Run("aggregate bytes", func(t *testing.T) {
		registry := NewRegistry()
		baseline, err := registry.LDAPSyntaxDescriptions()
		if err != nil {
			t.Fatal(err)
		}
		remaining := maxLDAPSyntaxSchemaBytes
		for _, description := range baseline {
			remaining -= len(description)
		}
		syntax := LDAPSyntax{OID: "1.2.3.1", Description: "x", Extensions: map[string][]string{"X-SUBST": {SyntaxDirectoryString}}}
		syntax.Description = strings.Repeat("a", remaining-len(FormatLDAPSyntax(syntax))+1)
		if err := registry.registerLDAPSyntax(syntax); err != nil {
			t.Fatal(err)
		}
		atLimit, err := registry.LDAPSyntaxDescriptions()
		if err != nil {
			t.Fatal(err)
		}
		var size int
		for _, description := range atLimit {
			size += len(description)
		}
		if size != maxLDAPSyntaxSchemaBytes {
			t.Fatalf("size = %d, want %d", size, maxLDAPSyntaxSchemaBytes)
		}
		registerPublicationSyntax(t, registry, "( 1.2.3.2 X-SUBST '"+SyntaxBoolean+"' )")
		if got, err := registry.LDAPSyntaxDescriptions(); err == nil || got != nil {
			t.Fatalf("oversize publication returned %d definitions, err=%v", len(got), err)
		}
		if got, _ := registry.LDAPSyntax(syntax.OID); got.Description != syntax.Description {
			t.Fatal("failed publication changed registry")
		}
	})
	t.Run("escaped bytes", func(t *testing.T) {
		registry := NewRegistry()
		if err := registry.registerLDAPSyntax(LDAPSyntax{
			OID: "1.2.3.1", Description: strings.Repeat("'", maxLDAPSyntaxSchemaBytes/3),
			Extensions: map[string][]string{"X-SUBST": {SyntaxBoolean}},
		}); err != nil {
			t.Fatal(err)
		}
		if got, err := registry.LDAPSyntaxDescriptions(); err == nil || got != nil {
			t.Fatalf("oversize escaped publication returned %d definitions, err=%v", len(got), err)
		}
	})
	t.Run("definition count", func(t *testing.T) {
		registry := NewRegistry()
		initial := len(syntaxPublicationMap(t, registry))
		for index := initial; index < maxLDAPSyntaxSchemaDefinitions; index++ {
			if err := registry.registerLDAPSyntax(LDAPSyntax{
				OID: fmt.Sprintf("1.2.3.%d", index), Extensions: map[string][]string{"X-SUBST": {SyntaxBoolean}},
			}); err != nil {
				t.Fatal(err)
			}
		}
		got, err := registry.LDAPSyntaxDescriptions()
		if err != nil || len(got) != maxLDAPSyntaxSchemaDefinitions {
			t.Fatalf("at count limit: %d definitions, err=%v", len(got), err)
		}
		registerPublicationSyntax(t, registry, "( 1.2.4.1 X-SUBST '"+SyntaxBoolean+"' )")
		if got, err := registry.LDAPSyntaxDescriptions(); err == nil || got != nil {
			t.Fatalf("over count limit: %d definitions, err=%v", len(got), err)
		}
	})
}

func TestLDAPSyntaxPublicationBudget(t *testing.T) {
	for _, syntax := range []LDAPSyntax{
		{OID: "1.2.3"},
		{OID: "1.2.3", Description: "'\\\x00\x7f\n text"},
		{OID: "1.2.3", Extensions: map[string][]string{"X-EMPTY": {}, "X-SINGLE": {"one"}, "X-MULTI": {"two", "three"}}},
		{OID: "1.2.3", Extensions: map[string][]string{"x-origin": {"'\\"}}},
	} {
		size := len(FormatLDAPSyntax(syntax))
		if remaining, ok := ldapSyntaxPublicationBudget(syntax, size); !ok || remaining != 0 {
			t.Errorf("exact budget: remaining=%d ok=%t syntax=%#v", remaining, ok, syntax)
		}
		if _, ok := ldapSyntaxPublicationBudget(syntax, size-1); ok {
			t.Errorf("accepted undersized budget for %#v", syntax)
		}
	}
}

func FuzzLDAPSyntaxPublicationBudget(f *testing.F) {
	f.Add("description", "one", "two")
	f.Add("'\\\x00\x7f\n", "", "'\\")
	f.Fuzz(func(t *testing.T, description, first, second string) {
		if len(description)+len(first)+len(second) > 8192 {
			t.Skip()
		}
		syntax := LDAPSyntax{
			OID: "1.2.3", Description: description,
			Extensions: map[string][]string{"X-ORIGIN": {first, second}, "X-SUBST": {SyntaxBoolean}},
		}
		size := len(FormatLDAPSyntax(syntax))
		if remaining, ok := ldapSyntaxPublicationBudget(syntax, size); !ok || remaining != 0 {
			t.Fatalf("exact budget: size=%d remaining=%d ok=%t", size, remaining, ok)
		}
		if _, ok := ldapSyntaxPublicationBudget(syntax, size-1); ok {
			t.Fatal("accepted undersized budget")
		}
	})
}

func TestLDAPSyntaxPublicationPinnedSource(t *testing.T) {
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
	source := read("servers/slapd/schema_init.c")
	// Resolve the active experimental PMI macros, not the obsolete #if 0 OIDs.
	macros := regexp.MustCompile(`(?s)#else[^\n]*\n(#define X509_PMI_SyntaxOID.*?)#endif`).FindStringSubmatch(source)
	if len(macros) != 2 {
		t.Fatal("active AttributeCertificate OID macros not found")
	}
	quoted := regexp.MustCompile(`"(?:\\.|[^"\\])*"`)
	joinQuoted := func(input string) string {
		t.Helper()
		var joined strings.Builder
		for _, literal := range quoted.FindAllString(input, -1) {
			value, err := strconv.Unquote(literal)
			if err != nil {
				t.Fatal(err)
			}
			joined.WriteString(value)
		}
		return joined.String()
	}
	definitions := regexp.MustCompile(`(?m)^#define\s+(\w+)\s+([^\n]+)$`).FindAllStringSubmatch(macros[1], -1)
	replacements := make(map[string]string)
	for _, definition := range definitions {
		value := definition[2]
		for name, replacement := range replacements {
			value = strings.ReplaceAll(value, name, strconv.Quote(replacement))
		}
		replacements[definition[1]] = joinQuoted(value)
	}
	if replacements["attributeCertificateSyntaxOID"] != SyntaxAttributeCertificate {
		t.Fatalf("native AttributeCertificate OID = %q", replacements["attributeCertificateSyntaxOID"])
	}
	for _, name := range []string{"X_BINARY", "X_NOT_H_R"} {
		match := regexp.MustCompile(`(?m)^#define\s+` + name + `\s+([^\n]+)$`).FindStringSubmatch(source)
		if len(match) != 2 {
			t.Fatalf("missing native %s extension", name)
		}
		replacements[name] = joinQuoted(match[1])
	}
	start := strings.Index(source, "static slap_syntax_defs_rec syntax_defs[] = {")
	end := strings.Index(source, "char *csnSIDMatchSyntaxes[]")
	if start < 0 || end < start {
		t.Fatal("native syntax table not found")
	}
	source = source[start:end] + read("servers/slapd/aci.c")
	// This pinned table has a disabled duplicate Country String definition.
	source = regexp.MustCompile(`(?ms)^#if\s+0[^\n]*\n.*?^#endif[^\n]*`).ReplaceAllString(source, "")
	source = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(source, "")
	source = regexp.MustCompile(`(?m)^#.*$`).ReplaceAllString(source, "")
	var names []string
	for name := range replacements {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	for _, name := range names {
		source = strings.ReplaceAll(source, name, strconv.Quote(replacements[name]))
	}
	rows := regexp.MustCompile(`(?s)\{\s*((?:"(?:\\.|[^"\\])*"\s*)+),\s*([^,]+),\s*[^,]+,\s*(\w+)\s*,`)
	type nativeSyntax struct {
		syntax    LDAPSyntax
		hidden    bool
		validated bool
	}
	native := make(map[string]nativeSyntax)
	for _, row := range rows.FindAllStringSubmatch(source, -1) {
		description := joinQuoted(row[1])
		syntax, err := ParseLDAPSyntax(description)
		if err != nil {
			// aci.c also contains non-syntax declarations.
			continue
		}
		native[syntax.OID] = nativeSyntax{syntax, strings.Contains(row[2], "SLAP_SYNTAX_HIDE"), row[3] != "NULL"}
	}
	if len(native) < 60 {
		t.Fatalf("incomplete native table extraction: %d syntaxes", len(native))
	}
	seen := make(map[string]bool)
	for _, definition := range builtinSyntaxPublicationDefinitions() {
		if seen[definition.oid] {
			t.Errorf("duplicate metadata OID %s", definition.oid)
		}
		seen[definition.oid] = true
		entry, found := native[definition.oid]
		if !found || FormatLDAPSyntax(entry.syntax) != FormatLDAPSyntax(definition.syntax()) ||
			entry.hidden != (definition.flags&syntaxPublicationHidden != 0) ||
			entry.validated != (definition.flags&syntaxPublicationValidated != 0) {
			t.Errorf("metadata differs from pinned source: %#v versus %#v (found %t)", definition, entry, found)
		}
	}
	for oid, syntax := range NewRegistry().syntaxes {
		if _, exists := native[oid]; exists && syntax.validator != nil && !seen[oid] {
			t.Errorf("registered native syntax missing from catalog: %s", oid)
		}
	}
	source = read("servers/slapd/syntax.c")
	for _, fragment := range []string{
		"if ( ! syn->ssyn_validate )", "syn->ssyn_flags & SLAP_SYNTAX_HIDE",
		"ssyn->ssyn_flags = subst->ssyn_flags;", "ssyn->ssyn_validate = subst->ssyn_validate;",
		"ldap_syntax2bv( &syn->ssyn_syn, &val )", "AC_MEMCPY( &ssyn->ssyn_syn, syn, sizeof(LDAPSyntax) );",
	} {
		if !strings.Contains(source, fragment) {
			t.Errorf("missing native publication/substitute contract: %s", fragment)
		}
	}
}
