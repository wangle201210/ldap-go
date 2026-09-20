package schema

import (
	"bytes"
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

// Load content schema without the configuration catalog or its former hidden
// placeholders so each install test exercises a real first registration.
func configurationBaseRegistry(t *testing.T) *Registry {
	t.Helper()
	registry := NewRegistry()
	for _, description := range builtinAttributeTypes {
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			t.Fatal(err)
		}
	}
	for _, description := range builtinObjectClasses {
		if err := registry.ParseAndRegisterObjectClass(description); err != nil {
			t.Fatal(err)
		}
	}
	return registry
}

func configurationAttribute(t *testing.T, name string) AttributeType {
	t.Helper()
	for _, description := range openLDAPConfigurationAttributeTypes {
		attribute, err := ParseAttributeType(description)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(attribute.Names, name) {
			return attribute
		}
	}
	t.Fatalf("missing configuration attribute %s", name)
	return AttributeType{}
}

func configurationClass(t *testing.T, name string) ObjectClass {
	t.Helper()
	for _, description := range openLDAPConfigurationObjectClasses {
		class, err := ParseObjectClass(description)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(class.Names, name) {
			return class
		}
	}
	t.Fatalf("missing configuration class %s", name)
	return ObjectClass{}
}

func TestOpenLDAPConfigurationCatalogAndClosure(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if len(openLDAPConfigurationAttributeTypes) != 111 || len(openLDAPConfigurationObjectClasses) != 9 {
		t.Fatalf("catalog = %d attributes, %d classes; want 111 and 9", len(openLDAPConfigurationAttributeTypes), len(openLDAPConfigurationObjectClasses))
	}
	publicAttributes := make(map[string]bool)
	for _, description := range registry.AttributeTypeDescriptions() {
		attribute, err := ParseAttributeType(description)
		if err != nil {
			t.Fatal(err)
		}
		publicAttributes[attribute.OID] = true
	}
	publicClasses := make(map[string]bool)
	for _, description := range registry.ObjectClassDescriptions() {
		class, err := ParseObjectClass(description)
		if err != nil {
			t.Fatal(err)
		}
		publicClasses[class.OID] = true
	}
	for _, description := range openLDAPConfigurationAttributeTypes {
		want, err := ParseAttributeType(description)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range append([]string{want.OID}, want.Names...) {
			got, ok := registry.AttributeType(strings.ToUpper(key))
			if !ok || !reflect.DeepEqual(got, want) || !publicAttributes[want.OID] {
				t.Errorf("public attribute %s = %#v, want %#v", key, got, want)
			}
		}
		if err := registry.validateConfigurationAttribute(want.OID); err != nil {
			t.Errorf("attribute closure %s: %v", want.Name(), err)
		}
	}
	for _, description := range openLDAPConfigurationObjectClasses {
		want, err := ParseObjectClass(description)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range append([]string{want.OID}, want.Names...) {
			got, ok := registry.ObjectClass(strings.ToUpper(key))
			if !ok || !reflect.DeepEqual(got, want) || !publicClasses[want.OID] {
				t.Errorf("public class %s = %#v, want %#v", key, got, want)
			}
		}
	}
	// Also walk configuration subclasses, including hidden overlay definitions.
	configClass := configurationClass(t, "olcConfig")
	for _, class := range registry.ObjectClasses() {
		closure := make(map[string]*ObjectClass)
		if err := registry.collectObjectClass(&class, closure, make(map[string]bool)); err != nil {
			t.Errorf("class closure %s: %v", class.Name(), err)
			continue
		}
		if closure[configClass.OID] == nil && class.Name() != "olcFrontendConfig" {
			continue
		}
		for _, ancestor := range closure {
			for _, names := range [][]string{ancestor.Must, ancestor.May} {
				for _, name := range names {
					if err := registry.validateConfigurationAttribute(name); err != nil {
						t.Errorf("class %s attribute %s: %v", class.Name(), name, err)
					}
				}
			}
		}
	}
}

func TestOpenLDAPConfigurationRegistrationAliasesAndClones(t *testing.T) {
	registry := configurationBaseRegistry(t)
	attribute := configurationAttribute(t, "olcAccess")
	attribute.Names = append(attribute.Names, "siteAccess")
	attribute.Description = "Site description"
	attribute.Hidden = true
	attribute.Extensions["X-ORIGIN"] = []string{"site"}
	attribute.Extensions["X-SCHEMA-FILE"] = []string{"site.schema"}
	if err := registry.RegisterAttributeType(attribute); err != nil {
		t.Fatal(err)
	}
	class := configurationClass(t, "olcModuleList")
	class.Names = append(class.Names, "siteModuleList")
	class.Hidden = true
	if err := registry.RegisterObjectClass(class); err != nil {
		t.Fatal(err)
	}
	before := registry.Clone()
	for iteration := 0; iteration < 3; iteration++ {
		if err := RegisterOpenLDAPConfigurationSchema(registry); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []string{attribute.OID, "olcAccess", "siteAccess"} {
		got, ok := registry.AttributeType(key)
		if !ok || got.Hidden || got.Description != attribute.Description || !reflect.DeepEqual(got.Names, attribute.Names) || !reflect.DeepEqual(got.Extensions, attribute.Extensions) {
			t.Fatalf("attribute alias %s lost metadata: %#v", key, got)
		}
		if registry.attributes[schemaKey(key)] != registry.attributes[attribute.OID] {
			t.Errorf("attribute alias %s points to another definition", key)
		}
	}
	for _, key := range []string{class.OID, "olcModuleList", "siteModuleList"} {
		got, ok := registry.ObjectClass(key)
		if !ok || got.Hidden || !reflect.DeepEqual(got.Names, class.Names) || registry.objectClasses[schemaKey(key)] != registry.objectClasses[class.OID] {
			t.Fatalf("class alias %s lost metadata: %#v", key, got)
		}
	}
	if !before.attributes[attribute.OID].Hidden || !before.objectClasses[class.OID].Hidden || before.HasAttributeType("olcConnMaxPending") {
		t.Fatal("registration modified an earlier clone")
	}
	installed := registry.Clone()
	if err := RegisterOpenLDAPConfigurationSchema(registry); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(installed.attributes, registry.attributes) || !reflect.DeepEqual(installed.objectClasses, registry.objectClasses) {
		t.Fatal("repeated registration changes definitions")
	}
	installed.attributes[attribute.OID].Names[1] = "changedAlias"
	installed.attributes[attribute.OID].Extensions["X-ORDERED"][0] = "SIBLINGS"
	installed.objectClasses[class.OID].Names[1] = "changedClassAlias"
	installed.objectClasses[class.OID].May[0] = "sn"
	if got := registry.attributes[attribute.OID]; got.Names[1] != "siteAccess" || got.Extensions["X-ORDERED"][0] != "VALUES" {
		t.Fatal("clone mutation reached attribute names/extensions")
	}
	if got := registry.objectClasses[class.OID]; got.Names[1] != "siteModuleList" || got.May[0] != "cn" {
		t.Fatal("clone mutation reached class names/attributes")
	}
}

func TestOpenLDAPConfigurationAcceptsSemanticAliases(t *testing.T) {
	registry := configurationBaseRegistry(t)
	// Preload all definitions using numeric rule and superior identifiers, as a
	// schema importer may do. This must not silently change their behavior.
	for _, description := range openLDAPConfigurationAttributeTypes {
		attribute, err := ParseAttributeType(description)
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range []*string{&attribute.Equality, &attribute.Ordering, &attribute.Substring} {
			if *rule != "" {
				// These native metadata aliases are not executable matchers in
				// the Go catalog; compatible registration must not enable them.
				switch *rule {
				case "certificateExactMatch":
					*rule = "2.5.13.34"
					continue
				case "privateKeyMatch":
					*rule = "1.3.6.1.4.1.4203.666.4.13"
					continue
				}
				definition, ok := BuiltinMatchingRule(*rule)
				if !ok {
					t.Fatalf("unknown catalog matching rule %s", *rule)
				}
				*rule = definition.OID
			}
		}
		if attribute.Superior != "" {
			if parent, ok := registry.AttributeType(attribute.Superior); ok {
				attribute.Superior = parent.OID
			} else {
				t.Fatalf("missing catalog superior %s", attribute.Superior)
			}
		}
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	for _, description := range openLDAPConfigurationObjectClasses {
		class, err := ParseObjectClass(description)
		if err != nil {
			t.Fatal(err)
		}
		for index, name := range class.Superiors {
			parent, ok := registry.ObjectClass(name)
			if !ok {
				t.Fatalf("missing catalog parent class %s", name)
			}
			class.Superiors[index] = parent.OID
		}
		for _, names := range [][]string{class.Must, class.May} {
			for index, name := range names {
				attribute, ok := registry.AttributeType(name)
				if !ok {
					t.Fatalf("missing class attribute %s", name)
				}
				names[index] = attribute.OID
			}
			slices.Reverse(names)
		}
		if err := registry.RegisterObjectClass(class); err != nil {
			t.Fatal(err)
		}
	}
	before := registry.Clone()
	if err := RegisterOpenLDAPConfigurationSchema(registry); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before.attributes, registry.attributes) || !reflect.DeepEqual(before.objectClasses, registry.objectClasses) {
		t.Fatal("compatible registration rewrote preloaded semantic aliases")
	}
	for _, name := range []string{"olcTLSCACertificate", "olcTLSCertificate", "olcTLSCertificateKey"} {
		if _, err := registry.Compare(name, "", []byte("invalid DER"), []byte("invalid DER")); err == nil {
			t.Errorf("metadata registration enabled an unsupported matcher on %s", name)
		}
	}
}

func TestOpenLDAPConfigurationConflictRollback(t *testing.T) {
	attributeCases := []struct {
		name   string
		mutate func(*AttributeType)
	}{
		{"OID", func(a *AttributeType) { a.OID += ".9" }},
		{"canonical name", func(a *AttributeType) { a.Names = append([]string{"renamedRootPW"}, a.Names...) }},
		{"equality", func(a *AttributeType) { a.Equality = "caseIgnoreMatch" }},
		{"superior", func(a *AttributeType) { a.Superior = "labeledURI" }},
		{"ordering", func(a *AttributeType) { a.Ordering = "octetStringOrderingMatch" }},
		{"substring", func(a *AttributeType) { a.Substring = "octetStringSubstringsMatch" }},
		{"syntax", func(a *AttributeType) { a.Syntax = SyntaxDirectoryString }},
		{"length", func(a *AttributeType) { a.SyntaxLength = 12 }},
		{"single value", func(a *AttributeType) { a.SingleValue = false }},
		{"obsolete", func(a *AttributeType) { a.Obsolete = true }},
		{"usage", func(a *AttributeType) { a.Usage = UsageDSAOperation }},
		{"modification", func(a *AttributeType) { a.NoUserModification = true }},
		{"new behavior extension", func(a *AttributeType) { a.Extensions = map[string][]string{"X-ORDERED": {"VALUES"}} }},
	}
	for _, test := range attributeCases {
		t.Run("attribute/"+test.name, func(t *testing.T) {
			registry := configurationBaseRegistry(t)
			attribute := configurationAttribute(t, "olcRootPW")
			test.mutate(&attribute)
			attribute.Hidden = true
			if err := registry.RegisterAttributeType(attribute); err != nil {
				t.Fatal(err)
			}
			assertConfigurationRollback(t, registry)
		})
	}
	classCases := []struct {
		name   string
		mutate func(*ObjectClass)
	}{
		{"OID", func(c *ObjectClass) { c.OID += ".9" }},
		{"canonical name", func(c *ObjectClass) { c.Names = append([]string{"renamedModuleList"}, c.Names...) }},
		{"kind", func(c *ObjectClass) { c.Kind = ObjectClassAuxiliary }},
		{"superior", func(c *ObjectClass) { c.Superiors = []string{"top"} }},
		{"must", func(c *ObjectClass) { c.Must = []string{"cn"} }},
		{"may", func(c *ObjectClass) { c.May = append(c.May, "description") }},
		{"obsolete", func(c *ObjectClass) { c.Obsolete = true }},
		{"extension", func(c *ObjectClass) { c.Extensions = map[string][]string{"X-ORDERED": {"SIBLINGS"}} }},
	}
	for _, test := range classCases {
		t.Run("class/"+test.name, func(t *testing.T) {
			registry := configurationBaseRegistry(t)
			class := configurationClass(t, "olcModuleList")
			test.mutate(&class)
			class.Hidden = true
			if err := registry.RegisterObjectClass(class); err != nil {
				t.Fatal(err)
			}
			assertConfigurationRollback(t, registry)
		})
	}
	for _, kind := range []string{"attribute", "class"} {
		t.Run(kind+"/split identifiers", func(t *testing.T) {
			registry := configurationBaseRegistry(t)
			if kind == "attribute" {
				byOID := configurationAttribute(t, "olcRootPW")
				byName := cloneAttributeType(byOID)
				byOID.Names = []string{"otherRootPassword"}
				byName.OID += ".99"
				byOID.Hidden, byName.Hidden = true, true
				for _, attribute := range []AttributeType{byOID, byName} {
					if err := registry.RegisterAttributeType(attribute); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				byOID := configurationClass(t, "olcModuleList")
				byName := cloneObjectClass(byOID)
				byOID.Names = []string{"otherModuleList"}
				byName.OID += ".99"
				byOID.Hidden, byName.Hidden = true, true
				for _, class := range []ObjectClass{byOID, byName} {
					if err := registry.RegisterObjectClass(class); err != nil {
						t.Fatal(err)
					}
				}
			}
			assertConfigurationRollback(t, registry)
		})
	}
	t.Run("hidden legacy alias collision", func(t *testing.T) {
		registry := configurationBaseRegistry(t)
		if err := registry.RegisterAttributeType(AttributeType{
			OID: "1.3.6.1.4.1.99999.99.999", Names: []string{"siteBoolean", "olcMirrorMode"},
			Syntax: SyntaxBoolean, Equality: "booleanMatch", Hidden: true,
		}); err != nil {
			t.Fatal(err)
		}
		assertConfigurationRollback(t, registry)
	})
	for _, values := range [][]string{nil, {"SIBLINGS"}, {"VALUES", "SIBLINGS"}} {
		t.Run(fmt.Sprintf("ordered extension/%v", values), func(t *testing.T) {
			registry := configurationBaseRegistry(t)
			attribute := configurationAttribute(t, "olcAccess")
			attribute.Extensions = nil
			if values != nil {
				attribute.Extensions = map[string][]string{"X-ORDERED": values}
			}
			if err := registry.RegisterAttributeType(attribute); err != nil {
				t.Fatal(err)
			}
			assertConfigurationRollback(t, registry)
		})
	}
}

func assertConfigurationRollback(t *testing.T, registry *Registry) {
	t.Helper()
	// A failure after this early compatible declaration must not publish it.
	if !registry.HasAttributeType("olcModulePath") {
		attribute := configurationAttribute(t, "olcModulePath")
		attribute.Hidden = true
		attribute.Description = ""
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	before := registry.Clone()
	if err := RegisterOpenLDAPConfigurationSchema(registry); err == nil {
		t.Fatal("accepted conflicting or incomplete configuration schema")
	}
	if !reflect.DeepEqual(before.attributes, registry.attributes) || !reflect.DeepEqual(before.objectClasses, registry.objectClasses) {
		t.Fatal("failed install changed a definition, alias, visibility, or published a partial catalog")
	}
}

func TestOpenLDAPConfigurationDependencyFailures(t *testing.T) {
	if err := RegisterOpenLDAPConfigurationSchema(nil); err == nil {
		t.Fatal("nil registry accepted")
	}
	for _, dependency := range []string{"top", "objectClass", "cn", "name", "labeledURI"} {
		t.Run("missing/"+dependency, func(t *testing.T) {
			registry := configurationBaseRegistry(t)
			if class, ok := registry.ObjectClass(dependency); ok {
				for _, key := range schemaKeys(class.OID, class.Names) {
					delete(registry.objectClasses, key)
				}
			} else if attribute, ok := registry.AttributeType(dependency); ok {
				for _, key := range schemaKeys(attribute.OID, attribute.Names) {
					delete(registry.attributes, key)
				}
			} else {
				t.Fatalf("missing fixture dependency %s", dependency)
			}
			assertConfigurationRollback(t, registry)
		})
	}
	for _, dependency := range []string{"attribute cycle", "class cycle", "missing syntax"} {
		t.Run(dependency, func(t *testing.T) {
			registry := configurationBaseRegistry(t)
			switch dependency {
			case "attribute cycle":
				registry.attributes["labeleduri"].Superior = "labeledURI"
			case "class cycle":
				registry.objectClasses["top"].Superiors = []string{"olcConfig"}
			case "missing syntax":
				delete(registry.syntaxes, SyntaxPKCS8PrivateKey)
			}
			assertConfigurationRollback(t, registry)
		})
	}
}

func TestOpenLDAPConfigurationRegistrationPreservesMatching(t *testing.T) {
	registry := configurationBaseRegistry(t)
	for _, description := range builtinHiddenAttributeTypes {
		attribute, err := ParseAttributeType(description)
		if err != nil {
			t.Fatal(err)
		}
		attribute.Hidden = true
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	before := registry.Clone()
	if err := RegisterOpenLDAPConfigurationSchema(registry); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, left, right string
		equal             bool
	}{
		{"olcAccess", "{0}TO * BY * READ", "to * by * read", true},
		{"olcAccess", "{0}to * by * read", "{1}to * by * read", false},
		{"olcAuthzRegexp", "{1}UID=([^,]+) uid=$1", "uid=([^,]+) uid=$1", true},
		{"olcBackend", "MDB", "mdb", true},
		{"olcDatabase", "{1}MDB", "{1}mdb", true},
		{"olcDatabase", "{1}mdb", "{2}mdb", false},
		{"olcOverlay", "{0}SYNCProv", "{0}syncprov", true},
		{"olcModulePath", "/usr/Lib", "/usr/lib", false},
		{"olcLogLevel", "STATS", "stats", true},
		{"cn", " Alice  Example ", "alice example", true},
		{"uidNumber", "12", "13", false},
		{"userPassword", "AbC", "abc", false},
	}
	for _, test := range tests {
		t.Run(test.name+"/"+test.right, func(t *testing.T) {
			oldResult, oldError := before.Compare(test.name, "", []byte(test.left), []byte(test.right))
			newResult, newError := registry.Compare(test.name, "", []byte(test.left), []byte(test.right))
			if oldError != nil || newError != nil || oldResult != newResult || (newResult == 0) != test.equal {
				t.Fatalf("Compare before %d/%v after %d/%v, equal=%t", oldResult, oldError, newResult, newError, test.equal)
			}
			oldKey, oldError := before.NormalizeEqualityValue(test.name, []byte(test.left))
			newKey, newError := registry.NormalizeEqualityValue(test.name, []byte(test.left))
			if oldError != nil || newError != nil || !bytes.Equal(oldKey, newKey) {
				t.Fatalf("equality key changed: %q/%v -> %q/%v", oldKey, oldError, newKey, newError)
			}
		})
	}
	// Installing the core catalog must not expose unrelated hidden definitions.
	configurationOIDs := make(map[string]bool)
	for _, description := range openLDAPConfigurationAttributeTypes {
		attribute, err := ParseAttributeType(description)
		if err != nil {
			t.Fatal(err)
		}
		configurationOIDs[attribute.OID] = true
	}
	for key, old := range before.attributes {
		if !configurationOIDs[old.OID] {
			if got := registry.attributes[key]; !reflect.DeepEqual(got, old) {
				t.Errorf("unrelated hidden definition %s changed", key)
			}
		}
	}
}

func TestOpenLDAPConfigurationConcurrentRegistration(t *testing.T) {
	registry := configurationBaseRegistry(t)
	const count = 12
	errors := make(chan error, count*2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index := 0; index < count; index++ {
		workers.Add(2)
		go func() {
			defer workers.Done()
			<-start
			errors <- RegisterOpenLDAPConfigurationSchema(registry)
		}()
		go func() {
			defer workers.Done()
			<-start
			errors <- registry.RegisterAttributeType(AttributeType{
				OID: fmt.Sprintf("1.3.6.1.4.1.99999.99.%d", index), Names: []string{fmt.Sprintf("siteValue%d", index)}, Syntax: SyntaxDirectoryString,
			})
		}()
	}
	close(start)
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < count; index++ {
		if !registry.HasAttributeType(fmt.Sprintf("siteValue%d", index)) {
			t.Fatalf("concurrent registration %d was lost", index)
		}
	}
	if !registry.HasAttributeType("olcWriteTimeout") {
		t.Fatal("configuration registration lost")
	}
}

func TestOpenLDAPConfigurationSchemaEntries(t *testing.T) {
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	entry := directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: byteValues("olcDatabaseConfig")},
			{Description: "olcDatabase", Values: byteValues("{1}mdb")},
			{Description: "olcRootDN", Values: byteValues("cn=admin,dc=example,dc=com")},
			{Description: "olcRootPW", Values: [][]byte{{0, 0xff, 'P'}}},
			{Description: "olcMirrorMode", Values: byteValues("TRUE")},
		},
	}
	if err := registry.ValidateEntry(entry); err != nil {
		t.Fatal(err)
	}
	assertViolation(t, registry.ValidateEntry(entry.Without("olcDatabase")), ViolationMissingRequiredAttribute)
	invalid := entry.Clone()
	invalid.ReplaceValues("olcRootPW", byteValues("one", "two"))
	assertViolation(t, registry.ValidateEntry(invalid), ViolationSingleValue)
	invalid = entry.Clone()
	invalid.ReplaceValues("olcMirrorMode", byteValues("yes"))
	assertViolation(t, registry.ValidateEntry(invalid), ViolationSyntax)
	for _, name := range []string{"olcMirrorMode", "olcMultiProvider", "1.3.6.1.4.1.4203.1.12.2.3.2.0.16"} {
		if result, err := registry.Compare(name, "", []byte("TRUE"), []byte("TRUE")); err != nil || result != 0 {
			t.Errorf("boolean alias %s: %d/%v", name, result, err)
		}
	}
}

func TestOpenLDAPConfigurationPinnedSource(t *testing.T) {
	root := os.Getenv("OPENLDAP_SOURCE")
	if root == "" {
		t.Skip("set OPENLDAP_SOURCE to a Git checkout containing the OpenLDAP 2.6.13 pin")
	}
	const pin = "d172686d3d270bc961b78f3ff00d7019c8dfb094"
	data, err := exec.Command("git", "-C", root, "show", pin+":servers/slapd/bconfig.c").CombinedOutput()
	if err != nil {
		t.Fatalf("read pinned bconfig.c: %v: %s", err, data)
	}
	source := string(data)
	section := func(marker string) string {
		t.Helper()
		_, body, ok := strings.Cut(source, marker)
		if !ok {
			t.Fatalf("missing native table %s", marker)
		}
		body, _, ok = strings.Cut(body, "\n};")
		if !ok {
			t.Fatalf("unterminated native table %s", marker)
		}
		return body
	}
	macros := make(map[string]string)
	for _, pair := range regexp.MustCompile(`\{\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\}`).FindAllStringSubmatch(section("static OidRec OidMacros[] = {"), -1) {
		value := pair[2]
		if prefix, suffix, ok := strings.Cut(value, ":"); ok {
			base, exists := macros[prefix]
			if !exists {
				t.Fatalf("unresolved native OID macro %s", prefix)
			}
			value = base + "." + suffix
		}
		macros[pair[1]] = value
	}
	if len(macros) != 21 {
		t.Fatalf("native OID macros = %d, want 21", len(macros))
	}
	quoted := regexp.MustCompile(`"(?:\\.|[^"\\])*"`)
	groups := regexp.MustCompile(`(?:"(?:\\.|[^"\\])*"\s*)+`)
	macroToken := regexp.MustCompile(`\b(?:OLcfg[A-Za-z]*|OMs[A-Za-z]*)(?::[0-9.]+)?\b`)
	extract := func(body string) []string {
		t.Helper()
		var definitions []string
		for _, group := range groups.FindAllString(body, -1) {
			var joined strings.Builder
			for _, literal := range quoted.FindAllString(group, -1) {
				value, err := strconv.Unquote(literal)
				if err != nil {
					t.Fatal(err)
				}
				joined.WriteString(value)
			}
			value := joined.String()
			if !strings.HasPrefix(value, "( OLcfg") {
				continue
			}
			value = macroToken.ReplaceAllStringFunc(value, func(token string) string {
				prefix, suffix, hasSuffix := strings.Cut(token, ":")
				base, ok := macros[prefix]
				if !ok {
					t.Fatalf("unknown native macro %s", token)
				}
				if hasSuffix {
					return base + "." + suffix
				}
				return base
			})
			definitions = append(definitions, value)
		}
		return definitions
	}
	// Conditional handlers do not hide their schema strings in this table.
	attributes := extract(section("static ConfigTable config_back_cf_table[] = {"))
	classes := extract(section("static ConfigOCs cf_ocs[] = {"))
	if len(attributes) != 111 || len(classes) != 9 || len(attributes) != len(openLDAPConfigurationAttributeTypes) || len(classes) != len(openLDAPConfigurationObjectClasses) {
		t.Fatalf("extracted native definitions = %d attributes, %d classes", len(attributes), len(classes))
	}
	for index, description := range attributes {
		want, err := ParseAttributeType(description)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseAttributeType(openLDAPConfigurationAttributeTypes[index])
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("native attribute %s differs:\ngot  %#v\nwant %#v", want.Name(), got, want)
		}
	}
	for index, description := range classes {
		want, err := ParseObjectClass(description)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseObjectClass(openLDAPConfigurationObjectClasses[index])
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("native class %s differs:\ngot  %#v\nwant %#v", want.Name(), got, want)
		}
	}
	dummy := extract(section("ConfigTable olcDatabaseDummy[] = {"))
	if len(dummy) != 1 {
		t.Fatalf("native database dummy definitions = %d", len(dummy))
	}
	dummyAttribute, err := ParseAttributeType(dummy[0])
	if err != nil || !reflect.DeepEqual(dummyAttribute, configurationAttribute(t, "olcDatabase")) {
		t.Fatalf("native dummy introduced another attribute: %#v/%v", dummyAttribute, err)
	}
	data, err = exec.Command("git", "-C", root, "show", pin+":servers/slapd/schema_init.c").CombinedOutput()
	if err != nil {
		t.Fatalf("read pinned schema_init.c: %v: %s", err, data)
	}
	for _, definition := range []string{
		"( 2.5.13.34 NAME 'certificateExactMatch' ",
		"( 1.3.6.1.4.1.4203.666.4.13 NAME 'privateKeyMatch' ",
	} {
		if !strings.Contains(string(data), strconv.Quote(definition)) {
			t.Errorf("native matching rule alias missing: %s", definition)
		}
	}
	// This is a Git-object metadata contract. Live subschema visibility and
	// request behavior are tested separately against the native server.
}
