package server

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const matchingRulesReferenceCommit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

// This fixture deliberately includes attributes with no configured matching
// rule. mr.c derives APPLIES from usable syntax, its superclasses, equality,
// and compatibility syntax; grouping configured EQUALITY/ORDERING/SUBSTR
// values would produce a substantially different subschema.
func matchingRulesReferenceAttributes() []string {
	return []string{
		"( 1.3.6.1.4.1.4203.666.11.99.810.1 NAME ( 'mrRefDirectory' 'mrRefDirectoryAlias' ) EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 1.3.6.1.4.1.4203.666.11.99.810.2 NAME 'mrRefDirectoryBare' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 1.3.6.1.4.1.4203.666.11.99.810.3 NAME 'mrRefIA5' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		"( 1.3.6.1.4.1.4203.666.11.99.810.4 NAME 'mrRefIA5Bare' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		"( 1.3.6.1.4.1.4203.666.11.99.810.5 NAME 'mrRefPrintable' SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )",
		"( 1.3.6.1.4.1.4203.666.11.99.810.6 NAME 'mrRefDN' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		"( 1.3.6.1.4.1.4203.666.11.99.810.7 NAME 'mrRefAttributeDescription' EQUALITY objectIdentifierFirstComponentMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.3 )",
		"( 1.3.6.1.4.1.4203.666.11.99.810.8 NAME 'mrRefMatchingDescription' SYNTAX 1.3.6.1.4.1.1466.115.121.1.30 )",
		"( 1.3.6.1.4.1.4203.666.11.99.810.9 NAME 'mrRefUseDescription' SYNTAX 1.3.6.1.4.1.1466.115.121.1.31 )",
		"( 1.3.6.1.4.1.4203.666.11.99.810.10 NAME 'mrRefInteger' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		"( 1.3.6.1.4.1.4203.666.11.99.810.11 NAME 'mrRefIntegerBare' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		"( 1.3.6.1.4.1.4203.666.11.99.810.12 NAME 'mrRefOctet' EQUALITY octetStringMatch SUBSTR octetStringSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
		"( 1.3.6.1.4.1.4203.666.11.99.810.13 NAME 'mrRefInherited' SUP mrRefDirectory )",
		"( 1.3.6.1.4.1.4203.666.11.99.810.14 NAME 'mrRefInheritedTwice' SUP mrRefInherited )",
		"( 1.3.6.1.4.1.4203.666.11.99.810.15 NAME 'mrRefCountry' SYNTAX 1.3.6.1.4.1.1466.115.121.1.11 )",
		"( 1.3.6.1.4.1.4203.666.11.99.810.16 NAME 'mrRefObjectIdentifier' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
	}
}

func requireMatchingRulesReference(t *testing.T) openLDAPReferenceTools {
	t.Helper()
	if os.Getenv(openLDAPReferenceTestsEnv) != "1" {
		t.Skipf("set %s=1 and load the pinned OpenLDAP reference environment", openLDAPReferenceTestsEnv)
	}
	if os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" || os.Getenv("OPENLDAP_COMMIT") != matchingRulesReferenceCommit || os.Getenv("OPENLDAP_VERIFIED_COMMIT") != matchingRulesReferenceCommit {
		t.Fatal("matching-rule differential requires the verified OpenLDAP 2.6.13 build")
	}
	// Check prerequisites before the shared helper, which may otherwise skip.
	for _, key := range []string{"OPENLDAP_SLAPD", "OPENLDAP_SLAPADD", "OPENLDAP_SOURCE", "OPENLDAP_SCHEMA_DIR"} {
		if os.Getenv(key) == "" {
			t.Fatalf("enabled reference test requires %s", key)
		}
		if _, err := os.Stat(os.Getenv(key)); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
	}
	for _, name := range []string{"core.schema", "cosine.schema", "inetorgperson.schema"} {
		if _, err := os.Stat(filepath.Join(os.Getenv("OPENLDAP_SCHEMA_DIR"), name)); err != nil {
			t.Fatal(err)
		}
	}
	for file, hash := range map[string]string{
		"mr.c":          "74767b71f66c676022a11d6d604eb77addb8699e2a3ae83c1cead0ba1cb4903f",
		"schema_init.c": "99b997916f864fd56b11536a41b373dff69f39fb28516fe1f896bf82c2015a03",
		"schema_prep.c": "7ef51e04ce5342da36e44ea71580d5191ae3eb1b5616ae9da90d1633f25bbe20",
	} {
		data, err := os.ReadFile(filepath.Join(os.Getenv("OPENLDAP_SOURCE"), "servers", "slapd", file))
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != hash {
			t.Fatalf("%s must match commit %s: %v", file, matchingRulesReferenceCommit, err)
		}
	}
	tools := requireOpenLDAPReferenceTools(t)
	version, err := exec.CommandContext(t.Context(), tools.slapd, "-VV").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "slapd 2.6.13") {
		t.Fatalf("reference slapd version: %v: %s", err, version)
	}
	return tools
}

func matchingRulesReferenceACL() []string {
	return []string{
		`to dn.exact="cn=Subschema" attrs=matchingRules by dn.exact="cn=rules-hidden,dc=example,dc=com" none by * read`,
		`to dn.exact="cn=Subschema" attrs=matchingRuleUse by dn.exact="cn=uses-hidden,dc=example,dc=com" none by * read`,
		`to * by * read`,
	}
}

func matchingRulesReferenceGoServer(t *testing.T) string {
	t.Helper()
	var config strings.Builder
	config.WriteString("dn: cn=config\nobjectClass: olcGlobal\ncn: config\n\ndn: cn=schema,cn=config\nobjectClass: olcSchemaConfig\ncn: schema\n\ndn: cn={9}matching-reference,cn=schema,cn=config\nobjectClass: olcSchemaConfig\ncn: {9}matching-reference\n")
	for _, definition := range matchingRulesReferenceAttributes() {
		fmt.Fprintln(&config, "olcAttributeTypes:", definition)
	}
	config.WriteString("\ndn: olcDatabase={-1}frontend,cn=config\nobjectClass: olcDatabaseConfig\nobjectClass: olcFrontendConfig\nolcDatabase: {-1}frontend\n")
	for i, rule := range matchingRulesReferenceACL() {
		fmt.Fprintf(&config, "olcAccess: {%d}%s\n", i, rule)
	}
	config.WriteString("\ndn: olcDatabase={1}mdb,cn=config\nobjectClass: olcDatabaseConfig\nobjectClass: olcMdbConfig\nolcDatabase: {1}mdb\nolcSuffix: dc=example,dc=com\nolcRootDN: cn=admin,dc=example,dc=com\nolcRootPW: secret\n\ndn: dc=example,dc=com\nobjectClass: top\nobjectClass: domain\ndc: example\n\n")
	config.WriteString(matchingRulesReferenceSeed())
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := migration.ImportLDIF(t.Context(), store, strings.NewReader(config.String()), migration.ImportOptions{SkipSchemaValidation: true}); err != nil {
		t.Fatal(err)
	}
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	return "ldap://" + address
}

func matchingRulesReferenceSeed() string {
	var result strings.Builder
	for _, name := range []string{"rules-hidden", "uses-hidden"} {
		fmt.Fprintf(&result, "dn: cn=%s,dc=example,dc=com\nobjectClass: person\ncn: %s\nsn: Reader\nuserPassword: secret\n\n", name, name)
	}
	return result.String()
}

type matchingRulesReferenceDescription struct {
	OID, Syntax, Description string
	Names, Applies           []string
	Obsolete                 bool
}

// This parser is deliberately independent of the production schema parser.
// Only the schema-set ordering of NAME and APPLIES is normalized; OIDs,
// canonical names, descriptions, and assertion syntaxes remain exact.
var matchingRulesReferenceTokens = regexp.MustCompile(`'[^']*'|[()]|\$|[^\s()$]+`)

func matchingRulesReferenceParse(t *testing.T, value string, use bool) matchingRulesReferenceDescription {
	t.Helper()
	tokens := matchingRulesReferenceTokens.FindAllString(value, -1)
	if len(tokens) < 5 || tokens[0] != "(" || tokens[len(tokens)-1] != ")" {
		t.Fatalf("invalid native schema description: %q", value)
	}
	result := matchingRulesReferenceDescription{OID: tokens[1]}
	tokens = tokens[2 : len(tokens)-1]
	unquote := func(token string) string {
		if len(token) < 2 || token[0] != '\'' || token[len(token)-1] != '\'' {
			t.Fatalf("expected quoted schema value in %q", value)
		}
		return token[1 : len(token)-1]
	}
	seen := map[string]bool{}
	for len(tokens) > 0 {
		keyword := tokens[0]
		tokens = tokens[1:]
		if seen[keyword] {
			t.Fatalf("duplicate %s in %q", keyword, value)
		}
		seen[keyword] = true
		if keyword == "OBSOLETE" {
			result.Obsolete = true
			continue
		}
		if len(tokens) == 0 {
			t.Fatalf("missing %s value in %q", keyword, value)
		}
		switch keyword {
		case "NAME", "APPLIES":
			var values []string
			if tokens[0] == "(" {
				tokens = tokens[1:]
				for len(tokens) > 0 && tokens[0] != ")" {
					if tokens[0] != "$" {
						values = append(values, tokens[0])
					}
					tokens = tokens[1:]
				}
				if len(tokens) == 0 {
					t.Fatalf("unterminated %s list in %q", keyword, value)
				}
				tokens = tokens[1:]
			} else {
				values = append(values, tokens[0])
				tokens = tokens[1:]
			}
			if keyword == "NAME" {
				for i := range values {
					values[i] = unquote(values[i])
				}
				result.Names = values
			} else {
				result.Applies = values
			}
			slices.Sort(values)
			if len(slices.Compact(slices.Clone(values))) != len(values) {
				t.Fatalf("duplicate %s member in %q", keyword, value)
			}
		case "SYNTAX":
			result.Syntax, tokens = tokens[0], tokens[1:]
		case "DESC":
			result.Description, tokens = unquote(tokens[0]), tokens[1:]
		default:
			t.Fatalf("unhandled schema field %q in %q", keyword, value)
		}
	}
	if use && (len(result.Applies) == 0 || result.Syntax != "") || !use && (result.Syntax == "" || len(result.Applies) != 0) {
		t.Fatalf("wrong schema description kind (use=%v): %q", use, value)
	}
	return result
}

func matchingRulesReferenceCatalog(t *testing.T, values []string, use bool) map[string]matchingRulesReferenceDescription {
	t.Helper()
	result := make(map[string]matchingRulesReferenceDescription, len(values))
	for _, value := range values {
		description := matchingRulesReferenceParse(t, value, use)
		if _, duplicate := result[description.OID]; duplicate {
			t.Fatalf("duplicate matching-rule OID %s", description.OID)
		}
		result[description.OID] = description
	}
	return result
}

func matchingRulesReferenceFixtureApplies(description matchingRulesReferenceDescription) []string {
	var values []string
	for _, name := range description.Applies {
		if strings.HasPrefix(name, "mrRef") || strings.HasPrefix(name, "1.3.6.1.4.1.4203.666.11.99.810.") {
			values = append(values, name)
		}
	}
	return values
}

type matchingRulesReferenceObservation struct {
	Code    uint16
	Entries int
	Values  map[string][]string
}

func matchingRulesReferenceCode(t *testing.T, err error) uint16 {
	t.Helper()
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	if result, ok := err.(*ldap.Error); ok {
		return result.ResultCode
	}
	t.Fatalf("non-LDAP error: %v", err)
	return 0
}

func matchingRulesReferenceConnect(t *testing.T, uri, identity string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri, ldap.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	client.SetTimeout(5 * time.Second)
	if identity != "" {
		if err := client.Bind("cn="+identity+",dc=example,dc=com", "secret"); err != nil {
			t.Fatal(err)
		}
	}
	return client
}

func matchingRulesReferenceSearch(t *testing.T, client *ldap.Conn, filter string, attrs []string, typesOnly bool) matchingRulesReferenceObservation {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest("cn=Subschema", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, typesOnly, filter, attrs, nil))
	observation := matchingRulesReferenceObservation{Code: matchingRulesReferenceCode(t, err), Values: map[string][]string{}}
	if result == nil {
		return observation
	}
	observation.Entries = len(result.Entries)
	for _, entry := range result.Entries {
		for _, attribute := range entry.Attributes {
			if strings.EqualFold(attribute.Name, "matchingRules") || strings.EqualFold(attribute.Name, "matchingRuleUse") {
				if _, duplicate := observation.Values[attribute.Name]; duplicate {
					t.Fatalf("duplicate schema attribute %s", attribute.Name)
				}
				observation.Values[attribute.Name] = slices.Clone(attribute.Values)
			}
		}
	}
	return observation
}

func matchingRulesReferenceCompare(t *testing.T, client *ldap.Conn, attribute, assertion string) matchingRulesReferenceObservation {
	t.Helper()
	matched, err := client.Compare("cn=Subschema", attribute, assertion)
	code := matchingRulesReferenceCode(t, err)
	if err == nil {
		code = ldap.LDAPResultCompareFalse
		if matched {
			code = ldap.LDAPResultCompareTrue
		}
	}
	return matchingRulesReferenceObservation{Code: code}
}

func matchingRulesReferenceObserve(t *testing.T, uri string) map[string]matchingRulesReferenceObservation {
	t.Helper()
	client := matchingRulesReferenceConnect(t, uri, "")
	observations := map[string]matchingRulesReferenceObservation{}
	for _, test := range []struct {
		name      string
		attrs     []string
		typesOnly bool
		want      []string
	}{
		{"explicit", []string{"matchingRules", "matchingRuleUse"}, false, []string{"matchingRules", "matchingRuleUse"}},
		{"OID", []string{"2.5.21.4", "2.5.21.8"}, false, []string{"matchingRules", "matchingRuleUse"}},
		{"case-folded", []string{"MATCHINGRULES", "matchingruleuse"}, false, []string{"matchingRules", "matchingRuleUse"}},
		{"rules-only", []string{"matchingRules"}, false, []string{"matchingRules"}},
		{"uses-only", []string{"matchingRuleUse"}, false, []string{"matchingRuleUse"}},
		{"default", nil, false, nil},
		{"star", []string{"*"}, false, nil},
		{"none", []string{"1.1"}, false, nil},
		{"plus", []string{"+"}, false, []string{"matchingRules", "matchingRuleUse"}},
		{"star-plus", []string{"*", "+"}, false, []string{"matchingRules", "matchingRuleUse"}},
		{"none-explicit", []string{"1.1", "matchingRules"}, false, []string{"matchingRules"}},
		{"types-only", []string{"matchingRules", "matchingRuleUse"}, true, []string{"matchingRules", "matchingRuleUse"}},
		{"types-only-OID", []string{"2.5.21.4", "2.5.21.8"}, true, []string{"matchingRules", "matchingRuleUse"}},
		{"types-only-plus", []string{"+"}, true, []string{"matchingRules", "matchingRuleUse"}},
	} {
		t.Run("select-"+test.name, func(t *testing.T) {
			got := matchingRulesReferenceSearch(t, client, "(objectClass=*)", test.attrs, test.typesOnly)
			observations["select-"+test.name] = got
			if got.Code != 0 || got.Entries != 1 || len(got.Values) != len(test.want) {
				t.Errorf("selection: code=%d entries=%d attributes=%d; want 0/1/%v", got.Code, got.Entries, len(got.Values), test.want)
			}
			for _, name := range test.want {
				values, present := got.Values[name]
				if !present || (len(values) == 0) != test.typesOnly {
					t.Errorf("%s: present=%v values=%d typesOnly=%v", name, present, len(values), test.typesOnly)
				}
			}
		})
	}
	for _, attribute := range []string{"matchingRules", "2.5.21.4", "matchingRuleUse", "2.5.21.8"} {
		for _, assertion := range []string{
			"2.5.13.2", "caseIgnoreMatch", "CASEIGNOREMATCH",
			"2.5.13.4", "caseIgnoreSubstringsMatch",
			"1.3.6.1.4.1.1466.109.114.3", "caseIgnoreIA5SubstringsMatch",
			"1.3.6.1.4.1.4203.666.4.4", "directoryStringApproxMatch",
			"2.5.13.99999", "1.2.3.999", "noSuchMatchingRule", "noSuchRule",
			"bad rule", " caseIgnoreMatch ", " ", "2.5..13", "",
			"( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		} {
			name := attribute + "=" + assertion
			t.Run("compare-"+name, func(t *testing.T) {
				got := matchingRulesReferenceCompare(t, client, attribute, assertion)
				observations["compare-"+name] = got
				t.Logf("Compare %q = %d", name, got.Code)
			})
			t.Run("filter-"+name, func(t *testing.T) {
				got := matchingRulesReferenceSearch(t, client, "("+attribute+"="+ldap.EscapeFilter(assertion)+")", []string{"1.1"}, false)
				observations["filter-"+name] = got
				t.Logf("filter %q: code=%d entries=%d", name, got.Code, got.Entries)
			})
			t.Run("not-filter-"+name, func(t *testing.T) {
				got := matchingRulesReferenceSearch(t, client, "(!("+attribute+"="+ldap.EscapeFilter(assertion)+"))", []string{"1.1"}, false)
				observations["not-filter-"+name] = got
				t.Logf("NOT filter %q: code=%d entries=%d", name, got.Code, got.Entries)
			})
		}
	}
	for _, identity := range []string{"rules-hidden", "uses-hidden"} {
		t.Run("ACL-"+identity, func(t *testing.T) {
			limited := matchingRulesReferenceConnect(t, uri, identity)
			got := matchingRulesReferenceSearch(t, limited, "(objectClass=*)", []string{"matchingRules", "matchingRuleUse"}, false)
			observations["ACL-"+identity] = got
			hidden, visible := "matchingRules", "matchingRuleUse"
			if identity == "uses-hidden" {
				hidden, visible = visible, hidden
			}
			if got.Code != 0 || got.Entries != 1 || len(got.Values) != 1 || len(got.Values[visible]) == 0 {
				t.Errorf("ACL %s: code=%d entries=%d attributeCount=%d visibleValues=%d", identity, got.Code, got.Entries, len(got.Values), len(got.Values[visible]))
			}
			if _, present := got.Values[hidden]; present {
				t.Errorf("ACL leaked %s", hidden)
			}
			for _, attribute := range []string{hidden, visible} {
				name := "ACL-" + identity + "-" + attribute
				observations[name+"-compare"] = matchingRulesReferenceCompare(t, limited, attribute, "2.5.13.2")
				observations[name+"-filter"] = matchingRulesReferenceSearch(t, limited, "("+attribute+"=2.5.13.2)", []string{"1.1"}, false)
				t.Logf("%s Compare=%d filter=%d/%d", attribute, observations[name+"-compare"].Code, observations[name+"-filter"].Code, observations[name+"-filter"].Entries)
			}
		})
	}
	return observations
}

func matchingRulesReferenceAssertPublished(t *testing.T, uri string, observations map[string]matchingRulesReferenceObservation) {
	t.Helper()
	client := matchingRulesReferenceConnect(t, uri, "")
	for attribute, values := range observations["select-explicit"].Values {
		for oid, description := range matchingRulesReferenceCatalog(t, values, attribute == "matchingRuleUse") {
			for _, assertion := range append([]string{oid}, description.Names...) {
				t.Run("published-"+attribute+"="+assertion, func(t *testing.T) {
					compared := matchingRulesReferenceCompare(t, client, attribute, assertion)
					if compared.Code != ldap.LDAPResultCompareTrue {
						t.Errorf("published rule Compare(%q)=%d, want compareTrue", assertion, compared.Code)
					}
					found := matchingRulesReferenceSearch(t, client, "("+attribute+"="+ldap.EscapeFilter(assertion)+")", []string{"1.1"}, false)
					if found.Code != 0 || found.Entries != 1 {
						t.Errorf("published rule search(%q)=%d/%d, want success/1", assertion, found.Code, found.Entries)
					}
				})
			}
		}
	}
}

func matchingRulesReferenceAssertExpected(t *testing.T, observations map[string]matchingRulesReferenceObservation) {
	t.Helper()
	// The descriptor matcher can return undefined internally; native Compare
	// turns an unrecognized valid rule name into compareFalse, not code 21.
	// OID syntax validation still rejects whitespace and malformed assertions.
	for _, attribute := range []string{"matchingRules", "2.5.21.4", "matchingRuleUse", "2.5.21.8"} {
		for assertion, code := range map[string]uint16{
			"2.5.13.2": 6, "caseIgnoreMatch": 6, "CASEIGNOREMATCH": 6,
			"2.5.13.99999": 5, "1.2.3.999": 5, "noSuchRule": 5, "noSuchMatchingRule": 5,
			"bad rule": 21, " caseIgnoreMatch ": 21, " ": 21, "2.5..13": 21, "": 21,
		} {
			name := attribute + "=" + assertion
			if got := observations["compare-"+name].Code; got != code {
				t.Errorf("native Compare %s = %d, want %d", name, got, code)
			}
			wantEntries := 0
			if code == ldap.LDAPResultCompareTrue {
				wantEntries = 1
			}
			if got := observations["filter-"+name]; got.Code != 0 || got.Entries != wantEntries {
				t.Errorf("native filter %s = %d/%d, want 0/%d", name, got.Code, got.Entries, wantEntries)
			}
			// An unknown numeric OID is False, while an unknown descriptor
			// or malformed assertion is Undefined and stays so under NOT.
			wantNotEntries := 0
			if assertion == "2.5.13.99999" || assertion == "1.2.3.999" {
				wantNotEntries = 1
			}
			if got := observations["not-filter-"+name]; got.Code != 0 || got.Entries != wantNotEntries {
				t.Errorf("native NOT filter %s = %d/%d, want 0/%d", name, got.Code, got.Entries, wantNotEntries)
			}
		}
	}
	full := observations["select-explicit"]
	rules := matchingRulesReferenceCatalog(t, full.Values["matchingRules"], false)
	uses := matchingRulesReferenceCatalog(t, full.Values["matchingRuleUse"], true)
	directory := []string{"mrRefCountry", "mrRefDirectory", "mrRefDirectoryBare", "mrRefInherited", "mrRefInheritedTwice", "mrRefPrintable"}
	for oid, expected := range map[string][]string{
		"2.5.13.2": directory, "2.5.13.3": directory, "2.5.13.5": directory, "2.5.13.6": directory,
		"2.5.13.4": {"mrRefCountry", "mrRefPrintable"}, "2.5.13.7": {"mrRefCountry", "mrRefPrintable"},
		"1.3.6.1.4.1.1466.109.114.1": {"mrRefCountry", "mrRefIA5", "mrRefIA5Bare"},
		"1.3.6.1.4.1.1466.109.114.2": {"mrRefCountry", "mrRefIA5", "mrRefIA5Bare"},
		"2.5.13.1":                   {"mrRefDN"},
		"2.5.13.14":                  {"mrRefInteger", "mrRefIntegerBare"}, "2.5.13.15": {"mrRefInteger", "mrRefIntegerBare"},
		"2.5.13.17": {"mrRefOctet"}, "2.5.13.18": {"mrRefOctet"},
		"2.5.13.30": {"mrRefAttributeDescription", "mrRefMatchingDescription", "mrRefObjectIdentifier", "mrRefUseDescription"},
	} {
		t.Run("native-APPLIES-"+oid, func(t *testing.T) {
			if _, present := rules[oid]; !present {
				t.Fatalf("native rule %s missing", oid)
			}
			got := matchingRulesReferenceFixtureApplies(uses[oid])
			if !slices.Equal(got, expected) {
				t.Errorf("fixture APPLIES %s = %v, want %v", oid, got, expected)
			}
			t.Logf("%s APPLIES %v", oid, got)
		})
	}
	for _, oid := range []string{"2.5.13.10", "2.5.13.12", "2.5.13.19", "2.5.13.21", "1.3.6.1.4.1.1466.109.114.3", "1.3.6.1.4.1.4203.1.2.1"} {
		if _, present := uses[oid]; present {
			t.Errorf("substring rule without MR_EXT/compat must omit matchingRuleUse: %s", oid)
		}
	}
	for _, oid := range []string{"2.5.13.22", "2.5.13.24"} {
		if _, present := rules[oid]; present {
			t.Errorf("rule without a matching function must omit matchingRules: %s", oid)
		}
	}
	for _, name := range []string{"directoryStringApproxMatch", "IA5StringApproxMatch", "dnSubtreeMatch", "dnOneLevelMatch", "dnSubordinateMatch", "dnSuperiorMatch", "CSNMatch", "CSNOrderingMatch", "csnSIDMatch", "authzMatch", "privateKeyMatch", "OpenLDAPaciMatch"} {
		for _, catalog := range []map[string]matchingRulesReferenceDescription{rules, uses} {
			for _, description := range catalog {
				if slices.Contains(description.Names, name) {
					t.Errorf("hidden matching rule published: %s", name)
				}
			}
		}
	}
	t.Logf("observed %d matchingRules and %d matchingRuleUse values", len(rules), len(uses))
}

func matchingRulesReferenceDifferential(t *testing.T, native, implemented map[string]matchingRulesReferenceObservation) {
	t.Helper()
	goRules := matchingRulesReferenceCatalog(t, implemented["select-explicit"].Values["matchingRules"], false)
	if len(goRules) == 0 {
		t.Fatal("Go must publish matchingRules; an empty shared inventory is not parity")
	}
	for _, oid := range []string{"2.5.13.1", "2.5.13.2", "2.5.13.3", "2.5.13.4", "2.5.13.5", "2.5.13.6", "2.5.13.7", "2.5.13.14", "2.5.13.15", "2.5.13.17", "2.5.13.18", "2.5.13.19", "2.5.13.30", "1.3.6.1.4.1.1466.109.114.1", "1.3.6.1.4.1.1466.109.114.2", "1.3.6.1.4.1.1466.109.114.3", "1.3.6.1.4.1.4203.1.2.1"} {
		if _, present := goRules[oid]; !present {
			t.Errorf("implemented fixture matching rule %s must be published", oid)
		}
	}
	for name, want := range native {
		t.Run(name, func(t *testing.T) {
			got, present := implemented[name]
			if !present || got.Code != want.Code || got.Entries != want.Entries || len(got.Values) != len(want.Values) {
				t.Fatalf("Go code=%d entries=%d attributes=%d present=%v; native=%d/%d/%d", got.Code, got.Entries, len(got.Values), present, want.Code, want.Entries, len(want.Values))
			}
			for attribute, values := range got.Values {
				nativeValues, present := want.Values[attribute]
				if !present || (len(values) == 0) != (len(nativeValues) == 0) {
					t.Fatalf("%s: Go values=%d native values=%d present=%v", attribute, len(values), len(nativeValues), present)
				}
				use := attribute == "matchingRuleUse"
				goCatalog := matchingRulesReferenceCatalog(t, values, use)
				nativeCatalog := matchingRulesReferenceCatalog(t, nativeValues, use)
				for oid, actual := range goCatalog {
					expected, known := nativeCatalog[oid]
					if !known {
						t.Errorf("Go publishes %s %s which pinned native does not publish", attribute, oid)
						continue
					}
					if use {
						actual.Applies = matchingRulesReferenceFixtureApplies(actual)
						expected.Applies = matchingRulesReferenceFixtureApplies(expected)
					}
					if !reflect.DeepEqual(actual, expected) {
						t.Errorf("%s %s: Go=%+v native=%+v", attribute, oid, actual, expected)
					}
				}
				if use && len(values) > 0 {
					for oid := range goRules {
						if len(matchingRulesReferenceFixtureApplies(nativeCatalog[oid])) > 0 {
							if _, present := goCatalog[oid]; !present {
								t.Errorf("shared rule %s omits matchingRuleUse despite native fixture APPLIES", oid)
							}
						}
					}
				}
			}
		})
	}
	if len(native) != len(implemented) {
		t.Errorf("observation count native=%d Go=%d", len(native), len(implemented))
	}
	t.Logf("compared %d live SDK operations and all %d Go-published rule descriptors", len(native), len(goRules))
}

func TestOpenLDAPMatchingRulesReference(t *testing.T) {
	tools := requireMatchingRulesReference(t)
	var global strings.Builder
	for _, definition := range matchingRulesReferenceAttributes() {
		fmt.Fprintln(&global, "attributetype", definition)
	}
	global.WriteString("database frontend\n")
	for _, rule := range matchingRulesReferenceACL() {
		fmt.Fprintln(&global, "access", rule)
	}
	uri, stop := startOpenLDAPReferenceServerWithConfig(t, tools, nil, global.String(), "", "\n"+matchingRulesReferenceSeed())
	defer stop()
	var native, implemented map[string]matchingRulesReferenceObservation
	t.Run("native", func(t *testing.T) {
		native = matchingRulesReferenceObserve(t, uri)
		matchingRulesReferenceAssertExpected(t, native)
		matchingRulesReferenceAssertPublished(t, uri, native)
	})
	t.Run("go", func(t *testing.T) {
		uri := matchingRulesReferenceGoServer(t)
		implemented = matchingRulesReferenceObserve(t, uri)
		matchingRulesReferenceAssertPublished(t, uri, implemented)
	})
	t.Run("differential", func(t *testing.T) {
		if native == nil || implemented == nil {
			t.Fatal("differential requires both native and Go observations")
		}
		matchingRulesReferenceDifferential(t, native, implemented)
	})
}
