package server

import (
	"crypto/sha256"
	"encoding/hex"
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

const (
	syntaxPublicationReferenceCommit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"
	syntaxPublicationAttributeOID    = "1.3.6.1.4.1.1466.101.120.16"
	syntaxPublicationStandardPrefix  = "1.3.6.1.4.1.1466.115.121.1."
	syntaxPublicationFixturePrefix   = "1.3.6.1.4.1.4203.666.11.99.820."
)

func requireSyntaxPublicationReference(t *testing.T) openLDAPReferenceTools {
	t.Helper()
	if os.Getenv(openLDAPReferenceTestsEnv) != "1" {
		t.Skipf("set %s=1 and load the pinned OpenLDAP reference environment", openLDAPReferenceTestsEnv)
	}
	if os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" || os.Getenv("OPENLDAP_COMMIT") != syntaxPublicationReferenceCommit || os.Getenv("OPENLDAP_VERIFIED_COMMIT") != syntaxPublicationReferenceCommit {
		t.Fatal("syntax differential requires the verified OpenLDAP 2.6.13 build")
	}
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
		"schema_init.c": "99b997916f864fd56b11536a41b373dff69f39fb28516fe1f896bf82c2015a03",
		"schema_prep.c": "7ef51e04ce5342da36e44ea71580d5191ae3eb1b5616ae9da90d1633f25bbe20",
		"syntax.c":      "412df195ef8e368732529aa455a0862f112e7ce226c93cf417a8376cd0812b72",
		"dn.c":          "78c5a2a97add39d0379c478efaf46cd08bdbcb7a9c9dbf8da46cf191651dce9b",
	} {
		data, err := os.ReadFile(filepath.Join(os.Getenv("OPENLDAP_SOURCE"), "servers", "slapd", file))
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != hash {
			t.Fatalf("%s must match commit %s: %v", file, syntaxPublicationReferenceCommit, err)
		}
	}
	tools := requireOpenLDAPReferenceTools(t)
	version, err := exec.CommandContext(t.Context(), tools.slapd, "-VV").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "slapd 2.6.13") {
		t.Fatalf("reference slapd version: %v: %s", err, version)
	}
	return tools
}

func syntaxPublicationDeclarations() []string {
	return []string{
		"( " + syntaxPublicationFixturePrefix + "1 DESC 'Reference directory alias' X-SUBST '" + syntaxPublicationStandardPrefix + "15' X-ORIGIN ( 'fixture' 'syntax differential' ) )",
		"( " + syntaxPublicationFixturePrefix + "2 DESC 'Reference binary alias' X-SUBST '" + syntaxPublicationStandardPrefix + "5' )",
		"( " + syntaxPublicationFixturePrefix + "3 DESC 'Reference alias chain' X-SUBST '" + syntaxPublicationFixturePrefix + "2' )",
		"( " + syntaxPublicationFixturePrefix + "4 DESC 'Reference declaration only' X-NOT-HUMAN-READABLE 'TRUE' X-ORIGIN 'fixture' )",
		"( " + syntaxPublicationFixturePrefix + "5 DESC 'Reference hidden alias' X-SUBST '1.3.6.1.4.1.4203.1.1.1' )",
	}
}

type syntaxPublicationValueSyntax struct {
	name, oid, equality string
}

func syntaxPublicationValueSyntaxes() []syntaxPublicationValueSyntax {
	return []syntaxPublicationValueSyntax{
		{"Audio", syntaxPublicationStandardPrefix + "4", ""},
		{"Binary", syntaxPublicationStandardPrefix + "5", ""},
		{"BitString", syntaxPublicationStandardPrefix + "6", "bitStringMatch"},
		{"DeliveryMethod", syntaxPublicationStandardPrefix + "14", ""},
		{"JPEG", syntaxPublicationStandardPrefix + "28", ""},
		{"OtherMailbox", syntaxPublicationStandardPrefix + "39", ""},
		{"RDN", "1.2.36.79672281.1.5.0", ""},
		{"NISNetgroup", "1.3.6.1.1.1.0.0", ""},
		{"BootParameter", "1.3.6.1.1.1.0.1", ""},
		{"SyntaxDescription", syntaxPublicationStandardPrefix + "54", ""},
		{"DirectoryAlias", syntaxPublicationFixturePrefix + "1", ""},
		{"BinaryAlias", syntaxPublicationFixturePrefix + "2", ""},
		{"BinaryAliasChain", syntaxPublicationFixturePrefix + "3", ""},
		{"DeclarationOnly", syntaxPublicationFixturePrefix + "4", ""},
	}
}

func syntaxPublicationAttributeDefinitions() []string {
	var definitions []string
	for i, syntax := range syntaxPublicationValueSyntaxes() {
		equality := ""
		if syntax.equality != "" {
			equality = " EQUALITY " + syntax.equality
		}
		definitions = append(definitions, fmt.Sprintf("( %s10.%d NAME 'syntaxRef%s'%s SYNTAX %s )", syntaxPublicationFixturePrefix, i+1, syntax.name, equality, syntax.oid))
	}
	return definitions
}

func syntaxPublicationObjectClass() string {
	var names []string
	for _, syntax := range syntaxPublicationValueSyntaxes() {
		names = append(names, "syntaxRef"+syntax.name)
	}
	return "( " + syntaxPublicationFixturePrefix + "20 NAME 'syntaxRefValues' SUP top AUXILIARY MAY ( " + strings.Join(names, " $ ") + " ) )"
}

func syntaxPublicationACL() []string {
	return []string{
		`to dn.exact="cn=Subschema" attrs=ldapSyntaxes by dn.exact="cn=syntax-hidden,dc=example,dc=com" none by * read`,
		`to * by * read`,
	}
}

func syntaxPublicationSeed() string {
	return "\ndn: cn=syntax-hidden,dc=example,dc=com\nobjectClass: person\ncn: syntax-hidden\nsn: Reader\nuserPassword: secret\n\n"
}

func syntaxPublicationGoServer(t *testing.T) string {
	t.Helper()
	var config strings.Builder
	config.WriteString("dn: cn=config\nobjectClass: olcGlobal\ncn: config\n\ndn: cn=schema,cn=config\nobjectClass: olcSchemaConfig\ncn: schema\n\ndn: cn={9}syntax-reference,cn=schema,cn=config\nobjectClass: olcSchemaConfig\ncn: {9}syntax-reference\n")
	for _, definition := range syntaxPublicationDeclarations() {
		fmt.Fprintln(&config, "olcLdapSyntaxes:", definition)
	}
	for _, definition := range syntaxPublicationAttributeDefinitions() {
		fmt.Fprintln(&config, "olcAttributeTypes:", definition)
	}
	fmt.Fprintln(&config, "olcObjectClasses:", syntaxPublicationObjectClass())
	config.WriteString("\ndn: olcDatabase={-1}frontend,cn=config\nobjectClass: olcDatabaseConfig\nobjectClass: olcFrontendConfig\nolcDatabase: {-1}frontend\n")
	for i, rule := range syntaxPublicationACL() {
		fmt.Fprintf(&config, "olcAccess: {%d}%s\n", i, rule)
	}
	config.WriteString("\ndn: olcDatabase={1}mdb,cn=config\nobjectClass: olcDatabaseConfig\nobjectClass: olcMdbConfig\nolcDatabase: {1}mdb\nolcSuffix: dc=example,dc=com\nolcRootDN: cn=admin,dc=example,dc=com\nolcRootPW: secret\n\ndn: dc=example,dc=com\nobjectClass: top\nobjectClass: domain\ndc: example\n\n")
	config.WriteString(syntaxPublicationSeed())
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := migration.ImportLDIF(t.Context(), store, strings.NewReader(config.String()), migration.ImportOptions{SkipSchemaValidation: true}); err != nil {
		t.Fatal(err)
	}
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	return "ldap://" + address
}

type syntaxPublicationDescription struct {
	OID, Description string
	Extensions       map[string][]string
}

var syntaxPublicationTokens = regexp.MustCompile(`'[^']*'|[()]|[^\s()]+`)

// Independent of ParseLDAPSyntax: compare metadata without importing the
// production publication/parser implementation into its own oracle.
func syntaxPublicationParse(t *testing.T, value string) syntaxPublicationDescription {
	t.Helper()
	tokens := syntaxPublicationTokens.FindAllString(value, -1)
	if len(tokens) < 3 || tokens[0] != "(" || tokens[len(tokens)-1] != ")" {
		t.Fatalf("invalid LDAPSyntaxDescription: %q", value)
	}
	result := syntaxPublicationDescription{OID: tokens[1], Extensions: map[string][]string{}}
	tokens = tokens[2 : len(tokens)-1]
	unquote := func(token string) string {
		if len(token) < 2 || token[0] != '\'' || token[len(token)-1] != '\'' {
			t.Fatalf("expected quoted value in %q", value)
		}
		var out strings.Builder
		for i := 1; i < len(token)-1; i++ {
			if token[i] != '\\' {
				out.WriteByte(token[i])
				continue
			}
			if i+2 >= len(token)-1 {
				t.Fatalf("truncated schema escape in %q", value)
			}
			decoded, err := hex.DecodeString(token[i+1 : i+3])
			if err != nil {
				t.Fatalf("invalid schema escape in %q", value)
			}
			out.Write(decoded)
			i += 2
		}
		return out.String()
	}
	seen := map[string]bool{}
	for len(tokens) > 0 {
		key := tokens[0]
		tokens = tokens[1:]
		if seen[key] || len(tokens) == 0 || key != "DESC" && !strings.HasPrefix(key, "X-") {
			t.Fatalf("invalid or duplicate schema field %q in %q", key, value)
		}
		seen[key] = true
		var values []string
		if tokens[0] == "(" {
			tokens = tokens[1:]
			for len(tokens) > 0 && tokens[0] != ")" {
				values = append(values, unquote(tokens[0]))
				tokens = tokens[1:]
			}
			if len(tokens) == 0 || len(values) == 0 {
				t.Fatalf("invalid extension list in %q", value)
			}
			tokens = tokens[1:]
		} else {
			values, tokens = []string{unquote(tokens[0])}, tokens[1:]
		}
		if key == "DESC" {
			if len(values) != 1 {
				t.Fatalf("invalid DESC in %q", value)
			}
			result.Description = values[0]
		} else {
			// Extension values are retained exactly, including order and case.
			result.Extensions[key] = values
		}
	}
	return result
}

func syntaxPublicationCatalog(t *testing.T, values []string) map[string]syntaxPublicationDescription {
	t.Helper()
	catalog := make(map[string]syntaxPublicationDescription, len(values))
	for _, value := range values {
		description := syntaxPublicationParse(t, value)
		if _, duplicate := catalog[description.OID]; duplicate {
			t.Fatalf("duplicate published syntax %s", description.OID)
		}
		catalog[description.OID] = description
	}
	return catalog
}

// Captured from the pinned live provider, not generated from the Go registry.
// PKCS#8 deliberately has no X flags, and X-SUBST aliases retain only their
// declared extensions rather than copying their target's published flags.
func syntaxPublicationExpectedDescriptions() []string {
	var values []string
	for suffix, description := range map[string]string{
		"4": "Audio", "5": "Binary", "6": "Bit String", "7": "Boolean",
		"8": "Certificate", "9": "Certificate List", "10": "Certificate Pair",
		"11": "Country String", "12": "Distinguished Name", "14": "Delivery Method",
		"15": "Directory String", "22": "Facsimile Telephone Number", "24": "Generalized Time",
		"26": "IA5 String", "27": "Integer", "28": "JPEG", "34": "Name And Optional UID",
		"36": "Numeric String", "38": "OID", "39": "Other Mailbox", "40": "Octet String",
		"41": "Postal Address", "44": "Printable String", "45": "SubtreeSpecification",
		"49": "Supported Algorithm", "50": "Telephone Number", "52": "Telex Number",
	} {
		extensions := ""
		switch suffix {
		case "4", "5", "28":
			extensions = " X-NOT-HUMAN-READABLE 'TRUE'"
		case "8", "9", "10", "49":
			extensions = " X-BINARY-TRANSFER-REQUIRED 'TRUE' X-NOT-HUMAN-READABLE 'TRUE'"
		}
		values = append(values, "( "+syntaxPublicationStandardPrefix+suffix+" DESC '"+description+"'"+extensions+" )")
	}
	values = append(values,
		"( 1.2.36.79672281.1.5.0 DESC 'RDN' )",
		"( 1.2.840.113549.1.8.1.1 DESC 'PKCS#8 PrivateKeyInfo' )",
		"( 1.3.6.1.1.1.0.0 DESC 'RFC2307 NIS Netgroup Triple' )",
		"( 1.3.6.1.1.1.0.1 DESC 'RFC2307 Boot Parameter' )",
		"( 1.3.6.1.1.16.1 DESC 'UUID' )",
		"( 1.3.6.1.4.1.4203.666.11.10.2.1 DESC 'X.509 AttributeCertificate' X-BINARY-TRANSFER-REQUIRED 'TRUE' X-NOT-HUMAN-READABLE 'TRUE' )",
	)
	return append(values, syntaxPublicationDeclarations()[:3]...)
}

type syntaxPublicationObservation struct {
	Code    uint16
	Entries int
	Present bool
	Values  []string
	Stored  []string
}

func syntaxPublicationConnect(t *testing.T, uri, dn string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri, ldap.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	client.SetTimeout(5 * time.Second)
	if dn != "" {
		if err := client.Bind(dn, "secret"); err != nil {
			t.Fatal(err)
		}
	}
	return client
}

func syntaxPublicationSearch(t *testing.T, client *ldap.Conn, filter string, attrs []string, typesOnly bool) syntaxPublicationObservation {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest("cn=Subschema", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, typesOnly, filter, attrs, nil))
	observation := syntaxPublicationObservation{Code: matchingRulesReferenceCode(t, err)}
	if result == nil {
		return observation
	}
	observation.Entries = len(result.Entries)
	for _, entry := range result.Entries {
		for _, attribute := range entry.Attributes {
			if strings.EqualFold(attribute.Name, "ldapSyntaxes") || attribute.Name == syntaxPublicationAttributeOID {
				if observation.Present {
					t.Fatal("duplicate ldapSyntaxes attribute")
				}
				if attribute.Name != "ldapSyntaxes" {
					t.Errorf("published attribute name %q, want canonical ldapSyntaxes", attribute.Name)
				}
				observation.Present = true
				observation.Values = slices.Clone(attribute.Values)
			}
		}
	}
	return observation
}

func syntaxPublicationCompare(t *testing.T, client *ldap.Conn, attribute, assertion string) syntaxPublicationObservation {
	t.Helper()
	match, err := client.Compare("cn=Subschema", attribute, assertion)
	code := matchingRulesReferenceCode(t, err)
	if err == nil {
		code = ldap.LDAPResultCompareFalse
		if match {
			code = ldap.LDAPResultCompareTrue
		}
	}
	return syntaxPublicationObservation{Code: code}
}

type syntaxPublicationAssertion struct {
	name, value  string
	compare      uint16
	entries, not int
}

func syntaxPublicationAssertions() []syntaxPublicationAssertion {
	return []syntaxPublicationAssertion{
		{"syntax-OID", syntaxPublicationStandardPrefix + "15", 6, 1, 0},
		{"bit-OID", syntaxPublicationStandardPrefix + "6", 6, 1, 0},
		{"syntax-name", "Directory String", 21, 0, 0},
		{"single-word-name", "Integer", 21, 0, 0},
		{"known-rule-name", "caseIgnoreMatch", 21, 0, 0},
		{"unknown-name", "noSuchSyntax", 21, 0, 0},
		{"unknown-OID", "1.2.3.987654", 5, 0, 1},
		{"hidden-OID", "1.3.6.1.4.1.4203.666.11.2.1", 5, 0, 1},
		{"no-validator-OID", syntaxPublicationStandardPrefix + "54", 5, 0, 1},
		{"declaration-OID", syntaxPublicationFixturePrefix + "4", 5, 0, 1},
		{"alias-OID", syntaxPublicationFixturePrefix + "1", 6, 1, 0},
		{"malformed-OID", "1.2..3", 21, 0, 0},
		{"leading-zero", "1.02.3", 21, 0, 0},
		{"empty", "", 21, 0, 0},
		{"whitespace", " ", 21, 0, 0},
		{"padded-OID", " " + syntaxPublicationStandardPrefix + "15 ", 21, 0, 0},
		{"description", "( " + syntaxPublicationStandardPrefix + "15 DESC 'Directory String' )", 21, 0, 0},
	}
}

func syntaxPublicationObserve(t *testing.T, uri string) map[string]syntaxPublicationObservation {
	t.Helper()
	client := syntaxPublicationConnect(t, uri, "")
	observations := map[string]syntaxPublicationObservation{}
	for _, test := range []struct {
		name      string
		attrs     []string
		typesOnly bool
		present   bool
	}{
		{"explicit", []string{"ldapSyntaxes"}, false, true},
		{"OID", []string{syntaxPublicationAttributeOID}, false, true},
		{"case-folded", []string{"LDAPSYNTAXES"}, false, true},
		{"default", nil, false, false},
		{"star", []string{"*"}, false, false},
		{"none", []string{"1.1"}, false, false},
		{"plus", []string{"+"}, false, true},
		{"star-plus", []string{"*", "+"}, false, true},
		{"none-explicit", []string{"1.1", "ldapSyntaxes"}, false, true},
		{"duplicate", []string{"ldapSyntaxes", syntaxPublicationAttributeOID}, false, true},
		{"types-only", []string{"ldapSyntaxes"}, true, true},
		{"types-only-OID", []string{syntaxPublicationAttributeOID}, true, true},
		{"types-only-plus", []string{"+"}, true, true},
	} {
		t.Run("select-"+test.name, func(t *testing.T) {
			got := syntaxPublicationSearch(t, client, "(objectClass=*)", test.attrs, test.typesOnly)
			observations["select-"+test.name] = got
			if got.Code != 0 || got.Entries != 1 || got.Present != test.present || (len(got.Values) > 0) != (test.present && !test.typesOnly) {
				t.Errorf("selection code=%d entries=%d present=%v values=%d; want 0/1/%v typesOnly=%v", got.Code, got.Entries, got.Present, len(got.Values), test.present, test.typesOnly)
			}
		})
	}
	for _, attribute := range []string{"ldapSyntaxes", syntaxPublicationAttributeOID} {
		for _, assertion := range syntaxPublicationAssertions() {
			name := attribute + "/" + assertion.name
			t.Run(name, func(t *testing.T) {
				observations[name+"/compare"] = syntaxPublicationCompare(t, client, attribute, assertion.value)
				filter := "(" + attribute + "=" + ldap.EscapeFilter(assertion.value) + ")"
				observations[name+"/filter"] = syntaxPublicationSearch(t, client, filter, []string{"1.1"}, false)
				observations[name+"/not"] = syntaxPublicationSearch(t, client, "(!"+filter+")", []string{"1.1"}, false)
				t.Logf("assertion=%q Compare=%d filter=%d/%d NOT=%d/%d", assertion.value, observations[name+"/compare"].Code, observations[name+"/filter"].Code, observations[name+"/filter"].Entries, observations[name+"/not"].Code, observations[name+"/not"].Entries)
			})
		}
	}
	t.Run("ACL", func(t *testing.T) {
		limited := syntaxPublicationConnect(t, uri, "cn=syntax-hidden,dc=example,dc=com")
		for _, attrs := range [][]string{{"ldapSyntaxes"}, {syntaxPublicationAttributeOID}, {"+"}} {
			for _, typesOnly := range []bool{false, true} {
				name := fmt.Sprintf("ACL/select-%s/typesOnly=%t", attrs[0], typesOnly)
				observations[name] = syntaxPublicationSearch(t, limited, "(objectClass=*)", attrs, typesOnly)
				got := observations[name]
				if got.Code != 0 || got.Entries != 1 || got.Present {
					t.Errorf("%s code=%d entries=%d present=%v", name, got.Code, got.Entries, got.Present)
				}
			}
		}
		observations["ACL/compare"] = syntaxPublicationCompare(t, limited, "ldapSyntaxes", syntaxPublicationStandardPrefix+"15")
		observations["ACL/filter"] = syntaxPublicationSearch(t, limited, "(ldapSyntaxes="+syntaxPublicationStandardPrefix+"15)", []string{"1.1"}, false)
		observations["ACL/not"] = syntaxPublicationSearch(t, limited, "(!(ldapSyntaxes="+syntaxPublicationStandardPrefix+"15))", []string{"1.1"}, false)
		t.Logf("ACL Compare=%d filter=%d/%d NOT=%d/%d", observations["ACL/compare"].Code, observations["ACL/filter"].Code, observations["ACL/filter"].Entries, observations["ACL/not"].Code, observations["ACL/not"].Entries)
	})
	return observations
}

type syntaxPublicationValueCase struct {
	syntax, name, value string
	want                uint16
}

func syntaxPublicationValueCorpus() []syntaxPublicationValueCase {
	var cases []syntaxPublicationValueCase
	for _, syntax := range []string{"Audio", "Binary", "JPEG", "BinaryAlias", "BinaryAliasChain"} {
		for _, value := range []struct{ name, value string }{
			{"empty", ""}, {"text", "not ASN.1 or an image"}, {"NUL", "\x00"},
			{"arbitrary-header", "\xff\x80\x00\x7f"}, {"truncated-BER", "\x30\x82\xff"},
			{"indefinite-BER", "\x30\x80\x04\x01A\x00\x00"}, {"jpeg-header-only", "\xff\xd8\xff"},
		} {
			cases = append(cases, syntaxPublicationValueCase{syntax, value.name, value.value, 0})
		}
		cases = append(cases, syntaxPublicationValueCase{syntax + ";binary", "transfer-option", "\xff\x80\x00", 17})
	}
	cases = append(cases,
		syntaxPublicationValueCase{"BitString", "empty-bits", "''B", 0},
		syntaxPublicationValueCase{"BitString", "bits", "'010110'B", 0},
		syntaxPublicationValueCase{"BitString", "empty-value", "", 21},
		syntaxPublicationValueCase{"BitString", "lowercase-suffix", "'01'b", 21},
		syntaxPublicationValueCase{"BitString", "bad-digit", "'012'B", 21},
		syntaxPublicationValueCase{"BitString", "unquoted", "0101", 21},
		syntaxPublicationValueCase{"BitString", "padded", " '01'B", 21},
		syntaxPublicationValueCase{"BitString", "NUL", "'0\x001'B", 21},
		syntaxPublicationValueCase{"DeliveryMethod", "single", "any", 0},
		syntaxPublicationValueCase{"DeliveryMethod", "uppercase", "G3FAX", 0},
		syntaxPublicationValueCase{"DeliveryMethod", "list", "any $ mhs $ physical $ telex $ teletex $ g3fax $ g4fax $ ia5 $ videotex $ telephone", 0},
		syntaxPublicationValueCase{"DeliveryMethod", "compact", "any$mhs", 0},
		syntaxPublicationValueCase{"DeliveryMethod", "duplicate", "any $ any", 0},
		syntaxPublicationValueCase{"DeliveryMethod", "empty", "", 21},
		syntaxPublicationValueCase{"DeliveryMethod", "unknown", "email", 21},
		syntaxPublicationValueCase{"DeliveryMethod", "leading-space", " any", 21},
		syntaxPublicationValueCase{"DeliveryMethod", "trailing-space", "any ", 21},
		syntaxPublicationValueCase{"DeliveryMethod", "trailing-dollar", "any$", 21},
		syntaxPublicationValueCase{"DeliveryMethod", "tab", "any\t$ mhs", 21},
		syntaxPublicationValueCase{"DeliveryMethod", "missing-dollar", "any mhs", 21},
		syntaxPublicationValueCase{"OtherMailbox", "mailbox", "smtp$user@example.com", 0},
		syntaxPublicationValueCase{"OtherMailbox", "arbitrary-ASCII", "not a mailbox", 0},
		syntaxPublicationValueCase{"OtherMailbox", "empty", "", 0},
		syntaxPublicationValueCase{"OtherMailbox", "ASCII-controls", "\x00\t\r\n\x7f", 0},
		syntaxPublicationValueCase{"OtherMailbox", "non-ASCII", "caf\xc3\xa9", 21},
		syntaxPublicationValueCase{"OtherMailbox", "high-byte", "\x80", 21},
		syntaxPublicationValueCase{"RDN", "single", "cn=Alice", 0},
		syntaxPublicationValueCase{"RDN", "empty", "", 0},
		syntaxPublicationValueCase{"RDN", "multi-valued", "cn=Alice+uid=alice", 0},
		syntaxPublicationValueCase{"RDN", "escaped-comma", `cn=Alice\, Example`, 0},
		syntaxPublicationValueCase{"RDN", "DN-tail", "cn=Alice,dc=example", 0},
		syntaxPublicationValueCase{"RDN", "DN-tail-one", "cn=one,dc=ignored", 0},
		syntaxPublicationValueCase{"RDN", "old-quoted", `cn="a,b"`, 0},
		syntaxPublicationValueCase{"RDN", "old-quoted-DN", `cn="a,b",dc=ignored`, 0},
		syntaxPublicationValueCase{"RDN", "attribute-case", "CN=Alice", 0},
		syntaxPublicationValueCase{"RDN", "OID-attribute", "2.5.4.3=Alice", 0},
		syntaxPublicationValueCase{"RDN", "spaces", "cn=  Alice  ", 0},
		syntaxPublicationValueCase{"RDN", "escaped-hex", `cn=Al\69ce`, 0},
		syntaxPublicationValueCase{"RDN", "no-equals", "Alice", 21},
		syntaxPublicationValueCase{"RDN", "unknown-attribute", "noSuchAttribute=Alice", 21},
		syntaxPublicationValueCase{"RDN", "dangling-escape", "cn=Alice\\", 21},
		syntaxPublicationValueCase{"NISNetgroup", "triple", "(host,user,domain)", 0},
		syntaxPublicationValueCase{"NISNetgroup", "empty-fields", "(,,)", 0},
		syntaxPublicationValueCase{"NISNetgroup", "descriptor-chars", "(host-1,user2,DOMAIN)", 0},
		syntaxPublicationValueCase{"NISNetgroup", "empty", "", 21},
		syntaxPublicationValueCase{"NISNetgroup", "hostname-dot", "(host.example,user,domain)", 0},
		syntaxPublicationValueCase{"NISNetgroup", "underscore", "(host_name,user,domain)", 21},
		syntaxPublicationValueCase{"NISNetgroup", "space", "(host, user,domain)", 21},
		syntaxPublicationValueCase{"NISNetgroup", "too-many", "(host,user,domain,extra)", 21},
		syntaxPublicationValueCase{"NISNetgroup", "missing-close", "(host,user,domain", 21},
		syntaxPublicationValueCase{"NISNetgroup", "trailing", "(host,user,domain)x", 21},
		syntaxPublicationValueCase{"BootParameter", "normal", "root=server:/export/root", 0},
		syntaxPublicationValueCase{"BootParameter", "empty-fields", "=:", 0},
		syntaxPublicationValueCase{"BootParameter", "printable-path", "root=server:/path with spaces?x=1", 0},
		syntaxPublicationValueCase{"BootParameter", "empty", "", 21},
		syntaxPublicationValueCase{"BootParameter", "hostname-dot", "root=server.example:/path", 0},
		syntaxPublicationValueCase{"BootParameter", "underscore", "root_key=server:/path", 21},
		syntaxPublicationValueCase{"BootParameter", "no-colon", "root=server", 21},
		syntaxPublicationValueCase{"BootParameter", "path-tab", "root=server:/path\t", 21},
		syntaxPublicationValueCase{"BootParameter", "path-high-byte", "root=server:/\xff", 21},
		syntaxPublicationValueCase{"SyntaxDescription", "valid-description", "( 1.2.3 DESC 'Example' )", 21},
		syntaxPublicationValueCase{"SyntaxDescription", "malformed", "not a syntax description", 21},
		syntaxPublicationValueCase{"SyntaxDescription", "empty", "", 21},
		syntaxPublicationValueCase{"DirectoryAlias", "UTF8", "caf\xc3\xa9", 0},
		syntaxPublicationValueCase{"DirectoryAlias", "empty", "", 0},
		syntaxPublicationValueCase{"DirectoryAlias", "invalid-UTF8", "\xff", 21},
		syntaxPublicationValueCase{"DeclarationOnly", "text", "anything", 21},
		syntaxPublicationValueCase{"DeclarationOnly", "empty", "", 21},
	)
	return cases
}

func syntaxPublicationObserveValues(t *testing.T, uri string) map[string]syntaxPublicationObservation {
	t.Helper()
	client := syntaxPublicationConnect(t, uri, "cn=admin,dc=example,dc=com")
	observations := map[string]syntaxPublicationObservation{}
	for i, test := range syntaxPublicationValueCorpus() {
		name := "value/" + test.syntax + "/" + test.name
		t.Run(name, func(t *testing.T) {
			cn := fmt.Sprintf("syntax-ref-%d", i)
			dn := "cn=" + cn + ",dc=example,dc=com"
			attribute := "syntaxRef" + test.syntax
			request := ldap.NewAddRequest(dn, nil)
			request.Attribute("objectClass", []string{"top", "person", "syntaxRefValues"})
			request.Attribute("cn", []string{cn})
			request.Attribute("sn", []string{"Syntax Reference"})
			request.Attribute(attribute, []string{test.value})
			code := matchingRulesReferenceCode(t, client.Add(request))
			observations[name] = syntaxPublicationObservation{Code: code}
			t.Logf("Add %s/%s (%d bytes) = %d", test.syntax, test.name, len(test.value), code)
			if code == 0 {
				result, err := client.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{attribute}, nil))
				if err != nil || len(result.Entries) != 1 {
					t.Fatalf("read added value: %v, result=%+v", err, result)
				}
				if test.syntax != "RDN" && !slices.Equal(result.Entries[0].GetAttributeValues(attribute), []string{test.value}) {
					t.Errorf("stored bytes=%q, want %q", result.Entries[0].GetAttributeValues(attribute), test.value)
				}
				got := observations[name]
				got.Stored = slices.Clone(result.Entries[0].GetAttributeValues(attribute))
				observations[name] = got
				if test.syntax == "RDN" {
					t.Logf("RDN input=%q stored=%q", test.value, got.Stored)
				}
				if err := client.Del(ldap.NewDelRequest(dn, nil)); err != nil {
					t.Fatal(err)
				}
			} else {
				_, err := client.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"1.1"}, nil))
				if got := matchingRulesReferenceCode(t, err); got != ldap.LDAPResultNoSuchObject {
					t.Errorf("failed Add left a searchable entry: search result=%d", got)
				}
			}
		})
	}
	return observations
}

func syntaxPublicationAssertExpected(t *testing.T, observed map[string]syntaxPublicationObservation) {
	t.Helper()
	for _, attribute := range []string{"ldapSyntaxes", syntaxPublicationAttributeOID} {
		for _, test := range syntaxPublicationAssertions() {
			name := attribute + "/" + test.name
			for operation, want := range map[string]syntaxPublicationObservation{
				"compare": {Code: test.compare}, "filter": {Entries: test.entries}, "not": {Entries: test.not},
			} {
				if got, present := observed[name+"/"+operation]; !present || !reflect.DeepEqual(got, want) {
					t.Errorf("%s/%s = %+v, want %+v (observed=%t)", name, operation, got, want, present)
				}
			}
		}
	}
	for _, test := range syntaxPublicationValueCorpus() {
		name := "value/" + test.syntax + "/" + test.name
		if got, present := observed[name]; !present || got.Code != test.want {
			t.Errorf("%s = %d, want %d (observed=%t)", name, got.Code, test.want, present)
		}
	}
	for name, stored := range map[string]string{
		"single": "cn=Alice", "empty": "", "multi-valued": "cn=Alice+uid=alice",
		"escaped-comma": `cn=Alice\2C Example`, "DN-tail": "cn=Alice", "DN-tail-one": "cn=one",
		"old-quoted": `cn=a\2Cb`, "old-quoted-DN": `cn=a\2Cb`, "attribute-case": "cn=Alice",
		"OID-attribute": "cn=Alice", "spaces": "cn=Alice", "escaped-hex": "cn=Alice",
	} {
		if got := observed["value/RDN/"+name]; got.Code != 0 || !slices.Equal(got.Stored, []string{stored}) {
			t.Errorf("RDN/%s stored=%q code=%d, want %q/0", name, got.Stored, got.Code, stored)
		}
	}
	for operation, want := range map[string]syntaxPublicationObservation{
		"compare": {Code: ldap.LDAPResultInsufficientAccessRights}, "filter": {}, "not": {},
	} {
		if got, present := observed["ACL/"+operation]; !present || !reflect.DeepEqual(got, want) {
			t.Errorf("ACL/%s = %+v, want %+v (observed=%t)", operation, got, want, present)
		}
	}
}

func syntaxPublicationAssertCatalog(t *testing.T, observed map[string]syntaxPublicationObservation) {
	t.Helper()
	catalog := syntaxPublicationCatalog(t, observed["select-explicit"].Values)
	if len(catalog) == 0 {
		t.Fatal("an empty shared syntax catalog is not publication parity")
	}
	for oid, expected := range syntaxPublicationCatalog(t, syntaxPublicationExpectedDescriptions()) {
		if actual, present := catalog[oid]; !present || !reflect.DeepEqual(actual, expected) {
			t.Errorf("syntax %s: got %+v, want %+v (published=%t)", oid, actual, expected, present)
		}
	}
	for _, oid := range []string{
		syntaxPublicationStandardPrefix + "1", syntaxPublicationStandardPrefix + "2", syntaxPublicationStandardPrefix + "3",
		syntaxPublicationStandardPrefix + "16", syntaxPublicationStandardPrefix + "17", syntaxPublicationStandardPrefix + "30",
		syntaxPublicationStandardPrefix + "31", syntaxPublicationStandardPrefix + "35", syntaxPublicationStandardPrefix + "37", syntaxPublicationStandardPrefix + "54",
		"1.3.6.1.1.15.1", "1.3.6.1.1.15.5", "1.3.6.1.4.1.4203.666.11.2.1", "1.3.6.1.4.1.4203.666.11.2.4",
		"1.3.6.1.4.1.4203.1.1.1", "1.3.6.1.4.1.4203.666.2.7", syntaxPublicationFixturePrefix + "4", syntaxPublicationFixturePrefix + "5",
	} {
		if _, present := catalog[oid]; present {
			t.Errorf("hidden/no-validator syntax %s must not be published", oid)
		}
	}
	t.Logf("published %d LDAPSyntaxDescriptions", len(catalog))
}

func syntaxPublicationDifferential(t *testing.T, native, implemented map[string]syntaxPublicationObservation) {
	t.Helper()
	if len(native) == 0 || len(native) != len(implemented) {
		t.Fatalf("both providers must run all operations: native=%d Go=%d", len(native), len(implemented))
	}
	for name, want := range native {
		t.Run(name, func(t *testing.T) {
			got, present := implemented[name]
			if !present || got.Code != want.Code || got.Entries != want.Entries || got.Present != want.Present || (len(got.Values) > 0) != (len(want.Values) > 0) || !slices.Equal(got.Stored, want.Stored) {
				t.Fatalf("Go=%+v, native=%+v (observed=%t)", got, want, present)
			}
			nativeCatalog := syntaxPublicationCatalog(t, want.Values)
			for oid, actual := range syntaxPublicationCatalog(t, got.Values) {
				if expected, present := nativeCatalog[oid]; !present || !reflect.DeepEqual(actual, expected) {
					t.Errorf("Go-published %s metadata=%+v, native=%+v (published=%t)", oid, actual, expected, present)
				}
			}
		})
	}
	t.Logf("compared %d live SDK observations and every Go-published syntax descriptor", len(native))
}

func TestOpenLDAPSyntaxPublicationReference(t *testing.T) {
	tools := requireSyntaxPublicationReference(t)
	var native, implemented map[string]syntaxPublicationObservation
	t.Run("native", func(t *testing.T) {
		var global strings.Builder
		for _, definition := range syntaxPublicationDeclarations() {
			fmt.Fprintln(&global, "ldapsyntax", definition)
		}
		for _, definition := range syntaxPublicationAttributeDefinitions() {
			fmt.Fprintln(&global, "attributetype", definition)
		}
		fmt.Fprintln(&global, "objectclass", syntaxPublicationObjectClass())
		global.WriteString("database frontend\n")
		for _, rule := range syntaxPublicationACL() {
			fmt.Fprintln(&global, "access", rule)
		}
		uri, stop := startOpenLDAPReferenceServerWithConfig(t, tools, nil, global.String(), "", syntaxPublicationSeed())
		defer stop()
		native = syntaxPublicationObserve(t, uri)
		for name, observation := range syntaxPublicationObserveValues(t, uri) {
			native[name] = observation
		}
		syntaxPublicationAssertExpected(t, native)
		syntaxPublicationAssertCatalog(t, native)
	})
	t.Run("go", func(t *testing.T) {
		uri := syntaxPublicationGoServer(t)
		implemented = syntaxPublicationObserve(t, uri)
		for name, observation := range syntaxPublicationObserveValues(t, uri) {
			implemented[name] = observation
		}
		syntaxPublicationAssertCatalog(t, implemented)
	})
	t.Run("differential", func(t *testing.T) {
		syntaxPublicationDifferential(t, native, implemented)
	})
}

// Frozen expectations come from the pinned provider above. This entry point
// runs the same SDK corpus without installing OpenLDAP or linking any C code.
func TestSyntaxPublicationGoContract(t *testing.T) {
	uri := syntaxPublicationGoServer(t)
	observed := syntaxPublicationObserve(t, uri)
	for name, observation := range syntaxPublicationObserveValues(t, uri) {
		observed[name] = observation
	}
	syntaxPublicationAssertExpected(t, observed)
	syntaxPublicationAssertCatalog(t, observed)
}
