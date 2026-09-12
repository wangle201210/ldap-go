package schema

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func TestExtraSyntaxNativeGrammar(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, oid string
		valid     []string
		invalid   []string
	}{
		{
			name: "Delivery Method", oid: SyntaxDeliveryMethod,
			valid: []string{
				"any", "MHS", "physical", "telex", "teletex", "g3fax", "G4FAX", "ia5", "videotex", "telephone",
				"any$any", "TeLePhOnE $ MHS", "any  $   physical$ia5",
			},
			invalid: []string{
				"", " ", " any", "any ", "any $ ", "$any", "any$$ia5", "any ia5", "any$", "g5fax",
				"any\t$ia5", "any$\tia5", "any\n$ia5", "any$ia5\r", "any\x00", "a\xffy", "\u0130A5",
				"telephoneextra", "email", "telet", "physical$ ",
			},
		},
		{
			name: "Other Mailbox", oid: SyntaxOtherMailbox,
			valid:   []string{"", " ", "\x00\t\n\r\x7f", "SMTP$user@example.com", "$", "not an address", "$$"},
			invalid: []string{"\x80", "\xff", "smtp$\xc3\xa9", "\u4e2d\u6587"},
		},
		{
			name: "NIS Netgroup Triple", oid: SyntaxNISNetgroupTriple,
			valid: []string{"(,,)", "(host,user,domain)", "(-,-,-)", "(h.example,u-1,d)", "(.;-,;.,-;)"},
			invalid: []string{
				"", "()", "(,)", "(,,,)", "(a,b,c,d)", "(a,b,c", "a,b,c)", " (a,b,c)", "(a,b,c) ",
				"(a, b,c)", "(a,b,\tc)", "(a,b,c)junk", "(a,b,c))", "((a,b,c)", "(a_b,c,d)",
				"(a/b,c,d)", "(a,b,c\x00)", "(a,b,c\x7f)", "(a,b,c\x80)", "(a,b,\xc3\xa9)", "(a,b,c)\x00",
			},
		},
		{
			name: "Boot Parameter", oid: SyntaxBootParameter,
			valid: []string{
				"=:", "key=:", "=server:", "=:/path", "root=server:/export/root", "root=server:",
				".-;=.;-:", "key=s: '()+,-./:=?", "k=s:/one path/two", "k=s:a=b:c",
			},
			invalid: []string{
				"", "=", ":", "key=server", "key:server=", "a:b=c:d", "a=b=c:d", "key =server:/", "key= server:/",
				"key=server :/", "key_name=s:/", "key=s_name:/", "key=s:/a_b", "key=s:/a$b", "key=s:/a\\b",
				"key=s:/a\tb", "key=s:/a\nb", "key=s:\x00", "key=s:\x7f", "key=s:\x80", "key=s:\xc3\xa9",
			},
		},
		{
			name: "RDN parser", oid: SyntaxRDN,
			valid: []string{
				"", "cn=Alice", "cn=Alice+uid=alice", "2.5.4.3=Alice", " cn = Alice ", "\tcn\t=\tAlice\r",
				`cn=Alice\, Example`, `cn=Alice\+Example`, `cn=Alice\;Example`, `cn=Alice\00Example`,
				"cn=Alice,dc=example", "cn=Alice;ignored", "cn=Alice,not-a-dn", "cn=Alice,", `cn="Alice, Example"`,
				`cn="Alice+Example"+uid=alice`, `cn="Alice"ignored`, "cn=\xc3\xa9", "cn=Alice\tExample",
				"cn=Alice\\\tExample", "cn=#0405416c696365",
			},
			invalid: []string{
				" ", "\t", "\u00a0", "cn", "=Alice", "cn=Alice+", "cn=Alice+uid", "cn=a+CN=b", "cn=a\x00",
				"cn=a,ignored\x00", `cn=Alice\`, `cn=Alice\q`, `cn="Alice`, `cn=Al"ice`, "cn=<Alice>",
				"cn=#", "cn=#0401", "cn=#04016100", "cn=#xyz",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := NewRegistry()
			if err := registry.RegisterAttributeType(AttributeType{OID: "1.2.3.4", Names: []string{"testValue"}, Syntax: test.oid}); err != nil {
				t.Fatal(err)
			}
			for _, valid := range []bool{true, false} {
				values := test.invalid
				if valid {
					values = test.valid
				}
				for _, value := range values {
					if err := validateSyntax(test.oid, 0, []byte(value)); (err == nil) != valid {
						t.Errorf("validateSyntax(%q): %v; want valid=%t", value, err, valid)
					}
					if err := registry.ValidateAttributeValue("testValue", []byte(value)); (err == nil) != valid {
						t.Errorf("ValidateAttributeValue(%q): %v; want valid=%t", value, err, valid)
					}
				}
			}
		})
	}
}

func TestExtraBlobSyntaxMetadataAndArbitraryBytes(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	for _, oid := range []string{SyntaxAudio, SyntaxBinary, SyntaxJPEG} {
		t.Run(oid, func(t *testing.T) {
			syntax, ok := registry.LDAPSyntax(oid)
			if !ok || !syntax.HasValidator() || syntax.BinaryTransferRequired || syntax.BEREncoded != (oid == SyntaxBinary) {
				t.Fatalf("incorrect native blob/BER metadata: %#v", syntax)
			}
			if strings.Join(syntax.Extensions["X-NOT-HUMAN-READABLE"], "") != "TRUE" {
				t.Fatal("missing X-NOT-HUMAN-READABLE")
			}
			for _, value := range [][]byte{nil, {}, {0}, {0xff}, {0x30, 0xff}, []byte("not an image\x00\t\n\x7f\x80")} {
				if err := syntax.validator(value); err != nil {
					t.Fatalf("blob %x rejected: %v", value, err)
				}
				if err := validateSyntax(oid, 0, value); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestExtraSyntaxByteAlphabets(t *testing.T) {
	t.Parallel()
	for character := 0; character < 256; character++ {
		value := byte(character)
		if err := validateSyntax(SyntaxOtherMailbox, 0, []byte{value}); (err == nil) != (character < 128) {
			t.Errorf("OtherMailbox byte %x: %v", value, err)
		}
		adChar := strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.;", rune(value))
		for _, triple := range [][]byte{{'(', value, ',', ',', ')'}, {'(', ',', value, ',', ')'}, {'(', ',', ',', value, ')'}} {
			if err := validateNISNetgroupTriple(triple); (err == nil) != adChar {
				t.Errorf("netgroup %x: %v; want valid=%t", triple, err, adChar)
			}
		}
		printable := strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?", rune(value))
		if err := validateBootParameter([]byte{'=', ':', value}); (err == nil) != printable {
			t.Errorf("boot path byte %x: %v; want valid=%t", value, err, printable)
		}
		if err := validateBootParameter([]byte{value, '=', ':'}); (err == nil) != adChar {
			t.Errorf("boot key byte %x: %v; want valid=%t", value, err, adChar)
		}
		if err := validateBootParameter([]byte{'=', value, ':'}); (err == nil) != (adChar || value == ':') {
			// The first ':' ends the empty server; the second is a valid path.
			t.Errorf("boot server byte %x: %v", value, err)
		}
	}
}

func TestExtraSyntaxBoundsAndRDNDecodedBytes(t *testing.T) {
	t.Parallel()
	valid := "cn=" + strings.Repeat("a", maxRDNSyntaxLength-3)
	if err := validateRDN([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	if err := validateRDN([]byte(valid + "a")); err == nil {
		t.Fatal("oversized RDN accepted")
	}
	for _, oid := range []string{SyntaxAudio, SyntaxBinary, SyntaxJPEG, SyntaxOtherMailbox, SyntaxDeliveryMethod, SyntaxRDN, SyntaxNISNetgroupTriple, SyntaxBootParameter} {
		if err := validateSyntax(oid, 2, []byte("any")); err == nil {
			t.Errorf("syntax %s bypassed caller's length limit", oid)
		}
	}
	for _, test := range []struct{ input, want string }{
		{`cn="a\41b"`, "a41b"},
		{`cn=a\41b`, "aAb"},
		{`cn="a,b"`, "a,b"},
		{`cn=a\00b`, "a\x00b"},
		{"cn=a\xffb", "a\xffb"},
		{"cn=\"a\xffb\"", "a\xffb"},
		{"cn=a\\\tb", "a\tb"},
		{"cn=#0403610062", "a\x00b"},
		{"cn=#040361ff62", "a\xffb"},
	} {
		dn, err := parseRDNSyntax([]byte(test.input))
		if err != nil {
			t.Errorf("parseRDNSyntax(%q): %v", test.input, err)
			continue
		}
		if values := dn.RDNValues(); len(values) != 1 || string(values[0].Value) != test.want {
			t.Errorf("parseRDNSyntax(%q) decoded %#v; want %q", test.input, values, test.want)
		}
	}
}

func TestPrettyRDNValueNativeReadbacks(t *testing.T) {
	t.Parallel()
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	// Frozen actual stored values from syntax_publication_reference_test.go.
	for _, test := range []struct{ input, want string }{
		{"cn=Alice", "cn=Alice"},
		{"", ""},
		{"cn=Alice+uid=alice", "cn=Alice+uid=alice"},
		{`cn=Alice\, Example`, `cn=Alice\2C Example`},
		{"cn=Alice,dc=example", "cn=Alice"},
		{"cn=one,dc=ignored", "cn=one"},
		{`cn="a,b"`, `cn=a\2Cb`},
		{`cn="a,b",dc=ignored`, `cn=a\2Cb`},
		{"CN=Alice", "cn=Alice"},
		{"2.5.4.3=Alice", "cn=Alice"},
		{"cn=  Alice  ", "cn=Alice"},
		{`cn=Al\69ce`, "cn=Alice"},
	} {
		value := []byte(test.input)
		pretty, err := registry.PrettyRDNValue(value)
		if err != nil || string(pretty) != test.want {
			t.Errorf("PrettyRDNValue(%q) = %q, %v; want %q", test.input, pretty, err, test.want)
		}
		if string(value) != test.input {
			t.Fatal("PrettyRDNValue mutated its input")
		}
	}
	if pretty, err := registry.PrettyRDNValue(nil); err != nil || len(pretty) != 0 {
		t.Fatalf("nil value = %q, %v", pretty, err)
	}
}

func TestPrettyRDNValueSchemaAndBounds(t *testing.T) {
	t.Parallel()
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, attribute := range []AttributeType{
		{OID: "1.2.3.100", Names: []string{"CamelCase", "anAlias"}, Syntax: SyntaxDirectoryString},
		{OID: "1.2.3.101", Names: []string{"orderedName"}, Syntax: SyntaxDirectoryString, Extensions: map[string][]string{"X-ORDERED": {"VALUES"}}},
		{OID: "1.2.3.102", Names: []string{"nestedName"}, Syntax: SyntaxRDN},
	} {
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct{ input, want string }{
		{"anAlias=Value+uid=u", "CamelCase=Value+uid=u"},
		{"uid=u+anAlias=VaLuE", "CamelCase=VaLuE+uid=u"},
		{"cn=a  b", "cn=a  b"},
		{`cn=" a "`, `cn=\20a\20`},
		{`cn="a+b=c;d\\e"`, `cn=a\2Bb\3Dc\3Bd\5Ce`},
		{"cn=\xc3\xa9", "cn=\xc3\xa9"},
		{`nestedName="CN=Alice,dc=ignored"`, `nestedName=cn\3DAlice`},
	} {
		got, err := registry.PrettyRDNValue([]byte(test.input))
		if err != nil || string(got) != test.want {
			t.Errorf("PrettyRDNValue(%q) = %q, %v; want %q", test.input, got, err, test.want)
		}
	}
	for _, value := range []string{
		"noSuchAttribute=Alice", "noSuchAttribute=Alice,cn=Alice", "uidNumber=NaN", "cn=", "userPassword=",
		"cn=Alice+2.5.4.3=Bob", "anAlias=a+CamelCase=b", "orderedName=value", "cn=\xff", `cn=\FF`,
		"cn=#0405416c696365", "cn=Alice\x00", "cn=Alice,ignored\x00",
		"cn=" + strings.Repeat("a", maxRDNSyntaxLength-2), strings.Repeat("nestedName=", 32) + "cn=Alice",
	} {
		if got, err := registry.PrettyRDNValue([]byte(value)); err == nil || got != nil {
			t.Errorf("invalid value %q returned %q, %v", value, got, err)
		}
	}
	value := "cn=" + strings.Repeat("a", maxRDNSyntaxLength-3)
	if got, err := registry.PrettyRDNValue([]byte(value)); err != nil || string(got) != value {
		t.Errorf("8192-byte RDN: %v", err)
	}
}

func TestExtraRDNConstructedBERIsNotRecursivelyDecoded(t *testing.T) {
	t.Parallel()
	encoded := berTestValue(berTagOctetString, 'a')
	for range 500 {
		encoded = append([]byte{0x30, 0x82, byte(len(encoded) >> 8), byte(len(encoded))}, encoded...)
	}
	value := []byte("cn=#" + hex.EncodeToString(encoded))
	if len(value) > maxRDNSyntaxLength {
		t.Fatal("fixture exceeds the RDN input bound")
	}
	dn, err := parseRDNSyntax(value)
	if err != nil {
		t.Fatal(err)
	}
	element, err := parseBERElement(encoded, 0)
	if err != nil {
		t.Fatal(err)
	}
	if values := dn.RDNValues(); len(values) != 1 || !bytes.Equal(values[0].Value, encoded[element.contentStart:]) {
		t.Fatal("RDN parser altered the outer BER element's content")
	}
}

func TestExtraSyntaxSubstitutionAndLength(t *testing.T) {
	t.Parallel()
	for oid, value := range map[string]string{
		SyntaxAudio: "\x00\xff", SyntaxBinary: "\x00\xff", SyntaxJPEG: "\x00\xff",
		SyntaxOtherMailbox: "\x00\x7f", SyntaxDeliveryMethod: "any",
		SyntaxRDN: "cn=a", SyntaxNISNetgroupTriple: "(,,)", SyntaxBootParameter: "=:",
	} {
		registry := NewRegistry()
		if err := registry.registerLDAPSyntax(LDAPSyntax{OID: "1.2.3.1", Extensions: map[string][]string{"X-SUBST": {oid}}}); err != nil {
			t.Fatal(err)
		}
		attribute := AttributeType{OID: "1.2.3.2", Names: []string{"testValue"}, Syntax: "1.2.3.1", SyntaxLength: len(value)}
		if err := registry.RegisterAttributeType(attribute); err != nil {
			t.Fatal(err)
		}
		if err := registry.ValidateAttributeValue("testValue", []byte(value)); err != nil {
			t.Errorf("%s substituted syntax: %v", oid, err)
		}
		if err := registry.ValidateAttributeValue("testValue", []byte(value+value)); err == nil {
			t.Errorf("%s substituted syntax bypassed the caller's length bound", oid)
		}
		alias, ok := registry.LDAPSyntax("1.2.3.1")
		if !ok || alias.BinaryTransferRequired || alias.BEREncoded != (oid == SyntaxBinary) || !alias.HasValidator() {
			t.Errorf("%s substituted syntax metadata: %#v", oid, alias)
		}
	}
}

func TestExtraSyntaxPinnedSource(t *testing.T) {
	root := os.Getenv("OPENLDAP_SOURCE")
	if root == "" {
		t.Skip("set OPENLDAP_SOURCE to a Git checkout containing OpenLDAP 2.6.13")
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
	for oid, validator := range map[string]string{
		SyntaxAudio: "blobValidate", SyntaxBinary: "berValidate", SyntaxJPEG: "blobValidate",
		SyntaxOtherMailbox: "IA5StringValidate", SyntaxDeliveryMethod: "deliveryMethodValidate",
		SyntaxNISNetgroupTriple: "nisNetgroupTripleValidate", SyntaxBootParameter: "bootParameterValidate", SyntaxRDN: "rdnValidate",
	} {
		pattern := `(?s)\{\s*"\( ` + regexp.QuoteMeta(oid) + `\s[^}]*?\b` + validator + `\b[^}]*\}`
		if !regexp.MustCompile(pattern).MatchString(source) {
			t.Errorf("pinned OID %s is not wired to %s", oid, validator)
		}
	}
	if !strings.Contains(source, "#define berValidate blobValidate") || !strings.Contains(source, "blobValidate(\n\tSyntax *syntax,\n\tstruct berval *in )\n{\n\t/* any value allowed */\n\treturn LDAP_SUCCESS;\n}") {
		t.Fatal("native BER/blob validator changed")
	}
	header := read("servers/slapd/slap.h")
	if !regexp.MustCompile(fmt.Sprintf(`#define\s+SLAP_LDAPDN_MAXLEN\s+%d\b`, maxRDNSyntaxLength)).MatchString(header) {
		t.Fatal("RDN length limit differs from pinned source")
	}
	dnSource := read("servers/slapd/dn.c")
	start := strings.Index(dnSource, "\nrdnValidate(")
	if start < 0 {
		t.Fatal("rdnValidate missing from native source")
	}
	end := strings.Index(dnSource[start:], "\n}\n")
	if end < 0 || !strings.Contains(dnSource[start:start+end], "ldap_bv2rdn_x(") || !strings.Contains(dnSource[start:start+end], "LDAPRDN_validate( rdn )") {
		t.Fatal("native first-RDN/schema validation contract changed")
	}
}

func FuzzExtraSyntaxValidators(f *testing.F) {
	for _, value := range [][]byte{nil, {}, {0xff}, []byte("any $ ia5"), []byte("(,,)"), []byte("=:"), []byte(`cn="a,b"`), []byte("cn=#3080308000000000")} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		if len(value) > 1<<20 {
			t.Skip()
		}
		original := bytes.Clone(value)
		for _, oid := range []string{SyntaxAudio, SyntaxBinary, SyntaxJPEG, SyntaxOtherMailbox, SyntaxDeliveryMethod, SyntaxRDN, SyntaxNISNetgroupTriple, SyntaxBootParameter} {
			_ = validateSyntax(oid, 0, value)
			if !bytes.Equal(value, original) {
				t.Fatalf("syntax %s mutated its input", oid)
			}
		}
	})
}
