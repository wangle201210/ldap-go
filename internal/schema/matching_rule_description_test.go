package schema

import (
	"reflect"
	"strings"
	"testing"
)

func TestMatchingRuleDescriptionRoundTrip(t *testing.T) {
	t.Parallel()

	description := `{7}( 2.5.13.2 NAME ( 'caseIgnoreMatch' 'case-ignore' ) DESC 'owner\27s \5C rule' OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN ( 'RFC 4517' 'local' ) X-NOTE ')' )`
	want := MatchingRule{
		OID: "2.5.13.2", Names: []string{"caseIgnoreMatch", "case-ignore"},
		Description: "owner's \\ rule", Obsolete: true, Syntax: SyntaxDirectoryString,
		Extensions: map[string][]string{"X-ORIGIN": {"RFC 4517", "local"}, "X-NOTE": {")"}},
	}
	got, err := ParseMatchingRule(description)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseMatchingRule(): %#v, %v; want %#v", got, err, want)
	}
	formatted := FormatMatchingRule(got)
	wantFormatted := `( 2.5.13.2 NAME ( 'caseIgnoreMatch' 'case-ignore' ) DESC 'owner\27s \5C rule' OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-NOTE ')' X-ORIGIN ( 'RFC 4517' 'local' ) )`
	if formatted != wantFormatted {
		t.Fatalf("FormatMatchingRule() = %q; want %q", formatted, wantFormatted)
	}
	roundTrip, err := ParseMatchingRule(formatted)
	if err != nil || !reflect.DeepEqual(roundTrip, want) {
		t.Fatalf("round trip: %#v, %v; want %#v", roundTrip, err, want)
	}
}

func TestMatchingRuleUseDescriptionRoundTrip(t *testing.T) {
	t.Parallel()

	description := `( 2.5.13.2 NAME 'caseIgnoreMatch' DESC 'directory strings' OBSOLETE APPLIES ( cn $ 2.5.4.4 $ displayName ) X-ORIGIN 'RFC 4512' )`
	want := MatchingRuleUse{
		OID: "2.5.13.2", Names: []string{"caseIgnoreMatch"}, Description: "directory strings",
		Obsolete: true, Applies: []string{"cn", "2.5.4.4", "displayName"},
		Extensions: map[string][]string{"X-ORIGIN": {"RFC 4512"}},
	}
	got, err := ParseMatchingRuleUse(description)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseMatchingRuleUse(): %#v, %v; want %#v", got, err, want)
	}
	if formatted := FormatMatchingRuleUse(got); formatted != description {
		t.Fatalf("FormatMatchingRuleUse() = %q; want %q", formatted, description)
	}
	roundTrip, err := ParseMatchingRuleUse(FormatMatchingRuleUse(got))
	if err != nil || !reflect.DeepEqual(roundTrip, want) {
		t.Fatalf("round trip: %#v, %v; want %#v", roundTrip, err, want)
	}
}

func TestMatchingRuleDescriptionsAcceptCompatibleForms(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		"",
		"NAME 'customRule'",
		"NAME ( )",
		"DESC ''",
		"DESC '(' X-NOTE ( ')' '$' )",
		"NAME 'a-9' DESC 'NAME SYNTAX APPLIES'",
		"name ( 'foo' 'bar' ) obsolete desc 'text'",
		"X-NOTE ( ) X-LOCAL_TAG 'value'",
		"X-NOTE '\\27\\5c\\00\\7F'",
		"DESC '\\E4\\B8\\AD\\E6\\96\\87'",
	} {
		t.Run(body, func(t *testing.T) {
			rule, err := ParseMatchingRule("( 1.2 SYNTAX 1.3 " + body + " )")
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseMatchingRule(FormatMatchingRule(rule))
			if err != nil || !reflect.DeepEqual(got, rule) {
				t.Fatalf("rule round trip: %#v, %v; want %#v", got, err, rule)
			}
			use, err := ParseMatchingRuleUse("\t{0}( 1.2 APPLIES ( cn$SN ) " + body + " )\n")
			if err != nil {
				t.Fatal(err)
			}
			gotUse, err := ParseMatchingRuleUse(FormatMatchingRuleUse(use))
			if err != nil || !reflect.DeepEqual(gotUse, use) {
				t.Fatalf("use round trip: %#v, %v; want %#v", gotUse, err, use)
			}
		})
	}
}

func TestMatchingRuleDescriptionsRejectMalformedFields(t *testing.T) {
	t.Parallel()

	for _, field := range []string{
		"NAME", "NAME bare", "NAME '1.2'", "NAME '1name'", "NAME '-name'",
		"NAME 'under_score'", "NAME 'with space'", "NAME 'cn;lang-en'", "NAME ''",
		`NAME '\66oo'`, "NAME ( 'a' $ 'b' )", "NAME ( ( 'a' ) )",
		"NAME 'a' NAME 'b'", "NAME 'a' name 'b'", "NAME ( ) NAME ( )",
		"DESC", "DESC unquoted", "DESC ( 'a' )", "DESC 'a' DESC 'b'", "DESC '' DESC ''",
		`DESC '\'`, `DESC '\xx'`, `DESC '\a'`, "DESC 'unterminated",
		"DESC '\xff'", `DESC '\FF'`, `DESC '\C0\80'`,
		"OBSOLETE OBSOLETE", "OBSOLETE TRUE",
		"X-ORIGIN", "X- 'a'", "X-TAG1 'a'", "X-TAG.VALUE 'a'", "X-ORIGIN bare",
		"X-NOTE ( 'a' $ 'b' )", "X-NOTE ( ( 'a' ) )",
		"X-NOTE 'a' X-NOTE 'b'", "X-NOTE ( ) x-note 'b'",
		"NAME'a'", "NAME ( 'a''b' )", "DESC 'a'OBSOLETE",
		"DESC 'a' 'OBSOLETE'", "'NAME' 'a'", "DESC 'a')(", "( )", "$",
		"SUP other", "SINGLE-VALUE", "MUST cn", "UNKNOWN 'a'",
		"\x00", "\u00a0OBSOLETE", "\u017fYNTAX 1.3", "X-\u017f 'a'",
	} {
		t.Run(field, func(t *testing.T) {
			if got, err := ParseMatchingRule("( 1.2 SYNTAX 1.3 " + field + " )"); err == nil || !reflect.DeepEqual(got, MatchingRule{}) {
				t.Fatalf("accepted malformed rule field %q: %#v, %v", field, got, err)
			}
			if got, err := ParseMatchingRuleUse("( 1.2 APPLIES cn " + field + " )"); err == nil || !reflect.DeepEqual(got, MatchingRuleUse{}) {
				t.Fatalf("accepted malformed use field %q: %#v, %v", field, got, err)
			}
		})
	}
}

func TestMatchingRuleDescriptionsRequireNumericOIDs(t *testing.T) {
	t.Parallel()

	for _, oid := range []string{"", "name", "1", ".1.2", "1.2.", "1..2", "01.2", "1.02", "1.-2", "1.2a", "'1.2'", "1.2{64}", "1.2:3"} {
		t.Run(oid, func(t *testing.T) {
			if _, err := ParseMatchingRule("( " + oid + " SYNTAX 1.3 )"); err == nil {
				t.Fatalf("accepted rule OID %q", oid)
			}
			if _, err := ParseMatchingRuleUse("( " + oid + " APPLIES cn )"); err == nil {
				t.Fatalf("accepted rule use OID %q", oid)
			}
			if _, err := ParseMatchingRule("( 1.2 SYNTAX " + oid + " )"); err == nil {
				t.Fatalf("accepted syntax OID %q", oid)
			}
		})
	}
	for _, oid := range []string{"0.0", "1.0", "2.5.13.2", "1.2.9999999999999999999999999999999999999999999999999"} {
		if _, err := ParseMatchingRule("( " + oid + " SYNTAX " + oid + " )"); err != nil {
			t.Fatalf("valid numeric OID %q: %v", oid, err)
		}
	}
}

func TestMatchingRuleDescriptionsRequiredFieldsAndStructure(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"", "1.2", "( )", "( 1.2 )", "( 1.2 NAME 'rule' )",
		"( 1.2 APPLIES cn )", "( 1.2 SYNTAX 1.3 SYNTAX 1.4 )",
		"( 1.2 SYNTAX ( 1.3 ) )", "( 1.2 SYNTAX 1.3 APPLIES cn )",
		"( 1.2 SYNTAX 1.3", "( 1.2 SYNTAX 1.3 ) trailing",
		"( 1.2 SYNTAX 1.3 ) ( 1.3 SYNTAX 1.4 )",
		"{}( 1.2 SYNTAX 1.3 )", "{-1}( 1.2 SYNTAX 1.3 )", "{x}( 1.2 SYNTAX 1.3 )",
	} {
		if _, err := ParseMatchingRule(value); err == nil {
			t.Errorf("accepted malformed rule %q", value)
		}
	}
	for _, value := range []string{
		"", "1.2", "( )", "( 1.2 )", "( 1.2 NAME 'rule' )", "( 1.2 SYNTAX 1.3 )",
		"( 1.2 APPLIES cn APPLIES sn )", "( 1.2 APPLIES )", "( 1.2 APPLIES ( ) )",
		"( 1.2 APPLIES ( cn sn ) )", "( 1.2 APPLIES ( cn $ ) )", "( 1.2 APPLIES ( $ cn ) )",
		"( 1.2 APPLIES ( cn $$ sn ) )", "( 1.2 APPLIES ( ( cn ) ) )",
		"( 1.2 APPLIES 'cn' )", "( 1.2 APPLIES ( cn $ 'sn' ) )",
		"( 1.2 APPLIES cn;lang-en )", "( 1.2 APPLIES * )", "( 1.2 APPLIES 01.2 )",
		"( 1.2 APPLIES cn SYNTAX 1.3 )", "( 1.2 APPLIES cn ) ( 1.3 APPLIES sn )",
		"( 1.2 APPLIES cn", "( 1.2 APPLIES cn ) trailing",
	} {
		if _, err := ParseMatchingRuleUse(value); err == nil {
			t.Errorf("accepted malformed rule use %q", value)
		}
	}
}

func TestMatchingRuleDescriptionBounds(t *testing.T) {
	t.Parallel()

	for _, use := range []bool{false, true} {
		parse := func(value string) error {
			if use {
				_, err := ParseMatchingRuleUse(value)
				return err
			}
			_, err := ParseMatchingRule(value)
			return err
		}
		required := "SYNTAX 1.3"
		if use {
			required = "APPLIES cn"
		}
		prefix, suffix := "( 1.2 "+required+" DESC '", "' )"
		atLimit := prefix + strings.Repeat("a", maxMatchingRuleDescriptionSize-len(prefix)-len(suffix)) + suffix
		if err := parse(atLimit); err != nil {
			t.Fatalf("use=%v: exact size limit: %v", use, err)
		}
		if err := parse(atLimit + " "); err == nil {
			t.Fatalf("use=%v: accepted oversized input", use)
		}
		manyTokens := "( 1.2 " + required + " X-NOTE ( " + strings.Repeat("'a' ", maxMatchingRuleDescriptionTokens) + ") )"
		if err := parse(manyTokens); err == nil || !strings.Contains(err.Error(), "tokens") {
			t.Fatalf("use=%v: token bound: %v", use, err)
		}
		nested := "( 1.2 " + required + " X-NOTE " + strings.Repeat("(", 10000) + "'x'" + strings.Repeat(")", 10000) + " )"
		if err := parse(nested); err == nil {
			t.Fatalf("use=%v: accepted nested schema lists", use)
		}
	}
}

func TestMatchingRuleDescriptionSyntaxValidation(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatal(err)
	}
	// The SYNTAX field names an assertion syntax. It must never execute that
	// syntax's validator (in particular, a certificate/crypto decoder).
	registry.syntaxes[SyntaxCertificate].validator = func([]byte) error {
		t.Fatal("description validation executed the referenced certificate validator")
		return nil
	}
	for _, test := range []struct {
		attribute, syntax, valid, invalid string
	}{
		{"matchingRules", SyntaxMatchingRule, "( 1.2 SYNTAX " + SyntaxCertificate + " )", "( 1.2 NAME 'rule' )"},
		{"matchingRuleUse", SyntaxMatchingRuleUse, "( 1.2 APPLIES ( unknownAttribute $ 1.9.8 ) )", "( 1.2 APPLIES ( ) )"},
	} {
		attribute, ok := registry.AttributeType(test.attribute)
		if !ok || attribute.Syntax != test.syntax {
			t.Fatalf("attribute %s syntax = %q, known=%v", test.attribute, attribute.Syntax, ok)
		}
		for _, validate := range []func([]byte) error{
			func(value []byte) error { return validateSyntax(test.syntax, 0, value) },
			func(value []byte) error { return registry.validateSyntax(test.syntax, 0, value) },
			func(value []byte) error { return registry.ValidateAttributeValue(test.attribute, value) },
		} {
			if err := validate([]byte(test.valid)); err != nil {
				t.Errorf("%s rejected valid description: %v", test.attribute, err)
			}
			if err := validate([]byte(test.invalid)); err == nil {
				t.Errorf("%s accepted invalid description", test.attribute)
			}
		}
		if err := validateSyntax(test.syntax, len(test.valid)-1, []byte(test.valid)); err == nil {
			t.Errorf("%s ignored declared syntax length", test.attribute)
		}
		if err := registry.validateSyntax(test.syntax, len(test.valid)-1, []byte(test.valid)); err == nil {
			t.Errorf("%s registry ignored declared syntax length", test.attribute)
		}
	}
	if _, err := ParseMatchingRule("( 1.2 SYNTAX 1.2.99999999 )"); err != nil {
		t.Fatalf("parsing an unknown syntax must not require registration: %v", err)
	}
}

func FuzzMatchingRuleDescriptionRoundTrip(f *testing.F) {
	for _, seed := range []struct {
		use   bool
		value string
	}{
		{false, "( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"},
		{true, "( 2.5.13.2 NAME 'caseIgnoreMatch' APPLIES ( cn $ 2.5.4.4 ) )"},
		{false, "( 1.2 NAME ( ) DESC '' SYNTAX 1.3 X-NOTE ( ) )"},
		{true, "( 1.2 DESC ')' APPLIES cn X-NOTE ( '(' '$' ) )"},
		{false, `( 1.2 DESC '\27\5C\00' SYNTAX 1.3 )`},
		{true, "( 1.2 APPLIES ( cn $$ sn ) )"},
		{false, ""},
	} {
		f.Add(seed.use, seed.value)
	}
	f.Fuzz(func(t *testing.T, use bool, description string) {
		if use {
			first, err := ParseMatchingRuleUse(description)
			if err != nil {
				return
			}
			formatted := FormatMatchingRuleUse(first)
			if len(formatted) > maxMatchingRuleDescriptionSize {
				return
			}
			second, err := ParseMatchingRuleUse(formatted)
			if err != nil || !reflect.DeepEqual(first, second) {
				t.Fatalf("use round trip: %#v -> %#v, %v", first, second, err)
			}
		} else {
			first, err := ParseMatchingRule(description)
			if err != nil {
				return
			}
			formatted := FormatMatchingRule(first)
			if len(formatted) > maxMatchingRuleDescriptionSize {
				return
			}
			second, err := ParseMatchingRule(formatted)
			if err != nil || !reflect.DeepEqual(first, second) {
				t.Fatalf("rule round trip: %#v -> %#v, %v", first, second, err)
			}
		}
	})
}
