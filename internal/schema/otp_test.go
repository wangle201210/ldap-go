package schema

import (
	"reflect"
	"strings"
	"testing"
)

func TestRegisterOpenLDAPOTPSchemaComplete(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}

	type attributeExpectation struct {
		suffix, superior, syntax, equality, ordering, substring string
		syntaxLength                                            int
		singleValue                                             bool
	}
	wantAttributes := map[string]attributeExpectation{
		"oathSecret":             {suffix: ".4.1", syntax: SyntaxOctetString, equality: "octetStringMatch", substring: "octetStringSubstringsMatch", singleValue: true},
		"oathTokenSerialNumber":  {suffix: ".4.2", syntax: "1.3.6.1.4.1.1466.115.121.1.44", equality: "caseIgnoreMatch", substring: "caseIgnoreSubstringsMatch", syntaxLength: 64, singleValue: true},
		"oathTokenIdentifier":    {suffix: ".4.3", syntax: SyntaxDirectoryString, equality: "caseIgnoreMatch", syntaxLength: 256, singleValue: true},
		"oathParamsEntry":        {suffix: ".4.4", superior: "distinguishedName", singleValue: true},
		"oathTOTPTimeStepPeriod": {suffix: ".4.4.1", syntax: SyntaxInteger, equality: "integerMatch", ordering: "integerOrderingMatch", singleValue: true},
		"oathOTPLength":          {suffix: ".4.5", syntax: SyntaxInteger, equality: "integerMatch", ordering: "integerOrderingMatch", singleValue: true},
		"oathHOTPParams":         {suffix: ".4.5.1", superior: "oathParamsEntry", singleValue: true},
		"oathTOTPParams":         {suffix: ".4.5.2", superior: "oathParamsEntry", singleValue: true},
		"oathHMACAlgorithm":      {suffix: ".4.6", syntax: SyntaxOID, equality: "objectIdentifierMatch", singleValue: true},
		"oathTimestamp":          {suffix: ".4.7", syntax: SyntaxGeneralizedTime, equality: "generalizedTimeMatch", ordering: "generalizedTimeOrderingMatch", singleValue: true},
		"oathLastFailure":        {suffix: ".4.7.1", superior: "oathTimestamp", singleValue: true},
		"oathLastLogin":          {suffix: ".4.7.2", superior: "oathTimestamp", singleValue: true},
		"oathSecretTime":         {suffix: ".4.7.3", superior: "oathTimestamp", singleValue: true},
		"oathSecretMaxAge":       {suffix: ".4.8", syntax: SyntaxInteger, equality: "integerMatch", ordering: "integerOrderingMatch", singleValue: true},
		"oathToken":              {suffix: ".4.9", superior: "distinguishedName", singleValue: true},
		"oathHOTPToken":          {suffix: ".4.9.1", superior: "oathToken", singleValue: true},
		"oathTOTPToken":          {suffix: ".4.9.2", superior: "oathToken", singleValue: true},
		"oathCounter":            {suffix: ".4.10", syntax: SyntaxInteger, equality: "integerMatch", ordering: "integerOrderingMatch", singleValue: true},
		"oathFailureCount":       {suffix: ".4.10.1", superior: "oathCounter", singleValue: true},
		"oathHOTPCounter":        {suffix: ".4.10.2", superior: "oathCounter", singleValue: true},
		"oathHOTPLookAhead":      {suffix: ".4.10.3", superior: "oathCounter", singleValue: true},
		"oathThrottleLimit":      {suffix: ".4.10.5", superior: "oathCounter", singleValue: true},
		"oathTOTPLastTimeStep":   {suffix: ".4.10.6", superior: "oathCounter", singleValue: true},
		"oathMaxUsageCount":      {suffix: ".4.10.7", superior: "oathCounter", singleValue: true},
		"oathTOTPTimeStepWindow": {suffix: ".4.10.8", superior: "oathCounter", singleValue: true},
		"oathTOTPTimeStepDrift":  {suffix: ".4.10.9", superior: "oathCounter", singleValue: true},
		"oathSecretLength":       {suffix: ".4.11", syntax: SyntaxInteger, equality: "integerMatch", ordering: "integerOrderingMatch", singleValue: true},
		"oathEncKey":             {suffix: ".4.12", syntax: SyntaxDirectoryString, equality: "caseIgnoreMatch", substring: "caseIgnoreSubstringsMatch", singleValue: true},
		"oathResultCode":         {suffix: ".4.13", syntax: SyntaxInteger, equality: "integerMatch", ordering: "integerOrderingMatch", singleValue: true},
		"oathSuccessResultCode":  {suffix: ".4.13.1", superior: "oathResultCode"},
		"oathFailureResultCode":  {suffix: ".4.13.2", superior: "oathResultCode"},
		"oathTokenPIN":           {suffix: ".4.14", syntax: SyntaxDirectoryString, equality: "caseIgnoreMatch", substring: "caseIgnoreSubstringsMatch", singleValue: true},
		"oathMessage":            {suffix: ".4.15", syntax: SyntaxDirectoryString, equality: "caseIgnoreMatch", substring: "caseIgnoreSubstringsMatch", syntaxLength: 1024, singleValue: true},
		"oathSuccessMessage":     {suffix: ".4.15.1", superior: "oathMessage"},
		"oathFailureMessage":     {suffix: ".4.15.2", superior: "oathMessage"},
	}
	if len(wantAttributes) != len(openLDAPOTPAttributeTypes) {
		t.Fatalf("attribute expectation count = %d, definitions = %d", len(wantAttributes), len(openLDAPOTPAttributeTypes))
	}
	for name, want := range wantAttributes {
		attribute, found := registry.AttributeType(name)
		if !found {
			t.Errorf("attribute type %s was not registered", name)
			continue
		}
		if wantOID := openLDAPOTPSchemaOID + want.suffix; attribute.OID != wantOID {
			t.Errorf("%s OID = %q, want %q", name, attribute.OID, wantOID)
		}
		if !reflect.DeepEqual(attribute.Names, []string{name}) {
			t.Errorf("%s names = %q, want [%s]", name, attribute.Names, name)
		}
		if attribute.Superior != want.superior || attribute.Syntax != want.syntax || attribute.SyntaxLength != want.syntaxLength || attribute.Equality != want.equality || attribute.Ordering != want.ordering || attribute.Substring != want.substring || attribute.SingleValue != want.singleValue {
			t.Errorf("%s direct definition = SUP %q, syntax %q{%d}, equality %q, ordering %q, substr %q, single %t; want SUP %q, syntax %q{%d}, equality %q, ordering %q, substr %q, single %t", name, attribute.Superior, attribute.Syntax, attribute.SyntaxLength, attribute.Equality, attribute.Ordering, attribute.Substring, attribute.SingleValue, want.superior, want.syntax, want.syntaxLength, want.equality, want.ordering, want.substring, want.singleValue)
		}
		if got := attribute.Extensions["X-ORIGIN"]; !reflect.DeepEqual(got, []string{"OATH-LDAP"}) {
			t.Errorf("%s X-ORIGIN = %q, want [OATH-LDAP]", name, got)
		}
	}

	wantObjectClasses := map[string]string{
		"oathUser":       ".6.1",
		"oathHOTPUser":   ".6.1.1",
		"oathTOTPUser":   ".6.1.2",
		"oathParams":     ".6.2",
		"oathHOTPParams": ".6.2.1",
		"oathTOTPParams": ".6.2.2",
		"oathToken":      ".6.3",
		"oathHOTPToken":  ".6.3.1",
		"oathTOTPToken":  ".6.3.2",
	}
	if len(wantObjectClasses) != len(openLDAPOTPObjectClasses) {
		t.Fatalf("object-class expectation count = %d, definitions = %d", len(wantObjectClasses), len(openLDAPOTPObjectClasses))
	}
	for name, suffix := range wantObjectClasses {
		objectClass, found := registry.ObjectClass(name)
		if !found {
			t.Errorf("object class %s was not registered", name)
			continue
		}
		if want := openLDAPOTPSchemaOID + suffix; objectClass.OID != want {
			t.Errorf("%s OID = %q, want %q", name, objectClass.OID, want)
		}
		if !reflect.DeepEqual(objectClass.Names, []string{name}) {
			t.Errorf("%s names = %q, want [%s]", name, objectClass.Names, name)
		}
		if got := objectClass.Extensions["X-ORIGIN"]; !reflect.DeepEqual(got, []string{"OATH-LDAP"}) {
			t.Errorf("%s X-ORIGIN = %q, want [OATH-LDAP]", name, got)
		}
	}
}

func TestOpenLDAPOTPRuntimeAttributeDefinitions(t *testing.T) {
	t.Parallel()

	registry := newOpenLDAPOTPTestRegistry(t)
	tests := []struct {
		name     string
		syntax   string
		equality string
		ordering string
	}{
		{name: "oathSecret", syntax: SyntaxOctetString, equality: "octetStringMatch"},
		{name: "oathTOTPTimeStepPeriod", syntax: SyntaxInteger, equality: "integerMatch", ordering: "integerOrderingMatch"},
		{name: "oathOTPLength", syntax: SyntaxInteger, equality: "integerMatch", ordering: "integerOrderingMatch"},
		{name: "oathHOTPParams", syntax: SyntaxDistinguishedName, equality: "distinguishedNameMatch"},
		{name: "oathTOTPParams", syntax: SyntaxDistinguishedName, equality: "distinguishedNameMatch"},
		{name: "oathHMACAlgorithm", syntax: SyntaxOID, equality: "objectIdentifierMatch"},
		{name: "oathHOTPToken", syntax: SyntaxDistinguishedName, equality: "distinguishedNameMatch"},
		{name: "oathTOTPToken", syntax: SyntaxDistinguishedName, equality: "distinguishedNameMatch"},
		{name: "oathHOTPCounter", syntax: SyntaxInteger, equality: "integerMatch", ordering: "integerOrderingMatch"},
		{name: "oathHOTPLookAhead", syntax: SyntaxInteger, equality: "integerMatch", ordering: "integerOrderingMatch"},
		{name: "oathTOTPLastTimeStep", syntax: SyntaxInteger, equality: "integerMatch", ordering: "integerOrderingMatch"},
		{name: "oathTOTPTimeStepWindow", syntax: SyntaxInteger, equality: "integerMatch", ordering: "integerOrderingMatch"},
		{name: "oathTOTPTimeStepDrift", syntax: SyntaxInteger, equality: "integerMatch", ordering: "integerOrderingMatch"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			effective, found, err := registry.EffectiveAttributeType(test.name)
			if err != nil {
				t.Fatalf("EffectiveAttributeType(%q): %v", test.name, err)
			}
			if !found {
				t.Fatalf("EffectiveAttributeType(%q) was not found", test.name)
			}
			if effective.Syntax != test.syntax || effective.Equality != test.equality || effective.Ordering != test.ordering {
				t.Errorf("%s effective rules = syntax %q, equality %q, ordering %q; want %q, %q, %q", test.name, effective.Syntax, effective.Equality, effective.Ordering, test.syntax, test.equality, test.ordering)
			}
		})
	}
}

func TestOpenLDAPOTPObjectClassDefinitionsPreserveUpstream(t *testing.T) {
	t.Parallel()

	registry := newOpenLDAPOTPTestRegistry(t)
	tests := []struct {
		name      string
		kind      ObjectClassKind
		superiors []string
		must      []string
		may       []string
	}{
		{name: "oathUser", kind: ObjectClassAbstract},
		// otp.c declares the HOTP token reference MAY despite the man page
		// describing it as mandatory. Compatibility requires preserving MAY.
		{name: "oathHOTPUser", kind: ObjectClassAuxiliary, superiors: []string{"oathUser"}, may: []string{"oathHOTPToken"}},
		{name: "oathTOTPUser", kind: ObjectClassAuxiliary, superiors: []string{"oathUser"}, must: []string{"oathTOTPToken"}},
		{name: "oathParams", kind: ObjectClassAbstract, must: []string{"oathOTPLength", "oathHMACAlgorithm"}, may: []string{"oathSecretMaxAge", "oathSecretLength", "oathMaxUsageCount", "oathThrottleLimit", "oathEncKey", "oathSuccessResultCode", "oathSuccessMessage", "oathFailureResultCode", "oathFailureMessage"}},
		{name: "oathHOTPParams", kind: ObjectClassAuxiliary, superiors: []string{"oathParams"}, must: []string{"oathHOTPLookAhead"}},
		// Runtime reads drift from params, but otp.c does not allow it here.
		{name: "oathTOTPParams", kind: ObjectClassAuxiliary, superiors: []string{"oathParams"}, must: []string{"oathTOTPTimeStepPeriod"}, may: []string{"oathTOTPTimeStepWindow"}},
		{name: "oathToken", kind: ObjectClassAbstract, may: []string{"oathSecret", "oathSecretTime", "oathLastLogin", "oathFailureCount", "oathLastFailure", "oathTokenSerialNumber", "oathTokenIdentifier", "oathTokenPIN"}},
		{name: "oathHOTPToken", kind: ObjectClassAuxiliary, superiors: []string{"oathToken"}, may: []string{"oathHOTPParams", "oathHOTPCounter"}},
		// otp.c permits drift on the token even though runtime reads it from params.
		{name: "oathTOTPToken", kind: ObjectClassAuxiliary, superiors: []string{"oathToken"}, may: []string{"oathTOTPParams", "oathTOTPLastTimeStep", "oathTOTPTimeStepDrift"}},
	}
	for _, test := range tests {
		objectClass, found := registry.ObjectClass(test.name)
		if !found {
			t.Fatalf("object class %s was not found", test.name)
		}
		if objectClass.Kind != test.kind || !reflect.DeepEqual(objectClass.Superiors, test.superiors) || !reflect.DeepEqual(objectClass.Must, test.must) || !reflect.DeepEqual(objectClass.May, test.may) {
			t.Errorf("%s = kind %q, SUP %q, MUST %q, MAY %q; want %q, %q, %q, %q", test.name, objectClass.Kind, objectClass.Superiors, objectClass.Must, objectClass.May, test.kind, test.superiors, test.must, test.may)
		}
	}
}

func TestRegisterOpenLDAPOTPSchemaRepeatedCall(t *testing.T) {
	t.Parallel()

	registry := newOpenLDAPOTPTestRegistry(t)
	attributesBefore := registry.AttributeTypeDescriptions()
	objectClassesBefore := registry.ObjectClassDescriptions()
	err := RegisterOpenLDAPOTPSchema(registry)
	if err == nil || !strings.Contains(err.Error(), `attribute type "oathSecret"`) || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("second RegisterOpenLDAPOTPSchema() error = %v, want stable oathSecret duplicate error", err)
	}
	if _, found := registry.ObjectClass("oathTOTPToken"); !found {
		t.Fatal("second registration damaged existing OTP schema")
	}
	if got := registry.AttributeTypeDescriptions(); !reflect.DeepEqual(got, attributesBefore) {
		t.Fatal("second registration changed registered attribute types")
	}
	if got := registry.ObjectClassDescriptions(); !reflect.DeepEqual(got, objectClassesBefore) {
		t.Fatal("second registration changed registered object classes")
	}
}

func TestRegisterOpenLDAPOTPSchemaRejectsNilRegistry(t *testing.T) {
	t.Parallel()

	if err := RegisterOpenLDAPOTPSchema(nil); err == nil || err.Error() != "register OpenLDAP OTP schema: nil registry" {
		t.Fatalf("RegisterOpenLDAPOTPSchema(nil) error = %v", err)
	}
}

func newOpenLDAPOTPTestRegistry(t *testing.T) *Registry {
	t.Helper()
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	return registry
}
