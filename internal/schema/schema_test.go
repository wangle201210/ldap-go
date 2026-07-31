package schema

import (
	"errors"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestParseOpenLDAPSchemaDescriptions(t *testing.T) {
	t.Parallel()

	attribute, err := ParseAttributeType(
		"{12}( 1.2.3.4 NAME ( 'appID' 'legacyAppID' ) DESC 'Application\\20identifier' " +
			"EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch " +
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} SINGLE-VALUE X-ORIGIN 'test' )",
	)
	if err != nil {
		t.Fatalf("ParseAttributeType(): %v", err)
	}
	if attribute.OID != "1.2.3.4" ||
		len(attribute.Names) != 2 ||
		attribute.Description != "Application identifier" ||
		attribute.SyntaxLength != 64 ||
		!attribute.SingleValue ||
		attribute.Extensions["X-ORIGIN"][0] != "test" {
		t.Fatalf("attribute = %#v", attribute)
	}

	objectClass, err := ParseObjectClass(
		"{3}( 1.2.3.5 NAME 'appUser' SUP ( person $ organizationalPerson ) " +
			"AUXILIARY MUST appID MAY ( mail $ description ) X-ORIGIN ( 'one' 'two' ) )",
	)
	if err != nil {
		t.Fatalf("ParseObjectClass(): %v", err)
	}
	if objectClass.Kind != ObjectClassAuxiliary ||
		len(objectClass.Superiors) != 2 ||
		len(objectClass.Must) != 1 ||
		len(objectClass.May) != 2 ||
		len(objectClass.Extensions["X-ORIGIN"]) != 2 {
		t.Fatalf("objectClass = %#v", objectClass)
	}
}

func TestBuiltinSchemaValidatesEntries(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	valid := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: byteValues("inetOrgPerson")},
			{Description: "uid", Values: byteValues("alice")},
			{Description: "cn", Values: byteValues("Alice")},
			{Description: "sn", Values: byteValues("Example")},
			{Description: "mail", Values: byteValues("alice@example.com")},
		},
	}
	if err := registry.ValidateEntry(valid); err != nil {
		t.Fatalf("ValidateEntry(valid): %v", err)
	}

	missingRequired := valid.Clone()
	missingRequired.ReplaceValues("sn", nil)
	assertViolation(t, registry.ValidateEntry(missingRequired), ViolationMissingRequiredAttribute)

	undefined := valid.Clone()
	undefined.Attributes = append(undefined.Attributes, directory.Attribute{
		Description: "notInSchema",
		Values:      byteValues("value"),
	})
	assertViolation(t, registry.ValidateEntry(undefined), ViolationUndefinedAttribute)

	singleValue := directory.Entry{
		DN: "dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: byteValues("domain")},
			{Description: "dc", Values: byteValues("example", "second")},
		},
	}
	assertViolation(t, registry.ValidateEntry(singleValue), ViolationSingleValue)

	referral := directory.Entry{
		DN: "ou=remote,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values:      byteValues("referral", "extensibleObject"),
			},
			{Description: "ou", Values: byteValues("remote")},
			{
				Description: "ref",
				Values:      byteValues("ldap://remote.example/dc=remote,dc=example"),
			},
		},
	}
	if err := registry.ValidateEntry(referral); err != nil {
		t.Fatalf("ValidateEntry(referral): %v", err)
	}
	if !registry.EntryHasObjectClass(referral, "referral") {
		t.Fatal("referral object class was not identified")
	}

	alias := directory.Entry{
		DN: "cn=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values:      byteValues("alias", "extensibleObject"),
			},
			{Description: "cn", Values: byteValues("alice")},
			{
				Description: "aliasedObjectName",
				Values:      byteValues("uid=alice,dc=example,dc=com"),
			},
		},
	}
	if err := registry.ValidateEntry(alias); err != nil {
		t.Fatalf("ValidateEntry(alias): %v", err)
	}
	if !registry.EntryHasObjectClass(alias, "alias") {
		t.Fatal("alias object class was not identified")
	}
	if !registry.IsDNValued("aliasedEntryName") {
		t.Fatal("aliasedObjectName alias was not identified as DN-valued")
	}

	aliasAttributeOnOrdinaryEntry := valid.Clone()
	aliasAttributeOnOrdinaryEntry.Attributes = append(
		aliasAttributeOnOrdinaryEntry.Attributes,
		directory.Attribute{
			Description: "aliasedObjectName",
			Values:      byteValues("uid=bob,dc=example,dc=com"),
		},
	)
	assertViolation(
		t,
		registry.ValidateEntry(aliasAttributeOnOrdinaryEntry),
		ViolationDisallowedAttribute,
	)

	refOnOrdinaryEntry := valid.Clone()
	refOnOrdinaryEntry.Attributes = append(
		refOnOrdinaryEntry.Attributes,
		directory.Attribute{
			Description: "ref",
			Values:      byteValues("ldap://remote.example/"),
		},
	)
	assertViolation(
		t,
		registry.ValidateEntry(refOnOrdinaryEntry),
		ViolationDisallowedAttribute,
	)

	subentry := directory.Entry{
		DN: "cn=policy,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: byteValues("subentry")},
			{Description: "cn", Values: byteValues("policy")},
			{Description: "subtreeSpecification", Values: byteValues("{}")},
		},
	}
	if err := registry.ValidateEntry(subentry); err != nil {
		t.Fatalf("ValidateEntry(subentry): %v", err)
	}
	if !registry.EntryHasObjectClass(subentry, "subentry") {
		t.Fatal("subentry object class was not identified")
	}

	missingSubtreeSpecification := subentry.Clone()
	missingSubtreeSpecification.ReplaceValues("subtreeSpecification", nil)
	assertViolation(
		t,
		registry.ValidateEntry(missingSubtreeSpecification),
		ViolationMissingRequiredAttribute,
	)

	subtreeSpecificationOnOrdinaryEntry := valid.Clone()
	subtreeSpecificationOnOrdinaryEntry.Attributes = append(
		subtreeSpecificationOnOrdinaryEntry.Attributes,
		directory.Attribute{
			Description: "subtreeSpecification",
			Values:      byteValues("{}"),
		},
	)
	assertViolation(
		t,
		registry.ValidateEntry(subtreeSpecificationOnOrdinaryEntry),
		ViolationDisallowedAttribute,
	)
}

func TestRegistryIdentifiesDNValuedAttributes(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if err := registry.ParseAndRegisterAttributeType(
		"( 1.2.3.4 NAME 'delegatedCreator' SUP creatorsName )",
	); err != nil {
		t.Fatalf("register inherited DN attribute: %v", err)
	}

	if !registry.IsDNValued("creatorsName") {
		t.Fatal("direct DN syntax was not identified")
	}
	if !registry.IsDNValued("delegatedCreator") {
		t.Fatal("inherited DN syntax was not identified")
	}
	if registry.IsDNValued("cn") || registry.IsDNValued("undefined") {
		t.Fatal("non-DN attribute was identified as DN-valued")
	}
}

func TestRegistryCloneIsIndependent(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	cloned := registry.Clone()
	if err := cloned.ParseAndRegisterAttributeType(
		"( 1.2.3.4 NAME 'cloneOnly' EQUALITY caseIgnoreMatch SYNTAX " +
			SyntaxDirectoryString + " )",
	); err != nil {
		t.Fatalf("register clone attribute: %v", err)
	}
	if _, exists := registry.AttributeType("cloneOnly"); exists {
		t.Fatal("clone mutation changed the source registry")
	}
	if _, exists := cloned.AttributeType("cn"); !exists {
		t.Fatal("clone lost a built-in alias")
	}
}

func TestRegistryAcceptsCustomOpenLDAPSchema(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if err := registry.ParseAndRegisterAttributeType(
		"( 1.2.3.4 NAME 'appID' EQUALITY caseIgnoreMatch " +
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
	); err != nil {
		t.Fatalf("register attribute: %v", err)
	}
	if err := registry.ParseAndRegisterObjectClass(
		"( 1.2.3.5 NAME 'appUser' SUP top AUXILIARY MUST appID )",
	); err != nil {
		t.Fatalf("register object class: %v", err)
	}
	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: byteValues("inetOrgPerson", "appUser")},
			{Description: "uid", Values: byteValues("alice")},
			{Description: "cn", Values: byteValues("Alice")},
			{Description: "sn", Values: byteValues("Example")},
			{Description: "appID", Values: byteValues("portal")},
		},
	}
	if err := registry.ValidateEntry(entry); err != nil {
		t.Fatalf("ValidateEntry(custom): %v", err)
	}
}

func TestSchemaAwareMatching(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	comparison, err := registry.Compare("uid", "", []byte(" Alice   Example "), []byte("alice example"))
	if err != nil {
		t.Fatalf("Compare(uid): %v", err)
	}
	if comparison != 0 {
		t.Fatalf("Compare(uid) = %d, want 0", comparison)
	}
	comparison, err = registry.Compare("userPassword", "", []byte("Secret"), []byte("secret"))
	if err != nil {
		t.Fatalf("Compare(userPassword): %v", err)
	}
	if comparison == 0 {
		t.Fatal("octetStringMatch ignored byte case")
	}
	matches, err := registry.MatchSubstring(
		"mail",
		[]byte("Alice.Example@EXAMPLE.COM"),
		directory.Substring{Initial: []byte("alice"), Final: []byte(".com")},
	)
	if err != nil {
		t.Fatalf("MatchSubstring(mail): %v", err)
	}
	if !matches {
		t.Fatal("caseIgnoreIA5 substring did not match")
	}
}

func TestSchemaOrderingMatching(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	comparison, err := registry.CompareOrdering(
		"uidNumber",
		"",
		[]byte("10"),
		[]byte("2"),
	)
	if err != nil {
		t.Fatalf("CompareOrdering(uidNumber): %v", err)
	}
	if comparison <= 0 {
		t.Fatalf("CompareOrdering(uidNumber) = %d, want positive", comparison)
	}

	comparison, err = registry.CompareOrdering(
		"cn",
		"2.5.13.3",
		[]byte(" Alice "),
		[]byte("bob"),
	)
	if err != nil {
		t.Fatalf("CompareOrdering(cn, OID): %v", err)
	}
	if comparison >= 0 {
		t.Fatalf("CompareOrdering(cn, OID) = %d, want negative", comparison)
	}

	comparison, err = registry.CompareOrdering(
		"mail",
		"1.3.6.1.4.1.1466.109.114.2",
		[]byte(" Alice@example.com "),
		[]byte("bob@example.com"),
	)
	if err != nil {
		t.Fatalf("CompareOrdering(mail, IA5 OID): %v", err)
	}
	if comparison >= 0 {
		t.Fatalf(
			"CompareOrdering(mail, IA5 OID) = %d, want negative",
			comparison,
		)
	}

	if _, err := registry.OrderingRule("cn", ""); err == nil {
		t.Fatal("OrderingRule(cn) accepted an attribute without ORDERING")
	}
	if _, err := registry.OrderingRule("missing", "caseIgnoreOrderingMatch"); err == nil {
		t.Fatal("OrderingRule(missing) accepted an undefined attribute")
	}
	if _, err := registry.OrderingRule("cn", "missingOrderingMatch"); err == nil {
		t.Fatal("OrderingRule(cn) accepted an unsupported matching rule")
	}
}

func TestSchemaDescriptionsRoundTripAndPublishOnce(t *testing.T) {
	t.Parallel()

	attribute, err := ParseAttributeType(
		"( 1.2.3.4 NAME ( 'appID' 'legacyAppID' ) DESC 'Application\\20ID' " +
			"EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} " +
			"SINGLE-VALUE X-ORIGIN ( 'one' 'two' ) )",
	)
	if err != nil {
		t.Fatalf("ParseAttributeType(): %v", err)
	}
	formatted := FormatAttributeType(attribute)
	roundTripped, err := ParseAttributeType(formatted)
	if err != nil {
		t.Fatalf("ParseAttributeType(formatted): %v", err)
	}
	if roundTripped.OID != attribute.OID ||
		roundTripped.Description != attribute.Description ||
		roundTripped.SyntaxLength != attribute.SyntaxLength ||
		len(roundTripped.Names) != len(attribute.Names) {
		t.Fatalf("round-tripped attribute = %#v, source = %#v", roundTripped, attribute)
	}

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	descriptions := registry.AttributeTypeDescriptions()
	uidDefinitions := 0
	for _, description := range descriptions {
		if strings.HasPrefix(description, "( 0.9.2342.19200300.100.1.1 ") {
			uidDefinitions++
		}
	}
	if uidDefinitions != 1 {
		t.Fatalf("published uid definitions = %d, want 1", uidDefinitions)
	}
}

func TestStructuralObjectClassUsesMostSpecificClass(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	entry := directory.Entry{
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values:      byteValues("top", "person", "organizationalPerson", "inetOrgPerson"),
			},
		},
	}
	structural, err := registry.StructuralObjectClass(entry)
	if err != nil {
		t.Fatalf("StructuralObjectClass(): %v", err)
	}
	if structural != "inetOrgPerson" {
		t.Fatalf("structural object class = %q, want inetOrgPerson", structural)
	}
}

func assertViolation(t *testing.T, err error, kind ViolationKind) {
	t.Helper()
	var violation *Violation
	if !errors.As(err, &violation) || violation.Kind != kind {
		t.Fatalf("error = %v, want violation kind %d", err, kind)
	}
}

func byteValues(values ...string) [][]byte {
	result := make([][]byte, len(values))
	for i := range values {
		result[i] = []byte(values[i])
	}
	return result
}
