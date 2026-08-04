package schema

import (
	"context"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLoadOpenLDAPConfigSchema(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	schemaEntry := directory.Entry{
		DN: "cn={1}application,cn=schema,cn=config",
		Attributes: []directory.Attribute{
			{
				Description: "olcAttributeTypes",
				Values: byteValues(
					"{0}( 1.2.3.4 NAME 'appID' EQUALITY caseIgnoreMatch " +
						"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
				),
			},
			{
				Description: "olcObjectClasses",
				Values: byteValues(
					"{0}( 1.2.3.5 NAME 'appUser' SUP top AUXILIARY MUST appID )",
				),
			},
			{
				Description: "olcDitContentRules",
				Values: byteValues(
					"{0}( 2.16.840.1.113730.3.2.2 " +
						"NAME 'appPersonRule' AUX appUser MUST uid NOT jpegPhoto )",
				),
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		return tx.Put(schemaEntry, false)
	}); err != nil {
		t.Fatalf("seed schema: %v", err)
	}

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	result, err := LoadOpenLDAPConfig(context.Background(), store, registry)
	if err != nil {
		t.Fatalf("LoadOpenLDAPConfig(): %v", err)
	}
	if result.AttributeTypes != 1 ||
		result.ObjectClasses != 1 ||
		result.ContentRules != 1 {
		t.Fatalf("LoadResult = %#v", result)
	}
	if contentRule, ok := registry.DITContentRule("appPersonRule"); !ok ||
		contentRule.OID != "2.16.840.1.113730.3.2.2" {
		t.Fatalf("appPersonRule = %#v, found %t", contentRule, ok)
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
		t.Fatalf("ValidateEntry(): %v", err)
	}
}

func TestLoadOpenLDAPConfigSchemaIgnoresBusinessEntries(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "olcAttributeTypes", Values: byteValues("not a schema description")},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		return tx.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed entry: %v", err)
	}

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	result, err := LoadOpenLDAPConfig(context.Background(), store, registry)
	if err != nil {
		t.Fatalf("LoadOpenLDAPConfig(): %v", err)
	}
	if result.AttributeTypes != 0 ||
		result.ObjectClasses != 0 ||
		result.ContentRules != 0 {
		t.Fatalf("LoadResult = %#v", result)
	}
}

func TestLoadOpenLDAPConfigRejectsDuplicateDITContentRules(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entry := directory.Entry{
		DN: "cn={1}rules,cn=schema,cn=config",
		Attributes: []directory.Attribute{
			{
				Description: "olcDitContentRules",
				Values: byteValues(
					"{0}( 2.5.6.6 NAME 'firstPersonRule' )",
					"{1}( 2.5.6.6 NAME 'secondPersonRule' )",
				),
			},
		},
	}
	if err := store.Update(context.Background(), func(tx storage.Writer) error {
		return tx.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed duplicate content rules: %v", err)
	}
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if _, err := LoadOpenLDAPConfig(
		context.Background(),
		store,
		registry,
	); err == nil {
		t.Fatal("LoadOpenLDAPConfig() accepted duplicate DIT content rules")
	}
}

func TestBuiltinOpenLDAPCSNAttributes(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	entryCSN, ok := registry.AttributeType("entryCSN")
	if !ok ||
		entryCSN.Syntax != SyntaxCSN ||
		entryCSN.SyntaxLength != 64 ||
		!entryCSN.SingleValue ||
		!entryCSN.NoUserModification ||
		entryCSN.Usage != UsageDirectoryOperation {
		t.Fatalf("entryCSN = %#v, found %t", entryCSN, ok)
	}
	contextCSN, ok := registry.AttributeType("contextCSN")
	if !ok ||
		contextCSN.Syntax != SyntaxCSN ||
		contextCSN.SyntaxLength != 64 ||
		contextCSN.SingleValue ||
		!contextCSN.NoUserModification ||
		contextCSN.Usage != UsageDSAOperation {
		t.Fatalf("contextCSN = %#v, found %t", contextCSN, ok)
	}
	lastChangeNumber, ok := registry.AttributeType("lastChangeNumber")
	if !ok || lastChangeNumber.OID != "1.3.6.1.4.1.4203.666.1.28" ||
		lastChangeNumber.Syntax != SyntaxInteger ||
		!lastChangeNumber.SingleValue ||
		!lastChangeNumber.NoUserModification ||
		lastChangeNumber.Usage != UsageDirectoryOperation {
		t.Fatalf(
			"lastChangeNumber = %#v, found %t",
			lastChangeNumber,
			ok,
		)
	}

	modern := "20260730010101.000001Z#00000A#001#00000B"
	legacy := "20260730010101Z#00000a#01#00000b"
	leapSecond := "20161231235960.000000Z#000001#001#000001"
	entry := directory.Entry{
		DN: "dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: byteValues("domain")},
			{Description: "dc", Values: byteValues("example")},
			{Description: "entryCSN", Values: byteValues(modern)},
			{
				Description: "contextCSN",
				Values:      byteValues(modern, legacy, leapSecond),
			},
		},
	}
	if err := registry.ValidateEntry(entry); err != nil {
		t.Fatalf("ValidateEntry(valid CSNs): %v", err)
	}

	comparison, err := registry.Compare(
		"contextCSN",
		"",
		[]byte(legacy),
		[]byte("20260730010101.000000Z#00000a#001#00000b"),
	)
	if err != nil || comparison != 0 {
		t.Fatalf("legacy CSN equality = %d, %v", comparison, err)
	}
	comparison, err = registry.CompareOrdering(
		"contextCSN",
		"",
		[]byte(modern),
		[]byte(legacy),
	)
	if err != nil || comparison <= 0 {
		t.Fatalf("CSN ordering = %d, %v", comparison, err)
	}
	comparison, err = registry.CompareOrdering(
		"contextCSN",
		"",
		[]byte(leapSecond),
		[]byte("20170101000000.000000Z#000001#001#000001"),
	)
	if err != nil || comparison >= 0 {
		t.Fatalf("leap-second CSN ordering = %d, %v", comparison, err)
	}

	for _, malformed := range []string{
		"20260730010101.000001Z#+00001#001#00000b",
		"20260730010101.000001Z#000001#0+1#00000b",
		"20260730010101.000001Z#000001#001#0000+1",
		"20260730010101.00001Z#000001#001#000001",
		"20260230010101.000001Z#000001#001#000001",
	} {
		invalid := entry.Clone()
		invalid.ReplaceValues("contextCSN", byteValues(malformed))
		assertViolation(t, registry.ValidateEntry(invalid), ViolationSyntax)
	}
}

func TestBuiltinOpenLDAPACI(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	attribute, ok := registry.AttributeType("OpenLDAPaci")
	if !ok || !attribute.Hidden || attribute.Syntax != SyntaxOpenLDAPACI ||
		attribute.Equality != "OpenLDAPaciMatch" ||
		attribute.Usage != UsageDirectoryOperation ||
		!registry.IsACIValued("OpenLDAPaci") {
		t.Fatalf("OpenLDAPaci = %#v, found %t", attribute, ok)
	}
	roleOccupant, ok := registry.AttributeType("roleOccupant")
	if !ok || !registry.IsDNReferenceValued("roleOccupant") {
		t.Fatalf("roleOccupant = %#v, found %t", roleOccupant, ok)
	}
	allowed, known := registry.ObjectClassAllowsAttribute("organizationalRole", "roleOccupant")
	if !known || !allowed {
		t.Fatal("organizationalRole does not allow roleOccupant")
	}

	valid := directory.Entry{
		DN: "dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: byteValues("domain")},
			{Description: "dc", Values: byteValues("example")},
			{
				Description: "OpenLDAPaci",
				Values: byteValues(
					"0#subtree#grant;d,c,s,r;[all]#public#",
				),
			},
		},
	}
	if err := registry.ValidateEntry(valid); err != nil {
		t.Fatalf("ValidateEntry(valid ACI): %v", err)
	}
	invalid := valid.Clone()
	invalid.ReplaceValues("OpenLDAPaci", byteValues("not an ACI"))
	if err := registry.ValidateEntry(invalid); err == nil {
		t.Fatal("ValidateEntry() accepted invalid OpenLDAP ACI syntax")
	}

	left := []byte("0#SUBTREE#GRANT;r;CN#ACCESS-ID#UID=Alice,DC=Example,DC=COM")
	right := []byte("0#subtree#grant;r;cn#access-id#uid=alice,dc=example,dc=com")
	comparison, err := registry.Compare("OpenLDAPaci", "", left, right)
	if err != nil {
		t.Fatalf("Compare(OpenLDAPaci): %v", err)
	}
	if comparison != 0 {
		t.Fatalf("Compare(OpenLDAPaci) = %d, want 0", comparison)
	}
}

func TestBuiltinDITContentRulesAttribute(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	attribute, found := registry.AttributeType("dITContentRules")
	if !found ||
		attribute.OID != "2.5.21.2" ||
		attribute.Syntax != SyntaxDITContentRule ||
		attribute.Usage != UsageDirectoryOperation {
		t.Fatalf("dITContentRules = %#v, found %t", attribute, found)
	}
}

func TestBuiltinOpenLDAPAuthorizationSchema(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, name := range []string{
		"authzTo",
		"saslAuthzTo",
		"authzFrom",
		"saslAuthzFrom",
	} {
		attribute, found := registry.AttributeType(name)
		if !found ||
			attribute.Syntax != SyntaxAuthz ||
			attribute.Equality != "authzMatch" ||
			attribute.Usage != UsageDistributedOperation ||
			!attribute.Hidden ||
			len(attribute.Extensions["X-ORDERED"]) != 1 ||
			attribute.Extensions["X-ORDERED"][0] != "VALUES" {
			t.Fatalf("%s = %#v, found %t", name, attribute, found)
		}
	}

	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: byteValues("inetOrgPerson")},
			{Description: "uid", Values: byteValues("alice")},
			{Description: "cn", Values: byteValues("Alice")},
			{Description: "sn", Values: byteValues("Example")},
			{
				Description: "authzTo",
				Values: byteValues(
					"{0}dn.subtree:ou=people,dc=example,dc=com",
					"{1}ldap:///ou=people,dc=example,dc=com??sub?(uid=*)",
				),
			},
			{
				Description: "saslAuthzFrom",
				Values:      byteValues("group:cn=operators,dc=example,dc=com"),
			},
		},
	}
	if err := registry.ValidateEntry(entry); err != nil {
		t.Fatalf("ValidateEntry(authz rules): %v", err)
	}
	invalid := entry.Clone()
	invalid.ReplaceValues("authzTo", byteValues("not an authz rule"))
	assertViolation(t, registry.ValidateEntry(invalid), ViolationSyntax)

	descriptions := strings.Join(registry.AttributeTypeDescriptions(), "\n")
	if strings.Contains(descriptions, "1.3.6.1.4.1.4203.666.1.8") ||
		strings.Contains(descriptions, "1.3.6.1.4.1.4203.666.1.9") {
		t.Fatalf("published authorization attributes:\n%s", descriptions)
	}
}

func TestBuiltinDynamicDirectorySchema(t *testing.T) {
	t.Parallel()

	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	entryTTL, ok := registry.AttributeType("entryTtl")
	if !ok ||
		entryTTL.OID != "1.3.6.1.4.1.1466.101.119.3" ||
		entryTTL.Syntax != SyntaxInteger ||
		!entryTTL.SingleValue ||
		!entryTTL.NoUserModification ||
		entryTTL.Usage != UsageDSAOperation ||
		entryTTL.Hidden {
		t.Fatalf("entryTtl = %#v, found %t", entryTTL, ok)
	}
	dynamicSubtrees, ok := registry.AttributeType("dynamicSubtrees")
	if !ok ||
		dynamicSubtrees.OID != "1.3.6.1.4.1.1466.101.119.4" ||
		dynamicSubtrees.Syntax != SyntaxDistinguishedName ||
		dynamicSubtrees.SingleValue ||
		!dynamicSubtrees.NoUserModification ||
		dynamicSubtrees.Usage != UsageDSAOperation ||
		dynamicSubtrees.Hidden {
		t.Fatalf(
			"dynamicSubtrees = %#v, found %t",
			dynamicSubtrees,
			ok,
		)
	}
	expiration, ok := registry.AttributeType("entryExpireTimestamp")
	if !ok ||
		expiration.OID != "1.3.6.1.4.1.4203.666.1.57" ||
		expiration.Syntax != SyntaxGeneralizedTime ||
		!expiration.SingleValue ||
		!expiration.NoUserModification ||
		expiration.Usage != UsageDSAOperation ||
		!expiration.Hidden {
		t.Fatalf("entryExpireTimestamp = %#v, found %t", expiration, ok)
	}
	dynamicObject, ok := registry.ObjectClass("dynamicObject")
	if !ok ||
		dynamicObject.OID != "1.3.6.1.4.1.1466.101.119.2" ||
		dynamicObject.Kind != ObjectClassAuxiliary {
		t.Fatalf("dynamicObject = %#v, found %t", dynamicObject, ok)
	}

	descriptions := strings.Join(registry.AttributeTypeDescriptions(), "\n")
	if !strings.Contains(descriptions, "1.3.6.1.4.1.1466.101.119.3") ||
		!strings.Contains(descriptions, "1.3.6.1.4.1.1466.101.119.4") ||
		strings.Contains(descriptions, "1.3.6.1.4.1.4203.666.1.57") {
		t.Fatalf("published DDS attribute descriptions:\n%s", descriptions)
	}

	entry := directory.Entry{
		DN: "cn=lease,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values:      byteValues("organizationalRole", "dynamicObject"),
			},
			{Description: "cn", Values: byteValues("lease")},
			{Description: "entryTtl", Values: byteValues("60")},
			{
				Description: "entryExpireTimestamp",
				Values:      byteValues("20260731120000Z"),
			},
		},
	}
	if err := registry.ValidateEntry(entry); err != nil {
		t.Fatalf("ValidateEntry(dynamicObject): %v", err)
	}
}

func TestBuiltinDynamicGroupSchema(t *testing.T) {
	t.Parallel()
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, attribute := range []string{
		"memberURL",
		"dgIdentity",
		"dgAuthz",
		"dgMemberOf",
	} {
		if _, found := registry.AttributeType(attribute); !found {
			t.Fatalf("missing dynamic-group attribute %q", attribute)
		}
	}
	for _, objectClass := range []string{"groupOfURLs", "dgIdentityAux"} {
		if _, found := registry.ObjectClass(objectClass); !found {
			t.Fatalf("missing dynamic-group objectClass %q", objectClass)
		}
	}
	if !registry.AttributeDescriptionSubtype("memberURL", "labeledURI") {
		t.Fatal("memberURL is not a labeledURI subtype")
	}
	if !registry.IsDNValued("dgIdentity") || !registry.IsDNValued("dgMemberOf") {
		t.Fatal("dynamic-group DN attributes do not use DN syntax")
	}
}
