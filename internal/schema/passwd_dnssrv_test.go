package schema

import "testing"

func TestBuiltinPasswdAndDNSSRVConfigurationSchema(t *testing.T) {
	t.Parallel()
	registry, err := NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	passwdFile, ok := registry.AttributeType("olcPasswdFile")
	if !ok || passwdFile.OID != openLDAPPasswdDatabaseAttributeOID+".1" ||
		!passwdFile.SingleValue || passwdFile.Equality != "caseExactMatch" {
		t.Fatalf("olcPasswdFile = %#v, found %t", passwdFile, ok)
	}
	passwdConfig, ok := registry.ObjectClass("olcPasswdConfig")
	if !ok || passwdConfig.OID != openLDAPPasswdDatabaseObjectOID+".1" ||
		!containsSchemaName(passwdConfig.Superiors, "olcDatabaseConfig") ||
		!containsSchemaName(passwdConfig.May, "olcPasswdFile") {
		t.Fatalf("olcPasswdConfig = %#v, found %t", passwdConfig, ok)
	}
	for _, name := range []string{"olcDNSSRVCacheTTL", "olcDNSSRVNegativeTTL"} {
		attribute, found := registry.AttributeType(name)
		if !found || !attribute.SingleValue {
			t.Fatalf("%s = %#v, found %t", name, attribute, found)
		}
	}
	dnssrvConfig, ok := registry.ObjectClass("olcDNSSRVConfig")
	if !ok || !containsSchemaName(dnssrvConfig.Superiors, "olcDatabaseConfig") {
		t.Fatalf("olcDNSSRVConfig = %#v, found %t", dnssrvConfig, ok)
	}
}

func containsSchemaName(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
