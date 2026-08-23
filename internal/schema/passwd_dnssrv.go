package schema

import (
	"fmt"
	"strings"
)

const (
	openLDAPPasswdDatabaseAttributeOID = "1.3.6.1.4.1.4203.1.12.2.3.2.9"
	openLDAPPasswdDatabaseObjectOID    = "1.3.6.1.4.1.4203.1.12.2.4.2.9"

	// OpenLDAP 2.6.13 does not expose backend-specific cn=config fields for
	// back-dnssrv. This experimental arc contains ldap-go's cache controls.
	ldapGoDNSSRVConfigOID = "1.3.6.1.4.1.4203.666.11.99.8"
)

var passwdDNSSRVAttributeTypes = []string{
	"( " + openLDAPPasswdDatabaseAttributeOID + ".1 NAME 'olcPasswdFile' DESC 'File containing passwd records' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + ldapGoDNSSRVConfigOID + ".1 NAME 'olcDNSSRVCacheTTL' DESC 'Positive DNS SRV cache lifetime' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( " + ldapGoDNSSRVConfigOID + ".2 NAME 'olcDNSSRVNegativeTTL' DESC 'Negative DNS SRV cache lifetime' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
}

var passwdDNSSRVObjectClasses = []string{
	"( " + openLDAPPasswdDatabaseObjectOID + ".1 NAME 'olcPasswdConfig' DESC 'Passwd backend configuration' SUP olcDatabaseConfig MAY olcPasswdFile )",
	"( " + ldapGoDNSSRVConfigOID + ".3 NAME 'olcDNSSRVConfig' DESC 'DNS SRV backend cache configuration' SUP olcDatabaseConfig MAY ( olcDNSSRVCacheTTL $ olcDNSSRVNegativeTTL ) )",
}

// RegisterOpenLDAPPasswdDNSSRVSchema registers the OpenLDAP back-passwd
// configuration schema and the cache controls used by ldap-go's back-dnssrv.
func RegisterOpenLDAPPasswdDNSSRVSchema(registry *Registry) error {
	if registry == nil {
		return fmt.Errorf("register passwd and dnssrv schema: nil registry")
	}
	for _, description := range passwdDNSSRVAttributeTypes {
		attribute, err := ParseAttributeType(description)
		if err != nil {
			return fmt.Errorf("parse passwd and dnssrv attribute type: %w", err)
		}
		if err := registerCompatiblePasswdDNSSRVAttribute(registry, attribute); err != nil {
			return err
		}
	}
	for _, description := range passwdDNSSRVObjectClasses {
		objectClass, err := ParseObjectClass(description)
		if err != nil {
			return fmt.Errorf("parse passwd and dnssrv object class: %w", err)
		}
		if err := registerCompatiblePasswdDNSSRVObjectClass(registry, objectClass); err != nil {
			return err
		}
	}
	return nil
}

func registerCompatiblePasswdDNSSRVAttribute(registry *Registry, want AttributeType) error {
	existing, found := registry.AttributeType(want.OID)
	for _, name := range want.Names {
		byName, ok := registry.AttributeType(name)
		if !ok {
			continue
		}
		if found && !strings.EqualFold(existing.OID, byName.OID) {
			return fmt.Errorf("register attribute type %q: identifiers conflict", want.Name())
		}
		existing, found = byName, true
	}
	if !found {
		if err := registry.RegisterAttributeType(want); err != nil {
			return fmt.Errorf("register attribute type %q: %w", want.Name(), err)
		}
		return nil
	}
	if !compatibleSockAttribute(existing, want) {
		return fmt.Errorf("register attribute type %q: incompatible existing definition", want.Name())
	}
	return nil
}

func registerCompatiblePasswdDNSSRVObjectClass(registry *Registry, want ObjectClass) error {
	existing, found := registry.ObjectClass(want.OID)
	for _, name := range want.Names {
		byName, ok := registry.ObjectClass(name)
		if !ok {
			continue
		}
		if found && !strings.EqualFold(existing.OID, byName.OID) {
			return fmt.Errorf("register object class %q: identifiers conflict", want.Name())
		}
		existing, found = byName, true
	}
	if !found {
		if err := registry.RegisterObjectClass(want); err != nil {
			return fmt.Errorf("register object class %q: %w", want.Name(), err)
		}
		return nil
	}
	if !compatibleSockObjectClass(existing, want) {
		return fmt.Errorf("register object class %q: incompatible existing definition", want.Name())
	}
	return nil
}
