package schema

import "fmt"

const (
	openLDAPAsyncMetaDatabaseAttributeOID = "1.3.6.1.4.1.4203.1.12.2.3.2"
	openLDAPAsyncMetaDatabaseObjectOID    = "1.3.6.1.4.1.4203.1.12.2.4.2"
)

var openLDAPAsyncMetaAttributeTypes = []string{
	"( " + openLDAPAsyncMetaDatabaseAttributeOID + ".3.113 NAME 'olcDbMaxPendingOps' DESC 'Maximum number of pending operations' SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( " + openLDAPAsyncMetaDatabaseAttributeOID + ".3.114 NAME 'olcDbMaxTargetConns' DESC 'Maximum number of open connections per target' SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( " + openLDAPAsyncMetaDatabaseAttributeOID + ".3.115 NAME 'olcDbMaxTimeoutOps' DESC 'Maximum number of consecutive timeout operations after which the connection is reset' SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( " + openLDAPAsyncMetaDatabaseAttributeOID + ".3.116 NAME 'olcAsyncMetaSub' DESC 'Placeholder to name a Target entry' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE X-ORDERED 'SIBLINGS' )",
	"( " + openLDAPAsyncMetaDatabaseAttributeOID + ".3.117 NAME 'olcDbSuffixMassage' DESC 'DN suffix massage' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
}

var openLDAPAsyncMetaObjectClasses = []string{
	"( " + openLDAPAsyncMetaDatabaseObjectOID + ".3.4 NAME 'olcAsyncMetaConfig' DESC 'Asyncmeta backend configuration' SUP olcDatabaseConfig STRUCTURAL MAY ( olcDbDnCacheTtl $ olcDbIdleTimeout $ olcDbOnErr $ olcDbPseudoRootBindDefer $ olcDbConnectionPoolMax $ olcDbMaxTimeoutOps $ olcDbMaxPendingOps $ olcDbMaxTargetConns $ olcDbBindTimeout $ olcDbCancel $ olcDbChaseReferrals $ olcDbClientPr $ olcDbDefaultTarget $ olcDbNetworkTimeout $ olcDbNoRefs $ olcDbNoUndefFilter $ olcDbNretries $ olcDbProtocolVersion $ olcDbQuarantine $ olcDbRebindAsUser $ olcDbSessionTrackingRequest $ olcDbStartTLS $ olcDbTFSupport ) )",
	"( " + openLDAPAsyncMetaDatabaseObjectOID + ".3.5 NAME 'olcAsyncMetaTargetConfig' DESC 'Asyncmeta target configuration' SUP olcConfig STRUCTURAL MUST ( olcAsyncMetaSub $ olcDbURI ) MAY ( olcDbIDAssertAuthzFrom $ olcDbIDAssertBind $ olcDbSuffixMassage $ olcDbSubtreeExclude $ olcDbSubtreeInclude $ olcDbTimeout $ olcDbKeepalive $ olcDbFilter $ olcDbTcpUserTimeout $ olcDbBindTimeout $ olcDbCancel $ olcDbChaseReferrals $ olcDbClientPr $ olcDbDefaultTarget $ olcDbNetworkTimeout $ olcDbNoRefs $ olcDbNoUndefFilter $ olcDbNretries $ olcDbProtocolVersion $ olcDbQuarantine $ olcDbRebindAsUser $ olcDbSessionTrackingRequest $ olcDbStartTLS $ olcDbTFSupport ) )",
}

// RegisterOpenLDAPAsyncMetaSchema registers the cn=config schema exported by
// OpenLDAP 2.6.13 back-asyncmeta. Shared back-ldap attributes are registered by
// RegisterOpenLDAPMetaSchema; this function owns asyncmeta's unique fields.
func RegisterOpenLDAPAsyncMetaSchema(registry *Registry) error {
	if registry == nil {
		return fmt.Errorf("register OpenLDAP back-asyncmeta schema: nil registry")
	}
	for _, description := range openLDAPAsyncMetaAttributeTypes {
		attribute, err := ParseAttributeType(description)
		if err != nil {
			return fmt.Errorf("parse OpenLDAP back-asyncmeta attribute type: %w", err)
		}
		if err := registerCompatibleMetaAttribute(registry, attribute); err != nil {
			return err
		}
	}
	for _, description := range openLDAPAsyncMetaObjectClasses {
		objectClass, err := ParseObjectClass(description)
		if err != nil {
			return fmt.Errorf("parse OpenLDAP back-asyncmeta object class: %w", err)
		}
		if err := registerCompatibleMetaObjectClass(registry, objectClass); err != nil {
			return err
		}
	}
	return nil
}
