package schema

import "fmt"

const (
	SyntaxACIItem                = "1.3.6.1.4.1.1466.115.121.1.1"
	SyntaxOpenLDAPACI            = "1.3.6.1.4.1.4203.666.2.1"
	SyntaxBoolean                = "1.3.6.1.4.1.1466.115.121.1.7"
	SyntaxCertificate            = "1.3.6.1.4.1.1466.115.121.1.8"
	SyntaxCertificateList        = "1.3.6.1.4.1.1466.115.121.1.9"
	SyntaxCertificatePair        = "1.3.6.1.4.1.1466.115.121.1.10"
	SyntaxAttributeType          = "1.3.6.1.4.1.1466.115.121.1.3"
	SyntaxAuthenticationPassword = "1.3.6.1.4.1.4203.1.1.2"
	SyntaxAuthz                  = "1.3.6.1.4.1.4203.666.2.7"
	SyntaxDITContentRule         = "1.3.6.1.4.1.1466.115.121.1.16"
	SyntaxDITStructureRule       = "1.3.6.1.4.1.1466.115.121.1.17"
	SyntaxDistinguishedName      = "1.3.6.1.4.1.1466.115.121.1.12"
	SyntaxDirectoryString        = "1.3.6.1.4.1.1466.115.121.1.15"
	SyntaxFacsimileTelephone     = "1.3.6.1.4.1.1466.115.121.1.22"
	SyntaxGeneralizedTime        = "1.3.6.1.4.1.1466.115.121.1.24"
	SyntaxIA5String              = "1.3.6.1.4.1.1466.115.121.1.26"
	SyntaxInteger                = "1.3.6.1.4.1.1466.115.121.1.27"
	SyntaxNameAndOptionalUID     = "1.3.6.1.4.1.1466.115.121.1.34"
	SyntaxNumericString          = "1.3.6.1.4.1.1466.115.121.1.36"
	SyntaxNameForm               = "1.3.6.1.4.1.1466.115.121.1.35"
	SyntaxObjectClass            = "1.3.6.1.4.1.1466.115.121.1.37"
	SyntaxOID                    = "1.3.6.1.4.1.1466.115.121.1.38"
	SyntaxOctetString            = "1.3.6.1.4.1.1466.115.121.1.40"
	SyntaxPostalAddress          = "1.3.6.1.4.1.1466.115.121.1.41"
	SyntaxPrintableString        = "1.3.6.1.4.1.1466.115.121.1.44"
	SyntaxSubtreeSpecification   = "1.3.6.1.4.1.1466.115.121.1.45"
	SyntaxSupportedAlgorithm     = "1.3.6.1.4.1.1466.115.121.1.49"
	SyntaxTelephoneNumber        = "1.3.6.1.4.1.1466.115.121.1.50"
	SyntaxTelexNumber            = "1.3.6.1.4.1.1466.115.121.1.52"
	SyntaxUUID                   = "1.3.6.1.1.16.1"
	SyntaxCSN                    = "1.3.6.1.4.1.4203.666.11.2.1"
	SyntaxAttributeCertificate   = "1.3.6.1.4.1.4203.666.11.10.2.1"
	SyntaxPKCS8PrivateKey        = "1.2.840.113549.1.8.1.1"
	SyntaxOpenLDAPVoid           = "1.3.6.1.4.1.4203.1.1.1"
)

func NewBuiltinRegistry() (*Registry, error) {
	registry := NewRegistry()
	for _, description := range builtinAttributeTypes {
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			return nil, fmt.Errorf("register built-in attribute type: %w", err)
		}
	}
	for _, description := range builtinPasswordPolicyAttributeTypes {
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			return nil, fmt.Errorf(
				"register password policy attribute type: %w",
				err,
			)
		}
	}
	for _, description := range builtinHiddenAttributeTypes {
		attribute, err := ParseAttributeType(description)
		if err != nil {
			return nil, fmt.Errorf("parse hidden built-in attribute type: %w", err)
		}
		attribute.Hidden = true
		if err := registry.RegisterAttributeType(attribute); err != nil {
			return nil, fmt.Errorf("register hidden built-in attribute type: %w", err)
		}
	}
	for _, description := range builtinObjectClasses {
		if err := registry.ParseAndRegisterObjectClass(description); err != nil {
			return nil, fmt.Errorf("register built-in object class: %w", err)
		}
	}
	for _, description := range builtinHiddenObjectClasses {
		objectClass, err := ParseObjectClass(description)
		if err != nil {
			return nil, fmt.Errorf("parse hidden built-in object class: %w", err)
		}
		objectClass.Hidden = true
		if err := registry.RegisterObjectClass(objectClass); err != nil {
			return nil, fmt.Errorf("register hidden built-in object class: %w", err)
		}
	}
	for _, description := range builtinPasswordPolicyObjectClasses {
		if err := registry.ParseAndRegisterObjectClass(description); err != nil {
			return nil, fmt.Errorf(
				"register password policy object class: %w",
				err,
			)
		}
	}
	if err := RegisterOpenLDAPOTPSchema(registry); err != nil {
		return nil, fmt.Errorf("register OpenLDAP OTP schema: %w", err)
	}
	if err := RegisterOpenLDAPAutoCASchema(registry); err != nil {
		return nil, fmt.Errorf("register OpenLDAP AutoCA schema: %w", err)
	}
	if err := RegisterOpenLDAPMetaSchema(registry); err != nil {
		return nil, fmt.Errorf("register OpenLDAP back-meta schema: %w", err)
	}
	if err := RegisterOpenLDAPSockSchema(registry); err != nil {
		return nil, fmt.Errorf("register OpenLDAP back-sock schema: %w", err)
	}
	return registry, nil
}

var builtinAttributeTypes = []string{
	"( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX " + SyntaxOID + " )",
	"( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( 2.5.4.49 NAME 'distinguishedName' DESC 'RFC4519: common supertype of DN attributes' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " )",
	"( 2.5.4.3 NAME 'cn' SUP name )",
	"( 2.5.4.4 NAME 'sn' SUP name )",
	"( 2.5.4.5 NAME 'serialNumber' DESC 'RFC2256: serial number of the entity' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxPrintableString + "{64} )",
	"( 2.5.4.42 NAME 'givenName' SUP name )",
	"( 2.5.4.11 NAME 'ou' SUP name )",
	"( 2.5.4.13 NAME 'description' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( 2.5.4.7 NAME ( 'l' 'localityName' ) SUP name )",
	"( 2.5.4.8 NAME ( 'st' 'stateOrProvinceName' ) SUP name )",
	"( 2.5.4.9 NAME ( 'street' 'streetAddress' ) EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + "{128} )",
	"( 2.5.4.10 NAME ( 'o' 'organizationName' ) SUP name )",
	"( 2.5.4.15 NAME 'businessCategory' DESC 'RFC2256: business category' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + "{128} )",
	"( 2.5.4.16 NAME 'postalAddress' EQUALITY caseIgnoreListMatch SUBSTR caseIgnoreListSubstringsMatch SYNTAX " + SyntaxPostalAddress + " )",
	"( 2.5.4.17 NAME 'postalCode' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + "{40} )",
	"( 2.5.4.18 NAME 'postOfficeBox' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + "{40} )",
	"( 2.5.4.19 NAME 'physicalDeliveryOfficeName' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + "{128} )",
	"( 2.5.4.20 NAME 'telephoneNumber' EQUALITY telephoneNumberMatch SUBSTR telephoneNumberSubstringsMatch SYNTAX " + SyntaxTelephoneNumber + "{32} )",
	"( 2.5.4.21 NAME 'telexNumber' SYNTAX " + SyntaxTelexNumber + " )",
	"( 2.5.4.23 NAME ( 'facsimileTelephoneNumber' 'fax' ) SYNTAX " + SyntaxFacsimileTelephone + " )",
	"( 2.5.4.25 NAME 'internationalISDNNumber' EQUALITY numericStringMatch SUBSTR numericStringSubstringsMatch SYNTAX " + SyntaxNumericString + "{16} )",
	"( 2.5.4.7.1 NAME 'c-l' SUP l COLLECTIVE )",
	"( 2.5.4.8.1 NAME 'c-st' SUP st COLLECTIVE )",
	"( 2.5.4.9.1 NAME 'c-street' SUP street COLLECTIVE )",
	"( 2.5.4.10.1 NAME 'c-o' SUP o COLLECTIVE )",
	"( 2.5.4.11.1 NAME 'c-ou' SUP ou COLLECTIVE )",
	"( 2.5.4.16.1 NAME 'c-PostalAddress' SUP postalAddress COLLECTIVE )",
	"( 2.5.4.17.1 NAME 'c-PostalCode' SUP postalCode COLLECTIVE )",
	"( 2.5.4.18.1 NAME 'c-PostOfficeBox' SUP postOfficeBox COLLECTIVE )",
	"( 2.5.4.19.1 NAME 'c-PhysicalDeliveryOfficeName' SUP physicalDeliveryOfficeName COLLECTIVE )",
	"( 2.5.4.20.1 NAME 'c-TelephoneNumber' SUP telephoneNumber COLLECTIVE )",
	"( 2.5.4.21.1 NAME 'c-TelexNumber' SUP telexNumber COLLECTIVE )",
	"( 2.5.4.23.1 NAME 'c-FacsimileTelephoneNumber' SUP facsimileTelephoneNumber COLLECTIVE )",
	"( 2.5.4.25.1 NAME 'c-InternationalISDNNumber' SUP internationalISDNNumber COLLECTIVE )",
	"( 2.5.4.1 NAME ( 'aliasedObjectName' 'aliasedEntryName' ) DESC 'RFC4512: name of aliased object' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE )",
	"( 2.5.4.31 NAME 'member' DESC 'RFC4519: member of a group' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " )",
	"( 2.5.4.32 NAME 'owner' DESC 'RFC2256: owner of the object' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " )",
	"( 2.5.4.33 NAME 'roleOccupant' DESC 'RFC2256: occupant of role' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " )",
	"( 2.5.4.34 NAME 'seeAlso' DESC 'RFC4519: DN of related object' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " )",
	"( 2.5.4.50 NAME 'uniqueMember' DESC 'RFC4519: unique member of a group' EQUALITY uniqueMemberMatch SYNTAX " + SyntaxNameAndOptionalUID + " )",
	"( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( 0.9.2342.19200300.100.1.25 NAME ( 'dc' 'domainComponent' ) EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX " + SyntaxIA5String + " SINGLE-VALUE )",
	"( 0.9.2342.19200300.100.1.3 NAME ( 'mail' 'rfc822Mailbox' ) EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX " + SyntaxIA5String + " )",
	"( 2.5.4.35 NAME 'userPassword' EQUALITY octetStringMatch SYNTAX " + SyntaxOctetString + " )",
	"( 1.3.6.1.4.1.4203.1.3.4 NAME 'authPassword' DESC 'RFC3112: authentication password attribute' EQUALITY 1.3.6.1.4.1.4203.1.2.2 SYNTAX " + SyntaxAuthenticationPassword + " )",
	"( 0.9.2342.19200300.100.1.60 NAME 'jpegPhoto' SYNTAX " + SyntaxOctetString + " )",
	"( 1.3.6.1.4.1.250.1.57 NAME 'labeledURI' DESC 'RFC2079: Uniform Resource Identifier with optional label' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( 2.16.840.1.113730.3.1.198 NAME 'memberURL' DESC 'Identifies an URL associated with each member of a group. Any type of labeled URL can be used.' SUP labeledURI )",
	"( 1.3.6.1.4.1.4203.666.11.8.1.1 NAME 'dgIdentity' DESC 'Identity to use when processing the memberURL' SUP distinguishedName SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.8.1.2 NAME 'dgAuthz' DESC 'Optional authorization rules that determine who is allowed to assume the dgIdentity' EQUALITY authzMatch SYNTAX " + SyntaxAuthz + " X-ORDERED 'VALUES' )",
	"( 1.3.6.1.4.1.4203.666.11.8.1.3 NAME 'dgMemberOf' DESC 'Group that the entry belongs to' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " )",
	"( 1.3.6.1.1.1.1.0 NAME 'uidNumber' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( 1.3.6.1.1.1.1.1 NAME 'gidNumber' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( 1.3.6.1.1.1.1.3 NAME 'homeDirectory' EQUALITY caseExactIA5Match SYNTAX " + SyntaxIA5String + " SINGLE-VALUE )",
	"( 2.5.21.5 NAME 'attributeTypes' EQUALITY objectIdentifierFirstComponentMatch SYNTAX " + SyntaxAttributeType + " USAGE directoryOperation )",
	"( 2.5.21.6 NAME 'objectClasses' EQUALITY objectIdentifierFirstComponentMatch SYNTAX " + SyntaxObjectClass + " USAGE directoryOperation )",
	"( 2.5.21.1 NAME 'dITStructureRules' EQUALITY integerFirstComponentMatch SYNTAX " + SyntaxDITStructureRule + " USAGE directoryOperation )",
	"( 2.5.21.2 NAME 'dITContentRules' EQUALITY objectIdentifierFirstComponentMatch SYNTAX " + SyntaxDITContentRule + " USAGE directoryOperation )",
	"( 2.5.21.7 NAME 'nameForms' EQUALITY objectIdentifierFirstComponentMatch SYNTAX " + SyntaxNameForm + " USAGE directoryOperation )",
	"( 2.5.18.1 NAME 'createTimestamp' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX " + SyntaxGeneralizedTime + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 2.5.18.2 NAME 'modifyTimestamp' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX " + SyntaxGeneralizedTime + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 2.5.18.3 NAME 'creatorsName' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 2.5.18.4 NAME 'modifiersName' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 2.5.18.5 NAME 'administrativeRole' DESC 'RFC3672: administrative role' EQUALITY objectIdentifierMatch SYNTAX " + SyntaxOID + " USAGE directoryOperation )",
	"( 2.5.18.6 NAME 'subtreeSpecification' DESC 'RFC3672: subtree specification' SYNTAX " + SyntaxSubtreeSpecification + " SINGLE-VALUE USAGE directoryOperation )",
	"( 2.5.18.7 NAME 'collectiveExclusions' DESC 'RFC3671: collective attribute exclusions' EQUALITY objectIdentifierMatch SYNTAX " + SyntaxOID + " USAGE directoryOperation )",
	"( 2.5.18.12 NAME 'collectiveAttributeSubentries' DESC 'RFC3671: collective attribute subentries' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 1.3.6.1.4.1.453.16.2.188 NAME 'authTimestamp' DESC 'last successful authentication using any method/mech' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX " + SyntaxGeneralizedTime + " SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.2.840.113556.1.2.102 NAME 'memberOf' DESC 'Group that the entry belongs to' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " NO-USER-MODIFICATION USAGE dSAOperation X-ORIGIN 'iPlanet Delegated Administrator' )",
	"( 2.5.21.9 NAME 'structuralObjectClass' EQUALITY objectIdentifierMatch SYNTAX " + SyntaxOID + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 2.5.21.10 NAME 'governingStructureRule' EQUALITY integerMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 2.5.18.10 NAME 'subschemaSubentry' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 1.3.6.1.1.20 NAME 'entryDN' DESC 'DN of the entry' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 2.5.18.9 NAME 'hasSubordinates' DESC 'X.501: entry has children' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 2.16.840.1.113730.3.1.34 NAME 'ref' DESC 'RFC3296: subordinate referral URL' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " USAGE distributedOperation )",
	"( 1.3.6.1.1.16.4 NAME 'entryUUID' EQUALITY UUIDMatch ORDERING UUIDOrderingMatch SYNTAX " + SyntaxUUID + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 1.3.6.1.4.1.4203.666.1.7 NAME 'entryCSN' DESC 'change sequence number of the entry content' EQUALITY CSNMatch ORDERING CSNOrderingMatch SYNTAX " + SyntaxCSN + "{64} SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 1.3.6.1.4.1.4203.666.1.25 NAME 'contextCSN' DESC 'the largest committed CSN of a context' EQUALITY CSNMatch ORDERING CSNOrderingMatch SYNTAX " + SyntaxCSN + "{64} NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.1466.101.119.3 NAME 'entryTtl' DESC 'RFC2589: remaining lifetime of a dynamic entry' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.1466.101.119.4 NAME 'dynamicSubtrees' DESC 'RFC2589: naming contexts supporting dynamic entries' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.1466.101.120.5 NAME 'namingContexts' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " USAGE dSAOperation )",
	"( 1.3.6.1.4.1.1466.101.120.15 NAME 'supportedLDAPVersion' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " USAGE dSAOperation )",
	"( 1.3.6.1.1.4 NAME 'vendorName' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE USAGE dSAOperation )",
	"( 1.3.6.1.1.5 NAME 'vendorVersion' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE USAGE dSAOperation )",
}

var builtinHiddenAttributeTypes = []string{
	"( 1.3.6.1.4.1.4203.1.12.2.3.0.30 NAME 'olcModuleLoad' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " X-ORDERED 'VALUES' )",
	"( 1.3.6.1.4.1.4203.1.12.2.3.0.31 NAME 'olcModulePath' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.1.12.2.3.3.2.1 NAME ( 'olcPcache' 'olcProxyCache' ) DESC 'Proxy Cache basic parameters' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.1.12.2.3.3.2.2 NAME ( 'olcPcacheAttrset' 'olcProxyAttrset' ) DESC 'A set of attributes to cache' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( 1.3.6.1.4.1.4203.1.12.2.3.3.2.3 NAME ( 'olcPcacheTemplate' 'olcProxyCacheTemplate' ) DESC 'Proxy Cache filter template' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( 1.3.6.1.4.1.4203.1.12.2.3.3.2.4 NAME 'olcPcachePosition' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.1.12.2.3.3.2.5 NAME ( 'olcPcacheMaxQueries' 'olcProxyCacheQueries' ) EQUALITY integerMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.1.12.2.3.3.2.6 NAME ( 'olcPcachePersist' 'olcProxySaveQueries' ) EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.1.12.2.3.3.2.7 NAME ( 'olcPcacheValidate' 'olcProxyCheckCacheability' ) EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.1.12.2.3.3.2.8 NAME 'olcPcacheOffline' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.1.12.2.3.3.2.9 NAME 'olcPcacheBind' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( 1.3.6.1.4.1.4203.1.12.2.3.3.19.1 NAME 'olcCollectInfo' DESC 'DN of entry and attribute to distribute' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( 1.3.6.1.4.1.4203.1.12.2.3.3.25.1 NAME 'olcNestGroupMember' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.1.12.2.3.3.25.2 NAME 'olcNestGroupMemberOf' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.1.12.2.3.3.25.3 NAME 'olcNestGroupBase' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " )",
	"( 1.3.6.1.4.1.4203.1.12.2.3.3.25.4 NAME 'olcNestGroupFlags' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( 1.3.6.1.4.1.4203.1.3.1 NAME 'entry' DESC 'OpenLDAP ACL entry pseudo-attribute' SYNTAX 1.3.6.1.4.1.4203.1.1.1 SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.1.3.2 NAME 'children' DESC 'OpenLDAP ACL children pseudo-attribute' SYNTAX 1.3.6.1.4.1.4203.1.1.1 SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.5 NAME 'OpenLDAPaci' DESC 'OpenLDAP access control information (experimental)' EQUALITY OpenLDAPaciMatch SYNTAX " + SyntaxOpenLDAPACI + " USAGE directoryOperation )",
	"( 1.3.6.1.4.1.4203.666.1.28 NAME 'lastChangeNumber' DESC 'RetroChangelog latest change record' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.1 NAME 'reqDN' DESC 'Target DN of request' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.2 NAME 'reqStart' DESC 'Start time of request' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX " + SyntaxGeneralizedTime + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.3 NAME 'reqEnd' DESC 'End time of request' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX " + SyntaxGeneralizedTime + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.4 NAME 'reqType' DESC 'Type of request' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.5 NAME 'reqSession' DESC 'Session ID of request' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.6 NAME 'reqAuthzID' DESC 'Authorization ID of requestor' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.7 NAME 'reqResult' DESC 'Result code of request' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.8 NAME 'reqMessage' DESC 'Error text of request' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.9 NAME 'reqReferral' DESC 'Referrals returned for request' SUP labeledURI )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.10 NAME 'reqControls' DESC 'Request controls' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " X-ORDERED 'VALUES' )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.11 NAME 'reqRespControls' DESC 'Response controls of request' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " X-ORDERED 'VALUES' )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.12 NAME 'reqId' DESC 'ID of Request to Abandon' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.13 NAME 'reqVersion' DESC 'Protocol version of Bind request' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.14 NAME 'reqMethod' DESC 'Bind method of request' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.15 NAME 'reqAssertion' DESC 'Compare Assertion of request' SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.16 NAME 'reqMod' DESC 'Modifications of request' EQUALITY octetStringMatch SUBSTR octetStringSubstringsMatch SYNTAX " + SyntaxOctetString + " )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.17 NAME 'reqOld' DESC 'Old values of entry before request completed' EQUALITY octetStringMatch SUBSTR octetStringSubstringsMatch SYNTAX " + SyntaxOctetString + " )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.18 NAME 'reqNewRDN' DESC 'New RDN of request' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.19 NAME 'reqDeleteOldRDN' DESC 'Delete old RDN' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.20 NAME 'reqNewSuperior' DESC 'New superior DN of request' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.21 NAME 'reqScope' DESC 'Scope of request' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.22 NAME 'reqDerefAliases' DESC 'Disposition of Aliases in request' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.23 NAME 'reqAttrsOnly' DESC 'Attributes and values of request' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.24 NAME 'reqFilter' DESC 'Filter of request' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.25 NAME 'reqAttr' DESC 'Attributes of request' EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.26 NAME 'reqSizeLimit' DESC 'Size limit of request' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.27 NAME 'reqTimeLimit' DESC 'Time limit of request' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.28 NAME 'reqEntries' DESC 'Number of entries returned' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.29 NAME 'reqData' DESC 'Data of extended request' EQUALITY octetStringMatch SUBSTR octetStringSubstringsMatch SYNTAX " + SyntaxOctetString + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.30 NAME 'auditContext' DESC 'DN of auditContainer' SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.31 NAME 'reqEntryUUID' DESC 'UUID of entry' EQUALITY UUIDMatch ORDERING UUIDOrderingMatch SYNTAX " + SyntaxUUID + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.32 NAME 'minCSN' DESC 'CSN set that the logs are recorded from' EQUALITY CSNMatch ORDERING CSNOrderingMatch SYNTAX " + SyntaxCSN + "{64} NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.11.5.1.33 NAME 'reqNewDN' DESC 'New DN after rename' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.1.8 NAME ( 'authzTo' 'saslAuthzTo' ) DESC 'proxy authorization targets' EQUALITY authzMatch SYNTAX " + SyntaxAuthz + " X-ORDERED 'VALUES' USAGE distributedOperation )",
	"( 1.3.6.1.4.1.4203.666.1.9 NAME ( 'authzFrom' 'saslAuthzFrom' ) DESC 'proxy authorization sources' EQUALITY authzMatch SYNTAX " + SyntaxAuthz + " X-ORDERED 'VALUES' USAGE distributedOperation )",
	"( 1.3.6.1.4.1.4203.666.1.10 NAME 'monitorContext' DESC 'monitor context' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.57 NAME 'entryExpireTimestamp' DESC 'OpenLDAP DDS expiration timestamp' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX " + SyntaxGeneralizedTime + " SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.1 NAME 'monitoredInfo' DESC 'monitored info' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + "{32768} NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.2 NAME 'managedInfo' DESC 'monitor managed info' SUP name )",
	"( 1.3.6.1.4.1.4203.666.1.55.3 NAME 'monitorCounter' DESC 'monitor counter' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.4 NAME 'monitorOpCompleted' DESC 'monitor completed operations' SUP monitorCounter NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.5 NAME 'monitorOpInitiated' DESC 'monitor initiated operations' SUP monitorCounter NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.6 NAME 'monitorConnectionNumber' DESC 'monitor connection number' SUP monitorCounter NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.7 NAME 'monitorConnectionAuthzDN' DESC 'monitor connection authorization DN' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.8 NAME 'monitorConnectionLocalAddress' DESC 'monitor connection local address' SUP monitoredInfo NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.9 NAME 'monitorConnectionPeerAddress' DESC 'monitor connection peer address' SUP monitoredInfo NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.10 NAME 'monitorTimestamp' DESC 'monitor timestamp' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX " + SyntaxGeneralizedTime + " SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.11 NAME 'monitorOverlay' DESC 'name of overlays defined for a given database' SUP monitoredInfo NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.12 NAME 'readOnly' DESC 'read/write status of a given database' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.13 NAME 'restrictedOperation' DESC 'name of restricted operation for a given database' SUP managedInfo )",
	"( 1.3.6.1.4.1.4203.666.1.55.14 NAME 'monitorConnectionProtocol' DESC 'monitor connection protocol' SUP monitoredInfo NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.15 NAME 'monitorConnectionOpsReceived' DESC 'monitor number of operations received by the connection' SUP monitorCounter NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.16 NAME 'monitorConnectionOpsExecuting' DESC 'monitor number of operations in execution within the connection' SUP monitorCounter NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.17 NAME 'monitorConnectionOpsPending' DESC 'monitor number of pending operations within the connection' SUP monitorCounter NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.18 NAME 'monitorConnectionOpsCompleted' DESC 'monitor number of operations completed within the connection' SUP monitorCounter NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.19 NAME 'monitorConnectionGet' DESC 'number of times connection_get() was called so far' SUP monitorCounter NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.20 NAME 'monitorConnectionRead' DESC 'number of times connection_read() was called so far' SUP monitorCounter NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.21 NAME 'monitorConnectionWrite' DESC 'number of times connection_write() was called so far' SUP monitorCounter NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.22 NAME 'monitorConnectionMask' DESC 'monitor connection mask' SUP monitoredInfo NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.23 NAME 'monitorConnectionListener' DESC 'monitor connection listener' SUP monitoredInfo NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.24 NAME 'monitorConnectionPeerDomain' DESC 'monitor connection peer domain' SUP monitoredInfo NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.25 NAME 'monitorConnectionStartTime' DESC 'monitor connection start time' SUP monitorTimestamp SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.26 NAME 'monitorConnectionActivityTime' DESC 'monitor connection activity time' SUP monitorTimestamp SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.27 NAME 'monitorIsShadow' DESC 'TRUE if the database is shadow' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.28 NAME 'monitorUpdateRef' DESC 'update referral for shadow databases' SUP monitoredInfo SINGLE-VALUE USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.29 NAME 'monitorRuntimeConfig' DESC 'TRUE if component allows runtime configuration' EQUALITY booleanMatch SYNTAX " + SyntaxBoolean + " SINGLE-VALUE USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.30 NAME 'monitorSuperiorDN' DESC 'monitor superior DN' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.31 NAME 'monitorConnectionOpsAsync' DESC 'monitor number of asynchronous operations in execution within the connection' SUP monitorCounter NO-USER-MODIFICATION USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.32 NAME 'monitorLogLevel' DESC 'current slapd log level' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + " USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.1.55.33 NAME 'monitorDebugLevel' DESC 'current slapd debug level' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + " USAGE dSAOperation )",
	"( 1.3.6.1.4.1.4203.666.11.4.1.1 NAME 'errCode' DESC 'LDAP error code' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.4.1.2 NAME 'errOp' DESC 'Operations the errObject applies to' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( 1.3.6.1.4.1.4203.666.11.4.1.3 NAME 'errText' DESC 'LDAP error textual description' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.4.1.4 NAME 'errSleepTime' DESC 'Time to wait before returning the error' EQUALITY integerMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.4.1.5 NAME 'errMatchedDN' DESC 'Value to be returned as matched DN' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.4.1.6 NAME 'errUnsolicitedOID' DESC 'OID to be returned within unsolicited response' EQUALITY objectIdentifierMatch SYNTAX " + SyntaxOID + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.4.1.7 NAME 'errUnsolicitedData' DESC 'Data to be returned within unsolicited response' SYNTAX " + SyntaxOctetString + " SINGLE-VALUE )",
	"( 1.3.6.1.4.1.4203.666.11.4.1.8 NAME 'errDisconnect' DESC 'Disconnect without notice' SYNTAX " + SyntaxBoolean + " SINGLE-VALUE )",
}

var builtinHiddenObjectClasses = []string{
	"( 1.3.6.1.4.1.4203.1.12.2.4.0.0 NAME 'olcConfig' DESC 'OpenLDAP configuration object' ABSTRACT SUP top )",
	"( 1.3.6.1.4.1.4203.1.12.2.4.0.8 NAME 'olcModuleList' DESC 'OpenLDAP dynamic module info' SUP olcConfig STRUCTURAL MAY ( cn $ olcModulePath $ olcModuleLoad ) )",
	"( 1.3.6.1.4.1.4203.1.12.2.4.3.2.1 NAME 'olcPcacheConfig' SUP top AUXILIARY MUST ( olcPcache $ olcPcacheAttrset $ olcPcacheTemplate ) MAY ( olcPcachePosition $ olcPcacheMaxQueries $ olcPcachePersist $ olcPcacheValidate $ olcPcacheOffline $ olcPcacheBind ) )",
	"( 1.3.6.1.4.1.4203.1.12.2.4.3.2.2 NAME 'olcPcacheDatabase' SUP top AUXILIARY )",
	"( 1.3.6.1.4.1.4203.1.12.2.4.3.25.1 NAME 'olcNestGroupConfig' SUP top AUXILIARY MAY ( olcNestGroupMember $ olcNestGroupMemberOf $ olcNestGroupBase $ olcNestGroupFlags ) )",
	"( 1.3.6.1.4.1.4203.666.11.5.2.0 NAME 'auditContainer' DESC 'AuditLog container' SUP top STRUCTURAL MAY ( cn $ reqStart $ reqEnd ) )",
	"( 1.3.6.1.4.1.4203.666.11.5.2.1 NAME 'auditObject' DESC 'OpenLDAP request auditing' SUP top STRUCTURAL MUST ( reqStart $ reqType $ reqSession ) MAY ( reqDN $ reqAuthzID $ reqControls $ reqRespControls $ reqEnd $ reqResult $ reqMessage $ reqReferral $ reqEntryUUID ) )",
	"( 1.3.6.1.4.1.4203.666.11.5.2.2 NAME 'auditReadObject' DESC 'OpenLDAP read request record' SUP auditObject STRUCTURAL )",
	"( 1.3.6.1.4.1.4203.666.11.5.2.3 NAME 'auditWriteObject' DESC 'OpenLDAP write request record' SUP auditObject STRUCTURAL )",
	"( 1.3.6.1.4.1.4203.666.11.5.2.4 NAME 'auditAbandon' DESC 'Abandon operation' SUP auditObject STRUCTURAL MUST reqId )",
	"( 1.3.6.1.4.1.4203.666.11.5.2.5 NAME 'auditAdd' DESC 'Add operation' SUP auditWriteObject STRUCTURAL MUST reqMod )",
	"( 1.3.6.1.4.1.4203.666.11.5.2.6 NAME 'auditBind' DESC 'Bind operation' SUP auditObject STRUCTURAL MUST ( reqVersion $ reqMethod ) )",
	"( 1.3.6.1.4.1.4203.666.11.5.2.7 NAME 'auditCompare' DESC 'Compare operation' SUP auditReadObject STRUCTURAL MUST reqAssertion )",
	"( 1.3.6.1.4.1.4203.666.11.5.2.8 NAME 'auditDelete' DESC 'Delete operation' SUP auditWriteObject STRUCTURAL MAY reqOld )",
	"( 1.3.6.1.4.1.4203.666.11.5.2.9 NAME 'auditModify' DESC 'Modify operation' SUP auditWriteObject STRUCTURAL MAY ( reqOld $ reqMod ) )",
	"( 1.3.6.1.4.1.4203.666.11.5.2.10 NAME 'auditModRDN' DESC 'ModRDN operation' SUP auditWriteObject STRUCTURAL MUST ( reqNewRDN $ reqDeleteOldRDN ) MAY ( reqNewSuperior $ reqMod $ reqOld $ reqNewDN ) )",
	"( 1.3.6.1.4.1.4203.666.11.5.2.11 NAME 'auditSearch' DESC 'Search operation' SUP auditReadObject STRUCTURAL MUST ( reqScope $ reqDerefAliases $ reqAttrsOnly ) MAY ( reqFilter $ reqAttr $ reqEntries $ reqSizeLimit $ reqTimeLimit ) )",
	"( 1.3.6.1.4.1.4203.666.11.5.2.12 NAME 'auditExtended' DESC 'Extended operation' SUP auditObject STRUCTURAL MAY reqData )",
	"( 1.3.6.1.4.1.4203.666.3.16.1 NAME 'monitor' DESC 'OpenLDAP system monitoring' SUP top STRUCTURAL MUST cn MAY ( description $ seeAlso $ labeledURI $ monitoredInfo $ managedInfo $ monitorOverlay ) )",
	"( 1.3.6.1.4.1.4203.666.3.16.2 NAME 'monitorServer' DESC 'Server monitoring root entry' SUP monitor STRUCTURAL )",
	"( 1.3.6.1.4.1.4203.666.3.16.3 NAME 'monitorContainer' DESC 'monitor container class' SUP monitor STRUCTURAL )",
	"( 1.3.6.1.4.1.4203.666.3.16.4 NAME 'monitorCounterObject' DESC 'monitor counter class' SUP monitor STRUCTURAL )",
	"( 1.3.6.1.4.1.4203.666.3.16.5 NAME 'monitorOperation' DESC 'monitor operation class' SUP monitor STRUCTURAL )",
	"( 1.3.6.1.4.1.4203.666.3.16.6 NAME 'monitorConnection' DESC 'monitor connection class' SUP monitor STRUCTURAL )",
	"( 1.3.6.1.4.1.4203.666.3.16.7 NAME 'managedObject' DESC 'monitor managed entity class' SUP monitor STRUCTURAL )",
	"( 1.3.6.1.4.1.4203.666.3.16.8 NAME 'monitoredObject' DESC 'monitor monitored entity class' SUP monitor STRUCTURAL )",
	"( 1.3.6.1.4.1.4203.666.11.4.3.0 NAME 'errAbsObject' SUP top ABSTRACT MUST errCode MAY ( cn $ description $ errOp $ errText $ errSleepTime $ errMatchedDN $ errUnsolicitedOID $ errUnsolicitedData $ errDisconnect ) )",
	"( 1.3.6.1.4.1.4203.666.11.4.3.1 NAME 'errObject' SUP errAbsObject STRUCTURAL )",
	"( 1.3.6.1.4.1.4203.666.11.4.3.2 NAME 'errAuxObject' SUP errAbsObject AUXILIARY )",
}

var builtinObjectClasses = []string{
	"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
	"( 0.9.2342.19200300.100.4.13 NAME 'domain' SUP top STRUCTURAL MUST dc MAY ( userPassword $ description ) )",
	"( 2.5.6.5 NAME 'organizationalUnit' SUP top STRUCTURAL MUST ou MAY ( userPassword $ description ) )",
	"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )",
	"( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL MAY ( ou $ mail ) )",
	"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( uid $ mail $ jpegPhoto $ givenName ) )",
	"( 2.5.6.8 NAME 'organizationalRole' SUP top STRUCTURAL MUST cn MAY ( roleOccupant $ ou $ description ) )",
	"( 2.5.6.9 NAME 'groupOfNames' SUP top STRUCTURAL MUST ( member $ cn ) MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )",
	"( 2.5.6.17 NAME 'groupOfUniqueNames' SUP top STRUCTURAL MUST ( uniqueMember $ cn ) MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )",
	"( 2.5.6.14 NAME 'device' SUP top STRUCTURAL MUST cn MAY ( serialNumber $ seeAlso $ owner $ ou $ o $ l $ description ) )",
	"( 1.3.6.1.4.1.250.3.15 NAME 'labeledURIObject' DESC 'RFC2079: object that contains the URI attribute type' SUP top AUXILIARY MAY labeledURI )",
	"( 2.16.840.1.113730.3.2.33 NAME 'groupOfURLs' SUP top STRUCTURAL MUST cn MAY ( memberURL $ businessCategory $ description $ o $ ou $ owner $ seeAlso ) )",
	"( 1.3.6.1.4.1.4203.666.11.8.2.1 NAME 'dgIdentityAux' SUP top AUXILIARY MAY ( dgIdentity $ dgAuthz ) )",
	"( 1.3.6.1.1.1.2.0 NAME 'posixAccount' SUP top AUXILIARY MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) MAY ( userPassword $ description ) )",
	"( 2.5.20.1 NAME 'subschema' AUXILIARY MAY ( objectClasses $ attributeTypes $ dITStructureRules $ dITContentRules $ nameForms ) )",
	"( 2.5.17.0 NAME 'subentry' DESC 'RFC3672: subentry' SUP top STRUCTURAL MUST ( cn $ subtreeSpecification ) )",
	"( 2.5.17.2 NAME 'collectiveAttributeSubentry' DESC 'RFC3671: collective attribute subentry' AUXILIARY )",
	"( 1.3.6.1.4.1.4203.666.3.6 NAME 'syncProviderSubentry' DESC 'Persistent Info for SyncRepl Producer' AUXILIARY MAY contextCSN )",
	"( 2.5.6.1 NAME 'alias' DESC 'RFC4512: an alias' SUP top STRUCTURAL MUST aliasedObjectName )",
	"( 2.16.840.1.113730.3.2.6 NAME 'referral' DESC 'namedref: named subordinate referral' SUP top STRUCTURAL MUST ref )",
	"( 1.3.6.1.4.1.1466.101.119.2 NAME 'dynamicObject' DESC 'RFC2589: entry with a limited lifetime' SUP top AUXILIARY )",
	"( 1.3.6.1.4.1.1466.101.120.111 NAME 'extensibleObject' SUP top AUXILIARY )",
}
