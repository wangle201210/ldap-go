package schema

import "fmt"

const (
	SyntaxBoolean                = "1.3.6.1.4.1.1466.115.121.1.7"
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
	SyntaxSubtreeSpecification   = "1.3.6.1.4.1.1466.115.121.1.45"
	SyntaxTelephoneNumber        = "1.3.6.1.4.1.1466.115.121.1.50"
	SyntaxTelexNumber            = "1.3.6.1.4.1.1466.115.121.1.52"
	SyntaxUUID                   = "1.3.6.1.1.16.1"
	SyntaxCSN                    = "1.3.6.1.4.1.4203.666.11.2.1"
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
	for _, description := range builtinPasswordPolicyObjectClasses {
		if err := registry.ParseAndRegisterObjectClass(description); err != nil {
			return nil, fmt.Errorf(
				"register password policy object class: %w",
				err,
			)
		}
	}
	return registry, nil
}

var builtinAttributeTypes = []string{
	"( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX " + SyntaxOID + " )",
	"( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( 2.5.4.3 NAME 'cn' SUP name )",
	"( 2.5.4.4 NAME 'sn' SUP name )",
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
	"( 2.5.4.34 NAME 'seeAlso' DESC 'RFC4519: DN of related object' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " )",
	"( 2.5.4.50 NAME 'uniqueMember' DESC 'RFC4519: unique member of a group' EQUALITY uniqueMemberMatch SYNTAX " + SyntaxNameAndOptionalUID + " )",
	"( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( 0.9.2342.19200300.100.1.25 NAME ( 'dc' 'domainComponent' ) EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX " + SyntaxIA5String + " SINGLE-VALUE )",
	"( 0.9.2342.19200300.100.1.3 NAME ( 'mail' 'rfc822Mailbox' ) EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX " + SyntaxIA5String + " )",
	"( 2.5.4.35 NAME 'userPassword' EQUALITY octetStringMatch SYNTAX " + SyntaxOctetString + " )",
	"( 1.3.6.1.4.1.4203.1.3.4 NAME 'authPassword' DESC 'RFC3112: authentication password attribute' EQUALITY 1.3.6.1.4.1.4203.1.2.2 SYNTAX " + SyntaxAuthenticationPassword + " )",
	"( 0.9.2342.19200300.100.1.60 NAME 'jpegPhoto' SYNTAX " + SyntaxOctetString + " )",
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
	"( 1.2.840.113556.1.2.102 NAME 'memberOf' DESC 'Group that the entry belongs to' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " NO-USER-MODIFICATION USAGE dSAOperation X-ORIGIN 'iPlanet Delegated Administrator' )",
	"( 2.5.21.9 NAME 'structuralObjectClass' EQUALITY objectIdentifierMatch SYNTAX " + SyntaxOID + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 2.5.21.10 NAME 'governingStructureRule' EQUALITY integerMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 2.5.18.10 NAME 'subschemaSubentry' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
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
	"( 1.3.6.1.4.1.4203.666.1.8 NAME ( 'authzTo' 'saslAuthzTo' ) DESC 'proxy authorization targets' EQUALITY authzMatch SYNTAX " + SyntaxAuthz + " X-ORDERED 'VALUES' USAGE distributedOperation )",
	"( 1.3.6.1.4.1.4203.666.1.9 NAME ( 'authzFrom' 'saslAuthzFrom' ) DESC 'proxy authorization sources' EQUALITY authzMatch SYNTAX " + SyntaxAuthz + " X-ORDERED 'VALUES' USAGE distributedOperation )",
	"( 1.3.6.1.4.1.4203.666.1.57 NAME 'entryExpireTimestamp' DESC 'OpenLDAP DDS expiration timestamp' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX " + SyntaxGeneralizedTime + " SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
}

var builtinObjectClasses = []string{
	"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
	"( 0.9.2342.19200300.100.4.13 NAME 'domain' SUP top STRUCTURAL MUST dc MAY ( userPassword $ description ) )",
	"( 2.5.6.5 NAME 'organizationalUnit' SUP top STRUCTURAL MUST ou MAY ( userPassword $ description ) )",
	"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ description ) )",
	"( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL MAY ( ou $ mail ) )",
	"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( uid $ mail $ jpegPhoto $ givenName ) )",
	"( 2.5.6.8 NAME 'organizationalRole' SUP top STRUCTURAL MUST cn MAY ( ou $ description ) )",
	"( 2.5.6.9 NAME 'groupOfNames' SUP top STRUCTURAL MUST ( member $ cn ) MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )",
	"( 2.5.6.17 NAME 'groupOfUniqueNames' SUP top STRUCTURAL MUST ( uniqueMember $ cn ) MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )",
	"( 1.3.6.1.1.1.2.0 NAME 'posixAccount' SUP top AUXILIARY MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) MAY ( userPassword $ description ) )",
	"( 2.5.20.1 NAME 'subschema' AUXILIARY MAY ( objectClasses $ attributeTypes $ dITStructureRules $ dITContentRules $ nameForms ) )",
	"( 2.5.17.0 NAME 'subentry' DESC 'RFC3672: subentry' SUP top STRUCTURAL MUST ( cn $ subtreeSpecification ) )",
	"( 2.5.17.2 NAME 'collectiveAttributeSubentry' DESC 'RFC3671: collective attribute subentry' AUXILIARY )",
	"( 2.5.6.1 NAME 'alias' DESC 'RFC4512: an alias' SUP top STRUCTURAL MUST aliasedObjectName )",
	"( 2.16.840.1.113730.3.2.6 NAME 'referral' DESC 'namedref: named subordinate referral' SUP top STRUCTURAL MUST ref )",
	"( 1.3.6.1.4.1.1466.101.119.2 NAME 'dynamicObject' DESC 'RFC2589: entry with a limited lifetime' SUP top AUXILIARY )",
	"( 1.3.6.1.4.1.1466.101.120.111 NAME 'extensibleObject' SUP top AUXILIARY )",
}
