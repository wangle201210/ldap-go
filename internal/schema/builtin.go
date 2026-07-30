package schema

import "fmt"

const (
	SyntaxBoolean           = "1.3.6.1.4.1.1466.115.121.1.7"
	SyntaxAttributeType     = "1.3.6.1.4.1.1466.115.121.1.3"
	SyntaxDistinguishedName = "1.3.6.1.4.1.1466.115.121.1.12"
	SyntaxDirectoryString   = "1.3.6.1.4.1.1466.115.121.1.15"
	SyntaxGeneralizedTime   = "1.3.6.1.4.1.1466.115.121.1.24"
	SyntaxIA5String         = "1.3.6.1.4.1.1466.115.121.1.26"
	SyntaxInteger           = "1.3.6.1.4.1.1466.115.121.1.27"
	SyntaxObjectClass       = "1.3.6.1.4.1.1466.115.121.1.37"
	SyntaxOID               = "1.3.6.1.4.1.1466.115.121.1.38"
	SyntaxOctetString       = "1.3.6.1.4.1.1466.115.121.1.40"
	SyntaxUUID              = "1.3.6.1.1.16.1"
)

func NewBuiltinRegistry() (*Registry, error) {
	registry := NewRegistry()
	for _, description := range builtinAttributeTypes {
		if err := registry.ParseAndRegisterAttributeType(description); err != nil {
			return nil, fmt.Errorf("register built-in attribute type: %w", err)
		}
	}
	for _, description := range builtinObjectClasses {
		if err := registry.ParseAndRegisterObjectClass(description); err != nil {
			return nil, fmt.Errorf("register built-in object class: %w", err)
		}
	}
	return registry, nil
}

var builtinAttributeTypes = []string{
	"( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX " + SyntaxOID + " )",
	"( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( 2.5.4.3 NAME 'cn' SUP name )",
	"( 2.5.4.4 NAME 'sn' SUP name )",
	"( 2.5.4.11 NAME 'ou' SUP name )",
	"( 2.5.4.13 NAME 'description' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( 0.9.2342.19200300.100.1.25 NAME ( 'dc' 'domainComponent' ) EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX " + SyntaxIA5String + " SINGLE-VALUE )",
	"( 0.9.2342.19200300.100.1.3 NAME ( 'mail' 'rfc822Mailbox' ) EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX " + SyntaxIA5String + " )",
	"( 2.5.4.35 NAME 'userPassword' EQUALITY octetStringMatch SYNTAX " + SyntaxOctetString + " )",
	"( 0.9.2342.19200300.100.1.60 NAME 'jpegPhoto' SYNTAX " + SyntaxOctetString + " )",
	"( 1.3.6.1.1.1.1.0 NAME 'uidNumber' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( 1.3.6.1.1.1.1.1 NAME 'gidNumber' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " SINGLE-VALUE )",
	"( 1.3.6.1.1.1.1.3 NAME 'homeDirectory' EQUALITY caseExactIA5Match SYNTAX " + SyntaxIA5String + " SINGLE-VALUE )",
	"( 2.5.21.5 NAME 'attributeTypes' EQUALITY objectIdentifierFirstComponentMatch SYNTAX " + SyntaxAttributeType + " USAGE directoryOperation )",
	"( 2.5.21.6 NAME 'objectClasses' EQUALITY objectIdentifierFirstComponentMatch SYNTAX " + SyntaxObjectClass + " USAGE directoryOperation )",
	"( 2.5.18.1 NAME 'createTimestamp' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX " + SyntaxGeneralizedTime + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 2.5.18.2 NAME 'modifyTimestamp' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX " + SyntaxGeneralizedTime + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 2.5.18.3 NAME 'creatorsName' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 2.5.18.4 NAME 'modifiersName' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 2.5.21.9 NAME 'structuralObjectClass' EQUALITY objectIdentifierMatch SYNTAX " + SyntaxOID + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 2.5.18.10 NAME 'subschemaSubentry' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 1.3.6.1.1.16.4 NAME 'entryUUID' EQUALITY UUIDMatch ORDERING UUIDOrderingMatch SYNTAX " + SyntaxUUID + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 1.3.6.1.4.1.4203.666.1.7 NAME 'entryCSN' EQUALITY CSNMatch ORDERING CSNOrderingMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
	"( 1.3.6.1.4.1.1466.101.120.5 NAME 'namingContexts' EQUALITY distinguishedNameMatch SYNTAX " + SyntaxDistinguishedName + " USAGE dSAOperation )",
	"( 1.3.6.1.4.1.1466.101.120.15 NAME 'supportedLDAPVersion' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " USAGE dSAOperation )",
	"( 1.3.6.1.1.4 NAME 'vendorName' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE USAGE dSAOperation )",
	"( 1.3.6.1.1.5 NAME 'vendorVersion' EQUALITY caseExactMatch SYNTAX " + SyntaxDirectoryString + " SINGLE-VALUE USAGE dSAOperation )",
}

var builtinObjectClasses = []string{
	"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
	"( 0.9.2342.19200300.100.4.13 NAME 'domain' SUP top STRUCTURAL MUST dc MAY ( userPassword $ description ) )",
	"( 2.5.6.5 NAME 'organizationalUnit' SUP top STRUCTURAL MUST ou MAY ( userPassword $ description ) )",
	"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ description ) )",
	"( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL MAY ( ou $ mail ) )",
	"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( uid $ mail $ jpegPhoto ) )",
	"( 2.5.6.8 NAME 'organizationalRole' SUP top STRUCTURAL MUST cn MAY ( ou $ description ) )",
	"( 1.3.6.1.1.1.2.0 NAME 'posixAccount' SUP top AUXILIARY MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) MAY ( userPassword $ description ) )",
	"( 2.5.20.1 NAME 'subschema' AUXILIARY MAY ( objectClasses $ attributeTypes ) )",
	"( 1.3.6.1.4.1.1466.101.120.111 NAME 'extensibleObject' SUP top AUXILIARY )",
}
