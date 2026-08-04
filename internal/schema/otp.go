package schema

import "fmt"

const openLDAPOTPSchemaOID = "1.3.6.1.4.1.5427.1.389.4226"

var openLDAPOTPAttributeTypes = []string{
	"( " + openLDAPOTPSchemaOID + ".4.1 NAME 'oathSecret' DESC 'OATH-LDAP: Shared Secret (possibly encrypted with public key in oathEncKey)' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE EQUALITY octetStringMatch SUBSTR octetStringSubstringsMatch SYNTAX " + SyntaxOctetString + " )",
	"( " + openLDAPOTPSchemaOID + ".4.2 NAME 'oathTokenSerialNumber' DESC 'OATH-LDAP: Proprietary hardware token serial number assigned by vendor' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.44{64} )",
	"( " + openLDAPOTPSchemaOID + ".4.3 NAME 'oathTokenIdentifier' DESC 'OATH-LDAP: Globally unique OATH token identifier' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE EQUALITY caseIgnoreMatch SYNTAX " + SyntaxDirectoryString + "{256} )",
	"( " + openLDAPOTPSchemaOID + ".4.4 NAME 'oathParamsEntry' DESC 'OATH-LDAP: DN pointing to OATH parameter/policy object' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP distinguishedName )",
	"( " + openLDAPOTPSchemaOID + ".4.4.1 NAME 'oathTOTPTimeStepPeriod' DESC 'OATH-LDAP: Time window for TOTP (seconds)' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " )",
	"( " + openLDAPOTPSchemaOID + ".4.5 NAME 'oathOTPLength' DESC 'OATH-LDAP: Length of OTP (number of digits)' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " )",
	"( " + openLDAPOTPSchemaOID + ".4.5.1 NAME 'oathHOTPParams' DESC 'OATH-LDAP: DN pointing to HOTP parameter object' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP oathParamsEntry )",
	"( " + openLDAPOTPSchemaOID + ".4.5.2 NAME 'oathTOTPParams' DESC 'OATH-LDAP: DN pointing to TOTP parameter object' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP oathParamsEntry )",
	"( " + openLDAPOTPSchemaOID + ".4.6 NAME 'oathHMACAlgorithm' DESC 'OATH-LDAP: HMAC algorithm used for generating OTP values' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE EQUALITY objectIdentifierMatch SYNTAX " + SyntaxOID + " )",
	"( " + openLDAPOTPSchemaOID + ".4.7 NAME 'oathTimestamp' DESC 'OATH-LDAP: Timestamp (not directly used).' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX " + SyntaxGeneralizedTime + " )",
	"( " + openLDAPOTPSchemaOID + ".4.7.1 NAME 'oathLastFailure' DESC 'OATH-LDAP: Timestamp of last failed OATH validation' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP oathTimestamp )",
	"( " + openLDAPOTPSchemaOID + ".4.7.2 NAME 'oathLastLogin' DESC 'OATH-LDAP: Timestamp of last successful OATH validation' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP oathTimestamp )",
	"( " + openLDAPOTPSchemaOID + ".4.7.3 NAME 'oathSecretTime' DESC 'OATH-LDAP: Timestamp of generation of oathSecret attribute.' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP oathTimestamp )",
	"( " + openLDAPOTPSchemaOID + ".4.8 NAME 'oathSecretMaxAge' DESC 'OATH-LDAP: Time in seconds for which the shared secret (oathSecret) will be valid from oathSecretTime value.' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " )",
	"( " + openLDAPOTPSchemaOID + ".4.9 NAME 'oathToken' DESC 'OATH-LDAP: DN pointing to OATH token object' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP distinguishedName )",
	"( " + openLDAPOTPSchemaOID + ".4.9.1 NAME 'oathHOTPToken' DESC 'OATH-LDAP: DN pointing to OATH/HOTP token object' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP oathToken )",
	"( " + openLDAPOTPSchemaOID + ".4.9.2 NAME 'oathTOTPToken' DESC 'OATH-LDAP: DN pointing to OATH/TOTP token object' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP oathToken )",
	"( " + openLDAPOTPSchemaOID + ".4.10 NAME 'oathCounter' DESC 'OATH-LDAP: Counter for OATH data (not directly used)' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " )",
	"( " + openLDAPOTPSchemaOID + ".4.10.1 NAME 'oathFailureCount' DESC 'OATH-LDAP: OATH failure counter' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP oathCounter )",
	"( " + openLDAPOTPSchemaOID + ".4.10.2 NAME 'oathHOTPCounter' DESC 'OATH-LDAP: Counter for HOTP' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP oathCounter )",
	"( " + openLDAPOTPSchemaOID + ".4.10.3 NAME 'oathHOTPLookAhead' DESC 'OATH-LDAP: Look-ahead window for HOTP' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP oathCounter )",
	"( " + openLDAPOTPSchemaOID + ".4.10.5 NAME 'oathThrottleLimit' DESC 'OATH-LDAP: Failure throttle limit' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP oathCounter )",
	"( " + openLDAPOTPSchemaOID + ".4.10.6 NAME 'oathTOTPLastTimeStep' DESC 'OATH-LDAP: Last time step seen for TOTP (time/period)' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP oathCounter )",
	"( " + openLDAPOTPSchemaOID + ".4.10.7 NAME 'oathMaxUsageCount' DESC 'OATH-LDAP: Maximum number of times a token can be used' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP oathCounter )",
	"( " + openLDAPOTPSchemaOID + ".4.10.8 NAME 'oathTOTPTimeStepWindow' DESC 'OATH-LDAP: Size of time step +/- tolerance window used for TOTP validation' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP oathCounter )",
	"( " + openLDAPOTPSchemaOID + ".4.10.9 NAME 'oathTOTPTimeStepDrift' DESC 'OATH-LDAP: Last observed time step shift seen for TOTP' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE SUP oathCounter )",
	"( " + openLDAPOTPSchemaOID + ".4.11 NAME 'oathSecretLength' DESC 'OATH-LDAP: Length of plain-text shared secret (number of bytes)' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " )",
	"( " + openLDAPOTPSchemaOID + ".4.12 NAME 'oathEncKey' DESC 'OATH-LDAP: public key to be used for encrypting new shared secrets' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( " + openLDAPOTPSchemaOID + ".4.13 NAME 'oathResultCode' DESC 'OATH-LDAP: LDAP resultCode to use in response' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX " + SyntaxInteger + " )",
	"( " + openLDAPOTPSchemaOID + ".4.13.1 NAME 'oathSuccessResultCode' DESC 'OATH-LDAP: success resultCode to use in bind/compare response' X-ORIGIN 'OATH-LDAP' SUP oathResultCode )",
	"( " + openLDAPOTPSchemaOID + ".4.13.2 NAME 'oathFailureResultCode' DESC 'OATH-LDAP: failure resultCode to use in bind/compare response' X-ORIGIN 'OATH-LDAP' SUP oathResultCode )",
	"( " + openLDAPOTPSchemaOID + ".4.14 NAME 'oathTokenPIN' DESC 'OATH-LDAP: Configuration PIN (possibly encrypted with oathEncKey)' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + " )",
	"( " + openLDAPOTPSchemaOID + ".4.15 NAME 'oathMessage' DESC 'OATH-LDAP: success diagnosticMessage to use in bind/compare response' X-ORIGIN 'OATH-LDAP' SINGLE-VALUE EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + SyntaxDirectoryString + "{1024} )",
	"( " + openLDAPOTPSchemaOID + ".4.15.1 NAME 'oathSuccessMessage' DESC 'OATH-LDAP: success diagnosticMessage to use in bind/compare response' X-ORIGIN 'OATH-LDAP' SUP oathMessage )",
	"( " + openLDAPOTPSchemaOID + ".4.15.2 NAME 'oathFailureMessage' DESC 'OATH-LDAP: failure diagnosticMessage to use in bind/compare response' X-ORIGIN 'OATH-LDAP' SUP oathMessage )",
}

var openLDAPOTPObjectClasses = []string{
	"( " + openLDAPOTPSchemaOID + ".6.1 NAME 'oathUser' DESC 'OATH-LDAP: User Object' X-ORIGIN 'OATH-LDAP' ABSTRACT )",
	// OpenLDAP 2.6.13 intentionally declares oathHOTPToken as MAY, although
	// slapo-otp(5) describes the token reference as mandatory.
	"( " + openLDAPOTPSchemaOID + ".6.1.1 NAME 'oathHOTPUser' DESC 'OATH-LDAP: HOTP user object' X-ORIGIN 'OATH-LDAP' AUXILIARY SUP oathUser MAY ( oathHOTPToken ) )",
	"( " + openLDAPOTPSchemaOID + ".6.1.2 NAME 'oathTOTPUser' DESC 'OATH-LDAP: TOTP user object' X-ORIGIN 'OATH-LDAP' AUXILIARY SUP oathUser MUST ( oathTOTPToken ) )",
	"( " + openLDAPOTPSchemaOID + ".6.2 NAME 'oathParams' DESC 'OATH-LDAP: Parameter object' X-ORIGIN 'OATH-LDAP' ABSTRACT MUST ( oathOTPLength $ oathHMACAlgorithm ) MAY ( oathSecretMaxAge $ oathSecretLength $ oathMaxUsageCount $ oathThrottleLimit $ oathEncKey $ oathSuccessResultCode $ oathSuccessMessage $ oathFailureResultCode $ oathFailureMessage ) )",
	"( " + openLDAPOTPSchemaOID + ".6.2.1 NAME 'oathHOTPParams' DESC 'OATH-LDAP: HOTP parameter object' X-ORIGIN 'OATH-LDAP' AUXILIARY SUP oathParams MUST ( oathHOTPLookAhead ) )",
	"( " + openLDAPOTPSchemaOID + ".6.2.2 NAME 'oathTOTPParams' DESC 'OATH-LDAP: TOTP parameter object' X-ORIGIN 'OATH-LDAP' AUXILIARY SUP oathParams MUST ( oathTOTPTimeStepPeriod ) MAY ( oathTOTPTimeStepWindow ) )",
	"( " + openLDAPOTPSchemaOID + ".6.3 NAME 'oathToken' DESC 'OATH-LDAP: User Object' X-ORIGIN 'OATH-LDAP' ABSTRACT MAY ( oathSecret $ oathSecretTime $ oathLastLogin $ oathFailureCount $ oathLastFailure $ oathTokenSerialNumber $ oathTokenIdentifier $ oathTokenPIN ) )",
	"( " + openLDAPOTPSchemaOID + ".6.3.1 NAME 'oathHOTPToken' DESC 'OATH-LDAP: HOTP token object' X-ORIGIN 'OATH-LDAP' AUXILIARY SUP oathToken MAY ( oathHOTPParams $ oathHOTPCounter ) )",
	// Preserve otp.c's placement bug: runtime reads drift from the params entry,
	// while the schema permits it only on the TOTP token object class.
	"( " + openLDAPOTPSchemaOID + ".6.3.2 NAME 'oathTOTPToken' DESC 'OATH-LDAP: TOTP token' X-ORIGIN 'OATH-LDAP' AUXILIARY SUP oathToken MAY ( oathTOTPParams $ oathTOTPLastTimeStep $ oathTOTPTimeStepDrift ) )",
}

// RegisterOpenLDAPOTPSchema registers the complete OATH-LDAP schema embedded in
// OpenLDAP 2.6.13's otp overlay. It deliberately does not enable OTP Bind logic.
func RegisterOpenLDAPOTPSchema(registry *Registry) error {
	if registry == nil {
		return fmt.Errorf("register OpenLDAP OTP schema: nil registry")
	}
	for _, description := range openLDAPOTPAttributeTypes {
		attribute, err := ParseAttributeType(description)
		if err != nil {
			return fmt.Errorf("parse OpenLDAP OTP attribute type: %w", err)
		}
		if err := registry.RegisterAttributeType(attribute); err != nil {
			return fmt.Errorf(
				"register OpenLDAP OTP attribute type %q: %w",
				attribute.Name(),
				err,
			)
		}
	}
	for _, description := range openLDAPOTPObjectClasses {
		objectClass, err := ParseObjectClass(description)
		if err != nil {
			return fmt.Errorf("parse OpenLDAP OTP object class: %w", err)
		}
		if err := registry.RegisterObjectClass(objectClass); err != nil {
			return fmt.Errorf(
				"register OpenLDAP OTP object class %q: %w",
				objectClass.Name(),
				err,
			)
		}
	}
	return nil
}
