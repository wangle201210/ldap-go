package schema

import (
	"fmt"
	"sort"
	"strings"
)

const (
	maxLDAPSyntaxSchemaBytes       = 16 << 20
	maxLDAPSyntaxSchemaDefinitions = 8192
)

type syntaxPublicationFlags uint8

const (
	syntaxPublicationValidated syntaxPublicationFlags = 1 << iota
	syntaxPublicationHidden
	syntaxPublicationBinary
	syntaxPublicationNotHumanReadable
)

type syntaxPublicationDefinition struct {
	oid, description string
	flags            syntaxPublicationFlags
}

// Publication metadata comes from OpenLDAP 2.6.13, commit
// d172686d3d270bc961b78f3ff00d7019c8dfb094, schema_init.c and aci.c.
// This catalog neither installs nor executes validators. In particular, Go's
// schema-description parsers do not make native NULL-validator syntaxes public.
func builtinSyntaxPublicationDefinitions() []syntaxPublicationDefinition {
	const (
		v = syntaxPublicationValidated
		h = syntaxPublicationHidden
		b = syntaxPublicationBinary
		n = syntaxPublicationNotHumanReadable
	)
	return []syntaxPublicationDefinition{
		{SyntaxACIItem, "ACI Item", b | n},
		{SyntaxAttributeType, "Attribute Type Description", 0},
		{SyntaxAudio, "Audio", v | n},
		{SyntaxBinary, "Binary", v | n},
		{SyntaxBitString, "Bit String", v},
		{SyntaxBoolean, "Boolean", v},
		{SyntaxCertificate, "Certificate", v | b | n},
		{SyntaxCertificateList, "Certificate List", v | b | n},
		{SyntaxCertificatePair, "Certificate Pair", v | b | n},
		{SyntaxAttributeCertificate, "X.509 AttributeCertificate", v | b | n},
		{SyntaxDistinguishedName, "Distinguished Name", v},
		{SyntaxRDN, "RDN", v},
		{SyntaxDeliveryMethod, "Delivery Method", v},
		{SyntaxDirectoryString, "Directory String", v},
		{SyntaxDITContentRule, "DIT Content Rule Description", 0},
		{SyntaxDITStructureRule, "DIT Structure Rule Description", 0},
		{SyntaxFacsimileTelephone, "Facsimile Telephone Number", v},
		{SyntaxGeneralizedTime, "Generalized Time", v},
		{SyntaxIA5String, "IA5 String", v},
		{SyntaxInteger, "Integer", v},
		{SyntaxJPEG, "JPEG", v | n},
		{SyntaxMatchingRule, "Matching Rule Description", 0},
		{SyntaxMatchingRuleUse, "Matching Rule Use Description", 0},
		{SyntaxNameAndOptionalUID, "Name And Optional UID", v},
		{SyntaxNameForm, "Name Form Description", 0},
		{SyntaxNumericString, "Numeric String", v},
		{SyntaxObjectClass, "Object Class Description", 0},
		{SyntaxOID, "OID", v},
		{SyntaxOtherMailbox, "Other Mailbox", v},
		{SyntaxOctetString, "Octet String", v},
		{SyntaxPostalAddress, "Postal Address", v},
		{SyntaxPrintableString, "Printable String", v},
		{SyntaxCountryString, "Country String", v},
		{SyntaxSubtreeSpecification, "SubtreeSpecification", v},
		{SyntaxSupportedAlgorithm, "Supported Algorithm", v | b | n},
		{SyntaxTelephoneNumber, "Telephone Number", v},
		{SyntaxTelexNumber, "Telex Number", v},
		{SyntaxLDAPSyntaxDescription, "LDAP Syntax Description", 0},
		{SyntaxNISNetgroupTriple, "RFC2307 NIS Netgroup Triple", v},
		{SyntaxBootParameter, "RFC2307 Boot Parameter", v},
		{SyntaxUUID, "UUID", v},
		{SyntaxCSN, "CSN", v | h},
		{SyntaxOpenLDAPVoid, "OpenLDAP void", v | h},
		{SyntaxAuthz, "OpenLDAP authz", v | h},
		// Native runtime BINARY/BER flags do not imply schema X extensions.
		{SyntaxPKCS8PrivateKey, "PKCS#8 PrivateKeyInfo", v},
		{SyntaxOpenLDAPACI, "OpenLDAP Experimental ACI", v | h},
	}
}

func (definition syntaxPublicationDefinition) public() bool {
	return definition.flags&syntaxPublicationValidated != 0 &&
		definition.flags&syntaxPublicationHidden == 0
}

func (definition syntaxPublicationDefinition) syntax() LDAPSyntax {
	syntax := LDAPSyntax{OID: definition.oid, Description: definition.description}
	if definition.flags&(syntaxPublicationBinary|syntaxPublicationNotHumanReadable) != 0 {
		syntax.Extensions = make(map[string][]string)
		if definition.flags&syntaxPublicationBinary != 0 {
			syntax.Extensions["X-BINARY-TRANSFER-REQUIRED"] = []string{"TRUE"}
		}
		if definition.flags&syntaxPublicationNotHumanReadable != 0 {
			syntax.Extensions["X-NOT-HUMAN-READABLE"] = []string{"TRUE"}
		}
	}
	return syntax
}

// LDAPSyntaxDescriptions returns an independent snapshot in lexical OID order.
// Only registered Go validators with public native metadata are advertised.
// Custom X-SUBST declarations retain their own descriptions and extensions,
// while inheriting the substitute's native validator availability and hiding.
// The complete publication is limited to 16 MiB and 8192 definitions; errors
// return no partial result and never modify the registry.
func (registry *Registry) LDAPSyntaxDescriptions() ([]string, error) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()

	catalog := make(map[string]syntaxPublicationDefinition)
	for _, definition := range builtinSyntaxPublicationDefinitions() {
		catalog[definition.oid] = definition
	}
	var syntaxes []LDAPSyntax
	remaining := maxLDAPSyntaxSchemaBytes
	for _, registered := range registry.syntaxes {
		if registered == nil || registered.validator == nil {
			continue
		}
		var syntax LDAPSyntax
		if registered.builtin {
			definition, found := catalog[registered.OID]
			if !found || !definition.public() {
				continue
			}
			syntax = definition.syntax()
		} else {
			// Registration resolves validatorIdentity through X-SUBST chains.
			// Native syn_add copies runtime flags, not the substitute's DESC
			// or X extensions; a hidden or NULL-validator root stays hidden.
			definition, found := catalog[registered.validatorIdentity]
			if len(registered.Extensions["X-SUBST"]) != 1 || !found || !definition.public() {
				continue
			}
			syntax = *registered
		}
		if len(syntaxes) == maxLDAPSyntaxSchemaDefinitions {
			return nil, fmt.Errorf("LDAP syntax schema exceeds %d definitions", maxLDAPSyntaxSchemaDefinitions)
		}
		var ok bool
		remaining, ok = ldapSyntaxPublicationBudget(syntax, remaining)
		if !ok {
			return nil, fmt.Errorf("LDAP syntax schema exceeds %d bytes", maxLDAPSyntaxSchemaBytes)
		}
		syntaxes = append(syntaxes, syntax)
	}
	sort.Slice(syntaxes, func(i, j int) bool { return syntaxes[i].OID < syntaxes[j].OID })
	descriptions := make([]string, len(syntaxes))
	for index, syntax := range syntaxes {
		descriptions[index] = FormatLDAPSyntax(syntax)
	}
	return descriptions, nil
}

// Account for FormatLDAPSyntax's quoting and separators before it allocates
// strings or extension-value slices. Subtraction avoids integer overflow.
func ldapSyntaxPublicationBudget(syntax LDAPSyntax, remaining int) (int, bool) {
	consume := func(size int) bool {
		if size > remaining {
			return false
		}
		remaining -= size
		return true
	}
	quote := func(value string) bool {
		if !consume(2) || !consume(len(value)) {
			return false
		}
		for index := 0; index < len(value); index++ {
			character := value[index]
			if character == '\'' || character == '\\' || character < 0x20 || character == 0x7f {
				if !consume(2) {
					return false
				}
			}
		}
		return true
	}
	if !consume(4) || !consume(len(syntax.OID)) {
		return 0, false
	}
	if syntax.Description != "" && (!consume(len(" DESC ")) || !quote(syntax.Description)) {
		return 0, false
	}
	for name, values := range syntax.Extensions {
		if len(name) > remaining || !consume(2) || !consume(len(strings.ToUpper(name))) {
			return 0, false
		}
		if len(values) != 1 && !consume(4) {
			return 0, false
		}
		for index, value := range values {
			if (index > 0 && !consume(1)) || !quote(value) {
				return 0, false
			}
		}
	}
	return remaining, true
}
