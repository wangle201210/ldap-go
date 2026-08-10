package schema

import (
	"errors"
	"fmt"
)

func cloneLDAPSyntax(syntax LDAPSyntax) LDAPSyntax {
	syntax.Extensions = cloneExtensions(syntax.Extensions)
	return syntax
}

func (registry *Registry) installBuiltinLDAPSyntaxes() {
	validated := []string{
		SyntaxOpenLDAPACI,
		SyntaxBoolean,
		SyntaxAttributeType,
		SyntaxAuthenticationPassword,
		SyntaxAuthz,
		SyntaxDITContentRule,
		SyntaxDITStructureRule,
		SyntaxDistinguishedName,
		SyntaxDirectoryString,
		SyntaxFacsimileTelephone,
		SyntaxGeneralizedTime,
		SyntaxIA5String,
		SyntaxInteger,
		SyntaxNameAndOptionalUID,
		SyntaxNumericString,
		SyntaxNameForm,
		SyntaxObjectClass,
		SyntaxOID,
		SyntaxOctetString,
		SyntaxPostalAddress,
		SyntaxPrintableString,
		SyntaxSubtreeSpecification,
		SyntaxTelephoneNumber,
		SyntaxTelexNumber,
		SyntaxUUID,
		SyntaxCSN,
		SyntaxOpenLDAPVoid,
	}
	for _, oid := range validated {
		oid := oid
		registry.addBuiltinLDAPSyntax(LDAPSyntax{
			OID:               oid,
			validatorIdentity: oid,
			validator: func(value []byte) error {
				return validateSyntax(oid, 0, value)
			},
		})
	}

	registry.addBuiltinLDAPSyntax(LDAPSyntax{
		OID:                    SyntaxACIItem,
		Description:            "ACI Item",
		BinaryTransferRequired: true,
		BEREncoded:             true,
	})
	registry.addBuiltinLDAPSyntax(binaryLDAPSyntax(
		SyntaxCertificate,
		"Certificate",
		validateCertificate,
	))
	registry.addBuiltinLDAPSyntax(binaryLDAPSyntax(
		SyntaxCertificateList,
		"Certificate List",
		validateCertificateList,
	))
	registry.addBuiltinLDAPSyntax(binaryLDAPSyntax(
		SyntaxCertificatePair,
		"Certificate Pair",
		validateCertificatePair,
	))
	registry.addBuiltinLDAPSyntax(binaryLDAPSyntax(
		SyntaxSupportedAlgorithm,
		"Supported Algorithm",
		validateBlob,
	))
	registry.addBuiltinLDAPSyntax(binaryLDAPSyntax(
		SyntaxAttributeCertificate,
		"X.509 AttributeCertificate",
		validateAttributeCertificate,
	))
	registry.addBuiltinLDAPSyntax(binaryLDAPSyntax(
		SyntaxPKCS8PrivateKey,
		"PKCS#8 PrivateKeyInfo",
		validatePKCS8PrivateKey,
	))
}

func binaryLDAPSyntax(
	oid,
	description string,
	validator syntaxValidator,
) LDAPSyntax {
	return LDAPSyntax{
		OID:                    oid,
		Description:            description,
		BinaryTransferRequired: true,
		BEREncoded:             true,
		validator:              validator,
		validatorIdentity:      oid,
	}
}

func (registry *Registry) addBuiltinLDAPSyntax(syntax LDAPSyntax) {
	copy := cloneLDAPSyntax(syntax)
	copy.builtin = true
	registry.syntaxes[schemaKey(syntax.OID)] = &copy
}

func (registry *Registry) registerLDAPSyntax(syntax LDAPSyntax) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return registry.registerLDAPSyntaxLocked(syntax)
}

func (registry *Registry) registerLDAPSyntaxLocked(syntax LDAPSyntax) error {
	if syntax.OID == "" || syntax.OID[0] < '0' || syntax.OID[0] > '9' ||
		!validObjectIdentifier(syntax.OID) {
		return errors.New("LDAP syntax requires a numeric OID")
	}
	key := schemaKey(syntax.OID)
	registered := LDAPSyntax{
		OID:         syntax.OID,
		Description: syntax.Description,
		Extensions:  cloneExtensions(syntax.Extensions),
	}
	substitutes := syntax.Extensions["X-SUBST"]
	if len(substitutes) > 0 {
		if len(substitutes) != 1 {
			return fmt.Errorf(
				"LDAP syntax %q requires exactly one X-SUBST syntax",
				syntax.OID,
			)
		}
		substitute, exists := registry.syntaxes[schemaKey(substitutes[0])]
		if !exists {
			return fmt.Errorf(
				"LDAP syntax %q substitute syntax %q is not registered",
				syntax.OID,
				substitutes[0],
			)
		}
		registered.BinaryTransferRequired = substitute.BinaryTransferRequired
		registered.BEREncoded = substitute.BEREncoded
		registered.validator = substitute.validator
		registered.validatorIdentity = substitute.validatorIdentity
	}

	if existing, exists := registry.syntaxes[key]; exists {
		if compatibleLDAPSyntaxDeclaration(*existing, registered, len(substitutes) > 0) {
			return nil
		}
		return fmt.Errorf(
			"LDAP syntax %q conflicts with the already registered definition",
			syntax.OID,
		)
	}
	registry.syntaxes[key] = &registered
	return nil
}

func compatibleLDAPSyntaxDeclaration(
	existing,
	declaration LDAPSyntax,
	hasSubstitute bool,
) bool {
	if existing.builtin {
		if !hasSubstitute {
			return true
		}
		return sameLDAPSyntaxBehavior(existing, declaration)
	}
	return existing.OID == declaration.OID &&
		existing.Description == declaration.Description &&
		equalExtensions(existing.Extensions, declaration.Extensions) &&
		sameLDAPSyntaxBehavior(existing, declaration)
}

func sameLDAPSyntaxBehavior(left, right LDAPSyntax) bool {
	return left.BinaryTransferRequired == right.BinaryTransferRequired &&
		left.BEREncoded == right.BEREncoded &&
		left.validatorIdentity == right.validatorIdentity &&
		(left.validator == nil) == (right.validator == nil)
}

func equalExtensions(left, right map[string][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for name, leftValues := range left {
		rightValues, exists := right[name]
		if !exists || len(leftValues) != len(rightValues) {
			return false
		}
		for index := range leftValues {
			if leftValues[index] != rightValues[index] {
				return false
			}
		}
	}
	return true
}

func (registry *Registry) LDAPSyntax(oid string) (LDAPSyntax, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	syntax, exists := registry.syntaxes[schemaKey(oid)]
	if !exists {
		return LDAPSyntax{}, false
	}
	return cloneLDAPSyntax(*syntax), true
}

func (registry *Registry) syntaxRequiresBinaryTransfer(oid string) bool {
	syntax := registry.syntaxes[schemaKey(oid)]
	return syntax != nil && syntax.BinaryTransferRequired
}

func (registry *Registry) validateSyntax(
	oid string,
	maxLength int,
	value []byte,
) error {
	if maxLength > 0 && len(value) > maxLength {
		return fmt.Errorf("value exceeds syntax length %d", maxLength)
	}
	if oid == "" {
		return nil
	}
	syntax := registry.syntaxes[schemaKey(oid)]
	if syntax == nil {
		return fmt.Errorf("unsupported syntax %q", oid)
	}
	if syntax.validator == nil {
		return fmt.Errorf("no validator for syntax %s", syntax.OID)
	}
	return syntax.validator(value)
}
