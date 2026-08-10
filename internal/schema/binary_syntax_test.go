package schema

import (
	"strings"
	"testing"
)

func TestBuiltinBinarySyntaxMetadata(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	tests := []struct {
		name         string
		oid          string
		hasValidator bool
	}{
		{name: "ACI Item", oid: SyntaxACIItem},
		{name: "Certificate", oid: SyntaxCertificate, hasValidator: true},
		{name: "Certificate List", oid: SyntaxCertificateList, hasValidator: true},
		{name: "Certificate Pair", oid: SyntaxCertificatePair, hasValidator: true},
		{name: "Supported Algorithm", oid: SyntaxSupportedAlgorithm, hasValidator: true},
		{name: "Attribute Certificate", oid: SyntaxAttributeCertificate, hasValidator: true},
		{name: "PKCS#8", oid: SyntaxPKCS8PrivateKey, hasValidator: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			syntax, found := registry.LDAPSyntax(test.oid)
			if !found {
				t.Fatalf("LDAPSyntax(%q) was not found", test.oid)
			}
			if !syntax.BinaryTransferRequired || !syntax.BEREncoded {
				t.Fatalf("LDAPSyntax(%q) flags = binary %t, BER %t", test.oid, syntax.BinaryTransferRequired, syntax.BEREncoded)
			}
			if syntax.HasValidator() != test.hasValidator {
				t.Fatalf("LDAPSyntax(%q).HasValidator() = %t, want %t", test.oid, syntax.HasValidator(), test.hasValidator)
			}

			attribute := AttributeType{
				OID:    "1.2.3",
				Names:  []string{"binaryValue"},
				Syntax: test.oid,
				Usage:  UsageUserApplications,
			}
			if err := registry.validateAttributeDescription("binaryValue", attribute); err == nil ||
				!strings.Contains(err.Error(), "needs ';binary'") {
				t.Fatalf("bare AttributeDescription error = %v", err)
			}
			if err := registry.validateAttributeDescription("binaryValue;binary", attribute); err != nil {
				t.Fatalf("binary AttributeDescription: %v", err)
			}
		})
	}
}

func TestCertificatePairSequenceValidateCompatibility(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value []byte
		valid bool
	}{
		{name: "minimal sequence header", value: []byte{0x30, 0x00}, valid: true},
		{name: "malformed length remains accepted", value: []byte{0x30, 0xff}, valid: true},
		{name: "extra arbitrary bytes remain accepted", value: []byte{0x30, 0x80, 0xff}, valid: true},
		{name: "wrong tag", value: []byte{0x31, 0x00}},
		{name: "one byte", value: []byte{0x30}},
		{name: "empty"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateCertificatePair(test.value)
			if (err == nil) != test.valid {
				t.Fatalf("validateCertificatePair(%x) error = %v, valid %t", test.value, err, test.valid)
			}
		})
	}
}

func TestSupportedAlgorithmBlobValidateCompatibility(t *testing.T) {
	t.Parallel()

	for _, value := range [][]byte{
		nil,
		{},
		{0xff},
		{0x30, 0xff},
		[]byte("not BER"),
	} {
		if err := validateBlob(value); err != nil {
			t.Fatalf("validateBlob(%x): %v", value, err)
		}
	}
}

func TestACIItemHasNoValueValidator(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	if err := registry.RegisterAttributeType(AttributeType{
		OID:    "1.2.3.1",
		Names:  []string{"aciItemValue"},
		Syntax: SyntaxACIItem,
	}); err != nil {
		t.Fatalf("RegisterAttributeType(): %v", err)
	}
	err := registry.ValidateAttributeValue("aciItemValue", []byte{0x30, 0x00})
	if err == nil || !strings.Contains(err.Error(), "no validator for syntax "+SyntaxACIItem) {
		t.Fatalf("ValidateAttributeValue() error = %v", err)
	}
}

func TestShallowBinarySyntaxValidators(t *testing.T) {
	t.Parallel()

	certificateBody := joinBER(
		berTestValue(berTagInteger, 0x01),
		berTestValue(berTagSequence),
		berTestValue(berTagSequence),
		berTestValue(berTagSequence),
		berTestValue(berTagSequence),
		berTestValue(berTagSequence),
	)
	certificate := berTestValue(
		berTagSequence,
		joinBER(
			berTestValue(berTagSequence, certificateBody...),
			berTestValue(berTagSequence),
			berTestValue(berTagBitString, 0x00),
		)...,
	)
	if err := validateCertificate(certificate); err != nil {
		t.Fatalf("validateCertificate(minimal): %v", err)
	}
	if err := validateCertificate(append(append([]byte(nil), certificate...), 0x00)); err == nil {
		t.Fatal("validateCertificate() accepted trailing data")
	}

	certificateV3Body := joinBER(
		berTestValue(berTagContext0, berTestValue(berTagInteger, 0x02)...),
		certificateBody,
		berTestValue(berTagContext3, berTestValue(berTagSequence)...),
	)
	certificateV3 := berTestValue(
		berTagSequence,
		joinBER(
			berTestValue(berTagSequence, certificateV3Body...),
			berTestValue(berTagSequence),
			berTestValue(berTagBitString, 0x00),
		)...,
	)
	if err := validateCertificate(certificateV3); err != nil {
		t.Fatalf("validateCertificate(v3 extensions): %v", err)
	}

	certificateList := berTestValue(
		berTagSequence,
		joinBER(
			berTestValue(
				berTagSequence,
				joinBER(
					berTestValue(berTagSequence),
					berTestValue(berTagSequence),
					berTestValue(berTagUTCTime, []byte("260810120000Z")...),
				)...,
			),
			berTestValue(
				berTagSequence,
				berTestValue(berTagOID, 0x2a)...,
			),
			berTestValue(berTagBitString, 0x00),
		)...,
	)
	if err := validateCertificateList(certificateList); err != nil {
		t.Fatalf("validateCertificateList(minimal): %v", err)
	}

	attributeCertificate := berTestValue(
		berTagSequence,
		joinBER(
			berTestValue(
				berTagSequence,
				joinBER(
					berTestValue(berTagInteger, 0x01),
					berTestValue(berTagSequence),
					berTestValue(berTagContext0),
					berTestValue(berTagSequence),
					berTestValue(berTagInteger, 0x01),
					berTestValue(berTagSequence),
					berTestValue(berTagSequence),
				)...,
			),
			berTestValue(berTagSequence),
			berTestValue(berTagBitString, 0x00),
		)...,
	)
	if err := validateAttributeCertificate(attributeCertificate); err != nil {
		t.Fatalf("validateAttributeCertificate(minimal): %v", err)
	}

	privateKey := berTestValue(
		berTagSequence,
		joinBER(
			berTestValue(berTagInteger, 0x00),
			berTestValue(berTagSequence),
			berTestValue(berTagOctetString, 0x01),
		)...,
	)
	if err := validatePKCS8PrivateKey(privateKey); err != nil {
		t.Fatalf("validatePKCS8PrivateKey(minimal): %v", err)
	}
	if err := validatePKCS8PrivateKey(berTestValue(berTagSequence, berTestValue(berTagInteger, 0x00)...)); err == nil {
		t.Fatal("validatePKCS8PrivateKey() accepted missing fields")
	}
}

func berTestValue(tag uint64, content ...byte) []byte {
	if tag > 0xff {
		panic("test helper only supports one-octet tags")
	}
	if len(content) >= 0x80 {
		panic("test helper only supports short lengths")
	}
	value := []byte{byte(tag), byte(len(content))}
	return append(value, content...)
}

func joinBER(values ...[]byte) []byte {
	var result []byte
	for _, value := range values {
		result = append(result, value...)
	}
	return result
}
