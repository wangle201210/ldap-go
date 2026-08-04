package server

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

const (
	autoCAMinRSAKeyBits = 1024
	autoCAMaxRSAKeyBits = 16384
)

var autoCADNAttributeOIDs = map[string]asn1.ObjectIdentifier{
	"cn":                  {2, 5, 4, 3},
	"sn":                  {2, 5, 4, 4},
	"serialnumber":        {2, 5, 4, 5},
	"c":                   {2, 5, 4, 6},
	"l":                   {2, 5, 4, 7},
	"st":                  {2, 5, 4, 8},
	"street":              {2, 5, 4, 9},
	"o":                   {2, 5, 4, 10},
	"ou":                  {2, 5, 4, 11},
	"title":               {2, 5, 4, 12},
	"description":         {2, 5, 4, 13},
	"postalcode":          {2, 5, 4, 17},
	"givenname":           {2, 5, 4, 42},
	"initials":            {2, 5, 4, 43},
	"generationqualifier": {2, 5, 4, 44},
	"dnqualifier":         {2, 5, 4, 46},
	"pseudonym":           {2, 5, 4, 65},
	"uid":                 {0, 9, 2342, 19200300, 100, 1, 1},
	"dc":                  {0, 9, 2342, 19200300, 100, 1, 25},
	"mail":                {1, 2, 840, 113549, 1, 9, 1},
}

type autoCACertificatePair struct {
	CertificateDER []byte
	PrivateKeyDER  []byte
}

type autoCACertificateConfig struct {
	DN      string
	KeyBits int
	Days    int
	Now     time.Time
	Random  io.Reader
}

type autoCAUserCertificateConfig struct {
	DN      string
	Mail    string
	KeyBits int
	Days    int
	Now     time.Time
	Random  io.Reader
}

type autoCAServerCertificateConfig struct {
	DN           string
	IPHostNumber string
	KeyBits      int
	Days         int
	Now          time.Time
	Random       io.Reader
}

// autoCAKeyProvider is the algorithm boundary for later signer support. The
// Phase 1 implementation intentionally registers RSA only; it does not imply
// SM2, SM3, or a national-crypto configuration contract.
type autoCAKeyProvider interface {
	generateSigner(random io.Reader, keyBits int) (crypto.Signer, error)
	marshalPKCS8(signer crypto.Signer) ([]byte, error)
}

type autoCARSAKeyProvider struct{}

func (autoCARSAKeyProvider) generateSigner(
	random io.Reader,
	keyBits int,
) (crypto.Signer, error) {
	if keyBits < autoCAMinRSAKeyBits || keyBits > autoCAMaxRSAKeyBits {
		return nil, fmt.Errorf(
			"AutoCA RSA key bits must be between %d and %d",
			autoCAMinRSAKeyBits,
			autoCAMaxRSAKeyBits,
		)
	}
	key, err := rsa.GenerateKey(random, keyBits)
	if err != nil {
		return nil, fmt.Errorf("generate AutoCA RSA key: %w", err)
	}
	return key, nil
}

func (autoCARSAKeyProvider) marshalPKCS8(signer crypto.Signer) ([]byte, error) {
	key, ok := signer.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("marshal AutoCA RSA key: unsupported signer %T", signer)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal AutoCA RSA key as PKCS#8: %w", err)
	}
	return bytes.Clone(der), nil
}

func generateAutoCASelfSignedCA(
	config autoCACertificateConfig,
) (autoCACertificatePair, error) {
	return generateAutoCASelfSignedCAWithProvider(config, autoCARSAKeyProvider{})
}

func generateAutoCASelfSignedCAWithProvider(
	config autoCACertificateConfig,
	provider autoCAKeyProvider,
) (autoCACertificatePair, error) {
	if provider == nil {
		return autoCACertificatePair{}, errors.New("AutoCA key provider is required")
	}
	subject, rawSubject, err := autoCAX509Subject(config.DN)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	notBefore, notAfter, err := autoCAValidity(config.Now, config.Days)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	if config.Random == nil {
		return autoCACertificatePair{}, errors.New("AutoCA random source is required")
	}
	signer, err := provider.generateSigner(config.Random, config.KeyBits)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	serial, err := autoCARandomSerial(config.Random)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	subjectKeyID, err := autoCASubjectKeyID(signer.Public())
	if err != nil {
		return autoCACertificatePair{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		RawSubject:            rawSubject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          subjectKeyID,
		AuthorityKeyId:        bytes.Clone(subjectKeyID),
	}
	certificateDER, err := x509.CreateCertificate(
		config.Random,
		template,
		template,
		signer.Public(),
		signer,
	)
	if err != nil {
		return autoCACertificatePair{}, fmt.Errorf("create AutoCA CA certificate: %w", err)
	}
	privateKeyDER, err := provider.marshalPKCS8(signer)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	return autoCACertificatePair{
		CertificateDER: bytes.Clone(certificateDER),
		PrivateKeyDER:  bytes.Clone(privateKeyDER),
	}, nil
}

func generateAutoCAUserCertificate(
	ca autoCACertificatePair,
	config autoCAUserCertificateConfig,
) (autoCACertificatePair, error) {
	return generateAutoCAUserCertificateWithProvider(
		ca,
		config,
		autoCARSAKeyProvider{},
	)
}

func generateAutoCAUserCertificateWithProvider(
	ca autoCACertificatePair,
	config autoCAUserCertificateConfig,
	provider autoCAKeyProvider,
) (autoCACertificatePair, error) {
	if provider == nil {
		return autoCACertificatePair{}, errors.New("AutoCA key provider is required")
	}
	issuer, issuerSigner, err := autoCAParseIssuer(ca)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	subject, rawSubject, err := autoCAX509Subject(config.DN)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	emailAddresses, err := autoCAOptionalRFC822Names(config.Mail)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	notBefore, notAfter, err := autoCAValidity(config.Now, config.Days)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	if config.Random == nil {
		return autoCACertificatePair{}, errors.New("AutoCA random source is required")
	}
	signer, err := provider.generateSigner(config.Random, config.KeyBits)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	serial, err := autoCARandomSerial(config.Random)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	subjectKeyID, err := autoCASubjectKeyID(signer.Public())
	if err != nil {
		return autoCACertificatePair{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		RawSubject:   rawSubject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageContentCommitment |
			x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageEmailProtection,
			x509.ExtKeyUsageCodeSigning,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          subjectKeyID,
		AuthorityKeyId:        bytes.Clone(issuer.SubjectKeyId),
		EmailAddresses:        emailAddresses,
	}
	certificateDER, err := x509.CreateCertificate(
		config.Random,
		template,
		issuer,
		signer.Public(),
		issuerSigner,
	)
	if err != nil {
		return autoCACertificatePair{}, fmt.Errorf("create AutoCA user certificate: %w", err)
	}
	privateKeyDER, err := provider.marshalPKCS8(signer)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	return autoCACertificatePair{
		CertificateDER: bytes.Clone(certificateDER),
		PrivateKeyDER:  bytes.Clone(privateKeyDER),
	}, nil
}

func generateAutoCAServerCertificate(
	ca autoCACertificatePair,
	config autoCAServerCertificateConfig,
) (autoCACertificatePair, error) {
	return generateAutoCAServerCertificateWithProvider(
		ca,
		config,
		autoCARSAKeyProvider{},
	)
}

func generateAutoCAServerCertificateWithProvider(
	ca autoCACertificatePair,
	config autoCAServerCertificateConfig,
	provider autoCAKeyProvider,
) (autoCACertificatePair, error) {
	if provider == nil {
		return autoCACertificatePair{}, errors.New("AutoCA key provider is required")
	}
	issuer, issuerSigner, err := autoCAParseIssuer(ca)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	subject, rawSubject, err := autoCAX509Subject(config.DN)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	ipAddresses, err := autoCAOptionalIPAddresses(config.IPHostNumber)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	notBefore, notAfter, err := autoCAValidity(config.Now, config.Days)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	if config.Random == nil {
		return autoCACertificatePair{}, errors.New("AutoCA random source is required")
	}
	signer, err := provider.generateSigner(config.Random, config.KeyBits)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	serial, err := autoCARandomSerial(config.Random)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	subjectKeyID, err := autoCASubjectKeyID(signer.Public())
	if err != nil {
		return autoCACertificatePair{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		RawSubject:   rawSubject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          subjectKeyID,
		AuthorityKeyId:        bytes.Clone(issuer.SubjectKeyId),
		IPAddresses:           ipAddresses,
	}
	certificateDER, err := x509.CreateCertificate(
		config.Random,
		template,
		issuer,
		signer.Public(),
		issuerSigner,
	)
	if err != nil {
		return autoCACertificatePair{}, fmt.Errorf("create AutoCA server certificate: %w", err)
	}
	privateKeyDER, err := provider.marshalPKCS8(signer)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	return autoCACertificatePair{
		CertificateDER: bytes.Clone(certificateDER),
		PrivateKeyDER:  bytes.Clone(privateKeyDER),
	}, nil
}

func autoCAParseIssuer(
	ca autoCACertificatePair,
) (*x509.Certificate, crypto.Signer, error) {
	certificateDER := bytes.Clone(ca.CertificateDER)
	privateKeyDER := bytes.Clone(ca.PrivateKeyDER)
	if len(certificateDER) == 0 || len(privateKeyDER) == 0 {
		return nil, nil, errors.New("AutoCA issuer certificate and private key are required")
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse AutoCA issuer certificate: %w", err)
	}
	if !certificate.BasicConstraintsValid || !certificate.IsCA {
		return nil, nil, errors.New("AutoCA issuer certificate is not a CA")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse AutoCA issuer PKCS#8 key: %w", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("AutoCA issuer key %T is not a signer", privateKey)
	}
	match, err := autoCAPublicKeysEqual(certificate.PublicKey, signer.Public())
	if err != nil {
		return nil, nil, err
	}
	if !match {
		return nil, nil, errors.New("AutoCA issuer certificate and private key do not match")
	}
	return certificate, signer, nil
}

func autoCAX509Subject(rawDN string) (pkix.Name, []byte, error) {
	parsed, err := ldap.ParseDN(rawDN)
	if err != nil {
		return pkix.Name{}, nil, fmt.Errorf("parse AutoCA subject DN %q: %w", rawDN, err)
	}
	if len(parsed.RDNs) == 0 {
		return pkix.Name{}, nil, errors.New("AutoCA subject DN must not be empty")
	}
	rdns := make(pkix.RDNSequence, 0, len(parsed.RDNs))
	for rdnIndex := len(parsed.RDNs) - 1; rdnIndex >= 0; rdnIndex-- {
		parsedRDN := parsed.RDNs[rdnIndex]
		if len(parsedRDN.Attributes) == 0 {
			return pkix.Name{}, nil, errors.New("AutoCA subject DN contains an empty RDN")
		}
		rdn := make(pkix.RelativeDistinguishedNameSET, 0, len(parsedRDN.Attributes))
		for _, attribute := range parsedRDN.Attributes {
			oid, oidErr := autoCADNAttributeOID(attribute.Type)
			if oidErr != nil {
				return pkix.Name{}, nil, oidErr
			}
			if attribute.Value == "" {
				return pkix.Name{}, nil, fmt.Errorf(
					"AutoCA subject DN attribute %q must not be empty",
					attribute.Type,
				)
			}
			rdn = append(rdn, pkix.AttributeTypeAndValue{
				Type: oid,
				Value: asn1.RawValue{
					Class: asn1.ClassUniversal,
					Tag:   asn1.TagUTF8String,
					Bytes: []byte(attribute.Value),
				},
			})
		}
		rdns = append(rdns, rdn)
	}
	rawSubject, err := asn1.Marshal(rdns)
	if err != nil {
		return pkix.Name{}, nil, fmt.Errorf("marshal AutoCA subject DN: %w", err)
	}
	var normalized pkix.RDNSequence
	if rest, unmarshalErr := asn1.Unmarshal(rawSubject, &normalized); unmarshalErr != nil || len(rest) != 0 {
		if unmarshalErr == nil {
			unmarshalErr = errors.New("trailing subject data")
		}
		return pkix.Name{}, nil, fmt.Errorf("normalize AutoCA subject DN: %w", unmarshalErr)
	}
	var subject pkix.Name
	subject.FillFromRDNSequence(&normalized)
	return subject, bytes.Clone(rawSubject), nil
}

func autoCADNAttributeOID(attributeType string) (asn1.ObjectIdentifier, error) {
	normalized := strings.ToLower(strings.TrimSpace(attributeType))
	if oid, ok := autoCADNAttributeOIDs[normalized]; ok {
		return append(asn1.ObjectIdentifier(nil), oid...), nil
	}
	if oid, err := parseAutoCANumericOID(normalized); err == nil {
		return oid, nil
	}
	return nil, fmt.Errorf(
		"AutoCA subject DN attribute %q has no X.509 OID mapping",
		attributeType,
	)
}

func parseAutoCANumericOID(raw string) (asn1.ObjectIdentifier, error) {
	if raw == "" {
		return nil, errors.New("empty OID")
	}
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return nil, errors.New("OID must contain at least two arcs")
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for index, part := range parts {
		if part == "" {
			return nil, errors.New("OID contains an empty arc")
		}
		value := 0
		for _, char := range part {
			if char < '0' || char > '9' {
				return nil, errors.New("OID contains a non-numeric arc")
			}
			if value > (int(^uint(0)>>1)-int(char-'0'))/10 {
				return nil, errors.New("OID arc overflows int")
			}
			value = value*10 + int(char-'0')
		}
		oid[index] = value
	}
	if oid[0] > 2 || (oid[0] < 2 && oid[1] > 39) {
		return nil, errors.New("OID has invalid leading arcs")
	}
	return oid, nil
}

func autoCAValidity(now time.Time, days int) (time.Time, time.Time, error) {
	if now.IsZero() {
		return time.Time{}, time.Time{}, errors.New("AutoCA issuance time is required")
	}
	if days <= 0 {
		return time.Time{}, time.Time{}, errors.New("AutoCA certificate days must be positive")
	}
	notBefore := now.UTC().Truncate(time.Second)
	if notBefore.Year() < 1950 || notBefore.Year() > 9999 {
		return time.Time{}, time.Time{}, errors.New("AutoCA issuance time is outside the X.509 range")
	}
	notAfter := notBefore.AddDate(0, 0, days)
	if !notAfter.After(notBefore) || notAfter.Year() > 9999 {
		return time.Time{}, time.Time{}, errors.New("AutoCA certificate validity exceeds the X.509 range")
	}
	return notBefore, notAfter, nil
}

func autoCARandomSerial(random io.Reader) (*big.Int, error) {
	serialBytes := make([]byte, 8)
	if _, err := io.ReadFull(random, serialBytes); err != nil {
		return nil, fmt.Errorf("generate AutoCA certificate serial: %w", err)
	}
	serialBytes[0] |= 0x80
	return new(big.Int).SetBytes(serialBytes), nil
}

func autoCASubjectKeyID(publicKey any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal AutoCA public key: %w", err)
	}
	var subjectPublicKeyInfo struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(der, &subjectPublicKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("parse AutoCA subject public key: %w", err)
	}
	if len(rest) != 0 || len(subjectPublicKeyInfo.SubjectPublicKey.Bytes) == 0 {
		return nil, errors.New("parse AutoCA subject public key: invalid trailing or empty data")
	}
	digest := sha1.Sum(subjectPublicKeyInfo.SubjectPublicKey.Bytes)
	return bytes.Clone(digest[:]), nil
}

func autoCAPublicKeysEqual(left, right any) (bool, error) {
	leftDER, err := x509.MarshalPKIXPublicKey(left)
	if err != nil {
		return false, fmt.Errorf("marshal AutoCA certificate public key: %w", err)
	}
	rightDER, err := x509.MarshalPKIXPublicKey(right)
	if err != nil {
		return false, fmt.Errorf("marshal AutoCA private-key public key: %w", err)
	}
	return bytes.Equal(leftDER, rightDER), nil
}

func autoCARFC822Name(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.Count(raw, "@") != 1 {
		return "", fmt.Errorf("AutoCA mail %q is not an RFC822 address", raw)
	}
	parts := strings.SplitN(raw, "@", 2)
	if parts[0] == "" || parts[1] == "" || strings.HasPrefix(parts[1], ".") ||
		strings.HasSuffix(parts[1], ".") {
		return "", fmt.Errorf("AutoCA mail %q is not an RFC822 address", raw)
	}
	for _, char := range raw {
		if char < 0x21 || char > 0x7e || strings.ContainsRune("(),:;<>[\\]", char) {
			return "", fmt.Errorf("AutoCA mail %q is not an RFC822 address", raw)
		}
	}
	return raw, nil
}

func autoCAOptionalRFC822Names(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	mail, err := autoCARFC822Name(raw)
	if err != nil {
		return nil, err
	}
	return []string{mail}, nil
}

func autoCAOptionalIPAddresses(raw string) ([]net.IP, error) {
	if raw == "" {
		return nil, nil
	}
	if strings.TrimSpace(raw) != raw {
		return nil, fmt.Errorf("AutoCA ipHostNumber %q is not an IP address", raw)
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return nil, fmt.Errorf("AutoCA ipHostNumber %q is not an IP address", raw)
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return []net.IP{bytes.Clone(ipv4)}, nil
	}
	return []net.IP{bytes.Clone(ip.To16())}, nil
}
