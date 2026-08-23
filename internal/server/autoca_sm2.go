package server

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

const autoCASM2KeyBits = 256

func generateAutoCASM2SelfSignedCA(
	config autoCACertificateConfig,
) (autoCACertificatePair, error) {
	if err := validateAutoCASM2KeyBits(config.KeyBits); err != nil {
		return autoCACertificatePair{}, err
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
		return autoCACertificatePair{}, errors.New("AutoCA SM2 random source is required")
	}
	privateKey, err := sm2.GenerateKey(config.Random)
	if err != nil {
		return autoCACertificatePair{}, fmt.Errorf("generate AutoCA SM2 key: %w", err)
	}
	serial, err := autoCARandomSerial(config.Random)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	subjectKeyID, err := autoCASM2SubjectKeyID(privateKey.Public())
	if err != nil {
		return autoCACertificatePair{}, err
	}
	template := &smx509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		RawSubject:            rawSubject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SignatureAlgorithm:    smx509.SM2WithSM3,
		KeyUsage:              smx509.KeyUsageDigitalSignature | smx509.KeyUsageCRLSign | smx509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          subjectKeyID,
		AuthorityKeyId:        bytes.Clone(subjectKeyID),
	}
	certificateDER, err := smx509.CreateCertificate(
		config.Random,
		template,
		template,
		privateKey.Public(),
		privateKey,
	)
	if err != nil {
		return autoCACertificatePair{}, fmt.Errorf("create AutoCA SM2 CA certificate: %w", err)
	}
	privateKeyDER, err := smx509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return autoCACertificatePair{}, fmt.Errorf("marshal AutoCA SM2 key as PKCS#8: %w", err)
	}
	return autoCACertificatePair{
		CertificateDER: bytes.Clone(certificateDER),
		PrivateKeyDER:  bytes.Clone(privateKeyDER),
	}, nil
}

func generateAutoCASM2UserCertificate(
	ca autoCACertificatePair,
	config autoCAUserCertificateConfig,
) (autoCACertificatePair, error) {
	if err := validateAutoCASM2KeyBits(config.KeyBits); err != nil {
		return autoCACertificatePair{}, err
	}
	issuer, issuerKey, err := parseAutoCASM2Issuer(ca)
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
		return autoCACertificatePair{}, errors.New("AutoCA SM2 random source is required")
	}
	privateKey, err := sm2.GenerateKey(config.Random)
	if err != nil {
		return autoCACertificatePair{}, fmt.Errorf("generate AutoCA SM2 key: %w", err)
	}
	serial, err := autoCARandomSerial(config.Random)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	subjectKeyID, err := autoCASM2SubjectKeyID(privateKey.Public())
	if err != nil {
		return autoCACertificatePair{}, err
	}
	template := &smx509.Certificate{
		SerialNumber:       serial,
		Subject:            subject,
		RawSubject:         rawSubject,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		SignatureAlgorithm: smx509.SM2WithSM3,
		KeyUsage: smx509.KeyUsageDigitalSignature |
			smx509.KeyUsageContentCommitment |
			smx509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []smx509.ExtKeyUsage{
			smx509.ExtKeyUsageClientAuth,
			smx509.ExtKeyUsageEmailProtection,
			smx509.ExtKeyUsageCodeSigning,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          subjectKeyID,
		AuthorityKeyId:        bytes.Clone(issuer.SubjectKeyId),
		EmailAddresses:        emailAddresses,
	}
	certificateDER, err := smx509.CreateCertificate(
		config.Random,
		template,
		issuer,
		privateKey.Public(),
		issuerKey,
	)
	if err != nil {
		return autoCACertificatePair{}, fmt.Errorf("create AutoCA SM2 user certificate: %w", err)
	}
	privateKeyDER, err := smx509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return autoCACertificatePair{}, fmt.Errorf("marshal AutoCA SM2 key as PKCS#8: %w", err)
	}
	return autoCACertificatePair{
		CertificateDER: bytes.Clone(certificateDER),
		PrivateKeyDER:  bytes.Clone(privateKeyDER),
	}, nil
}

func generateAutoCASM2ServerCertificate(
	ca autoCACertificatePair,
	config autoCAServerCertificateConfig,
) (autoCACertificatePair, error) {
	if err := validateAutoCASM2KeyBits(config.KeyBits); err != nil {
		return autoCACertificatePair{}, err
	}
	issuer, issuerKey, err := parseAutoCASM2Issuer(ca)
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
	dnsNames, err := autoCAOptionalDNSNames(config.DNSNames)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	notBefore, notAfter, err := autoCAValidity(config.Now, config.Days)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	if config.Random == nil {
		return autoCACertificatePair{}, errors.New("AutoCA SM2 random source is required")
	}
	privateKey, err := sm2.GenerateKey(config.Random)
	if err != nil {
		return autoCACertificatePair{}, fmt.Errorf("generate AutoCA SM2 key: %w", err)
	}
	serial, err := autoCARandomSerial(config.Random)
	if err != nil {
		return autoCACertificatePair{}, err
	}
	subjectKeyID, err := autoCASM2SubjectKeyID(privateKey.Public())
	if err != nil {
		return autoCACertificatePair{}, err
	}
	template := &smx509.Certificate{
		SerialNumber:       serial,
		Subject:            subject,
		RawSubject:         rawSubject,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		SignatureAlgorithm: smx509.SM2WithSM3,
		KeyUsage: smx509.KeyUsageDigitalSignature |
			smx509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []smx509.ExtKeyUsage{
			smx509.ExtKeyUsageServerAuth,
			smx509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          subjectKeyID,
		AuthorityKeyId:        bytes.Clone(issuer.SubjectKeyId),
		IPAddresses:           ipAddresses,
		DNSNames:              dnsNames,
	}
	certificateDER, err := smx509.CreateCertificate(
		config.Random,
		template,
		issuer,
		privateKey.Public(),
		issuerKey,
	)
	if err != nil {
		return autoCACertificatePair{}, fmt.Errorf("create AutoCA SM2 server certificate: %w", err)
	}
	privateKeyDER, err := smx509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return autoCACertificatePair{}, fmt.Errorf("marshal AutoCA SM2 key as PKCS#8: %w", err)
	}
	return autoCACertificatePair{
		CertificateDER: bytes.Clone(certificateDER),
		PrivateKeyDER:  bytes.Clone(privateKeyDER),
	}, nil
}

func validateAutoCASM2KeyBits(keyBits int) error {
	if keyBits != autoCASM2KeyBits {
		return fmt.Errorf("AutoCA SM2 key bits must be %d", autoCASM2KeyBits)
	}
	return nil
}

func parseAutoCASM2Issuer(
	ca autoCACertificatePair,
) (*smx509.Certificate, *sm2.PrivateKey, error) {
	certificateDER := bytes.Clone(ca.CertificateDER)
	privateKeyDER := bytes.Clone(ca.PrivateKeyDER)
	if len(certificateDER) == 0 || len(privateKeyDER) == 0 {
		return nil, nil, errors.New("AutoCA SM2 issuer certificate and private key are required")
	}
	certificate, err := smx509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse AutoCA SM2 issuer certificate: %w", err)
	}
	if !certificate.BasicConstraintsValid || !certificate.IsCA {
		return nil, nil, errors.New("AutoCA SM2 issuer certificate is not a CA")
	}
	privateKeyValue, err := smx509.ParsePKCS8PrivateKey(privateKeyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse AutoCA SM2 issuer PKCS#8 key: %w", err)
	}
	privateKey, ok := privateKeyValue.(*sm2.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("AutoCA SM2 issuer key has unsupported type %T", privateKeyValue)
	}
	match, err := autoCASM2PublicKeysEqual(certificate.PublicKey, privateKey.Public())
	if err != nil {
		return nil, nil, err
	}
	if !match {
		return nil, nil, errors.New("AutoCA SM2 issuer certificate and private key do not match")
	}
	return certificate, privateKey, nil
}

func autoCASM2SubjectKeyID(publicKey any) ([]byte, error) {
	der, err := smx509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal AutoCA SM2 public key: %w", err)
	}
	var subjectPublicKeyInfo struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(der, &subjectPublicKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("parse AutoCA SM2 subject public key: %w", err)
	}
	if len(rest) != 0 || len(subjectPublicKeyInfo.SubjectPublicKey.Bytes) == 0 {
		return nil, errors.New("parse AutoCA SM2 subject public key: invalid trailing or empty data")
	}
	digest := sha1.Sum(subjectPublicKeyInfo.SubjectPublicKey.Bytes)
	return bytes.Clone(digest[:]), nil
}

func autoCASM2PublicKeysEqual(left, right any) (bool, error) {
	leftDER, err := smx509.MarshalPKIXPublicKey(left)
	if err != nil {
		return false, fmt.Errorf("marshal AutoCA SM2 certificate public key: %w", err)
	}
	rightDER, err := smx509.MarshalPKIXPublicKey(right)
	if err != nil {
		return false, fmt.Errorf("marshal AutoCA SM2 private-key public key: %w", err)
	}
	return bytes.Equal(leftDER, rightDER), nil
}
