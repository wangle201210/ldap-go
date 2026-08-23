package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var unsupportedGlobalTLSDirectives = []string{
	"olcTLSCACertificatePath",
	"olcTLSRandFile",
	"olcTLSDHParamFile",
	"olcTLSECName",
}

var recognizedGlobalTLSDirectives = append([]string{
	"olcTLSCACertificate",
	"olcTLSCACertificateFile",
	"olcTLSCertificate",
	"olcTLSCertificateFile",
	"olcTLSCertificateKey",
	"olcTLSCertificateKeyFile",
	"olcTLSCipherSuite",
	"olcTLSCRLCheck",
	"olcTLSCRLFile",
	"olcTLSVerifyClient",
	"olcTLSProtocolMin",
}, unsupportedGlobalTLSDirectives...)

type globalTLSAttributes struct {
	caCertificate      []byte
	caCertificateFile  string
	certificate        []byte
	certificateFile    string
	certificateKey     []byte
	certificateKeyFile string
	cipherSuite        string
	crlCheck           string
	crlFile            string
	verifyClient       string
	protocolMin        string
}

func (server *Server) loadGlobalTLSConfiguration(
	reader storage.Reader,
) (SecureTransport, error) {
	if server.config.TLSConfig != nil && server.config.SecureTransport != nil {
		return nil, errors.New("TLS config and secure transport are mutually exclusive")
	}
	entry, err := reader.Get(configurationSuffix)
	switch {
	case errors.Is(err, storage.ErrEntryNotFound):
		if server.config.ImplicitTLS && !server.hasExplicitSecureTransport() {
			return nil, errors.New("implicit TLS requires TLS configuration")
		}
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("load global TLS configuration: %w", err)
	}

	configured := globalTLSConfigurationPresent(entry)
	if configured && server.hasExplicitSecureTransport() {
		return nil, errors.New(
			"cn=config TLS directives conflict with the explicit Config TLS transport",
		)
	}
	if !configured {
		if server.config.ImplicitTLS && !server.hasExplicitSecureTransport() {
			return nil, errors.New("implicit TLS requires TLS configuration")
		}
		return nil, nil
	}

	for _, directive := range unsupportedGlobalTLSDirectives {
		if globalTLSAttributePresent(entry, directive) {
			return nil, fmt.Errorf(
				"%s %s is unsupported by the Go TLS runtime",
				entry.DN,
				directive,
			)
		}
	}

	attributes, err := parseGlobalTLSAttributes(entry)
	if err != nil {
		return nil, err
	}
	crlPolicy, err := parseGlobalTLSCRLCheck(attributes.crlCheck)
	if err != nil {
		return nil, fmt.Errorf("%s olcTLSCRLCheck: %w", entry.DN, err)
	}
	crls, err := loadGlobalTLSCRLs(attributes.crlFile)
	if err != nil {
		return nil, fmt.Errorf("%s olcTLSCRLFile: %w", entry.DN, err)
	}
	if !globalTLSServerMaterialPresent(attributes) {
		if server.config.ImplicitTLS && !server.hasExplicitSecureTransport() {
			return nil, errors.New("implicit TLS requires TLS certificate and key configuration")
		}
		return nil, nil
	}
	configuration, err := server.buildGlobalTLSConfig(
		entry.DN,
		attributes,
		crlPolicy,
		crls,
	)
	if err != nil {
		return nil, err
	}
	return standardTLSTransport{config: configuration}, nil
}

func (server *Server) hasExplicitSecureTransport() bool {
	return server.config.TLSConfig != nil || server.config.SecureTransport != nil
}

func globalTLSConfigurationPresent(entry directory.Entry) bool {
	for _, directive := range recognizedGlobalTLSDirectives {
		if globalTLSAttributePresent(entry, directive) {
			return true
		}
	}
	return false
}

func globalTLSAttributePresent(entry directory.Entry, description string) bool {
	for _, attribute := range entry.Attributes {
		base := strings.TrimSpace(attribute.Description)
		if separator := strings.IndexByte(base, ';'); separator >= 0 {
			base = base[:separator]
		}
		if strings.EqualFold(base, description) {
			return true
		}
	}
	return false
}

func globalTLSSingleValue(
	entry directory.Entry,
	description string,
) ([]byte, bool, error) {
	var values [][]byte
	for _, attribute := range entry.Attributes {
		base := strings.TrimSpace(attribute.Description)
		if separator := strings.IndexByte(base, ';'); separator >= 0 {
			base = base[:separator]
		}
		if strings.EqualFold(base, description) {
			values = append(values, attribute.Values...)
		}
	}
	if len(values) == 0 {
		return nil, false, nil
	}
	if len(values) != 1 {
		return nil, true, fmt.Errorf(
			"%s %s must contain exactly one value",
			entry.DN,
			description,
		)
	}
	return append([]byte(nil), values[0]...), true, nil
}

func parseGlobalTLSAttributes(entry directory.Entry) (globalTLSAttributes, error) {
	var attributes globalTLSAttributes
	var err error
	if attributes.caCertificate, _, err = globalTLSSingleValue(
		entry,
		"olcTLSCACertificate",
	); err != nil {
		return globalTLSAttributes{}, err
	}
	if attributes.caCertificateFile, err = globalTLSSingleString(
		entry,
		"olcTLSCACertificateFile",
	); err != nil {
		return globalTLSAttributes{}, err
	}
	if len(attributes.caCertificate) > 0 && attributes.caCertificateFile != "" {
		return globalTLSAttributes{}, fmt.Errorf(
			"%s configures both olcTLSCACertificate and olcTLSCACertificateFile",
			entry.DN,
		)
	}

	if attributes.certificate, _, err = globalTLSSingleValue(
		entry,
		"olcTLSCertificate",
	); err != nil {
		return globalTLSAttributes{}, err
	}
	if attributes.certificateFile, err = globalTLSSingleString(
		entry,
		"olcTLSCertificateFile",
	); err != nil {
		return globalTLSAttributes{}, err
	}
	if len(attributes.certificate) > 0 && attributes.certificateFile != "" {
		return globalTLSAttributes{}, fmt.Errorf(
			"%s configures both olcTLSCertificate and olcTLSCertificateFile",
			entry.DN,
		)
	}

	if attributes.certificateKey, _, err = globalTLSSingleValue(
		entry,
		"olcTLSCertificateKey",
	); err != nil {
		return globalTLSAttributes{}, err
	}
	if attributes.certificateKeyFile, err = globalTLSSingleString(
		entry,
		"olcTLSCertificateKeyFile",
	); err != nil {
		return globalTLSAttributes{}, err
	}
	if len(attributes.certificateKey) > 0 && attributes.certificateKeyFile != "" {
		return globalTLSAttributes{}, fmt.Errorf(
			"%s configures both olcTLSCertificateKey and olcTLSCertificateKeyFile",
			entry.DN,
		)
	}

	if attributes.cipherSuite, err = globalTLSSingleString(
		entry,
		"olcTLSCipherSuite",
	); err != nil {
		return globalTLSAttributes{}, err
	}
	if attributes.crlCheck, err = globalTLSSingleString(
		entry,
		"olcTLSCRLCheck",
	); err != nil {
		return globalTLSAttributes{}, err
	}
	if attributes.crlFile, err = globalTLSSingleString(
		entry,
		"olcTLSCRLFile",
	); err != nil {
		return globalTLSAttributes{}, err
	}
	if attributes.verifyClient, err = globalTLSSingleString(
		entry,
		"olcTLSVerifyClient",
	); err != nil {
		return globalTLSAttributes{}, err
	}
	if attributes.protocolMin, err = globalTLSSingleString(
		entry,
		"olcTLSProtocolMin",
	); err != nil {
		return globalTLSAttributes{}, err
	}
	return attributes, nil
}

func globalTLSServerMaterialPresent(attributes globalTLSAttributes) bool {
	return len(attributes.certificate) > 0 ||
		attributes.certificateFile != "" ||
		len(attributes.certificateKey) > 0 ||
		attributes.certificateKeyFile != ""
}

func globalTLSSingleString(
	entry directory.Entry,
	description string,
) (string, error) {
	value, present, err := globalTLSSingleValue(entry, description)
	if err != nil || !present {
		return "", err
	}
	trimmed := strings.TrimSpace(string(value))
	if trimmed == "" {
		return "", fmt.Errorf("%s %s cannot be empty", entry.DN, description)
	}
	return trimmed, nil
}

func (server *Server) buildGlobalTLSConfig(
	entryDN string,
	attributes globalTLSAttributes,
	crlPolicy string,
	crls []*x509.RevocationList,
) (*tls.Config, error) {
	certificateData, err := globalTLSData(
		attributes.certificate,
		attributes.certificateFile,
		"olcTLSCertificateFile",
	)
	if err != nil {
		return nil, fmt.Errorf("%s TLS certificate: %w", entryDN, err)
	}
	keyData, err := globalTLSData(
		attributes.certificateKey,
		attributes.certificateKeyFile,
		"olcTLSCertificateKeyFile",
	)
	if err != nil {
		return nil, fmt.Errorf("%s TLS private key: %w", entryDN, err)
	}
	if len(certificateData) == 0 {
		return nil, fmt.Errorf(
			"%s olcTLSCertificate or olcTLSCertificateFile is required",
			entryDN,
		)
	}
	if len(keyData) == 0 {
		return nil, fmt.Errorf(
			"%s olcTLSCertificateKey or olcTLSCertificateKeyFile is required",
			entryDN,
		)
	}

	certificate, err := parseGlobalTLSKeyPair(certificateData, keyData)
	if err != nil {
		return nil, fmt.Errorf(
			"%s olcTLSCertificate/olcTLSCertificateKey: %w",
			entryDN,
			err,
		)
	}
	now := time.Now()
	if server.clock != nil {
		now = server.clock()
	} else if server.config.Clock != nil {
		now = server.config.Clock()
	}
	if now.Before(certificate.Leaf.NotBefore) || now.After(certificate.Leaf.NotAfter) {
		return nil, fmt.Errorf(
			"%s olcTLSCertificate is not valid at %s",
			entryDN,
			now.UTC().Format(time.RFC3339),
		)
	}
	if !certificateSupportsServerAuthentication(certificate.Leaf) {
		return nil, fmt.Errorf(
			"%s olcTLSCertificate does not permit server authentication",
			entryDN,
		)
	}

	configuration := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}
	if attributes.protocolMin != "" {
		configuration.MinVersion, err = parseGlobalTLSProtocolMin(
			attributes.protocolMin,
		)
		if err != nil {
			return nil, fmt.Errorf("%s olcTLSProtocolMin: %w", entryDN, err)
		}
	}
	if attributes.cipherSuite != "" {
		if configuration.MinVersion >= tls.VersionTLS13 {
			return nil, fmt.Errorf(
				"%s olcTLSCipherSuite cannot configure TLS 1.3 cipher suites in Go",
				entryDN,
			)
		}
		configuration.CipherSuites, err = parseGlobalTLSCipherSuites(
			attributes.cipherSuite,
		)
		if err != nil {
			return nil, fmt.Errorf("%s olcTLSCipherSuite: %w", entryDN, err)
		}
	}

	configuration.ClientAuth, err = parseGlobalTLSVerifyClient(
		attributes.verifyClient,
	)
	if err != nil {
		return nil, fmt.Errorf("%s olcTLSVerifyClient: %w", entryDN, err)
	}
	caData, err := globalTLSData(
		attributes.caCertificate,
		attributes.caCertificateFile,
		"olcTLSCACertificateFile",
	)
	if err != nil {
		return nil, fmt.Errorf("%s TLS CA certificate: %w", entryDN, err)
	}
	if len(caData) > 0 {
		configuration.ClientCAs, err = parseGlobalTLSCAPool(caData)
		if err != nil {
			return nil, fmt.Errorf("%s olcTLSCACertificate: %w", entryDN, err)
		}
	}
	if globalTLSClientVerificationRequired(configuration.ClientAuth) &&
		configuration.ClientCAs == nil {
		configuration.ClientCAs, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("%s load system client CA pool: %w", entryDN, err)
		}
	}
	if crlPolicy != "none" {
		if !globalTLSCRLCurrentAt(crls, now) {
			return nil, fmt.Errorf(
				"%s olcTLSCRLCheck=%s requires at least one current olcTLSCRLFile CRL",
				entryDN,
				crlPolicy,
			)
		}
		if configuration.ClientAuth == tls.RequestClientCert &&
			configuration.ClientCAs == nil {
			configuration.ClientCAs, err = x509.SystemCertPool()
			if err != nil {
				return nil, fmt.Errorf("%s load system client CA pool: %w", entryDN, err)
			}
		}
		configureGlobalTLSCRLVerification(
			configuration,
			crls,
			crlPolicy,
			server.clock,
		)
	}
	return configuration, nil
}

func parseGlobalTLSCRLCheck(value string) (string, error) {
	policy := strings.ToLower(strings.TrimSpace(value))
	switch policy {
	case "", "none":
		return "none", nil
	case "peer", "all":
		return policy, nil
	default:
		return "", fmt.Errorf(
			"unsupported policy %q; expected none, peer, or all",
			value,
		)
	}
}

func loadGlobalTLSCRLs(path string) ([]*x509.RevocationList, error) {
	if path == "" {
		return nil, nil
	}
	data, err := globalTLSData(nil, path, "olcTLSCRLFile")
	if err != nil {
		return nil, err
	}
	return parseGlobalTLSCRLs(data)
}

func parseGlobalTLSCRLs(data []byte) ([]*x509.RevocationList, error) {
	remaining := bytes.TrimSpace(data)
	var crls []*x509.RevocationList
	for bytes.HasPrefix(remaining, []byte("-----BEGIN")) {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, errors.New("CRL data contains invalid PEM encoding")
		}
		remaining = bytes.TrimSpace(rest)
		if block.Type != "X509 CRL" && block.Type != "CRL" {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PEM CRL: %w", err)
		}
		crls = append(crls, crl)
	}
	if len(crls) > 0 {
		if len(remaining) != 0 {
			return nil, errors.New("CRL data contains trailing non-PEM bytes")
		}
		return crls, nil
	}
	crl, err := x509.ParseRevocationList(remaining)
	if err != nil {
		return nil, fmt.Errorf("parse DER CRL: %w", err)
	}
	return []*x509.RevocationList{crl}, nil
}

func globalTLSCRLCurrentAt(crls []*x509.RevocationList, now time.Time) bool {
	for _, crl := range crls {
		if globalTLSCRLValidAt(crl, now) {
			return true
		}
	}
	return false
}

func globalTLSCRLValidAt(crl *x509.RevocationList, now time.Time) bool {
	return crl != nil &&
		!now.Before(crl.ThisUpdate) &&
		(crl.NextUpdate.IsZero() || !now.After(crl.NextUpdate))
}

func configureGlobalTLSCRLVerification(
	configuration *tls.Config,
	crls []*x509.RevocationList,
	policy string,
	clock func() time.Time,
) {
	configuration.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return nil
		}
		chains := state.VerifiedChains
		if len(chains) == 0 {
			leaf := state.PeerCertificates[0]
			intermediates := x509.NewCertPool()
			for _, certificate := range state.PeerCertificates[1:] {
				intermediates.AddCert(certificate)
			}
			var err error
			chains, err = leaf.Verify(x509.VerifyOptions{
				Roots:         configuration.ClientCAs,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			})
			if err != nil {
				return fmt.Errorf("verify TLS client certificate for CRL checking: %w", err)
			}
		}
		now := time.Now()
		if clock != nil {
			now = clock()
		}
		var lastErr error
		for _, chain := range chains {
			if err := verifyGlobalTLSCRLs(chain, crls, policy, now); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
		if lastErr == nil {
			return errors.New("TLS client certificate has no verified chain")
		}
		return lastErr
	}
}

func verifyGlobalTLSCRLs(
	chain []*x509.Certificate,
	crls []*x509.RevocationList,
	policy string,
	now time.Time,
) error {
	if len(chain) < 2 {
		return errors.New("TLS verified client chain has no issuer")
	}
	checkCount := 1
	if policy == "all" {
		checkCount = len(chain) - 1
	}
	for index := 0; index < checkCount; index++ {
		certificate := chain[index]
		issuer := chain[index+1]
		var newest *x509.RevocationList
		for _, crl := range crls {
			if !globalTLSCRLValidAt(crl, now) ||
				!bytes.Equal(crl.RawIssuer, certificate.RawIssuer) ||
				crl.CheckSignatureFrom(issuer) != nil {
				continue
			}
			if newest == nil || crl.ThisUpdate.After(newest.ThisUpdate) ||
				(crl.ThisUpdate.Equal(newest.ThisUpdate) &&
					globalTLSCRLNumberAfter(crl, newest)) {
				newest = crl
			}
		}
		if newest == nil {
			return fmt.Errorf(
				"no current issuer-signed CRL is available for TLS client certificate %s",
				certificate.Subject.String(),
			)
		}
		for _, revoked := range newest.RevokedCertificateEntries {
			if revoked.SerialNumber == nil ||
				revoked.ReasonCode == 8 ||
				revoked.RevocationTime.After(now) {
				continue
			}
			if certificate.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
				return fmt.Errorf(
					"TLS client certificate %s is revoked",
					certificate.Subject.String(),
				)
			}
		}
	}
	return nil
}

func globalTLSCRLNumberAfter(
	left,
	right *x509.RevocationList,
) bool {
	if left.Number == nil {
		return false
	}
	return right.Number == nil || left.Number.Cmp(right.Number) > 0
}

func globalTLSData(inline []byte, path, kind string) ([]byte, error) {
	if len(inline) > 0 {
		return append([]byte(nil), inline...), nil
	}
	if path == "" {
		return nil, nil
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s file %q: %w", kind, path, err)
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("%s file %q is empty", kind, path)
	}
	return value, nil
}

func parseGlobalTLSKeyPair(
	certificateData,
	keyData []byte,
) (tls.Certificate, error) {
	certificates, err := parseGlobalTLSCertificates(certificateData)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse certificate: %w", err)
	}
	certificatePEM := make([]byte, 0)
	for _, certificate := range certificates {
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		})...)
	}
	keyPEM, err := normalizeGlobalTLSPrivateKey(keyData)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPair.Leaf = certificates[0]
	return keyPair, nil
}

func parseGlobalTLSCertificates(data []byte) ([]*x509.Certificate, error) {
	remaining := data
	var certificates []*x509.Certificate
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	if len(certificates) > 0 {
		if len(strings.TrimSpace(string(remaining))) != 0 {
			return nil, errors.New("certificate data contains trailing non-PEM bytes")
		}
		return certificates, nil
	}
	certificates, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, err
	}
	if len(certificates) == 0 {
		return nil, errors.New("certificate data contains no certificates")
	}
	return certificates, nil
}

func normalizeGlobalTLSPrivateKey(data []byte) ([]byte, error) {
	remaining := data
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if !strings.Contains(block.Type, "PRIVATE KEY") {
			continue
		}
		if x509.IsEncryptedPEMBlock(block) {
			return nil, errors.New("encrypted private keys are unsupported")
		}
		return pem.EncodeToMemory(block), nil
	}
	privateKey, err := parseGlobalTLSDERPrivateKey(data)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parseGlobalTLSDERPrivateKey(data []byte) (any, error) {
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		return key, nil
	}
	return nil, errors.New("private key is not valid PKCS#8, PKCS#1, or SEC1 DER")
}

func certificateSupportsServerAuthentication(certificate *x509.Certificate) bool {
	if len(certificate.ExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny || usage == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

func parseGlobalTLSCAPool(data []byte) (*x509.CertPool, error) {
	certificates, err := parseGlobalTLSCertificates(data)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool, nil
}

func parseGlobalTLSVerifyClient(value string) (tls.ClientAuthType, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "never":
		return tls.NoClientCert, nil
	case "allow":
		return tls.RequestClientCert, nil
	case "try":
		return tls.VerifyClientCertIfGiven, nil
	case "demand", "hard":
		return tls.RequireAndVerifyClientCert, nil
	default:
		return tls.NoClientCert, fmt.Errorf("unsupported policy %q", value)
	}
}

func globalTLSClientVerificationRequired(value tls.ClientAuthType) bool {
	return value == tls.VerifyClientCertIfGiven ||
		value == tls.RequireAndVerifyClientCert
}

func parseGlobalTLSProtocolMin(value string) (uint16, error) {
	switch strings.TrimSpace(value) {
	case "3.1":
		return tls.VersionTLS10, nil
	case "3.2":
		return tls.VersionTLS11, nil
	case "3.3":
		return tls.VersionTLS12, nil
	case "3.4":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf(
			"unsupported protocol %q; expected 3.1, 3.2, 3.3, or 3.4",
			value,
		)
	}
}

func parseGlobalTLSCipherSuites(value string) ([]uint16, error) {
	selectors := strings.FieldsFunc(value, func(character rune) bool {
		return character == ':' || character == ',' ||
			character == ' ' || character == '\t' ||
			character == '\r' || character == '\n'
	})
	if len(selectors) == 0 {
		return nil, errors.New("cipher suite is empty")
	}
	for _, selector := range selectors {
		upper := strings.ToUpper(selector)
		if strings.ContainsAny(selector, "!+@") ||
			strings.HasPrefix(selector, "-") ||
			upper == "DEFAULT" || upper == "HIGH" || upper == "ALL" {
			return nil, fmt.Errorf(
				"OpenSSL selector %q cannot be mapped exactly to Go TLS",
				selector,
			)
		}
	}
	return parseSyncConsumerCipherSuites(strings.Join(selectors, ":"))
}
