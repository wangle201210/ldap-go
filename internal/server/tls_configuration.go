package server

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"go/version"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var recognizedGlobalTLSDirectives = []string{
	"olcTLSCACertificate",
	"olcTLSCACertificateFile",
	"olcTLSCACertificatePath",
	"olcTLSCertificate",
	"olcTLSCertificateFile",
	"olcTLSCertificateKey",
	"olcTLSCertificateKeyFile",
	"olcTLSCipherSuite",
	"olcTLSCRLCheck",
	"olcTLSCRLFile",
	"olcTLSECName",
	"olcTLSVerifyClient",
	"olcTLSProtocolMin",
	"olcTLSRandFile",
	"olcTLSDHParamFile",
}

type globalTLSAttributes struct {
	caCertificate      []byte
	caCertificateFile  string
	caCertificatePath  string
	certificate        []byte
	certificateFile    string
	certificateKey     []byte
	certificateKeyFile string
	cipherSuite        string
	crlCheck           string
	crlFile            string
	ecName             string
	verifyClient       string
	protocolMin        string
	randFile           string
	dhParamFile        string
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

	attributes, err := parseGlobalTLSAttributes(entry)
	if err != nil {
		return nil, err
	}
	if err := validateGlobalTLSRandFile(attributes.randFile); err != nil {
		return nil, fmt.Errorf("%s olcTLSRandFile: %w", entry.DN, err)
	}
	if err := loadGlobalTLSDHParameters(attributes.dhParamFile); err != nil {
		return nil, fmt.Errorf("%s olcTLSDHParamFile: %w", entry.DN, err)
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
	if attributes.caCertificatePath, err = globalTLSSingleString(
		entry,
		"olcTLSCACertificatePath",
	); err != nil {
		return globalTLSAttributes{}, err
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
	if attributes.ecName, err = globalTLSSingleString(
		entry,
		"olcTLSECName",
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
	if attributes.randFile, err = globalTLSSingleString(
		entry,
		"olcTLSRandFile",
	); err != nil {
		return globalTLSAttributes{}, err
	}
	if attributes.dhParamFile, err = globalTLSSingleString(
		entry,
		"olcTLSDHParamFile",
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
	keyData, err := globalTLSPrivateKeyData(
		attributes.certificateKey,
		attributes.certificateKeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("%s TLS private key: %w", entryDN, err)
	}
	defer clearGlobalTLSSecret(keyData)
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
	if attributes.dhParamFile != "" &&
		!globalTLSDHParametersAreHandshakeInert(configuration) {
		return nil, fmt.Errorf(
			"%s olcTLSDHParamFile cannot be represented while TLS 1.2 or earlier uses the OpenSSL default cipher list, which may negotiate finite-field DHE; configure olcTLSProtocolMin 3.4 or an exact non-DHE olcTLSCipherSuite",
			entryDN,
		)
	}
	if attributes.ecName != "" {
		// OpenSSL accepts an ordered group list (and newer tuple/key-share
		// selectors). crypto/tls only exposes an allowed set here and explicitly
		// ignores its order, selecting groups with Go's internal preference.
		configuration.CurvePreferences, err = parseGlobalTLSECName(attributes.ecName)
		if err != nil {
			return nil, fmt.Errorf("%s olcTLSECName: %w", entryDN, err)
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
	if len(caData) > 0 || attributes.caCertificatePath != "" {
		configuration.ClientCAs, err = buildGlobalTLSCAPool(
			caData,
			attributes.caCertificatePath,
		)
		if err != nil {
			return nil, fmt.Errorf("%s TLS CA certificate configuration: %w", entryDN, err)
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

// Modern OpenLDAP builds with URANDOM_DEVICE make TLSRandFile an inert
// compatibility setting. Go's crypto/tls also seeds itself from the operating
// system, so only the LDAP string representation needs validation here.
func validateGlobalTLSRandFile(path string) error {
	if strings.IndexByte(path, 0) >= 0 {
		return errors.New("path contains a NUL byte")
	}
	return nil
}

type globalTLSDHParameters struct {
	Prime              *big.Int
	Generator          *big.Int
	PrivateValueLength int `asn1:"optional"`
}

func loadGlobalTLSDHParameters(path string) error {
	if path == "" {
		return nil
	}
	data, _, err := readGlobalTLSFile(path, "olcTLSDHParamFile")
	if err != nil {
		return err
	}
	block, trailing := pem.Decode(data)
	if block == nil {
		return errors.New("DH parameters are not PEM encoded")
	}
	if block.Type != "DH PARAMETERS" {
		return fmt.Errorf(
			"unsupported PEM block %q; expected DH PARAMETERS",
			block.Type,
		)
	}
	if len(bytes.TrimSpace(trailing)) != 0 {
		return errors.New("DH parameters contain trailing data")
	}
	var parameters globalTLSDHParameters
	rest, err := asn1.Unmarshal(block.Bytes, &parameters)
	if err != nil {
		return fmt.Errorf("parse PKCS#3 DH parameters: %w", err)
	}
	if len(rest) != 0 {
		return errors.New("PKCS#3 DH parameters contain trailing DER data")
	}
	if parameters.Prime == nil || parameters.Prime.Sign() <= 0 {
		return errors.New("PKCS#3 DH prime must be positive")
	}
	if parameters.Generator == nil || parameters.Generator.Cmp(big.NewInt(2)) < 0 ||
		parameters.Generator.Cmp(parameters.Prime) >= 0 {
		return errors.New("PKCS#3 DH generator is outside the valid range")
	}
	if parameters.PrivateValueLength < 0 {
		return errors.New("PKCS#3 DH private-value length cannot be negative")
	}
	return nil
}

func globalTLSDHParametersAreHandshakeInert(configuration *tls.Config) bool {
	if configuration.MinVersion >= tls.VersionTLS13 {
		return true
	}
	// crypto/tls exposes no finite-field DHE suites. A non-empty exact list
	// therefore proves that OpenSSL cannot select a suite which consumes the
	// configured parameters for TLS 1.2 or earlier.
	return len(configuration.CipherSuites) != 0
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
	value, _, err := readGlobalTLSFile(path, kind)
	if err != nil {
		return nil, err
	}
	return value, nil
}

const (
	globalTLSMaximumFileSize                          = 16 << 20
	globalTLSMaximumPassword                          = 4 << 10
	globalTLSPKCS8MaximumIterations                   = 10_000_000
	globalTLSPKCS8MaximumSaltSize                     = 1 << 10
	globalTLSPKCS8MaximumDerivedKeySize               = 1 << 10
	globalTLSPKCS8MaximumScryptMemory          uint64 = 256 << 20
	globalTLSPKCS8MaximumScryptWork            uint64 = 64 << 20
	globalTLSMaximumCADirectories                     = 16
	globalTLSMaximumCADirectoryFiles                  = 4096
	globalTLSMaximumCADirectoryBytes           int64  = 64 << 20
	globalTLSMaximumCADirectoryCertificates           = 4096
	globalTLSPrivateKeyPasswordFileEnvironment        = "LDAP_GO_TLS_KEY_PASSWORD_FILE"
)

var globalTLSCAHashFileName = regexp.MustCompile(`^[0-9A-Fa-f]{8}\.[0-9]+$`)

func readGlobalTLSFile(path, kind string) ([]byte, os.FileInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s file %q: %w", kind, path, err)
	}
	defer file.Close()
	information, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat %s file %q: %w", kind, path, err)
	}
	if !information.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s file %q is not a regular file", kind, path)
	}
	if information.Size() > globalTLSMaximumFileSize {
		return nil, nil, fmt.Errorf(
			"%s file %q exceeds the %d-byte limit",
			kind,
			path,
			globalTLSMaximumFileSize,
		)
	}
	value, err := io.ReadAll(io.LimitReader(file, globalTLSMaximumFileSize+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read %s file %q: %w", kind, path, err)
	}
	if len(value) == 0 {
		return nil, nil, fmt.Errorf("%s file %q is empty", kind, path)
	}
	if len(value) > globalTLSMaximumFileSize {
		return nil, nil, fmt.Errorf(
			"%s file %q exceeds the %d-byte limit",
			kind,
			path,
			globalTLSMaximumFileSize,
		)
	}
	return value, information, nil
}

func globalTLSPrivateKeyData(inline []byte, path string) ([]byte, error) {
	if len(inline) > 0 {
		return append([]byte(nil), inline...), nil
	}
	if path == "" {
		return nil, nil
	}
	value, _, err := readGlobalTLSFile(path, "olcTLSCertificateKeyFile")
	return value, err
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
	defer clearGlobalTLSSecret(keyPEM)
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
	if len(data) == 0 {
		return nil, errors.New("private key data is empty")
	}
	if len(data) > globalTLSMaximumFileSize {
		return nil, fmt.Errorf(
			"private key data exceeds the %d-byte limit",
			globalTLSMaximumFileSize,
		)
	}
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
			password, err := loadGlobalTLSPrivateKeyPassword()
			if err != nil {
				return nil, err
			}
			decrypted, err := x509.DecryptPEMBlock(block, password)
			clearGlobalTLSSecret(password)
			if err != nil {
				return nil, fmt.Errorf("decrypt traditional encrypted PEM private key: %w", err)
			}
			privateKey, parseErr := parseGlobalTLSDERPrivateKey(decrypted)
			clearGlobalTLSSecret(decrypted)
			if parseErr != nil {
				return nil, errors.New(
					"decrypt traditional encrypted PEM private key: incorrect password or invalid private key",
				)
			}
			der, err := x509.MarshalPKCS8PrivateKey(privateKey)
			if err != nil {
				return nil, fmt.Errorf("marshal decrypted private key: %w", err)
			}
			defer clearGlobalTLSSecret(der)
			return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
		}
		if block.Type == "ENCRYPTED PRIVATE KEY" {
			password, err := loadGlobalTLSPrivateKeyPassword()
			if err != nil {
				return nil, err
			}
			decrypted, err := decryptGlobalTLSPKCS8PrivateKey(block.Bytes, password)
			clearGlobalTLSSecret(password)
			if err != nil {
				return nil, err
			}
			defer clearGlobalTLSSecret(decrypted)
			privateKey, err := parseGlobalTLSDERPrivateKey(decrypted)
			if err != nil {
				return nil, errors.New(
					"decrypt PKCS#8 encrypted private key: incorrect password or invalid private key",
				)
			}
			der, err := x509.MarshalPKCS8PrivateKey(privateKey)
			if err != nil {
				return nil, fmt.Errorf("marshal decrypted PKCS#8 private key: %w", err)
			}
			defer clearGlobalTLSSecret(der)
			return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
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
	defer clearGlobalTLSSecret(der)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

var (
	globalTLSPBES2OID   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	globalTLSSMPBESOID  = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 4, 1, 5, 2}
	globalTLSPBKDF2OID  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	globalTLSSMPBKDFOID = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 4, 1, 5, 1}
	globalTLSScryptOID  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
)

type globalTLSEncryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

type globalTLSPBKDF2Parameters struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                      `asn1:"optional"`
	PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
}

type globalTLSScryptParameters struct {
	Salt                     []byte
	CostParameter            int
	BlockSize                int
	ParallelizationParameter int
	KeyLength                int `asn1:"optional"`
}

type globalTLSPBES1Parameters struct {
	Salt       []byte
	Iterations int
}

func decryptGlobalTLSPKCS8PrivateKey(data, password []byte) ([]byte, error) {
	information, err := parseAndValidateGlobalTLSEncryptedPrivateKey(data)
	if err != nil {
		return nil, err
	}
	var decrypted []byte
	switch {
	case pkcs.IsPBES2(information.EncryptionAlgorithm) ||
		pkcs.IsSMPBES(information.EncryptionAlgorithm):
		var parameters pkcs.PBES2Params
		if err := unmarshalGlobalTLSPKCS8(
			information.EncryptionAlgorithm.Parameters.FullBytes,
			&parameters,
		); err != nil {
			return nil, fmt.Errorf("parse PKCS#8 PBES2 parameters: %w", err)
		}
		decrypted, _, err = parameters.Decrypt(password, information.EncryptedData)
	case pkcs.IsPBES1(information.EncryptionAlgorithm):
		decrypted, _, err = (&pkcs.PBES1{
			Algorithm: information.EncryptionAlgorithm,
		}).Decrypt(password, information.EncryptedData)
	default:
		return nil, fmt.Errorf(
			"unsupported PKCS#8 encryption algorithm %s",
			information.EncryptionAlgorithm.Algorithm.String(),
		)
	}
	if err != nil {
		clearGlobalTLSSecret(decrypted)
		return nil, errors.New(
			"decrypt PKCS#8 encrypted private key: incorrect password or invalid encryption parameters",
		)
	}
	if len(decrypted) == 0 || len(decrypted) > globalTLSMaximumFileSize {
		clearGlobalTLSSecret(decrypted)
		return nil, errors.New("decrypted PKCS#8 private key has an invalid size")
	}
	return decrypted, nil
}

func parseAndValidateGlobalTLSEncryptedPrivateKey(
	data []byte,
) (globalTLSEncryptedPrivateKeyInfo, error) {
	var information globalTLSEncryptedPrivateKeyInfo
	if err := unmarshalGlobalTLSPKCS8(data, &information); err != nil {
		return information, fmt.Errorf("parse PKCS#8 encrypted private key: %w", err)
	}
	if len(information.EncryptedData) == 0 ||
		len(information.EncryptedData) > globalTLSMaximumFileSize {
		return information, errors.New("PKCS#8 encrypted private key has an invalid payload size")
	}
	switch {
	case information.EncryptionAlgorithm.Algorithm.Equal(globalTLSPBES2OID),
		information.EncryptionAlgorithm.Algorithm.Equal(globalTLSSMPBESOID):
		if err := validateGlobalTLSPBES2Parameters(
			information.EncryptionAlgorithm.Parameters.FullBytes,
		); err != nil {
			return information, err
		}
	case pkcs.IsPBES1(information.EncryptionAlgorithm):
		var parameters globalTLSPBES1Parameters
		if err := unmarshalGlobalTLSPKCS8(
			information.EncryptionAlgorithm.Parameters.FullBytes,
			&parameters,
		); err != nil {
			return information, fmt.Errorf("parse PKCS#8 PBES1 parameters: %w", err)
		}
		if err := validateGlobalTLSPKCS8SaltAndIterations(
			parameters.Salt,
			parameters.Iterations,
		); err != nil {
			return information, fmt.Errorf("PKCS#8 PBES1 parameters: %w", err)
		}
	default:
		return information, fmt.Errorf(
			"unsupported PKCS#8 encryption algorithm %s",
			information.EncryptionAlgorithm.Algorithm.String(),
		)
	}
	return information, nil
}

func validateGlobalTLSPBES2Parameters(data []byte) error {
	var parameters pkcs.PBES2Params
	if err := unmarshalGlobalTLSPKCS8(data, &parameters); err != nil {
		return fmt.Errorf("parse PKCS#8 PBES2 parameters: %w", err)
	}
	switch {
	case parameters.KeyDerivationFunc.Algorithm.Equal(globalTLSPBKDF2OID),
		parameters.KeyDerivationFunc.Algorithm.Equal(globalTLSSMPBKDFOID):
		var kdf globalTLSPBKDF2Parameters
		if err := unmarshalGlobalTLSPKCS8(
			parameters.KeyDerivationFunc.Parameters.FullBytes,
			&kdf,
		); err != nil {
			return fmt.Errorf("parse PKCS#8 PBKDF2 parameters: %w", err)
		}
		if err := validateGlobalTLSPKCS8SaltAndIterations(
			kdf.Salt,
			kdf.IterationCount,
		); err != nil {
			return fmt.Errorf("PKCS#8 PBKDF2 parameters: %w", err)
		}
		return validateGlobalTLSPKCS8KeyLength(kdf.KeyLength)
	case parameters.KeyDerivationFunc.Algorithm.Equal(globalTLSScryptOID):
		var kdf globalTLSScryptParameters
		if err := unmarshalGlobalTLSPKCS8(
			parameters.KeyDerivationFunc.Parameters.FullBytes,
			&kdf,
		); err != nil {
			return fmt.Errorf("parse PKCS#8 scrypt parameters: %w", err)
		}
		return validateGlobalTLSPKCS8Scrypt(kdf)
	default:
		return fmt.Errorf(
			"unsupported PKCS#8 KDF %s",
			parameters.KeyDerivationFunc.Algorithm.String(),
		)
	}
}

func validateGlobalTLSPKCS8SaltAndIterations(salt []byte, iterations int) error {
	if len(salt) > globalTLSPKCS8MaximumSaltSize {
		return fmt.Errorf("salt exceeds the %d-byte limit", globalTLSPKCS8MaximumSaltSize)
	}
	if iterations < 1 || iterations > globalTLSPKCS8MaximumIterations {
		return fmt.Errorf(
			"iteration count must be between 1 and %d",
			globalTLSPKCS8MaximumIterations,
		)
	}
	return nil
}

func validateGlobalTLSPKCS8KeyLength(length int) error {
	if length < 0 || length > globalTLSPKCS8MaximumDerivedKeySize {
		return fmt.Errorf(
			"derived key length must not exceed %d bytes",
			globalTLSPKCS8MaximumDerivedKeySize,
		)
	}
	return nil
}

func validateGlobalTLSPKCS8Scrypt(parameters globalTLSScryptParameters) error {
	if len(parameters.Salt) > globalTLSPKCS8MaximumSaltSize {
		return fmt.Errorf("PKCS#8 scrypt salt exceeds the %d-byte limit", globalTLSPKCS8MaximumSaltSize)
	}
	if err := validateGlobalTLSPKCS8KeyLength(parameters.KeyLength); err != nil {
		return fmt.Errorf("PKCS#8 scrypt parameters: %w", err)
	}
	if parameters.CostParameter <= 1 ||
		parameters.CostParameter&(parameters.CostParameter-1) != 0 ||
		parameters.BlockSize <= 0 ||
		parameters.ParallelizationParameter <= 0 {
		return errors.New("PKCS#8 scrypt cost, block size, and parallelism are invalid")
	}
	cost := uint64(parameters.CostParameter)
	blockSize := uint64(parameters.BlockSize)
	parallelism := uint64(parameters.ParallelizationParameter)
	if blockSize > globalTLSPKCS8MaximumScryptMemory/128 ||
		cost > globalTLSPKCS8MaximumScryptMemory/(128*blockSize) {
		return fmt.Errorf(
			"PKCS#8 scrypt memory cost exceeds the %d-byte limit",
			globalTLSPKCS8MaximumScryptMemory,
		)
	}
	if blockSize > globalTLSPKCS8MaximumScryptWork/cost ||
		parallelism > globalTLSPKCS8MaximumScryptWork/(cost*blockSize) {
		return fmt.Errorf(
			"PKCS#8 scrypt work factor exceeds the %d-unit limit",
			globalTLSPKCS8MaximumScryptWork,
		)
	}
	return nil
}

func unmarshalGlobalTLSPKCS8(data []byte, value any) error {
	rest, err := asn1.Unmarshal(data, value)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("ASN.1 data contains trailing bytes")
	}
	return nil
}

func loadGlobalTLSPrivateKeyPassword() ([]byte, error) {
	path, configured := os.LookupEnv(globalTLSPrivateKeyPasswordFileEnvironment)
	if !configured || path == "" {
		return nil, fmt.Errorf(
			"encrypted private key requires %s",
			globalTLSPrivateKeyPasswordFileEnvironment,
		)
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf(
			"%s must name an absolute password file path",
			globalTLSPrivateKeyPasswordFileEnvironment,
		)
	}
	linkInformation, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat TLS private key password file %q: %w", path, err)
	}
	if linkInformation.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("TLS private key password file %q must not be a symbolic link", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open TLS private key password file %q: %w", path, err)
	}
	defer file.Close()
	information, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat TLS private key password file %q: %w", path, err)
	}
	if !os.SameFile(linkInformation, information) {
		return nil, fmt.Errorf("TLS private key password file %q changed while it was opened", path)
	}
	if !information.Mode().IsRegular() {
		return nil, fmt.Errorf("TLS private key password file %q is not a regular file", path)
	}
	if runtime.GOOS != "windows" && information.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf(
			"TLS private key password file %q permissions %04o expose the password to group or other users",
			path,
			information.Mode().Perm(),
		)
	}
	if information.Size() > globalTLSMaximumPassword {
		return nil, fmt.Errorf(
			"TLS private key password file %q exceeds the %d-byte limit",
			path,
			globalTLSMaximumPassword,
		)
	}
	value, err := io.ReadAll(io.LimitReader(file, globalTLSMaximumPassword+1))
	if err != nil {
		return nil, fmt.Errorf("read TLS private key password file %q: %w", path, err)
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("TLS private key password file %q is empty", path)
	}
	if len(value) > globalTLSMaximumPassword {
		clearGlobalTLSSecret(value)
		return nil, fmt.Errorf(
			"TLS private key password file %q exceeds the %d-byte limit",
			path,
			globalTLSMaximumPassword,
		)
	}
	value = bytes.TrimSuffix(value, []byte("\n"))
	value = bytes.TrimSuffix(value, []byte("\r"))
	if bytes.IndexByte(value, 0) >= 0 {
		clearGlobalTLSSecret(value)
		return nil, errors.New("TLS private key password contains a NUL byte")
	}
	return value, nil
}

func clearGlobalTLSSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
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
	return globalTLSCAPool(certificates), nil
}

func buildGlobalTLSCAPool(data []byte, pathList string) (*x509.CertPool, error) {
	certificates := make([]*x509.Certificate, 0)
	if len(data) > 0 {
		parsed, err := parseGlobalTLSCertificates(data)
		if err != nil {
			return nil, fmt.Errorf("parse CA certificate data: %w", err)
		}
		certificates = append(certificates, parsed...)
	}
	if pathList != "" {
		fromDirectories, err := loadGlobalTLSCAPath(pathList)
		if err != nil {
			return nil, fmt.Errorf("olcTLSCACertificatePath: %w", err)
		}
		certificates = append(certificates, fromDirectories...)
	}
	certificates = deduplicateGlobalTLSCertificates(certificates)
	if len(certificates) == 0 {
		return nil, errors.New("CA configuration contains no PEM certificates")
	}
	return globalTLSCAPool(certificates), nil
}

func globalTLSCAPool(certificates []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool
}

func deduplicateGlobalTLSCertificates(
	certificates []*x509.Certificate,
) []*x509.Certificate {
	unique := make([]*x509.Certificate, 0, len(certificates))
	seen := make(map[string]struct{}, len(certificates))
	for _, certificate := range certificates {
		if certificate == nil {
			continue
		}
		fingerprint := string(certificate.Raw)
		if _, exists := seen[fingerprint]; exists {
			continue
		}
		seen[fingerprint] = struct{}{}
		unique = append(unique, certificate)
	}
	return unique
}

func loadGlobalTLSCAPath(configuredPath string) ([]*x509.Certificate, error) {
	return loadGlobalTLSCAPathWithLimits(configuredPath, globalTLSCAPathLimits{
		maximumDirectories:  globalTLSMaximumCADirectories,
		maximumFiles:        globalTLSMaximumCADirectoryFiles,
		maximumBytes:        globalTLSMaximumCADirectoryBytes,
		maximumCertificates: globalTLSMaximumCADirectoryCertificates,
	})
}

type globalTLSCAPathLimits struct {
	maximumDirectories  int
	maximumFiles        int
	maximumBytes        int64
	maximumCertificates int
}

type globalTLSCAPathBudget struct {
	limits       globalTLSCAPathLimits
	directories  int
	files        int
	bytes        int64
	certificates int
}

func loadGlobalTLSCAPathWithLimits(
	configuredPath string,
	limits globalTLSCAPathLimits,
) ([]*x509.Certificate, error) {
	directories := strings.Split(configuredPath, ";")
	budget := globalTLSCAPathBudget{limits: limits}
	certificates := make([]*x509.Certificate, 0)
	for _, configuredDirectory := range directories {
		if configuredDirectory == "" {
			return nil, errors.New("CA directory list contains an empty path")
		}
		budget.directories++
		if budget.directories > budget.limits.maximumDirectories {
			return nil, fmt.Errorf(
				"CA directory list exceeds the %d-directory limit",
				budget.limits.maximumDirectories,
			)
		}
		absolutePath, err := filepath.Abs(configuredDirectory)
		if err != nil {
			return nil, fmt.Errorf("resolve CA directory %q: %w", configuredDirectory, err)
		}
		root, err := os.OpenRoot(absolutePath)
		if err != nil {
			return nil, fmt.Errorf("open CA directory %q: %w", configuredDirectory, err)
		}
		loaded, loadErr := loadGlobalTLSCADirectory(root, configuredDirectory, &budget)
		closeErr := root.Close()
		if loadErr != nil {
			return nil, loadErr
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close CA directory %q: %w", configuredDirectory, closeErr)
		}
		certificates = append(certificates, loaded...)
	}
	return deduplicateGlobalTLSCertificates(certificates), nil
}

func loadGlobalTLSCADirectory(
	root *os.Root,
	configuredPath string,
	budget *globalTLSCAPathBudget,
) ([]*x509.Certificate, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("read CA directory %q: %w", configuredPath, err)
	}
	defer directory.Close()
	certificates := make([]*x509.Certificate, 0)
	for {
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			budget.files++
			if budget.files > budget.limits.maximumFiles {
				return nil, fmt.Errorf(
					"CA directories exceed the %d-file limit",
					budget.limits.maximumFiles,
				)
			}
			if !globalTLSCAHashFileName.MatchString(entry.Name()) {
				continue
			}
			parsed, err := loadGlobalTLSCAHashFile(root, configuredPath, entry.Name(), budget)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, parsed...)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read CA directory %q: %w", configuredPath, readErr)
		}
	}
	return certificates, nil
}

func loadGlobalTLSCAHashFile(
	root *os.Root,
	configuredPath,
	name string,
	budget *globalTLSCAPathBudget,
) ([]*x509.Certificate, error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open CA directory entry %q in %q: %w", name, configuredPath, err)
	}
	defer file.Close()
	information, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect CA directory entry %q in %q: %w", name, configuredPath, err)
	}
	if !information.Mode().IsRegular() {
		return nil, nil
	}
	if information.Size() > globalTLSMaximumFileSize {
		return nil, fmt.Errorf(
			"CA directory entry %q in %q exceeds the %d-byte limit",
			name,
			configuredPath,
			globalTLSMaximumFileSize,
		)
	}
	remaining := budget.limits.maximumBytes - budget.bytes
	if remaining < 0 {
		remaining = 0
	}
	readLimit := int64(globalTLSMaximumFileSize)
	if remaining < readLimit {
		readLimit = remaining
	}
	data, err := io.ReadAll(io.LimitReader(file, readLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read CA directory entry %q in %q: %w", name, configuredPath, err)
	}
	if int64(len(data)) > remaining {
		return nil, fmt.Errorf(
			"CA directories exceed the %d-byte total limit",
			budget.limits.maximumBytes,
		)
	}
	if len(data) > globalTLSMaximumFileSize {
		return nil, fmt.Errorf(
			"CA directory entry %q in %q exceeds the %d-byte limit",
			name,
			configuredPath,
			globalTLSMaximumFileSize,
		)
	}
	budget.bytes += int64(len(data))
	parsed, err := parseGlobalTLSCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("parse CA directory entry %q in %q: %w", name, configuredPath, err)
	}
	if len(parsed) > budget.limits.maximumCertificates-budget.certificates {
		return nil, fmt.Errorf(
			"CA directories exceed the %d-certificate limit",
			budget.limits.maximumCertificates,
		)
	}
	budget.certificates += len(parsed)
	expectedHash := strings.ToLower(name[:8])
	matching := make([]*x509.Certificate, 0, len(parsed))
	for _, certificate := range parsed {
		hash, hashErr := globalTLSOpenSSLSubjectHash(certificate)
		if hashErr != nil {
			return nil, fmt.Errorf(
				"hash CA directory entry %q in %q: %w",
				name,
				configuredPath,
				hashErr,
			)
		}
		if hash == expectedHash {
			matching = append(matching, certificate)
		}
	}
	return matching, nil
}

func globalTLSOpenSSLSubjectHash(certificate *x509.Certificate) (string, error) {
	if certificate == nil || len(certificate.RawSubject) == 0 {
		return "", errors.New("certificate subject is empty")
	}
	canonical, err := globalTLSOpenSSLCanonicalName(certificate.RawSubject)
	if err != nil {
		return "", err
	}
	digest := sha1.Sum(canonical)
	return fmt.Sprintf("%08x", binary.LittleEndian.Uint32(digest[:4])), nil
}

// OpenSSL hashes X.509 names after converting supported ASN.1 strings to
// UTF-8, folding ASCII case and whitespace, sorting each SET, and omitting the
// outer Name SEQUENCE. This mirrors x509_name_canon()/X509_NAME_hash_ex().
func globalTLSOpenSSLCanonicalName(rawSubject []byte) ([]byte, error) {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(rawSubject, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal ||
		sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return nil, errors.New("invalid X.509 subject name")
	}
	canonical := make([]byte, 0, len(rawSubject))
	sets := sequence.Bytes
	for len(sets) > 0 {
		var set asn1.RawValue
		sets, err = asn1.Unmarshal(sets, &set)
		if err != nil || set.Class != asn1.ClassUniversal || set.Tag != asn1.TagSet ||
			!set.IsCompound {
			return nil, errors.New("invalid X.509 subject RDN set")
		}
		entries := make([][]byte, 0, 1)
		values := set.Bytes
		for len(values) > 0 {
			var entry asn1.RawValue
			values, err = asn1.Unmarshal(values, &entry)
			if err != nil || entry.Class != asn1.ClassUniversal ||
				entry.Tag != asn1.TagSequence || !entry.IsCompound {
				return nil, errors.New("invalid X.509 subject attribute")
			}
			var oid asn1.ObjectIdentifier
			attributeRest, oidErr := asn1.Unmarshal(entry.Bytes, &oid)
			if oidErr != nil || len(oid) == 0 {
				return nil, errors.New("invalid X.509 subject attribute OID")
			}
			var value asn1.RawValue
			attributeRest, valueErr := asn1.Unmarshal(attributeRest, &value)
			if valueErr != nil || len(attributeRest) != 0 {
				return nil, errors.New("invalid X.509 subject attribute value")
			}
			oidDER, marshalErr := asn1.Marshal(oid)
			if marshalErr != nil {
				return nil, fmt.Errorf("marshal X.509 subject OID: %w", marshalErr)
			}
			valueDER, canonicalErr := globalTLSOpenSSLCanonicalString(value)
			if canonicalErr != nil {
				return nil, canonicalErr
			}
			body := append(append(make([]byte, 0, len(oidDER)+len(valueDER)), oidDER...), valueDER...)
			entries = append(entries, globalTLSDERValue(0x30, body))
		}
		sort.Slice(entries, func(left, right int) bool {
			return bytes.Compare(entries[left], entries[right]) < 0
		})
		setBody := make([]byte, 0)
		for _, entry := range entries {
			setBody = append(setBody, entry...)
		}
		canonical = append(canonical, globalTLSDERValue(0x31, setBody)...)
	}
	return canonical, nil
}

func globalTLSOpenSSLCanonicalString(value asn1.RawValue) ([]byte, error) {
	if value.Class != asn1.ClassUniversal {
		return append([]byte(nil), value.FullBytes...), nil
	}
	var decoded []byte
	switch value.Tag {
	case asn1.TagUTF8String:
		if !utf8.Valid(value.Bytes) {
			return nil, errors.New("invalid UTF-8 X.509 subject value")
		}
		decoded = append([]byte(nil), value.Bytes...)
	case asn1.TagPrintableString, asn1.TagIA5String, 26: // VisibleString
		decoded = append([]byte(nil), value.Bytes...)
	case 20: // T61String is converted by OpenSSL as an ISO-8859-1 byte string.
		for _, character := range value.Bytes {
			decoded = utf8.AppendRune(decoded, rune(character))
		}
	case 28: // UniversalString
		if len(value.Bytes)%4 != 0 {
			return nil, errors.New("invalid UniversalString X.509 subject value")
		}
		for offset := 0; offset < len(value.Bytes); offset += 4 {
			character := rune(binary.BigEndian.Uint32(value.Bytes[offset : offset+4]))
			if !utf8.ValidRune(character) {
				return nil, errors.New("invalid UniversalString code point")
			}
			decoded = utf8.AppendRune(decoded, character)
		}
	case 30: // BMPString
		if len(value.Bytes)%2 != 0 {
			return nil, errors.New("invalid BMPString X.509 subject value")
		}
		units := make([]uint16, len(value.Bytes)/2)
		for index := range units {
			units[index] = binary.BigEndian.Uint16(value.Bytes[index*2 : index*2+2])
		}
		for _, character := range utf16.Decode(units) {
			if character == utf8.RuneError {
				return nil, errors.New("invalid BMPString code point")
			}
			decoded = utf8.AppendRune(decoded, character)
		}
		clear(units)
	default:
		return append([]byte(nil), value.FullBytes...), nil
	}
	defer clear(decoded)
	canonical := make([]byte, 0, len(decoded))
	start := 0
	for start < len(decoded) && globalTLSOpenSSLASCIIWhitespace(decoded[start]) {
		start++
	}
	end := len(decoded)
	for end > start && globalTLSOpenSSLASCIIWhitespace(decoded[end-1]) {
		end--
	}
	for index := start; index < end; {
		character := decoded[index]
		if character < utf8.RuneSelf && globalTLSOpenSSLASCIIWhitespace(character) {
			canonical = append(canonical, ' ')
			for index < end && globalTLSOpenSSLASCIIWhitespace(decoded[index]) {
				index++
			}
			continue
		}
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		canonical = append(canonical, character)
		index++
	}
	return globalTLSDERValue(0x0c, canonical), nil
}

func globalTLSOpenSSLASCIIWhitespace(value byte) bool {
	return value == ' ' || (value >= '\t' && value <= '\r')
}

func globalTLSDERValue(tag byte, value []byte) []byte {
	result := make([]byte, 0, 1+5+len(value))
	result = append(result, tag)
	if len(value) < 128 {
		result = append(result, byte(len(value)))
	} else {
		length := uint64(len(value))
		var encoded [8]byte
		index := len(encoded)
		for length != 0 {
			index--
			encoded[index] = byte(length)
			length >>= 8
		}
		result = append(result, 0x80|byte(len(encoded)-index))
		result = append(result, encoded[index:]...)
	}
	return append(result, value...)
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

func parseGlobalTLSECName(value string) ([]tls.CurveID, error) {
	selector := strings.TrimSpace(value)
	if selector == "" {
		return nil, errors.New("curve name is empty")
	}
	if strings.ContainsAny(selector, ", \t\r\n?*+/{ }") {
		return nil, fmt.Errorf(
			"OpenSSL group selector %q cannot be mapped to a Go TLS allowed-group set",
			value,
		)
	}
	names := strings.Split(selector, ":")
	curves := make([]tls.CurveID, 0, len(names))
	seen := make(map[tls.CurveID]struct{}, len(names))
	for _, name := range names {
		if name == "" {
			return nil, errors.New("OpenSSL group list contains an empty name")
		}
		curve, minimumGoVersion, ok := globalTLSNamedGroup(name)
		if !ok {
			return nil, fmt.Errorf(
				"OpenSSL named group %q is not available in crypto/tls",
				name,
			)
		}
		if minimumGoVersion != "" &&
			version.Compare(runtime.Version(), minimumGoVersion) < 0 {
			return nil, fmt.Errorf(
				"OpenSSL named group %q requires %s or later; runtime is %s",
				name,
				minimumGoVersion,
				runtime.Version(),
			)
		}
		if disabledBy, disabled := globalTLSNamedGroupDisabledByGoDebug(curve); disabled {
			return nil, fmt.Errorf(
				"OpenSSL named group %q is disabled by GODEBUG=%s=0",
				name,
				disabledBy,
			)
		}
		if _, duplicate := seen[curve]; duplicate {
			continue
		}
		seen[curve] = struct{}{}
		curves = append(curves, curve)
	}
	return curves, nil
}

func globalTLSNamedGroup(name string) (tls.CurveID, string, bool) {
	switch strings.ToUpper(name) {
	case "X25519":
		return tls.X25519, "", true
	case "P-256", "PRIME256V1", "SECP256R1":
		return tls.CurveP256, "", true
	case "P-384", "SECP384R1":
		return tls.CurveP384, "", true
	case "P-521", "SECP521R1":
		return tls.CurveP521, "", true
	case "X25519MLKEM768":
		return tls.X25519MLKEM768, "go1.24", true
	case "SECP256R1MLKEM768":
		return tls.SecP256r1MLKEM768, "go1.26", true
	case "SECP384R1MLKEM1024":
		return tls.SecP384r1MLKEM1024, "go1.26", true
	default:
		return 0, "", false
	}
}

func globalTLSNamedGroupDisabledByGoDebug(curve tls.CurveID) (string, bool) {
	if value, configured := globalTLSGoDebugValue("tlsmlkem"); configured && value == "0" {
		switch curve {
		case tls.X25519MLKEM768,
			tls.SecP256r1MLKEM768,
			tls.SecP384r1MLKEM1024:
			return "tlsmlkem", true
		}
	}
	if value, configured := globalTLSGoDebugValue("tlssecpmlkem"); configured && value == "0" {
		switch curve {
		case tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024:
			return "tlssecpmlkem", true
		}
	}
	return "", false
}

func globalTLSGoDebugValue(name string) (string, bool) {
	settings := strings.Split(os.Getenv("GODEBUG"), ",")
	for index := len(settings) - 1; index >= 0; index-- {
		key, value, found := strings.Cut(strings.TrimSpace(settings[index]), "=")
		if found && key == name {
			return value, true
		}
	}
	return "", false
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
