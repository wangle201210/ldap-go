package server

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
	"github.com/go-ldap/ldap/v3"
)

type syncConsumerTLCPMaterial struct {
	roots *smx509.CertPool
	crls  []*smx509.RevocationList
}

func dialSyncConsumerTLCP(
	ctx context.Context,
	config syncConsumerConfig,
	provider *url.URL,
) (*ldap.Conn, error) {
	tlcpConfig, err := buildSyncConsumerTLCPConfig(config, provider)
	if err != nil {
		return nil, err
	}
	timeout := config.networkTimeout
	if timeout <= 0 {
		timeout = ldap.DefaultTimeout
	}
	dialer := &net.Dialer{Timeout: timeout}
	if err := configureSyncConsumerDialer(dialer, config); err != nil {
		return nil, err
	}
	port := provider.Port()
	if port == "" {
		port = ldap.DefaultLdapsPort
	}
	address := net.JoinHostPort(provider.Hostname(), port)
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", provider.String(), err)
	}
	secured := tlcp.Client(raw, tlcpConfig)
	handshakeContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := secured.HandshakeContext(handshakeContext); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("TLCP handshake with %s: %w", provider.String(), err)
	}
	connection := ldap.NewConn(secured, true)
	connection.Start()
	return connection, nil
}

func buildSyncConsumerTLCPConfig(
	config syncConsumerConfig,
	provider *url.URL,
) (*tlcp.Config, error) {
	if config.tls.protocolMinimum != "" {
		switch strings.ToLower(config.tls.protocolMinimum) {
		case "tlcp", "1.1":
		default:
			return nil, fmt.Errorf(
				"tls_protocol_min %q is not a TLCP version",
				config.tls.protocolMinimum,
			)
		}
	}
	tlcpConfig := &tlcp.Config{
		ServerName: provider.Hostname(),
	}
	if config.tls.cipherSuite != "" {
		cipherSuites, err := parseSyncConsumerTLCPCipherSuites(
			config.tls.cipherSuite,
		)
		if err != nil {
			return nil, err
		}
		tlcpConfig.CipherSuites = cipherSuites
	}
	if config.tls.ecName != "" {
		switch strings.ToLower(config.tls.ecName) {
		case "auto":
		case "sm2", "sm2p256v1":
			tlcpConfig.CurvePreferences = []tlcp.CurveID{tlcp.CurveSM2}
		default:
			return nil, fmt.Errorf(
				"tls_ecname %q is not supported by TLCP",
				config.tls.ecName,
			)
		}
	}
	if config.tls.certificateFile != "" || config.tls.keyFile != "" {
		if config.tls.certificateFile == "" || config.tls.keyFile == "" {
			return nil, errors.New(
				"tls_cert and tls_key must be configured together",
			)
		}
		certificate, err := tlcp.LoadX509KeyPair(
			config.tls.certificateFile,
			config.tls.keyFile,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"load syncrepl TLCP client certificate: %w",
				err,
			)
		}
		tlcpConfig.Certificates = []tlcp.Certificate{certificate}
	}
	if config.tls.tlcpEncryptionCertificate != "" ||
		config.tls.tlcpEncryptionKey != "" {
		if config.tls.tlcpEncryptionCertificate == "" ||
			config.tls.tlcpEncryptionKey == "" {
			return nil, errors.New(
				"tlcp_enc_cert and tlcp_enc_key must be configured together",
			)
		}
		if len(tlcpConfig.Certificates) == 0 {
			return nil, errors.New(
				"TLCP client encryption certificate requires tls_cert and tls_key",
			)
		}
		certificate, err := tlcp.LoadX509KeyPair(
			config.tls.tlcpEncryptionCertificate,
			config.tls.tlcpEncryptionKey,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"load syncrepl TLCP client encryption certificate: %w",
				err,
			)
		}
		tlcpConfig.Certificates = append(
			tlcpConfig.Certificates,
			certificate,
		)
	}
	if syncConsumerTLCPCipherSuitesRequireClientEncryption(
		tlcpConfig.CipherSuites,
	) && len(tlcpConfig.Certificates) < 2 {
		return nil, errors.New(
			"TLCP ECDHE suites require client signing and encryption certificates",
		)
	}
	if len(tlcpConfig.CipherSuites) == 0 &&
		len(tlcpConfig.Certificates) < 2 {
		tlcpConfig.CipherSuites = []uint16{
			tlcp.ECC_SM4_GCM_SM3,
			tlcp.ECC_SM4_CBC_SM3,
		}
	}
	material, err := loadSyncConsumerTLCPMaterial(config.tls)
	if err != nil {
		return nil, err
	}
	tlcpConfig.RootCAs = material.roots
	if err := configureSyncConsumerTLCPVerification(
		tlcpConfig,
		config.tls,
		material.crls,
	); err != nil {
		return nil, err
	}
	return tlcpConfig, nil
}

func parseSyncConsumerTLCPCipherSuites(value string) ([]uint16, error) {
	selectors := strings.FieldsFunc(value, func(character rune) bool {
		return character == ':' ||
			character == ',' ||
			character == ' ' ||
			character == '\t'
	})
	if len(selectors) == 0 {
		return nil, errors.New("tls_cipher_suite is empty")
	}
	if len(selectors) == 1 {
		switch strings.ToUpper(selectors[0]) {
		case "DEFAULT", "HIGH", "ALL":
			return nil, nil
		}
	}
	available := map[string]uint16{
		"ECC_SM4_GCM_SM3":   tlcp.ECC_SM4_GCM_SM3,
		"ECC_SM4_CBC_SM3":   tlcp.ECC_SM4_CBC_SM3,
		"ECDHE_SM4_GCM_SM3": tlcp.ECDHE_SM4_GCM_SM3,
		"ECDHE_SM4_CBC_SM3": tlcp.ECDHE_SM4_CBC_SM3,
	}
	all := []uint16{
		tlcp.ECC_SM4_GCM_SM3,
		tlcp.ECC_SM4_CBC_SM3,
		tlcp.ECDHE_SM4_GCM_SM3,
		tlcp.ECDHE_SM4_CBC_SM3,
	}
	var selected []uint16
	permanentlyExcluded := make(map[uint16]struct{})
	appendSuite := func(identifier uint16) {
		if _, excluded := permanentlyExcluded[identifier]; excluded {
			return
		}
		if !containsSyncConsumerCipherSuite(selected, identifier) {
			selected = append(selected, identifier)
		}
	}
	for _, rawSelector := range selectors {
		permanent := strings.HasPrefix(rawSelector, "!")
		exclude := permanent || strings.HasPrefix(rawSelector, "-")
		selector := strings.TrimLeft(rawSelector, "!-+")
		normalized := strings.ToUpper(strings.ReplaceAll(selector, "-", "_"))
		normalized = strings.TrimPrefix(normalized, "TLCP_")
		var identifiers []uint16
		switch normalized {
		case "DEFAULT", "HIGH", "ALL":
			identifiers = all
		default:
			identifier, found := available[normalized]
			if !found {
				return nil, fmt.Errorf(
					"unknown TLCP cipher suite selector %q",
					rawSelector,
				)
			}
			identifiers = []uint16{identifier}
		}
		for _, identifier := range identifiers {
			if exclude {
				selected = removeSyncConsumerCipherSuite(
					selected,
					identifier,
				)
				if permanent {
					permanentlyExcluded[identifier] = struct{}{}
				}
				continue
			}
			if strings.HasPrefix(rawSelector, "+") &&
				!containsSyncConsumerCipherSuite(selected, identifier) {
				continue
			}
			if strings.HasPrefix(rawSelector, "+") {
				selected = removeSyncConsumerCipherSuite(selected, identifier)
			}
			appendSuite(identifier)
		}
	}
	if len(selected) == 0 {
		return nil, errors.New("tls_cipher_suite selects no TLCP suites")
	}
	return selected, nil
}

func syncConsumerTLCPCipherSuitesRequireClientEncryption(
	suites []uint16,
) bool {
	for _, suite := range suites {
		if suite == tlcp.ECDHE_SM4_GCM_SM3 ||
			suite == tlcp.ECDHE_SM4_CBC_SM3 {
			return true
		}
	}
	return false
}

func containsSyncConsumerCipherSuite(
	suites []uint16,
	identifier uint16,
) bool {
	for _, suite := range suites {
		if suite == identifier {
			return true
		}
	}
	return false
}

func removeSyncConsumerCipherSuite(
	suites []uint16,
	identifier uint16,
) []uint16 {
	result := suites[:0]
	for _, suite := range suites {
		if suite != identifier {
			result = append(result, suite)
		}
	}
	return result
}

func loadSyncConsumerTLCPMaterial(
	config syncConsumerTLSConfig,
) (syncConsumerTLCPMaterial, error) {
	var roots *smx509.CertPool
	if config.caCertificate == "" && config.caDirectory == "" {
		systemRoots, err := smx509.SystemCertPool()
		if err == nil {
			roots = systemRoots
		}
	}
	if roots == nil {
		roots = smx509.NewCertPool()
	}
	material := syncConsumerTLCPMaterial{roots: roots}
	if config.caCertificate != "" {
		certificates, crls, err := readSyncConsumerTLCPTrustFile(
			config.caCertificate,
		)
		if err != nil {
			return syncConsumerTLCPMaterial{}, err
		}
		if len(certificates) == 0 {
			return syncConsumerTLCPMaterial{}, fmt.Errorf(
				"TLCP CA file %q contains no certificates",
				config.caCertificate,
			)
		}
		for _, certificate := range certificates {
			material.roots.AddCert(certificate)
		}
		material.crls = append(material.crls, crls...)
	}
	if config.caDirectory == "" {
		return material, nil
	}
	entries, err := os.ReadDir(config.caDirectory)
	if err != nil {
		return syncConsumerTLCPMaterial{}, fmt.Errorf(
			"read TLCP CA directory: %w",
			err,
		)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(config.caDirectory, entry.Name())
		certificates, crls, err := readSyncConsumerTLCPTrustFile(path)
		if err != nil {
			continue
		}
		for _, certificate := range certificates {
			material.roots.AddCert(certificate)
		}
		material.crls = append(material.crls, crls...)
	}
	return material, nil
}

func readSyncConsumerTLCPTrustFile(
	path string,
) ([]*smx509.Certificate, []*smx509.RevocationList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read TLCP trust file %q: %w", path, err)
	}
	var (
		certificates []*smx509.Certificate
		crls         []*smx509.RevocationList
	)
	remaining := data
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		switch block.Type {
		case "CERTIFICATE":
			certificate, err := smx509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf(
					"parse TLCP certificate in %q: %w",
					path,
					err,
				)
			}
			certificates = append(certificates, certificate)
		case "X509 CRL", "CRL":
			crl, err := smx509.ParseRevocationList(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf(
					"parse TLCP CRL in %q: %w",
					path,
					err,
				)
			}
			crls = append(crls, crl)
		}
	}
	if len(certificates) == 0 && len(crls) == 0 {
		return nil, nil, fmt.Errorf(
			"TLCP trust file %q contains no certificates or CRLs",
			path,
		)
	}
	return certificates, crls, nil
}

func configureSyncConsumerTLCPVerification(
	tlcpConfig *tlcp.Config,
	config syncConsumerTLSConfig,
	crls []*smx509.RevocationList,
) error {
	requireCert := config.requireCert
	if requireCert == "" {
		requireCert = "demand"
	}
	requireSAN := config.requireSAN
	if requireSAN == "" {
		requireSAN = "allow"
	}
	switch requireCert {
	case "never", "allow":
		tlcpConfig.InsecureSkipVerify = true
		return nil
	case "try", "demand", "hard":
	default:
		return fmt.Errorf("unknown tls_reqcert policy %q", requireCert)
	}

	tlcpConfig.InsecureSkipVerify = true
	tlcpConfig.VerifyConnection = func(state tlcp.ConnectionState) error {
		if len(state.PeerCertificates) < 2 {
			if requireCert == "try" {
				return nil
			}
			return errors.New(
				"TLCP peer did not provide signing and encryption certificates",
			)
		}
		var leafChains [][][]*smx509.Certificate
		for index, certificate := range state.PeerCertificates[:2] {
			intermediates := smx509.NewCertPool()
			for _, intermediate := range state.PeerCertificates[2:] {
				intermediates.AddCert(intermediate)
			}
			chains, err := certificate.Verify(smx509.VerifyOptions{
				Roots:         tlcpConfig.RootCAs,
				Intermediates: intermediates,
				KeyUsages: []smx509.ExtKeyUsage{
					smx509.ExtKeyUsageServerAuth,
				},
			})
			if err != nil {
				return fmt.Errorf(
					"verify TLCP peer certificate %d: %w",
					index,
					err,
				)
			}
			leafChains = append(leafChains, chains)
		}
		if err := verifySyncConsumerTLCPHostname(
			state.PeerCertificates[0],
			tlcpConfig.ServerName,
			requireSAN,
		); err != nil {
			return err
		}
		if config.crlCheck == "" || config.crlCheck == "none" {
			return nil
		}
		for leafIndex, chains := range leafChains {
			var lastErr error
			valid := false
			for _, chain := range chains {
				if err := verifySyncConsumerTLCPCRLs(
					chain,
					crls,
					config.crlCheck,
					time.Now(),
				); err == nil {
					valid = true
					break
				} else {
					lastErr = err
				}
			}
			if !valid {
				return fmt.Errorf(
					"verify TLCP certificate %d revocation: %w",
					leafIndex,
					lastErr,
				)
			}
		}
		return nil
	}
	return nil
}

func verifySyncConsumerTLCPHostname(
	certificate *smx509.Certificate,
	host,
	requireSAN string,
) error {
	if host == "" {
		return nil
	}
	sanPresent := false
	for _, extension := range certificate.Extensions {
		if extension.Id.String() == "2.5.29.17" {
			sanPresent = true
			break
		}
	}
	sanErr := certificate.VerifyHostname(host)
	switch requireSAN {
	case "never":
		return verifySyncConsumerTLCPCommonName(certificate, host)
	case "allow":
		if sanErr == nil {
			return nil
		}
		return verifySyncConsumerTLCPCommonName(certificate, host)
	case "try":
		if sanPresent {
			if sanErr != nil {
				return fmt.Errorf(
					"TLCP hostname %q does not match subjectAltName: %w",
					host,
					sanErr,
				)
			}
			return nil
		}
		return verifySyncConsumerTLCPCommonName(certificate, host)
	case "demand", "hard":
		if !sanPresent {
			return errors.New("TLCP peer certificate has no subjectAltName")
		}
		if sanErr != nil {
			return fmt.Errorf(
				"TLCP hostname %q does not match subjectAltName: %w",
				host,
				sanErr,
			)
		}
		return nil
	default:
		return fmt.Errorf("unknown tls_reqsan policy %q", requireSAN)
	}
}

func verifySyncConsumerTLCPCommonName(
	certificate *smx509.Certificate,
	host string,
) error {
	commonName := certificate.Subject.CommonName
	if strings.EqualFold(commonName, host) {
		return nil
	}
	if strings.HasPrefix(commonName, "*.") {
		dot := strings.IndexByte(host, '.')
		if dot > 0 && strings.EqualFold(commonName[1:], host[dot:]) {
			return nil
		}
	}
	return fmt.Errorf(
		"TLCP hostname %q does not match common name %q",
		host,
		commonName,
	)
}

func verifySyncConsumerTLCPCRLs(
	chain []*smx509.Certificate,
	crls []*smx509.RevocationList,
	policy string,
	now time.Time,
) error {
	if len(chain) < 2 {
		return errors.New("TLCP verified chain has no issuer")
	}
	checkCount := 1
	if policy == "all" {
		checkCount = len(chain) - 1
	}
	for index := 0; index < checkCount; index++ {
		certificate := chain[index]
		issuer := chain[index+1]
		var applicable []*smx509.RevocationList
		for _, crl := range crls {
			if !bytes.Equal(crl.RawIssuer, certificate.RawIssuer) {
				continue
			}
			if err := crl.CheckSignatureFrom(issuer); err != nil {
				continue
			}
			if now.Before(crl.ThisUpdate) ||
				(!crl.NextUpdate.IsZero() && now.After(crl.NextUpdate)) {
				continue
			}
			applicable = append(applicable, crl)
		}
		if len(applicable) == 0 {
			return fmt.Errorf(
				"no valid CRL is available for TLCP certificate %s",
				certificate.Subject.String(),
			)
		}
		for _, crl := range applicable {
			for _, revoked := range crl.RevokedCertificateEntries {
				if revoked.ReasonCode == 8 ||
					revoked.RevocationTime.After(now) {
					continue
				}
				if certificate.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
					return fmt.Errorf(
						"TLCP certificate %s is revoked",
						certificate.Subject.String(),
					)
				}
			}
		}
	}
	return nil
}
