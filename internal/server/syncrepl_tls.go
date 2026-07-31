package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type syncConsumerTLSMaterial struct {
	roots *x509.CertPool
	crls  []*x509.RevocationList
}

func parseSyncConsumerCipherSuites(value string) ([]uint16, error) {
	selectors := strings.FieldsFunc(value, func(character rune) bool {
		return character == ':' ||
			character == ',' ||
			character == ' ' ||
			character == '\t' ||
			character == '\r' ||
			character == '\n'
	})
	if len(selectors) == 0 {
		return nil, errors.New("tls_cipher_suite is empty")
	}
	if len(selectors) == 1 &&
		strings.EqualFold(selectors[0], "DEFAULT") {
		return nil, nil
	}

	secure := syncConsumerConfigurableCipherSuites(tls.CipherSuites())
	insecure := syncConsumerConfigurableCipherSuites(
		tls.InsecureCipherSuites(),
	)
	byName := make(map[string]uint16, len(secure)+len(insecure))
	all := make([]uint16, 0, len(secure)+len(insecure))
	for _, suite := range append(append(
		[]*tls.CipherSuite(nil),
		secure...,
	), insecure...) {
		all = append(all, suite.ID)
		for _, name := range syncConsumerCipherSuiteNames(suite.Name) {
			byName[strings.ToUpper(name)] = suite.ID
		}
	}

	var selected []uint16
	permanentlyExcluded := make(map[uint16]struct{})
	appendSuite := func(identifier uint16) {
		if _, excluded := permanentlyExcluded[identifier]; excluded {
			return
		}
		for _, existing := range selected {
			if existing == identifier {
				return
			}
		}
		selected = append(selected, identifier)
	}
	removeSuite := func(identifier uint16) {
		filtered := selected[:0]
		for _, existing := range selected {
			if existing != identifier {
				filtered = append(filtered, existing)
			}
		}
		selected = filtered
	}
	for _, rawSelector := range selectors {
		selector := rawSelector
		var operator byte
		if len(selector) > 1 {
			switch selector[0] {
			case '!', '-', '+':
				operator = selector[0]
				selector = selector[1:]
			}
		}
		upper := strings.ToUpper(selector)
		if strings.HasPrefix(upper, "@") {
			return nil, fmt.Errorf(
				"OpenSSL cipher directive %q cannot be represented by Go TLS",
				rawSelector,
			)
		}
		var identifiers []uint16
		switch upper {
		case "DEFAULT", "HIGH":
			for _, suite := range secure {
				identifiers = append(identifiers, suite.ID)
			}
		case "ALL":
			identifiers = append(identifiers, all...)
		default:
			if strings.HasPrefix(upper, "TLS_AES_") ||
				strings.HasPrefix(upper, "TLS_CHACHA20_") {
				return nil, fmt.Errorf(
					"TLS 1.3 cipher suite %q is not configurable in Go",
					selector,
				)
			}
			identifier, found := byName[upper]
			if !found {
				return nil, fmt.Errorf(
					"unknown tls_cipher_suite selector %q",
					rawSelector,
				)
			}
			identifiers = []uint16{identifier}
		}

		switch operator {
		case '!':
			for _, identifier := range identifiers {
				removeSuite(identifier)
				permanentlyExcluded[identifier] = struct{}{}
			}
		case '-':
			for _, identifier := range identifiers {
				removeSuite(identifier)
			}
		case '+':
			for _, identifier := range identifiers {
				present := false
				for _, existing := range selected {
					present = present || existing == identifier
				}
				if !present {
					continue
				}
				removeSuite(identifier)
				appendSuite(identifier)
			}
		default:
			for _, identifier := range identifiers {
				appendSuite(identifier)
			}
		}
	}
	if len(selected) == 0 {
		return nil, errors.New("tls_cipher_suite selects no supported suites")
	}
	return selected, nil
}

func syncConsumerConfigurableCipherSuites(
	suites []*tls.CipherSuite,
) []*tls.CipherSuite {
	result := make([]*tls.CipherSuite, 0, len(suites))
	for _, suite := range suites {
		for _, version := range suite.SupportedVersions {
			if version <= tls.VersionTLS12 {
				result = append(result, suite)
				break
			}
		}
	}
	return result
}

func syncConsumerCipherSuiteNames(goName string) []string {
	withoutPrefix := strings.TrimPrefix(goName, "TLS_")
	openSSL := strings.Replace(withoutPrefix, "_WITH_", "-", 1)
	openSSL = strings.ReplaceAll(openSSL, "_", "-")
	openSSL = strings.ReplaceAll(openSSL, "AES-128", "AES128")
	openSSL = strings.ReplaceAll(openSSL, "AES-256", "AES256")
	openSSL = strings.ReplaceAll(openSSL, "-CBC-", "-")
	names := []string{goName, openSSL}
	if strings.HasPrefix(openSSL, "RSA-") {
		names = append(names, strings.TrimPrefix(openSSL, "RSA-"))
	}
	return names
}

func parseSyncConsumerCurvePreferences(value string) ([]tls.CurveID, error) {
	names := strings.FieldsFunc(value, func(character rune) bool {
		return character == ':' ||
			character == ',' ||
			character == ' ' ||
			character == '\t'
	})
	if len(names) == 0 {
		return nil, errors.New("tls_ecname is empty")
	}
	curves := make([]tls.CurveID, 0, len(names))
	for _, name := range names {
		var curve tls.CurveID
		switch strings.ToLower(name) {
		case "auto":
			if len(names) != 1 {
				return nil, errors.New(
					"tls_ecname auto cannot be combined with explicit curves",
				)
			}
			return nil, nil
		case "x25519":
			curve = tls.X25519
		case "prime256v1", "secp256r1", "p-256", "p256":
			curve = tls.CurveP256
		case "secp384r1", "p-384", "p384":
			curve = tls.CurveP384
		case "secp521r1", "p-521", "p521":
			curve = tls.CurveP521
		default:
			return nil, fmt.Errorf("unknown tls_ecname curve %q", name)
		}
		duplicate := false
		for _, existing := range curves {
			duplicate = duplicate || existing == curve
		}
		if !duplicate {
			curves = append(curves, curve)
		}
	}
	return curves, nil
}

func loadSyncConsumerTLSMaterial(
	config syncConsumerTLSConfig,
) (syncConsumerTLSMaterial, error) {
	var roots *x509.CertPool
	if config.caCertificate == "" && config.caDirectory == "" {
		systemRoots, err := x509.SystemCertPool()
		if err == nil {
			roots = systemRoots
		}
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}
	material := syncConsumerTLSMaterial{roots: roots}
	if config.caCertificate != "" {
		certificates, crls, err := readSyncConsumerTrustFile(
			config.caCertificate,
		)
		if err != nil {
			return syncConsumerTLSMaterial{}, err
		}
		if len(certificates) == 0 {
			return syncConsumerTLSMaterial{}, fmt.Errorf(
				"TLS CA file %q contains no certificates",
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
		return syncConsumerTLSMaterial{}, fmt.Errorf(
			"read TLS CA directory: %w",
			err,
		)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(config.caDirectory, entry.Name())
		certificates, crls, err := readSyncConsumerTrustFile(path)
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

func readSyncConsumerTrustFile(
	path string,
) ([]*x509.Certificate, []*x509.RevocationList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read TLS trust file %q: %w", path, err)
	}
	var (
		certificates []*x509.Certificate
		crls         []*x509.RevocationList
	)
	for len(data) > 0 {
		block, remaining := pem.Decode(data)
		if block == nil {
			break
		}
		data = remaining
		switch block.Type {
		case "CERTIFICATE":
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf(
					"parse TLS certificate in %q: %w",
					path,
					err,
				)
			}
			certificates = append(certificates, certificate)
		case "X509 CRL", "CRL":
			crl, err := x509.ParseRevocationList(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf(
					"parse TLS CRL in %q: %w",
					path,
					err,
				)
			}
			crls = append(crls, crl)
		}
	}
	if len(certificates) == 0 && len(crls) == 0 {
		return nil, nil, fmt.Errorf(
			"TLS trust file %q contains no certificates or CRLs",
			path,
		)
	}
	return certificates, crls, nil
}

func configureSyncConsumerTLSVerification(
	tlsConfig *tls.Config,
	config syncConsumerTLSConfig,
	crls []*x509.RevocationList,
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
		tlsConfig.InsecureSkipVerify = true
		return nil
	case "try", "demand", "hard":
	default:
		return fmt.Errorf("unknown tls_reqcert policy %q", requireCert)
	}

	tlsConfig.InsecureSkipVerify = true
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			if requireCert == "try" {
				return nil
			}
			return errors.New("TLS peer provided no certificate")
		}
		leaf := state.PeerCertificates[0]
		intermediates := x509.NewCertPool()
		for _, certificate := range state.PeerCertificates[1:] {
			intermediates.AddCert(certificate)
		}
		chains, err := leaf.Verify(x509.VerifyOptions{
			Roots:         tlsConfig.RootCAs,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			return fmt.Errorf("verify TLS peer certificate: %w", err)
		}
		if err := verifySyncConsumerTLSHostname(
			leaf,
			tlsConfig.ServerName,
			requireSAN,
		); err != nil {
			return err
		}
		if config.crlCheck == "" || config.crlCheck == "none" {
			return nil
		}
		var lastErr error
		for _, chain := range chains {
			if err := verifySyncConsumerTLSCRLs(
				chain,
				crls,
				config.crlCheck,
				time.Now(),
			); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
		return lastErr
	}
	return nil
}

func verifySyncConsumerTLSHostname(
	certificate *x509.Certificate,
	host,
	requireSAN string,
) error {
	if host == "" {
		return nil
	}
	sanPresent := syncConsumerCertificateHasSAN(certificate)
	sanErr := certificate.VerifyHostname(host)
	switch requireSAN {
	case "never":
		return verifySyncConsumerTLSCommonName(certificate, host)
	case "allow":
		if sanErr == nil {
			return nil
		}
		return verifySyncConsumerTLSCommonName(certificate, host)
	case "try":
		if sanPresent {
			if sanErr != nil {
				return fmt.Errorf(
					"TLS hostname %q does not match subjectAltName: %w",
					host,
					sanErr,
				)
			}
			return nil
		}
		return verifySyncConsumerTLSCommonName(certificate, host)
	case "demand", "hard":
		if !sanPresent {
			return errors.New("TLS peer certificate has no subjectAltName")
		}
		if sanErr != nil {
			return fmt.Errorf(
				"TLS hostname %q does not match subjectAltName: %w",
				host,
				sanErr,
			)
		}
		return nil
	default:
		return fmt.Errorf("unknown tls_reqsan policy %q", requireSAN)
	}
}

func syncConsumerCertificateHasSAN(certificate *x509.Certificate) bool {
	for _, extension := range certificate.Extensions {
		if extension.Id.String() == "2.5.29.17" {
			return true
		}
	}
	return false
}

func verifySyncConsumerTLSCommonName(
	certificate *x509.Certificate,
	host string,
) error {
	commonName := certificate.Subject.CommonName
	if commonName == "" {
		return errors.New("TLS peer certificate has no common name")
	}
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
		"TLS hostname %q does not match common name %q",
		host,
		commonName,
	)
}

func verifySyncConsumerTLSCRLs(
	chain []*x509.Certificate,
	crls []*x509.RevocationList,
	policy string,
	now time.Time,
) error {
	if len(chain) < 2 {
		return errors.New("TLS verified chain has no issuer")
	}
	checkCount := 1
	if policy == "all" {
		checkCount = len(chain) - 1
	}
	if checkCount <= 0 {
		return errors.New("TLS verified chain has no issuer")
	}
	for index := 0; index < checkCount; index++ {
		certificate := chain[index]
		issuer := chain[index+1]
		var applicable []*x509.RevocationList
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
				"no valid CRL is available for TLS certificate %s",
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
						"TLS certificate %s is revoked",
						certificate.Subject.String(),
					)
				}
			}
		}
	}
	return nil
}
