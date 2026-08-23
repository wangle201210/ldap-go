package lloadd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type RuntimeOption func(*RuntimeConfig) error

func WithLogger(logger *slog.Logger) RuntimeOption {
	return func(config *RuntimeConfig) error {
		config.Logger = logger
		return nil
	}
}

func WithDialContext(dial DialContextFunc) RuntimeOption {
	return func(config *RuntimeConfig) error {
		if dial == nil {
			return errors.New("lloadd dial function is nil")
		}
		config.DialContext = dial
		return nil
	}
}

func WithBackendTLS(config *tls.Config) RuntimeOption {
	return func(runtime *RuntimeConfig) error {
		if config == nil {
			return errors.New("lloadd backend TLS configuration is nil")
		}
		runtime.BackendTLS = config.Clone()
		return nil
	}
}

func New(config Config, options ...RuntimeOption) (*Proxy, error) {
	runtime, err := config.RuntimeConfig()
	if err != nil {
		return nil, err
	}
	for index, option := range options {
		if option == nil {
			return nil, fmt.Errorf("lloadd runtime option %d is nil", index)
		}
		if err := option(&runtime); err != nil {
			return nil, err
		}
	}
	return NewProxy(runtime)
}

func (config Config) RuntimeConfig() (RuntimeConfig, error) {
	if err := config.Validate(); err != nil {
		return RuntimeConfig{}, err
	}
	for _, feature := range config.Features {
		switch feature {
		case FeatureProxyAuthz:
		case FeatureVerifyCredentials, FeatureReadPause:
		}
	}
	runtime := RuntimeConfig{
		ClientMaxMessageSize:   int64(config.MaxIncomingClient),
		UpstreamMaxMessageSize: int64(config.MaxIncomingUpstream),
		ClientMaxPending:       config.ClientMaxPending,
		WriteCoherence:         config.WriteCoherence,
		NetworkTimeout:         config.NetworkTimeout,
		IOTimeout:              config.IOTimeout,
		ClientIdleTimeout:      config.IdleTimeout,
		ProxyAuthz:             config.ProxyAuthz,
		VerifyCredentials:      config.HasFeature(FeatureVerifyCredentials),
		ReadPause:              config.HasFeature(FeatureReadPause),
		MonitorAccess:          append([]string(nil), config.Access...),
		UpstreamTCPUserTimeout: config.BindConf.TCPUserTimeout,
		RestrictExtended:       make(map[string]RuntimeRestriction),
		RestrictControls:       make(map[string]RuntimeRestriction),
		Bind: RuntimeBindConfig{
			Method:             string(config.BindConf.Method),
			DN:                 config.BindConf.BindDN,
			Credentials:        []byte(config.BindConf.Credentials),
			SASLMechanism:      config.BindConf.SASLMechanism,
			AuthenticationID:   config.BindConf.AuthCID,
			AuthorizationID:    config.BindConf.AuthZID,
			Realm:              config.BindConf.Realm,
			SecurityProperties: config.BindConf.SecurityProperties,
			Timeout:            config.BindConf.Timeout,
		},
	}
	if runtime.VerifyCredentials && !runtime.ProxyAuthz {
		return RuntimeConfig{}, errors.New("lloadd feature \"vc\" requires feature \"proxyauthz\"")
	}
	if config.BindConf.KeepAlive.Set {
		idle, err := runtimeKeepAliveDuration(config.BindConf.KeepAlive.Idle)
		if err != nil {
			return RuntimeConfig{}, fmt.Errorf("lloadd upstream keepalive idle: %w", err)
		}
		interval, err := runtimeKeepAliveDuration(config.BindConf.KeepAlive.Interval)
		if err != nil {
			return RuntimeConfig{}, fmt.Errorf("lloadd upstream keepalive interval: %w", err)
		}
		runtime.UpstreamKeepAliveSet = true
		runtime.UpstreamKeepAlive = net.KeepAliveConfig{
			Enable:   true,
			Idle:     idle,
			Interval: interval,
			Count:    runtimeKeepAliveCount(config.BindConf.KeepAlive.Probes),
		}
	}
	usesBackendTLS := config.BindConf.TLS != (BindTLSConfig{})
	if config.BindConf.Method == BindNone {
		runtime.Bind.Method = ""
	}
	normalizedBind, err := normalizeRuntimeServiceBind(runtime.Bind)
	if err != nil {
		return RuntimeConfig{}, err
	}
	runtime.Bind = normalizedBind
	switch normalizedBind.Method {
	case "simple":
		runtime.PrivilegedIdentity = "dn:" + normalizedBind.DN
	case "sasl":
		runtime.PrivilegedIdentity = normalizedBind.AuthorizationID
	}
	for _, restriction := range config.Restrictions {
		converted, err := runtimeRestriction(restriction.Action)
		if err != nil {
			return RuntimeConfig{}, err
		}
		switch restriction.Kind {
		case RestrictionExtendedOperation:
			runtime.RestrictExtended[restriction.OID] = converted
		case RestrictionControl:
			runtime.RestrictControls[restriction.OID] = converted
		}
	}
	for _, tier := range config.Tiers {
		runtimeTier := RuntimeTierConfig{Strategy: string(tier.Policy)}
		for _, backend := range tier.Backends {
			startTLS := backend.StartTLS == StartTLSOptional || backend.StartTLS == StartTLSCritical
			usesBackendTLS = usesBackendTLS || startTLS || backend.StartTLS == StartTLSImplicit
			runtimeTier.Backends = append(runtimeTier.Backends, RuntimeBackendConfig{
				URI:                  backend.URI,
				RegularConnections:   backend.NumConns,
				BindConnections:      backend.BindConns,
				Retry:                backend.Retry,
				MaxPendingOperations: backend.MaxPendingOps,
				ConnectionMaxPending: backend.ConnMaxPending,
				Weight:               backend.Weight,
				StartTLS:             startTLS,
				StartTLSCritical:     backend.StartTLS == StartTLSCritical,
			})
		}
		runtime.Tiers = append(runtime.Tiers, runtimeTier)
	}
	if usesBackendTLS {
		backendTLS, err := buildBackendTLSConfig(config.BindConf.TLS)
		if err != nil {
			return RuntimeConfig{}, fmt.Errorf("lloadd upstream TLS: %w", err)
		}
		runtime.BackendTLS = backendTLS
	}
	if len(runtime.RestrictExtended) == 0 {
		runtime.RestrictExtended = nil
	}
	if len(runtime.RestrictControls) == 0 {
		runtime.RestrictControls = nil
	}
	return runtime, nil
}

func runtimeKeepAliveDuration(seconds int) (time.Duration, error) {
	if seconds == 0 {
		return -1, nil
	}
	maximum := int64(^uint64(0)>>1) / int64(time.Second)
	if uint64(seconds) > uint64(maximum) {
		return 0, errors.New("value exceeds time.Duration")
	}
	return time.Duration(seconds) * time.Second, nil
}

func runtimeKeepAliveCount(count int) int {
	if count == 0 {
		return -1
	}
	return count
}

func buildBackendTLSConfig(config BindTLSConfig) (*tls.Config, error) {
	if (config.CertificateFile == "") != (config.KeyFile == "") {
		return nil, errors.New("tls_cert and tls_key must be configured together")
	}

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	var trustCertificates []*x509.Certificate
	var revocationLists []*x509.RevocationList
	if config.CACertificate != "" {
		certificates, lists, err := appendRootCertificateFile(roots, config.CACertificate)
		if err != nil {
			return nil, fmt.Errorf("tls_cacert: %w", err)
		}
		trustCertificates = append(trustCertificates, certificates...)
		revocationLists = append(revocationLists, lists...)
	}
	if config.CACertificateDir != "" {
		certificates, lists, err := appendRootCertificateDirectory(roots, config.CACertificateDir)
		if err != nil {
			return nil, fmt.Errorf("tls_cacertdir: %w", err)
		}
		trustCertificates = append(trustCertificates, certificates...)
		revocationLists = append(revocationLists, lists...)
	}

	result := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	}
	if config.CertificateFile != "" {
		certificate, err := tls.LoadX509KeyPair(config.CertificateFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load tls_cert/tls_key: %w", err)
		}
		result.Certificates = []tls.Certificate{certificate}
	}
	if config.ProtocolMin != "" {
		minimum, err := backendTLSMinimumVersion(config.ProtocolMin)
		if err != nil {
			return nil, err
		}
		result.MinVersion = minimum
	}
	if config.CipherSuite != "" {
		cipherSuites, err := backendTLSCipherSuites(config.CipherSuite)
		if err != nil {
			return nil, err
		}
		result.CipherSuites = cipherSuites
	}
	if config.ECName != "" {
		curve, err := backendTLSCurve(config.ECName)
		if err != nil {
			return nil, err
		}
		result.CurvePreferences = []tls.CurveID{curve}
	}
	crlCheck := strings.ToLower(strings.TrimSpace(config.CRLCheck))
	if crlCheck == "" {
		crlCheck = "none"
	}
	if crlCheck != "none" && crlCheck != "peer" && crlCheck != "all" {
		return nil, fmt.Errorf("unsupported tls_crlcheck policy %q", config.CRLCheck)
	}
	if crlCheck != "none" && len(revocationLists) == 0 {
		return nil, fmt.Errorf(
			"tls_crlcheck=%s requires a PEM CRL in tls_cacert or tls_cacertdir",
			crlCheck,
		)
	}

	requireCert := strings.ToLower(strings.TrimSpace(config.RequireCert))
	if requireCert == "" {
		requireCert = "demand"
	}
	requireSAN := strings.ToLower(strings.TrimSpace(config.RequireSAN))
	if requireSAN == "" {
		requireSAN = "allow"
	}
	switch requireCert {
	case "never", "allow", "try", "demand", "hard", "true":
	default:
		return nil, fmt.Errorf("unsupported tls_reqcert policy %q", config.RequireCert)
	}
	switch requireSAN {
	case "never", "allow", "try", "demand", "hard":
	default:
		return nil, fmt.Errorf("unsupported tls_reqsan policy %q", config.RequireSAN)
	}

	// Verification is performed here so OpenLDAP's reqcert/reqsan split can be
	// represented without silently weakening certificate-chain validation.
	result.InsecureSkipVerify = true //nolint:gosec -- VerifyConnection below is authoritative.
	result.VerifyConnection = func(state tls.ConnectionState) error {
		return verifyBackendTLSConnection(
			state,
			roots,
			trustCertificates,
			revocationLists,
			requireCert,
			requireSAN,
			crlCheck,
		)
	}
	return result, nil
}

func appendRootCertificateFile(
	pool *x509.CertPool,
	path string,
) ([]*x509.Certificate, []*x509.RevocationList, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	certificates, revocationLists, err := appendBackendTLSTrustPEM(pool, contents)
	if err != nil {
		return nil, nil, err
	}
	if len(certificates) == 0 {
		return nil, nil, errors.New("file contains no PEM certificates")
	}
	return certificates, revocationLists, nil
}

func appendRootCertificateDirectory(
	pool *x509.CertPool,
	path string,
) ([]*x509.Certificate, []*x509.RevocationList, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, nil, err
	}
	var certificates []*x509.Certificate
	var revocationLists []*x509.RevocationList
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			return nil, nil, err
		}
		fileCertificates, fileLists, err := appendBackendTLSTrustPEM(pool, contents)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		certificates = append(certificates, fileCertificates...)
		revocationLists = append(revocationLists, fileLists...)
	}
	if len(certificates) == 0 {
		return nil, nil, errors.New("directory contains no PEM certificates")
	}
	return certificates, revocationLists, nil
}

func appendBackendTLSTrustPEM(
	pool *x509.CertPool,
	contents []byte,
) ([]*x509.Certificate, []*x509.RevocationList, error) {
	var certificates []*x509.Certificate
	var revocationLists []*x509.RevocationList
	for len(contents) != 0 {
		block, rest := pem.Decode(contents)
		if block == nil {
			break
		}
		contents = rest
		switch block.Type {
		case "CERTIFICATE":
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parse certificate: %w", err)
			}
			pool.AddCert(certificate)
			certificates = append(certificates, certificate)
		case "X509 CRL", "CRL":
			list, err := x509.ParseRevocationList(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parse CRL: %w", err)
			}
			revocationLists = append(revocationLists, list)
		}
	}
	return certificates, revocationLists, nil
}

func backendTLSMinimumVersion(value string) (uint16, error) {
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
		return 0, fmt.Errorf("tls_protocol_min %q is not supported by Go TLS", value)
	}
}

func backendTLSCurve(value string) (tls.CurveID, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "x25519":
		return tls.X25519, nil
	case "p-256", "p256", "prime256v1", "secp256r1":
		return tls.CurveP256, nil
	case "p-384", "p384", "secp384r1":
		return tls.CurveP384, nil
	case "p-521", "p521", "secp521r1":
		return tls.CurveP521, nil
	default:
		return 0, fmt.Errorf("tls_ecname %q is not supported by Go TLS", value)
	}
}

func backendTLSCipherSuites(value string) ([]uint16, error) {
	normalized := strings.TrimSpace(value)
	if strings.EqualFold(normalized, "default") || strings.EqualFold(normalized, "high") ||
		strings.EqualFold(normalized, "high:!anull") {
		return nil, nil
	}

	byName := make(map[string]uint16)
	for _, suite := range tls.CipherSuites() {
		byName[strings.ToUpper(suite.Name)] = suite.ID
	}
	aliases := map[string]string{
		"ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"ECDHE-RSA-AES128-GCM-SHA256":   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"ECDHE-RSA-AES256-GCM-SHA384":   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		"ECDHE-RSA-CHACHA20-POLY1305":   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	}
	for alias, name := range aliases {
		if id, ok := byName[name]; ok {
			byName[alias] = id
		}
	}

	var result []uint16
	seen := make(map[uint16]struct{})
	for _, name := range strings.FieldsFunc(normalized, func(r rune) bool {
		return r == ':' || r == ',' || r == ' ' || r == '\t'
	}) {
		id, ok := byName[strings.ToUpper(name)]
		if !ok {
			return nil, fmt.Errorf("tls_cipher_suite contains unsupported value %q", name)
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	if len(result) == 0 {
		return nil, errors.New("tls_cipher_suite contains no usable cipher suites")
	}
	return result, nil
}

func verifyBackendTLSConnection(
	state tls.ConnectionState,
	roots *x509.CertPool,
	trustCertificates []*x509.Certificate,
	revocationLists []*x509.RevocationList,
	requireCert string,
	requireSAN string,
	crlCheck string,
) error {
	if requireCert == "never" || requireCert == "allow" {
		return nil
	}
	if len(state.PeerCertificates) == 0 {
		return errors.New("upstream TLS peer did not provide a certificate")
	}
	leaf := state.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("verify upstream TLS certificate chain: %w", err)
	}
	if crlCheck != "none" {
		var revocationErr error
		for _, chain := range chains {
			if err := verifyBackendTLSRevocation(
				chain,
				trustCertificates,
				revocationLists,
				crlCheck,
				time.Now(),
			); err == nil {
				revocationErr = nil
				break
			} else {
				revocationErr = err
			}
		}
		if revocationErr != nil {
			return revocationErr
		}
	}
	if state.ServerName == "" {
		return errors.New("upstream TLS server name is empty")
	}

	hasSAN := backendTLSCertificateHasSAN(leaf)
	if requireSAN != "never" {
		if err := leaf.VerifyHostname(state.ServerName); err == nil {
			return nil
		} else if (requireSAN == "try" && hasSAN) ||
			requireSAN == "demand" || requireSAN == "hard" {
			return fmt.Errorf("verify upstream TLS subjectAltName: %w", err)
		}
	}
	if !matchBackendTLSCommonName(leaf.Subject.CommonName, state.ServerName) {
		return fmt.Errorf(
			"upstream TLS common name %q does not match %q",
			leaf.Subject.CommonName,
			state.ServerName,
		)
	}
	return nil
}

func backendTLSCertificateHasSAN(certificate *x509.Certificate) bool {
	for _, extension := range certificate.Extensions {
		if extension.Id.String() == "2.5.29.17" {
			return true
		}
	}
	return false
}

func verifyBackendTLSRevocation(
	chain []*x509.Certificate,
	trustCertificates []*x509.Certificate,
	revocationLists []*x509.RevocationList,
	mode string,
	now time.Time,
) error {
	checkCount := 1
	if mode == "all" {
		checkCount = len(chain) - 1
		if checkCount == 0 {
			checkCount = 1
		}
	}
	for index := 0; index < checkCount && index < len(chain); index++ {
		certificate := chain[index]
		issuers := trustCertificates
		if index+1 < len(chain) {
			issuers = []*x509.Certificate{chain[index+1]}
		}
		list, err := currentBackendTLSRevocationList(
			certificate,
			issuers,
			revocationLists,
			now,
		)
		if err != nil {
			return err
		}
		for _, entry := range list.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
				return fmt.Errorf(
					"upstream TLS certificate serial %s is revoked",
					certificate.SerialNumber,
				)
			}
		}
		for _, entry := range list.RevokedCertificates {
			if entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
				return fmt.Errorf(
					"upstream TLS certificate serial %s is revoked",
					certificate.SerialNumber,
				)
			}
		}
	}
	return nil
}

func currentBackendTLSRevocationList(
	certificate *x509.Certificate,
	issuers []*x509.Certificate,
	revocationLists []*x509.RevocationList,
	now time.Time,
) (*x509.RevocationList, error) {
	var stale bool
	for _, issuer := range issuers {
		if !bytes.Equal(certificate.RawIssuer, issuer.RawSubject) {
			continue
		}
		for _, list := range revocationLists {
			if !bytes.Equal(list.RawIssuer, issuer.RawSubject) || list.CheckSignatureFrom(issuer) != nil {
				continue
			}
			if now.Before(list.ThisUpdate) || list.NextUpdate.IsZero() || now.After(list.NextUpdate) {
				stale = true
				continue
			}
			return list, nil
		}
	}
	if stale {
		return nil, fmt.Errorf(
			"upstream TLS certificate serial %s has no current CRL",
			certificate.SerialNumber,
		)
	}
	return nil, fmt.Errorf(
		"upstream TLS certificate serial %s has no issuer-signed CRL",
		certificate.SerialNumber,
	)
}

func matchBackendTLSCommonName(pattern, host string) bool {
	pattern = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if pattern == "" || host == "" {
		return false
	}
	if address := net.ParseIP(host); address != nil {
		return address.Equal(net.ParseIP(pattern))
	}
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == host
	}
	suffix := pattern[1:]
	return strings.HasSuffix(host, suffix) &&
		strings.Count(host, ".") == strings.Count(pattern, ".")
}

func runtimeRestriction(action RestrictionAction) (RuntimeRestriction, error) {
	switch action {
	case RestrictionActionIgnore:
		return RuntimeRestrictionNone, nil
	case RestrictionActionWrite:
		return RuntimeRestrictionWrite, nil
	case RestrictionActionBackend:
		return RuntimeRestrictionBackend, nil
	case RestrictionActionConnection:
		return RuntimeRestrictionConnection, nil
	case RestrictionActionIsolate:
		return RuntimeRestrictionIsolate, nil
	case RestrictionActionReject:
		return RuntimeRestrictionReject, nil
	default:
		return RuntimeRestrictionNone, fmt.Errorf("unsupported lloadd restriction %q", action)
	}
}
