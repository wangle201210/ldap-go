package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	autoCALocalTLSMetadataKey     = "autoca/local-tls/v1"
	autoCALocalTLSMetadataVersion = 1
)

var (
	errAutoCALocalTLSExpired = errors.New("AutoCA local TLS certificate is not currently valid")
	errAutoCALocalTLSRotate  = errors.New("AutoCA local TLS material requires rotation")
)

type autoCALocalTLSMaterial struct {
	Version              int    `json:"version"`
	ConfigurationDN      string `json:"configuration_dn"`
	LocalDN              string `json:"local_dn"`
	Profile              string `json:"profile"`
	AuthorityFingerprint string `json:"authority_fingerprint"`
	IdentityFingerprint  string `json:"identity_fingerprint"`
	ServerKeyBits        int    `json:"server_key_bits"`
	ServerDays           int    `json:"server_days"`
	CertificateDER       []byte `json:"certificate_der"`
	PrivateKeyDER        []byte `json:"private_key_der"`
}

type autoCALocalTLSSelection struct {
	database      *runtimeDatabase
	configuration *autoCARuntimeConfiguration
	entry         directory.Entry
	ipAddress     string
	dnsNames      []string
}

// pendingAutoCATLSTransport only exists while New or an online cn=config write
// is building a candidate before its storage transaction creates the material.
// A pending transport is never published as an active runtime.
type pendingAutoCATLSTransport struct{}

func (pendingAutoCATLSTransport) ServerHandshake(context.Context, net.Conn) (net.Conn, error) {
	return nil, errors.New("AutoCA local TLS material is pending")
}

func (server *Server) ensureAutoCALocalTLS(
	writer storage.Writer,
	runtime *runtimeState,
) error {
	explicit, err := autoCAExplicitGlobalServerMaterial(writer)
	if err != nil {
		return err
	}
	if server.hasExplicitSecureTransport() || explicit {
		if err := writer.DeleteMetadata(autoCALocalTLSMetadataKey); err != nil &&
			!errors.Is(err, storage.ErrMetadataNotFound) {
			return fmt.Errorf("delete inactive AutoCA local TLS material: %w", err)
		}
		return nil
	}

	selection, err := selectAutoCALocalTLS(writer, runtime)
	if err != nil {
		return err
	}
	if selection == nil {
		if err := writer.DeleteMetadata(autoCALocalTLSMetadataKey); err != nil &&
			!errors.Is(err, storage.ErrMetadataNotFound) {
			return fmt.Errorf("delete retired AutoCA local TLS material: %w", err)
		}
		return nil
	}
	if selection.configuration.profile != autoCAProfileOpenLDAPRSA {
		return fmt.Errorf(
			"%s olcAutoCAlocalDN cannot install profile %q into Go standard TLS; use explicit TLS/TLCP material for SM2",
			selection.configuration.configDNKey,
			selection.configuration.profile,
		)
	}

	now := server.autoCANow()
	desired := autoCALocalTLSDescriptor(*selection)
	pair, reusable, err := autoCALocalTLSStoredPair(writer, desired, *selection, now)
	rotate := errors.Is(err, errAutoCALocalTLSRotate)
	if err != nil && !rotate {
		return fmt.Errorf("load AutoCA local TLS material for %s: %w", selection.entry.DN, err)
	}
	if !reusable && !rotate {
		pair, reusable, err = autoCALocalTLSEntryPair(*selection, now)
		if err != nil {
			return fmt.Errorf("load AutoCA local TLS entry material for %s: %w", selection.entry.DN, err)
		}
	}
	if !reusable {
		pair, err = generateAutoCAServerCertificate(
			selection.configuration.authority,
			autoCAServerCertificateConfig{
				DN:           selection.entry.DN,
				IPHostNumber: selection.ipAddress,
				DNSNames:     append([]string(nil), selection.dnsNames...),
				KeyBits:      selection.configuration.serverKeyBits,
				Days:         selection.configuration.serverDays,
				Now:          now,
				Random:       rand.Reader,
			},
		)
		if err != nil {
			return fmt.Errorf("generate AutoCA local TLS certificate for %s: %w", selection.entry.DN, err)
		}
	}
	defer clearGlobalTLSSecret(pair.PrivateKeyDER)
	if err := validateAutoCALocalTLSPair(pair, *selection, now); err != nil {
		return fmt.Errorf("validate AutoCA local TLS certificate for %s: %w", selection.entry.DN, err)
	}

	entry := selection.entry.Clone()
	if !runtime.schema.EntryHasObjectClass(entry, "autoCAuser") {
		if err := entry.AddValues("objectClass", stringValues("autoCAuser")); err != nil {
			return fmt.Errorf("add AutoCA local TLS objectClass at %s: %w", entry.DN, err)
		}
	}
	entry.ReplaceValues("userCertificate;binary", [][]byte{pair.CertificateDER})
	// Unlike OpenLDAP's LDAP-visible userPrivateKey value, listener private
	// material is kept in metadata so no Search ACL mistake can disclose it.
	entry.ReplaceValues("userPrivateKey;binary", nil)
	if err := runtime.schema.ValidateEntry(entry); err != nil {
		return fmt.Errorf("validate AutoCA local TLS entry %s: %w", entry.DN, err)
	}
	tx := writerForDatabase(writer, *selection.database)
	if err := tx.Put(entry, true); err != nil {
		return fmt.Errorf("store AutoCA local TLS certificate at %s: %w", entry.DN, err)
	}

	desired.CertificateDER = bytes.Clone(pair.CertificateDER)
	desired.PrivateKeyDER = bytes.Clone(pair.PrivateKeyDER)
	defer clearGlobalTLSSecret(desired.PrivateKeyDER)
	encoded, err := json.Marshal(desired)
	if err != nil {
		return fmt.Errorf("encode AutoCA local TLS material: %w", err)
	}
	defer clearGlobalTLSSecret(encoded)
	if err := writer.SetMetadata(autoCALocalTLSMetadataKey, encoded); err != nil {
		return fmt.Errorf("store AutoCA local TLS material: %w", err)
	}
	return nil
}

func (server *Server) autoCANow() time.Time {
	if server != nil && server.clock != nil {
		return server.clock()
	}
	return time.Now()
}

func autoCAExplicitGlobalServerMaterial(reader storage.Reader) (bool, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("load global TLS configuration: %w", err)
	}
	attributes, err := parseGlobalTLSAttributes(entry)
	if err != nil {
		return false, err
	}
	return globalTLSServerMaterialPresent(attributes), nil
}

func selectAutoCALocalTLS(
	reader storage.Reader,
	runtime *runtimeState,
) (*autoCALocalTLSSelection, error) {
	if runtime == nil {
		return nil, nil
	}
	var selected *autoCALocalTLSSelection
	for index := range runtime.databases {
		database := &runtime.databases[index]
		configuration := activeAutoCAConfiguration(database)
		if configuration == nil || configuration.localDN == nil {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf(
				"olcAutoCAlocalDN is configured by both %s and %s; one global listener certificate is supported",
				selected.configuration.configDNKey,
				configuration.configDNKey,
			)
		}
		entry, err := readerForDatabase(reader, *database).Get(*configuration.localDN)
		if errors.Is(err, storage.ErrEntryNotFound) {
			// The first startup runtime is built before legacy/default entries are
			// partitioned. The subsequent owning transaction always writes through
			// the database-scoped writer after partitionDefaultEntries completes.
			entry, err = reader.Get(*configuration.localDN)
		}
		if err != nil {
			return nil, fmt.Errorf("load olcAutoCAlocalDN %s: %w", configuration.localDN, err)
		}
		if !runtime.schema.EntryHasObjectClass(entry, configuration.serverClass) {
			return nil, fmt.Errorf(
				"olcAutoCAlocalDN %s does not have server objectClass %s",
				entry.DN,
				configuration.serverClass,
			)
		}
		ipAddress := autoCAFirstString(runtime.schema.AttributeValues(entry, "ipHostNumber"))
		dnsNames := autoCALocalTLSDNSNames(runtime.schema.AttributeValues(entry, "cn"))
		if ipAddress == "" && len(dnsNames) == 0 {
			return nil, fmt.Errorf(
				"olcAutoCAlocalDN %s requires an ipHostNumber or DNS-compatible cn for TLS SAN",
				entry.DN,
			)
		}
		selected = &autoCALocalTLSSelection{
			database:      database,
			configuration: configuration,
			entry:         entry,
			ipAddress:     ipAddress,
			dnsNames:      dnsNames,
		}
	}
	return selected, nil
}

func autoCALocalTLSDNSNames(values [][]byte) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(string(value)), "."))
		if !autoCAValidDNSName(name) {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func autoCALocalTLSDescriptor(selection autoCALocalTLSSelection) autoCALocalTLSMaterial {
	authorityFingerprint := sha256.Sum256(selection.configuration.authority.CertificateDER)
	identityDigest := sha256.New()
	_, _ = identityDigest.Write([]byte(selection.entry.DN))
	_, _ = identityDigest.Write([]byte{0})
	_, _ = identityDigest.Write([]byte(selection.ipAddress))
	for _, name := range selection.dnsNames {
		_, _ = identityDigest.Write([]byte{0})
		_, _ = identityDigest.Write([]byte(name))
	}
	return autoCALocalTLSMaterial{
		Version:              autoCALocalTLSMetadataVersion,
		ConfigurationDN:      selection.configuration.configDNKey,
		LocalDN:              selection.configuration.localDN.Key(),
		Profile:              selection.configuration.profile,
		AuthorityFingerprint: hex.EncodeToString(authorityFingerprint[:]),
		IdentityFingerprint:  hex.EncodeToString(identityDigest.Sum(nil)),
		ServerKeyBits:        selection.configuration.serverKeyBits,
		ServerDays:           selection.configuration.serverDays,
	}
}

func decodeAutoCALocalTLSMaterial(reader storage.Reader) (autoCALocalTLSMaterial, error) {
	raw, err := reader.Metadata(autoCALocalTLSMetadataKey)
	if err != nil {
		return autoCALocalTLSMaterial{}, err
	}
	defer clearGlobalTLSSecret(raw)
	var material autoCALocalTLSMaterial
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&material); err != nil {
		return autoCALocalTLSMaterial{}, fmt.Errorf("decode AutoCA local TLS metadata: %w", err)
	}
	if material.Version != autoCALocalTLSMetadataVersion {
		return autoCALocalTLSMaterial{}, fmt.Errorf(
			"unsupported AutoCA local TLS metadata version %d",
			material.Version,
		)
	}
	return material, nil
}

func autoCALocalTLSStoredPair(
	reader storage.Reader,
	desired autoCALocalTLSMaterial,
	selection autoCALocalTLSSelection,
	now time.Time,
) (autoCACertificatePair, bool, error) {
	material, err := decodeAutoCALocalTLSMaterial(reader)
	if errors.Is(err, storage.ErrMetadataNotFound) {
		return autoCACertificatePair{}, false, nil
	}
	if err != nil {
		return autoCACertificatePair{}, false, err
	}
	if !autoCALocalTLSDescriptorEqual(material, desired) {
		clearGlobalTLSSecret(material.PrivateKeyDER)
		return autoCACertificatePair{}, false, errAutoCALocalTLSRotate
	}
	defer clearGlobalTLSSecret(material.PrivateKeyDER)
	pair := autoCACertificatePair{
		CertificateDER: bytes.Clone(material.CertificateDER),
		PrivateKeyDER:  bytes.Clone(material.PrivateKeyDER),
	}
	if err := validateAutoCALocalTLSPair(pair, selection, now); err != nil {
		clearGlobalTLSSecret(pair.PrivateKeyDER)
		if errors.Is(err, errAutoCALocalTLSExpired) {
			return autoCACertificatePair{}, false, errAutoCALocalTLSRotate
		}
		return autoCACertificatePair{}, false, err
	}
	return pair, true, nil
}

func autoCALocalTLSEntryPair(
	selection autoCALocalTLSSelection,
	now time.Time,
) (autoCACertificatePair, bool, error) {
	certificates := selection.entry.Values("userCertificate;binary")
	keys := selection.entry.Values("userPrivateKey;binary")
	if len(certificates) == 0 && len(keys) == 0 {
		return autoCACertificatePair{}, false, nil
	}
	if len(certificates) != 1 || len(keys) != 1 {
		return autoCACertificatePair{}, false, errors.New(
			"AutoCA local TLS entry has incomplete certificate/private-key material",
		)
	}
	pair := autoCACertificatePair{
		CertificateDER: bytes.Clone(certificates[0]),
		PrivateKeyDER:  bytes.Clone(keys[0]),
	}
	if err := validateAutoCALocalTLSPair(pair, selection, now); err != nil {
		clearGlobalTLSSecret(pair.PrivateKeyDER)
		if errors.Is(err, errAutoCALocalTLSExpired) {
			return autoCACertificatePair{}, false, nil
		}
		return autoCACertificatePair{}, false, err
	}
	return pair, true, nil
}

func autoCALocalTLSDescriptorEqual(left, right autoCALocalTLSMaterial) bool {
	return left.Version == right.Version &&
		left.ConfigurationDN == right.ConfigurationDN &&
		left.LocalDN == right.LocalDN &&
		left.Profile == right.Profile &&
		left.AuthorityFingerprint == right.AuthorityFingerprint &&
		left.IdentityFingerprint == right.IdentityFingerprint &&
		left.ServerKeyBits == right.ServerKeyBits &&
		left.ServerDays == right.ServerDays
}

func validateAutoCALocalTLSPair(
	pair autoCACertificatePair,
	selection autoCALocalTLSSelection,
	now time.Time,
) error {
	certificate, err := x509.ParseCertificate(pair.CertificateDER)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	privateKeyValue, err := x509.ParsePKCS8PrivateKey(pair.PrivateKeyDER)
	if err != nil {
		return fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	privateKey, ok := privateKeyValue.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("private key has type %T, want RSA", privateKeyValue)
	}
	match, err := autoCAPublicKeysEqual(certificate.PublicKey, privateKey.Public())
	if err != nil {
		return err
	}
	if !match {
		return errors.New("certificate and private key do not match")
	}
	if certificate.IsCA || !certificate.BasicConstraintsValid {
		return errors.New("certificate must be a non-CA leaf")
	}
	if !certificateSupportsServerAuthentication(certificate) {
		return errors.New("certificate does not permit server authentication")
	}
	if certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		certificate.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		return errors.New("certificate lacks TLS server key usages")
	}
	if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return errAutoCALocalTLSExpired
	}
	_, expectedSubject, err := autoCAX509Subject(selection.entry.DN)
	if err != nil {
		return err
	}
	if !bytes.Equal(certificate.RawSubject, expectedSubject) {
		return errors.New("certificate subject does not match olcAutoCAlocalDN")
	}
	authority, err := x509.ParseCertificate(selection.configuration.authority.CertificateDER)
	if err != nil {
		return fmt.Errorf("parse authority certificate: %w", err)
	}
	if err := certificate.CheckSignatureFrom(authority); err != nil {
		return fmt.Errorf("verify authority signature: %w", err)
	}
	if err := autoCALocalTLSValidateSANs(certificate, selection); err != nil {
		return err
	}
	return nil
}

func autoCALocalTLSValidateSANs(
	certificate *x509.Certificate,
	selection autoCALocalTLSSelection,
) error {
	wantIPs, err := autoCAOptionalIPAddresses(selection.ipAddress)
	if err != nil {
		return err
	}
	if len(certificate.IPAddresses) != len(wantIPs) {
		return fmt.Errorf("certificate IP SANs = %v, want %v", certificate.IPAddresses, wantIPs)
	}
	for index := range wantIPs {
		if !certificate.IPAddresses[index].Equal(wantIPs[index]) {
			return fmt.Errorf("certificate IP SANs = %v, want %v", certificate.IPAddresses, wantIPs)
		}
	}
	wantDNS, err := autoCAOptionalDNSNames(selection.dnsNames)
	if err != nil {
		return err
	}
	gotDNS := append([]string(nil), certificate.DNSNames...)
	sort.Strings(gotDNS)
	if !autoCALocalTLSEqualStrings(gotDNS, wantDNS) {
		return fmt.Errorf("certificate DNS SANs = %v, want %v", gotDNS, wantDNS)
	}
	return nil
}

func autoCALocalTLSEqualStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (server *Server) configureAutoCALocalTLS(
	reader storage.Reader,
	runtime *runtimeState,
	allowPending bool,
) error {
	if runtime == nil || server.hasExplicitSecureTransport() {
		return nil
	}
	if runtime.secureTransport != nil {
		if _, pending := runtime.secureTransport.(pendingAutoCATLSTransport); !pending {
			return nil
		}
		runtime.secureTransport = nil
	}
	explicit, err := autoCAExplicitGlobalServerMaterial(reader)
	if err != nil {
		return err
	}
	if explicit {
		return nil
	}
	selection, err := selectAutoCALocalTLS(reader, runtime)
	if err != nil {
		return err
	}
	if selection == nil {
		if !allowPending && server.requiresImplicitTLS() {
			return errors.New("implicit TLS requires TLS configuration or olcAutoCAlocalDN")
		}
		return nil
	}
	if selection.configuration.profile != autoCAProfileOpenLDAPRSA {
		return fmt.Errorf(
			"%s olcAutoCAlocalDN profile %q is not supported by Go standard TLS; configure explicit TLS/TLCP material for SM2",
			selection.configuration.configDNKey,
			selection.configuration.profile,
		)
	}
	desired := autoCALocalTLSDescriptor(*selection)
	material, err := decodeAutoCALocalTLSMaterial(reader)
	if err != nil || !autoCALocalTLSDescriptorEqual(material, desired) {
		if allowPending {
			runtime.secureTransport = pendingAutoCATLSTransport{}
			return nil
		}
		if err == nil {
			err = errors.New("AutoCA local TLS metadata does not match the active configuration")
		}
		return err
	}
	defer clearGlobalTLSSecret(material.PrivateKeyDER)
	pair := autoCACertificatePair{
		CertificateDER: bytes.Clone(material.CertificateDER),
		PrivateKeyDER:  bytes.Clone(material.PrivateKeyDER),
	}
	defer clearGlobalTLSSecret(pair.PrivateKeyDER)
	if err := validateAutoCALocalTLSPair(pair, *selection, server.autoCANow()); err != nil {
		if allowPending {
			runtime.secureTransport = pendingAutoCATLSTransport{}
			return nil
		}
		return err
	}

	entryDN := configurationSuffix.String()
	attributes := globalTLSAttributes{}
	entry, entryErr := reader.Get(configurationSuffix)
	switch {
	case entryErr == nil:
		entryDN = entry.DN
		attributes, err = parseGlobalTLSAttributes(entry)
		if err != nil {
			return err
		}
	case errors.Is(entryErr, storage.ErrEntryNotFound):
	default:
		return entryErr
	}
	attributes.certificate = pair.CertificateDER
	attributes.certificateFile = ""
	attributes.certificateKey = pair.PrivateKeyDER
	attributes.certificateKeyFile = ""
	if len(attributes.caCertificate) == 0 && attributes.caCertificateFile == "" &&
		attributes.caCertificatePath == "" {
		attributes.caCertificate = bytes.Clone(selection.configuration.authority.CertificateDER)
	}
	configuration, err := server.buildGlobalTLSConfigFromAttributes(entryDN, attributes)
	if err != nil {
		return err
	}
	runtime.secureTransport = standardTLSTransport{config: configuration}
	return nil
}
