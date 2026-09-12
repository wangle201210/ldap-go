package lloadd

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/wangle201210/ldap-go/internal/saslkrb5"
	"github.com/xdg-go/scram"
)

// Retain the config loader's strict reqcert/reqsan/CRL verifier. A custom
// InsecureSkipVerify callback alone is not evidence of verified transport.
type serviceSCRAMPlusTLSVerification struct {
	config *tls.Config
	verify func(tls.ConnectionState) error
}

func (policy *serviceSCRAMPlusTLSVerification) clone(original, cloned *tls.Config) *serviceSCRAMPlusTLSVerification {
	if policy == nil || policy.config != original {
		return nil
	}
	return &serviceSCRAMPlusTLSVerification{config: cloned, verify: policy.verify}
}

func serviceSCRAMPlus(mechanism string) bool {
	switch mechanism {
	case "SCRAM-SHA-1-PLUS", "SCRAM-SHA-256-PLUS", "SCRAM-SHA-512-PLUS":
		return true
	default:
		return false
	}
}

func validateServiceSCRAMPlusTLSConfig(config RuntimeConfig) error {
	if !serviceSCRAMPlus(config.Bind.SASLMechanism) {
		return nil
	}
	policy := config.backendTLSVerification
	if config.BackendTLS == nil || (config.BackendTLS.InsecureSkipVerify &&
		(policy == nil || policy.config != config.BackendTLS || policy.verify == nil)) {
		return errors.New("upstream SASL SCRAM-PLUS requires verified standard TLS")
	}
	return nil
}

func (backend *runtimeBackend) serviceSCRAMPlusChannelBinding(connection net.Conn) (scram.ChannelBinding, error) {
	// Require the concrete standard TLS transport, not a security flag or a
	// ConnectionState lookalike (including TLCP). Optional StartTLS may fail.
	secured, ok := connection.(*tls.Conn)
	if !ok || secured == nil {
		return scram.ChannelBinding{}, errors.New("service SASL SCRAM-PLUS requires verified standard TLS")
	}
	config := backend.proxy.config
	if err := validateServiceSCRAMPlusTLSConfig(config); err != nil {
		return scram.ChannelBinding{}, err
	}
	state := secured.ConnectionState()
	if !state.HandshakeComplete || len(state.PeerCertificates) == 0 {
		return scram.ChannelBinding{}, errors.New("service SASL SCRAM-PLUS requires a completed TLS handshake and server certificate")
	}
	provider, err := url.Parse(backend.config.URI)
	if err != nil || provider.Hostname() == "" ||
		(provider.Scheme != "ldap" && provider.Scheme != "ldaps") {
		return scram.ChannelBinding{}, errors.New("service SASL SCRAM-PLUS requires an LDAP TLS provider hostname")
	}
	state.ServerName = config.BackendTLS.ServerName
	if state.ServerName == "" {
		state.ServerName = provider.Hostname()
	}
	if policy := config.backendTLSVerification; policy != nil && policy.config == config.BackendTLS {
		err = policy.verify(state)
	} else {
		if len(state.VerifiedChains) == 0 {
			return scram.ChannelBinding{}, errors.New("service SASL SCRAM-PLUS requires a verified TLS peer")
		}
		// Recheck against this backend's trust and name even when a custom dialer
		// supplies a connection that was verified under a different TLS config.
		err = verifyBackendTLSConnection(state, config.BackendTLS.RootCAs, nil, nil, "demand", "demand", "none")
		if err == nil && config.BackendTLS.VerifyConnection != nil {
			err = config.BackendTLS.VerifyConnection(state)
		}
	}
	if err != nil {
		return scram.ChannelBinding{}, fmt.Errorf("verify service SASL SCRAM-PLUS TLS peer: %w", err)
	}
	data, err := saslkrb5.TLSServerEndpoint(state.PeerCertificates[0])
	if err != nil {
		return scram.ChannelBinding{}, fmt.Errorf("service SASL SCRAM-PLUS channel binding: %w", err)
	}
	// OpenLDAP 2.6.13 d172686d, libraries/libldap/cyrus.c: Cyrus's GS2 name
	// is "ldap"; binding data includes "tls-server-end-point:" and the RFC 5929
	// digest of the live server leaf certificate, including on resumed sessions.
	// This deliberately fixes endpoint selection. Native lloadd/upstream.c
	// instead supplies unprefixed tls-unique data; it has no tls_cbinding option.
	return scram.ChannelBinding{Type: "ldap", Data: data}, nil
}

func validateServiceSCRAMPlusServerFirst(message []byte, nonce string) error {
	core, err := serviceSCRAMPlusCoreMessage(message, 3)
	if err != nil {
		return err
	}
	return validateServiceSCRAMServerFirst(core, nonce)
}

func validateServiceSCRAMPlusServerFinal(message []byte, hashSize int) error {
	core, err := serviceSCRAMPlusCoreMessage(message, 1)
	if err != nil {
		return err
	}
	return validateServiceSCRAMServerFinal(core, hashSize)
}

func serviceSCRAMPlusCoreMessage(message []byte, count int) ([]byte, error) {
	if len(message) == 0 || len(message) > serviceSASLMaxChallengeSize ||
		!utf8.Valid(message) || bytes.IndexByte(message, 0) >= 0 {
		return nil, errors.New("SCRAM-PLUS challenge has invalid encoding or size")
	}
	fields := strings.Split(string(message), ",")
	if len(fields) < count {
		return nil, errors.New("SCRAM-PLUS challenge is missing required fields")
	}
	// RFC 5802 section 7 permits optional extensions. Validate their framing
	// before PBKDF2, but pass the ORIGINAL message to scram.Step for the HMAC.
	var seen [128]bool
	for _, field := range fields[count:] {
		if len(field) < 3 || field[1] != '=' ||
			!(field[0] >= 'a' && field[0] <= 'z' || field[0] >= 'A' && field[0] <= 'Z') {
			return nil, errors.New("SCRAM-PLUS extension has invalid syntax")
		}
		name := field[0]
		if seen[name] || strings.ContainsRune("aceimnprsv", rune(name)) {
			return nil, errors.New("SCRAM-PLUS extension repeats a field or uses a reserved attribute")
		}
		seen[name] = true
	}
	core := []byte(strings.Join(fields[:count], ","))
	// encoding/base64 ignores CR/LF, even in Strict mode. Core fields must
	// retain canonical base64; extension values have their own RFC grammar.
	if bytes.ContainsAny(core, "\r\n") {
		return nil, errors.New("SCRAM-PLUS core fields are not canonical")
	}
	return core, nil
}
