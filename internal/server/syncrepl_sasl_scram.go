package server

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/saslkrb5"
	"github.com/xdg-go/scram"
)

func syncConsumerSCRAMChannelBinding(
	transport *syncConsumerTransport,
	config syncConsumerConfig,
	provider string,
) (scram.ChannelBinding, error) {
	if transport == nil {
		return scram.ChannelBinding{}, errors.New("syncrepl SCRAM-PLUS requires verified standard TLS")
	}
	// Neither a secure flag/SSF nor a ConnectionState method establishes that
	// this is standard TLS. In particular, TLCP cannot provide this binding.
	secured, ok := transport.currentConnection().(*tls.Conn)
	if !ok {
		return scram.ChannelBinding{}, errors.New("syncrepl SCRAM-PLUS requires verified standard TLS")
	}
	state := secured.ConnectionState()
	if !state.HandshakeComplete || len(state.PeerCertificates) == 0 {
		return scram.ChannelBinding{}, errors.New("syncrepl SCRAM-PLUS requires a completed TLS handshake and server certificate")
	}
	parsed, err := parseSyncConsumerProviderURL(provider)
	if err != nil || parsed.Hostname() == "" ||
		(!strings.EqualFold(parsed.Scheme, "ldap") && !strings.EqualFold(parsed.Scheme, "ldaps")) {
		return scram.ChannelBinding{}, errors.New("syncrepl SCRAM-PLUS requires an LDAP TLS provider hostname")
	}
	if config.tls.requireCert == "never" || config.tls.requireCert == "allow" {
		return scram.ChannelBinding{}, errors.New("syncrepl SCRAM-PLUS requires certificate verification; tls_reqcert=never/allow is unsupported")
	}
	// Syncrepl's custom verifier leaves VerifiedChains empty. Reverify the
	// live peer against this provider's trust, hostname/SAN and CRL policy,
	// rather than treating InsecureSkipVerify or a configured CA as proof.
	verification, err := buildSyncConsumerTLSConfig(config, parsed)
	if err != nil {
		return scram.ChannelBinding{}, err
	}
	if verification.VerifyConnection == nil {
		return scram.ChannelBinding{}, errors.New("syncrepl SCRAM-PLUS TLS certificate verifier is unavailable")
	}
	if err := verification.VerifyConnection(state); err != nil {
		return scram.ChannelBinding{}, fmt.Errorf("verify syncrepl SCRAM-PLUS TLS peer: %w", err)
	}
	data, err := saslkrb5.TLSServerEndpoint(state.PeerCertificates[0])
	if err != nil {
		return scram.ChannelBinding{}, fmt.Errorf("syncrepl SCRAM-PLUS channel binding: %w", err)
	}
	// OpenLDAP 2.6.13 d172686d libraries/libldap/cyrus.c names the binding
	// "ldap" and authenticates the TLS type prefix along with the digest.
	return scram.ChannelBinding{Type: "ldap", Data: data}, nil
}

func (conversation *syncConsumerSCRAM) validateChallenge(challenge []byte) error {
	// Bound parsing and PBKDF2 work before calling xdg-go/scram. Its parser
	// accepts ignored fields and an unchanged nonce, and has no iteration cap.
	if len(challenge) == 0 || len(challenge) > maxSASLSCRAMSecretSize {
		return errors.New("SCRAM-PLUS challenge has invalid size")
	}
	fields := strings.Split(string(challenge), ",")
	if conversation.proofSent {
		if len(fields) != 1 || !strings.HasPrefix(fields[0], "v=") {
			return errors.New("SCRAM-PLUS server-final must contain only a verifier")
		}
		proof, err := base64.StdEncoding.Strict().DecodeString(fields[0][2:])
		defer clear(proof)
		if err != nil || len(proof) != conversation.hashSize ||
			base64.StdEncoding.EncodeToString(proof) != fields[0][2:] {
			return errors.New("SCRAM-PLUS server verifier is malformed")
		}
		return nil
	}
	if len(fields) != 3 || !strings.HasPrefix(fields[0], "r=") ||
		!strings.HasPrefix(fields[1], "s=") || !strings.HasPrefix(fields[2], "i=") {
		return errors.New("SCRAM-PLUS server-first must contain only r, s, and i fields")
	}
	nonce := fields[0][2:]
	if len(nonce) <= len(conversation.clientNonce) || !strings.HasPrefix(nonce, conversation.clientNonce) {
		return errors.New("SCRAM-PLUS server nonce did not strictly extend the client nonce")
	}
	for _, character := range []byte(nonce) {
		if character < 0x21 || character > 0x7e {
			return errors.New("SCRAM-PLUS server nonce is malformed")
		}
	}
	salt, err := base64.StdEncoding.Strict().DecodeString(fields[1][2:])
	defer clear(salt)
	if err != nil || len(salt) == 0 || len(salt) > 1024 ||
		base64.StdEncoding.EncodeToString(salt) != fields[1][2:] {
		return errors.New("SCRAM-PLUS server salt is malformed")
	}
	rawIterations := fields[2][2:]
	iterations, err := strconv.ParseUint(rawIterations, 10, 32)
	if err != nil || iterations < defaultSASLSCRAMIterations || iterations > maxSASLSCRAMIterations ||
		strconv.FormatUint(iterations, 10) != rawIterations {
		return fmt.Errorf("SCRAM-PLUS iterations must be between %d and %d", defaultSASLSCRAMIterations, maxSASLSCRAMIterations)
	}
	return nil
}
