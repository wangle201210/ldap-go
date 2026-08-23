package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/wangle201210/ldap-go/internal/saslkrb5"
)

type ldapBackendGSSAPIInitiator interface {
	InitialToken(string, []byte) ([]byte, error)
	AcceptAPRep([]byte) error
	ContextKey() (types.EncryptionKey, error)
	SecurityState() (saslkrb5.SecurityState, error)
	Close() error
}

type ldapBackendGSSAPIInitiatorFactory func(
	syncConsumerGSSAPISettings,
) (ldapBackendGSSAPIInitiator, error)

type ldapBackendGSSAPIBindResult struct {
	ssf uint32
	err error
}

const ldapBackendGSSAPIMaxConcurrentInitializations = 16

var ldapBackendGSSAPIInitializationSlots = make(
	chan struct{},
	ldapBackendGSSAPIMaxConcurrentInitializations,
)

func bindLDAPBackendGSSAPI(
	ctx context.Context,
	transport *syncConsumerTransport,
	configuration syncConsumerConfig,
	provider string,
) error {
	return bindLDAPBackendGSSAPIWithFactory(
		ctx,
		transport,
		configuration,
		provider,
		newLDAPBackendGSSAPIInitiator,
	)
}

func bindLDAPBackendGSSAPIWithFactory(
	ctx context.Context,
	transport *syncConsumerTransport,
	configuration syncConsumerConfig,
	provider string,
	factory ldapBackendGSSAPIInitiatorFactory,
) error {
	if transport == nil || transport.currentConnection() == nil {
		return errors.New("chain SASL GSSAPI transport is unavailable")
	}
	if factory == nil {
		return errors.New("chain SASL GSSAPI credential factory is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		_ = transport.close()
		return fmt.Errorf("chain SASL GSSAPI bind: %w", err)
	}
	select {
	case ldapBackendGSSAPIInitializationSlots <- struct{}{}:
	case <-ctx.Done():
		_ = transport.close()
		return fmt.Errorf("chain SASL GSSAPI bind: %w", ctx.Err())
	}
	settings, err := resolveSyncConsumerGSSAPISettings(
		configuration,
		provider,
		os.LookupEnv,
	)
	if err != nil {
		<-ldapBackendGSSAPIInitializationSlots
		return err
	}
	properties := configuration.securityProperties
	channelBinding := configuration.gssapiChannelBinding
	externalSSF := transport.ssf
	done := make(chan ldapBackendGSSAPIBindResult, 1)
	go func(
		localSettings syncConsumerGSSAPISettings,
		localProperties syncConsumerSASLSecurityProperties,
		localChannelBinding string,
		localExternalSSF uint32,
	) {
		defer func() { <-ldapBackendGSSAPIInitializationSlots }()
		ssf, bindErr := bindLDAPBackendGSSAPIBlocking(
			transport,
			localProperties,
			localChannelBinding,
			localExternalSSF,
			localSettings,
			factory,
		)
		localSettings.password = ""
		if ctx.Err() != nil {
			_ = transport.close()
		}
		done <- ldapBackendGSSAPIBindResult{ssf: ssf, err: bindErr}
	}(settings, properties, channelBinding, externalSSF)
	settings.password = ""
	select {
	case result := <-done:
		if result.err == nil && result.ssf > transport.ssf {
			transport.ssf = result.ssf
		}
		return result.err
	case <-ctx.Done():
		_ = transport.close()
		return fmt.Errorf("chain SASL GSSAPI bind: %w", ctx.Err())
	}
}

func newLDAPBackendGSSAPIInitiator(
	settings syncConsumerGSSAPISettings,
) (ldapBackendGSSAPIInitiator, error) {
	switch settings.source {
	case syncConsumerGSSAPIPassword:
		return saslkrb5.NewInitiatorWithPassword(
			settings.username,
			settings.realm,
			settings.password,
			settings.configuration,
		)
	case syncConsumerGSSAPIKeytab:
		return saslkrb5.NewInitiatorWithKeytab(
			settings.username,
			settings.realm,
			settings.credentialPath,
			settings.configuration,
		)
	case syncConsumerGSSAPICCache:
		return saslkrb5.NewInitiatorFromCCache(
			settings.credentialPath,
			settings.configuration,
		)
	default:
		return nil, errors.New("unknown chain SASL GSSAPI credential source")
	}
}

func bindLDAPBackendGSSAPIBlocking(
	transport *syncConsumerTransport,
	properties syncConsumerSASLSecurityProperties,
	channelBinding string,
	externalSSF uint32,
	settings syncConsumerGSSAPISettings,
	factory ldapBackendGSSAPIInitiatorFactory,
) (uint32, error) {
	initiator, err := factory(settings)
	settings.password = ""
	if err != nil {
		return 0, fmt.Errorf("initialize chain SASL GSSAPI credentials: %w", err)
	}
	defer initiator.Close()

	binding, err := ldapBackendGSSAPIChannelBinding(
		transport.currentConnection(),
		channelBinding,
	)
	if err != nil {
		return 0, err
	}
	defer clear(binding)
	initial, err := initiator.InitialToken(settings.servicePrincipal, binding)
	if err != nil {
		return 0, fmt.Errorf("create chain SASL GSSAPI AP-REQ: %w", err)
	}
	first, err := sendSyncConsumerSASLBind(transport, "GSSAPI", initial, true)
	clear(initial)
	if err != nil {
		return 0, fmt.Errorf("chain SASL GSSAPI AP-REQ: %w", err)
	}
	defer clear(first.saslCredentials)
	if first.code != 14 {
		return 0, fmt.Errorf("chain SASL GSSAPI AP-REQ: %w", first.err())
	}
	if !first.hasSASLCredentials || len(first.saslCredentials) == 0 {
		return 0, errors.New("chain SASL GSSAPI acceptor omitted AP-REP")
	}
	if err := initiator.AcceptAPRep(first.saslCredentials); err != nil {
		return 0, fmt.Errorf("verify chain SASL GSSAPI acceptor: %w", err)
	}
	clear(first.saslCredentials)

	second, err := sendSyncConsumerSASLBind(transport, "GSSAPI", nil, false)
	if err != nil {
		return 0, fmt.Errorf("request chain SASL GSSAPI security layers: %w", err)
	}
	defer clear(second.saslCredentials)
	if second.code != 14 {
		return 0, fmt.Errorf("request chain SASL GSSAPI security layers: %w", second.err())
	}
	if !second.hasSASLCredentials || len(second.saslCredentials) == 0 {
		return 0, errors.New("chain SASL GSSAPI acceptor omitted its security-layer offer")
	}

	key, err := initiator.ContextKey()
	if err != nil {
		return 0, err
	}
	defer clear(key.KeyValue)
	securityState, err := initiator.SecurityState()
	if err != nil {
		return 0, err
	}
	offer, err := saslkrb5.Unwrap(
		second.saslCredentials,
		key,
		true,
		securityState.AcceptorSubkey,
		securityState.ReceiveSequence,
	)
	clear(second.saslCredentials)
	if err != nil {
		return 0, fmt.Errorf("verify chain SASL GSSAPI security-layer offer: %w", err)
	}
	securityState.ReceiveSequence++
	layers, peerMaximum, err := saslkrb5.DecodeOffer(offer)
	clear(offer)
	if err != nil {
		return 0, err
	}
	selection, localMaximum, layerSSF, err := selectLDAPBackendGSSAPILayer(
		layers,
		key,
		properties,
		externalSSF,
	)
	if err != nil {
		return 0, err
	}
	payload, err := saslkrb5.EncodeNegotiation(
		selection,
		localMaximum,
		settings.authorizationID,
	)
	if err != nil {
		return 0, err
	}
	wrapped, err := saslkrb5.Wrap(
		payload,
		key,
		false,
		securityState.AcceptorSubkey,
		securityState.SendSequence,
	)
	clear(payload)
	if err != nil {
		return 0, fmt.Errorf("encode chain SASL GSSAPI security-layer selection: %w", err)
	}
	securityState.SendSequence++
	final, err := sendSyncConsumerSASLBind(transport, "GSSAPI", wrapped, true)
	clear(wrapped)
	if err != nil {
		return 0, fmt.Errorf("complete chain SASL GSSAPI bind: %w", err)
	}
	defer clear(final.saslCredentials)
	if final.code != 0 {
		return 0, fmt.Errorf("complete chain SASL GSSAPI bind: %w", final.err())
	}
	if final.hasSASLCredentials {
		return 0, errors.New("chain SASL GSSAPI acceptor returned unexpected completion data")
	}
	if selection == saslkrb5.SecurityNone {
		return 0, nil
	}

	connection := transport.currentConnection()
	var secured net.Conn
	if selection == saslkrb5.SecurityConfidentiality {
		secured, err = saslkrb5.NewConfidentialityConnection(
			connection, key, false, securityState, peerMaximum, localMaximum,
		)
	} else {
		secured, err = saslkrb5.NewIntegrityConnection(
			connection, key, false, securityState, peerMaximum, localMaximum,
		)
	}
	if err != nil {
		return 0, fmt.Errorf("install chain SASL GSSAPI security layer: %w", err)
	}
	transport.replaceConnection(secured)
	return layerSSF, nil
}

func ldapBackendGSSAPIChannelBinding(
	connection net.Conn,
	mode string,
) ([]byte, error) {
	if mode == "" {
		return nil, nil
	}
	if mode != saslkrb5.ChannelBindingTLSServerEndpoint {
		return nil, fmt.Errorf("unsupported chain SASL GSSAPI channel binding %q", mode)
	}
	secured, ok := connection.(interface{ ConnectionState() tls.ConnectionState })
	if !ok {
		return nil, errors.New(
			"chain SASL GSSAPI tls-server-end-point channel binding requires TLS",
		)
	}
	state := secured.ConnectionState()
	if !state.HandshakeComplete || len(state.PeerCertificates) == 0 ||
		len(state.VerifiedChains) == 0 {
		return nil, errors.New(
			"chain SASL GSSAPI TLS channel binding requires a verified server certificate",
		)
	}
	return saslkrb5.TLSServerEndpoint(state.PeerCertificates[0])
}

func selectLDAPBackendGSSAPILayer(
	layers byte,
	key types.EncryptionKey,
	properties syncConsumerSASLSecurityProperties,
	externalSSF uint32,
) (byte, uint32, uint32, error) {
	if properties.passCredentials {
		return 0, 0, 0, errors.New("chain SASL GSSAPI passcred is unsupported")
	}
	if properties.forwardSecrecy {
		return 0, 0, 0, errors.New("chain SASL GSSAPI forwardsec is unsupported")
	}
	keySSF, err := saslkrb5.SecurityStrength(key)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("determine chain SASL GSSAPI context strength: %w", err)
	}
	requiredSSF := uint32(0)
	if properties.minSSF > externalSSF {
		requiredSSF = properties.minSSF - externalSSF
	}
	limitSSF := uint32(0)
	if properties.maxSSF > externalSSF {
		limitSSF = properties.maxSSF - externalSSF
	}
	if layers&saslkrb5.SecurityConfidentiality != 0 &&
		properties.maxBufferSize != 0 && requiredSSF <= keySSF &&
		limitSSF >= keySSF {
		return saslkrb5.SecurityConfidentiality, properties.maxBufferSize, keySSF, nil
	}
	if layers&saslkrb5.SecurityIntegrity != 0 &&
		properties.maxBufferSize != 0 && requiredSSF <= 1 && limitSSF >= 1 {
		return saslkrb5.SecurityIntegrity, properties.maxBufferSize, 1, nil
	}
	if layers&saslkrb5.SecurityNone != 0 && requiredSSF == 0 {
		return saslkrb5.SecurityNone, 0, 0, nil
	}
	return 0, 0, 0, errors.New(
		"chain SASL GSSAPI acceptor offers no security layer allowed by secprops",
	)
}

func ldapBackendGSSAPIConfigured(configuration syncConsumerConfig) bool {
	return configuration.bindMethod == "sasl" &&
		strings.EqualFold(configuration.saslMechanism, "GSSAPI")
}
