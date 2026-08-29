package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/saslkrb5"
)

const defaultSecureHandshakeTimeout = 10 * time.Second
const defaultLocalSecurityStrengthFactor uint32 = 71

type SecureTransport interface {
	ServerHandshake(context.Context, net.Conn) (net.Conn, error)
}

type standardTLSTransport struct {
	config *tls.Config
}

type runtimeTLSTransport struct {
	server *Server
}

func (server *Server) requiresImplicitTLS() bool {
	return server != nil &&
		(server.config.ImplicitTLS || server.config.ImplicitTLSForConnection != nil ||
			server.config.ListenerSchemeForConnection != nil)
}

func (server *Server) implicitTLSForConnection(connection net.Conn) bool {
	scheme := server.listenerSchemeForConnection(connection)
	return scheme == "ldaps" || scheme == "ldap+tlcp"
}

func (server *Server) listenerSchemeForConnection(connection net.Conn) string {
	if server == nil {
		return "ldap"
	}
	if server.config.ListenerSchemeForConnection != nil {
		if scheme := strings.ToLower(strings.TrimSpace(
			server.config.ListenerSchemeForConnection(connection),
		)); scheme != "" {
			return scheme
		}
	}
	if server.config.ImplicitTLSForConnection != nil {
		if server.config.ImplicitTLSForConnection(connection) {
			return "ldaps"
		}
		return "ldap"
	}
	if connection != nil && connection.LocalAddr() != nil {
		network := connection.LocalAddr().Network()
		if network == "unix" || network == "unixpacket" {
			return "ldapi"
		}
	}
	if server.config.ImplicitTLS {
		return "ldaps"
	}
	return "ldap"
}

func (server *Server) secureTransportAvailable(runtime *runtimeState) bool {
	if server == nil || server.secureTransport == nil {
		return false
	}
	if _, dynamic := server.secureTransport.(runtimeTLSTransport); dynamic {
		return runtime != nil && runtime.secureTransport != nil
	}
	return true
}

type externalIdentityConnection interface {
	net.Conn
	ExternalIdentity() (string, bool)
}

type securityStrengthConnection interface {
	net.Conn
	SecurityStrengthFactor() uint32
}

type standardTLSConnection struct {
	*tls.Conn
	channelBinding []byte
}

func (connection *standardTLSConnection) TLSChannelBinding() ([]byte, bool) {
	if len(connection.channelBinding) == 0 {
		return nil, false
	}
	return append([]byte(nil), connection.channelBinding...), true
}

func (connection *standardTLSConnection) ExternalIdentity() (string, bool) {
	state := connection.ConnectionState()
	if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return "", false
	}
	return state.PeerCertificates[0].Subject.String(), true
}

func (connection *standardTLSConnection) SecurityStrengthFactor() uint32 {
	return tlsConnectionSecurityStrength(connection.ConnectionState())
}

func (transport standardTLSTransport) ServerHandshake(
	ctx context.Context,
	connection net.Conn,
) (net.Conn, error) {
	secured := tls.Server(connection, transport.config.Clone())
	if err := secured.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return &standardTLSConnection{
		Conn:           secured,
		channelBinding: staticTLSServerEndpoint(transport.config),
	}, nil
}

func staticTLSServerEndpoint(configuration *tls.Config) []byte {
	if configuration == nil || len(configuration.Certificates) != 1 ||
		configuration.GetCertificate != nil || configuration.GetConfigForClient != nil ||
		len(configuration.Certificates[0].Certificate) == 0 {
		return nil
	}
	certificate, err := x509.ParseCertificate(
		configuration.Certificates[0].Certificate[0],
	)
	if err != nil {
		return nil
	}
	binding, err := saslkrb5.TLSServerEndpoint(certificate)
	if err != nil {
		return nil
	}
	return binding
}

type tlsChannelBindingConnection interface {
	net.Conn
	TLSChannelBinding() ([]byte, bool)
}

func connectionTLSChannelBinding(connection net.Conn) []byte {
	provider, ok := connection.(tlsChannelBindingConnection)
	if !ok {
		return nil
	}
	binding, ok := provider.TLSChannelBinding()
	if !ok {
		return nil
	}
	return binding
}

func (transport runtimeTLSTransport) ServerHandshake(
	ctx context.Context,
	connection net.Conn,
) (net.Conn, error) {
	if transport.server == nil {
		return nil, errors.New("TLS runtime is unavailable")
	}
	runtime := transport.server.runtime.Load()
	if runtime == nil || runtime.secureTransport == nil {
		return nil, errors.New("TLS is not configured")
	}
	return runtime.secureTransport.ServerHandshake(ctx, connection)
}

func (server *Server) secureHandshake(
	ctx context.Context,
	connection net.Conn,
) (net.Conn, error) {
	handshakeContext := ctx
	cancel := func() {}
	if server.config.SecureHandshakeTimeout > 0 {
		handshakeContext, cancel = context.WithTimeout(
			ctx,
			server.config.SecureHandshakeTimeout,
		)
	}
	defer cancel()
	if !server.handshakeLimiter.acquire(handshakeContext) {
		return nil, handshakeContext.Err()
	}
	defer server.handshakeLimiter.release()
	return server.secureTransport.ServerHandshake(handshakeContext, connection)
}

func externalIdentityDN(connection net.Conn) string {
	provider, ok := connection.(externalIdentityConnection)
	if !ok {
		return ""
	}
	rawDN, ok := provider.ExternalIdentity()
	if !ok || rawDN == "" {
		return ""
	}
	dn, err := directory.ParseDN(rawDN)
	if err != nil || dn.Depth() == 0 {
		return ""
	}
	return dn.String()
}

func connectionSecurityStrength(
	connection net.Conn,
	secure bool,
) uint32 {
	if provider, ok := connection.(securityStrengthConnection); ok {
		return provider.SecurityStrengthFactor()
	}
	if secure {
		return 1
	}
	if address := connection.LocalAddr(); address != nil &&
		address.Network() == "unix" {
		return defaultLocalSecurityStrengthFactor
	}
	return 0
}

func tlsConnectionSecurityStrength(state tls.ConnectionState) uint32 {
	name := tls.CipherSuiteName(state.CipherSuite)
	switch {
	case strings.Contains(name, "CHACHA20"):
		return 256
	case strings.Contains(name, "AES_256"):
		return 256
	case strings.Contains(name, "AES_128"):
		return 128
	case strings.Contains(name, "3DES"):
		return 112
	case strings.Contains(name, "RC4"):
		return 128
	default:
		return 0
	}
}
