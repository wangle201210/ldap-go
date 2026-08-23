package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
)

const defaultSecureHandshakeTimeout = 10 * time.Second
const localSecurityStrengthFactor uint32 = 71

type SecureTransport interface {
	ServerHandshake(context.Context, net.Conn) (net.Conn, error)
}

type standardTLSTransport struct {
	config *tls.Config
}

type runtimeTLSTransport struct {
	server *Server
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
	return &standardTLSConnection{Conn: secured}, nil
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
	if server.config.SecureHandshakeTimeout <= 0 {
		return server.secureTransport.ServerHandshake(ctx, connection)
	}
	handshakeContext, cancel := context.WithTimeout(
		ctx,
		server.config.SecureHandshakeTimeout,
	)
	defer cancel()
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
		return localSecurityStrengthFactor
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
