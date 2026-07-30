package server

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
)

const defaultSecureHandshakeTimeout = 10 * time.Second

type SecureTransport interface {
	ServerHandshake(context.Context, net.Conn) (net.Conn, error)
}

type standardTLSTransport struct {
	config *tls.Config
}

type externalIdentityConnection interface {
	net.Conn
	ExternalIdentity() (string, bool)
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
