package server

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

const defaultSecureHandshakeTimeout = 10 * time.Second

type SecureTransport interface {
	ServerHandshake(context.Context, net.Conn) (net.Conn, error)
}

type standardTLSTransport struct {
	config *tls.Config
}

func (transport standardTLSTransport) ServerHandshake(
	ctx context.Context,
	connection net.Conn,
) (net.Conn, error) {
	secured := tls.Server(connection, transport.config.Clone())
	if err := secured.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return secured, nil
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
