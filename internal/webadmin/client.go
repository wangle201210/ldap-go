package webadmin

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

var defaultRandomReader io.Reader = rand.Reader

// ConnectConfig is the immutable transport configuration passed to an
// injectable Connector.
type ConnectConfig struct {
	URL              string
	StartTLS         bool
	TLSConfig        *tls.Config
	DialTimeout      time.Duration
	OperationTimeout time.Duration
}

// Connector creates a fresh, unauthenticated LDAP client for a login attempt.
type Connector interface {
	Connect(context.Context, ConnectConfig) (Client, error)
}

// Client is the LDAP operation surface used by the web application. Keeping it
// narrow makes security and failure behavior deterministic in tests.
type Client interface {
	Bind(username, password string) error
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Add(*ldap.AddRequest) error
	Modify(*ldap.ModifyRequest) error
	Del(*ldap.DelRequest) error
	ModifyDN(*ldap.ModifyDNRequest) error
	PasswordModify(*ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error)
	Close() error
}

type realConnector struct{}

func (realConnector) Connect(ctx context.Context, config ConnectConfig) (Client, error) {
	dialer := &net.Dialer{Timeout: config.DialTimeout}
	options := []ldap.DialOpt{ldap.DialWithDialer(dialer)}
	if config.TLSConfig != nil {
		options = append(options, ldap.DialWithTLSConfig(config.TLSConfig.Clone()))
	}

	type result struct {
		connection *ldap.Conn
		err        error
	}
	resultChannel := make(chan result, 1)
	go func() {
		connection, err := ldap.DialURL(config.URL, options...)
		resultChannel <- result{connection: connection, err: err}
	}()

	var connection *ldap.Conn
	select {
	case <-ctx.Done():
		go func() {
			result := <-resultChannel
			if result.connection != nil {
				_ = result.connection.Close()
			}
		}()
		return nil, ctx.Err()
	case result := <-resultChannel:
		if result.err != nil {
			return nil, result.err
		}
		connection = result.connection
	}

	connection.SetTimeout(config.OperationTimeout)
	if config.StartTLS {
		tlsConfig := config.TLSConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		if err := connection.StartTLS(tlsConfig.Clone()); err != nil {
			_ = connection.Close()
			return nil, err
		}
	}
	return connection, nil
}
