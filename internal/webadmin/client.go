package webadmin

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
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

// Connector creates a fresh, unauthenticated LDAP client for an authentication attempt.
type Connector interface {
	Connect(context.Context, ConnectConfig) (Client, error)
}

// Client is the LDAP operation surface used by the web application. Keeping it
// narrow makes security and failure behavior deterministic in tests.
type Client interface {
	Bind(username, password string) error
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Compare(dn, attribute, value string) (bool, error)
	Add(*ldap.AddRequest) error
	Modify(*ldap.ModifyRequest) error
	Del(*ldap.DelRequest) error
	ModifyDN(*ldap.ModifyDNRequest) error
	PasswordModify(*ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error)
	PasswordModifyWithHashScheme(*ldap.PasswordModifyRequest, string) error
	Close() error
}

type realConnector struct{}

type realClient struct {
	*ldap.Conn
}

func (client *realClient) PasswordModifyWithHashScheme(
	request *ldap.PasswordModifyRequest,
	scheme string,
) error {
	value := ldapwire.PasswordModifyRequestValue{
		UserIdentity:    []byte(request.UserIdentity),
		OldPassword:     []byte(request.OldPassword),
		NewPassword:     []byte(request.NewPassword),
		HasUserIdentity: request.UserIdentity != "",
		HasOldPassword:  request.OldPassword != "",
		HasNewPassword:  request.NewPassword != "",
	}
	defer func() {
		clear(value.UserIdentity)
		clear(value.OldPassword)
		clear(value.NewPassword)
	}()
	encoded := ldapwire.EncodePasswordModifyRequestValue(value)
	defer clear(encoded)
	requestValue := ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		string(encoded),
		"Password Modify requestValue",
	)
	defer func() {
		requestValue.Value = nil
		requestValue.Data.Reset()
	}()
	extended := ldap.NewExtendedRequest(ldapwire.PasswordModifyOID, requestValue)
	extended.Controls = []ldap.Control{
		ldap.NewControlString(ldapwire.PasswordHashSchemeControlOID, true, scheme),
	}
	_, err := client.Extended(extended)
	return err
}

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
	return &realClient{Conn: connection}, nil
}
