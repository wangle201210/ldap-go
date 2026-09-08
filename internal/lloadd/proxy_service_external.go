package lloadd

import (
	"crypto/tls"
	"errors"
	"net"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func validateServiceSASLExternalConfig(config RuntimeBindConfig) error {
	if config.AuthenticationID != "" || config.Realm != "" || len(config.Credentials) != 0 {
		return errors.New("upstream SASL EXTERNAL obtains its authentication identity from TLS or LDAPI; authcid, realm, and credentials must be empty")
	}
	if config.SecurityProperties != "" && config.SecurityProperties != "none" {
		return errors.New("upstream SASL EXTERNAL auth-only mode supports only empty secprops or secprops=none")
	}
	return nil
}

func (backend *runtimeBackend) bindServiceSASLExternal(
	connection net.Conn,
	nextMessageID *int64,
) error {
	// Inspect the established transport: optional StartTLS can return a cleartext
	// connection, and a custom dialer need not honor an ldapi URI.
	secured := false
	if connection, ok := connection.(interface{ ConnectionState() tls.ConnectionState }); ok {
		secured = connection.ConnectionState().HandshakeComplete
	}
	if address, ok := connection.RemoteAddr().(*net.UnixAddr); ok && address.Net == "unix" {
		secured = true
	}
	if !secured {
		return errors.New("service SASL EXTERNAL requires established TLS or an LDAPI Unix connection")
	}

	// EXTERNAL carries only the requested authorization identity. An explicitly
	// present empty response asks the server to use the transport identity.
	credentials := []byte(backend.proxy.config.Bind.AuthorizationID)
	defer clear(credentials)
	result, err := backend.exchangeServiceSASLBind(
		connection, nextMessageID, "EXTERNAL", credentials, true,
	)
	defer result.clear()
	if err != nil {
		return err
	}
	if result.code != ldapwire.ResultSuccess {
		return serviceSASLResultError("EXTERNAL", result.code)
	}
	return nil
}
