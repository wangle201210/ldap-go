package server

import (
	"context"
	"errors"
)

// bindSyncConsumerGSSAPISecurity uses the same raw, pure-Go RFC 4752 path as
// back-ldap. The bind must finish before go-ldap starts its response reader so
// the negotiated layer can replace the transport atomically.
func bindSyncConsumerGSSAPISecurity(
	ctx context.Context,
	transport *syncConsumerTransport,
	configuration syncConsumerConfig,
	provider string,
) error {
	return bindSyncConsumerGSSAPISecurityWithFactory(
		ctx,
		transport,
		configuration,
		provider,
		newLDAPBackendGSSAPIInitiator,
	)
}

func bindSyncConsumerGSSAPISecurityWithFactory(
	ctx context.Context,
	transport *syncConsumerTransport,
	configuration syncConsumerConfig,
	provider string,
	factory ldapBackendGSSAPIInitiatorFactory,
) error {
	if transport == nil || transport.currentConnection() == nil {
		return errors.New("syncrepl SASL GSSAPI transport is unavailable")
	}
	if err := validateSyncConsumerSASLSecurity(
		configuration.securityProperties, "GSSAPI", transport.ssf,
	); err != nil {
		return err
	}
	return bindLDAPBackendGSSAPIWithFactory(
		ctx,
		transport,
		configuration,
		provider,
		factory,
	)
}
