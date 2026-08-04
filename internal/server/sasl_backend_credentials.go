package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var errSASLCredentialEntryUnavailable = errors.New(
	"SASL credential entry is unavailable",
)

// lookupSASLCredentialEntry is the common auxiliary-property read path for
// password-based SASL mechanisms. Callers must clear the returned values.
func (server *Server) lookupSASLCredentialEntry(
	ctx context.Context,
	runtime *runtimeState,
	authenticationDN directory.DN,
	attributes []string,
) (directory.Entry, error) {
	if runtime == nil || len(attributes) == 0 {
		return directory.Entry{}, errSASLCredentialEntryUnavailable
	}
	database := databaseForDN(runtime, authenticationDN)
	if database == nil {
		return directory.Entry{}, errSASLCredentialEntryUnavailable
	}
	switch {
	case database.ldapBackend != nil:
		return server.lookupLDAPBackendSASLCredentialEntry(
			ctx,
			runtime,
			*database,
			authenticationDN,
			attributes,
		)
	case database.metaBackend != nil:
		return server.lookupMetaBackendSASLCredentialEntry(
			ctx,
			runtime,
			*database,
			authenticationDN,
			attributes,
		)
	default:
		return server.lookupLocalSASLCredentialEntry(
			ctx,
			runtime,
			*database,
			authenticationDN,
			attributes,
		)
	}
}

func (server *Server) lookupLocalSASLCredentialEntry(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	authenticationDN directory.DN,
	attributes []string,
) (directory.Entry, error) {
	var credentialEntry directory.Entry
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, database)
		entry, err := tx.Get(authenticationDN)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if runtime.schema.EntryHasObjectClass(entry, "subentry") ||
			runtime.schema.EntryHasObjectClass(entry, "alias") ||
			runtime.schema.EntryHasObjectClass(entry, "referral") {
			return nil
		}

		selected := entry.SelectWithMatcher(
			attributes,
			false,
			nil,
			runtime.schema.AttributeDescriptionSubtype,
		)
		credentialEntry.DN = entry.DN
		for _, attribute := range selected.Attributes {
			authorized := directory.Attribute{Description: attribute.Description}
			for _, value := range attribute.Values {
				if server.allowed(
					runtime,
					tx,
					"",
					entry,
					attribute.Description,
					value,
					acl.Auth,
				) {
					authorized.Values = append(authorized.Values, bytes.Clone(value))
				}
			}
			if len(authorized.Values) > 0 {
				credentialEntry.Attributes = append(
					credentialEntry.Attributes,
					authorized,
				)
			}
		}
		return nil
	})
	if err != nil {
		clearSASLCredentialEntry(&credentialEntry)
		return directory.Entry{}, err
	}
	if len(credentialEntry.Attributes) == 0 {
		return directory.Entry{}, errSASLCredentialEntryUnavailable
	}
	return credentialEntry, nil
}

func (server *Server) lookupLDAPBackendSASLCredentialEntry(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	authenticationDN directory.DN,
	attributes []string,
) (directory.Entry, error) {
	state := newSASLBackendCredentialState(runtime)
	defer state.metaTransports.close()
	message := saslBackendCredentialSearch(authenticationDN, attributes)

	var attempt chainAttempt
	defer clearSASLCredentialAttempt(&attempt)
	for index, configured := range database.ldapBackend.remotes {
		for current := 0; current < ldapBackendRemoteAttempts(
			len(database.ldapBackend.remotes),
		); current++ {
			remote := saslLDAPBackendCredentialRemote(configured)
			attempt = server.executeLDAPBackendTarget(
				ctx,
				state,
				*database.ldapBackend,
				remote,
				message,
			)
			if !ldapBackendShouldFailover(ctx, attempt) {
				break
			}
		}
		if !ldapBackendShouldFailover(ctx, attempt) ||
			index == len(database.ldapBackend.remotes)-1 {
			break
		}
	}
	entry, err := saslBackendCredentialEntryFromAttempt(
		runtime,
		authenticationDN,
		attributes,
		attempt,
	)
	if err != nil {
		return directory.Entry{}, fmt.Errorf(
			"back-ldap SASL credential search for %q: %w",
			authenticationDN.String(),
			err,
		)
	}
	return entry, nil
}

func (server *Server) lookupMetaBackendSASLCredentialEntry(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	authenticationDN directory.DN,
	attributes []string,
) (directory.Entry, error) {
	state := newSASLBackendCredentialState(runtime)
	defer state.metaTransports.close()
	candidates := database.metaBackend.candidateTargetsForDN(authenticationDN)
	var found *directory.Entry
	defer func() { clearSASLCredentialEntry(found) }()
	for _, target := range candidates {
		message, err := mapMetaRequestToRemote(
			target.rwm,
			saslBackendCredentialSearch(authenticationDN, attributes),
		)
		if err != nil {
			return directory.Entry{}, fmt.Errorf(
				"map back-meta SASL credential search for %q: %w",
				authenticationDN.String(),
				err,
			)
		}
		attempt, err := server.executeMetaBackendSASLCredentialSearch(
			ctx,
			state,
			target,
			message,
		)
		if err != nil {
			return directory.Entry{}, err
		}
		remotePackets := append([]*ber.Packet(nil), attempt.packets...)
		attempt, err = mapMetaAttemptToLocal(target.rwm, attempt)
		clearSASLCredentialPackets(remotePackets)
		if err != nil {
			clearSASLCredentialAttempt(&attempt)
			return directory.Entry{}, fmt.Errorf(
				"map back-meta SASL credential result for %q: %w",
				authenticationDN.String(),
				err,
			)
		}
		entry, err := saslBackendCredentialEntryFromAttempt(
			runtime,
			authenticationDN,
			attributes,
			attempt,
		)
		clearSASLCredentialAttempt(&attempt)
		if errors.Is(err, errSASLCredentialEntryUnavailable) {
			continue
		}
		if err != nil {
			return directory.Entry{}, fmt.Errorf(
				"back-meta target %q SASL credential search for %q: %w",
				target.configDNKey,
				authenticationDN.String(),
				err,
			)
		}
		if found != nil {
			clearSASLCredentialEntry(&entry)
			clearSASLCredentialEntry(found)
			return directory.Entry{}, fmt.Errorf(
				"back-meta SASL credential search for %q matched multiple targets",
				authenticationDN.String(),
			)
		}
		copy := entry
		found = &copy
	}
	if found == nil {
		return directory.Entry{}, errSASLCredentialEntryUnavailable
	}
	entry := *found
	found = nil
	return entry, nil
}

func (server *Server) executeMetaBackendSASLCredentialSearch(
	ctx context.Context,
	state *connectionState,
	target metaBackendTargetRuntimeConfiguration,
	message ldapwire.Message,
) (chainAttempt, error) {
	if target.ldapBackend == nil || len(target.ldapBackend.remotes) == 0 {
		return chainAttempt{}, errSASLCredentialEntryUnavailable
	}
	if !target.beginAttempt() {
		return chainAttempt{}, errors.New("back-meta target is quarantined")
	}

	var attempt chainAttempt
	remoteOrder := metaBackendRemoteOrder(target, len(target.ldapBackend.remotes))
	replayed := false
	for position := 0; position < len(remoteOrder); {
		index := remoteOrder[position]
		remote := saslMetaBackendCredentialRemote(
			target.ldapBackend.remotes[index],
		)
		attempt = server.executeMetaBackendTarget(
			ctx,
			state,
			*target.ldapBackend,
			remote,
			message,
			metaBackendTransportOwner(target),
		)
		if attempt.connected {
			rememberMetaBackendRemote(target, index)
		}
		retry, replay := metaBackendShouldRetryRemote(
			ctx,
			attempt,
			false,
			&replayed,
		)
		if !retry {
			break
		}
		if replay {
			remoteOrder = metaBackendRemoteOrder(
				target,
				len(target.ldapBackend.remotes),
			)
			position = 0
			continue
		}
		position++
	}
	if ctx.Err() == nil {
		target.finishAttempt(metaBackendAttemptCode(attempt))
	}
	return attempt, nil
}

func saslLDAPBackendCredentialRemote(
	configured chainRemoteConfiguration,
) chainRemoteConfiguration {
	remote := configured.clone()
	if remote.aclBind.bindMethod != "" {
		remote.bind = remote.aclBind
		remote.bind.credentials = bytes.Clone(remote.aclBind.credentials)
		return remote
	}
	return saslIDAssertCredentialRemote(remote)
}

func saslMetaBackendCredentialRemote(
	configured chainRemoteConfiguration,
) chainRemoteConfiguration {
	return saslIDAssertCredentialRemote(configured.clone())
}

func saslIDAssertCredentialRemote(
	remote chainRemoteConfiguration,
) chainRemoteConfiguration {
	// OpenLDAP suppresses native authzID assertion during an auth-check search.
	if remote.identity.native && remote.bind.bindMethod == "sasl" {
		remote.bind.authorizationID = ""
	}
	return remote
}

func newSASLBackendCredentialState(runtime *runtimeState) *connectionState {
	return &connectionState{
		protocolVersion: 3,
		runtime:         runtime,
		metaTransports:  newMetaTransportCache(time.Now),
	}
}

func saslBackendCredentialSearch(
	authenticationDN directory.DN,
	attributes []string,
) ldapwire.Message {
	return ldapwire.Message{
		ID: 1,
		Request: ldapwire.SearchRequest{
			BaseDN:       authenticationDN.String(),
			Scope:        directory.ScopeBase,
			DerefAliases: ldapwire.NeverDerefAliases,
			SizeLimit:    1,
			Filter: directory.Filter{
				Kind:      directory.FilterPresent,
				Attribute: "objectClass",
			},
			Attributes: append([]string(nil), attributes...),
		},
	}
}

func saslBackendCredentialEntryFromAttempt(
	runtime *runtimeState,
	authenticationDN directory.DN,
	attributes []string,
	attempt chainAttempt,
) (directory.Entry, error) {
	if attempt.transportErr != nil {
		return directory.Entry{}, attempt.transportErr
	}
	if !attempt.hasResult {
		return directory.Entry{}, errors.New("remote credential search returned no LDAP result")
	}
	switch attempt.result.Code {
	case ldapwire.ResultSuccess:
	case ldapwire.ResultNoSuchObject:
		return directory.Entry{}, errSASLCredentialEntryUnavailable
	default:
		return directory.Entry{}, fmt.Errorf(
			"remote credential search returned LDAP result %d: %s",
			attempt.result.Code,
			attempt.result.DiagnosticMessage,
		)
	}

	var found *directory.Entry
	defer func() { clearSASLCredentialEntry(found) }()
	for _, packet := range attempt.packets {
		if metaPacketTag(packet) != ldapwire.ApplicationSearchResultEntry {
			continue
		}
		entry, err := decodeTranslucentSearchEntry(packet)
		if err != nil {
			return directory.Entry{}, err
		}
		dn, err := directory.ParseDN(entry.DN)
		if err != nil || !authenticationDN.Equal(dn) {
			return directory.Entry{}, fmt.Errorf(
				"remote credential search returned unexpected entry %q",
				entry.DN,
			)
		}
		selected := entry.SelectWithMatcher(
			attributes,
			false,
			nil,
			runtime.schema.AttributeDescriptionSubtype,
		)
		if len(selected.Attributes) == 0 {
			continue
		}
		if found != nil {
			clearSASLCredentialEntry(&selected)
			clearSASLCredentialEntry(found)
			return directory.Entry{}, errors.New(
				"remote credential search returned multiple entries",
			)
		}
		copy := selected
		found = &copy
	}
	if found == nil {
		return directory.Entry{}, errSASLCredentialEntryUnavailable
	}
	entry := *found
	found = nil
	return entry, nil
}

func clearSASLCredentialEntry(entry *directory.Entry) {
	if entry == nil {
		return
	}
	for attributeIndex := range entry.Attributes {
		for valueIndex := range entry.Attributes[attributeIndex].Values {
			clear(entry.Attributes[attributeIndex].Values[valueIndex])
		}
		entry.Attributes[attributeIndex].Values = nil
	}
	entry.Attributes = nil
}

func clearSASLCredentialAttempt(attempt *chainAttempt) {
	if attempt == nil {
		return
	}
	clearSASLCredentialPackets(attempt.packets)
	attempt.packets = nil
}

func clearSASLCredentialPackets(packets []*ber.Packet) {
	for _, packet := range packets {
		clearSASLCredentialPacket(packet)
	}
}

func clearSASLCredentialPacket(packet *ber.Packet) {
	if packet == nil {
		return
	}
	clear(packet.ByteValue)
	if value, ok := packet.Value.([]byte); ok {
		clear(value)
	}
	if packet.Data != nil {
		clear(packet.Data.Bytes())
		packet.Data.Reset()
	}
	for _, child := range packet.Children {
		clearSASLCredentialPacket(child)
	}
}
