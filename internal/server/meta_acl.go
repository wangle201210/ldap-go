package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type metaACLRequirements struct {
	enabled          bool
	attributes       []string
	requiresComplete bool
	usesGroup        bool
}

func loadMetaACLRequirements(values [][]byte) (metaACLRequirements, error) {
	requirements := metaACLRequirements{enabled: len(values) != 0}
	seen := make(map[string]struct{})
	add := func(attribute string) {
		attribute = strings.TrimSpace(attribute)
		if attribute == "" {
			return
		}
		key := strings.ToLower(attribute)
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		requirements.attributes = append(requirements.attributes, attribute)
	}
	for _, value := range values {
		rule, err := acl.ParseRule(string(value))
		if err != nil {
			return metaACLRequirements{}, err
		}
		if rule.Target.Filter != nil {
			collectLDAPBackendFilterAttributes(
				*rule.Target.Filter,
				add,
				&requirements.requiresComplete,
			)
		}
		for _, clause := range rule.By {
			for _, matcher := range clause.Who {
				switch matcher.Kind {
				case acl.WhoDNAttribute:
					add(matcher.Attribute)
				case acl.WhoACI:
					add(matcher.ACIAttribute)
					// ACI values can name arbitrary DN attributes, groups,
					// sets, and set-reference attributes at runtime.
					requirements.requiresComplete = true
				case acl.WhoSet:
					requirements.requiresComplete = true
				case acl.WhoGroup:
					requirements.usesGroup = true
				}
			}
		}
	}
	if requirements.enabled {
		add("objectClass")
	}
	return requirements, nil
}

func (server *Server) prepareMetaACLSearchRequest(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	request ldapwire.SearchRequest,
) (ldapwire.SearchRequest, bool, error) {
	requirements, err := server.resolveMetaACLRequirements(ctx, state, database)
	if err != nil || !requirements.enabled {
		return request, false, err
	}

	prepared := request
	prepared.Attributes = append([]string(nil), request.Attributes...)
	add := func(attribute string) {
		if metaACLSelectionCovers(state.runtime, prepared.Attributes, attribute) {
			return
		}
		prepared.Attributes = append(prepared.Attributes, attribute)
	}
	for _, attribute := range requirements.attributes {
		add(attribute)
	}
	if requirements.requiresComplete || requirements.usesGroup {
		if !metaACLSelectsAllUserAttributes(prepared.Attributes) {
			prepared.Attributes = append(prepared.Attributes, "*")
		}
		if !metaACLSelectsAllOperationalAttributes(prepared.Attributes) {
			prepared.Attributes = append(prepared.Attributes, "+")
		}
	}
	// ACL target filters, value selectors, ACI, and sets require values even
	// when the frontend client requested attribute descriptions only.
	prepared.TypesOnly = false
	return prepared, true, nil
}

func metaACLSelectionCovers(
	runtime *runtimeState,
	requested []string,
	attribute string,
) bool {
	if runtime == nil || runtime.schema == nil {
		for _, candidate := range requested {
			if strings.EqualFold(candidate, attribute) {
				return true
			}
		}
		return len(requested) == 0
	}
	entry := directory.Entry{Attributes: []directory.Attribute{{
		Description: attribute,
		Values:      [][]byte{[]byte("probe")},
	}}}
	return len(entry.SelectWithMatcher(
		requested,
		false,
		runtime.schema.IsOperational,
		runtime.schema.AttributeDescriptionSubtype,
	).Attributes) != 0
}

func metaACLSelectsAllUserAttributes(attributes []string) bool {
	if len(attributes) == 0 {
		return true
	}
	for _, attribute := range attributes {
		if strings.EqualFold(attribute, "*") {
			return true
		}
	}
	return false
}

func metaACLSelectsAllOperationalAttributes(attributes []string) bool {
	for _, attribute := range attributes {
		if strings.EqualFold(attribute, "+") {
			return true
		}
	}
	return false
}

func (server *Server) resolveMetaACLRequirements(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
) (metaACLRequirements, error) {
	if server.config.AccessPolicy != nil {
		return metaACLRequirements{
			enabled:          true,
			requiresComplete: true,
		}, nil
	}

	server.configMu.Lock()
	defer server.configMu.Unlock()
	if active := server.runtime.Load(); active != nil && state.runtime != active {
		// The operation retained an older immutable ACL snapshot while cn=config
		// advanced. A complete entry is the only safe request for that snapshot.
		return metaACLRequirements{
			enabled:          true,
			requiresComplete: true,
		}, nil
	}

	var values [][]byte
	err := server.config.Store.View(context.WithoutCancel(ctx), func(reader storage.Reader) error {
		configurationReader := reader
		if _, err := reader.GetIn(
			configurationStoragePartition,
			configurationSuffix,
		); err == nil {
			configurationReader = storage.ReaderInPartition(
				reader,
				configurationStoragePartition,
			)
		} else if !errors.Is(err, storage.ErrEntryNotFound) {
			return err
		}
		return configurationReader.ForEach(func(entry directory.Entry) error {
			entryDN, err := directory.ParseDN(entry.DN)
			if err != nil {
				return fmt.Errorf("parse configuration entry DN %q: %w", entry.DN, err)
			}
			if !configurationSuffix.Equal(entryDN) &&
				!configurationSuffix.AncestorOf(entryDN) {
				return nil
			}
			entryValues := entry.Values("olcAccess")
			if len(entryValues) == 0 {
				return nil
			}
			databaseRules := entryDN.Key() == database.configDNKey
			globalRules := len(entry.Values("olcSuffix")) == 0
			if globalRules {
				name := ""
				if names := entry.Values("olcDatabase"); len(names) > 0 {
					name = strings.ToLower(string(names[0]))
				}
				if strings.Contains(name, "config") || strings.Contains(name, "monitor") {
					globalRules = false
				}
			}
			if !databaseRules && !globalRules {
				return nil
			}
			for _, value := range entryValues {
				values = append(values, bytes.Clone(value))
			}
			return nil
		})
	})
	if err != nil {
		return metaACLRequirements{}, err
	}
	return loadMetaACLRequirements(values)
}

type metaACLSearchSession struct {
	ctx      context.Context
	server   *Server
	state    *connectionState
	database runtimeDatabase
	request  ldapwire.SearchRequest
	enabled  bool
	cache    map[string]directory.Entry
	all      []directory.Entry
	allRead  bool
	failure  error
}

func newMetaACLSearchSession(
	ctx context.Context,
	server *Server,
	state *connectionState,
	database runtimeDatabase,
	request ldapwire.SearchRequest,
	enabled bool,
) *metaACLSearchSession {
	return &metaACLSearchSession{
		ctx:      ctx,
		server:   server,
		state:    state,
		database: database,
		request:  request,
		enabled:  enabled,
		cache:    make(map[string]directory.Entry),
	}
}

func (session *metaACLSearchSession) close() {
	if session == nil {
		return
	}
	for key, entry := range session.cache {
		clearSASLCredentialEntry(&entry)
		delete(session.cache, key)
	}
	for index := range session.all {
		clearSASLCredentialEntry(&session.all[index])
	}
	session.all = nil
}

func (server *Server) filterMetaSearchPackets(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	packets []*ber.Packet,
	session *metaACLSearchSession,
) ([]*ber.Packet, error) {
	filtered := make([]*ber.Packet, 0, len(packets))
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		reader = readerForDatabase(reader, database)
		var accessReader storage.Reader = reader
		if session != nil && session.enabled {
			accessReader = &metaACLReader{Reader: reader, session: session}
			if session.failure != nil {
				return session.failure
			}
		}
		for _, packet := range packets {
			if metaPacketTag(packet) != ldapwire.ApplicationSearchResultEntry {
				filtered = append(filtered, packet)
				continue
			}
			entry, err := decodeTranslucentSearchEntry(packet)
			if err != nil {
				return err
			}
			if session != nil && session.enabled {
				session.remember(entry)
			}
			if !server.allowed(
				state.runtime,
				accessReader,
				state.boundDN,
				entry,
				"entry",
				nil,
				acl.Read,
			) {
				if session != nil && session.failure != nil {
					return session.failure
				}
				continue
			}
			entry = server.attributesWithPrivilege(
				state.runtime,
				accessReader,
				state.boundDN,
				entry,
				acl.Read,
				session != nil && session.request.TypesOnly,
			)
			if session != nil && session.failure != nil {
				return session.failure
			}
			if session != nil && session.enabled {
				entry = server.selectEntry(
					state.runtime,
					entry,
					session.request.Attributes,
					session.request.TypesOnly,
				)
			}
			controls, err := decodePBindResponseControls(packet)
			if err != nil {
				return err
			}
			encoded := ldapwire.EncodeSearchResultEntry(0, entry, controls)
			mapped, err := ber.DecodePacketErr(encoded)
			if err != nil {
				return fmt.Errorf("encode ACL-filtered back-meta entry: %w", err)
			}
			filtered = append(filtered, mapped)
		}
		return nil
	})
	return filtered, err
}

type metaACLReader struct {
	storage.Reader
	session *metaACLSearchSession
}

func (reader *metaACLReader) AccessContext() any {
	if provider, ok := reader.Reader.(interface{ AccessContext() any }); ok {
		return provider.AccessContext()
	}
	return nil
}

func (reader *metaACLReader) StorageContext() context.Context {
	if provider, ok := reader.Reader.(interface{ StorageContext() context.Context }); ok {
		return provider.StorageContext()
	}
	return reader.session.ctx
}

func (reader *metaACLReader) Get(dn directory.DN) (directory.Entry, error) {
	if !reader.session.databaseOwnsDN(dn) {
		return reader.Reader.Get(dn)
	}
	if entry, found := reader.session.cached(dn); found {
		return entry, nil
	}
	entry, found, err := reader.session.lookup(dn)
	if err != nil {
		reader.session.fail(err)
		return directory.Entry{}, err
	}
	if !found {
		return directory.Entry{}, storage.ErrEntryNotFound
	}
	reader.session.remember(entry)
	return entry.Clone(), nil
}

func (reader *metaACLReader) ForEach(visit func(directory.Entry) error) error {
	entries, err := reader.session.readAll()
	if err != nil {
		reader.session.fail(err)
		return err
	}
	for _, entry := range entries {
		if err := visit(entry.Clone()); err != nil {
			return err
		}
	}
	return nil
}

func (session *metaACLSearchSession) fail(err error) {
	if err != nil && session.failure == nil {
		session.failure = fmt.Errorf("back-meta ACL auxiliary lookup failed: %w", err)
	}
}

func (session *metaACLSearchSession) databaseOwnsDN(dn directory.DN) bool {
	database := databaseForDN(session.state.runtime, dn)
	return database != nil && database.configDNKey == session.database.configDNKey
}

func (session *metaACLSearchSession) dnKey(dn directory.DN) string {
	if normalized, err := session.state.runtime.schema.NormalizeDN(dn.String()); err == nil {
		return normalized.Key()
	}
	return dn.Key()
}

func (session *metaACLSearchSession) remember(entry directory.Entry) {
	dn, err := session.state.runtime.schema.NormalizeDN(entry.DN)
	if err != nil {
		return
	}
	session.cache[session.dnKey(dn)] = entry.Clone()
}

func (session *metaACLSearchSession) cached(
	dn directory.DN,
) (directory.Entry, bool) {
	entry, found := session.cache[session.dnKey(dn)]
	return entry.Clone(), found
}

func (session *metaACLSearchSession) lookup(
	dn directory.DN,
) (directory.Entry, bool, error) {
	request := ldapwire.SearchRequest{
		BaseDN:       dn.String(),
		Scope:        directory.ScopeBase,
		DerefAliases: ldapwire.NeverDerefAliases,
		SizeLimit:    2,
		Filter: directory.Filter{
			Kind:      directory.FilterPresent,
			Attribute: "objectClass",
		},
		Attributes: []string{"*", "+"},
	}
	requestedDN, err := session.state.runtime.schema.NormalizeDN(dn.String())
	if err != nil {
		return directory.Entry{}, false, err
	}
	for _, target := range session.database.metaBackend.candidateTargetsForDN(dn) {
		entries, code, err := session.searchTarget(target, request)
		if err != nil {
			return directory.Entry{}, false, err
		}
		switch code {
		case ldapwire.ResultNoSuchObject, ldapwire.ResultReferral:
			continue
		case ldapwire.ResultSuccess:
		default:
			return directory.Entry{}, false, fmt.Errorf(
				"ACL lookup returned LDAP result %d",
				code,
			)
		}
		if len(entries) == 0 {
			continue
		}
		if len(entries) != 1 {
			return directory.Entry{}, false, errors.New("ACL lookup returned multiple entries")
		}
		entryDN, err := session.state.runtime.schema.NormalizeDN(entries[0].DN)
		if err != nil || !entryDN.Equal(requestedDN) {
			return directory.Entry{}, false, fmt.Errorf(
				"ACL lookup for %q returned unexpected entry %q",
				dn.String(),
				entries[0].DN,
			)
		}
		return entries[0].Clone(), true, nil
	}
	return directory.Entry{}, false, nil
}

func (session *metaACLSearchSession) readAll() ([]directory.Entry, error) {
	if session.allRead {
		return cloneMetaACLEntries(session.all), nil
	}
	seen := make(map[string]struct{})
	var entries []directory.Entry
	for _, target := range session.database.metaBackend.targets {
		if target.onlineURIUnavailable {
			return nil, errors.New("back-meta ACL target is unavailable")
		}
		request := ldapwire.SearchRequest{
			BaseDN:       target.suffix.String(),
			Scope:        target.scope,
			DerefAliases: ldapwire.NeverDerefAliases,
			Filter: directory.Filter{
				Kind:      directory.FilterPresent,
				Attribute: "objectClass",
			},
			Attributes: []string{"*", "+"},
		}
		found, code, err := session.searchTarget(target, request)
		if err != nil {
			return nil, err
		}
		if code == ldapwire.ResultNoSuchObject {
			continue
		}
		if code != ldapwire.ResultSuccess {
			return nil, fmt.Errorf("ACL set scan returned LDAP result %d", code)
		}
		for _, entry := range found {
			dn, err := session.state.runtime.schema.NormalizeDN(entry.DN)
			if err != nil {
				return nil, fmt.Errorf("normalize ACL set entry %q: %w", entry.DN, err)
			}
			key := session.dnKey(dn)
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			session.remember(entry)
			entries = append(entries, entry.Clone())
		}
	}
	session.all = cloneMetaACLEntries(entries)
	session.allRead = true
	return entries, nil
}

func (session *metaACLSearchSession) searchTarget(
	target metaBackendTargetRuntimeConfiguration,
	request ldapwire.SearchRequest,
) ([]directory.Entry, ldapwire.ResultCode, error) {
	if target.ldapBackend == nil || len(target.ldapBackend.remotes) == 0 {
		return nil, ldapwire.ResultUnavailable, errors.New("ACL target has no LDAP remote")
	}
	message, err := mapMetaRequestToRemote(target.rwm, ldapwire.Message{
		ID:      1,
		Request: request,
	})
	if err != nil {
		return nil, ldapwire.ResultOther, err
	}
	lookupState := ldapBackendACLLookupState(session.state)
	order := metaBackendRemoteOrder(target, len(target.ldapBackend.remotes))
	var attempt chainAttempt
	defer clearSASLCredentialAttempt(&attempt)
	for position, index := range order {
		configured := target.ldapBackend.remotes[index]
		for current := 0; current < ldapBackendRemoteAttempts(len(order)); current++ {
			remote := ldapBackendACLRemote(configured)
			candidate := message
			var failure *ldapwire.Result
			remote, candidate, failure = mapMetaRemoteIdentity(
				target.rwm,
				remote,
				candidate,
			)
			if failure != nil {
				return nil, failure.Code, errors.New(failure.DiagnosticMessage)
			}
			attempt = session.server.executeMetaBackendTargetWithCacheIdentity(
				session.ctx,
				lookupState,
				*target.ldapBackend,
				remote,
				remote,
				candidate,
				metaBackendTransportOwner(target),
			)
			if !ldapBackendShouldFailover(session.ctx, attempt) {
				break
			}
		}
		if attempt.connected {
			rememberMetaBackendRemote(target, index)
		}
		if !ldapBackendShouldFailover(session.ctx, attempt) || position == len(order)-1 {
			break
		}
	}
	if attempt.transportErr != nil {
		return nil, ldapwire.ResultUnavailable, attempt.transportErr
	}
	if !attempt.hasResult {
		return nil, ldapwire.ResultUnavailable, errors.New("ACL lookup returned no LDAP result")
	}
	attempt, err = mapMetaAttemptToLocal(target.rwm, attempt)
	if err != nil {
		return nil, ldapwire.ResultOther, err
	}
	entries := make([]directory.Entry, 0, len(attempt.packets))
	for _, packet := range attempt.packets {
		if metaPacketTag(packet) != ldapwire.ApplicationSearchResultEntry {
			continue
		}
		entry, err := decodeTranslucentSearchEntry(packet)
		if err != nil {
			return nil, ldapwire.ResultOther, err
		}
		entries = append(entries, entry)
	}
	return entries, attempt.result.Code, nil
}

func cloneMetaACLEntries(entries []directory.Entry) []directory.Entry {
	cloned := make([]directory.Entry, len(entries))
	for index := range entries {
		cloned[index] = entries[index].Clone()
	}
	return cloned
}
