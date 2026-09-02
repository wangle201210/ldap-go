package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type ldapBackendACLDiscoveryState struct {
	once                    sync.Once
	err                     error
	enabled                 bool
	entryAttributes         []string
	requiresCompleteEntries bool
	usesGroup               bool
	sourceValues            [][]byte
	fingerprint             string
}

func loadLDAPBackendACLRequirements(
	values [][]byte,
) (enabled bool, attributes []string, complete, usesGroup bool, err error) {
	if len(values) == 0 {
		return false, nil, false, false, nil
	}
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
		attributes = append(attributes, attribute)
	}
	for _, value := range values {
		rule, parseErr := acl.ParseRule(string(value))
		if parseErr != nil {
			return false, nil, false, false, parseErr
		}
		if rule.Target.Filter != nil {
			collectLDAPBackendFilterAttributes(*rule.Target.Filter, add, &complete)
		}
		for _, clause := range rule.By {
			for _, matcher := range clause.Who {
				switch matcher.Kind {
				case acl.WhoDNAttribute:
					add(matcher.Attribute)
				case acl.WhoACI:
					add(matcher.ACIAttribute)
				case acl.WhoSet:
					complete = true
				case acl.WhoGroup:
					usesGroup = true
				}
			}
		}
	}
	add("objectClass")
	return true, attributes, complete, usesGroup, nil
}

func collectLDAPBackendFilterAttributes(
	filter directory.Filter,
	add func(string),
	complete *bool,
) {
	switch filter.Kind {
	case directory.FilterAnd, directory.FilterOr, directory.FilterNot:
		for _, child := range filter.Children {
			collectLDAPBackendFilterAttributes(child, add, complete)
		}
	case directory.FilterExtensible:
		if filter.Attribute == "" {
			*complete = true
			return
		}
		add(filter.Attribute)
	case directory.FilterComputed:
	default:
		add(filter.Attribute)
	}
}

func prepareLDAPBackendACLSearch(
	message ldapwire.Message,
	database runtimeDatabase,
) ldapwire.Message {
	request, ok := message.Request.(ldapwire.SearchRequest)
	if !ok || database.ldapBackend == nil ||
		database.ldapBackend.aclDiscovery == nil ||
		!database.ldapBackend.aclDiscovery.enabled {
		return message
	}
	attributes := append([]string(nil), request.Attributes...)
	seen := make(map[string]struct{}, len(attributes))
	for _, attribute := range attributes {
		seen[strings.ToLower(attribute)] = struct{}{}
	}
	add := func(attribute string) {
		key := strings.ToLower(attribute)
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		attributes = append(attributes, attribute)
	}
	discovery := database.ldapBackend.aclDiscovery
	for _, attribute := range discovery.entryAttributes {
		add(attribute)
	}
	if discovery.requiresCompleteEntries || discovery.usesGroup {
		add("*")
		add("+")
	}
	request.Attributes = attributes
	message.Request = request
	return message
}

type ldapBackendACLSearchConnection struct {
	net.Conn
	ctx       context.Context
	server    *Server
	state     *connectionState
	database  runtimeDatabase
	messageID int64
	request   ldapwire.SearchRequest

	mu      sync.Mutex
	cache   map[string]directory.Entry
	failure error
}

func newLDAPBackendACLSearchConnection(
	ctx context.Context,
	connection net.Conn,
	server *Server,
	state *connectionState,
	database runtimeDatabase,
	messageID int64,
	request ldapwire.SearchRequest,
) *ldapBackendACLSearchConnection {
	return &ldapBackendACLSearchConnection{
		Conn:      connection,
		ctx:       ctx,
		server:    server,
		state:     state,
		database:  database,
		messageID: messageID,
		request:   request,
		cache:     make(map[string]directory.Entry),
	}
}

func (connection *ldapBackendACLSearchConnection) Write(value []byte) (int, error) {
	transformed, suppress, err := connection.transform(value)
	if err != nil {
		return 0, err
	}
	if suppress {
		return len(value), nil
	}
	if err := ldapwire.Write(connection.Conn, transformed); err != nil {
		return 0, err
	}
	return len(value), nil
}

func (connection *ldapBackendACLSearchConnection) beginFinalResponse() error {
	if finalizer, ok := connection.Conn.(interface{ beginFinalResponse() error }); ok {
		return finalizer.beginFinalResponse()
	}
	return nil
}

func (connection *ldapBackendACLSearchConnection) transform(
	value []byte,
) ([]byte, bool, error) {
	packet, err := ber.DecodePacketErr(value)
	if err != nil {
		return nil, false, fmt.Errorf("decode back-ldap ACL response: %w", err)
	}
	if len(packet.Children) < 2 ||
		packet.Children[1].ClassType != ber.ClassApplication {
		return value, false, nil
	}
	messageID, err := syncConsumerPacketInteger(packet.Children[0])
	if err != nil || messageID != connection.messageID {
		return value, false, nil
	}
	if uint64(packet.Children[1].Tag) == ldapwire.ApplicationSearchResultDone {
		connection.mu.Lock()
		failure := connection.failure
		connection.failure = nil
		for _, entry := range connection.cache {
			clearSASLCredentialEntry(&entry)
		}
		clear(connection.cache)
		connection.mu.Unlock()
		if failure == nil {
			return value, false, nil
		}
		result, resultErr := chainLDAPResult(
			packet,
			messageID,
			ldapwire.ApplicationSearchResultDone,
		)
		if resultErr != nil || result.Code != ldapwire.ResultSuccess {
			return value, false, nil
		}
		controls, controlErr := decodePBindResponseControls(packet)
		if controlErr != nil {
			return nil, false, fmt.Errorf("decode back-ldap ACL final controls: %w", controlErr)
		}
		result = ldapwire.ResultError(
			ldapwire.ResultUnavailable,
			"back-ldap ACL auxiliary lookup failed",
		)
		return ldapwire.EncodeSearchResultDone(messageID, result, controls), false, nil
	}
	if uint64(packet.Children[1].Tag) != ldapwire.ApplicationSearchResultEntry {
		return value, false, nil
	}
	entry, err := decodeTranslucentSearchEntry(packet)
	if err != nil {
		return nil, false, fmt.Errorf("decode back-ldap ACL search entry: %w", err)
	}
	controls, err := decodePBindResponseControls(packet)
	if err != nil {
		return nil, false, fmt.Errorf("decode back-ldap ACL entry controls: %w", err)
	}

	var visible *directory.Entry
	err = connection.server.config.Store.View(connection.ctx, func(base storage.Reader) error {
		reader := newLDAPBackendACLReader(
			connection.ctx,
			connection.server,
			connection.state,
			connection.database,
			base,
			connection.cache,
			&connection.mu,
			connection.recordFailure,
		)
		reader.remember(entry)
		if !connection.server.allowed(
			connection.state.runtime,
			reader,
			connection.state.boundDN,
			entry,
			"entry",
			nil,
			acl.Read,
		) {
			return nil
		}
		if reader.failed() {
			return nil
		}
		filtered := connection.server.ldapBackendReadableEntry(
			connection.state.runtime,
			reader,
			connection.state.boundDN,
			entry,
			entry,
			connection.request.TypesOnly,
		)
		if reader.failed() {
			return nil
		}
		selected := connection.server.selectEntry(
			connection.state.runtime,
			filtered,
			connection.request.Attributes,
			connection.request.TypesOnly,
		)
		visible = &selected
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if visible == nil {
		return nil, true, nil
	}
	return ldapwire.EncodeSearchResultEntry(messageID, *visible, controls), false, nil
}

func (connection *ldapBackendACLSearchConnection) recordFailure(err error) {
	if err == nil {
		return
	}
	connection.mu.Lock()
	if connection.failure == nil {
		connection.failure = err
	}
	connection.mu.Unlock()
}

func (server *Server) ldapBackendReadableEntry(
	runtime *runtimeState,
	reader storage.Reader,
	subjectDN string,
	aclEntry directory.Entry,
	remoteEntry directory.Entry,
	typesOnly bool,
) directory.Entry {
	filtered := directory.Entry{DN: remoteEntry.DN}
	for _, attribute := range remoteEntry.Attributes {
		if typesOnly {
			if server.allowed(
				runtime,
				reader,
				subjectDN,
				aclEntry,
				attribute.Description,
				nil,
				acl.Read,
			) {
				filtered.Attributes = append(filtered.Attributes, directory.Attribute{
					Description: attribute.Description,
				})
			}
			continue
		}
		selected := directory.Attribute{Description: attribute.Description}
		for _, value := range attribute.Values {
			if server.allowed(
				runtime,
				reader,
				subjectDN,
				aclEntry,
				attribute.Description,
				value,
				acl.Read,
			) {
				selected.Values = append(selected.Values, bytes.Clone(value))
			}
		}
		if len(attribute.Values) == 0 && server.allowed(
			runtime,
			reader,
			subjectDN,
			aclEntry,
			attribute.Description,
			nil,
			acl.Read,
		) {
			filtered.Attributes = append(filtered.Attributes, selected)
		} else if len(selected.Values) > 0 {
			filtered.Attributes = append(filtered.Attributes, selected)
		}
	}
	return filtered
}

type ldapBackendACLReader struct {
	storage.Reader
	ctx           context.Context
	server        *Server
	state         *connectionState
	database      runtimeDatabase
	cache         map[string]directory.Entry
	mu            *sync.Mutex
	reportFailure func(error)
	lookupFailed  bool
}

func newLDAPBackendACLReader(
	ctx context.Context,
	server *Server,
	state *connectionState,
	database runtimeDatabase,
	reader storage.Reader,
	cache map[string]directory.Entry,
	mu *sync.Mutex,
	reportFailure func(error),
) *ldapBackendACLReader {
	if cache == nil {
		cache = make(map[string]directory.Entry)
	}
	if mu == nil {
		mu = &sync.Mutex{}
	}
	return &ldapBackendACLReader{
		Reader:        reader,
		ctx:           ctx,
		server:        server,
		state:         state,
		database:      database,
		cache:         cache,
		mu:            mu,
		reportFailure: reportFailure,
	}
}

func (reader *ldapBackendACLReader) AccessContext() any {
	if provider, ok := reader.Reader.(interface{ AccessContext() any }); ok {
		return provider.AccessContext()
	}
	return nil
}

func (reader *ldapBackendACLReader) StorageContext() context.Context {
	if provider, ok := reader.Reader.(interface{ StorageContext() context.Context }); ok {
		return provider.StorageContext()
	}
	return reader.ctx
}

func (reader *ldapBackendACLReader) Get(dn directory.DN) (directory.Entry, error) {
	if !reader.databaseOwnsDN(dn) {
		return reader.Reader.Get(dn)
	}
	key := reader.dnKey(dn)
	reader.mu.Lock()
	entry, found := reader.cache[key]
	reader.mu.Unlock()
	if found {
		return entry.Clone(), nil
	}
	entry, found, resultCode, err := reader.server.lookupLDAPBackendACLEntry(
		reader.ctx,
		reader.state,
		reader.database,
		dn,
		[]string{"*", "+"},
		nil,
	)
	if err != nil {
		reader.fail(err)
		return directory.Entry{}, err
	}
	if !found {
		if resultCode != ldapwire.ResultNoSuchObject &&
			resultCode != ldapwire.ResultReferral {
			err = fmt.Errorf("back-ldap ACL lookup returned LDAP result %d", resultCode)
			reader.fail(err)
			return directory.Entry{}, err
		}
		return directory.Entry{}, storage.ErrEntryNotFound
	}
	reader.remember(entry)
	return entry.Clone(), nil
}

func (reader *ldapBackendACLReader) fail(err error) {
	reader.lookupFailed = true
	if reader.reportFailure != nil {
		reader.reportFailure(err)
	}
}

func (reader *ldapBackendACLReader) failed() bool {
	return reader.lookupFailed
}

func (reader *ldapBackendACLReader) remember(entry directory.Entry) {
	dn, err := reader.state.runtime.schema.NormalizeDN(entry.DN)
	if err != nil {
		return
	}
	reader.mu.Lock()
	reader.cache[reader.dnKey(dn)] = entry.Clone()
	reader.mu.Unlock()
}

func (reader *ldapBackendACLReader) databaseOwnsDN(dn directory.DN) bool {
	database := databaseForDN(reader.state.runtime, dn)
	return database != nil && database.configDNKey == reader.database.configDNKey
}

func (server *Server) resolveLDAPBackendACLRequirements(
	ctx context.Context,
	database runtimeDatabase,
) (bool, error) {
	configuration := database.ldapBackend
	if configuration == nil {
		return false, nil
	}
	discovery := configuration.aclDiscovery
	if discovery == nil {
		return false, errors.New("back-ldap ACL discovery state is missing")
	}
	discovery.once.Do(func() {
		if server.config.AccessPolicy != nil {
			discovery.enabled = true
			discovery.requiresCompleteEntries = true
			discovery.fingerprint = fmt.Sprintf(
				"policy:%p",
				server.config.AccessPolicy,
			)
			return
		}
		var globalValues [][]byte
		discovery.err = server.config.Store.View(
			context.WithoutCancel(ctx),
			func(reader storage.Reader) error {
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
					values := entry.Values("olcAccess")
					if len(values) == 0 || len(entry.Values("olcSuffix")) != 0 {
						return nil
					}
					databaseName := ""
					if names := entry.Values("olcDatabase"); len(names) > 0 {
						databaseName = strings.ToLower(string(names[0]))
					}
					if strings.Contains(databaseName, "config") ||
						strings.Contains(databaseName, "monitor") {
						return nil
					}
					for _, value := range values {
						globalValues = append(globalValues, bytes.Clone(value))
					}
					return nil
				})
			},
		)
		if discovery.err != nil || len(globalValues) == 0 {
			return
		}
		enabled, attributes, complete, usesGroup, err :=
			loadLDAPBackendACLRequirements(globalValues)
		if err != nil {
			discovery.err = err
			return
		}
		discovery.enabled = discovery.enabled || enabled
		discovery.requiresCompleteEntries =
			discovery.requiresCompleteEntries || complete
		discovery.usesGroup = discovery.usesGroup || usesGroup
		discovery.entryAttributes = mergeLDAPBackendACLAttributes(
			discovery.entryAttributes,
			attributes,
		)
		discovery.sourceValues = append(
			discovery.sourceValues,
			cloneLDAPBackendACLValues(globalValues)...,
		)
		discovery.fingerprint = ldapBackendACLValuesFingerprint(
			discovery.sourceValues,
		)
	})
	return discovery.enabled, discovery.err
}

func cloneLDAPBackendACLValues(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index := range values {
		cloned[index] = bytes.Clone(values[index])
	}
	return cloned
}

func ldapBackendACLValuesFingerprint(values [][]byte) string {
	if len(values) == 0 {
		return ""
	}
	digest := sha256.New()
	var length [8]byte
	for _, value := range values {
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write(value)
	}
	return fmt.Sprintf("%x", digest.Sum(nil))
}

func ldapBackendACLPcacheKey(database runtimeDatabase, key string) string {
	if database.ldapBackend == nil || database.ldapBackend.aclDiscovery == nil {
		return key
	}
	discovery := database.ldapBackend.aclDiscovery
	if !discovery.enabled {
		return key
	}
	fingerprint := discovery.fingerprint
	if fingerprint == "" {
		fingerprint = "configured"
	}
	return key + "\x00back-ldap-acl:" + fingerprint
}

func mergeLDAPBackendACLAttributes(left, right []string) []string {
	merged := append([]string(nil), left...)
	seen := make(map[string]struct{}, len(merged))
	for _, attribute := range merged {
		seen[strings.ToLower(attribute)] = struct{}{}
	}
	for _, attribute := range right {
		key := strings.ToLower(attribute)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, attribute)
	}
	return merged
}

func (reader *ldapBackendACLReader) dnKey(dn directory.DN) string {
	if reader.state != nil && reader.state.runtime != nil && reader.state.runtime.schema != nil {
		if normalized, err := reader.state.runtime.schema.NormalizeDN(dn.String()); err == nil {
			return normalized.Key()
		}
	}
	return dn.Key()
}

func (server *Server) lookupLDAPBackendACLEntry(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	dn directory.DN,
	attributes []string,
	controls []ldapwire.Control,
) (directory.Entry, bool, ldapwire.ResultCode, error) {
	message := ldapwire.Message{
		ID: 1,
		Request: ldapwire.SearchRequest{
			BaseDN:       dn.String(),
			Scope:        directory.ScopeBase,
			DerefAliases: ldapwire.NeverDerefAliases,
			SizeLimit:    2,
			Filter: directory.Filter{
				Kind:      directory.FilterPresent,
				Attribute: "objectClass",
			},
			Attributes: append([]string(nil), attributes...),
		},
		Controls: cloneLDAPControls(controls),
	}
	lookupState := ldapBackendACLLookupState(state)
	var attempt chainAttempt
	defer clearSASLCredentialAttempt(&attempt)
	order := preferredProxyRemoteOrder(
		database.ldapBackend.preferred,
		len(database.ldapBackend.remotes),
	)
	for position, index := range order {
		configured := database.ldapBackend.remotes[index]
		for current := 0; current < ldapBackendRemoteAttempts(len(order)); current++ {
			attempt = server.executeLDAPBackendTarget(
				ctx,
				lookupState,
				*database.ldapBackend,
				ldapBackendACLRemote(configured),
				message,
			)
			if !ldapBackendShouldFailover(ctx, attempt) {
				break
			}
		}
		if attempt.connected {
			rememberPreferredProxyRemote(database.ldapBackend.preferred, index)
		}
		if !ldapBackendShouldFailover(ctx, attempt) || position == len(order)-1 {
			break
		}
	}
	if attempt.transportErr != nil {
		return directory.Entry{}, false, ldapwire.ResultUnavailable, attempt.transportErr
	}
	if !attempt.hasResult {
		return directory.Entry{}, false, ldapwire.ResultUnavailable,
			errors.New("back-ldap ACL lookup returned no LDAP result")
	}
	if attempt.result.Code != ldapwire.ResultSuccess {
		return directory.Entry{}, false, attempt.result.Code, nil
	}
	comparisonDN, err := state.runtime.schema.NormalizeDN(dn.String())
	if err != nil {
		return directory.Entry{}, false, ldapwire.ResultInvalidDNSyntax, err
	}
	var found *directory.Entry
	for _, packet := range attempt.packets {
		if metaPacketTag(packet) != ldapwire.ApplicationSearchResultEntry {
			continue
		}
		entry, decodeErr := decodeTranslucentSearchEntry(packet)
		if decodeErr != nil {
			return directory.Entry{}, false, ldapwire.ResultOther, decodeErr
		}
		entryDN, parseErr := state.runtime.schema.NormalizeDN(entry.DN)
		if parseErr != nil || !entryDN.Equal(comparisonDN) {
			return directory.Entry{}, false, ldapwire.ResultOther, fmt.Errorf(
				"back-ldap ACL lookup for %q returned unexpected entry %q",
				dn.String(),
				entry.DN,
			)
		}
		if found != nil {
			return directory.Entry{}, false, ldapwire.ResultOther, fmt.Errorf(
				"back-ldap ACL lookup for %q returned multiple entries",
				dn.String(),
			)
		}
		copy := entry
		found = &copy
	}
	if found == nil {
		return directory.Entry{}, false, ldapwire.ResultNoSuchObject, nil
	}
	return found.Clone(), true, ldapwire.ResultSuccess, nil
}

func ldapBackendACLRemote(
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

func ldapBackendACLLookupState(state *connectionState) *connectionState {
	return &connectionState{
		protocolVersion: state.protocolVersion,
		runtime:         state.runtime,
		secure:          state.secure,
		implicitTLS:     state.implicitTLS,
		listenerScheme:  state.listenerScheme,
		externalSSF:     state.externalSSF,
		transportSSF:    state.transportSSF,
		tlsSSF:          state.tlsSSF,
		saslSSF:         state.saslSSF,
		domainName:      state.domainName,
		externalDN:      state.externalDN,
	}
}
