package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	syncConsumerCookieMetadataPrefix = "openldap/syncrepl/cookie/"
	syncConsumerProxyAuthzOID        = "2.16.840.1.113730.3.4.18"
	syncConsumerResponseBuffer       = 64
)

type syncConsumerRefreshState struct {
	seen     map[string]struct{}
	complete bool
}

type syncConsumerRetryCursor struct {
	policy []syncConsumerRetry
	index  int
	used   int
}

type syncConsumerDialResult struct {
	connection *ldap.Conn
	err        error
}

func (server *Server) runSyncConsumer(
	ctx context.Context,
	config syncConsumerConfig,
) {
	retry := syncConsumerRetryCursor{policy: config.retry}
	providerIndex := 0
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		provider := config.providerURLs[providerIndex%len(config.providerURLs)]
		providerIndex++
		err := server.runSyncConsumerCycle(ctx, config, provider)
		if ctx.Err() != nil {
			return
		}
		if err == nil && config.mode == syncConsumerRefreshOnly {
			retry = syncConsumerRetryCursor{policy: config.retry}
			if !waitSyncConsumer(ctx, config.interval) {
				return
			}
			continue
		}
		if err == nil {
			err = errors.New("refreshAndPersist stream ended")
		}

		delay, retryable := retry.next()
		if !retryable {
			server.config.Logger.Error(
				"syncrepl consumer stopped after retry policy was exhausted",
				"rid",
				fmt.Sprintf("%03d", config.rid),
				"provider",
				provider,
				"error",
				err,
			)
			return
		}
		server.config.Logger.Debug(
			"syncrepl consumer will retry",
			"rid",
			fmt.Sprintf("%03d", config.rid),
			"provider",
			provider,
			"delay",
			delay,
			"error",
			err,
		)
		if !waitSyncConsumer(ctx, delay) {
			return
		}
	}
}

func (server *Server) runSyncConsumerCycle(
	ctx context.Context,
	config syncConsumerConfig,
	provider string,
) error {
	if config.syncData != "default" {
		return fmt.Errorf("syncdata=%s is not implemented", config.syncData)
	}
	cookie, err := server.loadSyncConsumerCookie(ctx, config)
	if err != nil {
		return err
	}
	connection, err := dialSyncConsumer(ctx, config, provider)
	if err != nil {
		return err
	}
	defer connection.Close()

	stopClose := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			connection.Close()
		case <-stopClose:
		}
	}()
	defer close(stopClose)

	if config.operationTimeout > 0 {
		connection.SetTimeout(config.operationTimeout)
	}
	if config.startTLS != syncConsumerStartTLSOff {
		parsed, parseErr := url.Parse(provider)
		if parseErr != nil {
			return parseErr
		}
		if strings.EqualFold(parsed.Scheme, "ldaps") {
			return errors.New("starttls cannot be combined with an ldaps provider")
		}
		tlsConfig, tlsErr := buildSyncConsumerTLSConfig(config, parsed)
		if tlsErr != nil {
			return tlsErr
		}
		if startErr := connection.StartTLS(tlsConfig); startErr != nil {
			return fmt.Errorf("start TLS: %w", startErr)
		}
	}
	if err := bindSyncConsumer(connection, config, provider); err != nil {
		return err
	}

	controls := []ldap.Control{ldap.NewControlManageDsaIT(true)}
	if config.authorizationID != "" {
		controls = append(controls, ldap.NewControlString(
			syncConsumerProxyAuthzOID,
			true,
			config.authorizationID,
		))
	}
	request := ldap.NewSearchRequest(
		config.searchBase.String(),
		int(config.scope),
		ldap.NeverDerefAliases,
		config.sizeLimit,
		config.timeLimit,
		config.attributesOnly,
		config.filterText,
		syncConsumerRequestedAttributes(config),
		controls,
	)
	mode := ldap.SyncRequestModeRefreshOnly
	if config.mode == syncConsumerRefreshAndPersist {
		mode = ldap.SyncRequestModeRefreshAndPersist
	}
	response := connection.Syncrepl(
		ctx,
		request,
		syncConsumerResponseBuffer,
		mode,
		cookie,
		true,
	)
	refresh := syncConsumerRefreshState{seen: make(map[string]struct{})}
	for response.Next() {
		if err := server.processSyncConsumerResponse(
			ctx,
			config,
			&refresh,
			response.Entry(),
			response.Controls(),
		); err != nil {
			return err
		}
	}
	if err := response.Err(); err != nil {
		return fmt.Errorf("syncrepl search: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if config.mode == syncConsumerRefreshOnly && !refresh.complete {
		return errors.New("syncrepl refresh ended without Sync Done")
	}
	return nil
}

func (server *Server) processSyncConsumerResponse(
	ctx context.Context,
	config syncConsumerConfig,
	refresh *syncConsumerRefreshState,
	entry *ldap.Entry,
	controls []ldap.Control,
) error {
	if entry != nil {
		state, err := syncConsumerStateControl(controls)
		if err != nil {
			return err
		}
		if err := server.applySyncConsumerEntry(
			ctx,
			config,
			entry,
			state,
		); err != nil {
			return err
		}
		if state.State != ldap.SyncStateDelete {
			refresh.seen[state.EntryUUID.String()] = struct{}{}
		}
	}

	for _, control := range controls {
		switch typed := control.(type) {
		case *ldap.ControlSyncState:
			if entry == nil {
				return errors.New("Sync State control has no search entry")
			}
		case *ldap.ControlSyncDone:
			if err := server.finishSyncConsumerRefresh(
				ctx,
				config,
				refresh,
				typed.RefreshDeletes,
				typed.Cookie,
			); err != nil {
				return err
			}
		case *ldap.ControlSyncInfo:
			if err := server.processSyncConsumerInfo(
				ctx,
				config,
				refresh,
				typed,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func syncConsumerStateControl(
	controls []ldap.Control,
) (*ldap.ControlSyncState, error) {
	var state *ldap.ControlSyncState
	for _, control := range controls {
		typed, ok := control.(*ldap.ControlSyncState)
		if !ok {
			continue
		}
		if state != nil {
			return nil, errors.New("search entry has multiple Sync State controls")
		}
		state = typed
	}
	if state == nil {
		return nil, errors.New("syncrepl search entry has no Sync State control")
	}
	switch state.State {
	case ldap.SyncStatePresent,
		ldap.SyncStateAdd,
		ldap.SyncStateModify,
		ldap.SyncStateDelete:
	default:
		return nil, fmt.Errorf("unknown Sync State value %d", state.State)
	}
	return state, nil
}

func (server *Server) processSyncConsumerInfo(
	ctx context.Context,
	config syncConsumerConfig,
	refresh *syncConsumerRefreshState,
	info *ldap.ControlSyncInfo,
) error {
	switch info.Value {
	case ldap.SyncInfoNewcookie:
		if info.NewCookie == nil {
			return errors.New("newCookie Sync Info has no value")
		}
		return server.storeSyncConsumerCookie(
			ctx,
			config,
			info.NewCookie.Cookie,
		)
	case ldap.SyncInfoRefreshDelete:
		if info.RefreshDelete == nil {
			return errors.New("refreshDelete Sync Info has no value")
		}
		if info.RefreshDelete.RefreshDone {
			return server.finishSyncConsumerRefresh(
				ctx,
				config,
				refresh,
				true,
				info.RefreshDelete.Cookie,
			)
		}
		return server.storeSyncConsumerCookie(
			ctx,
			config,
			info.RefreshDelete.Cookie,
		)
	case ldap.SyncInfoRefreshPresent:
		if info.RefreshPresent == nil {
			return errors.New("refreshPresent Sync Info has no value")
		}
		if info.RefreshPresent.RefreshDone {
			return server.finishSyncConsumerRefresh(
				ctx,
				config,
				refresh,
				false,
				info.RefreshPresent.Cookie,
			)
		}
		return server.storeSyncConsumerCookie(
			ctx,
			config,
			info.RefreshPresent.Cookie,
		)
	case ldap.SyncInfoSyncIdSet:
		if info.SyncIdSet == nil {
			return errors.New("syncIdSet Sync Info has no value")
		}
		if info.SyncIdSet.RefreshDeletes {
			identifiers := make([]string, 0, len(info.SyncIdSet.SyncUUIDs))
			for _, identifier := range info.SyncIdSet.SyncUUIDs {
				identifiers = append(identifiers, identifier.String())
			}
			return server.deleteSyncConsumerUUIDs(
				ctx,
				config,
				identifiers,
				info.SyncIdSet.Cookie,
			)
		}
		for _, identifier := range info.SyncIdSet.SyncUUIDs {
			refresh.seen[identifier.String()] = struct{}{}
		}
		return server.storeSyncConsumerCookie(
			ctx,
			config,
			info.SyncIdSet.Cookie,
		)
	default:
		return fmt.Errorf("unknown Sync Info value %d", info.Value)
	}
}

func (server *Server) applySyncConsumerEntry(
	ctx context.Context,
	config syncConsumerConfig,
	source *ldap.Entry,
	state *ldap.ControlSyncState,
) error {
	if state.State == ldap.SyncStateDelete {
		return server.deleteSyncConsumerUUIDs(
			ctx,
			config,
			[]string{state.EntryUUID.String()},
			state.Cookie,
		)
	}

	runtime := server.runtime.Load()
	entry, err := syncConsumerDirectoryEntry(runtime, config, source, state)
	if err != nil {
		return err
	}
	return server.config.Store.Update(ctx, func(writer storage.Writer) error {
		existing, found, findErr := syncConsumerEntryByUUID(
			writer,
			config.partition,
			state.EntryUUID.String(),
		)
		if findErr != nil {
			return findErr
		}
		if found {
			existingDN, parseErr := directory.ParseDN(existing.DN)
			if parseErr != nil {
				return parseErr
			}
			nextDN, parseErr := directory.ParseDN(entry.DN)
			if parseErr != nil {
				return parseErr
			}
			if !existingDN.Equal(nextDN) {
				if deleteErr := writer.DeleteIn(
					config.partition,
					existingDN,
				); deleteErr != nil {
					return deleteErr
				}
			}
		}
		if err := writer.PutIn(config.partition, entry, true); err != nil {
			return err
		}
		return updateSyncConsumerCookie(writer, config, state.Cookie)
	})
}

func syncConsumerDirectoryEntry(
	runtime *runtimeState,
	config syncConsumerConfig,
	source *ldap.Entry,
	state *ldap.ControlSyncState,
) (directory.Entry, error) {
	if source == nil {
		return directory.Entry{}, errors.New("syncrepl entry is nil")
	}
	targetDN, err := mapSyncConsumerDN(config, source.DN)
	if err != nil {
		return directory.Entry{}, err
	}
	entry := directory.Entry{DN: targetDN.String()}
	for _, attribute := range source.Attributes {
		if syncConsumerAttributeExcluded(runtime, config, attribute.Name) {
			continue
		}
		values := make([][]byte, len(attribute.ByteValues))
		for index := range attribute.ByteValues {
			values[index] = bytes.Clone(attribute.ByteValues[index])
			if config.suffixMap != nil &&
				runtime != nil &&
				runtime.schema.IsDNValued(attribute.Name) {
				mapped, mapErr := mapSyncConsumerAttributeDN(
					config,
					values[index],
				)
				if mapErr != nil {
					return directory.Entry{}, fmt.Errorf(
						"map %s on %s: %w",
						attribute.Name,
						source.DN,
						mapErr,
					)
				}
				values[index] = mapped
			}
		}
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: attribute.Name,
			Values:      values,
		})
	}

	identifier := state.EntryUUID.String()
	entryUUIDValues := entry.Values("entryUUID")
	switch len(entryUUIDValues) {
	case 0:
		entry.ReplaceValues("entryUUID", [][]byte{[]byte(identifier)})
	case 1:
		parsed, parseErr := uuid.Parse(string(entryUUIDValues[0]))
		if parseErr != nil || parsed != state.EntryUUID {
			return directory.Entry{}, fmt.Errorf(
				"%s entryUUID does not match Sync State UUID %s",
				source.DN,
				identifier,
			)
		}
	default:
		return directory.Entry{}, fmt.Errorf(
			"%s has multiple entryUUID values",
			source.DN,
		)
	}
	if config.schemaChecking && runtime != nil {
		if err := runtime.schema.ValidateEntry(entry); err != nil {
			return directory.Entry{}, fmt.Errorf(
				"validate replicated entry %s: %w",
				entry.DN,
				err,
			)
		}
	}
	return entry, nil
}

func syncConsumerAttributeExcluded(
	runtime *runtimeState,
	config syncConsumerConfig,
	description string,
) bool {
	for _, excluded := range config.exAttributes {
		if runtime != nil &&
			runtime.schema.AttributeDescriptionSubtype(description, excluded) {
			return true
		}
		if strings.EqualFold(description, excluded) {
			return true
		}
	}
	return false
}

func mapSyncConsumerDN(
	config syncConsumerConfig,
	rawDN string,
) (directory.DN, error) {
	remote, err := directory.ParseDN(rawDN)
	if err != nil {
		return directory.DN{}, err
	}
	if !directory.InScope(config.searchBase, remote, config.scope) {
		return directory.DN{}, fmt.Errorf(
			"provider returned %q outside the configured replication scope",
			rawDN,
		)
	}
	if config.suffixMap == nil {
		return remote, nil
	}
	local, err := remote.ReplaceAncestor(config.searchBase, config.localBase)
	if err != nil {
		return directory.DN{}, fmt.Errorf("apply suffixmassage: %w", err)
	}
	return local, nil
}

func mapSyncConsumerAttributeDN(
	config syncConsumerConfig,
	value []byte,
) ([]byte, error) {
	remote, err := directory.ParseDN(string(value))
	if err != nil {
		return nil, err
	}
	if !config.searchBase.Equal(remote) &&
		!config.searchBase.AncestorOf(remote) {
		return bytes.Clone(value), nil
	}
	local, err := remote.ReplaceAncestor(config.searchBase, config.localBase)
	if err != nil {
		return nil, err
	}
	return []byte(local.String()), nil
}

func (server *Server) deleteSyncConsumerUUIDs(
	ctx context.Context,
	config syncConsumerConfig,
	identifiers []string,
	cookie []byte,
) error {
	wanted := make(map[string]struct{}, len(identifiers))
	for _, identifier := range identifiers {
		wanted[strings.ToLower(identifier)] = struct{}{}
	}
	return server.config.Store.Update(ctx, func(writer storage.Writer) error {
		var deleteDNs []directory.DN
		if err := writer.ForEachIn(
			config.partition,
			func(entry directory.Entry) error {
				values := entry.Values("entryUUID")
				if len(values) != 1 {
					return nil
				}
				if _, found := wanted[strings.ToLower(string(values[0]))]; !found {
					return nil
				}
				dn, err := directory.ParseDN(entry.DN)
				if err != nil {
					return err
				}
				deleteDNs = append(deleteDNs, dn)
				return nil
			},
		); err != nil {
			return err
		}
		for _, dn := range deleteDNs {
			if err := writer.DeleteIn(config.partition, dn); err != nil {
				return err
			}
		}
		return updateSyncConsumerCookie(writer, config, cookie)
	})
}

func (server *Server) finishSyncConsumerRefresh(
	ctx context.Context,
	config syncConsumerConfig,
	refresh *syncConsumerRefreshState,
	refreshDeletes bool,
	cookie []byte,
) error {
	if refresh.complete {
		return server.storeSyncConsumerCookie(ctx, config, cookie)
	}
	err := server.config.Store.Update(ctx, func(writer storage.Writer) error {
		if !refreshDeletes {
			runtime := server.runtime.Load()
			var deleteDNs []directory.DN
			if err := writer.ForEachIn(
				config.partition,
				func(entry directory.Entry) error {
					dn, err := directory.ParseDN(entry.DN)
					if err != nil {
						return err
					}
					if !directory.InScope(config.localBase, dn, config.scope) {
						return nil
					}
					matches, err := config.filter.MatchWith(
						entry,
						runtime.schema,
					)
					if err != nil || !matches {
						return err
					}
					values := entry.Values("entryUUID")
					if len(values) == 1 {
						identifier := strings.ToLower(string(values[0]))
						if _, present := refresh.seen[identifier]; present {
							return nil
						}
					}
					deleteDNs = append(deleteDNs, dn)
					return nil
				},
			); err != nil {
				return err
			}
			for _, dn := range deleteDNs {
				if err := writer.DeleteIn(config.partition, dn); err != nil {
					return err
				}
			}
		}
		return updateSyncConsumerCookie(writer, config, cookie)
	})
	if err != nil {
		return err
	}
	refresh.complete = true
	return nil
}

func (server *Server) loadSyncConsumerCookie(
	ctx context.Context,
	config syncConsumerConfig,
) ([]byte, error) {
	var cookie []byte
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		value, err := reader.Metadata(syncConsumerCookieMetadataKey(config))
		switch {
		case err == nil:
			cookie = bytes.Clone(value)
			return nil
		case errors.Is(err, storage.ErrMetadataNotFound):
			return nil
		default:
			return err
		}
	})
	if err != nil {
		return nil, fmt.Errorf("load syncrepl cookie: %w", err)
	}
	return cookie, nil
}

func (server *Server) storeSyncConsumerCookie(
	ctx context.Context,
	config syncConsumerConfig,
	cookie []byte,
) error {
	if len(cookie) == 0 {
		return nil
	}
	return server.config.Store.Update(ctx, func(writer storage.Writer) error {
		return updateSyncConsumerCookie(writer, config, cookie)
	})
}

func updateSyncConsumerCookie(
	writer storage.Writer,
	config syncConsumerConfig,
	cookie []byte,
) error {
	if len(cookie) == 0 {
		return nil
	}
	if err := writer.SetMetadata(
		syncConsumerCookieMetadataKey(config),
		cookie,
	); err != nil {
		return err
	}
	parsed := parseOpenLDAPSyncCookie(cookie)
	for _, csn := range parsed.csns {
		if err := advanceSyncContextCSN(writer, config.partition, csn); err != nil {
			return err
		}
	}
	return nil
}

func syncConsumerCookieMetadataKey(config syncConsumerConfig) string {
	partition := base64.RawURLEncoding.EncodeToString(
		[]byte(config.partition),
	)
	return fmt.Sprintf(
		"%s%s/%03d",
		syncConsumerCookieMetadataPrefix,
		partition,
		config.rid,
	)
}

func syncConsumerEntryByUUID(
	reader storage.Reader,
	partition string,
	identifier string,
) (directory.Entry, bool, error) {
	var (
		result directory.Entry
		found  bool
	)
	err := reader.ForEachIn(partition, func(entry directory.Entry) error {
		values := entry.Values("entryUUID")
		if len(values) != 1 ||
			!strings.EqualFold(string(values[0]), identifier) {
			return nil
		}
		if found {
			return fmt.Errorf(
				"entryUUID %s exists more than once in partition %q",
				identifier,
				partition,
			)
		}
		result = entry
		found = true
		return nil
	})
	return result, found, err
}

func syncConsumerRequestedAttributes(config syncConsumerConfig) []string {
	attributes := append([]string(nil), config.attributes...)
	requiredAttributes := []struct {
		description string
		wildcard    string
	}{
		{description: "objectClass", wildcard: "*"},
		{description: "structuralObjectClass", wildcard: "+"},
		{description: "entryCSN", wildcard: "+"},
		{description: "entryUUID", wildcard: "+"},
	}
	for _, required := range requiredAttributes {
		if !slices.ContainsFunc(attributes, func(value string) bool {
			return strings.EqualFold(value, required.description) ||
				strings.EqualFold(value, required.wildcard)
		}) {
			attributes = append(attributes, required.description)
		}
	}
	return attributes
}

func bindSyncConsumer(
	connection *ldap.Conn,
	config syncConsumerConfig,
	provider string,
) error {
	switch config.bindMethod {
	case "simple":
		if config.bindDN == "" && len(config.credentials) == 0 {
			return nil
		}
		if err := connection.Bind(
			config.bindDN,
			string(config.credentials),
		); err != nil {
			return fmt.Errorf("simple bind: %w", err)
		}
		return nil
	case "sasl":
		switch strings.ToUpper(config.saslMechanism) {
		case "EXTERNAL":
			if err := connection.ExternalBind(); err != nil {
				return fmt.Errorf("SASL EXTERNAL bind: %w", err)
			}
			return nil
		case "DIGEST-MD5":
			parsed, err := url.Parse(provider)
			if err != nil {
				return err
			}
			_, err = connection.DigestMD5Bind(&ldap.DigestMD5BindRequest{
				Host:     parsed.Hostname(),
				Username: config.authenticationID,
				Password: string(config.credentials),
			})
			if err != nil {
				return fmt.Errorf("SASL DIGEST-MD5 bind: %w", err)
			}
			return nil
		default:
			return fmt.Errorf(
				"SASL mechanism %q is not implemented",
				config.saslMechanism,
			)
		}
	default:
		return fmt.Errorf("unknown bind method %q", config.bindMethod)
	}
}

func dialSyncConsumer(
	ctx context.Context,
	config syncConsumerConfig,
	provider string,
) (*ldap.Conn, error) {
	parsed, err := url.Parse(provider)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := buildSyncConsumerTLSConfig(config, parsed)
	if err != nil {
		return nil, err
	}
	if config.tcpUserTimeout > 0 {
		return nil, errors.New("tcp-user-timeout is not implemented")
	}

	timeout := config.networkTimeout
	if timeout <= 0 {
		timeout = ldap.DefaultTimeout
	}
	dialer := &net.Dialer{Timeout: timeout}
	if config.keepalive.set {
		dialer.KeepAlive = time.Duration(config.keepalive.interval) * time.Second
	}
	result := make(chan syncConsumerDialResult)
	go func() {
		connection, dialErr := ldap.DialURL(
			provider,
			ldap.DialWithDialer(dialer),
			ldap.DialWithTLSConfig(tlsConfig),
		)
		select {
		case result <- syncConsumerDialResult{
			connection: connection,
			err:        dialErr,
		}:
		case <-ctx.Done():
			if connection != nil {
				connection.Close()
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case dialed := <-result:
		if dialed.err != nil {
			return nil, fmt.Errorf("connect to %s: %w", provider, dialed.err)
		}
		return dialed.connection, nil
	}
}

func buildSyncConsumerTLSConfig(
	config syncConsumerConfig,
	provider *url.URL,
) (*tls.Config, error) {
	if config.tls.cipherSuite != "" {
		return nil, errors.New("tls_cipher_suite is not implemented")
	}
	if config.tls.ecName != "" {
		return nil, errors.New("tls_ecname is not implemented")
	}
	if config.tls.crlCheck != "" && config.tls.crlCheck != "none" {
		return nil, errors.New("TLS CRL checking is not implemented")
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: provider.Hostname(),
	}
	switch config.tls.requireCert {
	case "never", "allow":
		// OpenLDAP permits an unverified peer for these policies.
		tlsConfig.InsecureSkipVerify = true
	}
	if config.tls.protocolMinimum != "" {
		version, err := parseSyncConsumerTLSVersion(
			config.tls.protocolMinimum,
		)
		if err != nil {
			return nil, err
		}
		tlsConfig.MinVersion = version
	}
	if config.tls.caCertificate != "" || config.tls.caDirectory != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if config.tls.caCertificate != "" {
			if err := appendSyncConsumerCAFile(
				roots,
				config.tls.caCertificate,
			); err != nil {
				return nil, err
			}
		}
		if config.tls.caDirectory != "" {
			entries, err := os.ReadDir(config.tls.caDirectory)
			if err != nil {
				return nil, fmt.Errorf("read TLS CA directory: %w", err)
			}
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				path := filepath.Join(config.tls.caDirectory, entry.Name())
				if err := appendSyncConsumerCAFile(roots, path); err != nil {
					continue
				}
			}
		}
		tlsConfig.RootCAs = roots
	}
	if config.tls.certificateFile != "" || config.tls.keyFile != "" {
		if config.tls.certificateFile == "" || config.tls.keyFile == "" {
			return nil, errors.New(
				"tls_cert and tls_key must be configured together",
			)
		}
		certificate, err := tls.LoadX509KeyPair(
			config.tls.certificateFile,
			config.tls.keyFile,
		)
		if err != nil {
			return nil, fmt.Errorf("load syncrepl TLS certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	return tlsConfig, nil
}

func appendSyncConsumerCAFile(pool *x509.CertPool, path string) error {
	pem, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read TLS CA file %q: %w", path, err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("TLS CA file %q contains no certificates", path)
	}
	return nil
}

func parseSyncConsumerTLSVersion(value string) (uint16, error) {
	switch value {
	case "1", "1.0", "3.1":
		return tls.VersionTLS10, nil
	case "1.1", "3.2":
		return tls.VersionTLS11, nil
	case "1.2", "3.3":
		return tls.VersionTLS12, nil
	case "1.3", "3.4":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unknown tls_protocol_min value %q", value)
	}
}

func (cursor *syncConsumerRetryCursor) next() (time.Duration, bool) {
	for cursor.index < len(cursor.policy) {
		current := cursor.policy[cursor.index]
		if current.attempts < 0 {
			return current.interval, true
		}
		if cursor.used < current.attempts {
			cursor.used++
			return current.interval, true
		}
		cursor.index++
		cursor.used = 0
	}
	return 0, false
}

func waitSyncConsumer(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
