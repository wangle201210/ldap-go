package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	"github.com/google/uuid"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	syncConsumerChangelogMetadataPrefix = "openldap/syncrepl/changelog/"
	syncConsumerPersistentSearchOID     = "2.16.840.1.113730.3.4.3"
	syncConsumerEntryChangeNoticeOID    = "2.16.840.1.113730.3.4.7"
)

var errSyncConsumerChangelogGap = errors.New(
	"DSEE changelog cannot be replayed safely",
)

type syncConsumerChangelogBounds struct {
	first uint64
	last  uint64
}

func (server *Server) runSyncConsumerChangelog(
	ctx context.Context,
	connection *ldap.Conn,
	config syncConsumerConfig,
	consumerMode syncConsumerMode,
) error {
	if config.logBase == nil {
		return errors.New("changelog search requires logbase")
	}
	bounds, err := readSyncConsumerChangelogBounds(connection, config)
	if err != nil {
		return err
	}
	lastChange, found, err := server.loadSyncConsumerChangelogState(ctx, config)
	if err != nil {
		return err
	}
	if !found || lastChange == 0 ||
		lastChange < bounds.first || lastChange > bounds.last {
		if err := server.runSyncConsumerChangelogSnapshot(
			ctx,
			connection,
			config,
			bounds.last,
		); err != nil {
			return fmt.Errorf("changelog fallback refresh: %w", err)
		}
		lastChange = bounds.last
	}

	err = server.runSyncConsumerChangelogSearch(
		ctx,
		connection,
		config,
		consumerMode,
		lastChange,
	)
	if err == nil || errors.Is(err, context.Canceled) {
		return err
	}
	if !errors.Is(err, errSyncConsumerChangelogGap) {
		return err
	}
	resetErr := server.resetSyncConsumerChangelogState(ctx, config)
	return errors.Join(
		err,
		resetErr,
	)
}

func readSyncConsumerChangelogBounds(
	connection *ldap.Conn,
	config syncConsumerConfig,
) (syncConsumerChangelogBounds, error) {
	connection.SetTimeout(config.operationTimeout)
	result, err := connection.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		config.timeLimit,
		false,
		"(objectClass=*)",
		[]string{"firstChangeNumber", "lastChangeNumber"},
		syncConsumerChangelogControls(config, false),
	))
	if err != nil {
		return syncConsumerChangelogBounds{}, fmt.Errorf(
			"read DSEE changelog bounds: %w",
			err,
		)
	}
	if len(result.Entries) != 1 {
		return syncConsumerChangelogBounds{}, fmt.Errorf(
			"DSEE root DSE returned %d entries, want 1",
			len(result.Entries),
		)
	}
	first, err := syncConsumerChangelogNumber(
		result.Entries[0],
		"firstChangeNumber",
	)
	if err != nil {
		return syncConsumerChangelogBounds{}, err
	}
	last, err := syncConsumerChangelogNumber(
		result.Entries[0],
		"lastChangeNumber",
	)
	if err != nil {
		return syncConsumerChangelogBounds{}, err
	}
	if first > last && last != 0 {
		return syncConsumerChangelogBounds{}, fmt.Errorf(
			"DSEE changelog bounds are inverted: first=%d last=%d",
			first,
			last,
		)
	}
	return syncConsumerChangelogBounds{first: first, last: last}, nil
}

func syncConsumerChangelogNumber(entry *ldap.Entry, description string) (uint64, error) {
	raw, err := syncConsumerAccesslogSingleValue(entry, description, true)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", description, raw, err)
	}
	return value, nil
}

func (server *Server) runSyncConsumerChangelogSnapshot(
	ctx context.Context,
	connection *ldap.Conn,
	config syncConsumerConfig,
	lastChange uint64,
) error {
	connection.SetTimeout(config.operationTimeout)
	request := ldap.NewSearchRequest(
		config.searchBase.String(),
		int(config.scope),
		ldap.NeverDerefAliases,
		config.sizeLimit,
		config.timeLimit,
		config.attributesOnly,
		config.filterText,
		syncConsumerChangelogSnapshotAttributes(config),
		syncConsumerChangelogControls(config, false),
	)
	response := connection.SearchAsync(ctx, request, syncConsumerResponseBuffer)
	seen := make(map[string]struct{})
	for response.Next() {
		source := response.Entry()
		if source == nil {
			continue
		}
		entry, err := syncConsumerChangelogSnapshotEntry(
			server.runtime.Load(),
			config,
			source,
		)
		if err != nil {
			return fmt.Errorf("map changelog snapshot entry %s: %w", source.DN, err)
		}
		dn, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		if err := server.config.Store.Update(ctx, func(writer storage.Writer) error {
			return writer.PutIn(config.partition, entry, true)
		}); err != nil {
			return fmt.Errorf("store changelog snapshot entry %s: %w", entry.DN, err)
		}
		seen[dn.Key()] = struct{}{}
	}
	if err := response.Err(); err != nil {
		return fmt.Errorf("DSEE snapshot search: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := connection.GetLastError(); err != nil {
		return fmt.Errorf("DSEE snapshot connection: %w", err)
	}
	return server.finishSyncConsumerChangelogSnapshot(
		ctx,
		config,
		seen,
		lastChange,
	)
}

func syncConsumerChangelogSnapshotAttributes(config syncConsumerConfig) []string {
	attributes := syncConsumerRequestedAttributes(config)
	if !slicesContainsEqualFold(attributes, "nsUniqueId") {
		attributes = append(attributes, "nsUniqueId")
	}
	return attributes
}

func slicesContainsEqualFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

func syncConsumerChangelogSnapshotEntry(
	runtime *runtimeState,
	config syncConsumerConfig,
	source *ldap.Entry,
) (directory.Entry, error) {
	if source == nil {
		return directory.Entry{}, errors.New("nil changelog snapshot entry")
	}
	identifier, err := syncConsumerDSEEEntryUUID(source)
	if err != nil {
		return directory.Entry{}, err
	}
	filtered := &ldap.Entry{DN: source.DN}
	for _, attribute := range source.Attributes {
		if strings.EqualFold(attribute.Name, "nsUniqueId") {
			continue
		}
		filtered.Attributes = append(filtered.Attributes, attribute)
	}
	state := &ldap.ControlSyncState{
		State:     ldap.SyncStateAdd,
		EntryUUID: identifier,
	}
	return syncConsumerDirectoryEntry(runtime, config, filtered, state)
}

func syncConsumerDSEEEntryUUID(source *ldap.Entry) (uuid.UUID, error) {
	values := source.GetEqualFoldRawAttributeValues("nsUniqueId")
	if len(values) == 0 {
		values = source.GetEqualFoldRawAttributeValues("entryUUID")
	}
	if len(values) != 1 {
		return uuid.Nil, fmt.Errorf(
			"DSEE entry %s must have one nsUniqueId or entryUUID, got %d",
			source.DN,
			len(values),
		)
	}
	return parseSyncConsumerDSEEUUID(string(values[0]))
}

func parseSyncConsumerDSEEUUID(value string) (uuid.UUID, error) {
	compact := strings.ReplaceAll(strings.TrimSpace(value), "-", "")
	if len(compact) != 32 {
		return uuid.Nil, fmt.Errorf("invalid DSEE UUID %q", value)
	}
	identifier, err := uuid.Parse(compact)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid DSEE UUID %q: %w", value, err)
	}
	return identifier, nil
}

func (server *Server) finishSyncConsumerChangelogSnapshot(
	ctx context.Context,
	config syncConsumerConfig,
	seen map[string]struct{},
	lastChange uint64,
) error {
	runtime := server.runtime.Load()
	return server.config.Store.Update(ctx, func(writer storage.Writer) error {
		var stale []directory.DN
		if err := writer.ForEachIn(config.partition, func(entry directory.Entry) error {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			if !directory.InScope(config.localBase, dn, config.scope) {
				return nil
			}
			if _, found := seen[dn.Key()]; found {
				return nil
			}
			matches, err := syncConsumerAccesslogEntryMatches(runtime, config, entry)
			if err != nil || !matches {
				return err
			}
			stale = append(stale, dn)
			return nil
		}); err != nil {
			return err
		}
		sort.Slice(stale, func(i, j int) bool {
			return stale[i].Depth() > stale[j].Depth()
		})
		for _, dn := range stale {
			if err := writer.DeleteIn(config.partition, dn); err != nil {
				return err
			}
		}
		return updateSyncConsumerChangelogState(writer, config, lastChange)
	})
}

func (server *Server) runSyncConsumerChangelogSearch(
	ctx context.Context,
	connection *ldap.Conn,
	config syncConsumerConfig,
	consumerMode syncConsumerMode,
	lastChange uint64,
) error {
	if lastChange == ^uint64(0) {
		return errors.New("DSEE changeNumber is exhausted")
	}
	connection.SetTimeout(config.operationTimeout)
	persistent := consumerMode == syncConsumerRefreshAndPersist
	if persistent {
		connection.SetTimeout(0)
	}
	request := ldap.NewSearchRequest(
		config.logBase.String(),
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		config.sizeLimit,
		config.timeLimit,
		false,
		fmt.Sprintf("(changeNumber>=%d)", lastChange+1),
		[]string{
			"targetDN",
			"changeType",
			"changes",
			"newRDN",
			"deleteOldRDN",
			"newSuperior",
			"targetUniqueId",
			"changeNumber",
		},
		syncConsumerChangelogControls(config, persistent),
	)
	response := connection.SearchAsync(ctx, request, syncConsumerResponseBuffer)
	for response.Next() {
		entry := response.Entry()
		if entry == nil {
			continue
		}
		if err := server.applySyncConsumerChangelogEntry(ctx, config, entry); err != nil {
			return fmt.Errorf(
				"%w: apply DSEE changelog entry %s: %v",
				errSyncConsumerChangelogGap,
				entry.DN,
				err,
			)
		}
	}
	if err := response.Err(); err != nil {
		return fmt.Errorf("DSEE changelog search: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := connection.GetLastError(); err != nil {
		return fmt.Errorf("DSEE changelog connection: %w", err)
	}
	return nil
}

func syncConsumerChangelogControls(
	config syncConsumerConfig,
	persistent bool,
) []ldap.Control {
	controls := []ldap.Control{ldap.NewControlManageDsaIT(true)}
	if config.authorizationID != "" {
		controls = append(controls, ldap.NewControlString(
			syncConsumerProxyAuthzOID,
			true,
			config.authorizationID,
		))
	}
	if persistent {
		value := ber.Encode(
			ber.ClassUniversal,
			ber.TypeConstructed,
			ber.TagSequence,
			nil,
			"Persistent Search",
		)
		value.AppendChild(ber.NewInteger(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagInteger,
			uint64(1),
			"changeTypes",
		))
		value.AppendChild(ber.NewBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			false,
			"changesOnly",
		))
		value.AppendChild(ber.NewBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"returnECs",
		))
		controls = append(controls, ldap.NewControlString(
			syncConsumerPersistentSearchOID,
			false,
			string(value.Bytes()),
		))
	}
	return controls
}

func (server *Server) applySyncConsumerChangelogEntry(
	ctx context.Context,
	config syncConsumerConfig,
	source *ldap.Entry,
) error {
	runtime := server.runtime.Load()
	operation, changeNumber, err := parseSyncConsumerChangelogOperation(
		runtime,
		config,
		source,
	)
	if err != nil {
		return err
	}
	return server.config.Store.Update(ctx, func(writer storage.Writer) error {
		current, found, err := readSyncConsumerChangelogState(writer, config)
		if err != nil {
			return err
		}
		if found && changeNumber <= current {
			return nil
		}
		if !found || changeNumber != current+1 {
			return fmt.Errorf(
				"changeNumber gap: current=%d incoming=%d",
				current,
				changeNumber,
			)
		}

		switch operation.kind {
		case syncConsumerAccesslogAdd:
			err = applySyncConsumerAccesslogAdd(runtime, writer, config, operation)
		case syncConsumerAccesslogDelete:
			err = applySyncConsumerAccesslogDelete(writer, config, operation)
		case syncConsumerAccesslogModify:
			err = applySyncConsumerAccesslogModify(runtime, writer, config, operation)
		case syncConsumerAccesslogModifyDN:
			err = applySyncConsumerAccesslogModifyDN(runtime, writer, config, operation)
		default:
			err = errors.New("unknown DSEE changelog operation")
		}
		if err != nil {
			return err
		}
		return updateSyncConsumerChangelogState(writer, config, changeNumber)
	})
}

func parseSyncConsumerChangelogOperation(
	runtime *runtimeState,
	config syncConsumerConfig,
	source *ldap.Entry,
) (syncConsumerAccesslogOperation, uint64, error) {
	if source == nil {
		return syncConsumerAccesslogOperation{}, 0, errors.New("nil changelog entry")
	}
	rawDN, err := syncConsumerAccesslogSingleValue(source, "targetDN", true)
	if err != nil {
		return syncConsumerAccesslogOperation{}, 0, err
	}
	remoteDN, err := directory.ParseDN(string(rawDN))
	if err != nil {
		return syncConsumerAccesslogOperation{}, 0, err
	}
	rawType, err := syncConsumerAccesslogSingleValue(source, "changeType", true)
	if err != nil {
		return syncConsumerAccesslogOperation{}, 0, err
	}
	var kind syncConsumerAccesslogOperationKind
	switch strings.ToLower(string(rawType)) {
	case "add":
		kind = syncConsumerAccesslogAdd
	case "delete":
		kind = syncConsumerAccesslogDelete
	case "modify":
		kind = syncConsumerAccesslogModify
	case "modrdn", "moddn":
		kind = syncConsumerAccesslogModifyDN
	default:
		return syncConsumerAccesslogOperation{}, 0, fmt.Errorf(
			"unknown changeType %q",
			rawType,
		)
	}
	changeNumber, err := syncConsumerChangelogNumber(source, "changeNumber")
	if err != nil {
		return syncConsumerAccesslogOperation{}, 0, err
	}
	modifications, err := parseSyncConsumerChangelogChanges(
		runtime,
		config,
		kind,
		source,
	)
	if err != nil {
		return syncConsumerAccesslogOperation{}, 0, err
	}
	operation := syncConsumerAccesslogOperation{
		kind:          kind,
		remoteDN:      remoteDN,
		modifications: modifications,
	}
	if kind != syncConsumerAccesslogModifyDN {
		return operation, changeNumber, nil
	}
	rawRDN, err := syncConsumerAccesslogSingleValue(source, "newRDN", true)
	if err != nil {
		return syncConsumerAccesslogOperation{}, 0, err
	}
	superior, ok := remoteDN.Parent()
	if !ok {
		return syncConsumerAccesslogOperation{}, 0, errors.New(
			"cannot rename the root DSE",
		)
	}
	rawSuperior, err := syncConsumerAccesslogSingleValue(
		source,
		"newSuperior",
		false,
	)
	if err != nil {
		return syncConsumerAccesslogOperation{}, 0, err
	}
	if rawSuperior != nil {
		superior, err = directory.ParseDN(string(rawSuperior))
		if err != nil {
			return syncConsumerAccesslogOperation{}, 0, err
		}
	}
	newRemoteDN, err := directory.ComposeDN(string(rawRDN), superior)
	if err != nil {
		return syncConsumerAccesslogOperation{}, 0, err
	}
	operation.newRemoteDN = &newRemoteDN
	rawDeleteOld, err := syncConsumerAccesslogSingleValue(
		source,
		"deleteOldRDN",
		false,
	)
	if err != nil {
		return syncConsumerAccesslogOperation{}, 0, err
	}
	if rawDeleteOld != nil {
		switch strings.ToLower(string(rawDeleteOld)) {
		case "true", "1":
			operation.deleteOldRDN = true
		case "false", "0":
		default:
			return syncConsumerAccesslogOperation{}, 0, fmt.Errorf(
				"invalid deleteOldRDN %q",
				rawDeleteOld,
			)
		}
	}
	return operation, changeNumber, nil
}

func parseSyncConsumerChangelogChanges(
	runtime *runtimeState,
	config syncConsumerConfig,
	kind syncConsumerAccesslogOperationKind,
	source *ldap.Entry,
) ([]syncConsumerAccesslogModification, error) {
	rawChanges, err := syncConsumerAccesslogSingleValue(source, "changes", false)
	if err != nil {
		return nil, err
	}
	if rawChanges == nil {
		if kind == syncConsumerAccesslogAdd || kind == syncConsumerAccesslogModify {
			return nil, errors.New("add or modify changelog entry has no changes value")
		}
		return nil, nil
	}
	var changeType string
	switch kind {
	case syncConsumerAccesslogAdd:
		changeType = "add"
	case syncConsumerAccesslogModify, syncConsumerAccesslogModifyDN:
		changeType = "modify"
	case syncConsumerAccesslogDelete:
		return nil, nil
	default:
		return nil, errors.New("unknown changelog changes type")
	}
	body := bytes.TrimSpace(rawChanges)
	if changeType == "modify" && !bytes.HasSuffix(body, []byte("-")) {
		body = append(bytes.Clone(body), '\n', '-')
	}
	document, err := ldif.Parse(
		"dn: cn=dsee-changelog-placeholder\nchangetype: " + changeType + "\n" +
			string(body) + "\n",
	)
	if err != nil {
		return nil, fmt.Errorf("parse changes LDIF: %w", err)
	}
	if len(document.Entries) != 1 {
		return nil, fmt.Errorf(
			"changes LDIF produced %d records, want 1",
			len(document.Entries),
		)
	}
	var result []syncConsumerAccesslogModification
	if changeType == "add" {
		request := document.Entries[0].Add
		if request == nil {
			return nil, errors.New("changes LDIF did not produce an add request")
		}
		for _, attribute := range request.Attributes {
			modification, keep, err := syncConsumerChangelogModification(
				runtime,
				config,
				attribute.Type,
				'+',
				attribute.Vals,
			)
			if err != nil {
				return nil, err
			}
			if keep {
				result = append(result, modification)
			}
		}
		rawUUID, err := syncConsumerAccesslogSingleValue(
			source,
			"targetUniqueId",
			false,
		)
		if err != nil {
			return nil, err
		}
		if rawUUID != nil && !syncConsumerChangelogHasAttribute(result, "entryUUID") {
			identifier, err := parseSyncConsumerDSEEUUID(string(rawUUID))
			if err != nil {
				return nil, err
			}
			result = append(result, syncConsumerAccesslogModification{
				description: "entryUUID",
				operation:   '+',
				values:      [][]byte{[]byte(identifier.String())},
			})
		}
		if len(result) == 0 {
			return nil, errors.New("add changelog entry has no usable attributes")
		}
		return result, nil
	}

	request := document.Entries[0].Modify
	if request == nil {
		return nil, errors.New("changes LDIF did not produce a modify request")
	}
	for _, change := range request.Changes {
		var operation byte
		switch change.Operation {
		case ldap.AddAttribute:
			operation = '+'
		case ldap.DeleteAttribute:
			operation = '-'
		case ldap.ReplaceAttribute:
			operation = '='
		case ldap.IncrementAttribute:
			operation = '#'
		default:
			return nil, fmt.Errorf(
				"unknown changes LDIF operation %d",
				change.Operation,
			)
		}
		modification, keep, err := syncConsumerChangelogModification(
			runtime,
			config,
			change.Modification.Type,
			operation,
			change.Modification.Vals,
		)
		if err != nil {
			return nil, err
		}
		if keep {
			result = append(result, modification)
		}
	}
	if kind == syncConsumerAccesslogModify && len(result) == 0 {
		return nil, errors.New("modify changelog entry has no usable changes")
	}
	return result, nil
}

func syncConsumerChangelogModification(
	runtime *runtimeState,
	config syncConsumerConfig,
	description string,
	operation byte,
	values []string,
) (syncConsumerAccesslogModification, bool, error) {
	if strings.EqualFold(description, "nsUniqueId") {
		return syncConsumerAccesslogModification{}, false, nil
	}
	if runtime != nil {
		if _, found := runtime.schema.AttributeType(description); !found {
			return syncConsumerAccesslogModification{}, false, fmt.Errorf(
				"changes references unknown attribute %q",
				description,
			)
		}
	}
	if syncConsumerAccesslogAttributeExcluded(runtime, config, description) {
		return syncConsumerAccesslogModification{}, false, nil
	}
	modification := syncConsumerAccesslogModification{
		description: description,
		operation:   operation,
		values:      make([][]byte, 0, len(values)),
	}
	for _, value := range values {
		raw := []byte(value)
		if config.suffixMap != nil && runtime != nil &&
			runtime.schema.IsDNValued(description) {
			mapped, err := mapSyncConsumerAttributeDN(config, raw)
			if err != nil {
				return syncConsumerAccesslogModification{}, false, fmt.Errorf(
					"map changes %s value: %w",
					description,
					err,
				)
			}
			raw = mapped
		}
		modification.values = append(modification.values, bytes.Clone(raw))
	}
	return modification, true, nil
}

func syncConsumerChangelogHasAttribute(
	modifications []syncConsumerAccesslogModification,
	description string,
) bool {
	for _, modification := range modifications {
		if strings.EqualFold(modification.description, description) {
			return true
		}
	}
	return false
}

func (server *Server) loadSyncConsumerChangelogState(
	ctx context.Context,
	config syncConsumerConfig,
) (uint64, bool, error) {
	var (
		value uint64
		found bool
	)
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		var err error
		value, found, err = readSyncConsumerChangelogState(reader, config)
		return err
	})
	return value, found, err
}

func readSyncConsumerChangelogState(
	reader storage.Reader,
	config syncConsumerConfig,
) (uint64, bool, error) {
	raw, err := reader.Metadata(syncConsumerChangelogMetadataKey(config))
	switch {
	case err == nil:
		value, parseErr := strconv.ParseUint(string(raw), 10, 64)
		if parseErr != nil {
			return 0, false, fmt.Errorf("parse stored lastChangeNumber: %w", parseErr)
		}
		return value, true, nil
	case !errors.Is(err, storage.ErrMetadataNotFound):
		return 0, false, err
	}
	entry, err := reader.GetIn(config.partition, config.localBase)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	values := entry.Values("lastChangeNumber")
	if len(values) == 0 {
		return 0, false, nil
	}
	if len(values) != 1 {
		return 0, false, fmt.Errorf(
			"replication context has %d lastChangeNumber values",
			len(values),
		)
	}
	value, err := strconv.ParseUint(string(values[0]), 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("parse context lastChangeNumber: %w", err)
	}
	return value, true, nil
}

func updateSyncConsumerChangelogState(
	writer storage.Writer,
	config syncConsumerConfig,
	value uint64,
) error {
	raw := []byte(strconv.FormatUint(value, 10))
	if err := writer.SetMetadata(syncConsumerChangelogMetadataKey(config), raw); err != nil {
		return err
	}
	entry, err := writer.GetIn(config.partition, config.localBase)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	entry.ReplaceValues("lastChangeNumber", [][]byte{bytes.Clone(raw)})
	return writer.PutIn(config.partition, entry, true)
}

func (server *Server) resetSyncConsumerChangelogState(
	ctx context.Context,
	config syncConsumerConfig,
) error {
	return server.config.Store.Update(ctx, func(writer storage.Writer) error {
		if err := writer.DeleteMetadata(syncConsumerChangelogMetadataKey(config)); err != nil &&
			!errors.Is(err, storage.ErrMetadataNotFound) {
			return err
		}
		entry, err := writer.GetIn(config.partition, config.localBase)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := entry.DeleteValues("lastChangeNumber", nil); err != nil &&
			!errors.Is(err, directory.ErrNoSuchAttribute) {
			return err
		}
		return writer.PutIn(config.partition, entry, true)
	})
}

func syncConsumerChangelogMetadataKey(config syncConsumerConfig) string {
	return strings.Replace(
		syncConsumerCookieMetadataKey(config),
		syncConsumerCookieMetadataPrefix,
		syncConsumerChangelogMetadataPrefix,
		1,
	)
}
