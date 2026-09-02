package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type relayRuntimeConfiguration struct {
	targetSuffix        *directory.DN
	targetDatabaseIndex int
}

type rwmSuffixMapping struct {
	local  directory.DN
	remote directory.DN
}

type rwmRuntimeConfiguration struct {
	suffix                *rwmSuffixMapping
	attributesToRemote    map[string]string
	attributesToLocal     map[string]string
	attributesDropMissing bool
	classesToRemote       map[string]string
	classesToLocal        map[string]string
	classesDropMissing    bool
	schema                *schema.Registry
}

func loadRelayRuntimeConfiguration(
	entry directory.Entry,
	database runtimeDatabase,
) (*relayRuntimeConfiguration, error) {
	if len(database.suffixes) != 1 {
		return nil, fmt.Errorf(
			"%s relay database requires exactly one olcSuffix",
			entry.DN,
		)
	}
	values := entry.Values("olcRelay")
	if len(values) > 1 {
		return nil, fmt.Errorf("%s olcRelay must be single-valued", entry.DN)
	}
	configuration := &relayRuntimeConfiguration{targetDatabaseIndex: -1}
	if len(values) == 0 {
		return configuration, nil
	}
	target, err := parseRuntimeDN(string(values[0]), database.dnNormalizer)
	if err != nil || target.Depth() == 0 {
		return nil, fmt.Errorf("%s olcRelay has invalid DN %q", entry.DN, values[0])
	}
	configuration.targetSuffix = &target
	return configuration, nil
}

func loadRWMRuntimeConfiguration(
	entry directory.Entry,
	database runtimeDatabase,
) (rwmRuntimeConfiguration, error) {
	configuration := rwmRuntimeConfiguration{
		attributesToRemote: make(map[string]string),
		attributesToLocal:  make(map[string]string),
		classesToRemote:    make(map[string]string),
		classesToLocal:     make(map[string]string),
	}
	for _, raw := range entry.Values("olcRwmRewrite") {
		value, err := stripRWMOrderingPrefix(string(raw))
		if err != nil {
			return rwmRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRwmRewrite: %w",
				entry.DN,
				err,
			)
		}
		words, err := splitRWMConfigurationWords(value)
		if err != nil {
			return rwmRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRwmRewrite: %w",
				entry.DN,
				err,
			)
		}
		if len(words) == 0 {
			return rwmRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRwmRewrite contains an empty unsupported rewrite directive; only suffixmassage is supported (map uses olcRwmMap)",
				entry.DN,
			)
		}
		if !strings.EqualFold(words[0], "rwm-suffixmassage") &&
			!strings.EqualFold(words[0], "suffixmassage") {
			return rwmRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRwmRewrite contains unsupported rewrite directive %q; only suffixmassage is supported (map uses olcRwmMap)",
				entry.DN,
				words[0],
			)
		}
		if configuration.suffix != nil {
			return rwmRuntimeConfiguration{}, fmt.Errorf(
				"%s configures multiple rwm suffixmassage directives",
				entry.DN,
			)
		}
		var localRaw, remoteRaw string
		switch len(words) {
		case 2:
			if len(database.suffixes) == 0 {
				return rwmRuntimeConfiguration{}, fmt.Errorf(
					"%s rwm suffixmassage requires a database suffix",
					entry.DN,
				)
			}
			localRaw = database.suffixes[0].String()
			remoteRaw = words[1]
		case 3:
			localRaw = words[1]
			remoteRaw = words[2]
		default:
			return rwmRuntimeConfiguration{}, fmt.Errorf(
				"%s rwm suffixmassage expects [local] remote DN",
				entry.DN,
			)
		}
		local, err := parseRuntimeDN(localRaw, database.dnNormalizer)
		if err != nil || local.Depth() == 0 {
			return rwmRuntimeConfiguration{}, fmt.Errorf(
				"%s rwm suffixmassage has invalid local DN %q",
				entry.DN,
				localRaw,
			)
		}
		if !databaseOwnsSuffix(database, local) {
			return rwmRuntimeConfiguration{}, fmt.Errorf(
				"%s rwm suffixmassage local DN %q is not a database suffix",
				entry.DN,
				localRaw,
			)
		}
		remote, err := parseRuntimeDN(remoteRaw, database.dnNormalizer)
		if err != nil || remote.Depth() == 0 {
			return rwmRuntimeConfiguration{}, fmt.Errorf(
				"%s rwm suffixmassage has invalid remote DN %q",
				entry.DN,
				remoteRaw,
			)
		}
		configuration.suffix = &rwmSuffixMapping{local: local, remote: remote}
	}

	for _, raw := range entry.Values("olcRwmMap") {
		value, err := stripRWMOrderingPrefix(string(raw))
		if err != nil {
			return rwmRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRwmMap: %w",
				entry.DN,
				err,
			)
		}
		words, err := splitRWMConfigurationWords(value)
		if err != nil {
			return rwmRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRwmMap: %w",
				entry.DN,
				err,
			)
		}
		if len(words) > 0 && strings.EqualFold(words[0], "rwm-map") {
			words = words[1:]
		}
		if err := applyRWMMapDirective(&configuration, words); err != nil {
			return rwmRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRwmMap: %w",
				entry.DN,
				err,
			)
		}
	}
	return configuration, nil
}

func applyRWMMapDirective(
	configuration *rwmRuntimeConfiguration,
	words []string,
) error {
	if len(words) != 2 && len(words) != 3 {
		return errors.New("expects type, local name, and optional remote name")
	}

	var (
		forward     map[string]string
		reverse     map[string]string
		dropMissing *bool
		attribute   bool
	)
	switch strings.ToLower(strings.TrimSpace(words[0])) {
	case "attribute":
		forward = configuration.attributesToRemote
		reverse = configuration.attributesToLocal
		dropMissing = &configuration.attributesDropMissing
		attribute = true
		if len(forward) == 0 && len(reverse) == 0 {
			if err := addRWMMapping(forward, reverse, "objectClass", "objectClass"); err != nil {
				return err
			}
		}
	case "objectclass":
		forward = configuration.classesToRemote
		reverse = configuration.classesToLocal
		dropMissing = &configuration.classesDropMissing
	default:
		return fmt.Errorf("unknown map type %q", words[0])
	}

	local := strings.TrimSpace(words[1])
	if local == "" {
		return errors.New("local name must not be empty")
	}
	if local == "*" {
		if len(words) == 2 || strings.TrimSpace(words[2]) == "*" {
			*dropMissing = len(words) == 2
			return nil
		}
		local = strings.TrimSpace(words[2])
		return addValidatedRWMMapping(forward, reverse, local, local, attribute)
	}

	if len(words) == 2 {
		return addValidatedRWMMapping(forward, reverse, "", local, attribute)
	}
	remote := strings.TrimSpace(words[2])
	if remote == "*" {
		remote = local
	}
	return addValidatedRWMMapping(forward, reverse, local, remote, attribute)
}

func addValidatedRWMMapping(
	forward map[string]string,
	reverse map[string]string,
	local string,
	remote string,
	attribute bool,
) error {
	if remote == "" {
		return errors.New("remote name must not be empty")
	}
	if attribute && (strings.EqualFold(local, "objectClass") ||
		strings.EqualFold(remote, "objectClass")) {
		return errors.New("objectClass attribute cannot be mapped")
	}
	return addRWMMapping(forward, reverse, local, remote)
}

func addRWMMapping(
	forward map[string]string,
	reverse map[string]string,
	local,
	remote string,
) error {
	localKey := strings.ToLower(local)
	remoteKey := strings.ToLower(remote)
	if local != "" {
		if existing, ok := forward[localKey]; ok && !strings.EqualFold(existing, remote) {
			return fmt.Errorf("duplicate mapping for %q", local)
		}
	}
	if existing, ok := reverse[remoteKey]; ok && !strings.EqualFold(existing, local) {
		return fmt.Errorf("reverse mapping for %q is ambiguous", remote)
	}
	if local != "" {
		forward[localKey] = remote
	}
	reverse[remoteKey] = local
	return nil
}

func stripRWMOrderingPrefix(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{") {
		return value, nil
	}
	end := strings.IndexByte(value, '}')
	if end < 2 {
		return "", errors.New("invalid ordered-value prefix")
	}
	for _, character := range value[1:end] {
		if !unicode.IsDigit(character) {
			return "", errors.New("invalid ordered-value prefix")
		}
	}
	return strings.TrimSpace(value[end+1:]), nil
}

func splitRWMConfigurationWords(value string) ([]string, error) {
	var (
		words   []string
		current strings.Builder
		quote   rune
		escaped bool
		started bool
	)
	flush := func() {
		if !started {
			return
		}
		words = append(words, current.String())
		current.Reset()
		started = false
	}
	for _, character := range value {
		switch {
		case escaped:
			current.WriteRune(character)
			escaped = false
			started = true
		case character == '\\':
			escaped = true
			started = true
		case quote != 0:
			if character == quote {
				quote = 0
			} else {
				current.WriteRune(character)
			}
			started = true
		case character == '\'' || character == '"':
			quote = character
			started = true
		case unicode.IsSpace(character):
			flush()
		default:
			current.WriteRune(character)
			started = true
		}
	}
	if escaped || quote != 0 {
		return nil, errors.New("unterminated quote or escape")
	}
	flush()
	return words, nil
}

func resolveRelayDatabases(databases []runtimeDatabase) error {
	for index := range databases {
		database := &databases[index]
		if !isRelayDatabase(*database) || database.relay == nil {
			continue
		}
		var targetDN *directory.DN
		if database.relay.targetSuffix != nil {
			targetDN = database.relay.targetSuffix
		} else if database.rwm != nil && database.rwm.suffix != nil {
			targetDN = &database.rwm.suffix.remote
		}
		if targetDN == nil {
			continue
		}
		targetIndex := databaseIndexForRelayTarget(databases, index, *targetDN)
		if targetIndex < 0 {
			if database.relay.targetSuffix == nil {
				continue
			}
			return fmt.Errorf(
				"%s olcRelay target %q has no configured database",
				database.name,
				targetDN.String(),
			)
		}
		if isRelayDatabase(databases[targetIndex]) {
			return fmt.Errorf(
				"%s relay target %q resolves to another relay database",
				database.name,
				targetDN.String(),
			)
		}
		if database.rwm != nil && database.rwm.suffix != nil &&
			!dnWithinAnySuffix(databases[targetIndex], database.rwm.suffix.remote) {
			return fmt.Errorf(
				"%s rwm remote suffix %q is outside relay target database %s",
				database.name,
				database.rwm.suffix.remote.String(),
				databases[targetIndex].name,
			)
		}
		database.relay.targetDatabaseIndex = targetIndex
		database.partition = databases[targetIndex].partition
		inheritRelayBackendFeatures(database, databases[targetIndex])
	}
	return nil
}

func inheritRelayBackendFeatures(relay *runtimeDatabase, target runtimeDatabase) {
	relay.lastMod = target.lastMod
	relay.lastBind = target.lastBind
	relay.lastBindPrecision = target.lastBindPrecision
	relay.maxDerefDepth = target.maxDerefDepth
	relay.serverSideSort = target.serverSideSort
	relay.sortMaxKeys = target.sortMaxKeys
	relay.sortLimiter = target.sortLimiter
	relay.syncProvider = target.syncProvider
	relay.syncCheckpointOps = target.syncCheckpointOps
	relay.syncCheckpointMinutes = target.syncCheckpointMinutes
	relay.syncSessionLogSize = target.syncSessionLogSize
	relay.syncNoPresent = target.syncNoPresent
	relay.syncReloadHint = target.syncReloadHint
	relay.nullBindAllowed = target.nullBindAllowed
	relay.nullDoSearch = target.nullDoSearch
	if relay.dds == nil {
		relay.dds = target.dds
	}
	if relay.ppolicy == nil {
		relay.ppolicy = target.ppolicy
	}
	if relay.chain == nil {
		relay.chain = target.chain
	}
	if relay.constraint == nil {
		relay.constraint = target.constraint
	}
	if relay.unique == nil {
		relay.unique = target.unique
	}
	if relay.valueSort == nil {
		relay.valueSort = target.valueSort
	}
	relay.retcodes = append(relay.retcodes, target.retcodes...)
	relay.memberOf = append(relay.memberOf, target.memberOf...)
	relay.refint = append(relay.refint, target.refint...)
}

func databaseIndexForRelayTarget(
	databases []runtimeDatabase,
	excluded int,
	dn directory.DN,
) int {
	bestIndex := -1
	bestDepth := -1
	for index := range databases {
		if index == excluded || databases[index].hidden || databases[index].disabled {
			continue
		}
		for _, suffix := range databases[index].suffixes {
			if !databaseDNAtOrBelow(databases[index], dn, suffix) {
				continue
			}
			if suffix.Depth() > bestDepth {
				bestIndex = index
				bestDepth = suffix.Depth()
			}
		}
	}
	return bestIndex
}

func dnWithinAnySuffix(database runtimeDatabase, dn directory.DN) bool {
	for _, suffix := range database.suffixes {
		if databaseDNAtOrBelow(database, dn, suffix) {
			return true
		}
	}
	return false
}

func databaseAuthenticationRoot(
	runtime *runtimeState,
	database runtimeDatabase,
	dn directory.DN,
) ([]byte, bool) {
	if database.rootDN != nil &&
		databaseDNEqual(database, *database.rootDN, dn) &&
		database.rootPasswordSet {
		return database.rootPassword, true
	}
	if runtime == nil || database.relay == nil {
		return nil, false
	}
	targetIndex := database.relay.targetDatabaseIndex
	if targetIndex < 0 || targetIndex >= len(runtime.databases) {
		return nil, false
	}
	remoteDN, err := normalizeRuntimeDatabaseDN(database, dn)
	if err != nil {
		return nil, false
	}
	if database.rwm != nil {
		remoteDN, err = database.rwm.mapDNToRemote(dn)
		if err != nil {
			return nil, false
		}
	}
	target := runtime.databases[targetIndex]
	if target.rootDN == nil ||
		!databaseDNEqual(target, *target.rootDN, remoteDN) ||
		!target.rootPasswordSet {
		return nil, false
	}
	return target.rootPassword, true
}

func databaseRootMatches(
	runtime *runtimeState,
	database runtimeDatabase,
	dn directory.DN,
) bool {
	if database.rootDN != nil && databaseDNEqual(database, *database.rootDN, dn) {
		return true
	}
	if runtime == nil || database.relay == nil {
		return false
	}
	targetIndex := database.relay.targetDatabaseIndex
	if targetIndex < 0 || targetIndex >= len(runtime.databases) {
		return false
	}
	target := runtime.databases[targetIndex]
	if target.rootDN == nil {
		return false
	}
	if databaseDNEqual(target, *target.rootDN, dn) {
		return true
	}
	if database.rwm == nil {
		return false
	}
	remoteDN, err := database.rwm.mapDNToRemote(dn)
	return err == nil && databaseDNEqual(target, *target.rootDN, remoteDN)
}

func databaseUsesNullBackend(runtime *runtimeState, database runtimeDatabase) bool {
	if isNullDatabase(database) {
		return true
	}
	if runtime == nil || database.relay == nil {
		return false
	}
	index := database.relay.targetDatabaseIndex
	return index >= 0 && index < len(runtime.databases) &&
		isNullDatabase(runtime.databases[index])
}

func readerForDatabase(
	reader storage.Reader,
	database runtimeDatabase,
	contexts ...context.Context,
) storage.Reader {
	if database.sqlBackend != nil {
		ctx := context.Background()
		if len(contexts) != 0 && contexts[0] != nil {
			ctx = contexts[0]
		} else if provider, ok := reader.(interface {
			StorageContext() context.Context
		}); ok && provider.StorageContext() != nil {
			ctx = provider.StorageContext()
		}
		var backend *sqlBackendReader
		if coordinator := sqlBackendReadCoordinatorFromContext(ctx); coordinator != nil {
			backend = coordinator.reader(database.sqlBackend, reader, ctx)
		} else {
			backend = &sqlBackendReader{
				Reader:        reader,
				configuration: database.sqlBackend,
				ctx:           ctx,
			}
		}
		if database.rwm == nil {
			return backend
		}
		return &rwmStorageReader{Reader: backend, configuration: database.rwm}
	}
	partitioned := storage.ReaderInPartition(reader, database.partition)
	if database.dnNormalizer != nil && databaseUsesSchemaAwareContentStorage(database) {
		partitioned = storage.ReaderInPartitionWithNormalizerLegacy(
			reader,
			database.partition,
			database.dnNormalizer,
		)
	}
	if database.rwm == nil {
		return partitioned
	}
	return &rwmStorageReader{Reader: partitioned, configuration: database.rwm}
}

func writerForDatabase(
	writer storage.Writer,
	database runtimeDatabase,
) storage.Writer {
	if database.sqlBackend != nil {
		ctx := context.Background()
		if provider, ok := writer.(interface {
			StorageContext() context.Context
		}); ok && provider.StorageContext() != nil {
			ctx = provider.StorageContext()
		}
		if coordinator := sqlBackendTransactionCoordinatorFromContext(ctx); coordinator != nil {
			backend := coordinator.writer(database.sqlBackend, writer)
			if database.rwm == nil {
				return backend
			}
			mappedReader := &rwmStorageReader{Reader: backend, configuration: database.rwm}
			return &rwmStorageWriter{
				rwmStorageReader: mappedReader,
				writer:           backend,
			}
		}
		reader := &sqlBackendReader{
			Reader:        writer,
			configuration: database.sqlBackend,
			ctx:           ctx,
		}
		backend := &sqlBackendWriter{Writer: writer, reader: reader}
		if database.rwm == nil {
			return backend
		}
		mappedReader := &rwmStorageReader{Reader: backend, configuration: database.rwm}
		return &rwmStorageWriter{
			rwmStorageReader: mappedReader,
			writer:           backend,
		}
	}
	partitioned := storage.WriterInPartition(writer, database.partition)
	if database.dnNormalizer != nil && databaseUsesSchemaAwareContentStorage(database) {
		partitioned = storage.WriterInPartitionWithNormalizerLegacy(
			writer,
			database.partition,
			database.dnNormalizer,
		)
	}
	if database.rwm == nil {
		return partitioned
	}
	reader := &rwmStorageReader{Reader: partitioned, configuration: database.rwm}
	return &rwmStorageWriter{
		rwmStorageReader: reader,
		writer:           partitioned,
	}
}

type rwmStorageReader struct {
	storage.Reader
	configuration *rwmRuntimeConfiguration
}

func (reader *rwmStorageReader) StorageSnapshotRevision() (uint64, bool) {
	if reader == nil {
		return 0, false
	}
	return storage.ReaderSnapshotRevision(reader.Reader)
}

func (reader *rwmStorageReader) NormalizeDNIdentity(
	dn directory.DN,
) (directory.DN, error) {
	if _, ok := reader.Reader.(interface {
		NormalizeDNIdentity(directory.DN) (directory.DN, error)
	}); !ok {
		return dn, nil
	}
	remote, err := reader.configuration.mapDNToRemote(dn)
	if err != nil {
		return directory.DN{}, err
	}
	remote, err = storage.NormalizeReaderDN(reader.Reader, remote)
	if err != nil {
		return directory.DN{}, err
	}
	return reader.configuration.mapDNToLocal(remote)
}

func (reader *rwmStorageReader) DNIdentityOrderKey(
	dn directory.DN,
) (string, error) {
	if _, ok := reader.Reader.(interface {
		DNIdentityOrderKey(directory.DN) (string, error)
	}); !ok {
		return dn.Key(), nil
	}
	remote, err := reader.configuration.mapDNToRemote(dn)
	if err != nil {
		return "", err
	}
	return storage.ReaderDNOrderKey(reader.Reader, remote)
}

func (reader *rwmStorageReader) AccessContext() any {
	if provider, ok := reader.Reader.(interface{ AccessContext() any }); ok {
		return provider.AccessContext()
	}
	return nil
}

func (reader *rwmStorageReader) remoteACLIdentity(subjectDN string) (string, error) {
	if subjectDN == "" {
		return "", nil
	}
	subject, err := directory.ParseDN(subjectDN)
	if err != nil {
		return subjectDN, nil
	}
	mapped, err := reader.configuration.mapDNToRemote(subject)
	if err != nil {
		return "", err
	}
	return mapped.String(), nil
}

func (reader *rwmStorageReader) remoteACLView(
	subjectDN string,
	entry directory.Entry,
	attribute string,
	value []byte,
) (storage.Reader, string, directory.Entry, string, []byte, error) {
	remoteEntry, err := reader.configuration.mapEntryToRemote(entry)
	if err != nil {
		return nil, "", directory.Entry{}, "", nil, err
	}
	remoteSubject := subjectDN
	if subjectDN != "" {
		if subject, parseErr := directory.ParseDN(subjectDN); parseErr == nil {
			subject, err = reader.configuration.mapDNToRemote(subject)
			if err != nil {
				return nil, "", directory.Entry{}, "", nil, err
			}
			remoteSubject = subject.String()
		}
	}
	remoteAttribute := reader.configuration.mapAttributeDescription(attribute, true)
	remoteValue := bytes.Clone(value)
	if value != nil {
		synthetic := directory.Entry{
			DN: entry.DN,
			Attributes: []directory.Attribute{{
				Description: attribute,
				Values:      [][]byte{value},
			}},
		}
		mapped, mapErr := reader.configuration.mapEntryToRemote(synthetic)
		if mapErr != nil {
			return nil, "", directory.Entry{}, "", nil, mapErr
		}
		if len(mapped.Attributes) == 1 && len(mapped.Attributes[0].Values) == 1 {
			remoteAttribute = mapped.Attributes[0].Description
			remoteValue = mapped.Attributes[0].Values[0]
		}
	}
	return reader.Reader, remoteSubject, remoteEntry, remoteAttribute, remoteValue, nil
}

func (reader *rwmStorageReader) Get(dn directory.DN) (directory.Entry, error) {
	remote, err := reader.configuration.mapDNToRemote(dn)
	if err != nil {
		return directory.Entry{}, err
	}
	entry, err := reader.Reader.Get(remote)
	if err != nil {
		return directory.Entry{}, err
	}
	return reader.configuration.mapEntryToLocal(entry)
}

func (reader *rwmStorageReader) GetIn(
	partition string,
	dn directory.DN,
) (directory.Entry, error) {
	remote, err := reader.configuration.mapDNToRemote(dn)
	if err != nil {
		return directory.Entry{}, err
	}
	entry, err := reader.Reader.GetIn(partition, remote)
	if err != nil {
		return directory.Entry{}, err
	}
	return reader.configuration.mapEntryToLocal(entry)
}

func (reader *rwmStorageReader) ForEach(fn func(directory.Entry) error) error {
	return reader.Reader.ForEach(func(entry directory.Entry) error {
		mapped, err := reader.configuration.mapEntryToLocal(entry)
		if err != nil {
			return err
		}
		return fn(mapped)
	})
}

func (reader *rwmStorageReader) ForEachIn(
	partition string,
	fn func(directory.Entry) error,
) error {
	return reader.Reader.ForEachIn(partition, func(entry directory.Entry) error {
		mapped, err := reader.configuration.mapEntryToLocal(entry)
		if err != nil {
			return err
		}
		return fn(mapped)
	})
}

func (reader *rwmStorageReader) ForEachPartition(
	fn func(string, directory.Entry) error,
) error {
	return reader.Reader.ForEachPartition(func(partition string, entry directory.Entry) error {
		mapped, err := reader.configuration.mapEntryToLocal(entry)
		if err != nil {
			return err
		}
		return fn(partition, mapped)
	})
}

type rwmStorageWriter struct {
	*rwmStorageReader
	writer storage.Writer
}

func (writer *rwmStorageWriter) treeDeletePreflight(dn directory.DN) error {
	preflight, ok := writer.writer.(treeDeletePreflighter)
	if !ok {
		return operationFailed(
			ldapwire.ResultUnwillingToPerform,
			"subtree delete not possible",
		)
	}
	remote, err := writer.configuration.mapDNToRemote(dn)
	if err != nil {
		return err
	}
	return preflight.treeDeletePreflight(remote)
}

func (writer *rwmStorageWriter) Put(entry directory.Entry, replace bool) error {
	mapped, err := writer.configuration.mapEntryToRemote(entry)
	if err != nil {
		return err
	}
	return writer.writer.Put(mapped, replace)
}

func (writer *rwmStorageWriter) PutIn(
	partition string,
	entry directory.Entry,
	replace bool,
) error {
	mapped, err := writer.configuration.mapEntryToRemote(entry)
	if err != nil {
		return err
	}
	return writer.writer.PutIn(partition, mapped, replace)
}

func (writer *rwmStorageWriter) Delete(dn directory.DN) error {
	remote, err := writer.configuration.mapDNToRemote(dn)
	if err != nil {
		return err
	}
	return writer.writer.Delete(remote)
}

func (writer *rwmStorageWriter) DeleteIn(partition string, dn directory.DN) error {
	remote, err := writer.configuration.mapDNToRemote(dn)
	if err != nil {
		return err
	}
	return writer.writer.DeleteIn(partition, remote)
}

func (writer *rwmStorageWriter) Clear() error {
	return writer.writer.Clear()
}

func (writer *rwmStorageWriter) SetNamingContexts(contexts []string) error {
	return writer.writer.SetNamingContexts(contexts)
}

func (writer *rwmStorageWriter) SetMetadata(key string, value []byte) error {
	return writer.writer.SetMetadata(key, value)
}

func (writer *rwmStorageWriter) DeleteMetadata(key string) error {
	return writer.writer.DeleteMetadata(key)
}

func (configuration *rwmRuntimeConfiguration) mapDNToRemote(
	dn directory.DN,
) (directory.DN, error) {
	if configuration == nil || configuration.suffix == nil {
		return dn, nil
	}
	local, err := configuration.normalizeDN(configuration.suffix.local)
	if err != nil {
		return directory.DN{}, err
	}
	remote, err := configuration.normalizeDN(configuration.suffix.remote)
	if err != nil {
		return directory.DN{}, err
	}
	comparisonDN, err := configuration.normalizeDN(dn)
	if err != nil {
		return directory.DN{}, err
	}
	if !local.Equal(comparisonDN) && !local.AncestorOf(comparisonDN) {
		return dn, nil
	}
	return comparisonDN.ReplaceAncestor(local, remote)
}

func (configuration *rwmRuntimeConfiguration) mapDNToLocal(
	dn directory.DN,
) (directory.DN, error) {
	if configuration == nil || configuration.suffix == nil {
		return dn, nil
	}
	local, err := configuration.normalizeDN(configuration.suffix.local)
	if err != nil {
		return directory.DN{}, err
	}
	remote, err := configuration.normalizeDN(configuration.suffix.remote)
	if err != nil {
		return directory.DN{}, err
	}
	comparisonDN, err := configuration.normalizeDN(dn)
	if err != nil {
		return directory.DN{}, err
	}
	if !remote.Equal(comparisonDN) && !remote.AncestorOf(comparisonDN) {
		return dn, nil
	}
	return comparisonDN.ReplaceAncestor(remote, local)
}

func (configuration *rwmRuntimeConfiguration) normalizeDN(
	dn directory.DN,
) (directory.DN, error) {
	if configuration == nil || configuration.schema == nil {
		return dn, nil
	}
	return directory.ParseDNWithNormalizer(dn.String(), configuration.schema)
}

func (configuration *rwmRuntimeConfiguration) mapEntryToRemote(
	entry directory.Entry,
) (directory.Entry, error) {
	return configuration.mapEntry(entry, true)
}

func (configuration *rwmRuntimeConfiguration) mapEntryToLocal(
	entry directory.Entry,
) (directory.Entry, error) {
	return configuration.mapEntry(entry, false)
}

func (configuration *rwmRuntimeConfiguration) mapEntry(
	entry directory.Entry,
	toRemote bool,
) (directory.Entry, error) {
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return directory.Entry{}, err
	}
	if toRemote {
		dn, err = configuration.mapDNToRemote(dn)
	} else {
		dn, err = configuration.mapDNToLocal(dn)
	}
	if err != nil {
		return directory.Entry{}, err
	}

	result := directory.Entry{DN: dn.String()}
	for _, attribute := range entry.Attributes {
		description := configuration.mapAttributeDescription(
			attribute.Description,
			toRemote,
		)
		if description == "" {
			continue
		}
		values := make([][]byte, 0, len(attribute.Values))
		for _, value := range attribute.Values {
			mapped := bytes.Clone(value)
			if strings.EqualFold(baseAttributeName(description), "objectClass") {
				mappedClass := configuration.mapObjectClass(string(value), toRemote)
				if mappedClass == "" {
					continue
				}
				mapped = []byte(mappedClass)
			} else if configuration.isDNReferenceAttribute(
				attribute.Description,
				description,
			) {
				mapped, err = configuration.mapDNReferenceValue(value, toRemote)
				if err != nil {
					return directory.Entry{}, fmt.Errorf(
						"map %s value in %s: %w",
						attribute.Description,
						entry.DN,
						err,
					)
				}
			} else if strings.EqualFold(baseAttributeName(description), "ref") {
				mapped = configuration.mapLDAPURLValue(value, toRemote)
			}
			values = append(values, mapped)
		}
		if len(values) == 0 && len(attribute.Values) != 0 {
			continue
		}
		index := mappedAttributeIndex(result.Attributes, description)
		if index < 0 {
			result.Attributes = append(result.Attributes, directory.Attribute{
				Description: description,
				Values:      values,
			})
		} else {
			result.Attributes[index].Values = append(
				result.Attributes[index].Values,
				values...,
			)
		}
	}
	return result, nil
}

func (configuration *rwmRuntimeConfiguration) mapAttributeDescription(
	description string,
	toRemote bool,
) string {
	if configuration == nil || rwmSpecialAttributeDescription(description) {
		return description
	}
	base := baseAttributeName(description)
	options := description[len(base):]
	mappings := configuration.attributesToRemote
	if !toRemote {
		mappings = configuration.attributesToLocal
	}
	if mapped, ok := mappings[strings.ToLower(base)]; ok {
		if mapped == "" {
			return ""
		}
		return mapped + options
	}
	if configuration.attributesDropMissing &&
		(len(configuration.attributesToRemote) != 0 || len(configuration.attributesToLocal) != 0) {
		return ""
	}
	return description
}

func rwmSpecialAttributeDescription(description string) bool {
	switch strings.ToLower(description) {
	case "*", "+", "1.1":
		return true
	default:
		return false
	}
}

func (configuration *rwmRuntimeConfiguration) mapObjectClass(
	value string,
	toRemote bool,
) string {
	if configuration == nil ||
		(len(configuration.classesToRemote) == 0 && len(configuration.classesToLocal) == 0) {
		return value
	}
	mappings := configuration.classesToRemote
	if !toRemote {
		mappings = configuration.classesToLocal
	}
	if mapped, ok := mappings[strings.ToLower(value)]; ok {
		return mapped
	}
	if configuration.classesDropMissing {
		return ""
	}
	return value
}

func (configuration *rwmRuntimeConfiguration) isDNReferenceAttribute(
	original,
	mapped string,
) bool {
	if configuration.schema == nil {
		return false
	}
	return configuration.schema.IsDNReferenceValued(original) ||
		configuration.schema.IsDNReferenceValued(mapped)
}

func (configuration *rwmRuntimeConfiguration) mapDNReferenceValue(
	value []byte,
	toRemote bool,
) ([]byte, error) {
	raw := string(value)
	dnPart := raw
	suffix := ""
	dn, err := directory.ParseDN(dnPart)
	if err != nil {
		if index := unescapedHashIndex(raw); index >= 0 {
			dnPart = raw[:index]
			suffix = raw[index:]
			dn, err = directory.ParseDN(dnPart)
		}
	}
	if err != nil {
		return nil, err
	}
	if toRemote {
		dn, err = configuration.mapDNToRemote(dn)
	} else {
		dn, err = configuration.mapDNToLocal(dn)
	}
	if err != nil {
		return nil, err
	}
	return []byte(dn.String() + suffix), nil
}

func (configuration *rwmRuntimeConfiguration) mapLDAPURLValue(
	value []byte,
	toRemote bool,
) []byte {
	parsed, err := url.Parse(string(value))
	if err != nil || parsed.Scheme == "" || parsed.Path == "" {
		return bytes.Clone(value)
	}
	rawDN, err := url.PathUnescape(strings.TrimPrefix(parsed.EscapedPath(), "/"))
	if err != nil || rawDN == "" {
		return bytes.Clone(value)
	}
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		return bytes.Clone(value)
	}
	if toRemote {
		dn, err = configuration.mapDNToRemote(dn)
	} else {
		dn, err = configuration.mapDNToLocal(dn)
	}
	if err != nil {
		return bytes.Clone(value)
	}
	parsed.Path = "/" + dn.String()
	parsed.RawPath = ""
	return []byte(parsed.String())
}

func baseAttributeName(description string) string {
	if index := strings.IndexByte(description, ';'); index >= 0 {
		return description[:index]
	}
	return description
}

func mappedAttributeIndex(attributes []directory.Attribute, description string) int {
	for index := range attributes {
		if strings.EqualFold(attributes[index].Description, description) {
			return index
		}
	}
	return -1
}

func unescapedHashIndex(value string) int {
	escaped := false
	for index, character := range value {
		switch {
		case escaped:
			escaped = false
		case character == '\\':
			escaped = true
		case character == '#':
			return index
		}
	}
	return -1
}
