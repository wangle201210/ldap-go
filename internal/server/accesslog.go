package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type accesslogOperation uint16

const (
	accesslogAdd accesslogOperation = 1 << iota
	accesslogDelete
	accesslogModify
	accesslogModifyDN
	accesslogCompare
	accesslogSearch
	accesslogBind
	accesslogUnbind
	accesslogAbandon
	accesslogExtended
	accesslogUnknown
	accesslogWrites = accesslogAdd | accesslogDelete |
		accesslogModify | accesslogModifyDN
	accesslogReads   = accesslogCompare | accesslogSearch
	accesslogSession = accesslogBind | accesslogUnbind | accesslogAbandon
	accesslogAll     = accesslogWrites | accesslogReads | accesslogSession |
		accesslogExtended | accesslogUnknown
)

type accesslogRuntimeConfiguration struct {
	targetSuffix        directory.DN
	sourceDatabaseIndex int
	targetDatabaseIndex int
	operations          accesslogOperation
	bases               []accesslogBaseConfiguration
	successOnly         bool
	oldFilter           *directory.Filter
	oldAttributes       []string
	purgeAge            time.Duration
	purgeInterval       time.Duration
}

type accesslogBaseConfiguration struct {
	operations accesslogOperation
	base       directory.DN
}

type accesslogWriteRecord struct {
	operation       accesslogOperation
	session         uint64
	authorizationDN string
	requestDN       directory.DN
	before          *directory.Entry
	after           *directory.Entry
	modifications   []ldapwire.Modification
	newRDN          string
	deleteOldRDN    bool
	newSuperior     *directory.DN
}

func loadAccesslogRuntimeConfiguration(
	entry directory.Entry,
) (accesslogRuntimeConfiguration, error) {
	values := entry.Values("olcAccessLogDB")
	if len(values) != 1 {
		return accesslogRuntimeConfiguration{}, fmt.Errorf(
			"%s olcAccessLogDB must be single-valued",
			entry.DN,
		)
	}
	target, err := directory.ParseDN(string(values[0]))
	if err != nil || target.Depth() == 0 {
		return accesslogRuntimeConfiguration{}, fmt.Errorf(
			"%s olcAccessLogDB has invalid suffix %q",
			entry.DN,
			values[0],
		)
	}

	var operations accesslogOperation
	for _, raw := range entry.Values("olcAccessLogOps") {
		for _, field := range strings.Fields(string(raw)) {
			parsed, parseErr := parseAccesslogOperations(field)
			if parseErr != nil {
				return accesslogRuntimeConfiguration{}, fmt.Errorf(
					"%s olcAccessLogOps value %q is not supported",
					entry.DN,
					field,
				)
			}
			operations |= parsed
		}
	}
	var bases []accesslogBaseConfiguration
	for _, raw := range entry.Values("olcAccessLogBase") {
		arguments, parseErr := tokenizeOpenLDAPConfig(string(raw))
		if parseErr != nil || len(arguments) != 2 {
			return accesslogRuntimeConfiguration{}, fmt.Errorf(
				"%s olcAccessLogBase value %q requires operations and a base DN",
				entry.DN,
				raw,
			)
		}
		baseOperations, parseErr := parseAccesslogOperations(arguments[0])
		if parseErr != nil || baseOperations == 0 {
			return accesslogRuntimeConfiguration{}, fmt.Errorf(
				"%s olcAccessLogBase operations %q are not supported",
				entry.DN,
				arguments[0],
			)
		}
		base, parseErr := directory.ParseDN(arguments[1])
		if parseErr != nil {
			return accesslogRuntimeConfiguration{}, fmt.Errorf(
				"%s olcAccessLogBase has invalid base DN %q",
				entry.DN,
				arguments[1],
			)
		}
		bases = append(bases, accesslogBaseConfiguration{
			operations: baseOperations,
			base:       base,
		})
	}
	successOnly, _, err := singleBoolean(
		entry,
		"olcAccessLogSuccess",
	)
	if err != nil {
		return accesslogRuntimeConfiguration{}, err
	}
	oldValues := entry.Values("olcAccessLogOld")
	if len(oldValues) > 1 {
		return accesslogRuntimeConfiguration{}, fmt.Errorf(
			"%s olcAccessLogOld must be single-valued",
			entry.DN,
		)
	}
	var oldFilter *directory.Filter
	if len(oldValues) == 1 {
		parsed, err := compileSyncConsumerFilter(string(oldValues[0]))
		if err != nil {
			return accesslogRuntimeConfiguration{}, fmt.Errorf(
				"%s olcAccessLogOld: %w",
				entry.DN,
				err,
			)
		}
		oldFilter = &parsed
	}
	var oldAttributes []string
	seenOldAttributes := make(map[string]struct{})
	for _, raw := range entry.Values("olcAccessLogOldAttr") {
		for _, description := range strings.FieldsFunc(
			string(raw),
			func(character rune) bool {
				return unicode.IsSpace(character) || character == ','
			},
		) {
			key := strings.ToLower(description)
			if _, duplicate := seenOldAttributes[key]; duplicate {
				continue
			}
			seenOldAttributes[key] = struct{}{}
			oldAttributes = append(oldAttributes, description)
		}
	}
	purgeValues := entry.Values("olcAccessLogPurge")
	if len(purgeValues) > 1 {
		return accesslogRuntimeConfiguration{}, fmt.Errorf(
			"%s olcAccessLogPurge must be single-valued",
			entry.DN,
		)
	}
	var purgeAge, purgeInterval time.Duration
	if len(purgeValues) == 1 {
		fields := strings.Fields(string(purgeValues[0]))
		if len(fields) != 2 {
			return accesslogRuntimeConfiguration{}, fmt.Errorf(
				"%s olcAccessLogPurge requires age and interval",
				entry.DN,
			)
		}
		purgeAge, err = parseAccesslogAge(fields[0])
		if err != nil {
			return accesslogRuntimeConfiguration{}, fmt.Errorf(
				"%s olcAccessLogPurge age: %w",
				entry.DN,
				err,
			)
		}
		purgeInterval, err = parseAccesslogAge(fields[1])
		if err != nil {
			return accesslogRuntimeConfiguration{}, fmt.Errorf(
				"%s olcAccessLogPurge interval: %w",
				entry.DN,
				err,
			)
		}
	}
	return accesslogRuntimeConfiguration{
		targetSuffix:        target,
		sourceDatabaseIndex: -1,
		targetDatabaseIndex: -1,
		operations:          operations,
		bases:               bases,
		successOnly:         successOnly,
		oldFilter:           oldFilter,
		oldAttributes:       oldAttributes,
		purgeAge:            purgeAge,
		purgeInterval:       purgeInterval,
	}, nil
}

func parseAccesslogOperations(value string) (accesslogOperation, error) {
	var operations accesslogOperation
	for _, field := range strings.Split(value, "|") {
		switch databaseType(strings.TrimSpace(field)) {
		case "all":
			operations |= accesslogAll
		case "writes":
			operations |= accesslogWrites
		case "reads":
			operations |= accesslogReads
		case "session":
			operations |= accesslogSession
		case "add":
			operations |= accesslogAdd
		case "delete":
			operations |= accesslogDelete
		case "modify":
			operations |= accesslogModify
		case "modrdn":
			operations |= accesslogModifyDN
		case "compare":
			operations |= accesslogCompare
		case "search":
			operations |= accesslogSearch
		case "bind":
			operations |= accesslogBind
		case "unbind":
			operations |= accesslogUnbind
		case "abandon":
			operations |= accesslogAbandon
		case "extended":
			operations |= accesslogExtended
		case "unknown":
			operations |= accesslogUnknown
		default:
			return 0, fmt.Errorf("unsupported accesslog operation %q", field)
		}
	}
	return operations, nil
}

func parseAccesslogAge(value string) (time.Duration, error) {
	if value == "" {
		return 0, errors.New("empty interval")
	}
	days := uint64(0)
	clock := value
	if separator := strings.IndexByte(value, '+'); separator >= 0 {
		if separator == 0 || strings.IndexByte(value[separator+1:], '+') >= 0 {
			return 0, fmt.Errorf("invalid interval %q", value)
		}
		parsed, err := strconv.ParseUint(value[:separator], 10, 32)
		if err != nil || parsed > 25000 {
			return 0, fmt.Errorf("invalid day count in %q", value)
		}
		days = parsed
		clock = value[separator+1:]
	}
	parts := strings.Split(clock, ":")
	if len(parts) != 2 && len(parts) != 3 {
		return 0, fmt.Errorf("invalid interval %q", value)
	}
	parsed := make([]uint64, len(parts))
	for index, part := range parts {
		if len(part) != 2 {
			return 0, fmt.Errorf("invalid interval %q", value)
		}
		number, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return 0, fmt.Errorf("invalid interval %q", value)
		}
		parsed[index] = number
	}
	if parsed[1] > 59 || (len(parsed) == 3 && parsed[2] > 59) {
		return 0, fmt.Errorf("invalid interval %q", value)
	}
	seconds := (days*24+parsed[0])*60*60 + parsed[1]*60
	if len(parsed) == 3 {
		seconds += parsed[2]
	}
	if seconds == 0 || seconds > uint64((time.Duration(1<<63-1))/time.Second) {
		return 0, fmt.Errorf("interval %q must be positive and bounded", value)
	}
	return time.Duration(seconds) * time.Second, nil
}

func validateAccesslogSchema(
	registry *schema.Registry,
	configuration *accesslogRuntimeConfiguration,
) error {
	if configuration == nil {
		return nil
	}
	for _, description := range configuration.oldAttributes {
		if _, found := registry.AttributeType(description); !found {
			return fmt.Errorf(
				"olcAccessLogOldAttr references unknown attribute %q",
				description,
			)
		}
	}
	if configuration.oldFilter != nil {
		if err := validateAccesslogFilterSchema(
			registry,
			*configuration.oldFilter,
		); err != nil {
			return fmt.Errorf("olcAccessLogOld: %w", err)
		}
	}
	return nil
}

func validateAccesslogFilterSchema(
	registry *schema.Registry,
	filter directory.Filter,
) error {
	if filter.Attribute != "" {
		if _, found := registry.AttributeType(filter.Attribute); !found {
			return fmt.Errorf(
				"filter references unknown attribute %q",
				filter.Attribute,
			)
		}
	}
	for _, child := range filter.Children {
		if err := validateAccesslogFilterSchema(registry, child); err != nil {
			return err
		}
	}
	return nil
}

func resolveAccesslogDatabases(databases []runtimeDatabase) error {
	for index := range databases {
		configuration := databases[index].accesslog
		if configuration == nil {
			continue
		}
		if isRelayDatabase(databases[index]) ||
			isConfigDatabase(databases[index]) ||
			isMonitorDatabase(databases[index]) ||
			isNullDatabase(databases[index]) {
			return fmt.Errorf(
				"%s accesslog overlay requires a local content database",
				databases[index].name,
			)
		}
		targetIndex := databaseIndexForDN(databases, configuration.targetSuffix)
		if targetIndex < 0 ||
			!databaseOwnsSuffix(databases[targetIndex], configuration.targetSuffix) {
			return fmt.Errorf(
				"%s accesslog target %q has no configured database",
				databases[index].name,
				configuration.targetSuffix.String(),
			)
		}
		if targetIndex == index {
			return fmt.Errorf(
				"%s accesslog target points to the source database",
				databases[index].name,
			)
		}
		normalizedTarget, err := normalizeRuntimeDatabaseDN(
			databases[targetIndex],
			configuration.targetSuffix,
		)
		if err != nil {
			return fmt.Errorf(
				"%s accesslog target %q: %w",
				databases[index].name,
				configuration.targetSuffix.String(),
				err,
			)
		}
		configuration.targetSuffix = normalizedTarget
		for baseIndex := range configuration.bases {
			normalizedBase, err := normalizeRuntimeDatabaseDN(
				databases[index],
				configuration.bases[baseIndex].base,
			)
			if err != nil {
				return fmt.Errorf(
					"%s accesslog base %q: %w",
					databases[index].name,
					configuration.bases[baseIndex].base.String(),
					err,
				)
			}
			configuration.bases[baseIndex].base = normalizedBase
		}
		if isRelayDatabase(databases[targetIndex]) ||
			isConfigDatabase(databases[targetIndex]) ||
			isMonitorDatabase(databases[targetIndex]) ||
			isNullDatabase(databases[targetIndex]) {
			return fmt.Errorf(
				"%s accesslog target %s is not a local content database",
				databases[index].name,
				databases[targetIndex].name,
			)
		}
		if databases[index].sqlBackend != nil &&
			databases[targetIndex].sqlBackend != nil &&
			accesslogConfigurationRecordsDatabaseWrites(
				configuration,
				databases[index],
			) {
			return fmt.Errorf(
				"%s accesslog cannot record successful writes in SQL target %s: independent SQL backends cannot be committed atomically",
				databases[index].name,
				databases[targetIndex].name,
			)
		}
		configuration.targetDatabaseIndex = targetIndex
		configuration.sourceDatabaseIndex = index
	}
	return nil
}

func accesslogConfigurationRecordsDatabaseWrites(
	configuration *accesslogRuntimeConfiguration,
	database runtimeDatabase,
) bool {
	if configuration == nil {
		return false
	}
	if configuration.operations&accesslogWrites != 0 {
		return true
	}
	for _, base := range configuration.bases {
		if base.operations&accesslogWrites == 0 {
			continue
		}
		for _, suffix := range database.suffixes {
			if base.base.Equal(suffix) ||
				base.base.AncestorOf(suffix) ||
				suffix.AncestorOf(base.base) {
				return true
			}
		}
	}
	return false
}

func (server *Server) ensureAccesslogContainers(
	writer storage.Writer,
	runtime *runtimeState,
) error {
	for index := range runtime.databases {
		configuration := runtime.databases[index].accesslog
		if configuration == nil || configuration.targetDatabaseIndex < 0 {
			continue
		}
		if _, _, err := server.ensureAccesslogContainer(
			context.Background(),
			writer,
			runtime,
			configuration,
		); err != nil {
			return err
		}
	}
	return nil
}

func (server *Server) ensureAccesslogContainer(
	ctx context.Context,
	writer storage.Writer,
	runtime *runtimeState,
	configuration *accesslogRuntimeConfiguration,
) (directory.Entry, *syncChange, error) {
	if configuration == nil ||
		configuration.targetDatabaseIndex < 0 ||
		configuration.targetDatabaseIndex >= len(runtime.databases) {
		return directory.Entry{}, nil, errors.New("accesslog target is unresolved")
	}
	target := runtime.databases[configuration.targetDatabaseIndex]
	tx := writerForDatabase(writer, target)
	sourceCSNs, err := accesslogSourceCSNs(writer, runtime, configuration)
	if err != nil {
		return directory.Entry{}, nil, err
	}
	entry, err := tx.Get(configuration.targetSuffix)
	if err == nil {
		if len(entry.Values("minCSN")) == 0 {
			values := entry.Values("contextCSN")
			if len(values) == 0 {
				values = accesslogCSNValues(sourceCSNs)
			}
			if len(values) != 0 {
				entry.ReplaceValues("minCSN", values)
				if err := tx.Put(entry, true); err != nil {
					return directory.Entry{}, nil, err
				}
			}
		}
		return entry, nil, nil
	}
	if !errors.Is(err, storage.ErrEntryNotFound) {
		return directory.Entry{}, nil, err
	}
	rdnValues := configuration.targetSuffix.RDNValues()
	if len(rdnValues) == 0 {
		return directory.Entry{}, nil, errors.New("accesslog suffix has no RDN")
	}
	objectClasses := []string{"auditContainer"}
	if !strings.EqualFold(rdnValues[0].Type, "cn") {
		objectClasses = append(objectClasses, "extensibleObject")
	}
	entry = directory.Entry{
		DN: configuration.targetSuffix.String(),
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues(objectClasses...)},
		},
	}
	for _, value := range rdnValues {
		entry.AddValues(value.Type, [][]byte{value.Value})
	}
	actor := ""
	if target.rootDN != nil {
		actor = target.rootDN.String()
	}
	if err := server.applyCreateOperationalAttributesContext(
		ctx,
		&entry,
		actor,
		target.lastMod,
		runtime.serverID,
		runtime.schema,
	); err != nil {
		return directory.Entry{}, nil, err
	}
	if err := server.applySchemaOperationalAttributes(runtime, &entry); err != nil {
		return directory.Entry{}, nil, err
	}
	contextValues := accesslogCSNValues(sourceCSNs)
	if len(contextValues) != 0 {
		entry.ReplaceValues("entryCSN", contextValues[:1])
	} else {
		contextValues = entry.Values("entryCSN")
	}
	entry.ReplaceValues("contextCSN", contextValues)
	entry.ReplaceValues("minCSN", contextValues)
	if err := runtime.schema.ValidateEntry(entry); err != nil {
		return directory.Entry{}, nil, err
	}
	if err := tx.Put(entry, false); err != nil {
		return directory.Entry{}, nil, err
	}
	change, err := server.recordSyncChangeContext(
		ctx,
		writer,
		runtime,
		target,
		nil,
		&entry,
	)
	if err == nil {
		if provider := effectiveSyncProviderDatabase(runtime, target); provider != nil {
			for _, csn := range sourceCSNs {
				if err := advanceSyncContextCSN(
					writer,
					provider.partition,
					csn,
				); err != nil {
					return directory.Entry{}, nil, err
				}
			}
		}
	}
	return entry, change, err
}

func accesslogSourceCSNs(
	reader storage.Reader,
	runtime *runtimeState,
	configuration *accesslogRuntimeConfiguration,
) (syncCSNState, error) {
	if runtime == nil || configuration == nil ||
		configuration.sourceDatabaseIndex < 0 ||
		configuration.sourceDatabaseIndex >= len(runtime.databases) {
		return nil, nil
	}
	source := runtime.databases[configuration.sourceDatabaseIndex]
	return syncContextCSNs(reader, source.partition)
}

func accesslogCSNValues(state syncCSNState) [][]byte {
	values := make([][]byte, 0, len(state))
	for _, raw := range orderedSyncCSNs(state) {
		values = append(values, []byte(raw))
	}
	return values
}

func (server *Server) recordAccesslogWrite(
	ctx context.Context,
	writer storage.Writer,
	runtime *runtimeState,
	source runtimeDatabase,
	record accesslogWriteRecord,
	sourceChange *syncChange,
) ([]*syncChange, error) {
	configuration := source.accesslog
	if configuration == nil {
		return nil, nil
	}
	requestDN, err := normalizeRuntimeDatabaseDN(source, record.requestDN)
	if err != nil {
		return nil, fmt.Errorf("normalize accesslog reqDN: %w", err)
	}
	record.requestDN = requestDN
	if record.newSuperior != nil {
		newSuperior, normalizeErr := normalizeRuntimeDatabaseDN(
			source,
			*record.newSuperior,
		)
		if normalizeErr != nil {
			return nil, fmt.Errorf(
				"normalize accesslog reqNewSuperior: %w",
				normalizeErr,
			)
		}
		record.newSuperior = &newSuperior
	}
	if !accesslogConfigurationApplies(
		configuration,
		record.operation,
		record.requestDN,
	) {
		return nil, nil
	}
	container, containerChange, err := server.ensureAccesslogContainer(
		ctx,
		writer,
		runtime,
		configuration,
	)
	if err != nil {
		return nil, err
	}
	_ = container

	csn, err := server.accesslogCSN(ctx, runtime, record, sourceChange)
	if err != nil {
		return nil, err
	}
	start := server.nextAccesslogTimestampContext(ctx)
	end := server.nextAccesslogTimestampContext(ctx)
	entry := directory.Entry{
		DN: "reqStart=" + start + "," + configuration.targetSuffix.String(),
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues(accesslogObjectClass(record.operation))},
			{Description: "reqStart", Values: stringValues(start)},
			{Description: "reqEnd", Values: stringValues(end)},
			{Description: "reqType", Values: stringValues(accesslogOperationName(record.operation))},
			{Description: "reqSession", Values: stringValues(strconv.FormatUint(record.session, 10))},
			{Description: "reqAuthzID", Values: stringValues(record.authorizationDN)},
			{Description: "reqDN", Values: stringValues(record.requestDN.String())},
			{Description: "reqResult", Values: stringValues("0")},
		},
	}
	if uuid := accesslogEntryUUID(record); uuid != "" {
		entry.ReplaceValues("reqEntryUUID", stringValues(uuid))
	}
	switch record.operation {
	case accesslogAdd:
		entry.ReplaceValues("reqMod", accesslogAddValues(record.after))
	case accesslogModify:
		entry.ReplaceValues(
			"reqMod",
			accesslogModifyValues(record),
		)
	case accesslogModifyDN:
		entry.ReplaceValues("reqNewRDN", stringValues(record.newRDN))
		deleteOldRDN := "FALSE"
		if record.deleteOldRDN {
			deleteOldRDN = "TRUE"
		}
		entry.ReplaceValues(
			"reqDeleteOldRDN",
			stringValues(deleteOldRDN),
		)
		if record.newSuperior != nil {
			entry.ReplaceValues(
				"reqNewSuperior",
				stringValues(record.newSuperior.String()),
			)
		}
		if record.after != nil {
			newDN, parseErr := parseRuntimeDN(
				record.after.DN,
				source.dnNormalizer,
			)
			if parseErr != nil {
				return nil, fmt.Errorf(
					"normalize accesslog reqNewDN: %w",
					parseErr,
				)
			}
			entry.ReplaceValues("reqNewDN", stringValues(newDN.String()))
		}
		entry.ReplaceValues(
			"reqMod",
			accesslogModifyDNValues(runtime.schema, record),
		)
	}
	oldValues, err := accesslogOldValues(runtime.schema, configuration, record)
	if err != nil {
		return nil, err
	}
	entry.ReplaceValues("reqOld", oldValues)

	return server.storeAccesslogEntry(
		writer,
		runtime,
		configuration,
		container,
		containerChange,
		entry,
		csn,
		record.authorizationDN,
		true,
	)
}

func (server *Server) storeAccesslogEntry(
	writer storage.Writer,
	runtime *runtimeState,
	configuration *accesslogRuntimeConfiguration,
	container directory.Entry,
	containerChange *syncChange,
	entry directory.Entry,
	csn openLDAPCSN,
	actor string,
	updateMinimum bool,
) ([]*syncChange, error) {
	uuid, err := randomUUID()
	if err != nil {
		return nil, err
	}
	timestamp := time.Now().UTC().Format("20060102150405Z")
	entry.ReplaceValues("entryUUID", stringValues(uuid))
	entry.ReplaceValues("entryCSN", stringValues(csn.raw))
	entry.ReplaceValues("createTimestamp", stringValues(timestamp))
	entry.ReplaceValues("modifyTimestamp", stringValues(timestamp))
	entry.ReplaceValues("creatorsName", stringValues(actor))
	entry.ReplaceValues("modifiersName", stringValues(actor))
	if err := server.applySchemaOperationalAttributes(runtime, &entry); err != nil {
		return nil, err
	}
	if err := runtime.schema.ValidateEntry(entry); err != nil {
		return nil, fmt.Errorf("validate accesslog entry: %w", err)
	}
	target := runtime.databases[configuration.targetDatabaseIndex]
	tx := writerForDatabase(writer, target)
	if updateMinimum {
		if changed, err := addAccesslogMinCSN(&container, csn); err != nil {
			return nil, err
		} else if changed {
			if err := tx.Put(container, true); err != nil {
				return nil, err
			}
		}
	}
	logDN, err := syncConsumerParseDN(tx, entry.DN)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Get(logDN); err == nil {
		return nil, storage.ErrEntryExists
	} else if !errors.Is(err, storage.ErrEntryNotFound) {
		return nil, err
	}
	if err := tx.Put(entry, false); err != nil {
		return nil, err
	}
	logChange, err := server.recordSyncChangeCSN(
		writer,
		runtime,
		target,
		nil,
		&entry,
		csn,
	)
	if err != nil {
		return nil, err
	}
	changes := make([]*syncChange, 0, 2)
	if containerChange != nil {
		changes = append(changes, containerChange)
	}
	if logChange != nil {
		changes = append(changes, logChange)
	}
	return changes, nil
}

func (server *Server) recordObservedAccesslogOperation(
	ctx context.Context,
	runtime *runtimeState,
	source runtimeDatabase,
	observation *operationAuditObservation,
	operation accesslogOperation,
	targetDN directory.DN,
	result int,
	hasResult bool,
) error {
	var changes []*syncChange
	err := server.config.Store.Update(ctx, func(writer storage.Writer) error {
		configuration := source.accesslog
		container, containerChange, err := server.ensureAccesslogContainer(
			ctx,
			writer,
			runtime,
			configuration,
		)
		if err != nil {
			return err
		}
		csn, err := parseOpenLDAPCSN(server.nextCSN(runtime.serverID))
		if err != nil {
			return err
		}
		start := server.nextAccesslogTimestamp()
		end := server.nextAccesslogTimestamp()
		entry := directory.Entry{
			DN: "reqStart=" + start + "," + configuration.targetSuffix.String(),
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues(accesslogObjectClass(operation))},
				{Description: "reqStart", Values: stringValues(start)},
				{Description: "reqEnd", Values: stringValues(end)},
				{Description: "reqType", Values: stringValues(accesslogOperationName(operation))},
				{Description: "reqSession", Values: stringValues(strconv.FormatUint(observation.event.ConnectionID, 10))},
				{Description: "reqAuthzID", Values: stringValues(observation.event.AuthorizationDN)},
			},
		}
		if operation != accesslogUnbind && operation != accesslogAbandon {
			entry.ReplaceValues("reqDN", stringValues(targetDN.String()))
		}
		if hasResult {
			entry.ReplaceValues("reqResult", stringValues(strconv.Itoa(result)))
		}
		if observation.diagnostic != "" {
			entry.ReplaceValues("reqMessage", stringValues(observation.diagnostic))
		}
		entry.ReplaceValues("reqReferral", stringValues(observation.referrals...))
		entry.ReplaceValues(
			"reqRespControls",
			accesslogControlValues(observation.responseControls),
		)
		if err := server.populateObservedAccesslogRequest(
			writer,
			runtime,
			source,
			configuration,
			observation,
			operation,
			targetDN,
			&entry,
		); err != nil {
			return err
		}
		changes, err = server.storeAccesslogEntry(
			writer,
			runtime,
			configuration,
			container,
			containerChange,
			entry,
			csn,
			observation.event.AuthorizationDN,
			false,
		)
		return err
	})
	if err != nil {
		return err
	}
	for _, change := range changes {
		server.publishSyncChange(change)
	}
	return nil
}

func runtimeHasAccesslog(runtime *runtimeState) bool {
	if runtime == nil {
		return false
	}
	for index := range runtime.databases {
		if runtime.databases[index].accesslog != nil {
			return true
		}
	}
	return false
}

func (server *Server) finishAccesslogObservation(
	observation *operationAuditObservation,
	stop operationStopMode,
	operationErr error,
) {
	if observation == nil || observation.runtime == nil {
		return
	}
	operation := accesslogOperationForRequest(observation.message.Request)
	if operation == 0 {
		return
	}
	observation.mu.Lock()
	result := observation.result
	hasResult := observation.hasResult
	observation.mu.Unlock()
	if stop == operationCanceled {
		result = int(ldapwire.ResultCanceled)
		hasResult = true
	}
	if stop == operationAbandoned ||
		(!hasResult && operation != accesslogUnbind &&
			operation != accesslogAbandon) ||
		(operationErr != nil && !hasResult) {
		return
	}
	targetDN, found := accesslogObservationTargetDN(observation)
	if !found {
		return
	}
	index := databaseIndexForDN(observation.runtime.databases, targetDN)
	if index < 0 || index >= len(observation.runtime.databases) {
		return
	}
	source := observation.runtime.databases[index]
	configuration := source.accesslog
	if configuration == nil {
		return
	}
	normalizedTarget, err := normalizeRuntimeDatabaseDN(source, targetDN)
	if err != nil {
		return
	}
	targetDN = normalizedTarget
	if !accesslogConfigurationApplies(configuration, operation, targetDN) {
		return
	}
	success := hasResult && accesslogResultIsSuccess(result)
	if operation&accesslogWrites != 0 && success {
		return
	}
	if configuration.successOnly && !success &&
		operation != accesslogUnbind && operation != accesslogAbandon {
		return
	}
	if observation.event.AuthorizationDN == "" {
		observation.event.AuthorizationDN = observation.initialAuthorizationDN
	}
	if err := server.recordObservedAccesslogOperation(
		context.Background(),
		observation.runtime,
		source,
		observation,
		operation,
		targetDN,
		result,
		hasResult,
	); err != nil {
		server.config.Logger.Error(
			"write accesslog operation",
			"operation",
			accesslogOperationName(operation),
			"error",
			err,
		)
	}
}

func accesslogResultIsSuccess(result int) bool {
	switch ldapwire.ResultCode(result) {
	case ldapwire.ResultSuccess,
		ldapwire.ResultCompareFalse,
		ldapwire.ResultCompareTrue:
		return true
	default:
		return false
	}
}

func accesslogOperationForRequest(request ldapwire.Request) accesslogOperation {
	switch request.(type) {
	case ldapwire.AddRequest:
		return accesslogAdd
	case ldapwire.DeleteRequest:
		return accesslogDelete
	case ldapwire.ModifyRequest:
		return accesslogModify
	case ldapwire.ModifyDNRequest:
		return accesslogModifyDN
	case ldapwire.CompareRequest:
		return accesslogCompare
	case ldapwire.SearchRequest:
		return accesslogSearch
	case ldapwire.BindRequest:
		return accesslogBind
	case ldapwire.UnbindRequest:
		return accesslogUnbind
	case ldapwire.AbandonRequest:
		return accesslogAbandon
	case ldapwire.ExtendedRequest:
		return accesslogExtended
	case ldapwire.UnsupportedRequest:
		return accesslogUnknown
	default:
		return 0
	}
}

func accesslogObservationTargetDN(
	observation *operationAuditObservation,
) (directory.DN, bool) {
	var raw string
	switch request := observation.message.Request.(type) {
	case ldapwire.BindRequest:
		raw = request.Name
	case ldapwire.SearchRequest:
		raw = request.BaseDN
	case ldapwire.AddRequest:
		raw = request.Entry.DN
	case ldapwire.ModifyRequest:
		raw = request.DN
	case ldapwire.DeleteRequest:
		raw = request.DN
	case ldapwire.ModifyDNRequest:
		raw = request.DN
	case ldapwire.CompareRequest:
		raw = request.DN
	case ldapwire.UnbindRequest, ldapwire.AbandonRequest:
		raw = observation.initialAuthorizationDN
	case ldapwire.ExtendedRequest:
		switch request.Name {
		case passwordModifyOID:
			decoded, err := ldapwire.DecodePasswordModifyRequestValue(
				request.Value,
				request.HasValue,
			)
			if err == nil && decoded.HasUserIdentity &&
				len(decoded.UserIdentity) != 0 {
				raw = string(decoded.UserIdentity)
			} else {
				raw = observation.initialAuthorizationDN
			}
		case dynamicRefreshOID:
			decoded, err := ldapwire.DecodeDynamicRefreshRequestValue(
				request.Value,
				request.HasValue,
			)
			if err != nil {
				return directory.DN{}, false
			}
			raw = decoded.EntryName
		default:
			return directory.DN{}, false
		}
	default:
		raw = observation.initialAuthorizationDN
	}
	if raw == "" {
		return directory.DN{}, false
	}
	dn, err := directory.ParseDN(raw)
	return dn, err == nil
}

func (server *Server) populateObservedAccesslogRequest(
	reader storage.Reader,
	runtime *runtimeState,
	source runtimeDatabase,
	configuration *accesslogRuntimeConfiguration,
	observation *operationAuditObservation,
	operation accesslogOperation,
	targetDN directory.DN,
	entry *directory.Entry,
) error {
	request := observation.message.Request
	entry.ReplaceValues(
		"reqControls",
		accesslogControlValues(observation.message.Controls),
	)

	var before *directory.Entry
	if operation&accesslogWrites != 0 && operation != accesslogAdd {
		tx := readerForDatabase(reader, source)
		stored, err := tx.Get(targetDN)
		if err == nil {
			before = &stored
		} else if !errors.Is(err, storage.ErrEntryNotFound) {
			return err
		}
	}
	writeRecord := accesslogWriteRecord{
		operation: operation,
		requestDN: targetDN,
		before:    before,
	}

	switch typed := request.(type) {
	case ldapwire.AddRequest:
		added := typed.Entry.Clone()
		writeRecord.after = &added
		entry.ReplaceValues("reqMod", accesslogAddValues(&added))
	case ldapwire.DeleteRequest:
	case ldapwire.ModifyRequest:
		writeRecord.modifications = typed.Changes
		entry.ReplaceValues(
			"reqMod",
			accesslogModificationValues(typed.Changes),
		)
	case ldapwire.ModifyDNRequest:
		writeRecord.newRDN = typed.NewRDN
		writeRecord.deleteOldRDN = typed.DeleteOldRDN
		entry.ReplaceValues("reqNewRDN", stringValues(typed.NewRDN))
		deleteOldRDN := "FALSE"
		if typed.DeleteOldRDN {
			deleteOldRDN = "TRUE"
		}
		entry.ReplaceValues("reqDeleteOldRDN", stringValues(deleteOldRDN))
		var superior directory.DN
		var hasSuperior bool
		if typed.HasNewSuperior {
			parsed, err := parseRuntimeDN(
				typed.NewSuperior,
				source.dnNormalizer,
			)
			if err == nil {
				superior = parsed
				hasSuperior = true
				writeRecord.newSuperior = &superior
				entry.ReplaceValues("reqNewSuperior", stringValues(superior.String()))
			}
		} else if parent, ok := targetDN.Parent(); ok {
			superior = parent
			hasSuperior = true
		}
		if hasSuperior {
			if newDN, err := directory.ComposeDN(typed.NewRDN, superior); err == nil {
				if normalized, normalizeErr := normalizeRuntimeDatabaseDN(
					source,
					newDN,
				); normalizeErr == nil {
					entry.ReplaceValues("reqNewDN", stringValues(normalized.String()))
				}
			}
		}
	case ldapwire.CompareRequest:
		assertion := append([]byte(typed.Attribute+"="), typed.Assertion...)
		entry.ReplaceValues("reqAssertion", [][]byte{assertion})
	case ldapwire.SearchRequest:
		entry.ReplaceValues("reqScope", stringValues(accesslogScopeName(typed.Scope)))
		entry.ReplaceValues(
			"reqDerefAliases",
			stringValues(accesslogDerefName(typed.DerefAliases)),
		)
		attributesOnly := "FALSE"
		if typed.TypesOnly {
			attributesOnly = "TRUE"
		}
		entry.ReplaceValues("reqAttrsOnly", stringValues(attributesOnly))
		entry.ReplaceValues("reqFilter", stringValues(accesslogFilterText(typed.Filter)))
		entry.ReplaceValues("reqAttr", stringValues(typed.Attributes...))
		entry.ReplaceValues("reqEntries", stringValues(strconv.Itoa(observation.entries)))
		entry.ReplaceValues("reqSizeLimit", stringValues(strconv.Itoa(typed.SizeLimit)))
		entry.ReplaceValues("reqTimeLimit", stringValues(strconv.Itoa(typed.TimeLimit)))
	case ldapwire.BindRequest:
		entry.ReplaceValues("reqVersion", stringValues(strconv.Itoa(typed.Version)))
		method := "SIMPLE"
		if typed.Authentication.IsSASL {
			method = "SASL(" + typed.Authentication.SASLMechanism + ")"
		}
		entry.ReplaceValues("reqMethod", stringValues(method))
	case ldapwire.AbandonRequest:
		entry.ReplaceValues("reqId", stringValues(strconv.FormatInt(typed.MessageID, 10)))
	case ldapwire.ExtendedRequest:
		entry.ReplaceValues("reqType", stringValues("extended{"+typed.Name+"}"))
		if typed.HasValue && typed.Name != passwordModifyOID {
			entry.ReplaceValues("reqData", [][]byte{bytes.Clone(typed.Value)})
		}
	}

	if uuid := accesslogEntryUUID(writeRecord); uuid != "" {
		entry.ReplaceValues("reqEntryUUID", stringValues(uuid))
	}
	if operation&accesslogWrites != 0 {
		oldValues, err := accesslogOldValues(
			runtime.schema,
			configuration,
			writeRecord,
		)
		if err != nil {
			return err
		}
		entry.ReplaceValues("reqOld", oldValues)
	}
	return nil
}

func accesslogControlValues(controls []ldapwire.Control) [][]byte {
	values := make([][]byte, 0, len(controls))
	for index, control := range controls {
		var value strings.Builder
		fmt.Fprintf(&value, "{%d}{%s", index, control.OID)
		if control.Critical {
			value.WriteString(" criticality TRUE")
		}
		if control.HasValue {
			value.WriteString(" controlValue \"")
			for _, character := range control.Value {
				fmt.Fprintf(&value, "%02X", character)
			}
			value.WriteByte('"')
		}
		value.WriteByte('}')
		values = append(values, []byte(value.String()))
	}
	return values
}

func accesslogScopeName(scope directory.Scope) string {
	switch scope {
	case directory.ScopeBase:
		return "base"
	case directory.ScopeSingleLevel:
		return "one"
	case directory.ScopeWholeSubtree:
		return "sub"
	case directory.ScopeChildren:
		return "subord"
	default:
		return "unknown"
	}
}

func accesslogDerefName(value int) string {
	switch value {
	case ldapwire.NeverDerefAliases:
		return "never"
	case ldapwire.DerefInSearching:
		return "searching"
	case ldapwire.DerefFindingBaseObject:
		return "finding"
	case ldapwire.DerefAlways:
		return "always"
	default:
		return "unknown"
	}
}

func accesslogFilterText(filter directory.Filter) string {
	switch filter.Kind {
	case directory.FilterAnd:
		return "(&" + accesslogFilterChildren(filter.Children) + ")"
	case directory.FilterOr:
		return "(|" + accesslogFilterChildren(filter.Children) + ")"
	case directory.FilterNot:
		return "(!" + accesslogFilterChildren(filter.Children) + ")"
	case directory.FilterEquality:
		return "(" + filter.Attribute + "=" + accesslogFilterValue(filter.Assertion) + ")"
	case directory.FilterGreaterOrEqual:
		return "(" + filter.Attribute + ">=" + accesslogFilterValue(filter.Assertion) + ")"
	case directory.FilterLessOrEqual:
		return "(" + filter.Attribute + "<=" + accesslogFilterValue(filter.Assertion) + ")"
	case directory.FilterApprox:
		return "(" + filter.Attribute + "~=" + accesslogFilterValue(filter.Assertion) + ")"
	case directory.FilterPresent:
		return "(" + filter.Attribute + "=*)"
	case directory.FilterSubstrings:
		var value strings.Builder
		value.WriteByte('(')
		value.WriteString(filter.Attribute)
		value.WriteByte('=')
		value.WriteString(accesslogFilterValue(filter.Substring.Initial))
		value.WriteByte('*')
		for _, middle := range filter.Substring.Any {
			value.WriteString(accesslogFilterValue(middle))
			value.WriteByte('*')
		}
		value.WriteString(accesslogFilterValue(filter.Substring.Final))
		value.WriteByte(')')
		return value.String()
	case directory.FilterExtensible:
		var value strings.Builder
		value.WriteByte('(')
		value.WriteString(filter.Attribute)
		if filter.DNAttributes {
			value.WriteString(":dn")
		}
		if filter.MatchingRule != "" {
			value.WriteByte(':')
			value.WriteString(filter.MatchingRule)
		}
		value.WriteString(":=")
		value.WriteString(accesslogFilterValue(filter.Assertion))
		value.WriteByte(')')
		return value.String()
	default:
		return "(objectClass=*)"
	}
}

func accesslogFilterChildren(children []directory.Filter) string {
	var value strings.Builder
	for _, child := range children {
		value.WriteString(accesslogFilterText(child))
	}
	return value.String()
}

func accesslogFilterValue(raw []byte) string {
	var value strings.Builder
	for _, character := range raw {
		switch character {
		case 0, '(', ')', '*', '\\':
			fmt.Fprintf(&value, "\\%02x", character)
		default:
			value.WriteByte(character)
		}
	}
	return value.String()
}

func accesslogConfigurationApplies(
	configuration *accesslogRuntimeConfiguration,
	operation accesslogOperation,
	dn directory.DN,
) bool {
	if configuration == nil {
		return false
	}
	if configuration.operations&operation != 0 {
		return true
	}
	for _, base := range configuration.bases {
		if base.operations&operation != 0 &&
			(base.base.Equal(dn) || base.base.AncestorOf(dn)) {
			return true
		}
	}
	return false
}

func addAccesslogMinCSN(
	container *directory.Entry,
	csn openLDAPCSN,
) (bool, error) {
	state := make(syncCSNState)
	for _, raw := range container.Values("minCSN") {
		parsed, err := parseOpenLDAPCSN(string(raw))
		if err != nil {
			return false, fmt.Errorf("parse accesslog minCSN %q: %w", raw, err)
		}
		state[parsed.serverID] = parsed
	}
	if _, exists := state[csn.serverID]; exists {
		return false, nil
	}
	state[csn.serverID] = csn
	container.ReplaceValues("minCSN", accesslogCSNValues(state))
	return true, nil
}

func (server *Server) accesslogCSN(
	ctx context.Context,
	runtime *runtimeState,
	record accesslogWriteRecord,
	sourceChange *syncChange,
) (openLDAPCSN, error) {
	if sourceChange != nil {
		return sourceChange.csn, nil
	}
	if record.after != nil {
		values := record.after.Values("entryCSN")
		if len(values) == 1 {
			if csn, err := parseOpenLDAPCSN(string(values[0])); err == nil {
				return csn, nil
			}
		}
	}
	return parseOpenLDAPCSN(server.nextCSNContext(ctx, runtime.serverID))
}

func (server *Server) nextAccesslogTimestamp() string {
	server.accesslogMu.Lock()
	defer server.accesslogMu.Unlock()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if !server.lastAccesslogTime.IsZero() && !now.After(server.lastAccesslogTime) {
		now = server.lastAccesslogTime.Add(time.Microsecond)
	}
	server.lastAccesslogTime = now
	return now.Format("20060102150405.000000Z")
}

func (server *Server) nextAccesslogTimestampContext(ctx context.Context) string {
	clock, ok := ctx.Value(transactionPreflightClockContextKey{}).(*transactionPreflightClock)
	if !ok {
		return server.nextAccesslogTimestamp()
	}
	now := clock.now
	if !clock.lastAccesslogTime.IsZero() && !now.After(clock.lastAccesslogTime) {
		now = clock.lastAccesslogTime.Add(time.Microsecond)
	}
	clock.lastAccesslogTime = now
	return now.Format("20060102150405.000000Z")
}

func (server *Server) seedAccesslogClock(runtime *runtimeState) error {
	if runtime == nil {
		return nil
	}
	seen := make(map[int]struct{})
	var latest time.Time
	err := server.config.Store.View(
		context.Background(),
		func(reader storage.Reader) error {
			for index := range runtime.databases {
				configuration := runtime.databases[index].accesslog
				if configuration == nil ||
					configuration.targetDatabaseIndex < 0 {
					continue
				}
				targetIndex := configuration.targetDatabaseIndex
				if _, alreadyScanned := seen[targetIndex]; alreadyScanned {
					continue
				}
				seen[targetIndex] = struct{}{}
				partition := runtime.databases[targetIndex].partition
				if err := reader.ForEachIn(
					partition,
					func(entry directory.Entry) error {
						values := entry.Values("reqStart")
						if len(values) == 0 {
							return nil
						}
						if len(values) != 1 {
							return fmt.Errorf(
								"accesslog entry %s has %d reqStart values",
								entry.DN,
								len(values),
							)
						}
						timestamp, err := parseAccesslogTimestamp(
							string(values[0]),
						)
						if err != nil {
							return fmt.Errorf(
								"accesslog entry %s reqStart: %w",
								entry.DN,
								err,
							)
						}
						if timestamp.After(latest) {
							latest = timestamp
						}
						return nil
					},
				); err != nil {
					return err
				}
			}
			return nil
		},
	)
	if err != nil {
		return err
	}
	server.accesslogMu.Lock()
	server.lastAccesslogTime = latest
	server.accesslogMu.Unlock()
	return nil
}

func parseAccesslogTimestamp(raw string) (time.Time, error) {
	for _, layout := range []string{
		"20060102150405.000000Z",
		"20060102150405Z",
	} {
		if timestamp, err := time.Parse(layout, raw); err == nil {
			return timestamp.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid generalized time %q", raw)
}

type accesslogPurgeSchedule struct {
	age      time.Duration
	interval time.Duration
	next     time.Time
}

func (server *Server) runAccesslogPurge(ctx context.Context) {
	schedules := make(map[string]accesslogPurgeSchedule)
	for {
		runtime := server.runtime.Load()
		now := time.Now().UTC()
		active := make(map[string]runtimeDatabase)
		if runtime != nil {
			for index := range runtime.databases {
				database := runtime.databases[index]
				if database.accesslog == nil ||
					database.accesslog.purgeAge <= 0 ||
					database.accesslog.purgeInterval <= 0 ||
					database.disabled {
					continue
				}
				key := database.configDNKey
				if key == "" {
					key = database.partition
				}
				active[key] = database
			}
		}
		for key := range schedules {
			if _, exists := active[key]; !exists {
				delete(schedules, key)
			}
		}

		var due []runtimeDatabase
		for key, database := range active {
			configuration := database.accesslog
			schedule, exists := schedules[key]
			if !exists || schedule.age != configuration.purgeAge ||
				schedule.interval != configuration.purgeInterval {
				schedule = accesslogPurgeSchedule{
					age:      configuration.purgeAge,
					interval: configuration.purgeInterval,
					next:     now.Add(configuration.purgeInterval),
				}
			}
			if !now.Before(schedule.next) {
				due = append(due, database)
				schedule.next = now.Add(schedule.interval)
			}
			schedules[key] = schedule
		}
		for _, database := range due {
			if err := server.purgeAccesslogDatabase(
				ctx,
				runtime,
				database,
				now,
			); err != nil && ctx.Err() == nil {
				server.config.Logger.Error(
					"accesslog purge failed",
					"database",
					database.name,
					"error",
					err,
				)
			}
		}

		wait, scheduled := nextAccesslogPurgeWait(schedules, time.Now().UTC())
		if !scheduled {
			select {
			case <-ctx.Done():
				return
			case <-server.accesslogWake:
				continue
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			stopAndDrainTimer(timer)
			return
		case <-server.accesslogWake:
			stopAndDrainTimer(timer)
		case <-timer.C:
		}
	}
}

func nextAccesslogPurgeWait(
	schedules map[string]accesslogPurgeSchedule,
	now time.Time,
) (time.Duration, bool) {
	var earliest time.Time
	for _, schedule := range schedules {
		if earliest.IsZero() || schedule.next.Before(earliest) {
			earliest = schedule.next
		}
	}
	if earliest.IsZero() {
		return 0, false
	}
	wait := earliest.Sub(now)
	if wait < 0 {
		wait = 0
	}
	return wait, true
}

func (server *Server) purgeAccesslogDatabase(
	ctx context.Context,
	runtime *runtimeState,
	source runtimeDatabase,
	now time.Time,
) error {
	configuration := source.accesslog
	if runtime == nil || configuration == nil ||
		configuration.targetDatabaseIndex < 0 ||
		configuration.targetDatabaseIndex >= len(runtime.databases) {
		return nil
	}
	target := runtime.databases[configuration.targetDatabaseIndex]
	cutoff := now.UTC().Add(-configuration.purgeAge)
	return server.config.Store.Update(ctx, func(writer storage.Writer) error {
		content := writerForDatabase(writer, target)
		var expired []directory.Entry
		if err := content.ForEach(
			func(entry directory.Entry) error {
				values := entry.Values("reqStart")
				if len(values) == 0 {
					return nil
				}
				entryDN, err := syncConsumerParseDN(content, entry.DN)
				if err != nil {
					return err
				}
				parent, hasParent := entryDN.Parent()
				if !hasParent || !parent.Equal(configuration.targetSuffix) {
					return nil
				}
				if len(values) != 1 {
					return fmt.Errorf(
						"accesslog entry %s has %d reqStart values",
						entry.DN,
						len(values),
					)
				}
				timestamp, err := parseAccesslogTimestamp(string(values[0]))
				if err != nil {
					return fmt.Errorf("accesslog entry %s: %w", entry.DN, err)
				}
				if !timestamp.After(cutoff) {
					expired = append(expired, entry)
				}
				return nil
			},
		); err != nil {
			return err
		}
		if len(expired) == 0 {
			return nil
		}

		minCSNs := make(syncCSNState)
		container, err := content.Get(configuration.targetSuffix)
		if err != nil {
			return err
		}
		for _, raw := range container.Values("minCSN") {
			csn, parseErr := parseOpenLDAPCSN(string(raw))
			if parseErr != nil {
				return fmt.Errorf("parse accesslog minCSN %q: %w", raw, parseErr)
			}
			minCSNs[csn.serverID] = csn
		}
		for _, entry := range expired {
			dn, parseErr := directory.ParseDN(entry.DN)
			if parseErr != nil {
				return parseErr
			}
			if err := writer.DeleteIn(target.partition, dn); err != nil {
				return err
			}
			for _, raw := range entry.Values("entryCSN") {
				csn, parseErr := parseOpenLDAPCSN(string(raw))
				if parseErr != nil {
					return fmt.Errorf(
						"parse purged accesslog entryCSN %q: %w",
						raw,
						parseErr,
					)
				}
				current, exists := minCSNs[csn.serverID]
				if !exists || compareOpenLDAPCSN(current, csn) < 0 {
					minCSNs[csn.serverID] = csn
				}
			}
		}
		values := make([][]byte, 0, len(minCSNs))
		for _, raw := range orderedSyncCSNs(minCSNs) {
			values = append(values, []byte(raw))
		}
		container.ReplaceValues("minCSN", values)
		return content.Put(container, true)
	})
}

func accesslogObjectClass(operation accesslogOperation) string {
	switch operation {
	case accesslogAdd:
		return "auditAdd"
	case accesslogDelete:
		return "auditDelete"
	case accesslogModify:
		return "auditModify"
	case accesslogModifyDN:
		return "auditModRDN"
	case accesslogCompare:
		return "auditCompare"
	case accesslogSearch:
		return "auditSearch"
	case accesslogBind:
		return "auditBind"
	case accesslogAbandon:
		return "auditAbandon"
	case accesslogExtended:
		return "auditExtended"
	default:
		return "auditObject"
	}
}

func accesslogOperationName(operation accesslogOperation) string {
	switch operation {
	case accesslogAdd:
		return "add"
	case accesslogDelete:
		return "delete"
	case accesslogModify:
		return "modify"
	case accesslogModifyDN:
		return "modrdn"
	case accesslogCompare:
		return "compare"
	case accesslogSearch:
		return "search"
	case accesslogBind:
		return "bind"
	case accesslogUnbind:
		return "unbind"
	case accesslogAbandon:
		return "abandon"
	case accesslogExtended:
		return "extended"
	default:
		return "unknown"
	}
}

func accesslogEntryUUID(record accesslogWriteRecord) string {
	entry := record.after
	if entry == nil {
		entry = record.before
	}
	if entry == nil {
		return ""
	}
	values := entry.Values("entryUUID")
	if len(values) != 1 {
		return ""
	}
	return string(values[0])
}

func accesslogAddValues(entry *directory.Entry) [][]byte {
	if entry == nil {
		return nil
	}
	attributes := append([]directory.Attribute(nil), entry.Attributes...)
	sort.SliceStable(attributes, func(i, j int) bool {
		return strings.ToLower(attributes[i].Description) <
			strings.ToLower(attributes[j].Description)
	})
	var values [][]byte
	for _, attribute := range attributes {
		for _, value := range attribute.Values {
			values = append(values, accesslogModificationValue(
				attribute.Description,
				'+',
				value,
				true,
			))
		}
	}
	return values
}

func accesslogDifferenceValuesExcluding(
	before,
	after *directory.Entry,
	excluded map[string]struct{},
) [][]byte {
	beforeAttributes := accesslogAttributeMap(before)
	afterAttributes := accesslogAttributeMap(after)
	keys := make(map[string]struct{}, len(beforeAttributes)+len(afterAttributes))
	for key := range beforeAttributes {
		keys[key] = struct{}{}
	}
	for key := range afterAttributes {
		keys[key] = struct{}{}
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	var result [][]byte
	for _, key := range ordered {
		if _, skip := excluded[key]; skip {
			continue
		}
		beforeAttribute, beforeExists := beforeAttributes[key]
		afterAttribute, afterExists := afterAttributes[key]
		if beforeExists && afterExists &&
			accesslogValuesEqual(beforeAttribute.Values, afterAttribute.Values) {
			continue
		}
		description := beforeAttribute.Description
		if afterExists {
			description = afterAttribute.Description
		}
		if !afterExists || len(afterAttribute.Values) == 0 {
			result = append(result, accesslogModificationValue(
				description,
				'=',
				nil,
				false,
			))
			continue
		}
		for _, value := range afterAttribute.Values {
			result = append(result, accesslogModificationValue(
				description,
				'=',
				value,
				true,
			))
		}
	}
	return result
}

func accesslogModifyValues(record accesslogWriteRecord) [][]byte {
	values := accesslogModificationValues(record.modifications)
	touched := make(map[string]struct{}, len(record.modifications))
	for _, modification := range record.modifications {
		touched[strings.ToLower(modification.Attribute.Description)] = struct{}{}
	}
	return append(
		values,
		accesslogDifferenceValuesExcluding(record.before, record.after, touched)...,
	)
}

func accesslogModifyDNValues(
	registry *schema.Registry,
	record accesslogWriteRecord,
) [][]byte {
	excluded := make(map[string]struct{})
	for _, value := range record.requestDN.RDNValues() {
		excluded[strings.ToLower(value.Type)] = struct{}{}
	}
	if record.after != nil {
		if newDN, err := registry.NormalizeDN(record.after.DN); err == nil {
			for _, value := range newDN.RDNValues() {
				excluded[strings.ToLower(value.Type)] = struct{}{}
			}
		}
	}
	return accesslogDifferenceValuesExcluding(
		record.before,
		record.after,
		excluded,
	)
}

func accesslogOldValues(
	registry *schema.Registry,
	configuration *accesslogRuntimeConfiguration,
	record accesslogWriteRecord,
) ([][]byte, error) {
	if configuration == nil ||
		configuration.oldFilter == nil ||
		record.before == nil ||
		record.operation == accesslogAdd {
		return nil, nil
	}
	if record.operation == accesslogModifyDN &&
		len(configuration.oldAttributes) == 0 {
		return nil, nil
	}
	matches, err := configuration.oldFilter.MatchWith(*record.before, registry)
	if err != nil {
		return nil, fmt.Errorf("match olcAccessLogOld filter: %w", err)
	}
	if !matches {
		return nil, nil
	}

	all := record.operation == accesslogDelete
	requested := append([]string(nil), configuration.oldAttributes...)
	if record.operation == accesslogModify {
		for _, modification := range record.modifications {
			requested = append(requested, modification.Attribute.Description)
		}
	}
	if record.operation == accesslogModifyDN {
		for _, value := range record.requestDN.RDNValues() {
			requested = append(requested, value.Type)
		}
		if record.after != nil {
			if afterDN, parseErr := registry.NormalizeDN(record.after.DN); parseErr == nil {
				for _, value := range afterDN.RDNValues() {
					requested = append(requested, value.Type)
				}
			}
		}
	}

	var values [][]byte
	for _, attribute := range record.before.Attributes {
		if !all && !accesslogOldAttributeRequested(
			registry,
			attribute.Description,
			requested,
		) {
			continue
		}
		for _, value := range attribute.Values {
			values = append(values, []byte(
				attribute.Description+": "+string(value),
			))
		}
	}
	return values, nil
}

func accesslogOldAttributeRequested(
	registry *schema.Registry,
	description string,
	requested []string,
) bool {
	for _, candidate := range requested {
		if registry.AttributeDescriptionSubtype(description, candidate) ||
			registry.AttributeDescriptionSubtype(candidate, description) {
			return true
		}
	}
	return false
}

func accesslogModificationValues(
	modifications []ldapwire.Modification,
) [][]byte {
	var values [][]byte
	for index, modification := range modifications {
		operation := byte('=')
		switch modification.Operation {
		case ldapwire.ModificationAdd:
			operation = '+'
		case ldapwire.ModificationDelete:
			operation = '-'
		case ldapwire.ModificationReplace:
			operation = '='
		case ldapwire.ModificationIncrement:
			operation = '#'
		}
		if len(modification.Attribute.Values) == 0 {
			values = append(values, accesslogModificationValue(
				modification.Attribute.Description,
				operation,
				nil,
				false,
			))
		} else {
			for _, value := range modification.Attribute.Values {
				values = append(values, accesslogModificationValue(
					modification.Attribute.Description,
					operation,
					value,
					true,
				))
			}
		}
		if index+1 < len(modifications) {
			values = append(values, []byte(":"))
		}
	}
	return values
}

func accesslogAttributeMap(
	entry *directory.Entry,
) map[string]directory.Attribute {
	result := make(map[string]directory.Attribute)
	if entry == nil {
		return result
	}
	for _, attribute := range entry.Attributes {
		result[strings.ToLower(attribute.Description)] = attribute
	}
	return result
}

func accesslogValuesEqual(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

func accesslogModificationValue(
	description string,
	operation byte,
	value []byte,
	hasValue bool,
) []byte {
	result := make([]byte, 0, len(description)+len(value)+3)
	result = append(result, description...)
	result = append(result, ':', operation)
	if hasValue {
		result = append(result, ' ')
		result = append(result, value...)
	}
	return result
}

func appendSyncChanges(
	destination []*syncChange,
	changes ...*syncChange,
) []*syncChange {
	for _, change := range changes {
		if change != nil {
			destination = append(destination, change)
		}
	}
	return destination
}
