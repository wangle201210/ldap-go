package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	dynamicRefreshOID = "1.3.6.1.4.1.1466.101.119.1"

	ddsRFCMaxTTL     = 31557600 * time.Second
	ddsDefaultMaxTTL = 86400 * time.Second
	ddsDefaultCheck  = 3600 * time.Second
)

type ddsRuntimeConfiguration struct {
	enabled           bool
	maxTTL            time.Duration
	minTTL            time.Duration
	defaultTTL        time.Duration
	interval          time.Duration
	tolerance         time.Duration
	maxDynamicObjects int
}

func loadDDSRuntimeConfiguration(
	entry directory.Entry,
	database runtimeDatabase,
) (ddsRuntimeConfiguration, error) {
	if databaseType(database.name) == "frontend" {
		return ddsRuntimeConfiguration{}, fmt.Errorf(
			"%s dds cannot be used as a global overlay",
			entry.DN,
		)
	}

	config := ddsRuntimeConfiguration{
		enabled:  true,
		maxTTL:   ddsDefaultMaxTTL,
		interval: ddsDefaultCheck,
	}
	state, present, err := singleBoolean(entry, "olcDDSstate")
	if err != nil {
		return ddsRuntimeConfiguration{}, err
	}
	if present {
		config.enabled = state
	}

	config.maxTTL, present, err = singleDDSTime(
		entry,
		"olcDDSmaxTtl",
		ddsDefaultMaxTTL,
	)
	if err != nil {
		return ddsRuntimeConfiguration{}, err
	}
	if present &&
		(config.maxTTL < ddsDefaultMaxTTL || config.maxTTL > ddsRFCMaxTTL) {
		return ddsRuntimeConfiguration{}, fmt.Errorf(
			"%s olcDDSmaxTtl must be between %s and %s",
			entry.DN,
			ddsDefaultMaxTTL,
			ddsRFCMaxTTL,
		)
	}

	config.minTTL, present, err = singleDDSTime(entry, "olcDDSminTtl", 0)
	if err != nil {
		return ddsRuntimeConfiguration{}, err
	}
	if present && config.minTTL == 0 {
		config.minTTL = ddsDefaultMaxTTL
	}
	if config.minTTL > ddsRFCMaxTTL {
		return ddsRuntimeConfiguration{}, fmt.Errorf(
			"%s olcDDSminTtl exceeds %s",
			entry.DN,
			ddsRFCMaxTTL,
		)
	}

	config.defaultTTL, present, err = singleDDSTime(
		entry,
		"olcDDSdefaultTtl",
		0,
	)
	if err != nil {
		return ddsRuntimeConfiguration{}, err
	}
	if present && config.defaultTTL == 0 {
		config.defaultTTL = ddsDefaultMaxTTL
	}
	if config.defaultTTL > ddsRFCMaxTTL {
		return ddsRuntimeConfiguration{}, fmt.Errorf(
			"%s olcDDSdefaultTtl exceeds %s",
			entry.DN,
			ddsRFCMaxTTL,
		)
	}

	config.interval, _, err = singleDDSTime(
		entry,
		"olcDDSinterval",
		ddsDefaultCheck,
	)
	if err != nil {
		return ddsRuntimeConfiguration{}, err
	}
	if config.interval <= 0 {
		return ddsRuntimeConfiguration{}, fmt.Errorf(
			"%s olcDDSinterval must be positive",
			entry.DN,
		)
	}

	config.tolerance, _, err = singleDDSTime(entry, "olcDDStolerance", 0)
	if err != nil {
		return ddsRuntimeConfiguration{}, err
	}
	if config.tolerance > ddsRFCMaxTTL {
		return ddsRuntimeConfiguration{}, fmt.Errorf(
			"%s olcDDStolerance exceeds %s",
			entry.DN,
			ddsRFCMaxTTL,
		)
	}

	config.maxDynamicObjects, err = singleNonnegativeInteger(
		entry,
		"olcDDSmaxDynamicObjects",
		0,
	)
	if err != nil {
		return ddsRuntimeConfiguration{}, err
	}

	if config.enabled {
		if database.shadow {
			return ddsRuntimeConfiguration{}, fmt.Errorf(
				"%s dds is incompatible with shadow database %s",
				entry.DN,
				database.name,
			)
		}
		effectiveDefault := config.defaultTTL
		if effectiveDefault == 0 {
			effectiveDefault = config.maxTTL
		}
		if effectiveDefault > config.maxTTL {
			return ddsRuntimeConfiguration{}, fmt.Errorf(
				"%s dds default TTL is greater than max TTL",
				entry.DN,
			)
		}
		if config.minTTL > config.maxTTL ||
			(config.defaultTTL != 0 && config.minTTL > config.defaultTTL) {
			return ddsRuntimeConfiguration{}, fmt.Errorf(
				"%s dds min TTL is greater than default or max TTL",
				entry.DN,
			)
		}
	}
	return config, nil
}

func (config ddsRuntimeConfiguration) effectiveDefaultTTL() time.Duration {
	if config.defaultTTL != 0 {
		return config.defaultTTL
	}
	return config.maxTTL
}

func singleDDSTime(
	entry directory.Entry,
	attribute string,
	defaultValue time.Duration,
) (time.Duration, bool, error) {
	values := entry.Values(attribute)
	if len(values) == 0 {
		return defaultValue, false, nil
	}
	if len(values) != 1 {
		return 0, false, fmt.Errorf(
			"%s %s must be single-valued",
			entry.DN,
			attribute,
		)
	}
	value := strings.TrimSpace(string(values[0]))
	duration, err := parseOpenLDAPTimeInterval(value)
	if err != nil {
		return 0, false, fmt.Errorf(
			"%s %s has invalid value %q: %w",
			entry.DN,
			attribute,
			values[0],
			err,
		)
	}
	return duration, true, nil
}

func parseOpenLDAPTimeInterval(value string) (time.Duration, error) {
	if value == "" {
		return 0, errors.New("empty time interval")
	}
	var seconds uint64
	remaining := value
	lastUnit := -1
	for remaining != "" {
		digits := 0
		for digits < len(remaining) &&
			remaining[digits] >= '0' &&
			remaining[digits] <= '9' {
			digits++
		}
		if digits == 0 {
			return 0, fmt.Errorf("invalid time interval %q", value)
		}
		number, err := strconv.ParseUint(remaining[:digits], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid time interval %q", value)
		}
		remaining = remaining[digits:]
		if remaining == "" {
			if lastUnit >= 3 {
				return 0, fmt.Errorf("invalid time interval %q", value)
			}
			if number > ^uint64(0)-seconds {
				return 0, fmt.Errorf("time interval %q is too large", value)
			}
			seconds += number
			break
		}
		unit := strings.IndexByte("dhms", remaining[0])
		if unit < 0 || unit <= lastUnit {
			return 0, fmt.Errorf("invalid time interval %q", value)
		}
		scale := [...]uint64{86400, 3600, 60, 1}
		if number > (^uint64(0)-seconds)/scale[unit] {
			return 0, fmt.Errorf("time interval %q is too large", value)
		}
		seconds += number * scale[unit]
		lastUnit = unit
		remaining = remaining[1:]
	}
	return durationFromUnsigned(seconds, time.Second, "time interval")
}

func dynamicSubtrees(databases []runtimeDatabase) []string {
	var subtrees []string
	seen := make(map[string]struct{})
	for index := range databases {
		database := &databases[index]
		if database.dds == nil || !database.dds.enabled {
			continue
		}
		for _, suffix := range database.suffixes {
			if _, exists := seen[suffix.Key()]; exists {
				continue
			}
			seen[suffix.Key()] = struct{}{}
			subtrees = append(subtrees, suffix.String())
		}
	}
	sort.Strings(subtrees)
	return subtrees
}

func projectDDSRemainingTTL(
	readable directory.Entry,
	source directory.Entry,
	now time.Time,
) directory.Entry {
	if !readable.HasAttribute("entryTtl") ||
		len(readable.Values("entryTtl")) == 0 {
		return readable
	}
	expiresValues := source.Values("entryExpireTimestamp")
	if len(expiresValues) != 1 {
		return readable
	}
	expires, err := parseDDSExpiration(string(expiresValues[0]))
	if err != nil {
		return readable
	}
	remaining := expires.Unix() - now.Unix()
	if remaining < 0 {
		remaining = 0
	}
	readable.ReplaceValues(
		"entryTtl",
		stringValues(strconv.FormatInt(remaining, 10)),
	)
	return readable
}

func prepareDDSAdd(
	runtime *runtimeState,
	database runtimeDatabase,
	entry *directory.Entry,
	now time.Time,
) error {
	if !runtime.schema.EntryHasObjectClass(*entry, "dynamicObject") {
		return nil
	}
	if database.dds == nil {
		return operationFailed(
			ldapwire.ResultObjectClassViolation,
			`objectClass "1.3.6.1.4.1.1466.101.119.2" not supported in context`,
		)
	}
	if !database.dds.enabled {
		return nil
	}
	if runtime.schema.EntryHasObjectClass(*entry, "referral") {
		return operationFailed(
			ldapwire.ResultObjectClassViolation,
			"a referral cannot be a dynamicObject",
		)
	}
	if runtime.schema.EntryHasObjectClass(*entry, "alias") {
		return operationFailed(
			ldapwire.ResultObjectClassViolation,
			"an alias cannot be a dynamicObject",
		)
	}

	ttl := database.dds.effectiveDefaultTTL()
	entry.ReplaceValues(
		"entryTtl",
		stringValues(strconv.FormatInt(int64(ttl/time.Second), 10)),
	)
	entry.ReplaceValues(
		"entryExpireTimestamp",
		stringValues(formatDDSExpiration(now.Add(ttl))),
	)
	return nil
}

func (server *Server) validateDDSAddParent(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	database runtimeDatabase,
	entry directory.Entry,
	parent directory.Entry,
) error {
	if database.dds == nil ||
		!database.dds.enabled ||
		runtime.schema.EntryHasObjectClass(entry, "dynamicObject") ||
		!runtime.schema.EntryHasObjectClass(parent, "dynamicObject") {
		return nil
	}
	if !server.allowed(
		runtime,
		reader,
		boundDN,
		parent,
		"entry",
		nil,
		acl.Disclose,
	) {
		return operationFailed(ldapwire.ResultNoSuchObject, "")
	}
	return operationFailed(
		ldapwire.ResultConstraintViolation,
		"no static subordinate entries allowed for dynamicObject",
	)
}

func enforceDDSDynamicObjectLimit(
	runtime *runtimeState,
	reader storage.Reader,
	database runtimeDatabase,
	dn directory.DN,
	entry directory.Entry,
) error {
	if database.dds == nil ||
		!database.dds.enabled ||
		database.dds.maxDynamicObjects == 0 ||
		!runtime.schema.EntryHasObjectClass(entry, "dynamicObject") ||
		databaseHasExactSuffix(database, dn) {
		return nil
	}

	count := 0
	if err := reader.ForEach(func(candidate directory.Entry) error {
		if runtime.schema.EntryHasObjectClass(candidate, "dynamicObject") {
			count++
		}
		return nil
	}); err != nil {
		return err
	}
	if count >= database.dds.maxDynamicObjects {
		return operationFailed(
			ldapwire.ResultUnwillingToPerform,
			"too many dynamicObjects in context",
		)
	}
	return nil
}

func validateDDSModification(
	runtime *runtimeState,
	database runtimeDatabase,
	before directory.Entry,
	after directory.Entry,
) error {
	wasDynamic := runtime.schema.EntryHasObjectClass(before, "dynamicObject")
	isDynamic := runtime.schema.EntryHasObjectClass(after, "dynamicObject")
	switch {
	case wasDynamic && !isDynamic:
		return operationFailed(
			ldapwire.ResultObjectClassViolation,
			"objectClass modification cannot turn dynamicObject into static entry",
		)
	case !wasDynamic && isDynamic:
		return operationFailed(
			ldapwire.ResultObjectClassViolation,
			"objectClass modification cannot turn static entry into dynamicObject",
		)
	case !isDynamic:
		return nil
	}
	if database.dds == nil {
		return operationFailed(
			ldapwire.ResultObjectClassViolation,
			`objectClass "1.3.6.1.4.1.1466.101.119.2" not supported in context`,
		)
	}
	if !database.dds.enabled {
		return nil
	}
	if runtime.schema.EntryHasObjectClass(after, "referral") {
		return operationFailed(
			ldapwire.ResultObjectClassViolation,
			"a referral cannot be a dynamicObject",
		)
	}
	if runtime.schema.EntryHasObjectClass(after, "alias") {
		return operationFailed(
			ldapwire.ResultObjectClassViolation,
			"an alias cannot be a dynamicObject",
		)
	}
	return nil
}

func (server *Server) validateDDSRename(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	database runtimeDatabase,
	source directory.Entry,
	newParent directory.Entry,
	hasNewSuperior bool,
) error {
	if !hasNewSuperior ||
		database.dds == nil ||
		!database.dds.enabled ||
		runtime.schema.EntryHasObjectClass(source, "dynamicObject") ||
		!runtime.schema.EntryHasObjectClass(newParent, "dynamicObject") {
		return nil
	}
	if !server.allowed(
		runtime,
		reader,
		boundDN,
		newParent,
		"entry",
		nil,
		acl.Disclose,
	) {
		return operationFailed(ldapwire.ResultNoSuchObject, "")
	}
	return operationFailed(
		ldapwire.ResultConstraintViolation,
		"static entry cannot have dynamicObject as newSuperior",
	)
}

func databaseHasExactSuffix(database runtimeDatabase, dn directory.DN) bool {
	for _, suffix := range database.suffixes {
		if suffix.Equal(dn) {
			return true
		}
	}
	return false
}

func formatDDSExpiration(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format("20060102150405Z")
}

func parseDDSExpiration(value string) (time.Time, error) {
	if parsed, err := time.Parse("20060102150405Z", value); err == nil {
		return parsed, nil
	}
	return time.Parse("20060102150405.000000Z", value)
}

func (server *Server) handleDynamicRefresh(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.ExtendedRequest,
) error {
	refresh, err := ldapwire.DecodeDynamicRefreshRequestValue(
		request.Value,
		request.HasValue,
	)
	if err != nil {
		return server.writeDynamicRefreshResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"data decoding error",
			),
			0,
		)
	}
	dn, err := directory.ParseDN(refresh.EntryName)
	if err != nil {
		return server.writeDynamicRefreshResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultInvalidDNSyntax,
				"invalid DN",
			),
			0,
		)
	}
	if refresh.RequestTTL <= 0 ||
		refresh.RequestTTL > int64(ddsRFCMaxTTL/time.Second) {
		return server.writeDynamicRefreshResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"invalid time-to-live for dynamicObject",
			),
			0,
		)
	}

	database := databaseForDN(state.runtime, dn)
	if database == nil {
		return server.writeDynamicRefreshResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultNoSuchObject,
				"no global superior knowledge",
			),
			0,
		)
	}
	if database.dds == nil {
		return server.writeDynamicRefreshResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnavailableCriticalExtension,
				"backend does not support dynamic directory services",
			),
			0,
		)
	}
	if !database.dds.enabled {
		return server.writeDynamicRefreshResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"not supported within naming context",
			),
			0,
		)
	}
	if result := updateOperationPrecondition(
		state.runtime,
		state.boundDN,
		dn,
	); result != nil {
		return server.writeDynamicRefreshResult(
			connection,
			message.ID,
			*result,
			0,
		)
	}

	ttl := time.Duration(refresh.RequestTTL) * time.Second
	if ttl > database.dds.maxTTL {
		return server.writeDynamicRefreshResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultSizeLimitExceeded,
				"time-to-live for dynamicObject exceeds limit",
			),
			0,
		)
	}
	if database.dds.minTTL != 0 && ttl < database.dds.minTTL {
		ttl = database.dds.minTTL
	}
	responseTTL := int64(ttl / time.Second)

	var syncChange *syncChange
	err = server.updateStorage(ctx, func(writer storage.Writer) error {
		tx := storage.WriterInPartition(writer, database.partition)
		entry, err := tx.Get(dn)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return &operationFailure{result: ldapwire.Result{
				Code: ldapwire.ResultNoSuchObject,
				MatchedDN: server.disclosedAncestor(
					state.runtime,
					tx,
					state.boundDN,
					dn,
				),
			}}
		}
		if err != nil {
			return err
		}
		logicalEntry, err := withCollectiveAttributes(
			state.runtime.schema,
			tx,
			entry,
		)
		if err != nil {
			return err
		}
		if !state.runtime.schema.EntryHasObjectClass(
			entry,
			"dynamicObject",
		) {
			if !server.allowed(
				state.runtime,
				tx,
				state.boundDN,
				logicalEntry,
				"entry",
				nil,
				acl.Disclose,
			) {
				return operationFailed(ldapwire.ResultNoSuchObject, "")
			}
			return operationFailed(
				ldapwire.ResultObjectClassViolation,
				"refresh operation only applies to dynamic objects",
			)
		}
		if !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			logicalEntry,
			"entryTtl",
			nil,
			acl.Manage,
		) {
			return operationFailed(
				ldapwire.ResultInsufficientAccessRights,
				"",
			)
		}

		before := entry.Clone()
		entry.ReplaceValues(
			"entryTtl",
			stringValues(strconv.FormatInt(responseTTL, 10)),
		)
		entry.ReplaceValues(
			"entryExpireTimestamp",
			stringValues(formatDDSExpiration(time.Now().Add(ttl))),
		)
		if lastModEnabled(state.runtime, dn) {
			server.applyModifyOperationalAttributes(
				&entry,
				state.boundDN,
				state.runtime.serverID,
			)
		}
		if err := state.runtime.schema.ValidateEntry(entry); err != nil {
			return operationFailureFromSchema(err)
		}
		if err := server.applySchemaOperationalAttributes(
			state.runtime,
			&entry,
		); err != nil {
			return err
		}
		if err := tx.Put(entry, true); err != nil {
			return err
		}
		syncChange, err = server.recordSyncChange(
			writer,
			state.runtime,
			*database,
			&before,
			&entry,
		)
		return err
	})
	if err != nil {
		return server.finishDynamicRefresh(
			connection,
			message.ID,
			err,
		)
	}
	server.finishWriteEffects(ctx, nil, syncChange)
	return server.writeDynamicRefreshResult(
		connection,
		message.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		responseTTL,
	)
}

func (server *Server) finishDynamicRefresh(
	connection net.Conn,
	messageID int64,
	err error,
) error {
	if failure := asOperationFailure(err); failure != nil {
		return server.writeDynamicRefreshResult(
			connection,
			messageID,
			failure.result,
			0,
		)
	}
	server.config.Logger.Error(
		"LDAP dynamic refresh failed",
		"message_id",
		messageID,
		"error",
		err,
	)
	return server.writeDynamicRefreshResult(
		connection,
		messageID,
		ldapwire.ResultError(
			ldapwire.ResultOperationsError,
			"internal operation error",
		),
		0,
	)
}

func (server *Server) writeDynamicRefreshResult(
	connection net.Conn,
	messageID int64,
	result ldapwire.Result,
	responseTTL int64,
) error {
	var (
		responseName  string
		responseValue []byte
	)
	if result.Code == ldapwire.ResultSuccess {
		responseName = dynamicRefreshOID
		responseValue = ldapwire.EncodeDynamicRefreshResponseValue(responseTTL)
	}
	return server.writeLDAPResultResponse(
		connection,
		messageID,
		ldapwire.ApplicationExtendedResponse,
		result,
		responseName,
		responseValue,
		nil,
	)
}

type ddsExpirationSchedule struct {
	interval time.Duration
	next     time.Time
}

func (server *Server) runDDSExpiration(ctx context.Context) {
	schedules := make(map[string]ddsExpirationSchedule)
	for {
		runtime := server.runtime.Load()
		now := time.Now()
		active := make(map[string]runtimeDatabase)
		if runtime != nil {
			for _, database := range runtime.databases {
				if database.dds == nil ||
					!database.dds.enabled ||
					database.disabled {
					continue
				}
				active[database.partition] = database
			}
		}
		for partition := range schedules {
			if _, exists := active[partition]; !exists {
				delete(schedules, partition)
			}
		}

		var due []runtimeDatabase
		for partition, database := range active {
			schedule, exists := schedules[partition]
			if !exists || schedule.interval != database.dds.interval {
				schedule = ddsExpirationSchedule{
					interval: database.dds.interval,
					next:     now.Add(database.dds.interval),
				}
			}
			if !now.Before(schedule.next) {
				due = append(due, database)
				schedule.next = now.Add(schedule.interval)
			}
			schedules[partition] = schedule
		}
		for _, database := range due {
			if err := server.expireDDSDatabase(ctx, database, now); err != nil &&
				ctx.Err() == nil {
				server.config.Logger.Error(
					"DDS expiration failed",
					"database",
					database.name,
					"error",
					err,
				)
			}
		}

		wait, scheduled := nextDDSExpirationWait(schedules, time.Now())
		if !scheduled {
			select {
			case <-ctx.Done():
				return
			case <-server.ddsWake:
				continue
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			stopAndDrainTimer(timer)
			return
		case <-server.ddsWake:
			stopAndDrainTimer(timer)
		case <-timer.C:
		}
	}
}

func nextDDSExpirationWait(
	schedules map[string]ddsExpirationSchedule,
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

func stopAndDrainTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (server *Server) expireDDSDatabase(
	ctx context.Context,
	scheduled runtimeDatabase,
	now time.Time,
) error {
	var changes []*syncChange
	err := server.config.Store.Update(ctx, func(writer storage.Writer) error {
		runtime := server.runtime.Load()
		database := runtimeDatabaseForPartition(runtime, scheduled.partition)
		if database == nil ||
			database.dds == nil ||
			!database.dds.enabled ||
			database.disabled {
			return nil
		}
		tx := storage.WriterInPartition(writer, database.partition)
		threshold := now.Add(-database.dds.tolerance)

		type expiredEntry struct {
			dn    directory.DN
			entry directory.Entry
		}
		var expired []expiredEntry
		if err := tx.ForEach(func(entry directory.Entry) error {
			if !runtime.schema.EntryHasObjectClass(entry, "dynamicObject") {
				return nil
			}
			values := entry.Values("entryExpireTimestamp")
			if len(values) != 1 {
				return nil
			}
			expires, err := parseDDSExpiration(string(values[0]))
			if err != nil || expires.After(threshold) {
				return nil
			}
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			expired = append(expired, expiredEntry{dn: dn, entry: entry})
			return nil
		}); err != nil {
			return err
		}
		sort.Slice(expired, func(i, j int) bool {
			return expired[i].dn.Depth() > expired[j].dn.Depth()
		})

		deleted := false
		for _, candidate := range expired {
			hasChildren := false
			if err := tx.ForEach(func(entry directory.Entry) error {
				dn, err := directory.ParseDN(entry.DN)
				if err != nil {
					return err
				}
				if candidate.dn.AncestorOf(dn) {
					hasChildren = true
				}
				return nil
			}); err != nil {
				return err
			}
			if hasChildren {
				continue
			}
			if err := tx.Delete(candidate.dn); err != nil {
				if errors.Is(err, storage.ErrEntryNotFound) {
					continue
				}
				return err
			}
			change, err := server.recordSyncChange(
				writer,
				runtime,
				*database,
				&candidate.entry,
				nil,
			)
			if err != nil {
				return err
			}
			if change != nil {
				changes = append(changes, change)
			}
			deleted = true
		}
		if deleted {
			return refreshNamingContexts(writer)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, change := range changes {
		server.publishSyncChange(change)
	}
	return nil
}
