package server

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type sqlBackendTransactionContextKey struct{}

type sqlBackendReadContextKey struct{}

type sqlBackendRenameContextKey struct{}

type sqlBackendModifyContextKey struct{}

type sqlBackendTreeDeleteContextKey struct{}

type sqlBackendRenameContext struct {
	oldDN directory.DN
	newDN directory.DN
}

type sqlBackendModifyContext struct {
	dn      directory.DN
	changes []ldapwire.Modification
}

type sqlBackendAttributeProcedureExecutionError struct {
	attribute string
	err       error
}

func (err *sqlBackendAttributeProcedureExecutionError) Error() string {
	return fmt.Sprintf(
		"execute SQL-backend attribute procedure for %s: %v",
		err.attribute,
		err.err,
	)
}

func (err *sqlBackendAttributeProcedureExecutionError) Unwrap() error {
	return err.err
}

func withSQLBackendModify(
	ctx context.Context,
	modify *sqlBackendModifyContext,
) context.Context {
	return context.WithValue(ctx, sqlBackendModifyContextKey{}, modify)
}

func sqlBackendModifyFromContext(ctx context.Context) *sqlBackendModifyContext {
	if ctx == nil {
		return nil
	}
	modify, _ := ctx.Value(sqlBackendModifyContextKey{}).(*sqlBackendModifyContext)
	return modify
}

func withSQLBackendTreeDelete(ctx context.Context) context.Context {
	return context.WithValue(ctx, sqlBackendTreeDeleteContextKey{}, true)
}

func sqlBackendTreeDeleteFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	treeDelete, _ := ctx.Value(sqlBackendTreeDeleteContextKey{}).(bool)
	return treeDelete
}

func withSQLBackendRename(
	ctx context.Context,
	oldDN,
	newDN directory.DN,
) context.Context {
	return context.WithValue(ctx, sqlBackendRenameContextKey{}, sqlBackendRenameContext{
		oldDN: oldDN,
		newDN: newDN,
	})
}

func sqlBackendRenameFromContext(ctx context.Context) *sqlBackendRenameContext {
	if ctx == nil {
		return nil
	}
	rename, ok := ctx.Value(sqlBackendRenameContextKey{}).(sqlBackendRenameContext)
	if !ok {
		return nil
	}
	return &rename
}

type sqlBackendReadSession struct {
	tx      *sql.Tx
	conn    *sql.Conn
	queryer sqlBackendQueryer
	err     error
}

type sqlBackendReadCoordinator struct {
	ctx      context.Context
	mu       sync.Mutex
	sessions map[*sqlBackendRuntimeConfiguration]sqlBackendReadSession
}

func newSQLBackendReadCoordinator(ctx context.Context) *sqlBackendReadCoordinator {
	return &sqlBackendReadCoordinator{
		ctx:      ctx,
		sessions: make(map[*sqlBackendRuntimeConfiguration]sqlBackendReadSession),
	}
}

func withSQLBackendReadCoordinator(
	ctx context.Context,
	coordinator *sqlBackendReadCoordinator,
) context.Context {
	return context.WithValue(ctx, sqlBackendReadContextKey{}, coordinator)
}

func sqlBackendReadCoordinatorFromContext(
	ctx context.Context,
) *sqlBackendReadCoordinator {
	if ctx == nil {
		return nil
	}
	coordinator, _ := ctx.Value(sqlBackendReadContextKey{}).(*sqlBackendReadCoordinator)
	return coordinator
}

func (coordinator *sqlBackendReadCoordinator) reader(
	configuration *sqlBackendRuntimeConfiguration,
	base storage.Reader,
	contexts ...context.Context,
) *sqlBackendReader {
	ctx := coordinator.ctx
	if len(contexts) != 0 && contexts[0] != nil {
		ctx = contexts[0]
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	session, found := coordinator.sessions[configuration]
	if !found {
		database, err := configuration.database(coordinator.ctx)
		if err == nil {
			session.conn, err = database.Conn(coordinator.ctx)
		}
		if err == nil && !configuration.autocommit {
			session.tx, err = session.conn.BeginTx(coordinator.ctx, &sql.TxOptions{
				Isolation: sql.LevelRepeatableRead,
				ReadOnly:  true,
			})
			if err != nil {
				session.tx, err = session.conn.BeginTx(coordinator.ctx, nil)
			}
		}
		if session.tx != nil {
			session.queryer = session.tx
		} else if err == nil {
			session.queryer = session.conn
		}
		session.err = sqlBackendLDAPError(err)
		coordinator.sessions[configuration] = session
	}
	return &sqlBackendReader{
		Reader:            base,
		configuration:     configuration,
		ctx:               ctx,
		queryer:           session.queryer,
		initializationErr: session.err,
	}
}

func (coordinator *sqlBackendReadCoordinator) close() {
	coordinator.mu.Lock()
	sessions := make([]sqlBackendReadSession, 0, len(coordinator.sessions))
	for _, session := range coordinator.sessions {
		sessions = append(sessions, session)
	}
	coordinator.mu.Unlock()
	for _, session := range sessions {
		if session.tx != nil {
			_ = session.tx.Rollback()
		}
		if session.conn != nil {
			_ = session.conn.Close()
		}
	}
}

type sqlBackendTransactionCoordinator struct {
	ctx              context.Context
	mu               sync.Mutex
	sessions         map[*sqlBackendRuntimeConfiguration]*sqlBackendWriter
	order            []*sqlBackendWriter
	cleanup          []func()
	candidateCleanup func()
}

func newSQLBackendTransactionCoordinator(
	ctx context.Context,
) *sqlBackendTransactionCoordinator {
	return &sqlBackendTransactionCoordinator{
		ctx:      ctx,
		sessions: make(map[*sqlBackendRuntimeConfiguration]*sqlBackendWriter),
	}
}

func withSQLBackendTransactionCoordinator(
	ctx context.Context,
	coordinator *sqlBackendTransactionCoordinator,
) context.Context {
	return context.WithValue(ctx, sqlBackendTransactionContextKey{}, coordinator)
}

func sqlBackendTransactionCoordinatorFromContext(
	ctx context.Context,
) *sqlBackendTransactionCoordinator {
	if ctx == nil {
		return nil
	}
	coordinator, _ := ctx.Value(sqlBackendTransactionContextKey{}).(*sqlBackendTransactionCoordinator)
	return coordinator
}

func (coordinator *sqlBackendTransactionCoordinator) writer(
	configuration *sqlBackendRuntimeConfiguration,
	base storage.Writer,
) *sqlBackendWriter {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if existing := coordinator.sessions[configuration]; existing != nil {
		return existing
	}
	writer := &sqlBackendWriter{
		Writer: base,
		reader: &sqlBackendReader{
			Reader:        base,
			configuration: configuration,
			ctx:           coordinator.ctx,
		},
	}
	writer.rename = sqlBackendRenameFromContext(coordinator.ctx)
	writer.modify = sqlBackendModifyFromContext(coordinator.ctx)
	if len(coordinator.sessions) != 0 {
		writer.initializationErr = operationFailed(
			ldapwire.ResultUnwillingToPerform,
			"one LDAP operation cannot write multiple SQL backends atomically",
		)
		writer.reader.initializationErr = writer.initializationErr
		coordinator.sessions[configuration] = writer
		coordinator.order = append(coordinator.order, writer)
		return writer
	}
	database, err := configuration.database(coordinator.ctx)
	if err == nil {
		writer.conn, err = database.Conn(coordinator.ctx)
	}
	// ModifyDN and Tree Delete span multiple mapped statements. Keep those
	// sequences atomic even when ordinary writes use autocommit; BeginTx
	// failure then stops the operation before its first DML.
	treeDelete := sqlBackendTreeDeleteFromContext(coordinator.ctx)
	if err == nil && (!configuration.autocommit || writer.rename != nil || treeDelete) {
		writer.tx, err = writer.conn.BeginTx(coordinator.ctx, nil)
		if err != nil && configuration.autocommit && (writer.rename != nil || treeDelete) &&
			!errors.Is(err, context.Canceled) &&
			!errors.Is(err, context.DeadlineExceeded) &&
			!errors.Is(err, driver.ErrBadConn) &&
			!errors.Is(err, sql.ErrConnDone) {
			diagnostic := "SQL backend ModifyDN requires transaction support"
			if treeDelete {
				diagnostic = "SQL backend Tree Delete requires transaction support"
			}
			err = operationFailed(
				ldapwire.ResultUnwillingToPerform,
				diagnostic,
			)
		}
	}
	if writer.tx != nil {
		writer.executor = writer.tx
	} else if err == nil {
		writer.executor = writer.conn
	}
	writer.reader.queryer = writer.executor
	writer.initializationErr = sqlBackendLDAPError(err)
	writer.reader.initializationErr = writer.initializationErr
	coordinator.sessions[configuration] = writer
	coordinator.order = append(coordinator.order, writer)
	return writer
}

func (coordinator *sqlBackendTransactionCoordinator) commit() error {
	coordinator.mu.Lock()
	writers := append([]*sqlBackendWriter(nil), coordinator.order...)
	coordinator.mu.Unlock()
	for _, writer := range writers {
		if writer.initializationErr != nil {
			coordinator.rollback()
			return writer.initializationErr
		}
	}
	for index, writer := range writers {
		if writer.tx == nil {
			if writer.conn != nil {
				_ = writer.conn.Close()
			}
			continue
		}
		if err := writer.tx.Commit(); err != nil {
			for _, pending := range writers[index+1:] {
				if pending.tx != nil {
					_ = pending.tx.Rollback()
				}
				if pending.conn != nil {
					_ = pending.conn.Close()
				}
			}
			if writer.conn != nil {
				_ = writer.conn.Close()
			}
			return sqlBackendLDAPError(fmt.Errorf("commit SQL backend: %w", err))
		}
		if writer.conn != nil {
			_ = writer.conn.Close()
		}
	}
	return nil
}

func (coordinator *sqlBackendTransactionCoordinator) rollback() {
	coordinator.mu.Lock()
	writers := append([]*sqlBackendWriter(nil), coordinator.order...)
	coordinator.mu.Unlock()
	for _, writer := range writers {
		if writer.tx != nil {
			_ = writer.tx.Rollback()
		}
		if writer.conn != nil {
			_ = writer.conn.Close()
		}
	}
	coordinator.runCleanup(true)
}

func (coordinator *sqlBackendTransactionCoordinator) deferCleanup(cleanup func()) {
	if cleanup == nil {
		return
	}
	coordinator.mu.Lock()
	coordinator.cleanup = append(coordinator.cleanup, cleanup)
	coordinator.mu.Unlock()
}

func (coordinator *sqlBackendTransactionCoordinator) setCandidateCleanup(
	cleanup func(),
) {
	if cleanup == nil {
		return
	}
	coordinator.mu.Lock()
	if coordinator.candidateCleanup != nil {
		coordinator.cleanup = append(coordinator.cleanup, coordinator.candidateCleanup)
	}
	coordinator.candidateCleanup = cleanup
	coordinator.mu.Unlock()
}

func (coordinator *sqlBackendTransactionCoordinator) completeUpdate() {
	coordinator.runCleanup(false)
}

func (coordinator *sqlBackendTransactionCoordinator) runCleanup(
	includeCandidate bool,
) {
	coordinator.mu.Lock()
	cleanups := coordinator.cleanup
	coordinator.cleanup = nil
	if includeCandidate && coordinator.candidateCleanup != nil {
		cleanups = append(cleanups, coordinator.candidateCleanup)
	}
	coordinator.candidateCleanup = nil
	coordinator.mu.Unlock()
	for _, cleanup := range cleanups {
		cleanup()
	}
}

func (writer *sqlBackendWriter) sqlExecutor() sqlBackendExecutor {
	if writer.executor != nil {
		return writer.executor
	}
	return writer.tx
}

func (writer *sqlBackendWriter) normalizedSQLDN(
	dn directory.DN,
) (directory.DN, string, error) {
	normalized, parameter, err := writer.reader.normalizedSQLDN(dn)
	if err != nil {
		return directory.DN{}, "", fmt.Errorf(
			"normalize SQL-backend DN %q: %w",
			dn.String(),
			err,
		)
	}
	return normalized, parameter, nil
}

func (writer *sqlBackendWriter) parseNormalizedSQLDN(
	value string,
) (directory.DN, string, error) {
	dn, err := directory.ParseDN(value)
	if err != nil {
		return directory.DN{}, "", err
	}
	return writer.normalizedSQLDN(dn)
}

func (writer *sqlBackendWriter) entryID(dn directory.DN) (sqlEntryID, error) {
	normalized, parameter, err := writer.normalizedSQLDN(dn)
	if err != nil {
		return sqlEntryID{}, err
	}
	if writer.reader.configuration.hasReversedDN {
		parameter = reverseUpperASCII(parameter)
	}
	return writer.entryIDWithParameter(normalized, parameter)
}

func (writer *sqlBackendWriter) entryIDWithParameter(
	normalized directory.DN,
	parameter string,
) (sqlEntryID, error) {
	rows, err := writer.sqlExecutor().QueryContext(
		writer.reader.ctx,
		writer.reader.configuration.idQuery,
		parameter,
	)
	if err != nil {
		return sqlEntryID{}, fmt.Errorf("SQL-backend entry ID query: %w", err)
	}
	defer rows.Close()

	var match sqlEntryID
	found := false
	for rows.Next() {
		var candidate sqlEntryID
		if err := rows.Scan(
			&candidate.id,
			&candidate.keyValue,
			&candidate.objectClassID,
			&candidate.dn,
		); err != nil {
			return sqlEntryID{}, fmt.Errorf("scan SQL-backend entry ID: %w", err)
		}
		storedDN, err := directory.ParseDN(candidate.dn)
		if err != nil {
			return sqlEntryID{}, fmt.Errorf(
				"SQL-backend entry %d DN: %w",
				candidate.id,
				err,
			)
		}
		storedDN, err = writer.reader.configuration.mapSQLDNToLDAP(storedDN)
		if err != nil {
			return sqlEntryID{}, fmt.Errorf(
				"SQL-backend entry %d DN layer: %w",
				candidate.id,
				err,
			)
		}
		if !storedDN.Equal(normalized) {
			continue
		}
		if found {
			return sqlEntryID{}, fmt.Errorf(
				"SQL-backend entry ID query returned duplicate DN identity %q",
				normalized.String(),
			)
		}
		match = candidate
		found = true
	}
	if err := rows.Err(); err != nil {
		return sqlEntryID{}, fmt.Errorf("iterate SQL-backend entry IDs: %w", err)
	}
	if !found {
		return sqlEntryID{}, storage.ErrEntryNotFound
	}
	return match, nil
}

func (writer *sqlBackendWriter) Put(entry directory.Entry, replace bool) (err error) {
	defer func() { err = sqlBackendLDAPError(err) }()
	if writer.initializationErr != nil {
		return writer.initializationErr
	}
	if writer.sqlExecutor() == nil {
		return sqlBackendWriteUnsupported()
	}
	if replace {
		return writer.replace(entry)
	}
	if writer.rename != nil && writer.pendingRename != nil {
		newDN, _, normalizeErr := writer.parseNormalizedSQLDN(entry.DN)
		if normalizeErr != nil {
			return normalizeErr
		}
		expected, _, normalizeErr := writer.normalizedSQLDN(writer.rename.newDN)
		if normalizeErr != nil {
			return normalizeErr
		}
		if expected.Equal(newDN) {
			return writer.renameEntry(entry)
		}
	}
	return writer.add(entry)
}

func (writer *sqlBackendWriter) PutIn(
	partition string,
	entry directory.Entry,
	replace bool,
) error {
	return writer.Put(entry, replace)
}

func (writer *sqlBackendWriter) Delete(dn directory.DN) (err error) {
	defer func() { err = sqlBackendLDAPError(err) }()
	if writer.initializationErr != nil {
		return writer.initializationErr
	}
	if writer.sqlExecutor() == nil {
		return sqlBackendWriteUnsupported()
	}
	comparisonDN, _, err := writer.normalizedSQLDN(dn)
	if err != nil {
		return err
	}
	if writer.rename != nil {
		oldDN, _, normalizeErr := writer.normalizedSQLDN(writer.rename.oldDN)
		if normalizeErr != nil {
			return normalizeErr
		}
		if !oldDN.Equal(comparisonDN) {
			return writer.delete(comparisonDN)
		}
		id, idErr := writer.entryID(comparisonDN)
		if idErr != nil {
			return idErr
		}
		entry, loadErr := writer.reader.loadEntry(writer.sqlExecutor(), id)
		if loadErr != nil {
			return loadErr
		}
		writer.pendingRename = &sqlBackendPendingRename{id: id, entry: entry}
		return nil
	}
	return writer.delete(comparisonDN)
}

func (writer *sqlBackendWriter) DeleteIn(string, directory.DN) error {
	return sqlBackendWriteUnsupported()
}

func (writer *sqlBackendWriter) Clear() error {
	return sqlBackendWriteUnsupported()
}

func (writer *sqlBackendWriter) add(entry directory.Entry) error {
	configuration := writer.reader.configuration
	structuralValues := entry.Values("structuralObjectClass")
	structural := ""
	if len(structuralValues) == 1 {
		structural = string(structuralValues[0])
	} else {
		var err error
		structural, err = configuration.registry.StructuralObjectClass(entry)
		if err != nil {
			return operationFailureFromSchema(err)
		}
	}
	mapping := configuration.objectClassIDs[strings.ToLower(structural)]
	if mapping == nil {
		return operationFailed(
			ldapwire.ResultUnwillingToPerform,
			"operation not permitted within namingContext",
		)
	}
	dn, _, err := writer.parseNormalizedSQLDN(entry.DN)
	if err != nil {
		return err
	}
	stored, err := configuration.mapLDAPDNToSQL(dn)
	if err != nil {
		return err
	}
	storedDN := stored.String()
	keyValue, err := writer.createMappedObject(entry, mapping)
	if err != nil {
		return err
	}
	parentID := int64(0)
	if parent, present := dn.Parent(); present && parent.Depth() > 0 {
		parent, err := writer.entryID(parent)
		if err != nil {
			return err
		}
		parentID = parent.id
	}
	if _, err := writer.sqlExecutor().ExecContext(
		writer.reader.ctx,
		configuration.insertEntry,
		storedDN,
		mapping.id,
		parentID,
		keyValue,
	); err != nil {
		return fmt.Errorf("insert SQL-backend entry: %w", err)
	}
	return writer.addEntryAttributes(entry, storedDN, keyValue, mapping)
}

func (writer *sqlBackendWriter) insertedEntryID(
	storedDN string,
) (sqlEntryID, error) {
	stored, err := directory.ParseDN(storedDN)
	if err != nil {
		return sqlEntryID{}, err
	}
	dn, err := writer.reader.configuration.mapSQLDNToLDAP(stored)
	if err != nil {
		return sqlEntryID{}, err
	}
	parameter := storedDN
	if writer.reader.configuration.hasReversedDN {
		parameter = reverseUpperASCII(parameter)
	}
	return writer.entryIDWithParameter(dn, parameter)
}

func (writer *sqlBackendWriter) createMappedObject(
	entry directory.Entry,
	mapping *sqlObjectClassMapping,
) (int64, error) {
	if mapping.createProcedure == "" {
		return 0, operationFailed(
			ldapwire.ResultUnwillingToPerform,
			"operation not permitted within namingContext",
		)
	}
	arguments := make([]any, 0, 2)
	var keyValue int64
	if mapping.expectReturn&1 != 0 {
		arguments = append(arguments, sql.Out{Dest: &keyValue})
	}
	if mapping.createHint != "" {
		values := entry.Values(mapping.createHint)
		var hint []byte
		if len(values) != 0 {
			hint = values[0]
		}
		parameter, err := writer.procedureValue(mapping.createHint, hint)
		if err != nil {
			return 0, err
		}
		arguments = append(arguments, parameter)
	}
	if mapping.expectReturn&1 != 0 {
		if _, err := writer.sqlExecutor().ExecContext(
			writer.reader.ctx,
			mapping.createProcedure,
			arguments...,
		); err != nil {
			return 0, fmt.Errorf("execute SQL-backend create procedure: %w", err)
		}
		return keyValue, nil
	}
	if writer.reader.configuration.createNeedsSelect {
		if _, err := writer.sqlExecutor().ExecContext(
			writer.reader.ctx,
			mapping.createProcedure,
			arguments...,
		); err != nil {
			return 0, fmt.Errorf("execute SQL-backend create procedure: %w", err)
		}
		if mapping.createKeyQuery == "" {
			return 0, errors.New("SQL-backend create key query is empty")
		}
		if err := writer.sqlExecutor().QueryRowContext(
			writer.reader.ctx,
			mapping.createKeyQuery,
		).Scan(&keyValue); err != nil {
			return 0, fmt.Errorf("read SQL-backend created key: %w", err)
		}
		return keyValue, nil
	}
	if err := writer.sqlExecutor().QueryRowContext(
		writer.reader.ctx,
		mapping.createProcedure,
		arguments...,
	).Scan(&keyValue); err != nil {
		return 0, fmt.Errorf("execute SQL-backend create procedure: %w", err)
	}
	return keyValue, nil
}

func (writer *sqlBackendWriter) addEntryAttributes(
	entry directory.Entry,
	storedDN string,
	keyValue int64,
	mapping *sqlObjectClassMapping,
) error {
	var entryID sqlEntryID
	entryIDResolved := false
	for _, attribute := range entry.Attributes {
		name := strings.ToLower(strings.Split(attribute.Description, ";")[0])
		if name == "objectclass" {
			for _, value := range attribute.Values {
				if strings.EqualFold(string(value), mapping.name) {
					continue
				}
				if !entryIDResolved {
					var err error
					entryID, err = writer.insertedEntryID(storedDN)
					if err != nil {
						return err
					}
					if entryID.objectClassID != mapping.id || entryID.keyValue != keyValue {
						return fmt.Errorf(
							"SQL-backend entry ID query returned oc_map_id=%d keyval=%d; want oc_map_id=%d keyval=%d",
							entryID.objectClassID,
							entryID.keyValue,
							mapping.id,
							keyValue,
						)
					}
					entryIDResolved = true
				}
				if _, err := writer.sqlExecutor().ExecContext(
					writer.reader.ctx,
					"INSERT INTO ldap_entry_objclasses (entry_id,oc_name) VALUES (?,?)",
					entryID.id,
					value,
				); err != nil {
					return fmt.Errorf("insert SQL-backend auxiliary objectClass: %w", err)
				}
			}
			continue
		}
		if writer.skipAttribute(attribute.Description) {
			continue
		}
		mappings := mapping.attributes[name]
		if len(mappings) == 0 {
			if writer.reader.configuration.failIfNoMapping {
				return sqlBackendNoMapping()
			}
			continue
		}
		attributeMapping := mappings[0]
		if attributeMapping.addProcedure == "" {
			if writer.reader.configuration.failIfNoMapping {
				return sqlBackendNoMapping()
			}
			continue
		}
		for _, value := range attribute.Values {
			if err := writer.executeAttributeProcedure(
				attributeMapping,
				true,
				keyValue,
				value,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func (writer *sqlBackendWriter) replace(entry directory.Entry) error {
	dn, _, err := writer.parseNormalizedSQLDN(entry.DN)
	if err != nil {
		return err
	}
	id, err := writer.entryID(dn)
	if err != nil {
		return err
	}
	mapping := writer.reader.configuration.objectClasses[id.objectClassID]
	if mapping == nil {
		return fmt.Errorf("unknown SQL-backend objectClass mapping %d", id.objectClassID)
	}
	before, err := writer.reader.loadEntry(writer.sqlExecutor(), id)
	if err != nil {
		return err
	}
	if !strings.EqualFold(
		firstSQLValue(before.Values("structuralObjectClass")),
		firstSQLValue(entry.Values("structuralObjectClass")),
	) {
		return operationFailed(
			ldapwire.ResultObjectClassModsProhibited,
			"structural objectClass cannot be changed",
		)
	}
	if writer.modify != nil {
		modifiedDN, _, normalizeErr := writer.normalizedSQLDN(writer.modify.dn)
		if normalizeErr != nil {
			return normalizeErr
		}
		if !modifiedDN.Equal(dn) {
			if err := writer.replaceMappedAttributes(before, entry, id, mapping); err != nil {
				return err
			}
			return writer.validateMappedEntry(entry)
		}
		if err := writer.applyMappedModifications(
			before,
			entry,
			id,
			mapping,
			writer.modify.changes,
		); err != nil {
			return err
		}
		return writer.validateMappedEntry(entry)
	}
	if err := writer.replaceMappedAttributes(before, entry, id, mapping); err != nil {
		return err
	}
	return writer.validateMappedEntry(entry)
}

func (writer *sqlBackendWriter) applyMappedModifications(
	before,
	after directory.Entry,
	id sqlEntryID,
	mapping *sqlObjectClassMapping,
	changes []ldapwire.Modification,
) error {
	if err := writer.replaceAuxiliaryObjectClasses(before, after, id); err != nil {
		return err
	}
	handled := map[string]struct{}{"objectclass": {}}
	for _, change := range changes {
		name := strings.ToLower(strings.Split(change.Attribute.Description, ";")[0])
		handled[name] = struct{}{}
		if name == "objectclass" || writer.skipAttribute(change.Attribute.Description) {
			continue
		}
		mappings := mapping.attributes[name]
		if len(mappings) == 0 {
			if writer.reader.configuration.failIfNoMapping {
				return sqlBackendNoMapping()
			}
			continue
		}
		attributeMapping := mappings[0]
		switch change.Operation {
		case ldapwire.ModificationAdd:
			if err := writer.addMappedValues(
				attributeMapping,
				id.keyValue,
				change.Attribute.Values,
			); err != nil {
				return err
			}
		case ldapwire.ModificationDelete:
			values := change.Attribute.Values
			if len(values) == 0 {
				var err error
				values, err = writer.reader.readAttributeValues(
					writer.sqlExecutor(),
					id.keyValue,
					attributeMapping,
				)
				if err != nil {
					return err
				}
			}
			if err := writer.deleteMappedValues(
				attributeMapping,
				id.keyValue,
				values,
			); err != nil {
				return err
			}
		case ldapwire.ModificationReplace:
			if attributeMapping.addProcedure == "" {
				if writer.reader.configuration.failIfNoMapping {
					return sqlBackendNoMapping()
				}
				continue
			}
			if attributeMapping.deleteProcedure != "" {
				values, err := writer.reader.readAttributeValues(
					writer.sqlExecutor(),
					id.keyValue,
					attributeMapping,
				)
				if err != nil {
					return err
				}
				if err := writer.deleteMappedValues(
					attributeMapping,
					id.keyValue,
					values,
				); err != nil {
					return err
				}
			} else if writer.reader.configuration.failIfNoMapping {
				return sqlBackendNoMapping()
			}
			if err := writer.addMappedValues(
				attributeMapping,
				id.keyValue,
				change.Attribute.Values,
			); err != nil {
				return err
			}
		case ldapwire.ModificationIncrement:
			if writer.reader.configuration.failIfNoMapping {
				return errors.New("SQL-backend increment is not supported")
			}
		}
	}
	return writer.replaceMappedAttributeNames(before, after, id, mapping, handled)
}

func (writer *sqlBackendWriter) addMappedValues(
	mapping sqlAttributeMapping,
	keyValue int64,
	values [][]byte,
) error {
	if len(values) == 0 {
		return nil
	}
	if mapping.addProcedure == "" {
		if writer.reader.configuration.failIfNoMapping {
			return sqlBackendNoMapping()
		}
		return nil
	}
	for _, value := range values {
		if err := writer.executeAttributeProcedure(mapping, true, keyValue, value); err != nil {
			return err
		}
	}
	return nil
}

func (writer *sqlBackendWriter) deleteMappedValues(
	mapping sqlAttributeMapping,
	keyValue int64,
	values [][]byte,
) error {
	if len(values) == 0 {
		return nil
	}
	if mapping.deleteProcedure == "" {
		if writer.reader.configuration.failIfNoMapping {
			return sqlBackendNoMapping()
		}
		return nil
	}
	for _, value := range values {
		if err := writer.executeAttributeProcedure(mapping, false, keyValue, value); err != nil {
			return err
		}
	}
	return nil
}

func (writer *sqlBackendWriter) renameEntry(entry directory.Entry) error {
	pending := writer.pendingRename
	if pending == nil {
		return errors.New("SQL-backend rename source is missing")
	}
	newDN, _, err := writer.parseNormalizedSQLDN(entry.DN)
	if err != nil {
		return err
	}
	stored, err := writer.reader.configuration.mapLDAPDNToSQL(newDN)
	if err != nil {
		return err
	}
	storedDN := stored.String()
	parentID := int64(0)
	if parent, present := newDN.Parent(); present && parent.Depth() > 0 {
		parentEntry, parentErr := writer.entryID(parent)
		if parentErr != nil {
			return parentErr
		}
		parentID = parentEntry.id
	}
	if _, err := writer.sqlExecutor().ExecContext(
		writer.reader.ctx,
		writer.reader.configuration.renameEntry,
		storedDN,
		parentID,
		pending.id.keyValue,
		pending.id.id,
	); err != nil {
		return fmt.Errorf("rename SQL-backend entry: %w", err)
	}
	writer.pendingRename = nil
	return writer.replaceFromRename(pending.entry, entry, pending.id)
}

func (writer *sqlBackendWriter) replaceFromRename(
	before,
	entry directory.Entry,
	id sqlEntryID,
) error {
	mapping := writer.reader.configuration.objectClasses[id.objectClassID]
	if mapping == nil {
		return fmt.Errorf("unknown SQL-backend objectClass mapping %d", id.objectClassID)
	}
	if !strings.EqualFold(
		firstSQLValue(before.Values("structuralObjectClass")),
		firstSQLValue(entry.Values("structuralObjectClass")),
	) {
		return operationFailed(
			ldapwire.ResultObjectClassModsProhibited,
			"structural objectClass cannot be changed",
		)
	}
	if err := writer.replaceMappedRDNAttributeDeltas(before, entry, id, mapping); err != nil {
		return err
	}
	return writer.validateRenamedEntry(entry)
}

func (writer *sqlBackendWriter) replaceMappedRDNAttributeDeltas(
	before,
	after directory.Entry,
	id sqlEntryID,
	mapping *sqlObjectClassMapping,
) error {
	oldDN, _, err := writer.normalizedSQLDN(writer.rename.oldDN)
	if err != nil {
		return err
	}
	newDN, _, err := writer.normalizedSQLDN(writer.rename.newDN)
	if err != nil {
		return err
	}
	names := make(map[string]string)
	for _, dn := range []directory.DN{oldDN, newDN} {
		for _, value := range dn.RDNValues() {
			base := strings.Split(value.Type, ";")[0]
			if _, present := names[strings.ToLower(base)]; !present {
				names[strings.ToLower(base)] = base
			}
		}
	}
	keys := make([]string, 0, len(names))
	for name := range names {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		if name == "objectclass" || writer.skipAttribute(name) {
			continue
		}
		removed, err := writer.sqlValueDifference(
			name,
			before.Values(names[name]),
			after.Values(names[name]),
		)
		if err != nil {
			return err
		}
		added, err := writer.sqlValueDifference(
			name,
			after.Values(names[name]),
			before.Values(names[name]),
		)
		if err != nil {
			return err
		}
		if len(removed) == 0 && len(added) == 0 {
			continue
		}
		mappings := mapping.attributes[name]
		if len(mappings) == 0 {
			if writer.reader.configuration.failIfNoMapping {
				return sqlBackendNoMapping()
			}
			continue
		}
		attributeMapping := mappings[0]
		if err := writer.deleteMappedValues(
			attributeMapping,
			id.keyValue,
			removed,
		); err != nil {
			return err
		}
		if err := writer.addMappedRDNValues(
			attributeMapping,
			id.keyValue,
			added,
		); err != nil {
			var executionError *sqlBackendAttributeProcedureExecutionError
			if !writer.reader.configuration.failIfNoMapping &&
				errors.As(err, &executionError) {
				continue
			}
			return err
		}
	}
	return nil
}

func (writer *sqlBackendWriter) addMappedRDNValues(
	mapping sqlAttributeMapping,
	keyValue int64,
	values [][]byte,
) error {
	if len(values) == 0 {
		return nil
	}
	if mapping.addProcedure == "" {
		if writer.reader.configuration.failIfNoMapping {
			return sqlBackendNoMapping()
		}
		return nil
	}
	for _, value := range values {
		if err := writer.executePreparedAttributeProcedure(
			mapping,
			true,
			keyValue,
			value,
		); err != nil {
			return err
		}
	}
	return nil
}

func (writer *sqlBackendWriter) validateRenamedEntry(expected directory.Entry) error {
	return writer.validateMappedEntry(expected)
}

func (writer *sqlBackendWriter) validateMappedEntry(expected directory.Entry) error {
	dn, _, err := writer.parseNormalizedSQLDN(expected.DN)
	if err != nil {
		return err
	}
	id, err := writer.entryID(dn)
	if err != nil {
		return err
	}
	stored, err := writer.reader.loadEntry(writer.sqlExecutor(), id)
	if err != nil {
		return err
	}
	if writer.reader.configuration.checkSchema {
		if err := writer.reader.configuration.registry.ValidateEntry(stored); err != nil {
			return operationFailureFromSchema(err)
		}
	}
	for _, namingValue := range dn.RDNValues() {
		present := false
		for _, storedValue := range stored.Values(namingValue.Type) {
			comparison, compareErr := writer.reader.configuration.registry.Compare(
				namingValue.Type,
				"",
				storedValue,
				namingValue.Value,
			)
			if compareErr != nil {
				return compareErr
			}
			if comparison == 0 {
				present = true
				break
			}
		}
		if !present {
			return operationFailed(
				ldapwire.ResultNamingViolation,
				fmt.Sprintf(
					"naming attribute '%s' is not present in entry",
					namingValue.Type,
				),
			)
		}
	}
	return nil
}

func (writer *sqlBackendWriter) sqlValueDifference(
	attribute string,
	left,
	right [][]byte,
) ([][]byte, error) {
	attributeType, attributeFound, err := writer.reader.configuration.registry.EffectiveAttributeType(
		attribute,
	)
	if err != nil {
		return nil, err
	}
	var difference [][]byte
	for _, value := range left {
		found := false
		for _, candidate := range right {
			if !attributeFound || attributeType.Equality == "" {
				found = bytes.Equal(value, candidate)
			} else {
				comparison, err := writer.reader.configuration.registry.Compare(
					attribute,
					"",
					value,
					candidate,
				)
				if err != nil {
					return nil, err
				}
				found = comparison == 0
			}
			if found {
				break
			}
		}
		if !found {
			difference = append(difference, value)
		}
	}
	return difference, nil
}

func (writer *sqlBackendWriter) replaceMappedAttributes(
	before,
	entry directory.Entry,
	id sqlEntryID,
	mapping *sqlObjectClassMapping,
) error {
	if err := writer.replaceAuxiliaryObjectClasses(before, entry, id); err != nil {
		return err
	}
	return writer.replaceMappedAttributeNames(before, entry, id, mapping, nil)
}

func (writer *sqlBackendWriter) replaceMappedAttributeNames(
	before,
	entry directory.Entry,
	id sqlEntryID,
	mapping *sqlObjectClassMapping,
	exclude map[string]struct{},
) error {
	names := make(map[string]string)
	for _, attribute := range before.Attributes {
		base := strings.Split(attribute.Description, ";")[0]
		names[strings.ToLower(base)] = base
	}
	for _, attribute := range entry.Attributes {
		base := strings.Split(attribute.Description, ";")[0]
		names[strings.ToLower(base)] = base
	}
	keys := make([]string, 0, len(names))
	for name := range names {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		if name == "objectclass" || writer.skipAttribute(name) {
			continue
		}
		if _, excluded := exclude[name]; excluded {
			continue
		}
		oldValues := before.Values(names[name])
		newValues := entry.Values(names[name])
		if sqlValuesEqual(oldValues, newValues) {
			continue
		}
		mappings := mapping.attributes[name]
		if len(mappings) == 0 {
			if writer.reader.configuration.failIfNoMapping {
				return sqlBackendNoMapping()
			}
			continue
		}
		attributeMapping := mappings[0]
		if err := writer.deleteMappedValues(
			attributeMapping,
			id.keyValue,
			oldValues,
		); err != nil {
			return err
		}
		if err := writer.addMappedValues(
			attributeMapping,
			id.keyValue,
			newValues,
		); err != nil {
			return err
		}
	}
	return nil
}

func (writer *sqlBackendWriter) replaceAuxiliaryObjectClasses(
	before,
	after directory.Entry,
	id sqlEntryID,
) error {
	structural := strings.ToLower(firstSQLValue(before.Values("structuralObjectClass")))
	oldValues := sqlStringSet(before.Values("objectClass"), structural)
	newValues := sqlStringSet(after.Values("objectClass"), structural)
	for value := range oldValues {
		if _, keep := newValues[value]; keep {
			continue
		}
		if _, err := writer.sqlExecutor().ExecContext(
			writer.reader.ctx,
			"DELETE FROM ldap_entry_objclasses WHERE entry_id=? AND LOWER(oc_name)=?",
			id.id,
			value,
		); err != nil {
			return err
		}
	}
	for value, original := range newValues {
		if _, exists := oldValues[value]; exists {
			continue
		}
		if _, err := writer.sqlExecutor().ExecContext(
			writer.reader.ctx,
			"INSERT INTO ldap_entry_objclasses (entry_id,oc_name) VALUES (?,?)",
			id.id,
			original,
		); err != nil {
			return err
		}
	}
	return nil
}

func (writer *sqlBackendWriter) delete(dn directory.DN) error {
	id, err := writer.entryID(dn)
	if err != nil {
		return err
	}
	mapping := writer.reader.configuration.objectClasses[id.objectClassID]
	if mapping == nil {
		return fmt.Errorf("unknown SQL-backend objectClass mapping %d", id.objectClassID)
	}
	if mapping.deleteProcedure == "" {
		return sqlBackendNoMapping()
	}
	for name, mappings := range mapping.attributes {
		if writer.skipAttribute(name) {
			continue
		}
		attributeMapping := mappings[0]
		if attributeMapping.deleteProcedure == "" {
			if writer.reader.configuration.failIfNoMapping {
				return errors.New("SQL-backend attribute delete procedure is missing")
			}
			continue
		}
		values, err := writer.reader.readAttributeValues(
			writer.sqlExecutor(),
			id.keyValue,
			attributeMapping,
		)
		if err != nil {
			return err
		}
		if err := writer.deleteMappedValues(
			attributeMapping,
			id.keyValue,
			values,
		); err != nil {
			return err
		}
	}
	if err := writer.executeObjectDelete(mapping, id.keyValue); err != nil {
		return err
	}
	configuration := writer.reader.configuration
	if _, err := writer.sqlExecutor().ExecContext(
		writer.reader.ctx,
		configuration.deleteObjectClass,
		id.id,
	); err != nil {
		return fmt.Errorf("delete SQL-backend objectClasses: %w", err)
	}
	if _, err := writer.sqlExecutor().ExecContext(
		writer.reader.ctx,
		configuration.deleteEntry,
		id.id,
	); err != nil {
		return fmt.Errorf("delete SQL-backend entry: %w", err)
	}
	return nil
}

func (writer *sqlBackendWriter) treeDeletePreflight(dn directory.DN) error {
	id, err := writer.entryID(dn)
	if err != nil {
		return err
	}
	mapping := writer.reader.configuration.objectClasses[id.objectClassID]
	if mapping == nil || mapping.deleteProcedure == "" {
		return operationFailed(
			ldapwire.ResultUnwillingToPerform,
			"subtree delete not possible",
		)
	}
	return nil
}

func (writer *sqlBackendWriter) executeObjectDelete(
	mapping *sqlObjectClassMapping,
	keyValue int64,
) error {
	if mapping.expectReturn&2 == 0 {
		_, err := writer.sqlExecutor().ExecContext(
			writer.reader.ctx,
			mapping.deleteProcedure,
			keyValue,
		)
		return err
	}
	resultCode := int64(ldapwire.ResultSuccess)
	_, err := writer.sqlExecutor().ExecContext(
		writer.reader.ctx,
		mapping.deleteProcedure,
		sql.Out{Dest: &resultCode},
		keyValue,
	)
	if err != nil {
		return err
	}
	return sqlBackendProcedureResult(resultCode, mapping.name)
}

func (writer *sqlBackendWriter) executeAttributeProcedure(
	mapping sqlAttributeMapping,
	add bool,
	keyValue int64,
	value []byte,
) error {
	statement, arguments, resultCode, err := writer.attributeProcedureCall(
		mapping,
		add,
		keyValue,
		value,
	)
	if err != nil {
		return err
	}
	if _, err = writer.sqlExecutor().ExecContext(
		writer.reader.ctx,
		statement,
		arguments...,
	); err != nil {
		return fmt.Errorf(
			"execute SQL-backend attribute procedure for %s: %w",
			mapping.name,
			err,
		)
	}
	return sqlBackendProcedureResult(*resultCode, mapping.name)
}

func (writer *sqlBackendWriter) executePreparedAttributeProcedure(
	mapping sqlAttributeMapping,
	add bool,
	keyValue int64,
	value []byte,
) error {
	statement, arguments, resultCode, err := writer.attributeProcedureCall(
		mapping,
		add,
		keyValue,
		value,
	)
	if err != nil {
		return err
	}
	preparer, ok := writer.sqlExecutor().(interface {
		PrepareContext(context.Context, string) (*sql.Stmt, error)
	})
	if !ok {
		return fmt.Errorf(
			"prepare SQL-backend attribute procedure for %s: executor does not support prepared statements",
			mapping.name,
		)
	}
	prepared, err := preparer.PrepareContext(writer.reader.ctx, statement)
	if err != nil {
		return fmt.Errorf(
			"prepare SQL-backend attribute procedure for %s: %w",
			mapping.name,
			err,
		)
	}
	defer prepared.Close()

	if _, err := prepared.ExecContext(writer.reader.ctx, arguments...); err != nil {
		if !sqlBackendIgnorableProcedureExecutionError(writer.reader.ctx, err) {
			return fmt.Errorf(
				"execute SQL-backend attribute procedure for %s: %w",
				mapping.name,
				err,
			)
		}
		if *resultCode != int64(ldapwire.ResultSuccess) {
			return sqlBackendProcedureResult(*resultCode, mapping.name)
		}
		return &sqlBackendAttributeProcedureExecutionError{
			attribute: mapping.name,
			err:       err,
		}
	}
	return sqlBackendProcedureResult(*resultCode, mapping.name)
}

func (writer *sqlBackendWriter) attributeProcedureCall(
	mapping sqlAttributeMapping,
	add bool,
	keyValue int64,
	value []byte,
) (string, []any, *int64, error) {
	statement := mapping.deleteProcedure
	bit := int64(2)
	if add {
		statement = mapping.addProcedure
		bit = 1
	}
	resultCode := new(int64)
	*resultCode = int64(ldapwire.ResultSuccess)
	arguments := make([]any, 0, 3)
	if mapping.expectReturn&bit != 0 {
		arguments = append(arguments, sql.Out{Dest: resultCode})
	}
	parameter, err := writer.procedureValue(mapping.name, value)
	if err != nil {
		return "", nil, nil, err
	}
	if mapping.parameterOrder&bit != 0 {
		arguments = append(
			arguments,
			parameter,
			keyValue,
		)
	} else {
		arguments = append(
			arguments,
			keyValue,
			parameter,
		)
	}
	return statement, arguments, resultCode, nil
}

func sqlBackendIgnorableProcedureExecutionError(
	ctx context.Context,
	err error,
) bool {
	if err == nil || ctx == nil || ctx.Err() != nil ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) ||
		errors.Is(err, sql.ErrTxDone) {
		return false
	}
	if message := err.Error(); strings.HasPrefix(message, "sql: converting argument ") ||
		strings.HasPrefix(message, "sql: expected ") {
		return false
	}
	if sqlBackendIsODBCParameterError(err) {
		return false
	}
	if code, ok := sqlBackendSQLiteExecutionErrorCode(err); ok {
		// SQLite extended result codes retain the primary code in the low byte.
		switch code & 0xff {
		case 4, 19: // SQLITE_ABORT, SQLITE_CONSTRAINT
			return true
		default:
			return false
		}
	}
	if ignorable, found := sqlBackendODBCExecutionErrorDisposition(err); found {
		return ignorable
	}
	return false
}

func sqlBackendSQLiteExecutionErrorCode(err error) (int, bool) {
	for current := err; current != nil; current = errors.Unwrap(current) {
		typeOf := reflect.TypeOf(current)
		if typeOf == nil {
			continue
		}
		if typeOf.Kind() == reflect.Pointer {
			typeOf = typeOf.Elem()
		}
		if typeOf.PkgPath() != "modernc.org/sqlite" || typeOf.Name() != "Error" {
			continue
		}
		codeError, ok := current.(interface{ Code() int })
		if !ok {
			return 0, false
		}
		return codeError.Code(), true
	}
	return 0, false
}

func (writer *sqlBackendWriter) procedureValue(
	attributeName string,
	value []byte,
) (any, error) {
	attribute, found, err := writer.reader.configuration.registry.EffectiveAttributeType(
		attributeName,
	)
	if err != nil || !found {
		return value, err
	}
	syntax, found := writer.reader.configuration.registry.LDAPSyntax(attribute.Syntax)
	if found && syntax.BinaryTransferRequired {
		return value, nil
	}
	if attribute.Syntax == schema.SyntaxDistinguishedName {
		dn, err := writer.reader.configuration.registry.NormalizeDN(string(value))
		if err != nil {
			return nil, fmt.Errorf(
				"normalize SQL-backend procedure DN value for %s: %w",
				attributeName,
				err,
			)
		}
		return dn.NormalizedString(), nil
	}
	return string(value), nil
}

func (writer *sqlBackendWriter) skipAttribute(description string) bool {
	base := strings.Split(description, ";")[0]
	if !writer.reader.configuration.registry.IsOperational(base) {
		return false
	}
	switch strings.ToLower(base) {
	case "pwdaccountlockedtime", "pwdchangedtime", "pwdfailuretime",
		"pwdgraceusetime", "pwdhistory", "pwdpolicysubentry", "pwdreset",
		"entryuuid", "ref":
		return false
	default:
		return true
	}
}

func sqlBackendProcedureResult(code int64, diagnostic string) error {
	if code == int64(ldapwire.ResultSuccess) {
		return nil
	}
	if !legalSQLBackendResultCode(code) {
		code = int64(ldapwire.ResultOther)
	}
	return operationFailed(ldapwire.ResultCode(code), diagnostic)
}

func legalSQLBackendResultCode(code int64) bool {
	return code >= 0 && code <= 14 || code >= 16 && code <= 21 ||
		code >= 32 && code <= 36 || code == int64(ldapwire.ResultProxyAuthorizationFailure) ||
		code >= 48 && code <= 54 ||
		code >= 64 && code <= 71 || code >= 80 && code <= 80
}

func sqlBackendNoMapping() error {
	return operationFailed(
		ldapwire.ResultUnwillingToPerform,
		"operation not permitted within namingContext",
	)
}

func firstSQLValue(values [][]byte) string {
	if len(values) == 0 {
		return ""
	}
	return string(values[0])
}

func sqlValuesEqual(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for _, value := range left {
		found := false
		for _, candidate := range right {
			if string(value) == string(candidate) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func sqlStringSet(values [][]byte, exclude string) map[string]string {
	result := make(map[string]string)
	for _, value := range values {
		original := string(value)
		key := strings.ToLower(original)
		if key != exclude {
			result[key] = original
		}
	}
	return result
}
