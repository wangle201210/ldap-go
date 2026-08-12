package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type sqlBackendTransactionContextKey struct{}

type sqlBackendReadContextKey struct{}

type sqlBackendRenameContextKey struct{}

type sqlBackendModifyContextKey struct{}

type sqlBackendRenameContext struct {
	oldDN directory.DN
	newDN directory.DN
}

type sqlBackendModifyContext struct {
	dn      directory.DN
	changes []ldapwire.Modification
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
) *sqlBackendReader {
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
		ctx:               coordinator.ctx,
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
	if err == nil && !configuration.autocommit {
		writer.tx, err = writer.conn.BeginTx(coordinator.ctx, nil)
	}
	if writer.tx != nil {
		writer.executor = writer.tx
	} else if err == nil {
		writer.executor = writer.conn
	}
	writer.reader.queryer = writer.executor
	writer.rename = sqlBackendRenameFromContext(coordinator.ctx)
	writer.modify = sqlBackendModifyFromContext(coordinator.ctx)
	writer.initializationErr = sqlBackendLDAPError(err)
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
		newDN, parseErr := directory.ParseDN(entry.DN)
		if parseErr != nil {
			return parseErr
		}
		if writer.rename.newDN.Equal(newDN) {
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
	if writer.rename != nil && writer.rename.oldDN.Equal(dn) {
		id, idErr := writer.reader.entryID(dn)
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
	return writer.delete(dn)
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
	keyValue, err := writer.createMappedObject(entry, mapping)
	if err != nil {
		return err
	}
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return err
	}
	parentID := int64(0)
	if parent, present := dn.Parent(); present && parent.Depth() > 0 {
		parent, err := writer.reader.entryID(parent)
		if err != nil {
			return err
		}
		parentID = parent.id
	}
	if _, err := writer.sqlExecutor().ExecContext(
		writer.reader.ctx,
		configuration.insertEntry,
		entry.DN,
		mapping.id,
		parentID,
		keyValue,
	); err != nil {
		return fmt.Errorf("insert SQL-backend entry: %w", err)
	}
	entryID, err := writer.reader.entryID(dn)
	if err != nil {
		return err
	}
	return writer.addEntryAttributes(entry, entryID, mapping)
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
		hint := ""
		if len(values) != 0 {
			hint = string(values[0])
		}
		arguments = append(arguments, hint)
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
	id sqlEntryID,
	mapping *sqlObjectClassMapping,
) error {
	for _, attribute := range entry.Attributes {
		name := strings.ToLower(strings.Split(attribute.Description, ";")[0])
		if name == "objectclass" {
			for _, value := range attribute.Values {
				if strings.EqualFold(string(value), mapping.name) {
					continue
				}
				if _, err := writer.sqlExecutor().ExecContext(
					writer.reader.ctx,
					"INSERT INTO ldap_entry_objclasses (entry_id,oc_name) VALUES (?,?)",
					id.id,
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
				id.keyValue,
				value,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func (writer *sqlBackendWriter) replace(entry directory.Entry) error {
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return err
	}
	id, err := writer.reader.entryID(dn)
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
	if writer.modify != nil && writer.modify.dn.Equal(dn) {
		return writer.applyMappedModifications(
			before,
			entry,
			id,
			mapping,
			writer.modify.changes,
		)
	}
	return writer.replaceMappedAttributes(before, entry, id, mapping)
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
	newDN, err := directory.ParseDN(entry.DN)
	if err != nil {
		return err
	}
	parentID := int64(0)
	if parent, present := newDN.Parent(); present && parent.Depth() > 0 {
		parentEntry, parentErr := writer.reader.entryID(parent)
		if parentErr != nil {
			return parentErr
		}
		parentID = parentEntry.id
	}
	if _, err := writer.sqlExecutor().ExecContext(
		writer.reader.ctx,
		writer.reader.configuration.renameEntry,
		entry.DN,
		parentID,
		pending.id.keyValue,
		pending.id.id,
	); err != nil {
		return fmt.Errorf("rename SQL-backend entry: %w", err)
	}
	writer.pendingRename = nil
	return writer.replaceFrom(pending.entry, entry, pending.id)
}

func (writer *sqlBackendWriter) replaceFrom(
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
	return writer.replaceMappedAttributes(before, entry, id, mapping)
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
	id, err := writer.reader.entryID(dn)
	if err != nil {
		return err
	}
	mapping := writer.reader.configuration.objectClasses[id.objectClassID]
	if mapping == nil {
		return fmt.Errorf("unknown SQL-backend objectClass mapping %d", id.objectClassID)
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
	if mapping.deleteProcedure == "" {
		return sqlBackendNoMapping()
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
	statement := mapping.deleteProcedure
	bit := int64(2)
	if add {
		statement = mapping.addProcedure
		bit = 1
	}
	arguments := make([]any, 0, 3)
	resultCode := int64(ldapwire.ResultSuccess)
	if mapping.expectReturn&bit != 0 {
		arguments = append(arguments, sql.Out{Dest: &resultCode})
	}
	if mapping.parameterOrder&bit != 0 {
		arguments = append(
			arguments,
			writer.procedureValue(mapping.name, value),
			keyValue,
		)
	} else {
		arguments = append(
			arguments,
			keyValue,
			writer.procedureValue(mapping.name, value),
		)
	}
	if _, err := writer.sqlExecutor().ExecContext(
		writer.reader.ctx,
		statement,
		arguments...,
	); err != nil {
		return fmt.Errorf("execute SQL-backend attribute procedure for %s: %w", mapping.name, err)
	}
	return sqlBackendProcedureResult(resultCode, mapping.name)
}

func (writer *sqlBackendWriter) procedureValue(
	attributeName string,
	value []byte,
) any {
	attribute, found, err := writer.reader.configuration.registry.EffectiveAttributeType(
		attributeName,
	)
	if err != nil || !found {
		return value
	}
	syntax, found := writer.reader.configuration.registry.LDAPSyntax(attribute.Syntax)
	if found && syntax.BinaryTransferRequired {
		return value
	}
	return string(value)
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
