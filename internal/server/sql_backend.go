package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/slingdata-io/godbc"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	defaultSQLDriver = "odbc"

	defaultSQLOCQuery = "SELECT id,name,keytbl,keycol,create_proc,delete_proc," +
		"expect_return FROM ldap_oc_mappings"
	defaultSQLSelectOCQuery = "SELECT id,name,keytbl,keycol,create_proc," +
		"create_keyval,delete_proc,expect_return FROM ldap_oc_mappings"
	defaultSQLATQuery = "SELECT name,sel_expr,from_tbls,join_where,add_proc," +
		"delete_proc,param_order,expect_return,sel_expr_u " +
		"FROM ldap_attr_mappings WHERE oc_map_id=?"
	defaultSQLIDQuery = "SELECT id,keyval,oc_map_id,dn FROM ldap_entries WHERE dn=?"
)

type sqlBackendRuntimeConfiguration struct {
	databaseName string
	databaseUser string
	databasePass string
	databaseHost string
	driverName   string

	ocQuery           string
	attributeQuery    string
	idQuery           string
	idQueryConfigured bool
	createNeedsSelect bool
	upperFunction     string
	upperNeedsCast    bool
	hasReversedDN     bool
	reversedDNSet     bool
	failIfNoMapping   bool
	allowOrphans      bool
	baseObject        string
	layers            []string
	aliasingKeyword   string
	aliasingQuote     string
	autocommit        bool

	registry *schema.Registry
	server   *Server

	mu             sync.Mutex
	db             *sql.DB
	objectClasses  map[int64]*sqlObjectClassMapping
	objectClassIDs map[string]*sqlObjectClassMapping
}

type sqlBackendSettings struct {
	databaseName      string
	databaseUser      string
	databasePass      string
	databaseHost      string
	driverName        string
	ocQuery           string
	attributeQuery    string
	idQuery           string
	idQueryConfigured bool
	createNeedsSelect bool
	upperFunction     string
	upperNeedsCast    bool
	hasReversedDN     bool
	reversedDNSet     bool
	failIfNoMapping   bool
	allowOrphans      bool
	baseObject        string
	layers            []string
	aliasingKeyword   string
	aliasingQuote     string
	autocommit        bool
}

type sqlObjectClassMapping struct {
	id              int64
	name            string
	keyTable        string
	keyColumn       string
	createProcedure string
	createKeyQuery  string
	deleteProcedure string
	expectReturn    int64
	createHint      string
	attributes      map[string][]sqlAttributeMapping
}

type sqlAttributeMapping struct {
	name             string
	description      string
	selectExpression string
	fromTables       string
	joinWhere        string
	addProcedure     string
	deleteProcedure  string
	parameterOrder   int64
	expectReturn     int64
	upperExpression  string
	query            string
}

type sqlEntryID struct {
	id            int64
	keyValue      int64
	objectClassID int64
	dn            string
}

func loadSQLBackendRuntimeConfiguration(
	entry directory.Entry,
) (*sqlBackendRuntimeConfiguration, error) {
	databaseName, err := requiredSQLString(entry, "olcDbName")
	if err != nil {
		return nil, err
	}
	databaseUser, err := requiredSQLString(entry, "olcDbUser")
	if err != nil {
		return nil, err
	}
	configuration := &sqlBackendRuntimeConfiguration{
		databaseName:    databaseName,
		databaseUser:    databaseUser,
		driverName:      defaultSQLDriver,
		ocQuery:         defaultSQLOCQuery,
		attributeQuery:  defaultSQLATQuery,
		idQuery:         defaultSQLIDQuery,
		aliasingKeyword: "AS ",
	}
	if configuration.databasePass, err = optionalSQLString(entry, "olcDbPass"); err != nil {
		return nil, err
	}
	if configuration.databaseHost, err = optionalSQLString(entry, "olcDbHost"); err != nil {
		return nil, err
	}
	configuration.createNeedsSelect, _, err = singleBoolean(entry, "olcSqlCreateNeedsSelect")
	if err != nil {
		return nil, err
	}
	if configuration.createNeedsSelect {
		configuration.ocQuery = defaultSQLSelectOCQuery
	}
	stringOptions := []struct {
		attribute string
		target    *string
	}{
		{"olcSqlOcQuery", &configuration.ocQuery},
		{"olcSqlAtQuery", &configuration.attributeQuery},
		{"olcSqlUpperFunc", &configuration.upperFunction},
		{"olcSqlBaseObject", &configuration.baseObject},
		{"olcSqlAliasingKeyword", &configuration.aliasingKeyword},
		{"olcSqlAliasingQuote", &configuration.aliasingQuote},
	}
	if value, present, valueErr := singleOptionalSQLString(entry, "olcSqlIdQuery"); valueErr != nil {
		return nil, valueErr
	} else if present {
		configuration.idQuery = value
		configuration.idQueryConfigured = true
	}
	for _, option := range stringOptions {
		value, present, valueErr := singleOptionalSQLString(entry, option.attribute)
		if valueErr != nil {
			return nil, valueErr
		}
		if present {
			*option.target = value
		}
	}
	configuration.aliasingKeyword = strings.TrimSpace(configuration.aliasingKeyword)
	if configuration.aliasingKeyword != "" {
		configuration.aliasingKeyword += " "
	}
	booleanOptions := []struct {
		attribute string
		target    *bool
	}{
		{"olcSqlFailIfNoMapping", &configuration.failIfNoMapping},
		{"olcSqlAllowOrphans", &configuration.allowOrphans},
		{"olcSqlAutocommit", &configuration.autocommit},
	}
	configuration.upperNeedsCast, _, err = singleBoolean(entry, "olcSqlUpperNeedsCast")
	if err != nil {
		return nil, err
	}
	configuration.hasReversedDN, configuration.reversedDNSet, err = singleBoolean(
		entry,
		"olcSqlHasLDAPinfoDnRu",
	)
	if err != nil {
		return nil, err
	}
	for _, option := range booleanOptions {
		value, _, valueErr := singleBoolean(entry, option.attribute)
		if valueErr != nil {
			return nil, valueErr
		}
		*option.target = value
	}
	for _, raw := range entry.Values("olcSqlLayer") {
		configuration.layers = append(configuration.layers, string(raw))
	}
	if configuration.baseObject != "" {
		return nil, fmt.Errorf(
			"%s olcSqlBaseObject is not supported by the SQL backend",
			entry.DN,
		)
	}
	if len(configuration.layers) != 0 {
		return nil, fmt.Errorf(
			"%s olcSqlLayer is not supported by the SQL backend",
			entry.DN,
		)
	}
	return configuration, nil
}

func requiredSQLString(entry directory.Entry, attribute string) (string, error) {
	value, present, err := singleOptionalSQLString(entry, attribute)
	if err != nil {
		return "", err
	}
	if !present || value == "" {
		return "", fmt.Errorf("%s SQL backend requires %s", entry.DN, attribute)
	}
	return value, nil
}

func optionalSQLString(entry directory.Entry, attribute string) (string, error) {
	value, _, err := singleOptionalSQLString(entry, attribute)
	return value, err
}

func singleOptionalSQLString(
	entry directory.Entry,
	attribute string,
) (string, bool, error) {
	values := entry.Values(attribute)
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 {
		return "", false, fmt.Errorf("%s %s must be single-valued", entry.DN, attribute)
	}
	return string(values[0]), true, nil
}

func (configuration *sqlBackendRuntimeConfiguration) setRuntime(
	registry *schema.Registry,
	driverName string,
	server *Server,
) {
	configuration.registry = registry
	configuration.server = server
	if strings.TrimSpace(driverName) != "" {
		configuration.driverName = strings.TrimSpace(driverName)
	}
}

func (configuration *sqlBackendRuntimeConfiguration) close() error {
	configuration.mu.Lock()
	defer configuration.mu.Unlock()
	if configuration.db == nil {
		return nil
	}
	err := configuration.db.Close()
	configuration.db = nil
	configuration.objectClasses = nil
	configuration.objectClassIDs = nil
	return err
}

func (configuration *sqlBackendRuntimeConfiguration) equivalent(
	other *sqlBackendRuntimeConfiguration,
) bool {
	if configuration == nil || other == nil {
		return configuration == other
	}
	return reflect.DeepEqual(configuration.settings(), other.settings()) && sqlSchemaEquivalent(
		configuration.registry,
		other.registry,
	)
}

func (configuration *sqlBackendRuntimeConfiguration) settings() sqlBackendSettings {
	configuration.mu.Lock()
	defer configuration.mu.Unlock()
	idQuery := configuration.idQuery
	if !configuration.idQueryConfigured {
		idQuery = ""
	}
	hasReversedDN := configuration.hasReversedDN
	if !configuration.reversedDNSet {
		hasReversedDN = false
	}
	return sqlBackendSettings{
		databaseName:      configuration.databaseName,
		databaseUser:      configuration.databaseUser,
		databasePass:      configuration.databasePass,
		databaseHost:      configuration.databaseHost,
		driverName:        configuration.driverName,
		ocQuery:           configuration.ocQuery,
		attributeQuery:    configuration.attributeQuery,
		idQuery:           idQuery,
		idQueryConfigured: configuration.idQueryConfigured,
		createNeedsSelect: configuration.createNeedsSelect,
		upperFunction:     configuration.upperFunction,
		upperNeedsCast:    configuration.upperNeedsCast,
		hasReversedDN:     hasReversedDN,
		reversedDNSet:     configuration.reversedDNSet,
		failIfNoMapping:   configuration.failIfNoMapping,
		allowOrphans:      configuration.allowOrphans,
		baseObject:        configuration.baseObject,
		layers:            append([]string(nil), configuration.layers...),
		aliasingKeyword:   configuration.aliasingKeyword,
		aliasingQuote:     configuration.aliasingQuote,
		autocommit:        configuration.autocommit,
	}
}

func sqlSchemaEquivalent(left, right *schema.Registry) bool {
	if left == nil || right == nil {
		return left == right
	}
	return reflect.DeepEqual(
		left.AttributeTypeDescriptions(),
		right.AttributeTypeDescriptions(),
	) && reflect.DeepEqual(
		left.ObjectClassDescriptions(),
		right.ObjectClassDescriptions(),
	)
}

func reuseSQLBackendOnlineConfigurationState(previous, next *runtimeState) {
	if previous == nil || next == nil {
		return
	}
	byConfigDN := make(map[string]*sqlBackendRuntimeConfiguration)
	for index := range previous.databases {
		database := &previous.databases[index]
		if database.sqlBackend != nil {
			byConfigDN[database.configDNKey] = database.sqlBackend
		}
	}
	for index := range next.databases {
		database := &next.databases[index]
		previousConfiguration := byConfigDN[database.configDNKey]
		if database.sqlBackend != nil &&
			previousConfiguration.equivalent(database.sqlBackend) {
			database.sqlBackend = previousConfiguration
		}
	}
}

func (configuration *sqlBackendRuntimeConfiguration) database(
	ctx context.Context,
) (*sql.DB, error) {
	configuration.mu.Lock()
	defer configuration.mu.Unlock()
	if configuration.db != nil {
		return configuration.db, nil
	}
	dsn := configuration.databaseName
	if configuration.driverName == defaultSQLDriver {
		dsn = "DSN=" + quoteODBCValue(configuration.databaseName) +
			";UID=" + quoteODBCValue(configuration.databaseUser) +
			";PWD=" + quoteODBCValue(configuration.databasePass)
	}
	database, err := sql.Open(configuration.driverName, dsn)
	if err != nil {
		return nil, &sqlBackendUnavailableError{err: err}
	}
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, &sqlBackendUnavailableError{err: err}
	}
	configuration.detectReversedDN(ctx, database)
	configuration.prepareDefaultIDQuery()
	if err := configuration.loadMappings(ctx, database); err != nil {
		_ = database.Close()
		return nil, err
	}
	configuration.db = database
	if configuration.server != nil {
		configuration.server.registerSQLBackend(configuration)
	}
	return database, nil
}

func (configuration *sqlBackendRuntimeConfiguration) detectReversedDN(
	ctx context.Context,
	database *sql.DB,
) {
	if configuration.reversedDNSet {
		return
	}
	rows, err := database.QueryContext(
		ctx,
		"SELECT dn_ru FROM ldap_entries WHERE 1=0",
	)
	if err != nil {
		configuration.hasReversedDN = false
		return
	}
	configuration.hasReversedDN = rows.Close() == nil
}

func (configuration *sqlBackendRuntimeConfiguration) prepareDefaultIDQuery() {
	if configuration.idQueryConfigured {
		return
	}
	const prefix = "SELECT id,keyval,oc_map_id,dn FROM ldap_entries WHERE "
	switch {
	case configuration.hasReversedDN:
		configuration.idQuery = prefix + "dn_ru=?"
	case configuration.upperFunction == "":
		configuration.idQuery = prefix + "dn=?"
	case configuration.upperNeedsCast:
		configuration.idQuery = prefix + configuration.upperFunction +
			"(dn)=" + configuration.upperFunction + "(cast (? as varchar(255)))"
	default:
		configuration.idQuery = prefix + configuration.upperFunction +
			"(dn)=" + configuration.upperFunction + "(?)"
	}
}

func quoteODBCValue(value string) string {
	return "{" + strings.ReplaceAll(value, "}", "}}") + "}"
}

func (configuration *sqlBackendRuntimeConfiguration) loadMappings(
	ctx context.Context,
	database *sql.DB,
) error {
	if configuration.registry == nil {
		return errors.New("SQL backend schema registry is not initialized")
	}
	rows, err := database.QueryContext(ctx, configuration.ocQuery)
	if err != nil {
		return fmt.Errorf("SQL-backend objectClass query: %w", err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("SQL-backend objectClass columns: %w", err)
	}
	minimumColumns := 7
	if configuration.createNeedsSelect {
		minimumColumns = 8
	}
	if len(columns) < minimumColumns || len(columns) > minimumColumns+1 {
		return fmt.Errorf(
			"SQL-backend objectClass query returned %d columns, want %d or %d",
			len(columns), minimumColumns, minimumColumns+1,
		)
	}
	byID := make(map[int64]*sqlObjectClassMapping)
	byName := make(map[string]*sqlObjectClassMapping)
	for rows.Next() {
		mapping, scanErr := scanSQLObjectClassMapping(rows, configuration.createNeedsSelect, len(columns))
		if scanErr != nil {
			return fmt.Errorf("SQL-backend objectClass mapping: %w", scanErr)
		}
		if _, found := configuration.registry.ObjectClass(mapping.name); !found {
			return fmt.Errorf("SQL-backend objectClass mapping %q is not in the LDAP schema", mapping.name)
		}
		if _, duplicate := byID[mapping.id]; duplicate {
			return fmt.Errorf("SQL-backend duplicate objectClass mapping ID %d", mapping.id)
		}
		nameKey := strings.ToLower(mapping.name)
		if _, duplicate := byName[nameKey]; duplicate {
			return fmt.Errorf("SQL-backend duplicate objectClass mapping %q", mapping.name)
		}
		mapping.attributes = make(map[string][]sqlAttributeMapping)
		byID[mapping.id] = mapping
		byName[nameKey] = mapping
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("SQL-backend objectClass mappings: %w", err)
	}
	for _, mapping := range byID {
		if err := configuration.loadAttributeMappings(ctx, database, mapping); err != nil {
			return err
		}
	}
	configuration.objectClasses = byID
	configuration.objectClassIDs = byName
	return nil
}

func scanSQLObjectClassMapping(
	rows *sql.Rows,
	createNeedsSelect bool,
	columnCount int,
) (*sqlObjectClassMapping, error) {
	var mapping sqlObjectClassMapping
	var name, keyTable, keyColumn, create, createKey, remove, hint sql.NullString
	var expect sql.NullInt64
	destinations := []any{&mapping.id, &name, &keyTable, &keyColumn, &create}
	if createNeedsSelect {
		destinations = append(destinations, &createKey)
	}
	destinations = append(destinations, &remove, &expect)
	if columnCount == len(destinations)+1 {
		destinations = append(destinations, &hint)
	}
	if err := rows.Scan(destinations...); err != nil {
		return nil, err
	}
	mapping.name = name.String
	mapping.keyTable = keyTable.String
	mapping.keyColumn = keyColumn.String
	mapping.createProcedure = create.String
	mapping.createKeyQuery = createKey.String
	mapping.deleteProcedure = remove.String
	mapping.expectReturn = expect.Int64
	mapping.createHint = hint.String
	if mapping.name == "" || mapping.keyTable == "" || mapping.keyColumn == "" {
		return nil, errors.New("name, key table, and key column are required")
	}
	return &mapping, nil
}

func (configuration *sqlBackendRuntimeConfiguration) loadAttributeMappings(
	ctx context.Context,
	database *sql.DB,
	objectClass *sqlObjectClassMapping,
) error {
	rows, err := database.QueryContext(ctx, configuration.attributeQuery, objectClass.id)
	if err != nil {
		return fmt.Errorf("SQL-backend attribute query for %s: %w", objectClass.name, err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("SQL-backend attribute columns for %s: %w", objectClass.name, err)
	}
	if len(columns) != 9 {
		return fmt.Errorf(
			"SQL-backend attribute query for %s returned %d columns, want 9",
			objectClass.name, len(columns),
		)
	}
	for rows.Next() {
		var name, selectExpression, fromTables, joinWhere sql.NullString
		var addProcedure, deleteProcedure, upperExpression sql.NullString
		var parameterOrder, expectReturn sql.NullInt64
		if err := rows.Scan(
			&name, &selectExpression, &fromTables, &joinWhere,
			&addProcedure, &deleteProcedure, &parameterOrder, &expectReturn,
			&upperExpression,
		); err != nil {
			return fmt.Errorf("SQL-backend attribute mapping for %s: %w", objectClass.name, err)
		}
		if name.String == "" || selectExpression.String == "" || fromTables.String == "" {
			return fmt.Errorf("SQL-backend attribute mapping for %s has empty required columns", objectClass.name)
		}
		if _, found := configuration.registry.AttributeType(name.String); !found {
			return fmt.Errorf(
				"SQL-backend attribute mapping %s/%s is not in the LDAP schema",
				objectClass.name, name.String,
			)
		}
		description := name.String
		if attribute, found, effectiveErr := configuration.registry.EffectiveAttributeType(name.String); effectiveErr != nil {
			return fmt.Errorf("SQL-backend attribute mapping %s/%s: %w", objectClass.name, name.String, effectiveErr)
		} else if found {
			if syntax, exists := configuration.registry.LDAPSyntax(attribute.Syntax); exists &&
				syntax.BinaryTransferRequired {
				description += ";binary"
			}
		}
		mapping := sqlAttributeMapping{
			name:             name.String,
			description:      description,
			selectExpression: selectExpression.String,
			fromTables:       fromTables.String,
			joinWhere:        joinWhere.String,
			addProcedure:     addProcedure.String,
			deleteProcedure:  deleteProcedure.String,
			parameterOrder:   parameterOrder.Int64,
			expectReturn:     expectReturn.Int64,
			upperExpression:  upperExpression.String,
		}
		mapping.query = configuration.attributeSelectQuery(objectClass, mapping)
		key := strings.ToLower(mapping.name)
		objectClass.attributes[key] = append(objectClass.attributes[key], mapping)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("SQL-backend attribute mappings for %s: %w", objectClass.name, err)
	}
	return nil
}

func (configuration *sqlBackendRuntimeConfiguration) attributeSelectQuery(
	objectClass *sqlObjectClassMapping,
	attribute sqlAttributeMapping,
) string {
	alias := configuration.aliasingQuote + attribute.name + configuration.aliasingQuote
	query := "SELECT " + attribute.selectExpression + " " +
		configuration.aliasingKeyword + alias + " FROM " + attribute.fromTables +
		" WHERE " + objectClass.keyTable + "." + objectClass.keyColumn + "=?"
	if attribute.joinWhere != "" {
		query += " AND " + attribute.joinWhere
	}
	return query + " ORDER BY " + alias
}

type sqlBackendReader struct {
	storage.Reader
	configuration *sqlBackendRuntimeConfiguration
	ctx           context.Context
}

func (reader *sqlBackendReader) AccessContext() any {
	if provider, ok := reader.Reader.(interface{ AccessContext() any }); ok {
		return provider.AccessContext()
	}
	return nil
}

func (reader *sqlBackendReader) Get(
	dn directory.DN,
) (entry directory.Entry, err error) {
	defer func() { err = sqlBackendLDAPError(err) }()
	database, err := reader.configuration.database(reader.ctx)
	if err != nil {
		return directory.Entry{}, err
	}
	parameter := dn.Key()
	if reader.configuration.hasReversedDN {
		parameter = reverseUpperASCII(parameter)
	}
	var id sqlEntryID
	err = database.QueryRowContext(reader.ctx, reader.configuration.idQuery, parameter).Scan(
		&id.id, &id.keyValue, &id.objectClassID, &id.dn,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return directory.Entry{}, storage.ErrEntryNotFound
	}
	if err != nil {
		return directory.Entry{}, fmt.Errorf("SQL-backend entry ID query: %w", err)
	}
	return reader.loadEntry(database, id)
}

func (reader *sqlBackendReader) ForEach(
	visit func(directory.Entry) error,
) (err error) {
	defer func() { err = sqlBackendLDAPError(err) }()
	database, err := reader.configuration.database(reader.ctx)
	if err != nil {
		return err
	}
	rows, err := database.QueryContext(
		reader.ctx,
		"SELECT id,keyval,oc_map_id,dn FROM ldap_entries ORDER BY id",
	)
	if err != nil {
		return fmt.Errorf("SQL-backend entry scan: %w", err)
	}
	var ids []sqlEntryID
	for rows.Next() {
		var id sqlEntryID
		if err := rows.Scan(&id.id, &id.keyValue, &id.objectClassID, &id.dn); err != nil {
			_ = rows.Close()
			return fmt.Errorf("SQL-backend entry ID: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("SQL-backend entry scan: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("SQL-backend entry scan close: %w", err)
	}
	for _, id := range ids {
		entry, err := reader.loadEntry(database, id)
		if err != nil {
			return err
		}
		if err := visit(entry); err != nil {
			return &sqlBackendVisitorError{err: err}
		}
	}
	return nil
}

func (reader *sqlBackendReader) GetIn(
	partition string,
	dn directory.DN,
) (directory.Entry, error) {
	return reader.Reader.GetIn(partition, dn)
}

func (reader *sqlBackendReader) ForEachIn(
	partition string,
	visit func(directory.Entry) error,
) error {
	return reader.Reader.ForEachIn(partition, visit)
}

func (reader *sqlBackendReader) ForEachPartition(
	visit func(string, directory.Entry) error,
) error {
	return reader.Reader.ForEachPartition(visit)
}

func (reader *sqlBackendReader) loadEntry(
	database *sql.DB,
	id sqlEntryID,
) (directory.Entry, error) {
	objectClass := reader.configuration.objectClasses[id.objectClassID]
	if objectClass == nil {
		return directory.Entry{}, fmt.Errorf(
			"SQL-backend entry %d references unknown objectClass mapping %d",
			id.id, id.objectClassID,
		)
	}
	if _, err := directory.ParseDN(id.dn); err != nil {
		return directory.Entry{}, fmt.Errorf("SQL-backend entry %d DN: %w", id.id, err)
	}
	entry := directory.Entry{DN: id.dn}
	appendSQLAttributeValue(&entry, "objectClass", []byte(objectClass.name))
	auxiliaryRows, err := database.QueryContext(
		reader.ctx,
		"SELECT oc_name FROM ldap_entry_objclasses WHERE entry_id=? ORDER BY oc_name",
		id.id,
	)
	if err != nil {
		return directory.Entry{}, fmt.Errorf("SQL-backend objectClass values for entry %d: %w", id.id, err)
	}
	for auxiliaryRows.Next() {
		var value sql.NullString
		if err := auxiliaryRows.Scan(&value); err != nil {
			_ = auxiliaryRows.Close()
			return directory.Entry{}, fmt.Errorf("SQL-backend objectClass value for entry %d: %w", id.id, err)
		}
		if value.Valid {
			appendSQLAttributeValue(&entry, "objectClass", []byte(value.String))
		}
	}
	if err := auxiliaryRows.Err(); err != nil {
		_ = auxiliaryRows.Close()
		return directory.Entry{}, fmt.Errorf("SQL-backend objectClass values for entry %d: %w", id.id, err)
	}
	if err := auxiliaryRows.Close(); err != nil {
		return directory.Entry{}, err
	}
	attributeNames := make([]string, 0, len(objectClass.attributes))
	for name := range objectClass.attributes {
		attributeNames = append(attributeNames, name)
	}
	sort.Strings(attributeNames)
	for _, name := range attributeNames {
		mappings := objectClass.attributes[name]
		for _, mapping := range mappings {
			values, err := reader.readAttributeValues(database, id.keyValue, mapping)
			if err != nil {
				return directory.Entry{}, fmt.Errorf(
					"SQL-backend attribute %s for entry %d: %w",
					mapping.name, id.id, err,
				)
			}
			for _, value := range values {
				appendSQLAttributeValue(&entry, mapping.description, value)
			}
		}
	}
	appendSQLAttributeValue(&entry, "structuralObjectClass", []byte(objectClass.name))
	appendSQLAttributeValue(&entry, "entryUUID", []byte(sqlEntryUUID(id.objectClassID, id.keyValue)))
	var childCount int64
	if err := database.QueryRowContext(
		reader.ctx,
		"SELECT COUNT(*) FROM ldap_entries WHERE parent=?",
		id.id,
	).Scan(&childCount); err != nil {
		return directory.Entry{}, fmt.Errorf("SQL-backend subordinate count for entry %d: %w", id.id, err)
	}
	if childCount > 0 {
		appendSQLAttributeValue(&entry, "hasSubordinates", []byte("TRUE"))
	} else {
		appendSQLAttributeValue(&entry, "hasSubordinates", []byte("FALSE"))
	}
	return entry, nil
}

func (reader *sqlBackendReader) readAttributeValues(
	database *sql.DB,
	keyValue int64,
	mapping sqlAttributeMapping,
) ([][]byte, error) {
	rows, err := database.QueryContext(reader.ctx, mapping.query, keyValue)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values [][]byte
	for rows.Next() {
		var raw any
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if raw == nil {
			continue
		}
		value, err := sqlAttributeBytes(raw)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func sqlAttributeBytes(value any) ([]byte, error) {
	switch value := value.(type) {
	case []byte:
		return append([]byte(nil), value...), nil
	case string:
		return []byte(value), nil
	case bool:
		if value {
			return []byte("TRUE"), nil
		}
		return []byte("FALSE"), nil
	case int64:
		return []byte(strconv.FormatInt(value, 10)), nil
	case float64:
		return []byte(strconv.FormatFloat(value, 'g', -1, 64)), nil
	case time.Time:
		return []byte(value.Format(time.RFC3339Nano)), nil
	default:
		return nil, fmt.Errorf("unsupported SQL value type %T", value)
	}
}

func appendSQLAttributeValue(entry *directory.Entry, description string, value []byte) {
	for index := range entry.Attributes {
		if strings.EqualFold(entry.Attributes[index].Description, description) {
			entry.Attributes[index].Values = append(
				entry.Attributes[index].Values,
				append([]byte(nil), value...),
			)
			return
		}
	}
	entry.Attributes = append(entry.Attributes, directory.Attribute{
		Description: description,
		Values:      [][]byte{append([]byte(nil), value...)},
	})
}

func sqlEntryUUID(objectClassID, keyValue int64) string {
	return fmt.Sprintf(
		"%08x-%04x-%04x-0000-000000000000",
		uint32(objectClassID), uint16(uint64(keyValue)>>16), uint16(keyValue),
	)
}

func reverseUpperASCII(value string) string {
	input := []byte(value)
	output := make([]byte, len(input))
	for index, character := range input {
		if character >= 'a' && character <= 'z' {
			character -= 'a' - 'A'
		}
		output[len(input)-1-index] = character
	}
	return string(output)
}

type sqlBackendUnavailableError struct {
	err error
}

type sqlBackendWriter struct {
	storage.Writer
	reader *sqlBackendReader
}

func (writer *sqlBackendWriter) AccessContext() any {
	return writer.reader.AccessContext()
}

func (writer *sqlBackendWriter) StorageContext() context.Context {
	return writer.reader.ctx
}

func (writer *sqlBackendWriter) Get(dn directory.DN) (directory.Entry, error) {
	return writer.reader.Get(dn)
}

func (writer *sqlBackendWriter) ForEach(visit func(directory.Entry) error) error {
	return writer.reader.ForEach(visit)
}

func (writer *sqlBackendWriter) Put(directory.Entry, bool) error {
	return sqlBackendWriteUnsupported()
}

func (writer *sqlBackendWriter) PutIn(string, directory.Entry, bool) error {
	return sqlBackendWriteUnsupported()
}

func (writer *sqlBackendWriter) Delete(directory.DN) error {
	return sqlBackendWriteUnsupported()
}

func (writer *sqlBackendWriter) DeleteIn(string, directory.DN) error {
	return sqlBackendWriteUnsupported()
}

func (writer *sqlBackendWriter) Clear() error {
	return sqlBackendWriteUnsupported()
}

func sqlBackendWriteUnsupported() error {
	return operationFailed(
		ldapwire.ResultUnwillingToPerform,
		"SQL backend write transaction support is not available",
	)
}

func (err *sqlBackendUnavailableError) Error() string {
	return "SQL backend unavailable: " + err.err.Error()
}

func (err *sqlBackendUnavailableError) Unwrap() error {
	return err.err
}

func sqlBackendLDAPError(err error) error {
	var visitor *sqlBackendVisitorError
	if errors.As(err, &visitor) {
		return visitor.err
	}
	if err == nil || errors.Is(err, storage.ErrEntryNotFound) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		asOperationFailure(err) != nil {
		return err
	}
	var unavailable *sqlBackendUnavailableError
	if errors.As(err, &unavailable) {
		return operationFailed(
			ldapwire.ResultUnavailable,
			"could not connect to SQL backend",
		)
	}
	return operationFailed(ldapwire.ResultOther, "SQL-backend error")
}

type sqlBackendVisitorError struct {
	err error
}

func (err *sqlBackendVisitorError) Error() string {
	return err.err.Error()
}

func (err *sqlBackendVisitorError) Unwrap() error {
	return err.err
}
