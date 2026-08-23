package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
	defaultSQLIDQuery              = "SELECT id,keyval,oc_map_id,dn FROM ldap_entries WHERE dn=?"
	defaultSQLInsertEntryStatement = "INSERT INTO ldap_entries " +
		"(dn,oc_map_id,parent,keyval) VALUES (?,?,?,?)"
	defaultSQLDeleteEntryStatement         = "DELETE FROM ldap_entries WHERE id=?"
	defaultSQLRenameEntryStatement         = "UPDATE ldap_entries SET dn=?,parent=?,keyval=? WHERE id=?"
	defaultSQLDeleteObjectClassesStatement = "DELETE FROM ldap_entry_objclasses WHERE entry_id=?"
	maxSQLBaseObjectFileSize               = 8 << 20
	maxSQLBaseObjectRecords                = 1024
)

type sqlScopeTemplate uint8

const (
	sqlScopeTemplateNone sqlScopeTemplate = iota
	sqlScopeTemplateLike
	sqlScopeTemplateUpperLike
)

type sqlDNLayer struct {
	kind   string
	local  directory.DN
	remote directory.DN
}

type sqlBackendRuntimeConfiguration struct {
	databaseName string
	databaseUser string
	databasePass string
	databaseHost string
	driverName   string

	ocQuery            string
	attributeQuery     string
	idQuery            string
	idQueryConfigured  bool
	dnMatchCondition   string
	dnMatchConfigured  bool
	hasChildrenQuery   string
	createNeedsSelect  bool
	upperFunction      string
	upperNeedsCast     bool
	hasReversedDN      bool
	reversedDNSet      bool
	failIfNoMapping    bool
	allowOrphans       bool
	baseObject         string
	baseObjectSuffix   string
	baseObjectDigest   [sha256.Size]byte
	baseObjectData     []byte
	baseObjectEntry    *directory.Entry
	layers             []string
	dnLayer            *sqlDNLayer
	subtreeCondition   string
	subtreeTemplate    sqlScopeTemplate
	childrenCondition  string
	childrenTemplate   sqlScopeTemplate
	useSubtreeShortcut bool
	checkSchema        bool
	suffixes           []string
	fetchAllAttrs      bool
	fetchAttrs         []string
	aliasingKeyword    string
	aliasingQuote      string
	autocommit         bool
	insertEntry        string
	deleteEntry        string
	renameEntry        string
	deleteObjectClass  string
	collectivePlanKey  string

	registry *schema.Registry
	server   *Server

	mu             sync.Mutex
	db             *sql.DB
	objectClasses  map[int64]*sqlObjectClassMapping
	objectClassIDs map[string]*sqlObjectClassMapping
	retired        bool
	references     int
}

type sqlBackendSettings struct {
	databaseName       string
	databaseUser       string
	databasePass       string
	databaseHost       string
	driverName         string
	ocQuery            string
	attributeQuery     string
	idQuery            string
	idQueryConfigured  bool
	dnMatchCondition   string
	dnMatchConfigured  bool
	createNeedsSelect  bool
	upperFunction      string
	upperNeedsCast     bool
	hasReversedDN      bool
	reversedDNSet      bool
	failIfNoMapping    bool
	allowOrphans       bool
	baseObject         string
	baseObjectSuffix   string
	baseObjectDigest   [sha256.Size]byte
	layers             []string
	dnLayer            *sqlDNLayer
	subtreeCondition   string
	subtreeTemplate    sqlScopeTemplate
	childrenCondition  string
	childrenTemplate   sqlScopeTemplate
	useSubtreeShortcut bool
	checkSchema        bool
	suffixes           []string
	fetchAllAttrs      bool
	fetchAttrs         []string
	aliasingKeyword    string
	aliasingQuote      string
	autocommit         bool
	insertEntry        string
	deleteEntry        string
	renameEntry        string
	deleteObjectClass  string
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

type sqlBackendSearchRequirementsContextKey struct{}

type sqlBackendIgnoreSearchRequirementsContextKey struct{}

type sqlBackendSearchRequirements struct {
	hasSubordinates bool
	attributes      []string
	filter          directory.Filter
	hasFilter       bool
	base            directory.DN
	scope           directory.Scope
	hasScope        bool
}

func withSQLBackendSearchRequirements(
	ctx context.Context,
	attributes []string,
	filters ...directory.Filter,
) context.Context {
	requirements := sqlBackendSearchRequirements{
		hasSubordinates: sqlBackendSearchRequestsHasSubordinates(attributes, filters),
		attributes:      append([]string(nil), attributes...),
	}
	if len(filters) > 0 {
		requirements.filter = filters[0]
		requirements.hasFilter = true
	}
	return context.WithValue(ctx, sqlBackendSearchRequirementsContextKey{}, requirements)
}

func withSQLBackendScopeRequirements(
	ctx context.Context,
	base directory.DN,
	scope directory.Scope,
) context.Context {
	requirements, _ := ctx.Value(
		sqlBackendSearchRequirementsContextKey{},
	).(sqlBackendSearchRequirements)
	requirements.base = base
	requirements.scope = scope
	requirements.hasScope = true
	return context.WithValue(ctx, sqlBackendSearchRequirementsContextKey{}, requirements)
}

func withoutSQLBackendSearchRequirements(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, sqlBackendIgnoreSearchRequirementsContextKey{}, true)
}

func sqlBackendSearchRequestsHasSubordinates(
	attributes []string,
	filters []directory.Filter,
) bool {
	for _, attribute := range attributes {
		if strings.EqualFold(strings.TrimSpace(attribute), "+") ||
			sqlBackendHasSubordinatesDescription(attribute) {
			return true
		}
	}
	for _, filter := range filters {
		if sqlBackendFilterReferencesHasSubordinates(filter) {
			return true
		}
	}
	return false
}

func sqlBackendFilterReferencesHasSubordinates(filter directory.Filter) bool {
	if sqlBackendHasSubordinatesDescription(filter.Attribute) {
		return true
	}
	for _, child := range filter.Children {
		if sqlBackendFilterReferencesHasSubordinates(child) {
			return true
		}
	}
	return false
}

func sqlBackendHasSubordinatesDescription(description string) bool {
	description = strings.TrimSpace(description)
	if separator := strings.IndexByte(description, ';'); separator >= 0 {
		description = description[:separator]
	}
	return strings.EqualFold(description, "hasSubordinates") ||
		strings.EqualFold(description, "2.5.18.9")
}

type sqlBackendQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type sqlBackendExecutor interface {
	sqlBackendQueryer
	ExecContext(context.Context, string, ...any) (sql.Result, error)
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
		databaseName:      databaseName,
		databaseUser:      databaseUser,
		driverName:        defaultSQLDriver,
		ocQuery:           defaultSQLOCQuery,
		attributeQuery:    defaultSQLATQuery,
		idQuery:           defaultSQLIDQuery,
		aliasingKeyword:   "AS ",
		insertEntry:       defaultSQLInsertEntryStatement,
		deleteEntry:       defaultSQLDeleteEntryStatement,
		renameEntry:       defaultSQLRenameEntryStatement,
		deleteObjectClass: defaultSQLDeleteObjectClassesStatement,
		checkSchema:       true,
	}
	for _, value := range entry.Values("olcSuffix") {
		configuration.suffixes = append(configuration.suffixes, string(value))
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
		{"olcSqlInsEntryStmt", &configuration.insertEntry},
		{"olcSqlDelEntryStmt", &configuration.deleteEntry},
		{"olcSqlRenEntryStmt", &configuration.renameEntry},
		{"olcSqlDelObjclassesStmt", &configuration.deleteObjectClass},
	}
	if value, present, valueErr := singleOptionalSQLString(entry, "olcSqlIdQuery"); valueErr != nil {
		return nil, valueErr
	} else if present {
		configuration.idQuery = value
		configuration.idQueryConfigured = true
	}
	if value, present, valueErr := singleOptionalSQLString(entry, "olcSqlDnMatchCond"); valueErr != nil {
		return nil, valueErr
	} else if present {
		configuration.dnMatchCondition = value
		configuration.dnMatchConfigured = true
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
		{"olcSqlFetchAllAttrs", &configuration.fetchAllAttrs},
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
		value := strings.TrimSpace(string(raw))
		if value == "" {
			return nil, fmt.Errorf("%s olcSqlLayer must not be empty", entry.DN)
		}
		configuration.layers = append(configuration.layers, value)
	}
	if configuration.baseObject != "" {
		suffixes := entry.Values("olcSuffix")
		if len(suffixes) == 0 {
			return nil, fmt.Errorf("%s olcSqlBaseObject requires olcSuffix", entry.DN)
		}
		if strings.EqualFold(strings.TrimSpace(configuration.baseObject), "TRUE") {
			configuration.baseObject = "TRUE"
		} else {
			path, pathErr := filepath.Abs(strings.TrimSpace(configuration.baseObject))
			if pathErr != nil || !filepath.IsAbs(strings.TrimSpace(configuration.baseObject)) {
				return nil, fmt.Errorf(
					"%s olcSqlBaseObject file must be an absolute path",
					entry.DN,
				)
			}
			configuration.baseObject = path
			configuration.baseObjectData, configuration.baseObjectDigest, err =
				readSQLBaseObjectFile(path)
			if err != nil {
				return nil, fmt.Errorf("%s olcSqlBaseObject: %w", entry.DN, err)
			}
		}
		configuration.baseObjectSuffix = string(suffixes[0])
	}
	if err := configuration.prepareSQLLayers(entry); err != nil {
		return nil, err
	}
	if value, present, valueErr := singleOptionalSQLString(entry, "olcSqlFetchAttrs"); valueErr != nil {
		return nil, valueErr
	} else if present {
		configuration.fetchAttrs, err = parseSQLFetchAttributes(value)
		if err != nil {
			return nil, fmt.Errorf("%s olcSqlFetchAttrs: %w", entry.DN, err)
		}
	}
	unsupportedStrings := []string{
		"olcSqlConcatPattern",
		"olcSqlStrcastFunc",
	}
	for _, attribute := range unsupportedStrings {
		if _, present, valueErr := singleOptionalSQLString(entry, attribute); valueErr != nil {
			return nil, valueErr
		} else if present {
			return nil, fmt.Errorf(
				"%s %s SQL-template semantics are not supported",
				entry.DN,
				attribute,
			)
		}
	}
	if value, present, valueErr := singleOptionalSQLString(entry, "olcSqlSubtreeCond"); valueErr != nil {
		return nil, valueErr
	} else if present {
		configuration.subtreeCondition = value
		configuration.subtreeTemplate, err = parseSQLScopeTemplate(value)
		if err != nil {
			return nil, fmt.Errorf("%s olcSqlSubtreeCond: %w", entry.DN, err)
		}
	}
	if value, present, valueErr := singleOptionalSQLString(entry, "olcSqlChildrenCond"); valueErr != nil {
		return nil, valueErr
	} else if present {
		configuration.childrenCondition = value
		configuration.childrenTemplate, err = parseSQLScopeTemplate(value)
		if err != nil {
			return nil, fmt.Errorf("%s olcSqlChildrenCond: %w", entry.DN, err)
		}
	}
	if configuration.useSubtreeShortcut, _, err = singleBoolean(entry, "olcSqlUseSubtreeShortcut"); err != nil {
		return nil, err
	}
	// OpenLDAP enables this unconditionally at database open when there is
	// exactly one naming context, even if the directive was absent or false.
	if len(configuration.suffixes) == 1 {
		configuration.useSubtreeShortcut = true
	}
	if value, present, valueErr := singleBoolean(entry, "olcSqlCheckSchema"); valueErr != nil {
		return nil, valueErr
	} else if present {
		configuration.checkSchema = value
	}
	configuration.prepareHasChildrenQuery()
	return configuration, nil
}

func parseSQLFetchAttributes(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	attributes := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		attribute := strings.TrimSpace(part)
		if attribute == "" {
			return nil, errors.New("attribute list contains an empty item")
		}
		key := strings.ToLower(attribute)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		attributes = append(attributes, attribute)
	}
	return attributes, nil
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
	return configuration.closeLocked()
}

func (configuration *sqlBackendRuntimeConfiguration) closeLocked() error {
	if configuration.db == nil {
		return nil
	}
	err := configuration.db.Close()
	configuration.db = nil
	configuration.objectClasses = nil
	configuration.objectClassIDs = nil
	return err
}

func (configuration *sqlBackendRuntimeConfiguration) retain() bool {
	configuration.mu.Lock()
	defer configuration.mu.Unlock()
	if configuration.retired {
		return false
	}
	configuration.references++
	return true
}

func (configuration *sqlBackendRuntimeConfiguration) release() bool {
	configuration.mu.Lock()
	defer configuration.mu.Unlock()
	if configuration.references > 0 {
		configuration.references--
	}
	if !configuration.retired || configuration.references != 0 {
		return false
	}
	_ = configuration.closeLocked()
	return true
}

func (configuration *sqlBackendRuntimeConfiguration) retire() bool {
	configuration.mu.Lock()
	defer configuration.mu.Unlock()
	configuration.retired = true
	if configuration.references != 0 {
		return false
	}
	_ = configuration.closeLocked()
	return true
}

func (configuration *sqlBackendRuntimeConfiguration) opened() bool {
	configuration.mu.Lock()
	defer configuration.mu.Unlock()
	return configuration.db != nil
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
	dnMatchCondition := configuration.dnMatchCondition
	if !configuration.dnMatchConfigured {
		dnMatchCondition = ""
	}
	return sqlBackendSettings{
		databaseName:       configuration.databaseName,
		databaseUser:       configuration.databaseUser,
		databasePass:       configuration.databasePass,
		databaseHost:       configuration.databaseHost,
		driverName:         configuration.driverName,
		ocQuery:            configuration.ocQuery,
		attributeQuery:     configuration.attributeQuery,
		idQuery:            idQuery,
		idQueryConfigured:  configuration.idQueryConfigured,
		dnMatchCondition:   dnMatchCondition,
		dnMatchConfigured:  configuration.dnMatchConfigured,
		createNeedsSelect:  configuration.createNeedsSelect,
		upperFunction:      configuration.upperFunction,
		upperNeedsCast:     configuration.upperNeedsCast,
		hasReversedDN:      hasReversedDN,
		reversedDNSet:      configuration.reversedDNSet,
		failIfNoMapping:    configuration.failIfNoMapping,
		allowOrphans:       configuration.allowOrphans,
		baseObject:         configuration.baseObject,
		baseObjectSuffix:   configuration.baseObjectSuffix,
		baseObjectDigest:   configuration.baseObjectDigest,
		layers:             append([]string(nil), configuration.layers...),
		dnLayer:            cloneSQLDNLayer(configuration.dnLayer),
		subtreeCondition:   configuration.subtreeCondition,
		subtreeTemplate:    configuration.subtreeTemplate,
		childrenCondition:  configuration.childrenCondition,
		childrenTemplate:   configuration.childrenTemplate,
		useSubtreeShortcut: configuration.useSubtreeShortcut,
		checkSchema:        configuration.checkSchema,
		suffixes:           append([]string(nil), configuration.suffixes...),
		fetchAllAttrs:      configuration.fetchAllAttrs,
		fetchAttrs:         append([]string(nil), configuration.fetchAttrs...),
		aliasingKeyword:    configuration.aliasingKeyword,
		aliasingQuote:      configuration.aliasingQuote,
		autocommit:         configuration.autocommit,
		insertEntry:        configuration.insertEntry,
		deleteEntry:        configuration.deleteEntry,
		renameEntry:        configuration.renameEntry,
		deleteObjectClass:  configuration.deleteObjectClass,
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

func sqlBackendConfigurations(
	runtime *runtimeState,
) map[*sqlBackendRuntimeConfiguration]struct{} {
	configurations := make(map[*sqlBackendRuntimeConfiguration]struct{})
	if runtime == nil {
		return configurations
	}
	for index := range runtime.databases {
		if configuration := runtime.databases[index].sqlBackend; configuration != nil {
			configurations[configuration] = struct{}{}
		}
	}
	return configurations
}

func (server *Server) retainActiveRuntime() *runtimeState {
	server.runtimeActivationMu.Lock()
	defer server.runtimeActivationMu.Unlock()
	runtime := server.runtime.Load()
	retained := make([]*sqlBackendRuntimeConfiguration, 0)
	for configuration := range sqlBackendConfigurations(runtime) {
		if !configuration.retain() {
			for _, previous := range retained {
				previous.release()
			}
			return nil
		}
		retained = append(retained, configuration)
	}
	return runtime
}

func (server *Server) releaseRuntimeSQLBackends(runtime *runtimeState) {
	for configuration := range sqlBackendConfigurations(runtime) {
		if configuration.release() {
			server.unregisterSQLBackend(configuration)
		}
	}
}

func (server *Server) retireSQLBackends(previous, next *runtimeState) {
	nextConfigurations := sqlBackendConfigurations(next)
	for configuration := range sqlBackendConfigurations(previous) {
		if _, active := nextConfigurations[configuration]; active {
			continue
		}
		if configuration.retire() {
			server.unregisterSQLBackend(configuration)
		}
	}
}

func (server *Server) closeCandidateSQLBackends(
	runtime *runtimeState,
	except *runtimeState,
) {
	retained := sqlBackendConfigurations(except)
	for configuration := range sqlBackendConfigurations(runtime) {
		if _, keep := retained[configuration]; keep {
			continue
		}
		if configuration.retire() {
			server.unregisterSQLBackend(configuration)
		}
	}
}

func (server *Server) validateSQLBackends(
	ctx context.Context,
	runtime *runtimeState,
) error {
	if runtime == nil {
		return nil
	}
	for index := range runtime.databases {
		database := &runtime.databases[index]
		if database.sqlBackend == nil {
			continue
		}
		if _, err := database.sqlBackend.database(ctx); err != nil {
			return fmt.Errorf("%s: %w", database.name, err)
		}
	}
	return nil
}

func (configuration *sqlBackendRuntimeConfiguration) database(
	ctx context.Context,
) (*sql.DB, error) {
	configuration.mu.Lock()
	defer configuration.mu.Unlock()
	if configuration.retired && configuration.references == 0 {
		return nil, &sqlBackendUnavailableError{
			err: errors.New("SQL backend configuration is retired"),
		}
	}
	if configuration.db != nil {
		return configuration.db, nil
	}
	dsn := configuration.databaseName
	if configuration.driverName == defaultSQLDriver {
		dsn = "DSN=" + quoteODBCValue(configuration.databaseName) +
			";UID=" + quoteODBCValue(configuration.databaseUser) +
			";PWD=" + quoteODBCValue(configuration.databasePass)
	}
	var database *sql.DB
	if configuration.driverName == defaultSQLDriver {
		connector, err := newSQLBackendODBCConnector(dsn)
		if err != nil {
			return nil, &sqlBackendUnavailableError{err: err}
		}
		database = sql.OpenDB(connector)
	} else {
		var err error
		database, err = sql.Open(configuration.driverName, dsn)
		if err != nil {
			return nil, &sqlBackendUnavailableError{err: err}
		}
	}
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, &sqlBackendUnavailableError{err: err}
	}
	configuration.detectReversedDN(ctx, database)
	configuration.prepareDefaultIDQuery()
	configuration.prepareHasChildrenQuery()
	if err := configuration.loadMappings(ctx, database); err != nil {
		_ = database.Close()
		return nil, err
	}
	if err := configuration.prepareBaseObject(); err != nil {
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

func (configuration *sqlBackendRuntimeConfiguration) prepareHasChildrenQuery() {
	condition := configuration.dnMatchCondition
	if !configuration.dnMatchConfigured {
		switch {
		case configuration.upperFunction == "":
			condition = "ldap_entries.dn=?"
		case configuration.upperNeedsCast:
			condition = configuration.upperFunction + "(ldap_entries.dn)=" +
				configuration.upperFunction + "(cast (? as varchar(255)))"
		default:
			condition = configuration.upperFunction + "(ldap_entries.dn)=" +
				configuration.upperFunction + "(?)"
		}
	}
	configuration.hasChildrenQuery = "SELECT COUNT(distinct subordinates.id) " +
		"FROM ldap_entries,ldap_entries " + configuration.aliasingKeyword +
		"subordinates WHERE subordinates.parent=ldap_entries.id AND " + condition
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
	fromTables := mergeSQLFromTable(attribute.fromTables, objectClass.keyTable)
	query := "SELECT " + attribute.selectExpression + " " +
		configuration.aliasingKeyword + alias + " FROM " + fromTables +
		" WHERE " + objectClass.keyTable + "." + objectClass.keyColumn + "=?"
	if attribute.joinWhere != "" {
		query += " AND " + attribute.joinWhere
	}
	return query + " ORDER BY " + alias
}

func mergeSQLFromTable(fromTables, keyTable string) string {
	keyName := strings.ToLower(sqlTableName(keyTable))
	for _, specification := range splitSQLTableSpecifications(fromTables) {
		if strings.ToLower(sqlTableName(specification)) == keyName {
			return fromTables
		}
	}
	if strings.TrimSpace(fromTables) == "" {
		return keyTable
	}
	return fromTables + "," + keyTable
}

func splitSQLTableSpecifications(value string) []string {
	var result []string
	start := 0
	depth := 0
	var quote rune
	escaped := false
	for index, character := range value {
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if character == '\\' {
				escaped = true
				continue
			}
			if character == quote {
				quote = 0
			}
			continue
		}
		switch character {
		case '\'', '"', '`':
			quote = character
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				result = append(result, strings.TrimSpace(value[start:index]))
				start = index + 1
			}
		}
	}
	result = append(result, strings.TrimSpace(value[start:]))
	return result
}

func sqlTableName(specification string) string {
	fields := strings.Fields(strings.TrimSpace(specification))
	if len(fields) == 0 {
		return ""
	}
	return strings.Trim(fields[0], "\"`[]")
}

type sqlBackendReader struct {
	storage.Reader
	configuration     *sqlBackendRuntimeConfiguration
	ctx               context.Context
	queryer           sqlBackendQueryer
	initializationErr error
}

func (reader *sqlBackendReader) collectiveAttributePlanReader() (string, storage.Reader) {
	if reader == nil || reader.configuration == nil {
		return "", reader
	}
	cacheKey := reader.configuration.collectivePlanKey
	if cacheKey == "" {
		cacheKey = fmt.Sprintf("%p", reader.configuration)
	}
	metadata := *reader
	metadata.ctx = withoutSQLBackendSearchRequirements(reader.ctx)
	return "sql:" + cacheKey, &metadata
}

func (reader *sqlBackendReader) NormalizeDNIdentity(
	dn directory.DN,
) (directory.DN, error) {
	if reader.configuration == nil || reader.configuration.registry == nil {
		return dn, nil
	}
	return reader.configuration.registry.NormalizeDN(dn.String())
}

func (reader *sqlBackendReader) DNIdentityOrderKey(
	dn directory.DN,
) (string, error) {
	normalized, err := reader.NormalizeDNIdentity(dn)
	if err != nil {
		return "", err
	}
	return normalized.NormalizedString(), nil
}

func (reader *sqlBackendReader) normalizedSQLDN(
	dn directory.DN,
) (directory.DN, string, error) {
	normalized, err := reader.NormalizeDNIdentity(dn)
	if err != nil {
		return directory.DN{}, "", err
	}
	mapped, err := reader.configuration.mapLDAPDNToSQL(normalized)
	if err != nil {
		return directory.DN{}, "", err
	}
	return normalized, mapped.NormalizedString(), nil
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
	if reader.initializationErr != nil {
		return directory.Entry{}, reader.initializationErr
	}
	database, err := reader.configuration.database(reader.ctx)
	if err != nil {
		return directory.Entry{}, err
	}
	queryer := reader.queryer
	if queryer == nil {
		queryer = database
	}
	if entry, found, baseErr := reader.configuration.baseObjectForDN(dn); baseErr != nil {
		return directory.Entry{}, baseErr
	} else if found {
		if required, specified := reader.searchRequiresHasSubordinates(); specified && required {
			return reader.withHasSubordinates(queryer, entry)
		}
		return entry, nil
	}
	id, err := reader.entryIDWithQueryer(queryer, dn)
	if err != nil {
		return directory.Entry{}, err
	}
	entry, err = reader.loadEntry(queryer, id)
	if err != nil {
		return directory.Entry{}, err
	}
	if required, specified := reader.searchRequiresHasSubordinates(); specified && required {
		return reader.withHasSubordinates(queryer, entry)
	}
	return entry, nil
}

func (reader *sqlBackendReader) ForEach(
	visit func(directory.Entry) error,
) (err error) {
	defer func() { err = sqlBackendLDAPError(err) }()
	if reader.initializationErr != nil {
		return reader.initializationErr
	}
	database, err := reader.configuration.database(reader.ctx)
	if err != nil {
		return err
	}
	queryer := reader.queryer
	if queryer == nil {
		queryer = database
	}
	ids, planned, err := reader.sqlBackendFilterCandidates(queryer)
	if err != nil {
		return err
	}
	scopeIDs, scopePlanned, err := reader.sqlBackendScopeCandidates(queryer)
	if err != nil {
		return err
	}
	switch {
	case planned && scopePlanned:
		ids = intersectSQLBackendEntryIDs(ids, scopeIDs)
	case scopePlanned:
		ids = scopeIDs
	case !planned:
		ids, err = reader.scanSQLBackendEntryIDs(queryer)
		if err != nil {
			return err
		}
	}
	includeHasSubordinates, _ := reader.searchRequiresHasSubordinates()
	baseDN := directory.DN{}
	hasBaseObject := false
	if baseEntry := reader.configuration.baseObjectClone(); baseEntry != nil {
		baseDN, err = directory.ParseDN(baseEntry.DN)
		if err == nil {
			baseDN, err = reader.NormalizeDNIdentity(baseDN)
		}
		if err != nil {
			return fmt.Errorf("SQL-backend baseObject DN: %w", err)
		}
		hasBaseObject = true
		entry := *baseEntry
		if includeHasSubordinates {
			entry, err = reader.withHasSubordinates(queryer, entry)
			if err != nil {
				return err
			}
		}
		if err := visit(entry); err != nil {
			return &sqlBackendVisitorError{err: err}
		}
	}
	for _, id := range ids {
		if hasBaseObject {
			candidate, parseErr := directory.ParseDN(id.dn)
			if parseErr != nil {
				return fmt.Errorf("SQL-backend entry %d DN: %w", id.id, parseErr)
			}
			candidate, parseErr = reader.configuration.mapSQLDNToLDAP(candidate)
			if parseErr != nil {
				return fmt.Errorf("SQL-backend entry %d DN: %w", id.id, parseErr)
			}
			if candidate.Equal(baseDN) {
				continue
			}
		}
		entry, err := reader.loadEntryForRead(queryer, id)
		if err != nil {
			return err
		}
		if includeHasSubordinates {
			entry, err = reader.withHasSubordinates(queryer, entry)
			if err != nil {
				return err
			}
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
	queryer sqlBackendQueryer,
	id sqlEntryID,
) (directory.Entry, error) {
	return reader.loadEntryWithSelection(queryer, id, nil)
}

func (reader *sqlBackendReader) loadEntryForRead(
	queryer sqlBackendQueryer,
	id sqlEntryID,
) (directory.Entry, error) {
	selection, specified, err := reader.sqlBackendAttributeSelection()
	if err != nil {
		return directory.Entry{}, err
	}
	if !specified {
		selection = nil
	}
	return reader.loadEntryWithSelection(queryer, id, selection)
}

func (reader *sqlBackendReader) loadEntryWithSelection(
	queryer sqlBackendQueryer,
	id sqlEntryID,
	selection *sqlBackendAttributeSelection,
) (directory.Entry, error) {
	objectClass := reader.configuration.objectClasses[id.objectClassID]
	if objectClass == nil {
		return directory.Entry{}, fmt.Errorf(
			"SQL-backend entry %d references unknown objectClass mapping %d",
			id.id, id.objectClassID,
		)
	}
	normalizedDN, err := directory.ParseDN(id.dn)
	if err != nil {
		return directory.Entry{}, fmt.Errorf("SQL-backend entry %d DN: %w", id.id, err)
	}
	normalizedDN, err = reader.configuration.mapSQLDNToLDAP(normalizedDN)
	if err != nil {
		return directory.Entry{}, fmt.Errorf("SQL-backend entry %d DN: %w", id.id, err)
	}
	entry := directory.Entry{DN: normalizedDN.String()}
	appendSQLAttributeValue(&entry, "objectClass", []byte(objectClass.name))
	auxiliaryRows, err := queryer.QueryContext(
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
			if selection != nil && !selection.includes(
				reader.configuration.registry,
				mapping.name,
			) {
				continue
			}
			values, err := reader.readAttributeValues(queryer, id.keyValue, mapping)
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
	structuralObjectClass := objectClass.name
	if reader.configuration.checkSchema {
		structural, err := reader.configuration.registry.StructuralObjectClass(entry)
		if err != nil {
			return directory.Entry{}, operationFailureFromSchema(err)
		}
		if !reader.configuration.registry.EntryHasObjectClass(
			directory.Entry{Attributes: []directory.Attribute{{
				Description: "objectClass",
				Values:      stringValues(structural),
			}}},
			objectClass.name,
		) {
			return directory.Entry{}, operationFailed(
				ldapwire.ResultObjectClassViolation,
				fmt.Sprintf(
					"SQL-backend structural objectClass %q does not match mapping %q",
					structural,
					objectClass.name,
				),
			)
		}
		structuralObjectClass = structural
	}
	appendSQLAttributeValue(&entry, "structuralObjectClass", []byte(structuralObjectClass))
	appendSQLAttributeValue(&entry, "entryUUID", []byte(sqlEntryUUID(id.objectClassID, id.keyValue)))
	return entry, nil
}

func (reader *sqlBackendReader) searchRequiresHasSubordinates() (bool, bool) {
	requirements, specified := reader.sqlBackendSearchRequirements()
	return requirements.hasSubordinates, specified
}

func (reader *sqlBackendReader) withHasSubordinates(
	queryer sqlBackendQueryer,
	entry directory.Entry,
) (directory.Entry, error) {
	if entry.HasAttribute("hasSubordinates") {
		return entry, nil
	}
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return directory.Entry{}, fmt.Errorf("SQL-backend entry DN %q: %w", entry.DN, err)
	}
	dn, err = reader.NormalizeDNIdentity(dn)
	if err != nil {
		return directory.Entry{}, fmt.Errorf("SQL-backend entry DN %q: %w", entry.DN, err)
	}
	hasChildren, err := reader.hasChildrenWithQueryer(queryer, dn)
	if err != nil {
		return directory.Entry{}, err
	}
	if hasChildren {
		appendSQLAttributeValue(&entry, "hasSubordinates", []byte("TRUE"))
	} else {
		appendSQLAttributeValue(&entry, "hasSubordinates", []byte("FALSE"))
	}
	return entry, nil
}

func (reader *sqlBackendReader) sqlBackendHasChildren(
	dn directory.DN,
) (hasChildren bool, err error) {
	defer func() { err = sqlBackendLDAPError(err) }()
	if reader.initializationErr != nil {
		return false, reader.initializationErr
	}
	database, err := reader.configuration.database(reader.ctx)
	if err != nil {
		return false, err
	}
	queryer := reader.queryer
	if queryer == nil {
		queryer = database
	}
	return reader.hasChildrenWithQueryer(queryer, dn)
}

func (reader *sqlBackendReader) hasChildrenWithQueryer(
	queryer sqlBackendQueryer,
	dn directory.DN,
) (bool, error) {
	normalized, parameter, err := reader.normalizedSQLDN(dn)
	if err != nil {
		return false, fmt.Errorf("normalize SQL-backend DN %q: %w", dn.String(), err)
	}
	if len(parameter) > 255 {
		return false, fmt.Errorf("SQL-backend DN exceeds 255 bytes")
	}
	if reader.configuration.baseObjectMatches(normalized) {
		var childCount int64
		if err := queryer.QueryRowContext(
			reader.ctx,
			"SELECT COUNT(*) FROM ldap_entries WHERE parent=?",
			"baseObject",
		).Scan(&childCount); err != nil {
			return false, fmt.Errorf(
				"SQL-backend baseObject subordinate count for %s: %w",
				normalized.String(),
				err,
			)
		}
		return childCount > 0, nil
	}
	query := reader.configuration.hasChildrenQuery
	if query == "" {
		return false, errors.New("SQL-backend subordinate query is not configured")
	}
	var childCount int64
	if err := queryer.QueryRowContext(reader.ctx, query, parameter).Scan(&childCount); err != nil {
		return false, fmt.Errorf(
			"SQL-backend subordinate count for %s: %w",
			normalized.String(),
			err,
		)
	}
	return childCount > 0, nil
}

func (reader *sqlBackendReader) readAttributeValues(
	queryer sqlBackendQueryer,
	keyValue int64,
	mapping sqlAttributeMapping,
) ([][]byte, error) {
	rows, err := queryer.QueryContext(reader.ctx, mapping.query, keyValue)
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

func (reader *sqlBackendReader) entryID(dn directory.DN) (sqlEntryID, error) {
	if reader.initializationErr != nil {
		return sqlEntryID{}, reader.initializationErr
	}
	database, err := reader.configuration.database(reader.ctx)
	if err != nil {
		return sqlEntryID{}, err
	}
	queryer := reader.queryer
	if queryer == nil {
		queryer = database
	}
	return reader.entryIDWithQueryer(queryer, dn)
}

func (reader *sqlBackendReader) entryIDWithQueryer(
	queryer sqlBackendQueryer,
	dn directory.DN,
) (sqlEntryID, error) {
	normalized, parameter, err := reader.normalizedSQLDN(dn)
	if err != nil {
		return sqlEntryID{}, fmt.Errorf("normalize SQL-backend DN %q: %w", dn.String(), err)
	}
	if reader.configuration.hasReversedDN {
		parameter = reverseUpperASCII(parameter)
	}
	var id sqlEntryID
	err = queryer.QueryRowContext(
		reader.ctx,
		reader.configuration.idQuery,
		parameter,
	).Scan(&id.id, &id.keyValue, &id.objectClassID, &id.dn)
	if errors.Is(err, sql.ErrNoRows) {
		return sqlEntryID{}, storage.ErrEntryNotFound
	}
	if err != nil {
		return sqlEntryID{}, fmt.Errorf("SQL-backend entry ID query: %w", err)
	}
	storedDN, err := directory.ParseDN(id.dn)
	if err != nil {
		return sqlEntryID{}, fmt.Errorf("SQL-backend entry %d DN: %w", id.id, err)
	}
	storedDN, err = reader.configuration.mapSQLDNToLDAP(storedDN)
	if err != nil {
		return sqlEntryID{}, fmt.Errorf("SQL-backend entry %d DN: %w", id.id, err)
	}
	if !storedDN.Equal(normalized) {
		return sqlEntryID{}, storage.ErrEntryNotFound
	}
	return id, nil
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
	reader            *sqlBackendReader
	tx                *sql.Tx
	conn              *sql.Conn
	executor          sqlBackendExecutor
	initializationErr error
	rename            *sqlBackendRenameContext
	modify            *sqlBackendModifyContext
	pendingRename     *sqlBackendPendingRename
}

type sqlBackendPendingRename struct {
	id    sqlEntryID
	entry directory.Entry
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

func (writer *sqlBackendWriter) sqlBackendHasChildren(
	dn directory.DN,
) (hasChildren bool, err error) {
	defer func() { err = sqlBackendLDAPError(err) }()
	return writer.reader.sqlBackendHasChildren(dn)
}

func (reader *rwmStorageReader) sqlBackendHasChildren(
	dn directory.DN,
) (bool, error) {
	remote, err := reader.configuration.mapDNToRemote(dn)
	if err != nil {
		return false, err
	}
	backend, ok := reader.Reader.(interface {
		sqlBackendHasChildren(directory.DN) (bool, error)
	})
	if !ok {
		return false, errors.New("SQL-backend subordinate query is unavailable")
	}
	return backend.sqlBackendHasChildren(remote)
}

func storageSQLBackendHasChildren(
	reader storage.Reader,
	dn directory.DN,
) (bool, error) {
	backend, ok := reader.(interface {
		sqlBackendHasChildren(directory.DN) (bool, error)
	})
	if !ok {
		return false, errors.New("SQL-backend subordinate query is unavailable")
	}
	return backend.sqlBackendHasChildren(dn)
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
