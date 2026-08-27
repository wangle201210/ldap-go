package server

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var configurationSuffix = staticRuntimeDN("cn=config")

const (
	defaultConnectionMaxPending     = 100
	defaultConnectionMaxPendingAuth = 1000
)

type runtimeState struct {
	revision            uint64
	schema              *schema.Registry
	access              *acl.Policy
	secureTransport     SecureTransport
	databases           []runtimeDatabase
	serverID            uint16
	allows              allowsRuntimeConfiguration
	disallows           disallowsRuntimeConfiguration
	defaultSearchBase   defaultSearchBaseConfiguration
	defaultReferrals    []string
	passwordHashSchemes []string
	passwordCryptSalt   string
	externalPasswords   externalPasswordRuntimeConfiguration
	sasl                saslRuntimeConfiguration
	connectionPending   connectionPendingRuntimeConfiguration
	incomingLimits      incomingLimits
	security            securityStrengthRequirements
	requires            operationRequirements
	idleTimeout         time.Duration
	writeTimeout        time.Duration
	syncContexts        map[string]syncCSNState
}

type connectionPendingRuntimeConfiguration struct {
	maxPending     int
	maxPendingAuth int
}

type allowsRuntimeConfiguration struct {
	bindV2                   bool
	bindAnonymousCredentials bool
	bindAnonymousDN          bool
	anonymousUpdates         bool
	anonymousProxyAuthz      bool
}

type disallowsRuntimeConfiguration struct {
	anonymousBind                 bool
	simpleBind                    bool
	tlsToAnonymous                bool
	tlsAuthenticated              bool
	noncriticalProxyAuthorization bool
	noncriticalDontUseCopy        bool
}

func (server *Server) buildRuntimeState(reader storage.Reader) (*runtimeState, error) {
	registry := server.baseSchema.Clone()
	if _, err := schema.LoadOpenLDAPConfigReader(reader, registry); err != nil {
		return nil, fmt.Errorf("load OpenLDAP schema configuration: %w", err)
	}
	if err := validateOpenLDAPModuleConfiguration(reader); err != nil {
		return nil, fmt.Errorf("validate OpenLDAP module configuration: %w", err)
	}
	secureTransport, err := server.loadGlobalTLSConfiguration(reader)
	if err != nil {
		return nil, fmt.Errorf("load global TLS configuration: %w", err)
	}

	access := server.config.AccessPolicy
	if access == nil {
		var err error
		access, _, err = acl.LoadOpenLDAPConfigReader(reader)
		if err != nil {
			return nil, err
		}
	}
	if err := access.Validate(registry); err != nil {
		return nil, fmt.Errorf("validate OpenLDAP ACL configuration: %w", err)
	}

	databases, err := loadRuntimeDatabasesReaderWithNormalizer(reader, registry)
	if err != nil {
		return nil, err
	}
	security, requires, err := loadFrontendSecurityConfiguration(reader, databases)
	if err != nil {
		return nil, err
	}
	for index := range databases {
		if databaseUsesLocalContentStorage(databases[index]) {
			databases[index].dnNormalizer = registry
		}
		if databases[index].sqlBackend != nil {
			databases[index].sqlBackend.setRuntime(registry, server.config.SQLDriver, server)
		}
		if databases[index].rwm != nil {
			databases[index].rwm.schema = registry
		}
		if databases[index].metaBackend != nil {
			for targetIndex := range databases[index].metaBackend.targets {
				target := &databases[index].metaBackend.targets[targetIndex]
				if target.rwm != nil {
					target.rwm.schema = registry
				}
			}
		}
		if databases[index].dnssrvBackend != nil {
			databases[index].dnssrvBackend.resolver = server.config.DNSSRVResolver
			databases[index].dnssrvBackend.now = server.clock
		}
		if err := validateCollectSchema(
			registry,
			databases[index].collect,
		); err != nil {
			return nil, fmt.Errorf(
				"%s collect overlay: %w",
				databases[index].name,
				err,
			)
		}
		if err := validateNestGroupSchema(
			registry,
			databases[index].nestGroups,
		); err != nil {
			return nil, fmt.Errorf(
				"%s nestgroup overlay: %w",
				databases[index].name,
				err,
			)
		}
		if err := validateAccesslogSchema(
			registry,
			databases[index].accesslog,
		); err != nil {
			return nil, fmt.Errorf(
				"%s accesslog overlay: %w",
				databases[index].name,
				err,
			)
		}
		if err := validateConstraintSchema(
			registry,
			databases[index].constraint,
		); err != nil {
			return nil, fmt.Errorf(
				"%s constraint overlay: %w",
				databases[index].name,
				err,
			)
		}
		if err := validateDynlistSchema(
			registry,
			databases[index].dynlist,
		); err != nil {
			return nil, fmt.Errorf(
				"%s dynlist overlay: %w",
				databases[index].name,
				err,
			)
		}
		if err := validateDynamicGroupSchema(
			registry,
			databases[index].dyngroup,
		); err != nil {
			return nil, fmt.Errorf(
				"%s dyngroup overlay: %w",
				databases[index].name,
				err,
			)
		}
		if err := validateUniqueSchema(
			registry,
			databases[index].unique,
		); err != nil {
			return nil, fmt.Errorf(
				"%s unique overlay: %w",
				databases[index].name,
				err,
			)
		}
		if err := validateValueSortSchema(
			registry,
			databases[index].valueSort,
		); err != nil {
			return nil, fmt.Errorf(
				"%s valsort overlay: %w",
				databases[index].name,
				err,
			)
		}
		if err := validateRemoteAuthSchema(
			registry,
			databases[index].remoteAuth,
		); err != nil {
			return nil, fmt.Errorf(
				"%s remoteauth overlay: %w",
				databases[index].name,
				err,
			)
		}
		if err := validateHomedirSchema(
			registry,
			databases[index].homedir,
		); err != nil {
			return nil, fmt.Errorf(
				"%s homedir overlay: %w",
				databases[index].name,
				err,
			)
		}
		if err := validateAutoCASchema(
			registry,
			databases[index].autoca,
		); err != nil {
			return nil, fmt.Errorf(
				"%s autoca overlay: %w",
				databases[index].name,
				err,
			)
		}
		if err := validateMemberOfSchema(
			registry,
			databases[index].memberOf,
		); err != nil {
			return nil, fmt.Errorf(
				"%s memberof overlay: %w",
				databases[index].name,
				err,
			)
		}
		if err := validateRefintSchema(
			registry,
			databases[index].refint,
		); err != nil {
			return nil, fmt.Errorf(
				"%s refint overlay: %w",
				databases[index].name,
				err,
			)
		}
	}
	serverID, err := loadServerID(reader, server.config.ListenerURLs)
	if err != nil {
		return nil, err
	}
	for _, database := range databases {
		if database.multiProvider && serverID == 0 {
			return nil, fmt.Errorf(
				"%s olcMultiProvider requires a non-zero olcServerID",
				database.name,
			)
		}
	}
	allows, err := loadAllowsRuntimeConfiguration(reader)
	if err != nil {
		return nil, err
	}
	disallows, err := loadDisallowsRuntimeConfiguration(reader)
	if err != nil {
		return nil, err
	}
	defaultSearchBase, err := loadDefaultSearchBaseWithNormalizer(reader, registry)
	if err != nil {
		return nil, err
	}
	defaultReferrals, err := loadDefaultReferralConfiguration(reader)
	if err != nil {
		return nil, err
	}
	passwordHashSchemes, err := loadPasswordHashSchemes(reader)
	if err != nil {
		return nil, err
	}
	passwordCryptSalt, err := loadPasswordCryptSaltFormat(reader)
	if err != nil {
		return nil, err
	}
	externalPasswords, err := loadExternalPasswordRuntimeConfiguration(
		reader,
		server.config,
	)
	if err != nil {
		return nil, err
	}
	sasl, err := loadSASLRuntimeConfiguration(reader)
	if err != nil {
		return nil, err
	}
	connectionPending, err := loadConnectionPendingRuntimeConfiguration(reader)
	if err != nil {
		return nil, err
	}
	incomingLimits, err := loadIncomingLimitRuntimeConfiguration(reader)
	if err != nil {
		return nil, err
	}
	idleTimeout, writeTimeout, err := loadConnectionTimeoutRuntimeConfiguration(reader)
	if err != nil {
		return nil, err
	}
	if server.config.RootDN != "" {
		if err := applyBootstrapRoot(
			databases,
			server.config.RootDN,
			server.config.RootPassword,
			registry,
		); err != nil {
			return nil, err
		}
	}
	runtime := &runtimeState{
		schema:              registry,
		access:              access,
		secureTransport:     secureTransport,
		databases:           databases,
		serverID:            serverID,
		allows:              allows,
		disallows:           disallows,
		defaultSearchBase:   defaultSearchBase,
		defaultReferrals:    defaultReferrals,
		passwordHashSchemes: passwordHashSchemes,
		passwordCryptSalt:   passwordCryptSalt,
		externalPasswords:   externalPasswords,
		sasl:                sasl,
		connectionPending:   connectionPending,
		incomingLimits:      incomingLimits,
		security:            security,
		requires:            requires,
		idleTimeout:         idleTimeout,
		writeTimeout:        writeTimeout,
	}
	if err := loadAutoCAAuthorities(reader, runtime); err != nil {
		return nil, err
	}
	if err := server.configureAutoCALocalTLS(reader, runtime, true); err != nil {
		return nil, fmt.Errorf("load AutoCA local TLS configuration: %w", err)
	}
	if err := server.preparePcachePersistence(reader, runtime); err != nil {
		return nil, err
	}
	return runtime, nil
}

func loadConnectionPendingRuntimeConfiguration(
	reader storage.Reader,
) (connectionPendingRuntimeConfiguration, error) {
	configuration := connectionPendingRuntimeConfiguration{
		maxPending:     defaultConnectionMaxPending,
		maxPendingAuth: defaultConnectionMaxPendingAuth,
	}
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return configuration, nil
	}
	if err != nil {
		return connectionPendingRuntimeConfiguration{}, fmt.Errorf(
			"load global connection pending configuration: %w",
			err,
		)
	}

	for _, attribute := range []struct {
		description string
		target      *int
	}{
		{"olcConnMaxPending", &configuration.maxPending},
		{"olcConnMaxPendingAuth", &configuration.maxPendingAuth},
	} {
		values := entry.Values(attribute.description)
		if len(values) == 0 {
			continue
		}
		if len(values) != 1 {
			return connectionPendingRuntimeConfiguration{}, fmt.Errorf(
				"%s must contain exactly one value",
				attribute.description,
			)
		}
		value, err := strconv.ParseInt(
			strings.TrimLeft(string(values[0]), " \t\n\v\f\r"),
			0,
			32,
		)
		if err != nil {
			return connectionPendingRuntimeConfiguration{}, fmt.Errorf(
				"%s must be a 32-bit integer: %w",
				attribute.description,
				err,
			)
		}
		*attribute.target = int(value)
	}
	return configuration, nil
}

func loadPasswordCryptSaltFormat(reader storage.Reader) (string, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return auth.DefaultOpenLDAPCryptSaltFormat, nil
	}
	if err != nil {
		return "", fmt.Errorf("load global crypt salt configuration: %w", err)
	}
	values := entry.Values("olcPasswordCryptSaltFormat")
	if len(values) == 0 {
		return auth.DefaultOpenLDAPCryptSaltFormat, nil
	}
	if len(values) != 1 {
		return "", errors.New("olcPasswordCryptSaltFormat must contain exactly one value")
	}
	format := string(values[0])
	if err := auth.ValidateOpenLDAPCryptSaltFormat(format); err != nil {
		return "", fmt.Errorf("olcPasswordCryptSaltFormat: %w", err)
	}
	return format, nil
}

func hashPasswordForRuntime(
	runtime *runtimeState,
	password []byte,
	scheme string,
) ([]byte, error) {
	saltFormat := auth.DefaultOpenLDAPCryptSaltFormat
	if runtime != nil && runtime.passwordCryptSalt != "" {
		saltFormat = runtime.passwordCryptSalt
	}
	return auth.HashPasswordWithCryptSaltFormat(password, scheme, saltFormat, nil)
}

func loadPasswordHashSchemes(reader storage.Reader) ([]string, error) {
	var globalValues [][]byte
	global, err := reader.Get(configurationSuffix)
	switch {
	case err == nil:
		globalValues = global.Values("olcPasswordHash")
	case errors.Is(err, storage.ErrEntryNotFound):
	default:
		return nil, fmt.Errorf("load global password hash configuration: %w", err)
	}

	var frontendValues [][]byte
	frontendFound := false
	err = reader.ForEach(func(entry directory.Entry) error {
		entryDN, err := directory.ParseDN(entry.DN)
		if err != nil {
			return fmt.Errorf("parse entry DN %q: %w", entry.DN, err)
		}
		if !configurationSuffix.Equal(entryDN) &&
			!configurationSuffix.AncestorOf(entryDN) {
			return nil
		}
		databaseValues := entry.Values("olcDatabase")
		if len(databaseValues) != 1 ||
			databaseType(string(databaseValues[0])) != "frontend" {
			return nil
		}
		if frontendFound {
			return fmt.Errorf("multiple frontend database entries configure password hashes")
		}
		frontendFound = true
		frontendValues = entry.Values("olcPasswordHash")
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("load frontend password hash configuration: %w", err)
	}

	values := globalValues
	if len(frontendValues) > 0 {
		values = frontendValues
	}
	if len(values) == 0 {
		return []string{auth.OpenLDAPDefaultHashScheme}, nil
	}

	var schemes []string
	for _, rawValue := range values {
		fields := strings.Fields(string(rawValue))
		if len(fields) == 0 {
			return nil, errors.New("olcPasswordHash contains an empty value")
		}
		for _, field := range fields {
			scheme, err := auth.NormalizePasswordHashScheme(field)
			if err != nil {
				return nil, fmt.Errorf("olcPasswordHash: %w", err)
			}
			schemes = append(schemes, scheme)
		}
	}
	return schemes, nil
}

func loadAllowsRuntimeConfiguration(
	reader storage.Reader,
) (allowsRuntimeConfiguration, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return allowsRuntimeConfiguration{}, nil
	}
	if err != nil {
		return allowsRuntimeConfiguration{}, fmt.Errorf(
			"load global configuration: %w",
			err,
		)
	}

	var configuration allowsRuntimeConfiguration
	for _, rawValue := range entry.Values("olcAllows") {
		for _, feature := range strings.Fields(string(rawValue)) {
			switch strings.ToLower(feature) {
			case "bind_v2":
				configuration.bindV2 = true
			case "bind_anon_cred":
				configuration.bindAnonymousCredentials = true
			case "bind_anon_dn":
				configuration.bindAnonymousDN = true
			case "update_anon":
				configuration.anonymousUpdates = true
			case "proxy_authz_anon":
				configuration.anonymousProxyAuthz = true
			default:
				return allowsRuntimeConfiguration{}, fmt.Errorf(
					"%s olcAllows has unknown feature %q",
					entry.DN,
					feature,
				)
			}
		}
	}
	return configuration, nil
}

func loadDisallowsRuntimeConfiguration(
	reader storage.Reader,
) (disallowsRuntimeConfiguration, error) {
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return disallowsRuntimeConfiguration{}, nil
	}
	if err != nil {
		return disallowsRuntimeConfiguration{}, fmt.Errorf(
			"load global configuration: %w",
			err,
		)
	}

	var configuration disallowsRuntimeConfiguration
	for _, rawValue := range entry.Values("olcDisallows") {
		for _, feature := range strings.Fields(string(rawValue)) {
			switch strings.ToLower(feature) {
			case "bind_anon":
				configuration.anonymousBind = true
			case "bind_simple":
				configuration.simpleBind = true
			case "tls_2_anon":
				configuration.tlsToAnonymous = true
			case "tls_authc":
				configuration.tlsAuthenticated = true
			case "proxy_authz_non_critical":
				configuration.noncriticalProxyAuthorization = true
			case "dontusecopy_non_critical":
				configuration.noncriticalDontUseCopy = true
			default:
				return disallowsRuntimeConfiguration{}, fmt.Errorf(
					"%s olcDisallows has unknown feature %q",
					entry.DN,
					feature,
				)
			}
		}
	}
	return configuration, nil
}

func updateOperationPrecondition(
	runtime *runtimeState,
	boundDN string,
	target directory.DN,
) *ldapwire.Result {
	if boundDN == "" && !runtime.allows.anonymousUpdates {
		result := ldapwire.ResultError(
			ldapwire.ResultStrongerAuthRequired,
			"modifications require authentication",
		)
		return &result
	}
	if database := databaseForDN(runtime, target); database != nil && isMonitorDatabase(*database) {
		result := ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"monitor database is read-only",
		)
		return &result
	}
	if database := databaseForDN(runtime, target); database != nil && database.readOnly {
		result := ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"operation restricted",
		)
		return &result
	}
	if database := databaseForDN(runtime, target); database != nil && database.shadow {
		if database.updateDN != nil && boundDN != "" {
			bound, err := directory.ParseDN(boundDN)
			if err == nil && databaseDNEqual(*database, *database.updateDN, bound) {
				return nil
			}
		}
		result := shadowUpdateResult(runtime, *database, target)
		return &result
	}
	return nil
}

func databaseRestrictionResult(
	runtime *runtimeState,
	target directory.DN,
	operation databaseRestrictions,
) *ldapwire.Result {
	database := databaseForDN(runtime, target)
	if database == nil || !databaseRestricts(*database, operation) {
		return nil
	}
	result := ldapwire.ResultError(
		ldapwire.ResultUnwillingToPerform,
		"operation restricted",
	)
	return &result
}

func requestDatabaseRestriction(request ldapwire.Request) databaseRestrictions {
	switch value := request.(type) {
	case ldapwire.BindRequest:
		return restrictBind
	case ldapwire.SearchRequest:
		return restrictSearch
	case ldapwire.AddRequest:
		return restrictAdd
	case ldapwire.ModifyRequest:
		return restrictModify
	case ldapwire.DeleteRequest:
		return restrictDelete
	case ldapwire.ModifyDNRequest:
		return restrictRename
	case ldapwire.CompareRequest:
		return restrictCompare
	case ldapwire.ExtendedRequest:
		switch value.Name {
		case startTLSOID:
			return restrictStartTLS
		case passwordModifyOID:
			return restrictPasswordModify
		case whoAmIOID:
			return restrictWhoAmI
		case cancelOID:
			return restrictCancel
		default:
			return restrictExtended
		}
	default:
		return 0
	}
}

func lastModEnabled(runtime *runtimeState, target directory.DN) bool {
	database := databaseForDN(runtime, target)
	return database == nil || database.lastMod
}

func (server *Server) validateRuntimeConfiguration(
	writer storage.Writer,
) (runtime *runtimeState, returnErr error) {
	runtime, err := server.buildRuntimeState(writer)
	if err != nil {
		if result, ok := collectConfigurationResult(err); ok {
			return nil, &operationFailure{result: result}
		}
		if result, ok := nestGroupConfigurationResult(err); ok {
			return nil, &operationFailure{result: result}
		}
		if result, ok := seqmodConfigurationResult(err); ok {
			return nil, &operationFailure{result: result}
		}
		if result, ok := securityConfigurationResult(err); ok {
			return nil, &operationFailure{result: result}
		}
		return nil, operationFailed(
			ldapwire.ResultConstraintViolation,
			"invalid cn=config: "+err.Error(),
		)
	}
	previous := server.runtime.Load()
	ctx := context.Background()
	if provider, ok := writer.(interface {
		StorageContext() context.Context
	}); ok && provider.StorageContext() != nil {
		ctx = provider.StorageContext()
	}
	coordinator := sqlBackendTransactionCoordinatorFromContext(ctx)
	cleanupCandidate := func() {
		server.closeCandidateSQLBackends(runtime, previous)
	}
	defer func() {
		if returnErr != nil {
			if coordinator != nil {
				coordinator.deferCleanup(cleanupCandidate)
			} else {
				cleanupCandidate()
			}
		}
	}()
	applyMetaBackendOnlineConfigurationState(previous, runtime)
	reuseSQLBackendOnlineConfigurationState(previous, runtime)
	if err := server.validateSQLBackends(ctx, runtime); err != nil {
		return nil, operationFailed(
			ldapwire.ResultConstraintViolation,
			"invalid SQL backend: "+err.Error(),
		)
	}
	reuseSeqmodCoordinators(previous, runtime)
	reusePcacheStates(previous, runtime)
	if err := server.ensurePcachePersistence(writer, runtime); err != nil {
		return nil, operationFailed(
			ldapwire.ResultConstraintViolation,
			"invalid pcache persistence: "+err.Error(),
		)
	}
	if err := server.ensureAutoCAAuthorities(writer, runtime); err != nil {
		return nil, operationFailed(
			ldapwire.ResultConstraintViolation,
			"invalid autoca state: "+err.Error(),
		)
	}
	if err := server.configureAutoCALocalTLS(writer, runtime, false); err != nil {
		return nil, operationFailed(
			ldapwire.ResultConstraintViolation,
			"invalid autoca local TLS state: "+err.Error(),
		)
	}
	if err := server.ensureAccesslogContainers(writer, runtime); err != nil {
		return nil, operationFailed(
			ldapwire.ResultConstraintViolation,
			"invalid accesslog state: "+err.Error(),
		)
	}
	if err := server.observeRuntimeCSNs(writer, runtime); err != nil {
		return nil, operationFailed(
			ldapwire.ResultConstraintViolation,
			"invalid sync provider state: "+err.Error(),
		)
	}
	runtime.revision = server.nextRuntimeRevision()
	if coordinator != nil {
		coordinator.setCandidateCleanup(cleanupCandidate)
	}
	return runtime, nil
}

func isConfigurationDN(dn directory.DN) bool {
	return configurationSuffix.Equal(dn) || configurationSuffix.AncestorOf(dn)
}

func staticRuntimeDN(value string) directory.DN {
	dn, err := directory.ParseDN(value)
	if err != nil {
		panic(err)
	}
	return dn
}
