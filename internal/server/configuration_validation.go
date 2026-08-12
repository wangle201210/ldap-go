package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

// ConfigurationSummary describes the persisted runtime configuration that was
// parsed and cross-validated by ValidateConfiguration.
type ConfigurationSummary struct {
	AttributeTypes    int
	ObjectClasses     int
	DITContentRules   int
	ACLRules          int
	Databases         int
	Overlays          int
	SASLAuthzRules    int
	SyncreplConsumers int
}

// ValidateConfiguration performs the read-only portion of Server startup. It
// loads custom schema and validates ACL, database, overlay, SASL, server ID,
// and syncrepl configuration without partitioning entries or creating runtime
// containers.
func ValidateConfiguration(
	ctx context.Context,
	config Config,
) (ConfigurationSummary, error) {
	if ctx == nil {
		return ConfigurationSummary{}, errors.New("validation context is required")
	}
	if config.Store == nil {
		return ConfigurationSummary{}, errors.New("store is required")
	}
	var summary ConfigurationSummary
	err := config.Store.View(ctx, func(reader storage.Reader) error {
		var err error
		summary, err = ValidateConfigurationReader(ctx, config, reader)
		return err
	})
	if err != nil {
		return ConfigurationSummary{}, fmt.Errorf(
			"validate runtime configuration: %w",
			err,
		)
	}
	return summary, nil
}

// ValidateConfigurationReader validates a configuration already visible in a
// caller-owned transaction. It allows offline import to reject invalid
// cn=config data before committing it.
func ValidateConfigurationReader(
	ctx context.Context,
	config Config,
	reader storage.Reader,
) (ConfigurationSummary, error) {
	if ctx == nil {
		return ConfigurationSummary{}, errors.New("validation context is required")
	}
	if reader == nil {
		return ConfigurationSummary{}, errors.New("configuration reader is required")
	}
	if err := ctx.Err(); err != nil {
		return ConfigurationSummary{}, err
	}
	if config.RootDN != "" && len(config.RootPassword) == 0 {
		return ConfigurationSummary{}, errors.New(
			"root password is required when root DN is configured",
		)
	}

	baseSchema := config.Schema
	if baseSchema == nil {
		var err error
		baseSchema, err = schema.NewBuiltinRegistry()
		if err != nil {
			return ConfigurationSummary{}, fmt.Errorf(
				"initialize built-in schema: %w",
				err,
			)
		}
	}
	validator := &Server{
		config:      config,
		baseSchema:  baseSchema.Clone(),
		sqlBackends: make(map[*sqlBackendRuntimeConfiguration]struct{}),
	}
	defer func() {
		validator.sqlBackendsMu.Lock()
		configurations := make([]*sqlBackendRuntimeConfiguration, 0, len(validator.sqlBackends))
		for configuration := range validator.sqlBackends {
			configurations = append(configurations, configuration)
		}
		validator.sqlBackendsMu.Unlock()
		for _, configuration := range configurations {
			_ = configuration.close()
		}
	}()

	listenerURLs, err := configurationValidationListenerURLs(
		reader,
		config.ListenerURLs,
	)
	if err != nil {
		return ConfigurationSummary{}, err
	}
	validator.config.ListenerURLs = listenerURLs
	runtime, err := validator.buildRuntimeState(reader)
	if err != nil {
		return ConfigurationSummary{}, err
	}
	if err := validator.validateSQLBackends(ctx, runtime); err != nil {
		return ConfigurationSummary{}, err
	}
	var aclResult acl.LoadResult
	if config.AccessPolicy == nil {
		_, aclResult, err = acl.LoadOpenLDAPConfigReader(reader)
		if err != nil {
			return ConfigurationSummary{}, err
		}
	}
	return summarizeConfiguration(runtime, aclResult.Rules), nil
}

func configurationValidationListenerURLs(
	reader storage.Reader,
	configured []string,
) ([]string, error) {
	if len(configured) > 0 {
		return append([]string(nil), configured...), nil
	}
	entry, err := reader.Get(configurationSuffix)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load global configuration: %w", err)
	}
	for _, rawValue := range entry.Values("olcServerID") {
		value, err := parseServerIDValue(string(rawValue))
		if err != nil {
			return nil, fmt.Errorf("%s olcServerID: %w", entry.DN, err)
		}
		if value.uri != "" {
			return []string{value.uri}, nil
		}
	}
	return nil, nil
}

func summarizeConfiguration(
	runtime *runtimeState,
	aclRules int,
) ConfigurationSummary {
	summary := ConfigurationSummary{
		AttributeTypes:  len(runtime.schema.AttributeTypeDescriptions()),
		ObjectClasses:   len(runtime.schema.ObjectClassDescriptions()),
		DITContentRules: len(runtime.schema.DITContentRuleDescriptions()),
		ACLRules:        aclRules,
		Databases:       len(runtime.databases),
		SASLAuthzRules:  len(runtime.sasl.authzRegexps),
	}
	for _, database := range runtime.databases {
		summary.Overlays += runtimeDatabaseOverlayCount(database)
		summary.SyncreplConsumers += len(database.syncConsumers)
	}
	return summary
}

func runtimeDatabaseOverlayCount(database runtimeDatabase) int {
	count := len(database.retcodes) + len(database.memberOf) + len(database.refint) +
		len(database.nestGroups) + len(database.totpPasswords)
	for _, configured := range []bool{
		database.rwm != nil,
		database.serverSideSort,
		database.syncProvider,
		database.dds != nil,
		database.ppolicy != nil,
		database.pbind != nil,
		database.remoteAuth != nil,
		database.chain != nil,
		database.translucent != nil,
		database.pcache != nil,
		database.otp != nil,
		database.autoca != nil,
		database.constraint != nil,
		database.collect != nil,
		database.seqmod != nil,
		database.dynlist != nil,
		database.dyngroup != nil,
		database.unique != nil,
		database.valueSort != nil,
		database.accesslog != nil,
		database.auditlog != nil,
	} {
		if configured {
			count++
		}
	}
	return count
}
