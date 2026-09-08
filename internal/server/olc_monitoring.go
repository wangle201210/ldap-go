package server

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type monitoringConfigurationError struct {
	code ldapwire.ResultCode
	err  error
}

func (failure *monitoringConfigurationError) Error() string { return failure.err.Error() }

func monitoringConfigurationResult(err error) (ldapwire.Result, bool) {
	var failure *monitoringConfigurationError
	if !errors.As(err, &failure) {
		return ldapwire.Result{}, false
	}
	return ldapwire.ResultError(failure.code, err.Error()), true
}

func loadDatabaseMonitoring(entry directory.Entry, database *runtimeDatabase) error {
	if err := validateMonitoringValues(entry.Values("olcMonitoring")); err != nil {
		return err
	}
	value, present, err := singleBoolean(entry, "olcMonitoring")
	if err != nil {
		return err
	}
	database.monitoringConfigured = present
	database.monitoring = value
	if !present {
		// Only back-mdb enables monitoring in its database initializer.
		database.monitoring = databaseType(database.name) == "mdb"
	}
	return nil
}

func validateMonitoringValues(values [][]byte) error {
	for _, value := range values {
		if string(value) != "TRUE" && string(value) != "FALSE" {
			return &monitoringConfigurationError{
				code: ldapwire.ResultInvalidAttributeSyntax,
				err:  fmt.Errorf("olcMonitoring has invalid Boolean value %q", value),
			}
		}
	}
	return nil
}

func validateMonitoringConfigurationEntry(entry directory.Entry) error {
	if len(entry.Values("olcMonitoring")) == 0 {
		return nil
	}
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return err
	}
	parent, ok := dn.Parent()
	if !ok || !parent.Equal(configurationSuffix) || len(entry.Values("olcDatabase")) != 1 {
		return &monitoringConfigurationError{
			code: ldapwire.ResultObjectClassViolation,
			err:  fmt.Errorf("%s: olcMonitoring requires a database configuration entry", entry.DN),
		}
	}
	return nil
}

func applyMonitoringModification(entry *directory.Entry, change ldapwire.Modification, permissive bool) (bool, error) {
	if !strings.EqualFold(change.Attribute.Description, "olcMonitoring") {
		return false, nil
	}
	if err := validateMonitoringValues(change.Attribute.Values); err != nil {
		return true, operationFailed(ldapwire.ResultInvalidAttributeSyntax, err.Error())
	}
	if len(change.Attribute.Values) > 1 {
		return true, operationFailed(ldapwire.ResultConstraintViolation, "olcMonitoring must be single-valued")
	}
	// Minimal cn=config fixtures need not import the configuration schema.
	// Boolean values have already been validated, so byte equality is exact.
	if err := applyModificationWithPermissive(entry, change, permissive); err != nil {
		return true, err
	}
	if len(entry.Values("olcMonitoring")) > 1 {
		return true, operationFailed(ldapwire.ResultConstraintViolation, "olcMonitoring must be single-valued")
	}
	return true, nil
}

func applyMonitoringOnlineChanges(runtime *runtimeState, dn directory.DN, changes []ldapwire.Modification) {
	for index := range runtime.databases {
		database := &runtime.databases[index]
		if database.configDNKey != dn.Key() || database.monitoringConfigured {
			continue
		}
		for _, change := range changes {
			if strings.EqualFold(change.Attribute.Description, "olcMonitoring") {
				// An empty replace also clears an implicit (absent) default.
				database.monitoring = false
				break
			}
		}
	}
}

func configureDatabaseMonitoring(databases []runtimeDatabase) {
	monitorAvailable := false
	for _, database := range databases {
		if isMonitorDatabase(database) && !database.disabled {
			monitorAvailable = true
			break
		}
	}
	for index := range databases {
		database := &databases[index]
		database.monitoringRegistered = monitorAvailable && database.monitoring && !database.disabled
	}
}

func preserveDatabaseMonitoring(previous, next *runtimeState) {
	if previous == nil {
		return
	}
	for index := range next.databases {
		database := &next.databases[index]
		for _, old := range previous.databases {
			if database.configDNKey != old.configDNKey || database.partition != old.partition || database.name != old.name {
				continue
			}
			if !database.monitoringConfigured {
				// CFG_MONITORING deletion clears the flag; it does not restore
				// the backend default. Keep it cleared on subsequent reloads.
				database.monitoring = old.monitoring && !old.monitoringConfigured
			}
			// OpenLDAP registers backend monitor attributes at database open.
			// Changing the flag online does not register/unregister them.
			// CFG_DISABLED closes the backend; clearing it does not reopen it.
			database.monitoringRegistered = old.monitoringRegistered && !database.disabled
			break
		}
	}
}

func populateDatabaseMonitoring(
	reader storage.Reader,
	runtime *runtimeState,
	dn directory.DN,
	entry *directory.Entry,
) error {
	index := monitorDatabaseIndexForEntry(runtime.databases, dn)
	if index < 0 {
		return nil
	}
	database := runtime.databases[index]
	if !database.monitoringRegistered || databaseType(database.name) != "mdb" {
		return nil
	}
	if len(entry.Values("olmMDBEntries")) != 0 {
		return nil
	}
	count, err := storage.PartitionEntryCount(reader, database.partition)
	if err != nil {
		return fmt.Errorf("count monitored database %s: %w", database.name, err)
	}
	entry.ReplaceValues("olmMDBEntries", stringValues(strconv.FormatUint(count, 10)))
	return nil
}

func monitorFilterRequiresDatabaseCount(
	server *Server,
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	entry directory.Entry,
	filter *directory.Filter,
) bool {
	if filter == nil || !entry.HasAttribute("olmMDBEntries") {
		return false
	}
	switch filter.Kind {
	case directory.FilterAnd, directory.FilterOr, directory.FilterNot:
		for index := range filter.Children {
			if monitorFilterRequiresDatabaseCount(
				server, runtime, reader, boundDN, entry, &filter.Children[index],
			) {
				return true
			}
		}
		return false
	case directory.FilterPresent:
		return false
	case directory.FilterExtensible:
		if filter.Attribute != "" && !runtime.schema.AttributeDescriptionSubtype(
			"olmMDBEntries", filter.Attribute,
		) {
			return false
		}
	case directory.FilterEquality,
		directory.FilterApprox,
		directory.FilterGreaterOrEqual,
		directory.FilterLessOrEqual,
		directory.FilterSubstrings:
		if !runtime.schema.AttributeDescriptionSubtype(
			"olmMDBEntries", filter.Attribute,
		) {
			return false
		}
	default:
		return false
	}
	return server.allowed(
		runtime,
		reader,
		boundDN,
		entry,
		"olmMDBEntries",
		filter.Assertion,
		acl.Search,
	)
}
