package server

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type runtimeDatabase struct {
	name            string
	partition       string
	suffixes        []directory.DN
	rootDN          *directory.DN
	rootPassword    []byte
	rootPasswordSet bool
	disabled        bool
	hidden          bool
	subordinate     bool
	advertise       bool
	readOnly        bool
	lastMod         bool
	maxDerefDepth   int
	configDNKey     string
	serverSideSort  bool
	sortMaxKeys     int
	sortLimiter     *serverSideSortLimiter
	syncProvider    bool
}

const configurationStoragePartition = storage.OpenLDAPConfigPartition

func loadRuntimeDatabases(
	ctx context.Context,
	store storage.Store,
) ([]runtimeDatabase, error) {
	var databases []runtimeDatabase
	err := store.View(ctx, func(reader storage.Reader) error {
		var err error
		databases, err = loadRuntimeDatabasesReader(reader)
		return err
	})
	return databases, err
}

func loadRuntimeDatabasesReader(reader storage.Reader) ([]runtimeDatabase, error) {
	configSuffix, err := directory.ParseDN("cn=config")
	if err != nil {
		return nil, err
	}

	var databases []runtimeDatabase
	if err := reader.ForEach(func(entry directory.Entry) error {
		entryDN, err := directory.ParseDN(entry.DN)
		if err != nil {
			return fmt.Errorf("parse entry DN %q: %w", entry.DN, err)
		}
		if !configSuffix.Equal(entryDN) && !configSuffix.AncestorOf(entryDN) {
			return nil
		}

		databaseValues := entry.Values("olcDatabase")
		if len(databaseValues) == 0 {
			return nil
		}
		if len(databaseValues) != 1 {
			return fmt.Errorf("%s olcDatabase must be single-valued", entry.DN)
		}
		entryUUIDValues := entry.Values("entryUUID")
		if len(entryUUIDValues) > 1 {
			return fmt.Errorf("%s entryUUID must be single-valued", entry.DN)
		}
		var entryUUID []byte
		if len(entryUUIDValues) == 1 {
			entryUUID = entryUUIDValues[0]
		}
		database := runtimeDatabase{
			name:          string(databaseValues[0]),
			partition:     storage.OpenLDAPDatabasePartition(string(databaseValues[0]), entryUUID),
			lastMod:       true,
			maxDerefDepth: defaultAliasDerefDepth,
			configDNKey:   entryDN.Key(),
		}
		for _, rawSuffix := range entry.Values("olcSuffix") {
			suffix, err := directory.ParseDN(string(rawSuffix))
			if err != nil {
				return fmt.Errorf("%s olcSuffix: %w", entry.DN, err)
			}
			database.suffixes = append(database.suffixes, suffix)
		}
		if len(database.suffixes) == 0 {
			switch {
			case isConfigDatabase(database):
				database.suffixes = []directory.DN{configSuffix}
				database.partition = configurationStoragePartition
			case isMonitorDatabase(database):
				monitor, err := directory.ParseDN("cn=Monitor")
				if err != nil {
					return err
				}
				database.suffixes = []directory.DN{monitor}
			}
		}

		rootDNValues := entry.Values("olcRootDN")
		if len(rootDNValues) > 1 {
			return fmt.Errorf("%s olcRootDN must be single-valued", entry.DN)
		}
		if len(rootDNValues) == 1 {
			rootDN, err := directory.ParseDN(string(rootDNValues[0]))
			if err != nil {
				return fmt.Errorf("%s olcRootDN: %w", entry.DN, err)
			}
			database.rootDN = &rootDN
		}

		rootPasswordValues := entry.Values("olcRootPW")
		if len(rootPasswordValues) > 1 {
			return fmt.Errorf("%s olcRootPW must be single-valued", entry.DN)
		}
		if len(rootPasswordValues) == 1 {
			if database.rootDN == nil {
				return fmt.Errorf("%s olcRootPW requires olcRootDN", entry.DN)
			}
			database.rootPasswordSet = true
			database.rootPassword = bytes.Clone(rootPasswordValues[0])
		}
		database.readOnly, _, err = singleBoolean(
			entry,
			"olcReadOnly",
		)
		if err != nil {
			return err
		}
		database.disabled, _, err = singleBoolean(entry, "olcDisabled")
		if err != nil {
			return err
		}
		database.hidden, _, err = singleBoolean(entry, "olcHidden")
		if err != nil {
			return err
		}
		var subordinatePresent bool
		database.subordinate, database.advertise, subordinatePresent, err =
			subordinateSetting(entry)
		if err != nil {
			return err
		}
		if subordinatePresent && len(database.suffixes) != 1 {
			return fmt.Errorf(
				"%s olcSubordinate requires exactly one suffix",
				entry.DN,
			)
		}
		if lastMod, present, err := singleBoolean(entry, "olcLastMod"); err != nil {
			return err
		} else if present {
			database.lastMod = lastMod
		}
		database.maxDerefDepth, err = singleNonnegativeInteger(
			entry,
			"olcMaxDerefDepth",
			defaultAliasDerefDepth,
		)
		if err != nil {
			return err
		}
		databases = append(databases, database)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("load runtime databases: %w", err)
	}
	namingContexts, err := reader.NamingContexts()
	if err != nil {
		return nil, fmt.Errorf("load runtime database naming contexts: %w", err)
	}
	if err := validateDatabaseSuffixes(databases); err != nil {
		return nil, err
	}
	if err := validateDatabasePartitions(databases); err != nil {
		return nil, err
	}
	if err := loadRuntimeDatabaseOverlays(reader, databases); err != nil {
		return nil, err
	}

	for _, rawContext := range namingContexts {
		contextDN, err := directory.ParseDN(rawContext)
		if err != nil {
			return nil, fmt.Errorf("parse naming context %q: %w", rawContext, err)
		}
		if databaseHasSuffix(databases, contextDN) {
			continue
		}
		databases = append(databases, runtimeDatabase{
			name:          "bootstrap",
			partition:     storage.OpenLDAPBootstrapPartition(contextDN),
			suffixes:      []directory.DN{contextDN},
			lastMod:       true,
			maxDerefDepth: defaultAliasDerefDepth,
		})
	}
	applyFrontendDatabaseDefaults(databases)
	return databases, nil
}

func loadRuntimeDatabaseOverlays(
	reader storage.Reader,
	databases []runtimeDatabase,
) error {
	configSuffix, err := directory.ParseDN("cn=config")
	if err != nil {
		return err
	}
	return reader.ForEach(func(entry directory.Entry) error {
		entryDN, err := directory.ParseDN(entry.DN)
		if err != nil {
			return fmt.Errorf("parse entry DN %q: %w", entry.DN, err)
		}
		if !configSuffix.AncestorOf(entryDN) {
			return nil
		}

		overlayValues := entry.Values("olcOverlay")
		if len(overlayValues) == 0 {
			return nil
		}
		if len(overlayValues) != 1 {
			return fmt.Errorf("%s olcOverlay must be single-valued", entry.DN)
		}
		overlayType := databaseType(string(overlayValues[0]))
		if overlayType != "sssvlv" && overlayType != "syncprov" {
			return nil
		}

		parent, ok := entryDN.Parent()
		if !ok {
			return fmt.Errorf(
				"%s %s overlay has no database parent",
				entry.DN,
				overlayType,
			)
		}
		databaseIndex := -1
		for index := range databases {
			if databases[index].configDNKey == parent.Key() {
				databaseIndex = index
				break
			}
		}
		if databaseIndex < 0 {
			return fmt.Errorf(
				"%s %s overlay parent is not a configured database",
				entry.DN,
				overlayType,
			)
		}
		database := &databases[databaseIndex]
		switch overlayType {
		case "sssvlv":
			if database.serverSideSort {
				return fmt.Errorf(
					"%s configures a duplicate sssvlv overlay for %s",
					entry.DN,
					database.name,
				)
			}

			maximum, err := singleNonnegativeInteger(
				entry,
				"olcSssVlvMax",
				defaultServerSideSortMax,
			)
			if err != nil {
				return err
			}
			if maximum == 0 {
				maximum = defaultServerSideSortMax
			}
			maxKeys, err := singleNonnegativeInteger(
				entry,
				"olcSssVlvMaxKeys",
				defaultServerSideSortMaxKeys,
			)
			if err != nil {
				return err
			}
			maxPerConn, err := singleNonnegativeInteger(
				entry,
				"olcSssVlvMaxPerConn",
				defaultServerSideSortMaxPerConn,
			)
			if err != nil {
				return err
			}
			database.serverSideSort = true
			database.sortMaxKeys = maxKeys
			database.sortLimiter = &serverSideSortLimiter{
				max:        maximum,
				maxPerConn: maxPerConn,
			}
		case "syncprov":
			if database.syncProvider {
				return fmt.Errorf(
					"%s configures a duplicate syncprov overlay for %s",
					entry.DN,
					database.name,
				)
			}
			if !database.lastMod {
				return fmt.Errorf(
					"%s syncprov overlay requires olcLastMod TRUE for %s",
					entry.DN,
					database.name,
				)
			}
			database.syncProvider = true
		}
		return nil
	})
}

func runtimeSupportsServerSideSort(databases []runtimeDatabase) bool {
	for _, database := range databases {
		if database.serverSideSort {
			return true
		}
	}
	return false
}

func runtimeSupportsSyncProvider(databases []runtimeDatabase) bool {
	for _, database := range databases {
		if database.syncProvider {
			return true
		}
	}
	return false
}

func serverSideSortSettingsForDatabase(
	databases []runtimeDatabase,
	databaseIndex int,
) (int, bool) {
	maxKeys := 0
	enabled := false
	if databaseIndex >= 0 &&
		databaseIndex < len(databases) &&
		databases[databaseIndex].serverSideSort {
		maxKeys = databases[databaseIndex].sortMaxKeys
		enabled = true
	}
	for _, database := range databases {
		if databaseType(database.name) == "frontend" &&
			database.serverSideSort {
			if !enabled || database.sortMaxKeys < maxKeys {
				maxKeys = database.sortMaxKeys
			}
			enabled = true
			break
		}
	}
	return maxKeys, enabled
}

func serverSideSortLimitersForDatabase(
	databases []runtimeDatabase,
	databaseIndex int,
) []*serverSideSortLimiter {
	var limiters []*serverSideSortLimiter
	if databaseIndex >= 0 &&
		databaseIndex < len(databases) &&
		databases[databaseIndex].serverSideSort &&
		databases[databaseIndex].sortLimiter != nil {
		limiters = append(limiters, databases[databaseIndex].sortLimiter)
	}
	for index := range databases {
		if databaseType(databases[index].name) == "frontend" &&
			databases[index].serverSideSort &&
			databases[index].sortLimiter != nil {
			if index != databaseIndex {
				limiters = append(limiters, databases[index].sortLimiter)
			}
			break
		}
	}
	return limiters
}

func singleNonnegativeInteger(
	entry directory.Entry,
	attribute string,
	defaultValue int,
) (int, error) {
	values := entry.Values(attribute)
	if len(values) == 0 {
		return defaultValue, nil
	}
	if len(values) != 1 {
		return 0, fmt.Errorf(
			"%s %s must be single-valued",
			entry.DN,
			attribute,
		)
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(values[0])))
	if err != nil || value < 0 {
		return 0, fmt.Errorf(
			"%s %s has invalid value %q",
			entry.DN,
			attribute,
			values[0],
		)
	}
	return value, nil
}

func singleBoolean(
	entry directory.Entry,
	attribute string,
) (value, present bool, err error) {
	values := entry.Values(attribute)
	if len(values) == 0 {
		return false, false, nil
	}
	if len(values) != 1 {
		return false, false, fmt.Errorf("%s %s must be single-valued", entry.DN, attribute)
	}
	switch {
	case strings.EqualFold(string(values[0]), "TRUE"):
		return true, true, nil
	case strings.EqualFold(string(values[0]), "FALSE"):
		return false, true, nil
	default:
		return false, false, fmt.Errorf(
			"%s %s has invalid value %q",
			entry.DN,
			attribute,
			values[0],
		)
	}
}

func subordinateSetting(
	entry directory.Entry,
) (subordinate, advertise, present bool, err error) {
	values := entry.Values("olcSubordinate")
	if len(values) == 0 {
		return false, false, false, nil
	}
	if len(values) != 1 {
		return false, false, false, fmt.Errorf(
			"%s olcSubordinate must be single-valued",
			entry.DN,
		)
	}
	switch {
	case strings.EqualFold(string(values[0]), "TRUE"):
		return true, false, true, nil
	case strings.EqualFold(string(values[0]), "FALSE"):
		return false, false, true, nil
	case strings.EqualFold(string(values[0]), "advertise"):
		return true, true, true, nil
	default:
		return false, false, false, fmt.Errorf(
			"%s olcSubordinate has invalid value %q",
			entry.DN,
			values[0],
		)
	}
}

func applyFrontendDatabaseDefaults(databases []runtimeDatabase) {
	frontendReadOnly := false
	for _, database := range databases {
		if databaseType(database.name) == "frontend" && database.readOnly {
			frontendReadOnly = database.readOnly
			break
		}
	}
	for index := range databases {
		databases[index].readOnly = databases[index].readOnly || frontendReadOnly
	}
}

func validateDatabaseSuffixes(databases []runtimeDatabase) error {
	owners := make(map[string]string)
	for _, database := range databases {
		if database.hidden || database.disabled {
			continue
		}
		for _, suffix := range database.suffixes {
			if owner, exists := owners[suffix.Key()]; exists {
				return fmt.Errorf(
					"database suffix %q is configured by both %q and %q",
					suffix.String(),
					owner,
					database.name,
				)
			}
			owners[suffix.Key()] = database.name
		}
	}
	return nil
}

func validateDatabasePartitions(databases []runtimeDatabase) error {
	owners := make(map[string]string)
	for _, database := range databases {
		if database.partition == "" {
			continue
		}
		if owner, exists := owners[database.partition]; exists {
			return fmt.Errorf(
				"databases %q and %q use the same storage partition",
				owner,
				database.name,
			)
		}
		owners[database.partition] = database.name
	}
	return nil
}

func applyBootstrapRoot(
	databases []runtimeDatabase,
	rawDN string,
	password []byte,
) error {
	rootDN, err := directory.ParseDN(rawDN)
	if err != nil {
		return fmt.Errorf("root DN: %w", err)
	}
	index := databaseIndexForRootOverride(databases, rootDN)
	if index < 0 {
		return fmt.Errorf("root DN %q is not within a configured naming context", rawDN)
	}
	databases[index].rootDN = &rootDN
	databases[index].rootPassword = bytes.Clone(password)
	databases[index].rootPasswordSet = true
	return nil
}

func databaseIndexForDN(databases []runtimeDatabase, dn directory.DN) int {
	bestIndex := -1
	bestDepth := -1
	for index := range databases {
		if databases[index].hidden || databases[index].disabled {
			continue
		}
		for _, suffix := range databases[index].suffixes {
			if !suffix.Equal(dn) && !suffix.AncestorOf(dn) {
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

func glueSuperiorDatabaseIndex(
	databases []runtimeDatabase,
	subordinateIndex int,
) int {
	if subordinateIndex < 0 ||
		subordinateIndex >= len(databases) ||
		!databases[subordinateIndex].subordinate ||
		len(databases[subordinateIndex].suffixes) != 1 {
		return -1
	}

	childSuffix := databases[subordinateIndex].suffixes[0]
	bestIndex := -1
	bestDepth := -1
	for index := range databases {
		database := &databases[index]
		if database.hidden || database.disabled || database.subordinate {
			continue
		}
		for _, suffix := range database.suffixes {
			if !suffix.AncestorOf(childSuffix) {
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

func databaseIndexForRootOverride(
	databases []runtimeDatabase,
	dn directory.DN,
) int {
	bestIndex := -1
	bestDepth := -1
	for index := range databases {
		if databases[index].hidden {
			continue
		}
		for _, suffix := range databases[index].suffixes {
			if !suffix.Equal(dn) && !suffix.AncestorOf(dn) {
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

func databaseIndexForLegacyDN(
	databases []runtimeDatabase,
	dn directory.DN,
) (int, error) {
	bestIndex := -1
	bestDepth := -1
	for index := range databases {
		for _, suffix := range databases[index].suffixes {
			if !suffix.Equal(dn) && !suffix.AncestorOf(dn) {
				continue
			}
			switch {
			case suffix.Depth() > bestDepth:
				bestIndex = index
				bestDepth = suffix.Depth()
			case suffix.Depth() == bestDepth &&
				bestIndex >= 0 &&
				databases[bestIndex].partition != databases[index].partition:
				return -1, fmt.Errorf(
					"DN %q belongs to multiple OpenLDAP databases at the same suffix depth",
					dn.String(),
				)
			}
		}
	}
	return bestIndex, nil
}

func databaseHasSuffix(databases []runtimeDatabase, suffix directory.DN) bool {
	for _, database := range databases {
		if databaseOwnsSuffix(database, suffix) {
			return true
		}
	}
	return false
}

func databaseOwnsSuffix(database runtimeDatabase, dn directory.DN) bool {
	for _, suffix := range database.suffixes {
		if suffix.Equal(dn) {
			return true
		}
	}
	return false
}

func configuredDatabasePartition(name string) string {
	return storage.OpenLDAPDatabasePartition(name, nil)
}

func isConfigDatabase(database runtimeDatabase) bool {
	return databaseType(database.name) == "config"
}

func isMonitorDatabase(database runtimeDatabase) bool {
	return databaseType(database.name) == "monitor"
}

func databaseType(name string) string {
	value := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(value, "{") {
		if end := strings.IndexByte(value, '}'); end >= 0 {
			value = value[end+1:]
		}
	}
	return value
}
