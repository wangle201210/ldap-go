package server

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type runtimeDatabase struct {
	name            string
	suffixes        []directory.DN
	rootDN          *directory.DN
	rootPassword    []byte
	rootPasswordSet bool
	readOnly        bool
	lastMod         bool
}

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
		database := runtimeDatabase{
			name:    string(databaseValues[0]),
			lastMod: true,
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
			case strings.Contains(strings.ToLower(database.name), "config"):
				database.suffixes = []directory.DN{configSuffix}
			case strings.Contains(strings.ToLower(database.name), "monitor"):
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
		if lastMod, present, err := singleBoolean(entry, "olcLastMod"); err != nil {
			return err
		} else if present {
			database.lastMod = lastMod
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

	for _, rawContext := range namingContexts {
		contextDN, err := directory.ParseDN(rawContext)
		if err != nil {
			return nil, fmt.Errorf("parse naming context %q: %w", rawContext, err)
		}
		if databaseHasSuffix(databases, contextDN) {
			continue
		}
		databases = append(databases, runtimeDatabase{
			name:     "bootstrap",
			suffixes: []directory.DN{contextDN},
			lastMod:  true,
		})
	}
	applyFrontendDatabaseDefaults(databases)
	return databases, nil
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

func applyFrontendDatabaseDefaults(databases []runtimeDatabase) {
	frontendReadOnly := false
	for _, database := range databases {
		if strings.Contains(strings.ToLower(database.name), "frontend") &&
			database.readOnly {
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

func applyBootstrapRoot(
	databases []runtimeDatabase,
	rawDN string,
	password []byte,
) error {
	rootDN, err := directory.ParseDN(rawDN)
	if err != nil {
		return fmt.Errorf("root DN: %w", err)
	}
	index := databaseIndexForDN(databases, rootDN)
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

func databaseHasSuffix(databases []runtimeDatabase, suffix directory.DN) bool {
	for _, database := range databases {
		for _, candidate := range database.suffixes {
			if candidate.Equal(suffix) {
				return true
			}
		}
	}
	return false
}
