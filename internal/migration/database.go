package migration

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type databaseTarget struct {
	partition string
	config    bool
}

func resolveDatabaseTarget(
	reader storage.Reader,
	selector string,
) (databaseTarget, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return databaseTarget{}, nil
	}
	if strings.EqualFold(selector, "config") ||
		strings.EqualFold(selector, "cn=config") ||
		selector == "0" {
		return databaseTarget{
			partition: storage.OpenLDAPConfigPartition,
			config:    true,
		}, nil
	}

	var selectorDN *directory.DN
	if parsed, err := directory.ParseDN(selector); err == nil && parsed.Depth() > 0 {
		selectorDN = &parsed
	}
	selectorIndex, selectorIsIndex := parseDatabaseIndex(selector)

	configSuffix, err := directory.ParseDN("cn=config")
	if err != nil {
		return databaseTarget{}, err
	}
	var matches []databaseTarget
	if err := reader.ForEach(func(entry directory.Entry) error {
		entryDN, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		if !configSuffix.Equal(entryDN) && !configSuffix.AncestorOf(entryDN) {
			return nil
		}
		values := entry.Values("olcDatabase")
		if len(values) == 0 {
			return nil
		}
		if len(values) != 1 {
			return fmt.Errorf("%s olcDatabase must be single-valued", entry.DN)
		}
		name := string(values[0])
		index, hasIndex := parseDatabaseIndex(name)
		matched := strings.EqualFold(selector, name) ||
			(selectorDN != nil && selectorDN.Equal(entryDN)) ||
			(selectorIsIndex && hasIndex && selectorIndex == index)
		if !matched {
			return nil
		}

		target := databaseTarget{}
		if databaseType(name) == "config" {
			target.partition = storage.OpenLDAPConfigPartition
			target.config = true
		} else {
			uuids := entry.Values("entryUUID")
			if len(uuids) > 1 {
				return fmt.Errorf("%s entryUUID must be single-valued", entry.DN)
			}
			var uuid []byte
			if len(uuids) == 1 {
				uuid = uuids[0]
			}
			target.partition = storage.OpenLDAPDatabasePartition(name, uuid)
		}
		matches = append(matches, target)
		return nil
	}); err != nil {
		return databaseTarget{}, fmt.Errorf("resolve database %q: %w", selector, err)
	}

	switch len(matches) {
	case 0:
		return databaseTarget{}, fmt.Errorf(
			"OpenLDAP database %q is not present in cn=config",
			selector,
		)
	case 1:
		return matches[0], nil
	default:
		return databaseTarget{}, fmt.Errorf(
			"OpenLDAP database selector %q is ambiguous",
			selector,
		)
	}
}

func parseDatabaseIndex(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if index, err := strconv.Atoi(value); err == nil && index >= 0 {
		return index, true
	}
	if !strings.HasPrefix(value, "{") {
		return 0, false
	}
	end := strings.IndexByte(value, '}')
	if end < 2 {
		return 0, false
	}
	index, err := strconv.Atoi(value[1:end])
	return index, err == nil && index >= 0
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

func isConfigurationDN(rawDN string) (bool, error) {
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		return false, err
	}
	configSuffix, err := directory.ParseDN("cn=config")
	if err != nil {
		return false, err
	}
	return configSuffix.Equal(dn) || configSuffix.AncestorOf(dn), nil
}
