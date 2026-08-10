package migration

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type databaseTarget struct {
	name            string
	backend         string
	configDN        directory.DN
	index           int
	hasIndex        bool
	partition       string
	config          bool
	suffixes        []directory.DN
	lastMod         bool
	rootDN          string
	syncUseSubentry bool
	subordinate     bool
	hidden          bool
	disabled        bool
}

func resolveDatabaseTarget(
	reader storage.Reader,
	selector string,
) (databaseTarget, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return databaseTarget{lastMod: true}, nil
	}
	if strings.EqualFold(selector, "config") ||
		strings.EqualFold(selector, "cn=config") ||
		selector == "0" {
		configSuffix, err := directory.ParseDN("cn=config")
		if err != nil {
			return databaseTarget{}, fmt.Errorf("parse config database suffix: %w", err)
		}
		return databaseTarget{
			name:      "{0}config",
			backend:   "config",
			index:     0,
			hasIndex:  true,
			partition: storage.OpenLDAPConfigPartition,
			config:    true,
			suffixes:  []directory.DN{configSuffix},
			lastMod:   true,
			rootDN:    configSuffix.String(),
		}, nil
	}

	var selectorDN *directory.DN
	if parsed, err := directory.ParseDN(selector); err == nil && parsed.Depth() > 0 {
		selectorDN = &parsed
	}
	selectorIndex, selectorIsIndex := parseDatabaseIndex(selector)

	targets, err := loadDatabaseTargets(reader)
	if err != nil {
		return databaseTarget{}, fmt.Errorf("resolve database %q: %w", selector, err)
	}
	var matches []databaseTarget
	for _, target := range targets {
		matched := strings.EqualFold(selector, target.name) ||
			(selectorDN != nil && selectorDN.Equal(target.configDN)) ||
			(selectorIsIndex && target.hasIndex && selectorIndex == target.index)
		if !matched {
			continue
		}
		matches = append(matches, target)
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

func loadDatabaseTargets(reader storage.Reader) ([]databaseTarget, error) {
	configSuffix, err := directory.ParseDN("cn=config")
	if err != nil {
		return nil, err
	}
	var targets []databaseTarget
	err = reader.ForEachIn(
		storage.OpenLDAPConfigPartition,
		func(entry directory.Entry) error {
			entryDN, err := directory.ParseDN(entry.DN)
			if err != nil {
				return fmt.Errorf("parse configuration entry DN %q: %w", entry.DN, err)
			}
			parent, hasParent := entryDN.Parent()
			if !hasParent || !configSuffix.Equal(parent) {
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
			for _, naming := range entryDN.RDNValues() {
				if strings.EqualFold(naming.Type, "olcDatabase") &&
					!strings.EqualFold(string(naming.Value), name) {
					return fmt.Errorf(
						"%s naming value %q does not match olcDatabase %q",
						entry.DN,
						naming.Value,
						name,
					)
				}
			}
			index, hasIndex := parseDatabaseIndex(name)
			target := databaseTarget{
				name:     name,
				backend:  databaseType(name),
				configDN: entryDN,
				index:    index,
				hasIndex: hasIndex,
				lastMod:  true,
			}
			if target.backend == "config" {
				target.partition = storage.OpenLDAPConfigPartition
				target.config = true
				target.suffixes = []directory.DN{configSuffix}
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
				for _, rawSuffix := range entry.Values("olcSuffix") {
					suffix, err := directory.ParseDN(string(rawSuffix))
					if err != nil || suffix.Depth() == 0 {
						if err == nil {
							err = fmt.Errorf("suffix DN must not be empty")
						}
						return fmt.Errorf("%s olcSuffix %q: %w", entry.DN, rawSuffix, err)
					}
					target.suffixes = append(target.suffixes, suffix)
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
				target.rootDN = rootDN.String()
			}
			lastModValues := entry.Values("olcLastMod")
			if len(lastModValues) > 1 {
				return fmt.Errorf("%s olcLastMod must be single-valued", entry.DN)
			}
			if len(lastModValues) == 1 {
				lastMod, err := parseOpenLDAPBoolean(string(lastModValues[0]))
				if err != nil {
					return fmt.Errorf("%s olcLastMod: %w", entry.DN, err)
				}
				target.lastMod = lastMod
			}
			syncUseSubentryValues := entry.Values("olcSyncUseSubentry")
			if len(syncUseSubentryValues) > 1 {
				return fmt.Errorf("%s olcSyncUseSubentry must be single-valued", entry.DN)
			}
			if len(syncUseSubentryValues) == 1 {
				syncUseSubentry, err := parseOpenLDAPBoolean(
					string(syncUseSubentryValues[0]),
				)
				if err != nil {
					return fmt.Errorf("%s olcSyncUseSubentry: %w", entry.DN, err)
				}
				target.syncUseSubentry = syncUseSubentry
			}
			subordinateValues := entry.Values("olcSubordinate")
			if len(subordinateValues) > 1 {
				return fmt.Errorf("%s olcSubordinate must be single-valued", entry.DN)
			}
			if len(subordinateValues) == 1 {
				switch strings.ToLower(strings.TrimSpace(string(subordinateValues[0]))) {
				case "advertise":
					target.subordinate = true
				default:
					subordinate, err := parseOpenLDAPBoolean(string(subordinateValues[0]))
					if err != nil {
						return fmt.Errorf("%s olcSubordinate: %w", entry.DN, err)
					}
					target.subordinate = subordinate
				}
			}
			for _, setting := range []struct {
				attribute   string
				destination *bool
			}{
				{attribute: "olcHidden", destination: &target.hidden},
				{attribute: "olcDisabled", destination: &target.disabled},
			} {
				values := entry.Values(setting.attribute)
				if len(values) > 1 {
					return fmt.Errorf("%s %s must be single-valued", entry.DN, setting.attribute)
				}
				if len(values) == 1 {
					value, err := parseOpenLDAPBoolean(string(values[0]))
					if err != nil {
						return fmt.Errorf("%s %s: %w", entry.DN, setting.attribute, err)
					}
					*setting.destination = value
				}
			}
			targets = append(targets, target)
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	sort.Slice(targets, func(left, right int) bool {
		if targets[left].hasIndex != targets[right].hasIndex {
			return targets[left].hasIndex
		}
		if targets[left].hasIndex && targets[left].index != targets[right].index {
			return targets[left].index < targets[right].index
		}
		return targets[left].configDN.Key() < targets[right].configDN.Key()
	})
	return targets, nil
}

func resolveDefaultDatabaseTarget(
	reader storage.Reader,
) (databaseTarget, bool, error) {
	targets, err := loadDatabaseTargets(reader)
	if err != nil {
		return databaseTarget{}, false, err
	}
	for _, target := range targets {
		switch target.backend {
		case "config", "frontend", "monitor":
			continue
		}
		if target.subordinate {
			continue
		}
		return target, true, nil
	}
	return databaseTarget{}, false, nil
}

func selectDatabaseTargetForDN(
	targets []databaseTarget,
	dn directory.DN,
) (databaseTarget, bool, error) {
	var matches []databaseTarget
	bestDepth := -1
	for _, target := range targets {
		if target.config || target.hidden || target.disabled {
			continue
		}
		for _, suffix := range target.suffixes {
			if !suffix.Equal(dn) && !suffix.AncestorOf(dn) {
				continue
			}
			if suffix.Depth() > bestDepth {
				matches = matches[:0]
				bestDepth = suffix.Depth()
			}
			if suffix.Depth() == bestDepth {
				matches = append(matches, target)
			}
		}
	}
	if len(matches) == 0 {
		return databaseTarget{}, false, nil
	}
	best := matches[0]
	for _, match := range matches[1:] {
		if !strings.EqualFold(match.name, best.name) {
			return databaseTarget{}, false, fmt.Errorf(
				"DN %q matches multiple OpenLDAP databases %q and %q",
				dn.String(),
				best.name,
				match.name,
			)
		}
	}
	return best, true, nil
}

func databaseTargetsOwnNamingContexts(targets []databaseTarget) bool {
	for _, target := range targets {
		if !target.config && !target.hidden && !target.disabled &&
			len(target.suffixes) > 0 {
			return true
		}
	}
	return false
}

func selectedDatabaseWriteTarget(
	selected databaseTarget,
	targets []databaseTarget,
	dn directory.DN,
	gluedSubordinates map[string]struct{},
) (databaseTarget, bool, databaseTarget) {
	selectedDepth := -1
	for _, suffix := range selected.suffixes {
		if suffix.Equal(dn) || suffix.AncestorOf(dn) {
			selectedDepth = max(selectedDepth, suffix.Depth())
		}
	}
	if selectedDepth < 0 {
		owner, found, err := selectDatabaseTargetForDN(targets, dn)
		if err == nil && found {
			return databaseTarget{}, false, owner
		}
		return databaseTarget{}, false, databaseTarget{}
	}
	writeTarget := selected
	var conflicting databaseTarget
	moreSpecificDepth := selectedDepth
	for _, target := range targets {
		if target.config || target.hidden || target.disabled ||
			target.partition == selected.partition {
			continue
		}
		for _, suffix := range target.suffixes {
			if (suffix.Equal(dn) || suffix.AncestorOf(dn)) &&
				suffix.Depth() > moreSpecificDepth {
				if target.subordinate {
					if _, attached := gluedSubordinates[target.partition]; !attached {
						continue
					}
					writeTarget = target
					conflicting = databaseTarget{}
				} else {
					conflicting = target
				}
				moreSpecificDepth = suffix.Depth()
			}
		}
	}
	if conflicting.name != "" {
		return databaseTarget{}, false, conflicting
	}
	return writeTarget, true, databaseTarget{}
}

func glueSubordinateTargets(
	reader storage.Reader,
	selected databaseTarget,
	targets []databaseTarget,
) ([]databaseTarget, error) {
	result, err := attachedSubordinateTargets(selected, targets)
	if err != nil {
		return nil, err
	}
	for _, subordinate := range result {
		for _, suffix := range subordinate.suffixes {
			if _, err := reader.GetIn(selected.partition, suffix); err == nil {
				return nil, fmt.Errorf(
					"subordinate database suffix entry DN %q is also present in superior database %q",
					suffix.String(),
					selected.name,
				)
			} else if !errors.Is(err, storage.ErrEntryNotFound) {
				return nil, fmt.Errorf(
					"check subordinate database suffix %q in superior database %q: %w",
					suffix.String(),
					selected.name,
					err,
				)
			}
		}
	}
	return result, nil
}

func attachedSubordinateTargets(
	selected databaseTarget,
	targets []databaseTarget,
) ([]databaseTarget, error) {
	if selected.config || selected.subordinate {
		return nil, nil
	}
	var result []databaseTarget
	for _, candidate := range targets {
		if !candidate.subordinate || candidate.hidden || candidate.disabled ||
			candidate.partition == selected.partition {
			continue
		}
		belongsToSelected := false
		for _, suffix := range candidate.suffixes {
			bestDepth := -1
			owner := ""
			ambiguous := false
			for _, possibleOwner := range targets {
				if possibleOwner.config || possibleOwner.subordinate ||
					possibleOwner.hidden || possibleOwner.disabled ||
					possibleOwner.partition == candidate.partition {
					continue
				}
				for _, ownerSuffix := range possibleOwner.suffixes {
					if !ownerSuffix.AncestorOf(suffix) {
						continue
					}
					depth := ownerSuffix.Depth()
					switch {
					case depth > bestDepth:
						bestDepth = depth
						owner = possibleOwner.partition
						ambiguous = false
					case depth == bestDepth && owner != possibleOwner.partition:
						ambiguous = true
					}
				}
			}
			if ambiguous {
				return nil, fmt.Errorf(
					"subordinate database %q has ambiguous glue superiors",
					candidate.name,
				)
			}
			if owner == selected.partition {
				belongsToSelected = true
				break
			}
		}
		if belongsToSelected {
			result = append(result, candidate)
		}
	}
	return result, nil
}

func (target databaseTarget) supportsOfflineImport() bool {
	switch target.backend {
	case "", "config", "mdb", "ldif", "wt", "null":
		return true
	default:
		return false
	}
}

func (target databaseTarget) supportsOfflineContextUpdate() bool {
	switch target.backend {
	case "", "config", "mdb", "ldif", "wt":
		return true
	default:
		return false
	}
}

func (target databaseTarget) supportsOfflineExport() bool {
	switch target.backend {
	case "", "config", "mdb", "ldif", "wt", "null":
		return true
	default:
		return false
	}
}

func (target databaseTarget) discardsOfflineImport() bool {
	return target.backend == "null"
}

func parseOpenLDAPBoolean(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on", "1":
		return true, nil
	case "false", "no", "off", "0":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q", value)
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
