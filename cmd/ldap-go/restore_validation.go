package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

// restoreBoltValidated stages and migrates the backup, then validates the exact
// destination temporary file again immediately before atomic publication.
func restoreBoltValidated(
	ctx context.Context,
	backupPath,
	databasePath string,
	replace bool,
) (storage.CheckReport, error) {
	return restoreBoltValidatedWithHooks(
		ctx,
		backupPath,
		databasePath,
		replace,
		restoreValidationHooks{},
	)
}

type restoreValidationHooks struct {
	afterInitialValidation func(string) error
}

func restoreBoltValidatedWithHooks(
	ctx context.Context,
	backupPath,
	databasePath string,
	replace bool,
	hooks restoreValidationHooks,
) (storage.CheckReport, error) {
	if ctx == nil {
		return storage.CheckReport{}, errors.New("restore context is required")
	}
	if err := ctx.Err(); err != nil {
		return storage.CheckReport{}, err
	}
	if err := validateRestoreSourceAndDestination(backupPath, databasePath); err != nil {
		return storage.CheckReport{}, err
	}

	destinationDirectory := filepath.Dir(databasePath)
	if err := os.MkdirAll(destinationDirectory, 0o700); err != nil {
		return storage.CheckReport{}, fmt.Errorf("create database directory: %w", err)
	}
	stagingDirectory, err := os.MkdirTemp(
		destinationDirectory,
		".ldap-go-restore-validation-*",
	)
	if err != nil {
		return storage.CheckReport{}, fmt.Errorf("create restore validation directory: %w", err)
	}
	defer os.RemoveAll(stagingDirectory)

	stagingPath := filepath.Join(stagingDirectory, "candidate.db")
	if _, err := storage.RestoreBolt(ctx, backupPath, stagingPath, false); err != nil {
		return storage.CheckReport{}, fmt.Errorf("stage restore backup: %w", err)
	}
	if _, err := validateRestoreCandidate(ctx, stagingPath); err != nil {
		return storage.CheckReport{}, fmt.Errorf("restore candidate is invalid: %w", err)
	}
	if hooks.afterInitialValidation != nil {
		if err := hooks.afterInitialValidation(stagingPath); err != nil {
			return storage.CheckReport{}, fmt.Errorf(
				"restore validation hook after initial validation: %w",
				err,
			)
		}
	}

	report, err := storage.RestoreBoltWithValidation(
		ctx,
		stagingPath,
		databasePath,
		replace,
		validateRestoreCandidate,
	)
	if err != nil {
		return storage.CheckReport{}, err
	}
	return report, nil
}

func validateRestoreSourceAndDestination(backupPath, databasePath string) error {
	if backupPath == "" || databasePath == "" {
		return errors.New("source and destination paths are required")
	}
	backupAbsolute, err := filepath.Abs(backupPath)
	if err != nil {
		return fmt.Errorf("resolve backup path: %w", err)
	}
	databaseAbsolute, err := filepath.Abs(databasePath)
	if err != nil {
		return fmt.Errorf("resolve database path: %w", err)
	}
	if backupAbsolute == databaseAbsolute {
		return errors.New("source and destination paths must differ")
	}
	backupInfo, backupErr := os.Stat(backupAbsolute)
	databaseInfo, databaseErr := os.Stat(databaseAbsolute)
	if backupErr == nil && databaseErr == nil && os.SameFile(backupInfo, databaseInfo) {
		return errors.New("source and destination paths identify the same file")
	}
	return nil
}

func validateRestoreCandidate(
	ctx context.Context,
	path string,
) (report storage.CheckReport, runErr error) {
	if err := validateRestoreCandidatePreMigration(ctx, path); err != nil {
		return storage.CheckReport{}, err
	}
	if err := prepareRestoreCandidate(ctx, path); err != nil {
		return storage.CheckReport{}, err
	}
	store, err := storage.OpenBoltReadOnly(path)
	if err != nil {
		return storage.CheckReport{}, fmt.Errorf("open candidate: %w", err)
	}
	defer func() { runErr = errors.Join(runErr, store.Close()) }()

	if _, err := server.ValidateConfiguration(ctx, server.Config{Store: store}); err != nil {
		return storage.CheckReport{}, fmt.Errorf("runtime configuration: %w", err)
	}
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		return storage.CheckReport{}, fmt.Errorf("initialize built-in schema: %w", err)
	}
	if _, err := schema.LoadOpenLDAPConfig(ctx, store, registry); err != nil {
		return storage.CheckReport{}, fmt.Errorf("load cn=config schema: %w", err)
	}

	report, err = storage.CheckBoltWithNormalizer(
		ctx,
		path,
		restoreIndexSchema{registry: registry},
	)
	if err != nil {
		return storage.CheckReport{}, fmt.Errorf("storage metadata or indexes: %w", err)
	}
	if err := validateRestoreEntries(ctx, store, registry); err != nil {
		return storage.CheckReport{}, fmt.Errorf("directory schema: %w", err)
	}
	return report, nil
}

func validateRestoreCandidatePreMigration(
	ctx context.Context,
	path string,
) (runErr error) {
	store, err := storage.OpenBoltReadOnly(path)
	if err != nil {
		return fmt.Errorf("open candidate: %w", err)
	}
	defer func() { runErr = errors.Join(runErr, store.Close()) }()
	if _, err := server.ValidateConfiguration(ctx, server.Config{Store: store}); err != nil {
		return fmt.Errorf("runtime configuration: %w", err)
	}
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		return fmt.Errorf("initialize built-in schema: %w", err)
	}
	if _, err := schema.LoadOpenLDAPConfig(ctx, store, registry); err != nil {
		return fmt.Errorf("load cn=config schema: %w", err)
	}
	if _, err := storage.CheckBoltWithNormalizer(
		ctx,
		path,
		restoreIndexSchema{registry: registry},
	); err != nil {
		return fmt.Errorf("storage metadata or indexes: %w", err)
	}
	return nil
}

func prepareRestoreCandidate(ctx context.Context, path string) (runErr error) {
	store, err := storage.OpenBolt(path)
	if err != nil {
		return fmt.Errorf("open candidate for migration: %w", err)
	}
	defer func() { runErr = errors.Join(runErr, store.Close()) }()
	if err := server.PrepareOfflineDNIdentities(ctx, store); err != nil {
		return fmt.Errorf("prepare current storage format: %w", err)
	}
	return nil
}

func validateRestoreEntries(
	ctx context.Context,
	store storage.Store,
	registry *schema.Registry,
) error {
	return store.View(ctx, func(reader storage.Reader) error {
		allowedPartitions, err := restoreRuntimePartitions(reader, registry)
		if err != nil {
			return err
		}
		return reader.ForEachPartition(func(partition string, entry directory.Entry) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if _, allowed := allowedPartitions[partition]; !allowed {
				return fmt.Errorf(
					"entry %q uses orphan storage partition %q",
					entry.DN,
					partition,
				)
			}
			// cn=config was parsed and cross-validated by ValidateConfiguration.
			// Configuration records intentionally do not require normal directory
			// structuralObjectClass bookkeeping.
			if partition == storage.OpenLDAPConfigPartition {
				dn, parseErr := directory.ParseDN(entry.DN)
				if parseErr != nil {
					return fmt.Errorf("configuration entry %q DN: %w", entry.DN, parseErr)
				}
				configDN, parseErr := directory.ParseDN("cn=config")
				if parseErr != nil {
					return parseErr
				}
				if !configDN.Equal(dn) && !configDN.AncestorOf(dn) {
					return fmt.Errorf(
						"configuration partition entry %q is outside cn=config",
						entry.DN,
					)
				}
				return nil
			}
			return validateRestoreEntry(registry, entry)
		})
	})
}

func restoreRuntimePartitions(
	reader storage.Reader,
	registry *schema.Registry,
) (map[string]struct{}, error) {
	allowed := map[string]struct{}{storage.OpenLDAPConfigPartition: {}}
	configDN, err := directory.ParseDN("cn=config")
	if err != nil {
		return nil, err
	}
	configuredSuffixes := make([]directory.DN, 0)
	err = reader.ForEachIn(storage.OpenLDAPConfigPartition, func(entry directory.Entry) error {
		entryDN, err := directory.ParseDN(entry.DN)
		if err != nil {
			return fmt.Errorf("configuration entry %q DN: %w", entry.DN, err)
		}
		parent, hasParent := entryDN.Parent()
		if !hasParent || !configDN.Equal(parent) {
			return nil
		}
		databaseValues := entry.Values("olcDatabase")
		if len(databaseValues) != 1 {
			return nil
		}
		databaseName := string(databaseValues[0])
		backend := restoreDatabaseType(databaseName)
		if restoreDatabaseUsesLocalStorage(backend) {
			entryUUID := entry.Values("entryUUID")
			var uuid []byte
			if len(entryUUID) == 1 {
				uuid = entryUUID[0]
			}
			allowed[storage.OpenLDAPDatabasePartition(databaseName, uuid)] = struct{}{}
		}
		for _, rawSuffix := range entry.Values("olcSuffix") {
			suffix, err := registry.NormalizeDN(string(rawSuffix))
			if err != nil {
				return fmt.Errorf("%s olcSuffix: %w", entry.DN, err)
			}
			configuredSuffixes = append(configuredSuffixes, suffix)
		}
		if backend == "config" && len(entry.Values("olcSuffix")) == 0 {
			normalized, err := registry.NormalizeDN("cn=config")
			if err != nil {
				return err
			}
			configuredSuffixes = append(configuredSuffixes, normalized)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	namingContexts, err := reader.NamingContexts()
	if err != nil {
		return nil, fmt.Errorf("load naming contexts: %w", err)
	}
	for _, rawContext := range namingContexts {
		legacy, err := directory.ParseDN(rawContext)
		if err != nil {
			return nil, fmt.Errorf("naming context %q: %w", rawContext, err)
		}
		normalized, err := registry.NormalizeDN(rawContext)
		if err != nil {
			return nil, fmt.Errorf("naming context %q: %w", rawContext, err)
		}
		configured := false
		for _, suffix := range configuredSuffixes {
			if suffix.Equal(normalized) {
				configured = true
				break
			}
		}
		if !configured {
			allowed[storage.OpenLDAPBootstrapPartition(legacy)] = struct{}{}
		}
	}
	return allowed, nil
}

func restoreDatabaseType(name string) string {
	value := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(value, "{") {
		if end := strings.IndexByte(value, '}'); end >= 0 {
			value = value[end+1:]
		}
	}
	return value
}

func restoreDatabaseUsesLocalStorage(backend string) bool {
	switch backend {
	case "ldif", "mdb", "wt":
		return true
	default:
		return false
	}
}

func validateRestoreEntry(registry *schema.Registry, entry directory.Entry) error {
	dn, err := registry.NormalizeDN(entry.DN)
	if err != nil {
		return fmt.Errorf("entry %q DN: %w", entry.DN, err)
	}
	if err := registry.ValidateEntry(entry); err != nil {
		return fmt.Errorf("entry %q: %w", entry.DN, err)
	}
	for _, rdnValue := range dn.RDNValues() {
		assertion, err := registry.NormalizeEqualityValue(rdnValue.Type, rdnValue.Value)
		if err != nil {
			return fmt.Errorf("entry %q RDN: %w", entry.DN, err)
		}
		matched := false
		for _, value := range registry.AttributeValues(entry, rdnValue.Type) {
			normalized, normalizeErr := registry.NormalizeEqualityValue(rdnValue.Type, value)
			if normalizeErr != nil {
				return fmt.Errorf("entry %q RDN: %w", entry.DN, normalizeErr)
			}
			if bytes.Equal(assertion, normalized) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf(
				"entry %q RDN attribute %q is missing its naming value",
				entry.DN,
				rdnValue.Type,
			)
		}
	}

	structural, err := registry.StructuralObjectClass(entry)
	if err != nil {
		return fmt.Errorf("entry %q structural object class: %w", entry.DN, err)
	}
	declared := registry.AttributeValues(entry, "structuralObjectClass")
	if len(declared) != 1 {
		return fmt.Errorf(
			"entry %q must declare exactly one structuralObjectClass",
			entry.DN,
		)
	}
	left, leftOK := registry.ObjectClass(string(declared[0]))
	right, rightOK := registry.ObjectClass(structural)
	if !leftOK || !rightOK || left.OID != right.OID {
		return fmt.Errorf(
			"entry %q declares structuralObjectClass %q but resolves to %q",
			entry.DN,
			declared[0],
			structural,
		)
	}
	return nil
}

// restoreIndexSchema supplies the loaded directory schema to the storage
// checker, allowing it to reconstruct every expected posting and detect both
// missing and stale index records.
type restoreIndexSchema struct {
	registry *schema.Registry
}

func (validator restoreIndexSchema) NormalizeDNAttribute(
	attribute string,
	value []byte,
) (string, []byte, error) {
	return validator.registry.NormalizeDNAttribute(attribute, value)
}

func (validator restoreIndexSchema) CanonicalDNAttributeName(attribute string) (string, error) {
	return validator.registry.CanonicalDNAttributeName(attribute)
}

func (validator restoreIndexSchema) EqualityIndexConfiguration() storage.EqualityIndexConfig {
	return storage.EqualityIndexConfig{Version: storage.EqualityIndexFormatVersion}
}

func (validator restoreIndexSchema) ResolveEqualityIndexAttribute(
	description string,
) (string, bool, bool, error) {
	attribute, err := validator.attribute(description)
	if err != nil {
		return "", false, false, err
	}
	return strings.ToLower(attribute.OID), attribute.Equality != "", true, nil
}

func (validator restoreIndexSchema) NormalizeEqualityIndexAssertion(
	description string,
	value []byte,
) ([]byte, error) {
	return validator.registry.NormalizeEqualityAssertion(description, value)
}

func (validator restoreIndexSchema) EqualityIndexValues(
	entry directory.Entry,
	description string,
) ([][]byte, error) {
	values := validator.registry.AttributeValues(entry, description)
	if strings.EqualFold(description, "2.5.4.0") {
		values = validator.expandObjectClasses(values)
	}
	return validator.normalizeValues(description, values)
}

func (validator restoreIndexSchema) ResolveSubstringIndexAttribute(
	description string,
) (string, bool, bool, bool, error) {
	attribute, err := validator.attribute(description)
	if err != nil {
		return "", false, false, false, err
	}
	enabled := attribute.Substring != ""
	return strings.ToLower(attribute.OID), enabled, enabled, enabled, nil
}

func (validator restoreIndexSchema) NormalizeSubstringIndexAssertion(
	description string,
	value directory.Substring,
) (directory.Substring, error) {
	normalize := func(raw []byte) ([]byte, error) {
		return validator.registry.NormalizeEqualityValue(description, raw)
	}
	var result directory.Substring
	var err error
	if value.Initial != nil {
		result.Initial, err = normalize(value.Initial)
		if err != nil {
			return directory.Substring{}, err
		}
	}
	for _, raw := range value.Any {
		normalized, normalizeErr := normalize(raw)
		if normalizeErr != nil {
			return directory.Substring{}, normalizeErr
		}
		result.Any = append(result.Any, normalized)
	}
	if value.Final != nil {
		result.Final, err = normalize(value.Final)
		if err != nil {
			return directory.Substring{}, err
		}
	}
	return result, nil
}

func (validator restoreIndexSchema) SubstringIndexValues(
	entry directory.Entry,
	description string,
) ([][]byte, error) {
	return validator.normalizeValues(
		description,
		validator.registry.AttributeValues(entry, description),
	)
}

func (validator restoreIndexSchema) ResolveOrderingIndexAttribute(
	description string,
) (string, bool, error) {
	attribute, err := validator.attribute(description)
	if err != nil {
		return "", false, err
	}
	return strings.ToLower(attribute.OID), attribute.Ordering != "", nil
}

func (validator restoreIndexSchema) NormalizeOrderingIndexAssertion(
	description string,
	value []byte,
) ([]byte, error) {
	attribute, err := validator.attribute(description)
	if err != nil {
		return nil, err
	}
	return validator.normalizeOrderingValue(attribute, value)
}

func (validator restoreIndexSchema) OrderingIndexValues(
	entry directory.Entry,
	description string,
) ([][]byte, error) {
	attribute, err := validator.attribute(description)
	if err != nil {
		return nil, err
	}
	values := validator.registry.AttributeValues(entry, description)
	result := make([][]byte, 0, len(values))
	for _, value := range values {
		normalized, err := validator.normalizeOrderingValue(attribute, value)
		if err != nil {
			return nil, err
		}
		result = append(result, normalized)
	}
	return result, nil
}

func (validator restoreIndexSchema) ResolveApproximateIndexAttribute(
	description string,
) (string, bool, bool, error) {
	attribute, err := validator.attribute(description)
	if err != nil {
		return "", false, false, err
	}
	_, associated := schema.AssociatedApproximateMatchingRule(attribute.Equality)
	return strings.ToLower(attribute.OID), associated, attribute.Equality != "" && !associated, nil
}

func (validator restoreIndexSchema) ApproximateIndexAssertionTerms(
	description string,
	value []byte,
) ([][]byte, bool, error) {
	attribute, err := validator.attribute(description)
	if err != nil {
		return nil, false, err
	}
	rule, associated := schema.AssociatedApproximateMatchingRule(attribute.Equality)
	if !associated {
		return nil, false, nil
	}
	terms, complete := schema.ApproximateIndexKeys(rule, value)
	return terms, complete, nil
}

func (validator restoreIndexSchema) ApproximateIndexValues(
	entry directory.Entry,
	description string,
) ([][]byte, error) {
	attribute, err := validator.attribute(description)
	if err != nil {
		return nil, err
	}
	rule, associated := schema.AssociatedApproximateMatchingRule(attribute.Equality)
	if !associated {
		return nil, nil
	}
	var result [][]byte
	for _, value := range validator.registry.AttributeValues(entry, description) {
		terms, _ := schema.ApproximateIndexKeys(rule, value)
		result = append(result, terms...)
	}
	return result, nil
}

func (validator restoreIndexSchema) attribute(description string) (schema.AttributeType, error) {
	attribute, found, err := validator.registry.EffectiveAttributeType(description)
	if err != nil {
		return schema.AttributeType{}, err
	}
	if !found {
		return schema.AttributeType{}, fmt.Errorf("undefined attribute type %q", description)
	}
	return attribute, nil
}

func (validator restoreIndexSchema) normalizeValues(
	description string,
	values [][]byte,
) ([][]byte, error) {
	result := make([][]byte, 0, len(values))
	for _, value := range values {
		normalized, err := validator.registry.NormalizeEqualityValue(description, value)
		if err != nil {
			return nil, err
		}
		result = append(result, normalized)
	}
	return result, nil
}

func (validator restoreIndexSchema) expandObjectClasses(values [][]byte) [][]byte {
	result := make([][]byte, 0, len(values))
	seen := make(map[string]struct{})
	var add func(string)
	add = func(identifier string) {
		key := strings.ToLower(strings.TrimSpace(identifier))
		if key == "" {
			return
		}
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		result = append(result, []byte(identifier))
		objectClass, found := validator.registry.ObjectClass(identifier)
		if !found {
			return
		}
		for _, superior := range objectClass.Superiors {
			add(superior)
		}
	}
	for _, value := range values {
		add(string(value))
	}
	return result
}

func (validator restoreIndexSchema) normalizeOrderingValue(
	attribute schema.AttributeType,
	value []byte,
) ([]byte, error) {
	if _, err := validator.registry.CompareOrdering(attribute.OID, "", value, value); err != nil {
		return nil, err
	}
	normalized, err := validator.registry.NormalizeEqualityValue(attribute.OID, value)
	if err != nil {
		return nil, err
	}
	switch canonicalRestoreIndexMatchingRule(attribute.Ordering) {
	case "integerorderingmatch":
		return sortableRestoreLDAPInteger(normalized)
	case "generalizedtimeorderingmatch":
		if len(normalized) == 0 || normalized[len(normalized)-1] != 'Z' {
			return nil, errors.New("invalid normalized generalized time")
		}
		return bytes.Clone(normalized[:len(normalized)-1]), nil
	default:
		return normalized, nil
	}
}

func sortableRestoreLDAPInteger(value []byte) ([]byte, error) {
	integer := new(big.Int)
	if _, ok := integer.SetString(strings.TrimSpace(string(value)), 10); !ok {
		return nil, errors.New("invalid LDAP integer")
	}
	if integer.Sign() == 0 {
		return []byte{1}, nil
	}
	digits := []byte(new(big.Int).Abs(integer).String())
	if uint64(len(digits)) > uint64(^uint32(0)) {
		return nil, errors.New("LDAP integer is too large to index")
	}
	result := make([]byte, 5, 5+len(digits))
	if integer.Sign() > 0 {
		result[0] = 2
		binary.BigEndian.PutUint32(result[1:], uint32(len(digits)))
		return append(result, digits...), nil
	}
	result[0] = 0
	binary.BigEndian.PutUint32(result[1:], ^uint32(len(digits)))
	for _, digit := range digits {
		result = append(result, ^digit)
	}
	return result, nil
}

func canonicalRestoreIndexMatchingRule(rule string) string {
	rule = strings.ToLower(strings.TrimSpace(rule))
	switch rule {
	case "2.5.13.15":
		return "integerorderingmatch"
	case "2.5.13.28":
		return "generalizedtimeorderingmatch"
	default:
		return rule
	}
}
