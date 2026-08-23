package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type runtimeDatabase struct {
	name                  string
	partition             string
	suffixes              []directory.DN
	dnNormalizer          directory.DNAttributeNormalizer
	ldapBackend           *ldapBackendRuntimeConfiguration
	metaBackend           *metaBackendRuntimeConfiguration
	asyncMetaBackend      *asyncMetaBackendRuntimeConfiguration
	passwdBackend         *passwdBackendRuntimeConfiguration
	dnssrvBackend         *dnssrvBackendRuntimeConfiguration
	sockBackend           *sockBackendRuntimeConfiguration
	sockOverlays          []sockOverlayRuntimeConfiguration
	sqlBackend            *sqlBackendRuntimeConfiguration
	metaTargetKey         string
	relay                 *relayRuntimeConfiguration
	rwm                   *rwmRuntimeConfiguration
	rootDN                *directory.DN
	rootPassword          []byte
	rootPasswordSet       bool
	disabled              bool
	hidden                bool
	subordinate           bool
	advertise             bool
	readOnly              bool
	searchSizeLimits      []databaseSearchSizeLimit
	equalityIndexes       storage.EqualityIndexConfig
	equalityIndexInit     *databaseEqualityIndexInitialization
	restrictions          databaseRestrictions
	shadow                bool
	multiProvider         bool
	updateDN              *directory.DN
	updateRefs            []string
	lastMod               bool
	lastBind              bool
	lastBindPrecision     int
	maxDerefDepth         int
	nullBindAllowed       bool
	nullDoSearch          bool
	configDNKey           string
	serverSideSort        bool
	sortMaxKeys           int
	sortLimiter           *serverSideSortLimiter
	syncProvider          bool
	syncCheckpointOps     int
	syncCheckpointMinutes int
	syncSessionLogSize    int
	syncNoPresent         bool
	syncReloadHint        bool
	syncUseSubentry       bool
	syncConsumers         []syncConsumerConfig
	dds                   *ddsRuntimeConfiguration
	ppolicy               *passwordPolicyRuntimeConfiguration
	pbind                 *pbindRuntimeConfiguration
	remoteAuth            *remoteAuthRuntimeConfiguration
	homedir               *homedirRuntimeConfiguration
	chain                 *chainRuntimeConfiguration
	translucent           *translucentRuntimeConfiguration
	pcache                *pcacheRuntimeConfiguration
	otp                   *otpRuntimeConfiguration
	totpPasswords         []totpPasswordRuntimeConfiguration
	autoca                *autoCARuntimeConfiguration
	constraint            *constraintRuntimeConfiguration
	collect               *collectRuntimeConfiguration
	seqmod                *seqmodRuntimeConfiguration
	nestGroups            []nestGroupRuntimeConfiguration
	deref                 bool
	dynlist               *dynlistRuntimeConfiguration
	dyngroup              *dynamicGroupRuntimeConfiguration
	unique                *uniqueRuntimeConfiguration
	valueSort             *valueSortRuntimeConfiguration
	accesslog             *accesslogRuntimeConfiguration
	auditlog              *auditlogRuntimeConfiguration
	retcodes              []retcodeRuntimeConfiguration
	memberOf              []memberOfRuntimeConfiguration
	refint                []refintRuntimeConfiguration
}

type databaseSearchSizeLimit struct {
	selector        databaseSearchLimitSelector
	subject         directory.DN
	soft            int
	hard            int
	softSet         bool
	hardSet         bool
	timeSoft        int
	timeHard        int
	timeSoftSet     bool
	timeHardSet     bool
	unchecked       int
	uncheckedSet    bool
	pageSize        int
	pageSizeSet     bool
	pageNoEstimate  bool
	pageEstimateSet bool
	pageTotal       int
	pageTotalSet    bool
	databaseDefault bool
}

type databaseSearchExecutionLimits struct {
	size           int
	time           int
	unchecked      int
	pageSize       int
	pageNoEstimate bool
	pageTotal      int
	root           bool
}

type databaseSearchLimitSelector uint8

const (
	databaseSearchLimitExact databaseSearchLimitSelector = iota
	databaseSearchLimitOneLevel
	databaseSearchLimitSubtree
	databaseSearchLimitChildren
	databaseSearchLimitAnonymous
	databaseSearchLimitUsers
	databaseSearchLimitAny
)

type databaseRestrictions uint32

const (
	restrictAdd databaseRestrictions = 1 << iota
	restrictBind
	restrictCompare
	restrictDelete
	restrictExtended
	restrictModify
	restrictRename
	restrictSearch
	restrictStartTLS
	restrictPasswordModify
	restrictWhoAmI
	restrictCancel
)

const (
	restrictReads  = restrictCompare | restrictSearch
	restrictWrites = restrictAdd | restrictDelete | restrictModify | restrictRename
	restrictAll    = restrictAdd | restrictBind | restrictCompare | restrictDelete |
		restrictExtended | restrictModify | restrictRename | restrictSearch
	restrictSpecificExtended = restrictStartTLS | restrictPasswordModify |
		restrictWhoAmI | restrictCancel
)

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
	return loadRuntimeDatabasesReaderWithNormalizer(reader, nil)
}

func loadRuntimeDatabasesReaderWithNormalizer(
	reader storage.Reader,
	normalizer directory.DNAttributeNormalizer,
) ([]runtimeDatabase, error) {
	legacyConfigSuffix, err := directory.ParseDN("cn=config")
	if err != nil {
		return nil, err
	}
	configSuffix := legacyConfigSuffix

	var databases []runtimeDatabase
	if err := reader.ForEach(func(entry directory.Entry) error {
		entryDN, err := directory.ParseDN(entry.DN)
		if err != nil {
			return fmt.Errorf("parse entry DN %q: %w", entry.DN, err)
		}
		if !legacyConfigSuffix.Equal(entryDN) &&
			!legacyConfigSuffix.AncestorOf(entryDN) {
			return nil
		}
		parent, hasParent := entryDN.Parent()
		if !hasParent || !legacyConfigSuffix.Equal(parent) {
			// Overlay-owned backends are not local naming-context databases.
			return nil
		}

		databaseValues := entry.Values("olcDatabase")
		if len(databaseValues) == 0 {
			return nil
		}
		if len(databaseValues) != 1 {
			return fmt.Errorf("%s olcDatabase must be single-valued", entry.DN)
		}
		if _, err := requireSupportedRuntimeDatabaseType(
			entry.DN,
			string(databaseValues[0]),
		); err != nil {
			return err
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
			dnNormalizer:  normalizer,
			lastMod:       true,
			maxDerefDepth: defaultAliasDerefDepth,
			configDNKey:   entryDN.Key(),
		}
		if isConfigDatabase(database) {
			// cn=config RDNs use configuration attributes such as olcDatabase
			// that are intentionally outside the content schema registry.
			database.dnNormalizer = nil
		}
		if !isConfigDatabase(database) &&
			!isMonitorDatabase(database) &&
			!isNullDatabase(database) &&
			!isLDAPBackendDatabase(database) &&
			!isMetaBackendDatabase(database) &&
			!isPasswdBackendDatabase(database) &&
			!isDNSSRVBackendDatabase(database) &&
			!isSockBackendDatabase(database) &&
			!isSQLBackendDatabase(database) {
			indexedNormalizer, indexes, err := loadDatabaseEqualityIndexes(
				entry,
				database.dnNormalizer,
			)
			if err != nil {
				return err
			}
			database.equalityIndexes = indexes
			if indexedNormalizer != nil {
				database.dnNormalizer = indexedNormalizer
				database.equalityIndexInit = &databaseEqualityIndexInitialization{}
			}
		}
		for _, rawSuffix := range entry.Values("olcSuffix") {
			suffix, err := parseRuntimeDN(
				string(rawSuffix),
				database.dnNormalizer,
			)
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
				monitor, err := parseRuntimeDN("cn=Monitor", normalizer)
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
			rootDN, err := parseRuntimeDN(
				string(rootDNValues[0]),
				database.dnNormalizer,
			)
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
		database.restrictions, err = parseDatabaseRestrictions(
			entry.Values("olcRestrict"),
		)
		if err != nil {
			return fmt.Errorf("%s olcRestrict: %w", entry.DN, err)
		}
		if database.readOnly {
			database.restrictions |= restrictWrites
		}
		database.readOnly = databaseIsReadOnly(database)
		database.searchSizeLimits, err = loadDatabaseSearchSizeLimitsWithNormalizer(
			entry,
			database.dnNormalizer,
		)
		if err != nil {
			return err
		}
		defaultTimeLimit, present, err := loadDatabaseDefaultTimeLimit(entry)
		if err != nil {
			return err
		}
		if present {
			database.searchSizeLimits = append(
				database.searchSizeLimits,
				defaultTimeLimit,
			)
		}
		defaultSizeLimit, present, err := loadDatabaseDefaultSizeLimit(entry)
		if err != nil {
			return err
		}
		if present {
			database.searchSizeLimits = append(
				database.searchSizeLimits,
				defaultSizeLimit,
			)
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
		database.syncUseSubentry, _, err = singleBoolean(entry, "olcSyncUseSubentry")
		if err != nil {
			return err
		}
		database.lastBind, _, err = singleBoolean(entry, "olcLastBind")
		if err != nil {
			return err
		}
		database.lastBindPrecision, err = singleNonnegativeInteger(
			entry,
			"olcLastBindPrecision",
			0,
		)
		if err != nil {
			return err
		}
		database.maxDerefDepth, err = singleNonnegativeInteger(
			entry,
			"olcMaxDerefDepth",
			defaultAliasDerefDepth,
		)
		if err != nil {
			return err
		}
		if isNullDatabase(database) {
			database.nullBindAllowed, _, err = singleBoolean(
				entry,
				"olcDbBindAllowed",
			)
			if err != nil {
				return err
			}
			database.nullDoSearch, _, err = singleBoolean(
				entry,
				"olcDbDoSearch",
			)
			if err != nil {
				return err
			}
		}
		if isRelayDatabase(database) {
			relay, err := loadRelayRuntimeConfiguration(entry, database)
			if err != nil {
				return err
			}
			database.relay = relay
		}
		if isLDAPBackendDatabase(database) {
			configuration, err := loadLDAPBackendRuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			database.ldapBackend = configuration
			// A proxy database never owns a local data partition.
			database.partition = ""
		}
		if isMetaBackendDatabase(database) {
			configuration, err := loadMetaBackendRuntimeConfigurationWithNormalizer(
				reader,
				entry,
				normalizer,
			)
			if err != nil {
				return err
			}
			database.metaBackend = configuration
			// A meta proxy database never owns a local data partition.
			database.partition = ""
		}
		if isAsyncMetaBackendDatabase(database) {
			configuration, err := loadAsyncMetaBackendRuntimeConfigurationWithNormalizer(
				reader,
				entry,
				normalizer,
			)
			if err != nil {
				return err
			}
			database.asyncMetaBackend = configuration
			database.metaBackend = configuration.meta
			database.partition = ""
		}
		if isPasswdBackendDatabase(database) {
			configuration, err := loadPasswdBackendRuntimeConfiguration(entry, database)
			if err != nil {
				return err
			}
			database.passwdBackend = configuration
			database.partition = ""
		}
		if isDNSSRVBackendDatabase(database) {
			configuration, err := loadDNSSRVBackendRuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			database.dnssrvBackend = configuration
			database.partition = ""
		}
		if isSockBackendDatabase(database) {
			configuration, err := loadSockBackendRuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			database.sockBackend = configuration
			// A socket backend delegates all data operations to an external
			// process and therefore owns no local storage partition.
			database.partition = ""
		}
		if isSQLBackendDatabase(database) {
			configuration, err := loadSQLBackendRuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			configuration.collectivePlanKey = database.configDNKey
			database.sqlBackend = configuration
			// back-sql stores directory entries in the configured SQL database.
			database.partition = ""
		}
		database.syncConsumers, err = loadSyncConsumerConfigs(entry, database)
		if err != nil {
			return err
		}
		if err := loadRuntimeShadowSettings(entry, &database); err != nil {
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
	if err := validateSyncConsumerRIDs(databases); err != nil {
		return nil, err
	}
	if err := loadRuntimeDatabaseOverlays(reader, databases); err != nil {
		return nil, err
	}
	if err := resolveRelayDatabases(databases); err != nil {
		return nil, err
	}
	if err := resolveAccesslogDatabases(databases); err != nil {
		return nil, err
	}
	if err := validateDatabasePartitions(databases); err != nil {
		return nil, err
	}

	for _, rawContext := range namingContexts {
		legacyContextDN, err := directory.ParseDN(rawContext)
		if err != nil {
			return nil, fmt.Errorf("parse naming context %q: %w", rawContext, err)
		}
		contextDN := legacyContextDN
		contextNormalizer := normalizer
		if legacyConfigSuffix.Equal(legacyContextDN) ||
			legacyConfigSuffix.AncestorOf(legacyContextDN) {
			contextNormalizer = nil
		} else {
			contextDN, err = parseRuntimeDN(rawContext, normalizer)
			if err != nil {
				return nil, fmt.Errorf("normalize naming context %q: %w", rawContext, err)
			}
		}
		if databaseHasSuffix(databases, contextDN) {
			continue
		}
		databases = append(databases, runtimeDatabase{
			name:          "bootstrap",
			partition:     storage.OpenLDAPBootstrapPartition(legacyContextDN),
			suffixes:      []directory.DN{contextDN},
			dnNormalizer:  contextNormalizer,
			lastMod:       true,
			maxDerefDepth: defaultAliasDerefDepth,
		})
	}
	applyFrontendDatabaseDefaults(databases)
	return databases, nil
}

type databaseEqualityIndexRegistry interface {
	directory.DNAttributeNormalizer
	directory.DNAttributeCanonicalNamer
	EffectiveAttributeType(string) (schema.AttributeType, bool, error)
	NormalizeEqualityValue(string, []byte) ([]byte, error)
	NormalizeEqualityAssertion(string, []byte) ([]byte, error)
	CompareOrdering(string, string, []byte, []byte) (int, error)
	AttributeValues(directory.Entry, string) [][]byte
	ObjectClass(string) (schema.ObjectClass, bool)
}

type databaseEqualityIndexInitialization struct {
	mu    sync.Mutex
	ready bool
}

type databaseEqualityIndexNormalizer struct {
	registry databaseEqualityIndexRegistry
	config   storage.EqualityIndexConfig
}

func (normalizer *databaseEqualityIndexNormalizer) NormalizeDNAttribute(
	attributeType string,
	value []byte,
) (string, []byte, error) {
	return normalizer.registry.NormalizeDNAttribute(attributeType, value)
}

func (normalizer *databaseEqualityIndexNormalizer) CanonicalDNAttributeName(
	attributeType string,
) (string, error) {
	return normalizer.registry.CanonicalDNAttributeName(attributeType)
}

func (normalizer *databaseEqualityIndexNormalizer) EqualityIndexConfiguration() storage.EqualityIndexConfig {
	config := normalizer.config
	config.Attributes = append(
		[]storage.EqualityIndexAttribute(nil),
		config.Attributes...,
	)
	return config
}

func (normalizer *databaseEqualityIndexNormalizer) ResolveEqualityIndexAttribute(
	description string,
) (canonical string, equality, presence bool, err error) {
	canonical, configured, found, err := normalizer.resolveIndexAttribute(description)
	if err != nil || !found {
		return canonical, false, false, err
	}
	return canonical, configured.Equality, configured.Presence, nil
}

func (normalizer *databaseEqualityIndexNormalizer) ResolveApproximateIndexAttribute(
	description string,
) (canonical string, approximate, equalityFallback bool, err error) {
	canonical, configured, found, err := normalizer.resolveIndexAttribute(description)
	if err != nil || !found {
		return canonical, false, false, err
	}
	attribute, typeFound, err := normalizer.registry.EffectiveAttributeType(description)
	if err != nil || !typeFound {
		return canonical, false, false, err
	}
	_, hasAssociatedApproximateRule := openLDAPApproximateMatchingRule(attribute.Equality)
	return canonical,
		configured.Approximate && hasAssociatedApproximateRule,
		configured.Equality && !hasAssociatedApproximateRule,
		nil
}

func (normalizer *databaseEqualityIndexNormalizer) ApproximateIndexAssertionTerms(
	description string,
	value []byte,
) ([][]byte, bool, error) {
	_, configured, found, err := normalizer.resolveIndexAttribute(description)
	if err != nil || !found || !configured.Approximate {
		return nil, false, err
	}
	keys, complete := schema.ApproximateIndexKeys(configured.ApproximateRule, value)
	return keys, complete, nil
}

func (normalizer *databaseEqualityIndexNormalizer) ApproximateIndexValues(
	entry directory.Entry,
	canonicalAttribute string,
) ([][]byte, error) {
	configured, found := normalizer.indexAttributeDefinition(canonicalAttribute)
	if !found || !configured.Approximate {
		return nil, nil
	}
	values := normalizer.registry.AttributeValues(entry, canonicalAttribute)
	var result [][]byte
	for _, value := range values {
		keys, _ := schema.ApproximateIndexKeys(configured.ApproximateRule, value)
		result = append(result, keys...)
	}
	return result, nil
}

func (normalizer *databaseEqualityIndexNormalizer) NormalizeEqualityIndexAssertion(
	description string,
	value []byte,
) ([]byte, error) {
	return normalizer.registry.NormalizeEqualityAssertion(description, value)
}

func (normalizer *databaseEqualityIndexNormalizer) EqualityIndexValues(
	entry directory.Entry,
	canonicalAttribute string,
) ([][]byte, error) {
	values := normalizer.registry.AttributeValues(entry, canonicalAttribute)
	if canonicalAttribute == "2.5.4.0" {
		values = normalizer.expandObjectClassIndexValues(values)
	}
	result := make([][]byte, 0, len(values))
	for _, value := range values {
		normalized, err := normalizer.registry.NormalizeEqualityValue(
			canonicalAttribute,
			value,
		)
		if err != nil {
			return nil, err
		}
		result = append(result, normalized)
	}
	return result, nil
}

func (normalizer *databaseEqualityIndexNormalizer) ResolveSubstringIndexAttribute(
	description string,
) (canonical string, initial, any, final bool, err error) {
	canonical, configured, found, err := normalizer.resolveIndexAttribute(description)
	if err != nil || !found {
		return canonical, false, false, false, err
	}
	return canonical, configured.SubstringInitial, configured.SubstringAny, configured.SubstringFinal, nil
}

func (normalizer *databaseEqualityIndexNormalizer) NormalizeSubstringIndexAssertion(
	description string,
	value directory.Substring,
) (directory.Substring, error) {
	normalize := func(raw []byte) ([]byte, error) {
		return normalizer.registry.NormalizeEqualityValue(description, raw)
	}
	var result directory.Substring
	var err error
	if value.Initial != nil {
		result.Initial, err = normalize(value.Initial)
		if err != nil {
			return directory.Substring{}, err
		}
	}
	result.Any = make([][]byte, 0, len(value.Any))
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

func (normalizer *databaseEqualityIndexNormalizer) SubstringIndexValues(
	entry directory.Entry,
	canonicalAttribute string,
) ([][]byte, error) {
	return normalizer.normalizeIndexValues(entry, canonicalAttribute, false)
}

func (normalizer *databaseEqualityIndexNormalizer) ResolveOrderingIndexAttribute(
	description string,
) (canonical string, ordering bool, err error) {
	canonical, configured, found, err := normalizer.resolveIndexAttribute(description)
	if err != nil || !found {
		return canonical, false, err
	}
	return canonical, configured.Ordering, nil
}

func (normalizer *databaseEqualityIndexNormalizer) resolveIndexAttribute(
	description string,
) (string, storage.EqualityIndexAttribute, bool, error) {
	canonical, base, attribute, err := canonicalDatabaseIndexAttributeDescription(
		normalizer.registry,
		description,
	)
	if err != nil {
		return "", storage.EqualityIndexAttribute{}, false, err
	}
	if configured, found := normalizer.indexAttributeDefinition(canonical); found {
		return canonical, configured, true, nil
	}
	if canonical != base {
		if configured, found := normalizer.indexAttributeDefinition(base); found && !configured.NoTags {
			return base, configured, true, nil
		}
	}
	for attribute.Superior != "" {
		superior, found, err := normalizer.registry.EffectiveAttributeType(attribute.Superior)
		if err != nil {
			return "", storage.EqualityIndexAttribute{}, false, err
		}
		if !found {
			break
		}
		key := strings.ToLower(superior.OID)
		if configured, configuredFound := normalizer.indexAttributeDefinition(key); configuredFound && !configured.NoSubtypes {
			return key, configured, true, nil
		}
		attribute = superior
	}
	return canonical, storage.EqualityIndexAttribute{}, false, nil
}

func (normalizer *databaseEqualityIndexNormalizer) indexAttributeDefinition(
	canonical string,
) (storage.EqualityIndexAttribute, bool) {
	index := sort.Search(len(normalizer.config.Attributes), func(index int) bool {
		return normalizer.config.Attributes[index].Attribute >= canonical
	})
	if index >= len(normalizer.config.Attributes) ||
		normalizer.config.Attributes[index].Attribute != canonical {
		return storage.EqualityIndexAttribute{}, false
	}
	return normalizer.config.Attributes[index], true
}

func (normalizer *databaseEqualityIndexNormalizer) NormalizeOrderingIndexAssertion(
	description string,
	value []byte,
) ([]byte, error) {
	attribute, found, err := normalizer.registry.EffectiveAttributeType(description)
	if err != nil || !found {
		if err == nil {
			err = fmt.Errorf("undefined attribute type %q", description)
		}
		return nil, err
	}
	return normalizer.normalizeOrderingIndexValue(attribute, value)
}

func (normalizer *databaseEqualityIndexNormalizer) OrderingIndexValues(
	entry directory.Entry,
	canonicalAttribute string,
) ([][]byte, error) {
	attribute, found, err := normalizer.registry.EffectiveAttributeType(canonicalAttribute)
	if err != nil || !found {
		if err == nil {
			err = fmt.Errorf("undefined attribute type %q", canonicalAttribute)
		}
		return nil, err
	}
	values := normalizer.registry.AttributeValues(entry, canonicalAttribute)
	result := make([][]byte, 0, len(values))
	for _, value := range values {
		normalized, err := normalizer.normalizeOrderingIndexValue(attribute, value)
		if err != nil {
			return nil, err
		}
		result = append(result, normalized)
	}
	return result, nil
}

func (normalizer *databaseEqualityIndexNormalizer) normalizeIndexValues(
	entry directory.Entry,
	canonicalAttribute string,
	expandObjectClass bool,
) ([][]byte, error) {
	values := normalizer.registry.AttributeValues(entry, canonicalAttribute)
	if expandObjectClass && canonicalAttribute == "2.5.4.0" {
		values = normalizer.expandObjectClassIndexValues(values)
	}
	result := make([][]byte, 0, len(values))
	for _, value := range values {
		normalized, err := normalizer.registry.NormalizeEqualityValue(canonicalAttribute, value)
		if err != nil {
			return nil, err
		}
		result = append(result, normalized)
	}
	return result, nil
}

func (normalizer *databaseEqualityIndexNormalizer) normalizeOrderingIndexValue(
	attribute schema.AttributeType,
	value []byte,
) ([]byte, error) {
	if _, err := normalizer.registry.CompareOrdering(attribute.OID, "", value, value); err != nil {
		return nil, err
	}
	normalized, err := normalizer.registry.NormalizeEqualityValue(attribute.OID, value)
	if err != nil {
		return nil, err
	}
	switch canonicalIndexMatchingRule(attribute.Ordering) {
	case "integerorderingmatch":
		return sortableLDAPInteger(normalized)
	case "generalizedtimeorderingmatch":
		if len(normalized) == 0 || normalized[len(normalized)-1] != 'Z' {
			return nil, errors.New("invalid normalized generalized time")
		}
		// The schema comparator orders normalized generalizedTime values after
		// removing the terminal Z. Keeping it would place fractional seconds
		// before the corresponding whole second in the byte-sorted index.
		return bytes.Clone(normalized[:len(normalized)-1]), nil
	default:
		return normalized, nil
	}
}

func sortableLDAPInteger(value []byte) ([]byte, error) {
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

func canonicalIndexMatchingRule(rule string) string {
	rule = strings.ToLower(strings.TrimSpace(rule))
	switch rule {
	case "2.5.13.2":
		return "caseignorematch"
	case "2.5.13.3":
		return "caseignoreorderingmatch"
	case "2.5.13.4":
		return "caseignoresubstringsmatch"
	case "2.5.13.5":
		return "caseexactmatch"
	case "2.5.13.6":
		return "caseexactorderingmatch"
	case "2.5.13.7":
		return "caseexactsubstringsmatch"
	case "2.5.13.8":
		return "numericstringmatch"
	case "2.5.13.9":
		return "numericstringorderingmatch"
	case "2.5.13.10":
		return "numericstringsubstringsmatch"
	case "2.5.13.14":
		return "integermatch"
	case "2.5.13.15":
		return "integerorderingmatch"
	case "2.5.13.17":
		return "octetstringmatch"
	case "2.5.13.18":
		return "octetstringorderingmatch"
	case "2.5.13.20":
		return "telephonenumbermatch"
	case "2.5.13.21":
		return "telephonenumbersubstringsmatch"
	case "2.5.13.27":
		return "generalizedtimematch"
	case "2.5.13.28":
		return "generalizedtimeorderingmatch"
	case "1.3.6.1.4.1.1466.109.114.1":
		return "caseexactia5match"
	case "1.3.6.1.4.1.1466.109.114.2":
		return "caseignoreia5match"
	case "1.3.6.1.1.16.2":
		return "uuidmatch"
	case "1.3.6.1.1.16.3":
		return "uuidorderingmatch"
	case "1.3.6.1.4.1.4203.666.11.2.2":
		return "csnmatch"
	case "1.3.6.1.4.1.4203.666.11.2.3":
		return "csnorderingmatch"
	default:
		return rule
	}
}

func substringIndexRulesEquivalent(equality, substring string) bool {
	equality = canonicalIndexMatchingRule(equality)
	substring = canonicalIndexMatchingRule(substring)
	pairs := map[string]string{
		"caseignoresubstringsmatch":      "caseignorematch",
		"caseexactsubstringsmatch":       "caseexactmatch",
		"caseignoreia5substringsmatch":   "caseignoreia5match",
		"caseexactia5substringsmatch":    "caseexactia5match",
		"numericstringsubstringsmatch":   "numericstringmatch",
		"telephonenumbersubstringsmatch": "telephonenumbermatch",
	}
	return pairs[substring] == equality
}

func orderingIndexRulesEquivalent(equality, ordering string) bool {
	equality = canonicalIndexMatchingRule(equality)
	ordering = canonicalIndexMatchingRule(ordering)
	pairs := map[string]string{
		"caseignoreorderingmatch":      "caseignorematch",
		"caseignoreia5orderingmatch":   "caseignoreia5match",
		"caseexactorderingmatch":       "caseexactmatch",
		"caseexactia5orderingmatch":    "caseexactia5match",
		"numericstringorderingmatch":   "numericstringmatch",
		"octetstringorderingmatch":     "octetstringmatch",
		"integerorderingmatch":         "integermatch",
		"uuidorderingmatch":            "uuidmatch",
		"generalizedtimeorderingmatch": "generalizedtimematch",
		"csnorderingmatch":             "csnmatch",
	}
	return pairs[ordering] == equality
}

func openLDAPApproximateMatchingRule(equality string) (string, bool) {
	return schema.AssociatedApproximateMatchingRule(equality)
}

func (normalizer *databaseEqualityIndexNormalizer) expandObjectClassIndexValues(
	values [][]byte,
) [][]byte {
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
		objectClass, found := normalizer.registry.ObjectClass(identifier)
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

func loadDatabaseEqualityIndexes(
	entry directory.Entry,
	normalizer directory.DNAttributeNormalizer,
) (directory.DNAttributeNormalizer, storage.EqualityIndexConfig, error) {
	values := entry.Values("olcDbIndex")
	if len(values) == 0 {
		return normalizer, storage.EqualityIndexConfig{}, nil
	}
	registry, ok := normalizer.(databaseEqualityIndexRegistry)
	if !ok {
		return nil, storage.EqualityIndexConfig{}, fmt.Errorf(
			"%s olcDbIndex requires a schema registry",
			entry.DN,
		)
	}
	directives, err := orderedDatabaseIndexDirectives(values)
	if err != nil {
		return nil, storage.EqualityIndexConfig{}, fmt.Errorf(
			"%s olcDbIndex: %w",
			entry.DN,
			err,
		)
	}
	byAttribute := make(map[string]storage.EqualityIndexAttribute)
	definedAttributes := make(map[string]string)
	var defaultModes databaseIndexModes
	for _, value := range directives {
		arguments, err := tokenizeOpenLDAPConfig(value)
		if err != nil {
			return nil, storage.EqualityIndexConfig{}, fmt.Errorf(
				"%s olcDbIndex: %w",
				entry.DN,
				err,
			)
		}
		if len(arguments) < 1 {
			return nil, storage.EqualityIndexConfig{}, fmt.Errorf(
				"%s olcDbIndex requires attributes",
				entry.DN,
			)
		}
		var modes databaseIndexModes
		for _, argument := range arguments[1:] {
			for _, indexType := range strings.Split(argument, ",") {
				switch strings.ToLower(strings.TrimSpace(indexType)) {
				case "eq":
					modes.equality = true
				case "pres":
					modes.presence = true
				case "sub":
					modes.substringInitial = true
					modes.substringAny = true
					modes.substringFinal = true
				case "subinitial":
					modes.substringInitial = true
				case "subany":
					modes.substringAny = true
				case "subfinal":
					modes.substringFinal = true
				case "ordering":
					modes.ordering = true
				case "":
				case "approx":
					modes.approximate = true
				case "nolang", "notags":
					// slap_str2index maps the legacy nolang spelling to NOTAGS.
					modes.noTags = true
				case "nosubtypes":
					modes.noSubtypes = true
				default:
					return nil, storage.EqualityIndexConfig{}, fmt.Errorf(
						"%s olcDbIndex has unknown index type %q",
						entry.DN,
						indexType,
					)
				}
			}
		}
		if len(arguments) == 1 {
			modes = defaultModes
		}
		if !modes.enabled() {
			return nil, storage.EqualityIndexConfig{}, fmt.Errorf(
				"%s olcDbIndex has no indexes selected",
				entry.DN,
			)
		}
		for _, description := range strings.Split(arguments[0], ",") {
			description = strings.TrimSpace(description)
			if strings.EqualFold(description, "default") {
				defaultModes.merge(modes)
				continue
			}
			canonicalDescription, _, attribute, err := canonicalDatabaseIndexAttributeDescription(
				registry,
				description,
			)
			if err != nil {
				return nil, storage.EqualityIndexConfig{}, fmt.Errorf(
					"%s olcDbIndex attribute %q: %w",
					entry.DN,
					description,
					err,
				)
			}
			if modes.equality && attribute.Equality == "" {
				return nil, storage.EqualityIndexConfig{}, fmt.Errorf(
					"%s olcDbIndex attribute %q has no equality matching rule",
					entry.DN,
					description,
				)
			}
			hasSubstring := modes.substringInitial || modes.substringAny || modes.substringFinal
			if hasSubstring {
				if attribute.Substring == "" {
					return nil, storage.EqualityIndexConfig{}, fmt.Errorf(
						"%s olcDbIndex attribute %q has no substring matching rule",
						entry.DN,
						description,
					)
				}
				if !substringIndexRulesEquivalent(attribute.Equality, attribute.Substring) {
					return nil, storage.EqualityIndexConfig{}, fmt.Errorf(
						"%s olcDbIndex attribute %q substring rule %q cannot be indexed without changing matching semantics",
						entry.DN,
						description,
						attribute.Substring,
					)
				}
			}
			if modes.ordering {
				if attribute.Ordering == "" {
					return nil, storage.EqualityIndexConfig{}, fmt.Errorf(
						"%s olcDbIndex attribute %q has no ordering matching rule",
						entry.DN,
						description,
					)
				}
				if !orderingIndexRulesEquivalent(attribute.Equality, attribute.Ordering) {
					return nil, storage.EqualityIndexConfig{}, fmt.Errorf(
						"%s olcDbIndex attribute %q ordering rule %q has no proven sortable normalization",
						entry.DN,
						description,
						attribute.Ordering,
					)
				}
			}
			approximateRule := ""
			if modes.approximate {
				var found bool
				approximateRule, found = openLDAPApproximateMatchingRule(attribute.Equality)
				if !found {
					return nil, storage.EqualityIndexConfig{}, fmt.Errorf(
						"%s olcDbIndex attribute %q has no OpenLDAP 2.6.13 associated approximate matching rule; back-mdb disallows this approx index",
						entry.DN,
						description,
					)
				}
			}
			key := canonicalDescription
			if previous, duplicate := definedAttributes[key]; duplicate {
				return nil, storage.EqualityIndexConfig{}, fmt.Errorf(
					"%s olcDbIndex duplicate index definition for attr %q (already defined as %q)",
					entry.DN,
					description,
					previous,
				)
			}
			definedAttributes[key] = description
			configured := byAttribute[key]
			configured.Attribute = key
			if attribute.Equality != "" {
				configured.EqualityRule = canonicalIndexMatchingRule(attribute.Equality)
			}
			if hasSubstring {
				configured.SubstringRule = canonicalIndexMatchingRule(attribute.Substring)
			}
			if modes.ordering {
				configured.OrderingRule = canonicalIndexMatchingRule(attribute.Ordering)
			}
			if modes.approximate {
				configured.ApproximateRule = approximateRule
			}
			configured.Equality = configured.Equality || modes.equality
			configured.Presence = configured.Presence || modes.presence
			configured.Approximate = configured.Approximate || modes.approximate
			configured.SubstringInitial = configured.SubstringInitial || modes.substringInitial
			configured.SubstringAny = configured.SubstringAny || modes.substringAny
			configured.SubstringFinal = configured.SubstringFinal || modes.substringFinal
			configured.Ordering = configured.Ordering || modes.ordering
			configured.NoTags = configured.NoTags || modes.noTags
			configured.NoSubtypes = configured.NoSubtypes || modes.noSubtypes
			byAttribute[key] = configured
		}
	}
	config := storage.EqualityIndexConfig{Version: storage.EqualityIndexFormatVersion}
	for _, attribute := range byAttribute {
		config.Attributes = append(config.Attributes, attribute)
	}
	sort.Slice(config.Attributes, func(left, right int) bool {
		return config.Attributes[left].Attribute < config.Attributes[right].Attribute
	})
	return &databaseEqualityIndexNormalizer{
		registry: registry,
		config:   config,
	}, config, nil
}

type databaseIndexModes struct {
	equality         bool
	presence         bool
	approximate      bool
	substringInitial bool
	substringAny     bool
	substringFinal   bool
	ordering         bool
	noTags           bool
	noSubtypes       bool
}

func (modes databaseIndexModes) enabled() bool {
	return modes.equality || modes.presence || modes.approximate ||
		modes.substringInitial || modes.substringAny || modes.substringFinal ||
		modes.ordering || modes.noTags || modes.noSubtypes
}

func (modes *databaseIndexModes) merge(other databaseIndexModes) {
	modes.equality = modes.equality || other.equality
	modes.presence = modes.presence || other.presence
	modes.approximate = modes.approximate || other.approximate
	modes.substringInitial = modes.substringInitial || other.substringInitial
	modes.substringAny = modes.substringAny || other.substringAny
	modes.substringFinal = modes.substringFinal || other.substringFinal
	modes.ordering = modes.ordering || other.ordering
	modes.noTags = modes.noTags || other.noTags
	modes.noSubtypes = modes.noSubtypes || other.noSubtypes
}

func canonicalDatabaseIndexAttributeDescription(
	registry databaseEqualityIndexRegistry,
	description string,
) (canonical, base string, attribute schema.AttributeType, err error) {
	parts := strings.Split(strings.TrimSpace(description), ";")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return "", "", schema.AttributeType{}, errors.New("empty AttributeDescription")
	}
	attribute, found, err := registry.EffectiveAttributeType(strings.TrimSpace(parts[0]))
	if err != nil {
		return "", "", schema.AttributeType{}, err
	}
	if !found {
		return "", "", schema.AttributeType{}, fmt.Errorf("undefined attribute type %q", parts[0])
	}
	base = strings.ToLower(attribute.OID)
	if len(parts) == 1 {
		return base, base, attribute, nil
	}
	options := make([]string, 0, len(parts)-1)
	seen := make(map[string]struct{}, len(parts)-1)
	for _, raw := range parts[1:] {
		option := strings.ToLower(strings.TrimSpace(raw))
		if !validDatabaseIndexAttributeOption(option) {
			return "", "", schema.AttributeType{}, fmt.Errorf("invalid attribute option %q", raw)
		}
		if _, duplicate := seen[option]; duplicate {
			continue
		}
		seen[option] = struct{}{}
		options = append(options, option)
	}
	sort.Strings(options)
	return base + ";" + strings.Join(options, ";"), base, attribute, nil
}

func validDatabaseIndexAttributeOption(option string) bool {
	if option == "" {
		return false
	}
	for index, character := range option {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' && index > 0 ||
			character == '-' && index > 0 {
			continue
		}
		return false
	}
	return true
}

type orderedDatabaseIndexDirective struct {
	value    string
	order    int
	position int
	ordered  bool
}

func orderedDatabaseIndexDirectives(values [][]byte) ([]string, error) {
	directives := make([]orderedDatabaseIndexDirective, 0, len(values))
	allOrdered := len(values) > 0
	seenOrders := make(map[int]struct{}, len(values))
	for position, raw := range values {
		value, order, ordered, err := parseOrderedDatabaseIndexPrefix(string(raw))
		if err != nil {
			return nil, err
		}
		if ordered {
			if _, duplicate := seenOrders[order]; duplicate {
				return nil, fmt.Errorf("duplicate ordered prefix {%d}", order)
			}
			seenOrders[order] = struct{}{}
		} else {
			allOrdered = false
		}
		directives = append(directives, orderedDatabaseIndexDirective{
			value: value, order: order, position: position, ordered: ordered,
		})
	}
	if allOrdered {
		sort.SliceStable(directives, func(left, right int) bool {
			return directives[left].order < directives[right].order
		})
	}
	result := make([]string, len(directives))
	for index := range directives {
		result[index] = directives[index].value
	}
	return result, nil
}

func stripOrderedDatabaseIndexPrefix(value string) (string, error) {
	value, _, _, err := parseOrderedDatabaseIndexPrefix(value)
	return value, err
}

func parseOrderedDatabaseIndexPrefix(value string) (string, int, bool, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{") {
		return value, 0, false, nil
	}
	end := strings.IndexByte(value, '}')
	if end <= 1 {
		return "", 0, false, errors.New("invalid ordered prefix")
	}
	order, err := strconv.Atoi(value[1:end])
	if err != nil || order < 0 {
		return "", 0, false, errors.New("invalid ordered prefix")
	}
	return strings.TrimSpace(value[end+1:]), order, true, nil
}

func loadDatabaseSearchSizeLimits(
	entry directory.Entry,
) ([]databaseSearchSizeLimit, error) {
	return loadDatabaseSearchSizeLimitsWithNormalizer(entry, nil)
}

func loadDatabaseSearchSizeLimitsWithNormalizer(
	entry directory.Entry,
	normalizer directory.DNAttributeNormalizer,
) ([]databaseSearchSizeLimit, error) {
	var limits []databaseSearchSizeLimit
	for _, raw := range entry.Values("olcLimits") {
		value := strings.TrimSpace(string(raw))
		if strings.HasPrefix(value, "{") {
			end := strings.IndexByte(value, '}')
			if end <= 1 {
				return nil, fmt.Errorf("%s olcLimits has invalid ordered prefix", entry.DN)
			}
			if _, err := strconv.Atoi(value[1:end]); err != nil {
				return nil, fmt.Errorf("%s olcLimits has invalid ordered prefix", entry.DN)
			}
			value = strings.TrimSpace(value[end+1:])
		}
		arguments, err := tokenizeOpenLDAPConfig(value)
		if err != nil {
			return nil, fmt.Errorf("%s olcLimits: %w", entry.DN, err)
		}
		if len(arguments) < 2 {
			return nil, fmt.Errorf("%s olcLimits requires a pattern and limits", entry.DN)
		}

		limit, supported, err := parseDatabaseSearchLimitSelector(
			arguments[0],
			normalizer,
		)
		if err != nil {
			return nil, fmt.Errorf("%s olcLimits subject: %w", entry.DN, err)
		}
		if !supported {
			return nil, fmt.Errorf(
				"%s olcLimits selector %q is not supported",
				entry.DN,
				arguments[0],
			)
		}
		for _, argument := range arguments[1:] {
			name, rawValue, found := strings.Cut(argument, "=")
			if !found {
				return nil, fmt.Errorf("%s olcLimits has invalid value %q", entry.DN, argument)
			}
			switch strings.ToLower(name) {
			case "size":
				parsed, err := parseDatabaseSearchSizeLimit(rawValue, false)
				if err != nil {
					return nil, fmt.Errorf("%s olcLimits %s: %w", entry.DN, name, err)
				}
				limit.soft, limit.softSet = parsed, true
				limit.hard, limit.hardSet = 0, true
			case "size.soft":
				parsed, err := parseDatabaseSearchSizeLimit(rawValue, false)
				if err != nil {
					return nil, fmt.Errorf("%s olcLimits %s: %w", entry.DN, name, err)
				}
				limit.soft, limit.softSet = parsed, true
			case "size.hard":
				parsed, err := parseDatabaseSearchSizeLimit(rawValue, true)
				if err != nil {
					return nil, fmt.Errorf("%s olcLimits %s: %w", entry.DN, name, err)
				}
				limit.hard, limit.hardSet = parsed, true
			case "time":
				parsed, err := parseDatabaseSearchTimeLimit(rawValue, false)
				if err != nil {
					return nil, fmt.Errorf("%s olcLimits %s: %w", entry.DN, name, err)
				}
				limit.timeSoft, limit.timeSoftSet = parsed, true
				limit.timeHard, limit.timeHardSet = 0, true
			case "time.soft":
				parsed, err := parseDatabaseSearchTimeLimit(rawValue, false)
				if err != nil {
					return nil, fmt.Errorf("%s olcLimits %s: %w", entry.DN, name, err)
				}
				limit.timeSoft, limit.timeSoftSet = parsed, true
			case "time.hard":
				parsed, err := parseDatabaseSearchTimeLimit(rawValue, true)
				if err != nil {
					return nil, fmt.Errorf("%s olcLimits %s: %w", entry.DN, name, err)
				}
				limit.timeHard, limit.timeHardSet = parsed, true
			case "size.unchecked", "size.pr", "size.prtotal":
				if err := applyDatabaseAuxiliarySizeLimit(
					&limit,
					name,
					rawValue,
				); err != nil {
					return nil, fmt.Errorf(
						"%s olcLimits %s: %w",
						entry.DN,
						name,
						err,
					)
				}
			default:
				return nil, fmt.Errorf(
					"%s olcLimits has unknown field %q",
					entry.DN,
					name,
				)
			}
		}
		if databaseSearchLimitHasValues(limit) {
			limits = append(limits, limit)
		}
	}
	return limits, nil
}

func parseDatabaseSearchLimitSelector(
	pattern string,
	normalizer directory.DNAttributeNormalizer,
) (databaseSearchSizeLimit, bool, error) {
	trimmed := strings.TrimSpace(pattern)
	lower := strings.ToLower(trimmed)
	switch lower {
	case "*":
		return databaseSearchSizeLimit{selector: databaseSearchLimitAny}, true, nil
	case "anonymous", "dn.anonymous":
		return databaseSearchSizeLimit{selector: databaseSearchLimitAnonymous}, true, nil
	case "users":
		return databaseSearchSizeLimit{selector: databaseSearchLimitUsers}, true, nil
	}

	separator := strings.IndexByte(trimmed, '=')
	if separator < 0 {
		return databaseSearchSizeLimit{}, false, nil
	}
	modifier := strings.ToLower(strings.TrimSpace(trimmed[:separator]))
	rawDN := strings.TrimSpace(trimmed[separator+1:])
	if modifier == "dn.this" || strings.HasPrefix(modifier, "dn.this.") {
		return databaseSearchSizeLimit{}, false, nil
	}
	if modifier == "dn.regex" || modifier == "dn.self.regex" {
		if rawDN == ".*" {
			return databaseSearchSizeLimit{selector: databaseSearchLimitAny}, true, nil
		}
		return databaseSearchSizeLimit{}, false, nil
	}

	selector := databaseSearchLimitExact
	switch modifier {
	case "dn", "dn.self", "dn.exact", "dn.base", "dn.self.exact", "dn.self.base":
	case "dn.one", "dn.onelevel", "dn.self.one", "dn.self.onelevel":
		selector = databaseSearchLimitOneLevel
	case "dn.sub", "dn.subtree", "dn.self.sub", "dn.self.subtree":
		selector = databaseSearchLimitSubtree
	case "dn.children", "dn.self.children":
		selector = databaseSearchLimitChildren
	default:
		return databaseSearchSizeLimit{}, false, nil
	}
	if rawDN == "*" {
		return databaseSearchSizeLimit{selector: databaseSearchLimitAny}, true, nil
	}
	subject, err := parseRuntimeDN(rawDN, normalizer)
	if err != nil {
		return databaseSearchSizeLimit{}, false, err
	}
	return databaseSearchSizeLimit{
		selector: selector,
		subject:  subject,
	}, true, nil
}

func parseDatabaseSearchSizeLimit(value string, hard bool) (int, error) {
	switch strings.ToLower(value) {
	case "none", "unlimited":
		return -1, nil
	case "soft":
		if hard {
			return 0, nil
		}
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < -1 {
		return 0, fmt.Errorf("invalid size limit %q", value)
	}
	return parsed, nil
}

func parseDatabaseSearchTimeLimit(value string, hard bool) (int, error) {
	switch strings.ToLower(value) {
	case "none", "unlimited":
		return -1, nil
	case "soft":
		if hard {
			return 0, nil
		}
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < -1 {
		return 0, fmt.Errorf("invalid time limit %q", value)
	}
	return parsed, nil
}

func loadDatabaseDefaultTimeLimit(
	entry directory.Entry,
) (databaseSearchSizeLimit, bool, error) {
	values := entry.Values("olcTimeLimit")
	if len(values) == 0 {
		return databaseSearchSizeLimit{}, false, nil
	}
	if len(values) != 1 {
		return databaseSearchSizeLimit{}, false, fmt.Errorf(
			"%s olcTimeLimit must be single-valued",
			entry.DN,
		)
	}
	arguments, err := tokenizeOpenLDAPConfig(string(values[0]))
	if err != nil || len(arguments) == 0 {
		return databaseSearchSizeLimit{}, false, fmt.Errorf(
			"%s olcTimeLimit is invalid",
			entry.DN,
		)
	}
	limit := databaseSearchSizeLimit{
		selector:        databaseSearchLimitAny,
		databaseDefault: true,
	}
	if len(arguments) == 1 && !strings.Contains(arguments[0], "=") {
		parsed, err := parseDatabaseSearchTimeLimit(arguments[0], false)
		if err != nil {
			return databaseSearchSizeLimit{}, false, fmt.Errorf(
				"%s olcTimeLimit: %w",
				entry.DN,
				err,
			)
		}
		limit.timeSoft, limit.timeSoftSet = parsed, true
		limit.timeHard, limit.timeHardSet = 0, true
		return limit, true, nil
	}
	for _, argument := range arguments {
		name, rawValue, found := strings.Cut(argument, "=")
		if !found {
			return databaseSearchSizeLimit{}, false, fmt.Errorf(
				"%s olcTimeLimit has invalid value %q",
				entry.DN,
				argument,
			)
		}
		switch strings.ToLower(name) {
		case "time":
			parsed, err := parseDatabaseSearchTimeLimit(rawValue, false)
			if err != nil {
				return databaseSearchSizeLimit{}, false, fmt.Errorf(
					"%s olcTimeLimit: %w",
					entry.DN,
					err,
				)
			}
			limit.timeSoft, limit.timeSoftSet = parsed, true
			limit.timeHard, limit.timeHardSet = 0, true
		case "time.soft":
			parsed, err := parseDatabaseSearchTimeLimit(rawValue, false)
			if err != nil {
				return databaseSearchSizeLimit{}, false, fmt.Errorf(
					"%s olcTimeLimit: %w",
					entry.DN,
					err,
				)
			}
			limit.timeSoft, limit.timeSoftSet = parsed, true
		case "time.hard":
			parsed, err := parseDatabaseSearchTimeLimit(rawValue, true)
			if err != nil {
				return databaseSearchSizeLimit{}, false, fmt.Errorf(
					"%s olcTimeLimit: %w",
					entry.DN,
					err,
				)
			}
			limit.timeHard, limit.timeHardSet = parsed, true
		default:
			return databaseSearchSizeLimit{}, false, fmt.Errorf(
				"%s olcTimeLimit has unknown field %q",
				entry.DN,
				name,
			)
		}
	}
	return limit, true, nil
}

func loadDatabaseDefaultSizeLimit(
	entry directory.Entry,
) (databaseSearchSizeLimit, bool, error) {
	values := entry.Values("olcSizeLimit")
	if len(values) == 0 {
		return databaseSearchSizeLimit{}, false, nil
	}
	if len(values) != 1 {
		return databaseSearchSizeLimit{}, false, fmt.Errorf(
			"%s olcSizeLimit must be single-valued",
			entry.DN,
		)
	}
	arguments, err := tokenizeOpenLDAPConfig(string(values[0]))
	if err != nil || len(arguments) == 0 {
		return databaseSearchSizeLimit{}, false, fmt.Errorf(
			"%s olcSizeLimit is invalid",
			entry.DN,
		)
	}
	limit := databaseSearchSizeLimit{
		selector:        databaseSearchLimitAny,
		databaseDefault: true,
	}
	if len(arguments) == 1 && !strings.Contains(arguments[0], "=") {
		parsed, err := parseDatabaseSearchSizeLimit(arguments[0], false)
		if err != nil {
			return databaseSearchSizeLimit{}, false, fmt.Errorf(
				"%s olcSizeLimit: %w",
				entry.DN,
				err,
			)
		}
		limit.soft, limit.softSet = parsed, true
		limit.hard, limit.hardSet = 0, true
		return limit, true, nil
	}
	for _, argument := range arguments {
		name, rawValue, found := strings.Cut(argument, "=")
		if !found {
			return databaseSearchSizeLimit{}, false, fmt.Errorf(
				"%s olcSizeLimit has invalid value %q",
				entry.DN,
				argument,
			)
		}
		switch strings.ToLower(name) {
		case "size":
			parsed, err := parseDatabaseSearchSizeLimit(rawValue, false)
			if err != nil {
				return databaseSearchSizeLimit{}, false, fmt.Errorf(
					"%s olcSizeLimit: %w",
					entry.DN,
					err,
				)
			}
			limit.soft, limit.softSet = parsed, true
			limit.hard, limit.hardSet = 0, true
		case "size.soft":
			parsed, err := parseDatabaseSearchSizeLimit(rawValue, false)
			if err != nil {
				return databaseSearchSizeLimit{}, false, fmt.Errorf(
					"%s olcSizeLimit: %w",
					entry.DN,
					err,
				)
			}
			limit.soft, limit.softSet = parsed, true
		case "size.hard":
			parsed, err := parseDatabaseSearchSizeLimit(rawValue, true)
			if err != nil {
				return databaseSearchSizeLimit{}, false, fmt.Errorf(
					"%s olcSizeLimit: %w",
					entry.DN,
					err,
				)
			}
			limit.hard, limit.hardSet = parsed, true
		case "size.unchecked", "size.pr", "size.prtotal":
			if err := applyDatabaseAuxiliarySizeLimit(&limit, name, rawValue); err != nil {
				return databaseSearchSizeLimit{}, false, fmt.Errorf(
					"%s olcSizeLimit: %w",
					entry.DN,
					err,
				)
			}
		default:
			return databaseSearchSizeLimit{}, false, fmt.Errorf(
				"%s olcSizeLimit has unknown field %q",
				entry.DN,
				name,
			)
		}
	}
	return limit, true, nil
}

func applyDatabaseAuxiliarySizeLimit(
	limit *databaseSearchSizeLimit,
	name, value string,
) error {
	lowerName := strings.ToLower(name)
	lowerValue := strings.ToLower(value)
	switch lowerName {
	case "size.unchecked":
		switch lowerValue {
		case "disabled":
			limit.unchecked, limit.uncheckedSet = 0, true
			return nil
		case "none", "unlimited":
			limit.unchecked, limit.uncheckedSet = -1, true
			return nil
		}
	case "size.pr":
		if lowerValue == "noestimate" {
			limit.pageNoEstimate, limit.pageEstimateSet = true, true
			return nil
		}
		if lowerValue == "none" || lowerValue == "unlimited" {
			limit.pageSize, limit.pageSizeSet = -1, true
			return nil
		}
	case "size.prtotal":
		switch lowerValue {
		case "disabled":
			limit.pageTotal, limit.pageTotalSet = -2, true
			return nil
		case "hard":
			limit.pageTotal, limit.pageTotalSet = 0, true
			return nil
		case "none", "unlimited":
			limit.pageTotal, limit.pageTotalSet = -1, true
			return nil
		}
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < -1 {
		return fmt.Errorf("invalid %s limit %q", name, value)
	}
	switch lowerName {
	case "size.unchecked":
		limit.unchecked, limit.uncheckedSet = parsed, true
	case "size.pr":
		limit.pageSize, limit.pageSizeSet = parsed, true
	case "size.prtotal":
		limit.pageTotal, limit.pageTotalSet = parsed, true
	default:
		return fmt.Errorf("unknown auxiliary size limit %q", name)
	}
	return nil
}

func databaseSearchLimitHasValues(limit databaseSearchSizeLimit) bool {
	return limit.softSet || limit.hardSet ||
		limit.timeSoftSet || limit.timeHardSet ||
		limit.uncheckedSet || limit.pageSizeSet ||
		limit.pageEstimateSet || limit.pageTotalSet
}

func effectiveDatabaseSearchLimit(
	runtime *runtimeState,
	database runtimeDatabase,
	boundDN string,
	serverLimit,
	requestLimit int,
) int {
	return effectiveDatabaseSearchExecutionLimits(
		runtime,
		database,
		boundDN,
		serverLimit,
		requestLimit,
		0,
	).size
}

func effectiveDatabaseSearchTimeLimit(
	runtime *runtimeState,
	database runtimeDatabase,
	boundDN string,
	requestLimit int,
) int {
	return effectiveDatabaseSearchExecutionLimits(
		runtime,
		database,
		boundDN,
		defaultSearchLimit,
		0,
		requestLimit,
	).time
}

func effectiveDatabaseSearchExecutionLimits(
	runtime *runtimeState,
	database runtimeDatabase,
	boundDN string,
	serverLimit, requestSize, requestTime int,
) databaseSearchExecutionLimits {
	if database.dnNormalizer == nil &&
		runtime != nil &&
		runtime.schema != nil &&
		!isConfigDatabase(database) {
		database.dnNormalizer = runtime.schema
	}
	subject, err := parseRuntimeDN(boundDN, database.dnNormalizer)
	root := err == nil && databaseRootMatches(runtime, database, subject)
	if err != nil || root {
		size := effectiveSearchLimit(serverLimit, requestSize)
		return databaseSearchExecutionLimits{
			size:      size,
			time:      requestTime,
			unchecked: -1,
			pageSize:  -1,
			pageTotal: size,
			root:      root,
		}
	}

	selected := databaseSearchSizeLimit{
		soft:         serverLimit,
		softSet:      true,
		hard:         0,
		hardSet:      true,
		unchecked:    -1,
		uncheckedSet: true,
		pageSize:     0,
		pageSizeSet:  true,
		pageTotal:    0,
		pageTotalSet: true,
		timeSoft:     0,
		timeSoftSet:  true,
		timeHard:     0,
		timeHardSet:  true,
	}
	for index := len(database.searchSizeLimits) - 1; index >= 0; index-- {
		defaults := database.searchSizeLimits[index]
		if !defaults.databaseDefault {
			continue
		}
		mergeDatabaseSearchLimit(&selected, defaults)
	}
	for _, rule := range database.searchSizeLimits {
		if rule.databaseDefault ||
			!databaseSearchLimitMatches(database, rule, subject) {
			continue
		}
		mergeDatabaseSearchLimit(&selected, rule)
		break
	}
	normalizeDatabaseSearchLimitHardValues(&selected)
	if selected.pageTotal > 0 &&
		selected.pageSize > selected.pageTotal {
		selected.pageSize = selected.pageTotal
	}
	return databaseSearchExecutionLimits{
		size: effectiveConfiguredSizeLimit(
			selected.soft,
			selected.hard,
			requestSize,
			serverLimit,
		),
		time:           effectiveConfiguredTimeLimit(selected.timeSoft, selected.timeHard, requestTime),
		unchecked:      selected.unchecked,
		pageSize:       selected.pageSize,
		pageNoEstimate: selected.pageNoEstimate,
		pageTotal:      effectivePagedTotalLimit(selected, requestSize, serverLimit),
	}
}

func normalizeDatabaseSearchLimitHardValues(limit *databaseSearchSizeLimit) {
	if limit.hard > 0 && (limit.hard < limit.soft || limit.soft == -1) {
		limit.hard = limit.soft
	}
	if limit.timeHard > 0 &&
		(limit.timeHard < limit.timeSoft || limit.timeSoft == -1) {
		limit.timeHard = limit.timeSoft
	}
}

func mergeDatabaseSearchLimit(
	destination *databaseSearchSizeLimit,
	source databaseSearchSizeLimit,
) {
	if source.softSet {
		destination.soft, destination.softSet = source.soft, true
	}
	if source.hardSet {
		destination.hard, destination.hardSet = source.hard, true
	}
	if source.timeSoftSet {
		destination.timeSoft, destination.timeSoftSet = source.timeSoft, true
	}
	if source.timeHardSet {
		destination.timeHard, destination.timeHardSet = source.timeHard, true
	}
	if source.uncheckedSet {
		destination.unchecked, destination.uncheckedSet = source.unchecked, true
	}
	if source.pageSizeSet {
		destination.pageSize, destination.pageSizeSet = source.pageSize, true
	}
	if source.pageEstimateSet {
		destination.pageNoEstimate = source.pageNoEstimate
		destination.pageEstimateSet = true
	}
	if source.pageTotalSet {
		destination.pageTotal, destination.pageTotalSet = source.pageTotal, true
	}
}

func effectiveConfiguredSizeLimit(
	soft, hard, requested, serverLimit int,
) int {
	limit := effectiveSearchLimit(serverLimit, requested)
	if requested <= 0 {
		if soft > 0 && soft < limit {
			return soft
		}
		return limit
	}
	if hard == 0 {
		hard = soft
	}
	if hard > 0 && hard < limit {
		return hard
	}
	return limit
}

func effectiveConfiguredTimeLimit(soft, hard, requested int) int {
	if requested <= 0 {
		if soft < 0 {
			return 0
		}
		return soft
	}
	if hard == 0 {
		hard = soft
	}
	if hard > 0 && requested > hard {
		return hard
	}
	return requested
}

func effectivePagedTotalLimit(
	configured databaseSearchSizeLimit,
	requested, serverLimit int,
) int {
	serverCap := effectiveSearchLimit(serverLimit, requested)
	total := configured.pageTotal
	if total == -2 {
		return -2
	}
	if total == 0 {
		total = configured.hard
		if total == 0 {
			total = configured.soft
		}
	}
	if total < 0 {
		return serverCap
	}
	if total > serverCap {
		return serverCap
	}
	return total
}

func applyDatabaseSearchLimits(
	state *connectionState,
	message ldapwire.Message,
	serverSizeLimit int,
) ldapwire.Message {
	request, ok := message.Request.(ldapwire.SearchRequest)
	if !ok || state == nil || state.runtime == nil {
		return message
	}
	base, err := normalizeSearchRequestBase(state.runtime, request.BaseDN)
	if err != nil {
		return message
	}
	database := databaseForDN(state.runtime, base)
	if database == nil {
		return message
	}
	limits := effectiveDatabaseSearchExecutionLimits(
		state.runtime,
		*database,
		state.boundDN,
		serverSizeLimit,
		request.SizeLimit,
		request.TimeLimit,
	)
	request.SizeLimit = limits.size
	for _, control := range message.Controls {
		if control.OID != pagedResultsControlOID || !control.HasValue {
			continue
		}
		if _, _, decodeErr := ldapwire.DecodePagedResultsValue(control.Value); decodeErr == nil &&
			limits.pageTotal >= 0 {
			request.SizeLimit = limits.pageTotal
		}
		break
	}
	request.TimeLimit = limits.time
	message.Request = request
	return message
}

func searchRequestDatabase(
	runtime *runtimeState,
	request ldapwire.SearchRequest,
) *runtimeDatabase {
	if runtime == nil {
		return nil
	}
	base, err := normalizeSearchRequestBase(runtime, request.BaseDN)
	if err != nil {
		return nil
	}
	return databaseForDN(runtime, base)
}

func databaseSearchCandidatesAreDelegated(
	runtime *runtimeState,
	database runtimeDatabase,
) bool {
	for followed := 0; ; followed++ {
		if database.ldapBackend != nil ||
			database.metaBackend != nil ||
			database.dnssrvBackend != nil ||
			database.sockBackend != nil ||
			database.passwdBackend != nil {
			return true
		}
		if runtime == nil || database.relay == nil {
			return false
		}
		if followed >= len(runtime.databases) {
			return true
		}
		target := database.relay.targetDatabaseIndex
		if target < 0 || target >= len(runtime.databases) {
			return true
		}
		database = runtime.databases[target]
	}
}

func databaseSearchLimitMatches(
	database runtimeDatabase,
	configured databaseSearchSizeLimit,
	subject directory.DN,
) bool {
	switch configured.selector {
	case databaseSearchLimitAnonymous:
		return subject.Depth() == 0
	case databaseSearchLimitUsers:
		return subject.Depth() > 0
	case databaseSearchLimitAny:
		return true
	case databaseSearchLimitOneLevel:
		return subject.Depth() == configured.subject.Depth()+1 &&
			databaseDNStrictlyBelow(database, subject, configured.subject)
	case databaseSearchLimitSubtree:
		return databaseDNAtOrBelow(database, subject, configured.subject)
	case databaseSearchLimitChildren:
		return databaseDNStrictlyBelow(database, subject, configured.subject)
	default:
		return databaseDNEqual(database, configured.subject, subject)
	}
}

func loadRuntimeDatabaseOverlays(
	reader storage.Reader,
	databases []runtimeDatabase,
) error {
	configSuffix, err := directory.ParseDN("cn=config")
	if err != nil {
		return err
	}
	if err := reader.ForEach(func(entry directory.Entry) error {
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
		overlayType, err := requireSupportedRuntimeOverlayType(
			entry.DN,
			string(overlayValues[0]),
		)
		if err != nil {
			return err
		}
		if seqmodOverlayDNTargetsSeqmod(entryDN) && overlayType != "seqmod" {
			return seqmodConfigurationFailure(
				ldapwire.ResultNamingViolation,
				"%s olcOverlay value does not match its seqmod RDN",
				entry.DN,
			)
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
		if database.sockBackend != nil ||
			((database.ldapBackend != nil || database.metaBackend != nil) &&
				overlayType != "pcache") {
			return fmt.Errorf(
				"%s %s overlay on delegated backend %s is unsupported because local overlays would be bypassed",
				entry.DN,
				overlayType,
				database.name,
			)
		}
		switch overlayType {
		case "sock":
			configuration, err := loadSockOverlayRuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			database.sockOverlays = append(database.sockOverlays, configuration)
		case "autoca":
			if database.autoca != nil {
				return fmt.Errorf(
					"%s configures a duplicate autoca overlay for %s",
					entry.DN,
					database.name,
				)
			}
			configuration, err := loadAutoCARuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			if err := validateAutoCADatabase(*database, configuration); err != nil {
				return err
			}
			database.autoca = &configuration
		case "otp":
			if database.otp != nil {
				return fmt.Errorf(
					"%s configures a duplicate otp overlay for %s",
					entry.DN,
					database.name,
				)
			}
			if databaseType(database.name) == "frontend" ||
				isConfigDatabase(*database) || isMonitorDatabase(*database) ||
				isNullDatabase(*database) || database.relay != nil ||
				database.readOnly || database.shadow ||
				len(database.suffixes) == 0 || database.partition == "" {
				return fmt.Errorf(
					"%s otp overlay requires a local database naming context",
					entry.DN,
				)
			}
			configuration, err := loadOTPRuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			database.otp = &configuration
		case "totp":
			configuration, err := loadTOTPPasswordRuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			database.totpPasswords = append(database.totpPasswords, configuration)
		case "pcache":
			if database.pcache != nil {
				return fmt.Errorf(
					"%s configures a duplicate pcache overlay for %s",
					entry.DN,
					database.name,
				)
			}
			if database.ldapBackend == nil {
				return fmt.Errorf(
					"%s pcache Phase 1 requires an ldap backend",
					entry.DN,
				)
			}
			if databaseType(database.name) == "frontend" || len(database.suffixes) == 0 {
				return fmt.Errorf(
					"%s pcache overlay requires a database naming context",
					entry.DN,
				)
			}
			if database.rootDN == nil {
				return fmt.Errorf(
					"%s pcache overlay requires olcRootDN on %s",
					entry.DN,
					database.name,
				)
			}
			configuration, err := loadPcacheRuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			database.pcache = &configuration
		case "translucent":
			if database.translucent != nil {
				return fmt.Errorf(
					"%s configures a duplicate translucent overlay for %s",
					entry.DN,
					database.name,
				)
			}
			if databaseType(database.name) == "frontend" {
				return fmt.Errorf(
					"%s translucent overlay cannot be global",
					entry.DN,
				)
			}
			configuration, err := loadTranslucentRuntimeConfiguration(
				reader,
				entry,
			)
			if err != nil {
				return err
			}
			database.translucent = &configuration
		case "nestgroup":
			configuration, err := loadNestGroupRuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			database.nestGroups = append(database.nestGroups, configuration)
		case "seqmod":
			if database.seqmod != nil {
				return seqmodConfigurationFailure(
					ldapwire.ResultOther,
					"%s seqmod overlay is already in the list for %s",
					entry.DN,
					database.name,
				)
			}
			configuration, err := loadSeqmodRuntimeConfiguration(entry, entryDN)
			if err != nil {
				return err
			}
			database.seqmod = &configuration
		case "collect":
			if database.collect != nil {
				return collectConfigurationFailure(
					ldapwire.ResultOther,
					"%s collect overlay is already in the list for %s",
					entry.DN,
					database.name,
				)
			}
			configuration, err := loadCollectRuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			database.collect = &configuration
		case "deref":
			if database.deref {
				return fmt.Errorf(
					"%s configures a duplicate deref overlay for %s",
					entry.DN,
					database.name,
				)
			}
			database.deref = true
		case "homedir":
			if database.homedir != nil {
				return fmt.Errorf(
					"%s configures a duplicate homedir overlay for %s",
					entry.DN,
					database.name,
				)
			}
			configuration, err := loadHomedirRuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			database.homedir = &configuration
		case "remoteauth":
			if database.remoteAuth != nil {
				return fmt.Errorf(
					"%s configures a duplicate remoteauth overlay for %s",
					entry.DN,
					database.name,
				)
			}
			if databaseType(database.name) == "frontend" {
				return fmt.Errorf(
					"%s remoteauth overlay cannot be global",
					entry.DN,
				)
			}
			configuration, err := loadRemoteAuthRuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			database.remoteAuth = &configuration
		case "pbind":
			if database.pbind != nil {
				return fmt.Errorf(
					"%s configures a duplicate pbind overlay for %s",
					entry.DN,
					database.name,
				)
			}
			if databaseType(database.name) == "frontend" {
				return fmt.Errorf(
					"%s pbind overlay cannot be global",
					entry.DN,
				)
			}
			configuration, err := loadPBindRuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			database.pbind = &configuration
		case "dynlist":
			if database.dynlist != nil {
				return fmt.Errorf(
					"%s configures a duplicate dynlist overlay for %s",
					entry.DN,
					database.name,
				)
			}
			configuration, err := loadDynlistRuntimeConfiguration(entry, *database)
			if err != nil {
				return err
			}
			database.dynlist = &configuration
		case "dyngroup":
			if database.dyngroup != nil {
				return fmt.Errorf(
					"%s configures a duplicate dyngroup overlay for %s",
					entry.DN,
					database.name,
				)
			}
			configuration, err := loadDynamicGroupRuntimeConfiguration(entry, *database)
			if err != nil {
				return err
			}
			database.dyngroup = &configuration
		case "auditlog":
			if database.auditlog != nil {
				return fmt.Errorf(
					"%s configures a duplicate auditlog overlay for %s",
					entry.DN,
					database.name,
				)
			}
			configuration, err := loadAuditlogRuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			database.auditlog = &configuration
		case "accesslog":
			if database.accesslog != nil {
				return fmt.Errorf(
					"%s configures a duplicate accesslog overlay for %s",
					entry.DN,
					database.name,
				)
			}
			configuration, err := loadAccesslogRuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			database.accesslog = &configuration
		case "rwm":
			if database.rwm != nil {
				return fmt.Errorf(
					"%s configures a duplicate rwm overlay for %s",
					entry.DN,
					database.name,
				)
			}
			configuration, err := loadRWMRuntimeConfiguration(entry, *database)
			if err != nil {
				return err
			}
			database.rwm = &configuration
		case "retcode":
			configuration, err := loadRetcodeRuntimeConfiguration(entry, *database)
			if err != nil {
				return err
			}
			database.retcodes = append(database.retcodes, configuration)
		case "valsort":
			if database.valueSort != nil {
				return fmt.Errorf(
					"%s configures a duplicate valsort overlay for %s",
					entry.DN,
					database.name,
				)
			}
			configuration, err := loadValueSortRuntimeConfiguration(entry)
			if err != nil {
				return err
			}
			database.valueSort = &configuration
		case "memberof":
			configuration, err := loadMemberOfRuntimeConfiguration(
				entry,
				*database,
			)
			if err != nil {
				return err
			}
			database.memberOf = append(database.memberOf, configuration)
		case "refint":
			configuration, err := loadRefintRuntimeConfiguration(
				entry,
				*database,
			)
			if err != nil {
				return err
			}
			database.refint = append(database.refint, configuration)
		case "unique":
			if database.unique != nil {
				return fmt.Errorf(
					"%s configures a duplicate unique overlay for %s",
					entry.DN,
					database.name,
				)
			}
			configuration, err := loadUniqueRuntimeConfiguration(
				entry,
				*database,
			)
			if err != nil {
				return err
			}
			database.unique = &configuration
		case "constraint":
			if database.constraint != nil {
				return fmt.Errorf(
					"%s configures a duplicate constraint overlay for %s",
					entry.DN,
					database.name,
				)
			}
			configuration, err := loadConstraintRuntimeConfiguration(
				entry,
				*database,
			)
			if err != nil {
				return err
			}
			database.constraint = &configuration
		case "chain":
			if database.chain != nil {
				return fmt.Errorf(
					"%s configures a duplicate chain overlay for %s",
					entry.DN,
					database.name,
				)
			}
			configuration, err := loadChainRuntimeConfiguration(reader, entry)
			if err != nil {
				return err
			}
			database.chain = &configuration
		case "dds":
			if database.dds != nil {
				return fmt.Errorf(
					"%s configures a duplicate dds overlay for %s",
					entry.DN,
					database.name,
				)
			}
			dds, err := loadDDSRuntimeConfiguration(entry, *database)
			if err != nil {
				return err
			}
			database.dds = &dds
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
		case "ppolicy":
			if database.ppolicy != nil {
				return fmt.Errorf(
					"%s configures a duplicate ppolicy overlay for %s",
					entry.DN,
					database.name,
				)
			}
			if databaseType(database.name) == "frontend" {
				return fmt.Errorf(
					"%s ppolicy overlay cannot be global",
					entry.DN,
				)
			}
			configuration, err := loadPasswordPolicyRuntimeConfiguration(
				entry,
				database.dnNormalizer,
			)
			if err != nil {
				return err
			}
			database.ppolicy = &configuration
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
			checkpointOps, checkpointMinutes, err := syncCheckpointSetting(
				entry,
			)
			if err != nil {
				return err
			}
			sessionLogSize, err := singleNonnegativeInteger(
				entry,
				"olcSpSessionlog",
				0,
			)
			if err != nil {
				return err
			}
			noPresent, _, err := singleBoolean(entry, "olcSpNoPresent")
			if err != nil {
				return err
			}
			reloadHint, _, err := singleBoolean(entry, "olcSpReloadHint")
			if err != nil {
				return err
			}
			database.syncProvider = true
			database.syncCheckpointOps = checkpointOps
			database.syncCheckpointMinutes = checkpointMinutes
			database.syncSessionLogSize = sessionLogSize
			database.syncNoPresent = noPresent
			database.syncReloadHint = reloadHint
		}
		return nil
	}); err != nil {
		return err
	}
	for _, database := range databases {
		if database.otp == nil {
			continue
		}
		if database.pbind != nil || database.remoteAuth != nil {
			return fmt.Errorf(
				"%s OTP overlay cannot share a database with a Bind-delegating overlay",
				database.name,
			)
		}
	}
	return nil
}

func syncCheckpointSetting(entry directory.Entry) (ops, minutes int, err error) {
	values := entry.Values("olcSpCheckpoint")
	if len(values) == 0 {
		return 0, 0, nil
	}
	if len(values) != 1 {
		return 0, 0, fmt.Errorf(
			"%s olcSpCheckpoint must be single-valued",
			entry.DN,
		)
	}
	fields := strings.Fields(string(values[0]))
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf(
			"%s olcSpCheckpoint must contain operations and minutes",
			entry.DN,
		)
	}
	ops, opsErr := strconv.Atoi(fields[0])
	minutes, minutesErr := strconv.Atoi(fields[1])
	if opsErr != nil || ops <= 0 || minutesErr != nil || minutes <= 0 {
		return 0, 0, fmt.Errorf(
			"%s olcSpCheckpoint has invalid value %q",
			entry.DN,
			values[0],
		)
	}
	return ops, minutes, nil
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
	var frontendRestrictions databaseRestrictions
	var frontendLimits []databaseSearchSizeLimit
	for _, database := range databases {
		if databaseType(database.name) == "frontend" {
			frontendRestrictions = effectiveDatabaseRestrictions(database)
			for _, limit := range database.searchSizeLimits {
				if limit.databaseDefault {
					frontendLimits = append(frontendLimits, limit)
				}
			}
			break
		}
	}
	for index := range databases {
		databases[index].restrictions |= frontendRestrictions
		databases[index].readOnly = databaseIsReadOnly(databases[index])
		if databaseType(databases[index].name) == "frontend" {
			continue
		}
		localLimitCount := len(databases[index].searchSizeLimits)
		for _, limit := range frontendLimits {
			inherited := limit
			for _, local := range databases[index].searchSizeLimits[:localLimitCount] {
				if !local.databaseDefault {
					continue
				}
				if local.softSet {
					inherited.softSet = false
				}
				if local.hardSet {
					inherited.hardSet = false
				}
				if local.uncheckedSet {
					inherited.uncheckedSet = false
				}
				if local.pageSizeSet {
					inherited.pageSizeSet = false
				}
				if local.pageTotalSet {
					inherited.pageTotalSet = false
				}
				if local.pageEstimateSet {
					inherited.pageEstimateSet = false
				}
				if local.timeSoftSet {
					inherited.timeSoftSet = false
				}
				if local.timeHardSet {
					inherited.timeHardSet = false
				}
			}
			if databaseSearchLimitHasValues(inherited) {
				databases[index].searchSizeLimits = append(
					databases[index].searchSizeLimits,
					inherited,
				)
			}
		}
	}
}

func effectiveDatabaseRestrictions(database runtimeDatabase) databaseRestrictions {
	restrictions := database.restrictions
	if database.readOnly {
		restrictions |= restrictWrites
	}
	return restrictions
}

func databaseIsReadOnly(database runtimeDatabase) bool {
	return effectiveDatabaseRestrictions(database)&restrictWrites == restrictWrites
}

func databaseRestricts(database runtimeDatabase, operation databaseRestrictions) bool {
	restrictions := effectiveDatabaseRestrictions(database)
	if operation&(restrictStartTLS|restrictPasswordModify|restrictWhoAmI|restrictCancel) != 0 {
		return restrictions&restrictExtended != 0 || restrictions&operation != 0
	}
	return restrictions&operation != 0
}

func frontendRestricts(runtime *runtimeState, operation databaseRestrictions) bool {
	database := runtimeDatabase{
		restrictions: monitorFrontendRestrictions(runtime.databases),
	}
	return databaseRestricts(database, operation)
}

func parseDatabaseRestrictions(values [][]byte) (databaseRestrictions, error) {
	var restrictions databaseRestrictions
	for _, raw := range values {
		value := string(raw)
		if strings.HasPrefix(value, "{") {
			end := strings.IndexByte(value, '}')
			if end < 0 {
				return 0, fmt.Errorf("invalid ordering prefix %q", value)
			}
			value = value[end+1:]
		}
		for _, word := range strings.Fields(value) {
			flag, ok := databaseRestrictionName(word, true)
			if !ok {
				return 0, fmt.Errorf("unknown operation %q", word)
			}
			restrictions |= flag
		}
	}
	if restrictions&restrictExtended != 0 {
		restrictions &^= restrictSpecificExtended
	}
	return restrictions, nil
}

func databaseRestrictionName(
	value string,
	allowAliases bool,
) (databaseRestrictions, bool) {
	switch strings.ToLower(value) {
	case "add":
		return restrictAdd, true
	case "bind":
		return restrictBind, true
	case "compare":
		return restrictCompare, true
	case "delete":
		return restrictDelete, true
	case "extended":
		return restrictExtended, true
	case "modify":
		return restrictModify, true
	case "rename":
		return restrictRename, true
	case "search":
		return restrictSearch, true
	case startTLSOID:
		return restrictStartTLS, true
	case passwordModifyOID:
		return restrictPasswordModify, true
	case whoAmIOID:
		return restrictWhoAmI, true
	case cancelOID:
		return restrictCancel, true
	}
	if !allowAliases {
		return 0, false
	}
	switch strings.ToLower(value) {
	case "modrdn":
		return restrictRename, true
	case "read":
		return restrictReads, true
	case "write":
		return restrictWrites, true
	case "all":
		return restrictAll, true
	case "extended=" + startTLSOID:
		return restrictStartTLS, true
	case "extended=" + passwordModifyOID:
		return restrictPasswordModify, true
	case "extended=" + whoAmIOID:
		return restrictWhoAmI, true
	case "extended=" + cancelOID:
		return restrictCancel, true
	default:
		return 0, false
	}
}

func databaseRestrictionValues(restrictions databaseRestrictions) []string {
	values := make([]string, 0, 12)
	for _, item := range []struct {
		value string
		flag  databaseRestrictions
	}{
		{"add", restrictAdd},
		{"bind", restrictBind},
		{"compare", restrictCompare},
		{"delete", restrictDelete},
		{"extended", restrictExtended},
		{"modify", restrictModify},
		{"rename", restrictRename},
		{"search", restrictSearch},
		{startTLSOID, restrictStartTLS},
		{passwordModifyOID, restrictPasswordModify},
		{whoAmIOID, restrictWhoAmI},
		{cancelOID, restrictCancel},
	} {
		if restrictions&item.flag != 0 {
			values = append(values, item.value)
		}
	}
	return values
}

func validateDatabaseSuffixes(databases []runtimeDatabase) error {
	owners := make(map[string]string)
	for _, database := range databases {
		if database.hidden || database.disabled {
			continue
		}
		for _, suffix := range database.suffixes {
			normalized, err := normalizeRuntimeDatabaseDN(database, suffix)
			if err != nil {
				return fmt.Errorf(
					"normalize database %q suffix %q: %w",
					database.name,
					suffix.String(),
					err,
				)
			}
			if owner, exists := owners[normalized.Key()]; exists {
				return fmt.Errorf(
					"database suffix %q is configured by both %q and %q",
					suffix.String(),
					owner,
					database.name,
				)
			}
			owners[normalized.Key()] = database.name
		}
	}
	return nil
}

func validateDatabasePartitions(databases []runtimeDatabase) error {
	owners := make(map[string]int)
	for index, database := range databases {
		if database.partition == "" {
			continue
		}
		if ownerIndex, exists := owners[database.partition]; exists {
			if isRelayDatabase(database) || isRelayDatabase(databases[ownerIndex]) {
				continue
			}
			return fmt.Errorf(
				"databases %q and %q use the same storage partition",
				databases[ownerIndex].name,
				database.name,
			)
		}
		owners[database.partition] = index
	}
	return nil
}

func applyBootstrapRoot(
	databases []runtimeDatabase,
	rawDN string,
	password []byte,
	normalizer directory.DNAttributeNormalizer,
) error {
	rootDN, err := parseRuntimeDN(rawDN, normalizer)
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
			if !databaseDNAtOrBelow(databases[index], dn, suffix) {
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
			if !databaseDNStrictlyBelow(*database, childSuffix, suffix) {
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

func effectiveSyncProviderDatabaseIndex(
	databases []runtimeDatabase,
	databaseIndex int,
) int {
	if databaseIndex < 0 || databaseIndex >= len(databases) {
		return -1
	}
	database := &databases[databaseIndex]
	if database.hidden || database.disabled {
		return -1
	}
	if database.syncProvider {
		return databaseIndex
	}
	if !database.subordinate || len(database.suffixes) != 1 {
		return -1
	}

	superiorIndex := glueSuperiorDatabaseIndex(databases, databaseIndex)
	if superiorIndex < 0 {
		return -1
	}
	targetSuffix := database.suffixes[0]
	bestIndex := -1
	bestDepth := -1
	for index := range databases {
		candidate := &databases[index]
		if candidate.hidden ||
			candidate.disabled ||
			!candidate.syncProvider {
			continue
		}
		if index != superiorIndex &&
			(!candidate.subordinate ||
				len(candidate.suffixes) != 1 ||
				glueSuperiorDatabaseIndex(databases, index) != superiorIndex) {
			continue
		}
		for _, suffix := range candidate.suffixes {
			if !databaseDNStrictlyBelow(*candidate, targetSuffix, suffix) {
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

func effectiveSyncProviderDatabase(
	runtime *runtimeState,
	database runtimeDatabase,
) *runtimeDatabase {
	if runtime == nil {
		return nil
	}
	databaseIndex := -1
	for index := range runtime.databases {
		if runtime.databases[index].partition == database.partition {
			databaseIndex = index
			break
		}
	}
	providerIndex := effectiveSyncProviderDatabaseIndex(
		runtime.databases,
		databaseIndex,
	)
	if providerIndex < 0 {
		return nil
	}
	return &runtime.databases[providerIndex]
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
			if !databaseDNAtOrBelow(databases[index], dn, suffix) {
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
		if databaseDNEqual(database, suffix, dn) {
			return true
		}
	}
	return false
}

func parseRuntimeDN(
	value string,
	normalizer directory.DNAttributeNormalizer,
) (directory.DN, error) {
	if normalizer != nil {
		return directory.ParseDNWithNormalizer(value, normalizer)
	}
	return directory.ParseDN(value)
}

func normalizeRuntimeDatabaseDN(
	database runtimeDatabase,
	dn directory.DN,
) (directory.DN, error) {
	return parseRuntimeDN(dn.String(), database.dnNormalizer)
}

func databaseDNEqual(
	database runtimeDatabase,
	left directory.DN,
	right directory.DN,
) bool {
	left, err := normalizeRuntimeDatabaseDN(database, left)
	if err != nil {
		return false
	}
	right, err = normalizeRuntimeDatabaseDN(database, right)
	return err == nil && left.Equal(right)
}

func databaseDNAtOrBelow(
	database runtimeDatabase,
	dn directory.DN,
	base directory.DN,
) bool {
	dn, err := normalizeRuntimeDatabaseDN(database, dn)
	if err != nil {
		return false
	}
	base, err = normalizeRuntimeDatabaseDN(database, base)
	return err == nil && (base.Equal(dn) || base.AncestorOf(dn))
}

func databaseDNStrictlyBelow(
	database runtimeDatabase,
	dn directory.DN,
	base directory.DN,
) bool {
	dn, err := normalizeRuntimeDatabaseDN(database, dn)
	if err != nil {
		return false
	}
	base, err = normalizeRuntimeDatabaseDN(database, base)
	return err == nil && base.AncestorOf(dn)
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

func isNullDatabase(database runtimeDatabase) bool {
	return databaseType(database.name) == "null"
}

func isRelayDatabase(database runtimeDatabase) bool {
	return databaseType(database.name) == "relay"
}

func isLDAPBackendDatabase(database runtimeDatabase) bool {
	return databaseType(database.name) == "ldap"
}

func isMetaBackendDatabase(database runtimeDatabase) bool {
	return databaseType(database.name) == "meta"
}

func isAsyncMetaBackendDatabase(database runtimeDatabase) bool {
	return databaseType(database.name) == "asyncmeta"
}

func isPasswdBackendDatabase(database runtimeDatabase) bool {
	return databaseType(database.name) == "passwd"
}

func isDNSSRVBackendDatabase(database runtimeDatabase) bool {
	return databaseType(database.name) == "dnssrv"
}

func isSockBackendDatabase(database runtimeDatabase) bool {
	return databaseType(database.name) == "sock"
}

func isSQLBackendDatabase(database runtimeDatabase) bool {
	return databaseType(database.name) == "sql"
}

func databaseUsesLocalContentStorage(database runtimeDatabase) bool {
	return database.partition != "" &&
		!isConfigDatabase(database) &&
		!isMonitorDatabase(database) &&
		!isNullDatabase(database) &&
		database.relay == nil &&
		database.ldapBackend == nil &&
		database.metaBackend == nil &&
		database.passwdBackend == nil &&
		database.dnssrvBackend == nil &&
		database.sockBackend == nil &&
		database.sqlBackend == nil
}

func databaseUsesSchemaAwareContentStorage(database runtimeDatabase) bool {
	return database.partition != "" &&
		!isConfigDatabase(database) &&
		!isMonitorDatabase(database) &&
		!isNullDatabase(database) &&
		database.ldapBackend == nil &&
		database.metaBackend == nil &&
		database.passwdBackend == nil &&
		database.dnssrvBackend == nil &&
		database.sockBackend == nil &&
		database.sqlBackend == nil
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
