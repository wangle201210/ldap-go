package migration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	"github.com/google/uuid"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type ImportOptions struct {
	Replace                       bool
	Database                      string
	SelectDefaultDatabase         bool
	DisableSubordinateGlue        bool
	DryRun                        bool
	Schema                        *schema.Registry
	SkipSchemaValidation          bool
	SkipValueValidation           bool
	RequireObjectClass            bool
	ValidateConfigurationEntries  bool
	GenerateOperationalAttributes bool
	CSNServerID                   uint16
	UpdateContextCSN              bool
	ValidateTransaction           func(storage.Reader) error
}

type ImportResult struct {
	Entries        int
	NamingContexts []string
}

type importedContentEntry struct {
	partition  string
	dn         directory.DN
	target     databaseTarget
	toolTarget databaseTarget
}

type pendingContentEntry struct {
	entry directory.Entry
}

var errImportDryRun = errors.New("rollback validated LDIF import")

// ImportLDIF atomically imports slapcat LDIF, including operational attributes.
// Configuration entries are isolated from content databases. Change records
// are rejected because they have different transaction semantics and are
// handled by the future ldapmodify-compatible command.
func ImportLDIF(
	ctx context.Context,
	store storage.Store,
	reader io.Reader,
	options ImportOptions,
) (ImportResult, error) {
	return importLDIF(
		ctx,
		store,
		reader,
		options,
		&importCSNGenerator{},
	)
}

func importLDIF(
	ctx context.Context,
	store storage.Store,
	reader io.Reader,
	options ImportOptions,
	csns *importCSNGenerator,
) (ImportResult, error) {
	if reader == nil {
		return ImportResult{}, errors.New("LDIF reader is required")
	}

	var result ImportResult
	err := storage.UpdateBulk(ctx, store, func(tx storage.Writer) error {
		var importedContent []importedContentEntry
		var importedConfiguration []importedContentEntry
		var pendingContent []pendingContentEntry
		target, err := resolveDatabaseTarget(tx, options.Database)
		if err != nil {
			return err
		}
		targetSelected := options.Database != ""
		if options.SelectDefaultDatabase && !targetSelected {
			var found bool
			target, found, err = resolveDefaultDatabaseTarget(tx)
			if err != nil {
				return fmt.Errorf("resolve default OpenLDAP database: %w", err)
			}
			targetSelected = found
			if !found {
				return errors.New("no available OpenLDAP content database")
			}
		}
		if targetSelected && !options.DryRun && !target.supportsOfflineImport() {
			return fmt.Errorf(
				"OpenLDAP %s backend %q does not support offline entry import",
				target.backend,
				target.name,
			)
		}
		if targetSelected && options.UpdateContextCSN &&
			!target.supportsOfflineContextUpdate() {
			return fmt.Errorf(
				"OpenLDAP %s backend %q does not support offline contextCSN updates",
				target.backend,
				target.name,
			)
		}
		var identitySchema *schema.Registry
		if targetSelected && !target.config {
			identitySchema, err = importedSchemaRegistry(tx, options.Schema)
			if err != nil {
				return fmt.Errorf("initialize schema-aware DN identity: %w", err)
			}
			configuredTargets, err := loadDatabaseTargetsWithNormalizer(
				tx,
				identitySchema,
			)
			if err != nil {
				return fmt.Errorf("load OpenLDAP databases for import: %w", err)
			}
			target, err = normalizedSelectedDatabaseTarget(target, configuredTargets)
			if err != nil {
				return err
			}
		}
		if options.Replace {
			if !targetSelected {
				if err := tx.Clear(); err != nil {
					return fmt.Errorf("clear destination: %w", err)
				}
			} else {
				replaceTargets := []databaseTarget{target}
				if !options.DisableSubordinateGlue {
					configuredTargets, err := loadDatabaseTargetsWithNormalizer(
						tx,
						identitySchema,
					)
					if err != nil {
						return fmt.Errorf("load OpenLDAP databases for replacement: %w", err)
					}
					subordinates, err := attachedSubordinateTargets(target, configuredTargets)
					if err != nil {
						return fmt.Errorf("resolve glued databases for replacement: %w", err)
					}
					replaceTargets = append(replaceTargets, subordinates...)
				}
				cleared := make(map[string]struct{}, len(replaceTargets))
				for _, replaceTarget := range replaceTargets {
					if _, exists := cleared[replaceTarget.partition]; exists {
						continue
					}
					if err := storage.WriterInPartition(tx, replaceTarget.partition).Clear(); err != nil {
						return fmt.Errorf("clear database %q: %w", replaceTarget.name, err)
					}
					cleared[replaceTarget.partition] = struct{}{}
				}
			}
		}

		document := &ldif.LDIF{}
		for record, parseErr := range ldif.UnmarshalEntries(reader, document) {
			if parseErr != nil {
				return fmt.Errorf("parse LDIF: %w", parseErr)
			}
			if record == nil {
				continue
			}
			if record.Entry == nil {
				return errors.New("LDIF change records are not accepted by content import")
			}

			entry := fromLDAPEntry(record.Entry)
			configurationEntry, err := isConfigurationDN(entry.DN)
			if err != nil {
				return fmt.Errorf("import %q: %w", entry.DN, err)
			}
			switch {
			case target.config && !configurationEntry:
				return fmt.Errorf(
					"entry %q is outside the selected config database",
					entry.DN,
				)
			case targetSelected && !target.config && configurationEntry:
				return fmt.Errorf(
					"entry %q belongs to cn=config, not database %q",
					entry.DN,
					options.Database,
				)
			}
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return fmt.Errorf("import %q: %w", entry.DN, err)
			}
			if configurationEntry {
				if err := tx.PutIn(storage.OpenLDAPConfigPartition, entry, false); err != nil {
					return fmt.Errorf("import %q: %w", entry.DN, err)
				}
				configurationTarget, err := resolveDatabaseTarget(tx, "0")
				if err != nil {
					return fmt.Errorf("resolve config database: %w", err)
				}
				importedConfiguration = append(
					importedConfiguration,
					importedContentEntry{
						partition:  storage.OpenLDAPConfigPartition,
						dn:         dn,
						target:     configurationTarget,
						toolTarget: configurationTarget,
					},
				)
			} else {
				pendingContent = append(pendingContent, pendingContentEntry{
					entry: entry,
				})
			}
			result.Entries++
		}

		if identitySchema == nil {
			identitySchema, err = importedSchemaRegistry(tx, options.Schema)
			if err != nil {
				return fmt.Errorf("initialize schema-aware DN identity: %w", err)
			}
		}
		configuredTargets, err := loadDatabaseTargetsWithNormalizer(
			tx,
			identitySchema,
		)
		if err != nil {
			return fmt.Errorf("load imported OpenLDAP databases: %w", err)
		}
		if targetSelected && !target.config {
			target, err = normalizedSelectedDatabaseTarget(target, configuredTargets)
			if err != nil {
				return err
			}
		}
		var gluedSubordinates map[string]struct{}
		if targetSelected && !options.DisableSubordinateGlue {
			subordinates, err := glueSubordinateTargets(tx, target, configuredTargets)
			if err != nil {
				return fmt.Errorf("open selected OpenLDAP database for glue import: %w", err)
			}
			gluedSubordinates = make(map[string]struct{}, len(subordinates))
			for _, subordinate := range subordinates {
				gluedSubordinates[subordinate.partition] = struct{}{}
			}
		}
		for _, pending := range pendingContent {
			identityDN, err := identitySchema.NormalizeDN(pending.entry.DN)
			if err != nil {
				return fmt.Errorf("import %q: normalize DN identity: %w", pending.entry.DN, err)
			}
			effectiveTarget := target
			toolTarget := target
			if !targetSelected {
				owner, found, err := selectDatabaseTargetForDN(
					configuredTargets,
					identityDN,
				)
				if err != nil {
					return fmt.Errorf("import %q: %w", pending.entry.DN, err)
				}
				if found {
					effectiveTarget = owner
					toolTarget = owner
				} else if databaseTargetsOwnNamingContexts(configuredTargets) {
					return fmt.Errorf(
						"import %q: no configured OpenLDAP database owns this DN",
						pending.entry.DN,
					)
				}
			} else {
				writeTarget, owned, moreSpecific := selectedDatabaseWriteTarget(
					target,
					configuredTargets,
					identityDN,
					gluedSubordinates,
				)
				if !owned && moreSpecific.name != "" {
					return fmt.Errorf(
						"import %q: DN belongs to OpenLDAP database %q, not selected database %q",
						pending.entry.DN,
						moreSpecific.name,
						target.name,
					)
				}
				if owned {
					effectiveTarget = writeTarget
				}
			}
			if !options.DryRun && !effectiveTarget.supportsOfflineImport() {
				return fmt.Errorf(
					"import %q: OpenLDAP %s backend %q does not support offline entry import",
					pending.entry.DN,
					effectiveTarget.backend,
					effectiveTarget.name,
				)
			}
			if err := storage.PutInWithDN(
				tx,
				effectiveTarget.partition,
				pending.entry,
				identityDN,
				false,
			); err != nil {
				return fmt.Errorf("import %q: %w", pending.entry.DN, err)
			}
			importedContent = append(importedContent, importedContentEntry{
				partition:  effectiveTarget.partition,
				dn:         identityDN,
				target:     effectiveTarget,
				toolTarget: toolTarget,
			})
		}

		if options.ValidateConfigurationEntries {
			if err := validateImportedHierarchy(tx, importedConfiguration); err != nil {
				return err
			}
		}
		if err := validateImportedHierarchy(tx, importedContent); err != nil {
			return err
		}
		if options.GenerateOperationalAttributes {
			operationalEntries := append(
				append([]importedContentEntry(nil), importedConfiguration...),
				importedContent...,
			)
			if err := applyImportedOperationalAttributes(
				tx,
				operationalEntries,
				options.CSNServerID,
				csns,
			); err != nil {
				return err
			}
		}
		allImported := append([]importedContentEntry(nil), importedContent...)
		if options.ValidateConfigurationEntries {
			allImported = append(
				append([]importedContentEntry(nil), importedConfiguration...),
				allImported...,
			)
		}
		if options.SkipSchemaValidation {
			if options.RequireObjectClass {
				if err := validateImportedObjectClasses(tx, allImported); err != nil {
					return err
				}
			}
		} else {
			if err := validateImportedContent(
				tx,
				allImported,
				options.Schema,
				options.SkipValueValidation,
			); err != nil {
				return err
			}
		}
		if options.UpdateContextCSN && target.lastMod {
			contextEntries := importedContent
			if target.config {
				contextEntries = importedConfiguration
			}
			if err := updateImportedContextCSN(
				tx,
				target,
				contextEntries,
				options.Schema,
			); err != nil {
				return err
			}
		}
		discardedPartitions := make(map[string]struct{})
		for _, imported := range importedContent {
			if imported.target.discardsOfflineImport() {
				discardedPartitions[imported.partition] = struct{}{}
			}
		}
		for partition := range discardedPartitions {
			if err := storage.WriterInPartition(tx, partition).Clear(); err != nil {
				return fmt.Errorf("discard null backend import: %w", err)
			}
		}
		if options.ValidateTransaction != nil {
			if err := options.ValidateTransaction(tx); err != nil {
				return fmt.Errorf("validate imported transaction: %w", err)
			}
		}

		contexts, err := storage.InferNamingContextsWithNormalizer(tx, identitySchema)
		if err != nil {
			return err
		}
		if err := tx.SetNamingContexts(contexts); err != nil {
			return fmt.Errorf("store naming contexts: %w", err)
		}
		result.NamingContexts = contexts
		if options.DryRun {
			return errImportDryRun
		}
		return nil
	})
	if errors.Is(err, errImportDryRun) {
		return result, nil
	}
	if err != nil {
		return ImportResult{}, err
	}
	return result, nil
}

type importCSNGenerator struct {
	last    time.Time
	counter uint32
}

func (generator *importCSNGenerator) next(serverID uint16) string {
	now := time.Now().UTC().Truncate(time.Microsecond)
	if generator.last.IsZero() || now.After(generator.last) {
		generator.last = now
		generator.counter = 0
	} else if generator.counter == 0xffffff {
		generator.last = generator.last.Add(time.Microsecond)
		generator.counter = 0
	} else {
		generator.counter++
	}
	return fmt.Sprintf(
		"%s#%06x#%03x#000000",
		generator.last.Format("20060102150405.000000Z"),
		generator.counter,
		serverID,
	)
}

func applyImportedOperationalAttributes(
	tx storage.Writer,
	entries []importedContentEntry,
	serverID uint16,
	csns *importCSNGenerator,
) error {
	for _, imported := range entries {
		if !imported.toolTarget.lastMod {
			continue
		}
		entry, err := tx.GetIn(imported.partition, imported.dn)
		if err != nil {
			return fmt.Errorf("load imported entry %q: %w", imported.dn.String(), err)
		}
		timestamp := time.Now().UTC().Format("20060102150405Z")
		if len(entry.Values("entryUUID")) == 0 {
			identifier, err := uuid.NewRandom()
			if err != nil {
				return fmt.Errorf("generate entryUUID for %q: %w", entry.DN, err)
			}
			entry.ReplaceValues("entryUUID", [][]byte{[]byte(identifier.String())})
		}
		if len(entry.Values("creatorsName")) == 0 {
			entry.ReplaceValues("creatorsName", [][]byte{[]byte(imported.toolTarget.rootDN)})
		}
		if len(entry.Values("createTimestamp")) == 0 {
			entry.ReplaceValues("createTimestamp", [][]byte{[]byte(timestamp)})
		}
		if len(entry.Values("entryCSN")) == 0 {
			entry.ReplaceValues("entryCSN", [][]byte{[]byte(csns.next(serverID))})
		}
		if len(entry.Values("modifiersName")) == 0 {
			entry.ReplaceValues("modifiersName", [][]byte{[]byte(imported.toolTarget.rootDN)})
		}
		if len(entry.Values("modifyTimestamp")) == 0 {
			entry.ReplaceValues("modifyTimestamp", [][]byte{[]byte(timestamp)})
		}
		if err := storage.PutInWithDN(
			tx,
			imported.partition,
			entry,
			imported.dn,
			true,
		); err != nil {
			return fmt.Errorf("store operational attributes for %q: %w", entry.DN, err)
		}
	}
	return nil
}

func validateImportedHierarchy(
	tx storage.Writer,
	entries []importedContentEntry,
) error {
	for _, imported := range entries {
		target := imported.target
		if target.discardsOfflineImport() {
			continue
		}
		if target.config {
			configSuffix, err := directory.ParseDN("cn=config")
			if err != nil {
				return err
			}
			target.suffixes = []directory.DN{configSuffix}
		}
		if len(target.suffixes) == 0 {
			continue
		}
		var owningSuffix *directory.DN
		for index := range target.suffixes {
			suffix := &target.suffixes[index]
			if suffix.Equal(imported.dn) || suffix.AncestorOf(imported.dn) {
				if owningSuffix == nil || suffix.Depth() > owningSuffix.Depth() {
					owningSuffix = suffix
				}
			}
		}
		if owningSuffix == nil {
			return fmt.Errorf(
				"import %q: DN is outside the selected database suffixes %s",
				imported.dn.String(),
				formatDatabaseSuffixes(target.suffixes),
			)
		}
		if owningSuffix.Equal(imported.dn) {
			continue
		}
		parent, hasParent := imported.dn.Parent()
		if !hasParent {
			return fmt.Errorf("import %q: entry has no parent", imported.dn.String())
		}
		if _, err := tx.GetIn(imported.partition, parent); err != nil {
			if errors.Is(err, storage.ErrEntryNotFound) {
				return fmt.Errorf(
					"import %q: parent entry %q is missing",
					imported.dn.String(),
					parent.String(),
				)
			}
			return fmt.Errorf(
				"import %q: read parent entry %q: %w",
				imported.dn.String(),
				parent.String(),
				err,
			)
		}
	}
	return nil
}

func formatDatabaseSuffixes(suffixes []directory.DN) string {
	values := make([]string, len(suffixes))
	for index := range suffixes {
		values[index] = suffixes[index].String()
	}
	return strings.Join(values, ", ")
}

func validateImportedObjectClasses(
	tx storage.Writer,
	entries []importedContentEntry,
) error {
	for _, imported := range entries {
		entry, err := tx.GetIn(imported.partition, imported.dn)
		if err != nil {
			return fmt.Errorf("validate imported entry %q: %w", imported.dn.String(), err)
		}
		if len(entry.Values("objectClass")) == 0 {
			return fmt.Errorf("import %q: no objectClass attribute", entry.DN)
		}
	}
	return nil
}

func validateImportedContent(
	tx storage.Writer,
	entries []importedContentEntry,
	baseSchema *schema.Registry,
	skipValueValidation bool,
) error {
	registry, err := importedSchemaRegistry(tx, baseSchema)
	if err != nil {
		return err
	}

	for _, imported := range entries {
		entry, err := tx.GetIn(imported.partition, imported.dn)
		if err != nil {
			return fmt.Errorf("validate imported entry %q: %w", imported.dn.String(), err)
		}
		if err := prepareImportedEntry(
			registry,
			&entry,
			imported.dn,
			skipValueValidation,
		); err != nil {
			return fmt.Errorf("import %q: schema validation: %w", entry.DN, err)
		}
		if err := storage.PutInWithDN(
			tx,
			imported.partition,
			entry,
			imported.dn,
			true,
		); err != nil {
			return fmt.Errorf("store validated entry %q: %w", entry.DN, err)
		}
	}
	return nil
}

func importedSchemaRegistry(
	tx storage.Reader,
	baseSchema *schema.Registry,
) (*schema.Registry, error) {
	registry := baseSchema
	if registry == nil {
		var err error
		registry, err = schema.NewBuiltinRegistry()
		if err != nil {
			return nil, fmt.Errorf("initialize built-in schema: %w", err)
		}
	} else {
		registry = registry.Clone()
	}
	if _, err := schema.LoadOpenLDAPConfigReader(tx, registry); err != nil {
		return nil, fmt.Errorf("load imported OpenLDAP schema: %w", err)
	}
	return registry, nil
}

func updateImportedContextCSN(
	tx storage.Writer,
	target databaseTarget,
	entries []importedContentEntry,
	baseSchema *schema.Registry,
) error {
	if len(target.suffixes) == 0 {
		return nil
	}
	registry, err := importedSchemaRegistry(tx, baseSchema)
	if err != nil {
		return err
	}
	maximum := make(map[uint16][]byte)
	for _, imported := range entries {
		entry, err := tx.GetIn(imported.partition, imported.dn)
		if err != nil {
			return fmt.Errorf("load imported entry %q: %w", imported.dn.String(), err)
		}
		values := entry.Values("entryCSN")
		if len(values) == 0 {
			continue
		}
		normalized, sid, err := normalizeImportedCSN(registry, values[0])
		if err != nil {
			return fmt.Errorf("import %q: entryCSN: %w", entry.DN, err)
		}
		if previous, exists := maximum[sid]; !exists {
			maximum[sid] = normalized
		} else if comparison, err := registry.CompareOrdering(
			"entryCSN",
			"",
			normalized,
			previous,
		); err != nil {
			return fmt.Errorf("compare entryCSN values: %w", err)
		} else if comparison > 0 {
			maximum[sid] = normalized
		}
	}
	if len(maximum) == 0 {
		return nil
	}

	suffix := target.suffixes[0]
	contextDN := suffix
	if target.syncUseSubentry {
		contextDN, err = directory.ParseDN("cn=ldapsync," + suffix.String())
		if err != nil {
			return fmt.Errorf("construct sync context subentry DN: %w", err)
		}
	}
	contextEntry, err := tx.GetIn(target.partition, contextDN)
	if target.syncUseSubentry && errors.Is(err, storage.ErrEntryNotFound) {
		contextEntry = directory.Entry{
			DN: contextDN.String(),
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: [][]byte{
					[]byte("top"),
					[]byte("subentry"),
					[]byte("syncProviderSubentry"),
				}},
				{Description: "structuralObjectClass", Values: [][]byte{[]byte("subentry")}},
				{Description: "cn", Values: [][]byte{[]byte("ldapsync")}},
				{Description: "subtreeSpecification", Values: [][]byte{[]byte("{}")}},
			},
		}
		err = nil
	}
	if errors.Is(err, storage.ErrEntryNotFound) {
		return fmt.Errorf("context entry %q is missing", contextDN.String())
	}
	if err != nil {
		return fmt.Errorf("load context entry %q: %w", contextDN.String(), err)
	}
	existingValues := contextEntry.Values("contextCSN")
	change := len(existingValues) == 0
	importedSIDs := make(map[uint16]struct{}, len(maximum))
	for sid := range maximum {
		importedSIDs[sid] = struct{}{}
	}
	for _, raw := range existingValues {
		normalized, sid, err := normalizeImportedCSN(registry, raw)
		if err != nil {
			return fmt.Errorf("context entry %q contextCSN: %w", contextDN.String(), err)
		}
		delete(importedSIDs, sid)
		if candidate, exists := maximum[sid]; !exists {
			maximum[sid] = normalized
		} else if comparison, err := registry.CompareOrdering(
			"entryCSN",
			"",
			normalized,
			candidate,
		); err != nil {
			return fmt.Errorf("compare contextCSN values: %w", err)
		} else if comparison > 0 {
			maximum[sid] = normalized
		} else if comparison < 0 {
			change = true
		}
	}
	if len(importedSIDs) > 0 {
		change = true
	}
	if !change {
		return nil
	}
	sids := make([]int, 0, len(maximum))
	for sid := range maximum {
		sids = append(sids, int(sid))
	}
	sort.Ints(sids)
	values := make([][]byte, len(sids))
	for index, sid := range sids {
		values[index] = maximum[uint16(sid)]
	}
	contextEntry.ReplaceValues("contextCSN", values)
	if target.config {
		if err := tx.PutIn(target.partition, contextEntry, true); err != nil {
			return fmt.Errorf("store contextCSN on %q: %w", contextDN.String(), err)
		}
		return nil
	}
	contextIdentityDN, err := registry.NormalizeDN(contextEntry.DN)
	if err != nil {
		return fmt.Errorf("normalize context entry DN %q: %w", contextEntry.DN, err)
	}
	if err := storage.PutInWithDN(
		tx,
		target.partition,
		contextEntry,
		contextIdentityDN,
		true,
	); err != nil {
		return fmt.Errorf("store contextCSN on %q: %w", contextDN.String(), err)
	}
	return nil
}

func normalizeImportedCSN(
	registry *schema.Registry,
	raw []byte,
) ([]byte, uint16, error) {
	normalized, err := registry.NormalizeEqualityValue("entryCSN", raw)
	if err != nil {
		return nil, 0, err
	}
	parts := strings.Split(string(normalized), "#")
	if len(parts) != 4 {
		return nil, 0, fmt.Errorf("invalid CSN %q", raw)
	}
	sid, err := strconv.ParseUint(parts[2], 16, 12)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid CSN SID %q", parts[2])
	}
	return normalized, uint16(sid), nil
}

func prepareImportedEntry(
	registry *schema.Registry,
	entry *directory.Entry,
	dn directory.DN,
	skipValueValidation bool,
) error {
	if err := ensureImportedNamingValues(registry, entry, dn); err != nil {
		return err
	}
	validationOptions := schema.EntryValidationOptions{
		SkipValueSyntax: skipValueValidation,
	}
	if err := registry.ValidateEntryWithOptions(*entry, validationOptions); err != nil {
		return err
	}

	structural, err := registry.StructuralObjectClass(*entry)
	if err != nil {
		return fmt.Errorf("resolve structural object class: %w", err)
	}
	values := registry.AttributeValues(*entry, "structuralObjectClass")
	if len(values) == 0 {
		entry.ReplaceValues("structuralObjectClass", [][]byte{[]byte(structural)})
		if err := registry.ValidateEntryWithOptions(*entry, validationOptions); err != nil {
			return err
		}
		sortImportedAttributes(entry)
		return nil
	}
	declared, found := registry.ObjectClass(string(values[0]))
	if !found {
		return &schema.Violation{
			Kind:      schema.ViolationStructuralObjectClass,
			Attribute: "structuralObjectClass",
			Message:   fmt.Sprintf("unknown structural object class %q", values[0]),
		}
	}
	computed, found := registry.ObjectClass(structural)
	if !found || declared.OID != computed.OID {
		return &schema.Violation{
			Kind:      schema.ViolationStructuralObjectClass,
			Attribute: "structuralObjectClass",
			Message: fmt.Sprintf(
				"declares %q but objectClass values resolve to %q",
				declared.Name(),
				structural,
			),
		}
	}
	sortImportedAttributes(entry)
	return nil
}

func sortImportedAttributes(entry *directory.Entry) {
	sort.SliceStable(entry.Attributes, func(left, right int) bool {
		return strings.ToLower(entry.Attributes[left].Description) <
			strings.ToLower(entry.Attributes[right].Description)
	})
}

func ensureImportedNamingValues(
	registry *schema.Registry,
	entry *directory.Entry,
	dn directory.DN,
) error {
	for _, naming := range dn.RDNValues() {
		attributeType, found, err := registry.EffectiveAttributeType(naming.Type)
		if err != nil {
			return err
		}
		if !found {
			return &schema.Violation{
				Kind:      schema.ViolationUndefinedAttribute,
				Attribute: naming.Type,
				Message:   "undefined naming attribute type",
			}
		}
		if attributeType.Usage != schema.UsageUserApplications ||
			attributeType.Collective || attributeType.Obsolete ||
			attributeType.Equality == "" {
			return &schema.Violation{
				Kind:      schema.ViolationNaming,
				Attribute: naming.Type,
				Message:   "attribute is not suitable for naming",
			}
		}

		values := registry.AttributeValues(*entry, naming.Type)
		matched := false
		for _, value := range values {
			comparison, err := registry.Compare(
				naming.Type,
				"",
				value,
				naming.Value,
			)
			if err != nil {
				return &schema.Violation{
					Kind:      schema.ViolationNaming,
					Attribute: naming.Type,
					Message:   err.Error(),
				}
			}
			if comparison == 0 {
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		if attributeType.SingleValue && len(values) != 0 {
			return &schema.Violation{
				Kind:      schema.ViolationNaming,
				Attribute: naming.Type,
				Message:   "single-valued naming attribute conflicts with the RDN",
			}
		}
		if err := entry.AddValues(naming.Type, [][]byte{naming.Value}); err != nil {
			return &schema.Violation{
				Kind:      schema.ViolationNaming,
				Attribute: naming.Type,
				Message:   err.Error(),
			}
		}
	}
	return nil
}

func fromLDAPEntry(source *ldap.Entry) directory.Entry {
	entry := directory.Entry{
		DN:         source.DN,
		Attributes: make([]directory.Attribute, 0, len(source.Attributes)),
	}
	for _, sourceAttribute := range source.Attributes {
		attribute := directory.Attribute{
			Description: sourceAttribute.Name,
			Values:      make([][]byte, len(sourceAttribute.ByteValues)),
		}
		for i := range sourceAttribute.ByteValues {
			attribute.Values[i] = append([]byte(nil), sourceAttribute.ByteValues[i]...)
		}
		entry.Attributes = append(entry.Attributes, attribute)
	}
	return entry
}
