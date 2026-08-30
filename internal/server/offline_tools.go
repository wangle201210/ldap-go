package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	maxOfflineLDIFSize   = 64 << 20
	maxOfflineLDIFLine   = 1 << 20
	maxOfflineLDIFRecord = 8 << 20
	maxOfflineURLValue   = 8 << 20
)

// OfflineAuthorizationResult is the identity mapping and authorization result
// produced by slapauth without starting an LDAP listener.
type OfflineAuthorizationResult struct {
	AuthenticationDN string
	AuthorizationDN  string
	Authorized       bool
}

// CheckOfflineAuthorization reuses slapd's configured SASL identity rewrite
// and authzTo/authzFrom policy against one consistent read transaction.
func CheckOfflineAuthorization(
	ctx context.Context,
	store storage.Store,
	mechanism, realm, authenticationID, authorizationID string,
) (OfflineAuthorizationResult, error) {
	var result OfflineAuthorizationResult
	err := store.View(ctx, func(reader storage.Reader) error {
		instance, runtime, err := buildOfflineRuntime(reader, store)
		if err != nil {
			return err
		}
		authenticationDN, err := instance.saslUserDN(
			ctx, runtime, mechanism, authenticationID, effectiveOfflineRealm(runtime, realm),
		)
		if err != nil {
			return fmt.Errorf("map authentication ID %q: %w", authenticationID, err)
		}
		result.AuthenticationDN = authenticationDN.String()
		if authorizationID == "" {
			result.Authorized = true
			return nil
		}
		authorizationDN, err := resolveOfflineAuthorizationID(
			ctx, instance, runtime, mechanism, realm, authorizationID,
		)
		if err != nil {
			return fmt.Errorf("map authorization ID %q: %w", authorizationID, err)
		}
		result.AuthorizationDN = authorizationDN.String()
		result.Authorized, err = instance.saslAuthorized(
			ctx, runtime, authenticationDN, authorizationDN,
		)
		return err
	})
	return result, err
}

func effectiveOfflineRealm(runtime *runtimeState, override string) string {
	if override != "" {
		return override
	}
	return runtime.sasl.realm
}

func resolveOfflineAuthorizationID(
	ctx context.Context,
	instance *Server,
	runtime *runtimeState,
	mechanism, realm, identity string,
) (directory.DN, error) {
	switch {
	case strings.HasPrefix(strings.ToLower(identity), "dn:"):
		return normalizeSASLIdentityDN(runtime, identity[3:])
	case strings.HasPrefix(strings.ToLower(identity), "u:"):
		return instance.saslUserDN(
			ctx, runtime, mechanism, identity[2:], effectiveOfflineRealm(runtime, realm),
		)
	default:
		return directory.DN{}, errors.New("authorization ID must use u: or dn: form")
	}
}

// OfflineSchemaOptions selects the database and optional entry subset checked
// by CheckOfflineSchema.
type OfflineSchemaOptions struct {
	Database            string
	IncludeSubordinates bool
	Continue            bool
	Subtree             string
	Filter              string
}

type OfflineSchemaIssue struct {
	DN      string
	EntryID uint64
	Code    uint16
	Err     error
}

type OfflineSchemaRecord struct {
	DN      string
	EntryID uint64
}

type OfflineSchemaReport struct {
	Checked int
	Issues  []OfflineSchemaIssue
	Records []OfflineSchemaRecord
}

// CheckOfflineSchema validates stored user and operational attributes without
// writing metadata, indexes, or entries.
func CheckOfflineSchema(
	ctx context.Context,
	store storage.Store,
	options OfflineSchemaOptions,
) (OfflineSchemaReport, error) {
	var report OfflineSchemaReport
	err := store.View(ctx, func(reader storage.Reader) error {
		_, runtime, err := buildOfflineRuntime(reader, store)
		if err != nil {
			return err
		}
		indexes, err := selectOfflineDatabases(
			runtime, options.Database, options.IncludeSubordinates,
		)
		if err != nil {
			return err
		}
		var subtree *directory.DN
		if strings.TrimSpace(options.Subtree) != "" {
			parsed, parseErr := runtime.schema.NormalizeDN(options.Subtree)
			if parseErr != nil || parsed.Depth() == 0 {
				if parseErr == nil {
					parseErr = errors.New("subtree DN must not be empty")
				}
				return fmt.Errorf("invalid subtree DN: %w", parseErr)
			}
			subtree = &parsed
		}
		var filter *directory.Filter
		if strings.TrimSpace(options.Filter) != "" {
			compiled, compileErr := ldapwire.CompileFilter(options.Filter)
			if compileErr != nil {
				return fmt.Errorf("invalid schema filter: %w", compileErr)
			}
			filter = &compiled
		}
		for _, index := range indexes {
			database := runtime.databases[index]
			if !offlineDatabaseReadable(database) {
				return fmt.Errorf("database %q does not support offline schema scans", database.name)
			}
			tx := readerForDatabase(reader, database, ctx)
			err := tx.ForEach(func(entry directory.Entry) error {
				entryDN, parseErr := runtime.schema.NormalizeDN(entry.DN)
				if parseErr != nil {
					return parseErr
				}
				if subtree != nil {
					if !subtree.Equal(entryDN) && !subtree.AncestorOf(entryDN) {
						return nil
					}
				}
				if filter != nil {
					matched, matchErr := filter.MatchWith(entry, runtime.schema)
					if matchErr != nil {
						return matchErr
					}
					if !matched {
						return nil
					}
				}
				report.Checked++
				record := OfflineSchemaRecord{
					DN:      entry.DN,
					EntryID: stableOfflineEntryID(database.partition, entryDN),
				}
				if validationErr := validateOfflineSchemaEntry(
					runtime.schema, entryDN, entry,
				); validationErr != nil {
					result := schemaValidationResult(validationErr)
					issue := OfflineSchemaIssue{
						DN: entry.DN, EntryID: record.EntryID,
						Code: uint16(result.Code), Err: validationErr,
					}
					report.Issues = append(report.Issues, issue)
					report.Records = append(report.Records, record)
					if !options.Continue {
						return errStopOfflineSchema
					}
					return nil
				}
				report.Records = append(report.Records, record)
				return nil
			})
			if errors.Is(err, errStopOfflineSchema) {
				return err
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, errStopOfflineSchema) {
		err = nil
	}
	sort.Slice(report.Records, func(left, right int) bool {
		if report.Records[left].EntryID != report.Records[right].EntryID {
			return report.Records[left].EntryID < report.Records[right].EntryID
		}
		return report.Records[left].DN < report.Records[right].DN
	})
	return report, err
}

func stableOfflineEntryID(partition string, dn directory.DN) uint64 {
	digest := sha256.Sum256([]byte(partition + "\x00" + dn.Key()))
	id := binary.BigEndian.Uint64(digest[:8])
	if id == 0 {
		return 1
	}
	return id
}

var errStopOfflineSchema = errors.New("stop after schema violation")

func validateOfflineSchemaEntry(
	registry *schema.Registry,
	dn directory.DN,
	entry directory.Entry,
) error {
	if err := registry.ValidateEntry(entry); err != nil {
		return err
	}
	for _, rdnValue := range dn.RDNValues() {
		matched, err := entryHasSchemaAttributeValue(
			entry, rdnValue.Type, rdnValue.Value, registry,
		)
		if err != nil {
			return err
		}
		if !matched {
			return &schema.Violation{
				Kind: schema.ViolationNaming, Attribute: rdnValue.Type,
				Message: "RDN value is missing from entry",
			}
		}
	}
	structural, err := registry.StructuralObjectClass(entry)
	if err != nil {
		return err
	}
	declared := registry.AttributeValues(entry, "structuralObjectClass")
	if len(declared) == 0 {
		if isConfigurationDN(dn) {
			return nil
		}
		return &schema.Violation{
			Kind: schema.ViolationStructuralObjectClass, Attribute: "structuralObjectClass",
			Message: "operational structural object class is missing",
		}
	}
	if len(declared) != 1 {
		return &schema.Violation{
			Kind: schema.ViolationSingleValue, Attribute: "structuralObjectClass",
			Message: "single-valued attribute has multiple values",
		}
	}
	left, leftOK := registry.ObjectClass(string(declared[0]))
	right, rightOK := registry.ObjectClass(structural)
	if !leftOK || !rightOK || left.OID != right.OID {
		return &schema.Violation{
			Kind:      schema.ViolationStructuralObjectClass,
			Attribute: "structuralObjectClass",
			Message:   fmt.Sprintf("declares %q but objectClass values resolve to %q", declared[0], structural),
		}
	}
	return nil
}

type OfflineModifyOptions struct {
	Database            string
	IncludeSubordinates bool
	Continue            bool
	DryRun              bool
	SkipSchema          bool
	SkipValueValidation bool
	ServerID            uint16
	ResumeLine          int
	UpdateContextCSN    bool
}

type OfflineModifyFailure struct {
	Line int
	DN   string
	Err  error
}

type OfflineModifyReport struct {
	Applied  int
	Failures []OfflineModifyFailure
}

type offlineContextCSNCandidate struct {
	partition string
	value     []byte
}

type offlineChangeResult struct {
	contextCSNs []offlineContextCSNCandidate
}

var (
	errOfflineModifyDryRun = errors.New("rollback offline modify dry run")
)

// ApplyOfflineChanges applies each LDIF record in its own transaction. Dry-run
// mode instead uses one shared transaction so dependent records see prior
// changes, then rolls the complete sequence back.
func ApplyOfflineChanges(
	ctx context.Context,
	store storage.Store,
	reader io.Reader,
	options OfflineModifyOptions,
) (OfflineModifyReport, error) {
	changes, parseFailures, err := parseOfflineChanges(
		reader,
		options.Continue,
		options.ResumeLine,
	)
	report := OfflineModifyReport{Failures: parseFailures}
	if err != nil {
		return report, err
	}
	instance, err := newOfflineServer(store)
	if err != nil {
		return report, err
	}
	if options.Continue {
		err = store.View(ctx, func(reader storage.Reader) error {
			runtime, err := buildOfflineRuntimeWithServer(instance, reader)
			if err != nil {
				return err
			}
			indexes, err := selectOfflineDatabases(
				runtime,
				options.Database,
				options.IncludeSubordinates,
			)
			if err != nil {
				return err
			}
			for _, index := range indexes {
				if isConfigDatabase(runtime.databases[index]) {
					return errors.New(
						"slapmodify -c does not support cn=config because partial configuration changes cannot be published safely",
					)
				}
			}
			return nil
		})
		if err != nil {
			return report, err
		}
	}
	if options.DryRun {
		var dryRunErr error
		applyErr := store.Update(ctx, func(writer storage.Writer) error {
			for _, change := range changes {
				var changeResult offlineChangeResult
				changeErr := applyOfflineChangeTransaction(
					ctx, instance, writer, change, options, &changeResult,
				)
				if changeErr == nil {
					report.Applied++
					continue
				}
				report.Failures = append(report.Failures, OfflineModifyFailure{
					Line: change.line, DN: change.dn, Err: changeErr,
				})
				if !options.Continue {
					dryRunErr = fmt.Errorf("line %d: %w", change.line, changeErr)
					break
				}
			}
			return errOfflineModifyDryRun
		})
		if !errors.Is(applyErr, errOfflineModifyDryRun) {
			return report, applyErr
		}
		sortOfflineModifyFailures(&report)
		if dryRunErr != nil {
			return report, dryRunErr
		}
		if len(report.Failures) != 0 {
			return report, fmt.Errorf("slapmodify rejected %d record(s)", len(report.Failures))
		}
		return report, nil
	}
	var contextCSNs []offlineContextCSNCandidate
	for _, change := range changes {
		var changeResult offlineChangeResult
		applyErr := store.Update(ctx, func(writer storage.Writer) error {
			return applyOfflineChangeTransaction(
				ctx, instance, writer, change, options, &changeResult,
			)
		})
		if applyErr == nil {
			report.Applied++
			contextCSNs = append(contextCSNs, changeResult.contextCSNs...)
			continue
		}
		report.Failures = append(report.Failures, OfflineModifyFailure{
			Line: change.line, DN: change.dn, Err: applyErr,
		})
		if !options.Continue {
			if report.Applied > 0 && options.UpdateContextCSN {
				if updateErr := updateOfflineContextCSN(
					ctx, store, instance, options, contextCSNs,
				); updateErr != nil {
					return report, errors.Join(
						fmt.Errorf("line %d: %w", change.line, applyErr),
						updateErr,
					)
				}
			}
			return report, fmt.Errorf("line %d: %w", change.line, applyErr)
		}
	}
	if report.Applied > 0 && options.UpdateContextCSN {
		if err := updateOfflineContextCSN(
			ctx, store, instance, options, contextCSNs,
		); err != nil {
			return report, err
		}
	}
	sortOfflineModifyFailures(&report)
	if len(report.Failures) != 0 {
		return report, fmt.Errorf("slapmodify rejected %d record(s)", len(report.Failures))
	}
	return report, nil
}

func updateOfflineContextCSN(
	ctx context.Context,
	store storage.Store,
	instance *Server,
	options OfflineModifyOptions,
	candidates []offlineContextCSNCandidate,
) error {
	return store.Update(ctx, func(writer storage.Writer) error {
		runtime, err := buildOfflineRuntimeWithServer(instance, writer)
		if err != nil {
			return err
		}
		if err := migrateRuntimeDNIdentitiesInWriter(writer, runtime); err != nil {
			return err
		}
		indexes, err := selectOfflineDatabases(
			runtime,
			options.Database,
			options.IncludeSubordinates,
		)
		if err != nil {
			return err
		}
		for _, index := range indexes {
			database := runtime.databases[index]
			if !database.lastMod || len(database.suffixes) == 0 {
				continue
			}
			if !offlineDatabaseWritable(database) {
				return fmt.Errorf(
					"database %q does not support offline contextCSN updates",
					database.name,
				)
			}
			databaseCandidates := make([][]byte, 0, len(candidates))
			for _, candidate := range candidates {
				if candidate.partition == database.partition {
					databaseCandidates = append(databaseCandidates, candidate.value)
				}
			}
			if err := updateOfflineDatabaseContextCSN(
				writerForDatabase(writer, database),
				database,
				runtime.schema,
				databaseCandidates,
			); err != nil {
				return fmt.Errorf("database %q contextCSN: %w", database.name, err)
			}
		}
		return nil
	})
}

func updateOfflineDatabaseContextCSN(
	tx storage.Writer,
	database runtimeDatabase,
	registry *schema.Registry,
	candidates [][]byte,
) error {
	maximum := make(map[uint16][]byte)
	for _, raw := range candidates {
		normalized, sid, err := normalizeOfflineCSN(registry, raw)
		if err != nil {
			return fmt.Errorf("committed change CSN: %w", err)
		}
		maximum[sid] = normalized
	}
	if err := tx.ForEach(func(entry directory.Entry) error {
		for _, raw := range entry.Values("entryCSN") {
			normalized, sid, err := normalizeOfflineCSN(registry, raw)
			if err != nil {
				return fmt.Errorf("entry %q entryCSN: %w", entry.DN, err)
			}
			previous, found := maximum[sid]
			if !found {
				maximum[sid] = normalized
				continue
			}
			comparison, err := registry.CompareOrdering(
				"entryCSN", "", normalized, previous,
			)
			if err != nil {
				return err
			}
			if comparison > 0 {
				maximum[sid] = normalized
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if len(maximum) == 0 {
		return nil
	}

	contextDN := database.suffixes[0]
	if database.syncUseSubentry {
		var err error
		contextDN, err = parseRuntimeDN(
			"cn=ldapsync,"+contextDN.String(),
			database.dnNormalizer,
		)
		if err != nil {
			return fmt.Errorf("construct sync context subentry: %w", err)
		}
	}
	contextEntry, err := tx.Get(contextDN)
	createContextEntry := database.syncUseSubentry && errors.Is(err, storage.ErrEntryNotFound)
	if createContextEntry {
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
		return err
	}
	for _, raw := range contextEntry.Values("contextCSN") {
		normalized, sid, err := normalizeOfflineCSN(registry, raw)
		if err != nil {
			return fmt.Errorf("existing contextCSN: %w", err)
		}
		candidate, found := maximum[sid]
		if !found {
			maximum[sid] = normalized
			continue
		}
		comparison, err := registry.CompareOrdering(
			"entryCSN", "", normalized, candidate,
		)
		if err != nil {
			return err
		}
		if comparison > 0 {
			maximum[sid] = normalized
		}
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
	if err := tx.Put(contextEntry, !createContextEntry); err != nil {
		return fmt.Errorf("store context entry %q: %w", contextDN.String(), err)
	}
	return nil
}

func normalizeOfflineCSN(
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

func sortOfflineModifyFailures(report *OfflineModifyReport) {
	sort.SliceStable(report.Failures, func(left, right int) bool {
		return report.Failures[left].Line < report.Failures[right].Line
	})
}

func applyOfflineChangeTransaction(
	ctx context.Context,
	instance *Server,
	writer storage.Writer,
	change offlineChange,
	options OfflineModifyOptions,
	result *offlineChangeResult,
) error {
	*result = offlineChangeResult{}
	runtime, err := buildOfflineRuntimeWithServer(instance, writer)
	if err != nil {
		return err
	}
	if err := migrateRuntimeDNIdentitiesInWriter(writer, runtime); err != nil {
		return err
	}
	indexes, err := selectOfflineDatabases(
		runtime, options.Database, options.IncludeSubordinates,
	)
	if err != nil {
		return err
	}
	allowed := make(map[int]struct{}, len(indexes))
	for _, index := range indexes {
		if !offlineDatabaseWritable(runtime.databases[index]) {
			return fmt.Errorf(
				"database %q does not support offline changes",
				runtime.databases[index].name,
			)
		}
		allowed[index] = struct{}{}
	}
	if err := instance.applyOfflineChange(
		ctx, writer, runtime, allowed, change, options, result,
	); err != nil {
		return offlineModifyDiagnosticError(err)
	}
	touchesConfig, err := offlineChangeTouchesConfig(runtime, change)
	if err != nil {
		return err
	}
	if touchesConfig {
		runtime, err = buildOfflineRuntimeWithServer(instance, writer)
		if err != nil {
			return fmt.Errorf("validate modified cn=config: %w", err)
		}
		if err := migrateRuntimeDNIdentitiesInWriter(writer, runtime); err != nil {
			return fmt.Errorf("migrate modified cn=config identities: %w", err)
		}
	}
	return refreshRuntimeNamingContexts(writer, runtime)
}

func offlineModifyDiagnosticError(err error) error {
	var failure *operationFailure
	if !errors.As(err, &failure) || failure.result.DiagnosticMessage == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, failure.result.DiagnosticMessage)
}

func offlineChangeTouchesConfig(
	runtime *runtimeState,
	change offlineChange,
) (bool, error) {
	dn, err := parseRuntimeConnectionDN(runtime, change.dn)
	if err != nil {
		return false, fmt.Errorf("normalize changed DN %q: %w", change.dn, err)
	}
	if isConfigurationDN(dn) {
		return true, nil
	}
	if change.kind != offlineChangeModifyDN || !change.hasSuperior {
		return false, nil
	}
	superior, err := parseRuntimeConnectionDN(runtime, change.newSuperior)
	if err != nil {
		return false, fmt.Errorf("normalize newSuperior %q: %w", change.newSuperior, err)
	}
	return isConfigurationDN(superior), nil
}

type offlineChangeKind uint8

const (
	offlineChangeAdd offlineChangeKind = iota + 1
	offlineChangeModify
	offlineChangeDelete
	offlineChangeModifyDN
)

type offlineChange struct {
	line          int
	dn            string
	kind          offlineChangeKind
	entry         directory.Entry
	modifications []ldapwire.Modification
	newRDN        string
	deleteOldRDN  bool
	newSuperior   string
	hasSuperior   bool
}

func (server *Server) applyOfflineChange(
	ctx context.Context,
	writer storage.Writer,
	runtime *runtimeState,
	allowed map[int]struct{},
	change offlineChange,
	options OfflineModifyOptions,
	result *offlineChangeResult,
) error {
	legacyDN, err := directory.ParseDN(change.dn)
	if err != nil || legacyDN.Depth() == 0 {
		if err == nil {
			err = errors.New("DN must not be empty")
		}
		return fmt.Errorf("invalid DN %q: %w", change.dn, err)
	}
	databaseIndex := databaseIndexForDN(runtime.databases, legacyDN)
	if databaseIndex < 0 {
		return fmt.Errorf("no configured database owns %q", change.dn)
	}
	if _, ok := allowed[databaseIndex]; !ok {
		return fmt.Errorf("entry %q is outside the selected database", change.dn)
	}
	database := runtime.databases[databaseIndex]
	dn, err := normalizeRuntimeDatabaseDN(database, legacyDN)
	if err != nil {
		return fmt.Errorf("normalize DN %q: %w", change.dn, err)
	}
	tx := writerForDatabase(writer, database)
	actor := ""
	if database.rootDN != nil {
		actor = database.rootDN.String()
	}
	switch change.kind {
	case offlineChangeAdd:
		entry := change.entry.Clone()
		entry.DN = dn.String()
		if database.lastMod {
			if err := server.applyCreateOperationalAttributesContext(
				ctx, &entry, actor, true, options.ServerID, runtime.schema,
			); err != nil {
				return err
			}
		}
		if err := server.prepareOfflineEntry(runtime, tx, dn, &entry, options); err != nil {
			return err
		}
		if err := validateOfflineAddParent(tx, database, dn); err != nil {
			return err
		}
		if err := tx.Put(entry, false); err != nil {
			return fmt.Errorf("add %q: %w", change.dn, err)
		}
	case offlineChangeModify:
		entry, err := tx.Get(dn)
		if err != nil {
			return fmt.Errorf("modify %q: %w", change.dn, err)
		}
		for _, modification := range change.modifications {
			if !options.SkipValueValidation {
				if err := validateOfflineAttributeValueSyntax(
					runtime.schema,
					modification.Attribute,
				); err != nil {
					return err
				}
			}
			if err := applyModification(&entry, modification); err != nil {
				return fmt.Errorf("modify %q: %w", change.dn, err)
			}
		}
		if database.lastMod {
			server.applyModifyOperationalAttributesContext(
				ctx, &entry, actor, options.ServerID,
			)
		}
		if err := server.prepareOfflineEntry(runtime, tx, dn, &entry, options); err != nil {
			return err
		}
		if err := tx.Put(entry, true); err != nil {
			return fmt.Errorf("modify %q: %w", change.dn, err)
		}
	case offlineChangeDelete:
		hasChildren := false
		if err := tx.ForEach(func(entry directory.Entry) error {
			candidate, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			candidate, err = storage.NormalizeReaderDN(tx, candidate)
			if err != nil {
				return err
			}
			if dn.AncestorOf(candidate) {
				hasChildren = true
			}
			return nil
		}); err != nil {
			return err
		}
		if hasChildren {
			return operationFailed(
				ldapwire.ResultNotAllowedOnNonLeaf,
				"subordinate objects must be deleted first",
			)
		}
		if err := tx.Delete(dn); err != nil {
			return fmt.Errorf("delete %q: %w", change.dn, err)
		}
		if database.lastMod && options.UpdateContextCSN {
			result.contextCSNs = append(result.contextCSNs, offlineContextCSNCandidate{
				partition: database.partition,
				value:     []byte(server.nextCSNContext(ctx, options.ServerID)),
			})
		}
	case offlineChangeModifyDN:
		return server.applyOfflineModifyDN(
			ctx, tx, runtime, databaseIndex, database, dn, actor, change, options,
		)
	default:
		return errors.New("unsupported offline change operation")
	}
	return nil
}

func (server *Server) applyOfflineModifyDN(
	ctx context.Context,
	tx storage.Writer,
	runtime *runtimeState,
	databaseIndex int,
	database runtimeDatabase,
	oldDN directory.DN,
	actor string,
	change offlineChange,
	options OfflineModifyOptions,
) error {
	newRDN, err := parseRuntimeDN(change.newRDN, database.dnNormalizer)
	if err != nil || newRDN.Depth() != 1 {
		if err == nil {
			err = errors.New("new RDN must contain exactly one relative distinguished name")
		}
		return fmt.Errorf("invalid newrdn %q: %w", change.newRDN, err)
	}
	var newSuperior directory.DN
	if change.hasSuperior {
		legacySuperior, parseErr := directory.ParseDN(change.newSuperior)
		if parseErr != nil {
			return fmt.Errorf("invalid newsuperior %q: %w", change.newSuperior, parseErr)
		}
		newSuperior, err = normalizeRuntimeDatabaseDN(database, legacySuperior)
		if err != nil {
			return fmt.Errorf("normalize newsuperior %q: %w", change.newSuperior, err)
		}
	} else {
		var ok bool
		newSuperior, ok = oldDN.Parent()
		if !ok {
			return errors.New("root DSE cannot be renamed")
		}
	}
	if oldDN.Equal(newSuperior) || oldDN.AncestorOf(newSuperior) {
		return errors.New("cannot move an entry below itself")
	}
	newDN, err := directory.ComposeLocalName(newRDN, newSuperior)
	if err != nil {
		return fmt.Errorf("compose renamed DN: %w", err)
	}
	destinationIndex := databaseIndexForDN(runtime.databases, newDN)
	if destinationIndex != databaseIndex || destinationIndex < 0 ||
		runtime.databases[destinationIndex].partition != database.partition {
		return errors.New("cannot rename between databases")
	}
	if !databaseOwnsSuffix(database, newDN) {
		if _, err := tx.Get(newSuperior); err != nil {
			return fmt.Errorf("newSuperior %q: %w", newSuperior.String(), err)
		}
	}

	type offlineMove struct {
		oldDN directory.DN
		newDN directory.DN
		entry directory.Entry
	}
	var moves []offlineMove
	oldKeys := make(map[string]struct{})
	if err := tx.ForEach(func(entry directory.Entry) error {
		candidate, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		candidate, err = storage.NormalizeReaderDN(tx, candidate)
		if err != nil {
			return err
		}
		if !oldDN.Equal(candidate) && !oldDN.AncestorOf(candidate) {
			return nil
		}
		replaced, err := candidate.ReplaceAncestor(oldDN, newDN)
		if err != nil {
			return err
		}
		moves = append(moves, offlineMove{oldDN: candidate, newDN: replaced, entry: entry})
		oldKeys[candidate.Key()] = struct{}{}
		return nil
	}); err != nil {
		return err
	}
	if len(moves) == 0 {
		return fmt.Errorf("rename %q: %w", change.dn, storage.ErrEntryNotFound)
	}
	for _, move := range moves {
		if _, err := tx.Get(move.newDN); err == nil {
			if _, moving := oldKeys[move.newDN.Key()]; !moving {
				return fmt.Errorf("rename %q: %w", change.dn, storage.ErrEntryExists)
			}
		} else if !errors.Is(err, storage.ErrEntryNotFound) {
			return err
		}
	}
	for index := range moves {
		move := &moves[index]
		move.entry.DN = move.newDN.String()
		if !move.oldDN.Equal(oldDN) {
			continue
		}
		if change.deleteOldRDN {
			deleteSchemaRDNValues(&move.entry, oldDN, runtime.schema)
		}
		ensureSchemaRDNValues(&move.entry, newDN, runtime.schema)
		if database.lastMod {
			server.applyModifyOperationalAttributesContext(
				ctx, &move.entry, actor, options.ServerID,
			)
		}
		if err := server.prepareOfflineEntry(
			runtime, tx, newDN, &move.entry, options,
		); err != nil {
			return err
		}
	}
	sort.Slice(moves, func(left, right int) bool {
		return moves[left].oldDN.Depth() > moves[right].oldDN.Depth()
	})
	for _, move := range moves {
		if err := tx.Delete(move.oldDN); err != nil {
			return fmt.Errorf("remove old DN %q: %w", move.oldDN.String(), err)
		}
	}
	sort.Slice(moves, func(left, right int) bool {
		return moves[left].newDN.Depth() < moves[right].newDN.Depth()
	})
	for _, move := range moves {
		if err := tx.Put(move.entry, false); err != nil {
			return fmt.Errorf("store renamed DN %q: %w", move.newDN.String(), err)
		}
	}
	return nil
}

func validateOfflineAddParent(
	reader storage.Reader,
	database runtimeDatabase,
	dn directory.DN,
) error {
	if databaseOwnsSuffix(database, dn) {
		return nil
	}
	parent, ok := dn.Parent()
	if !ok {
		return fmt.Errorf("add %q: parent is missing", dn.String())
	}
	if _, err := reader.Get(parent); err != nil {
		return fmt.Errorf("add %q: parent %q: %w", dn.String(), parent.String(), err)
	}
	return nil
}

func (server *Server) prepareOfflineEntry(
	runtime *runtimeState,
	reader storage.Reader,
	dn directory.DN,
	entry *directory.Entry,
	options OfflineModifyOptions,
) error {
	if options.SkipSchema || isConfigurationDN(dn) {
		if result := validateNewEntryAttributes(*entry); result != nil {
			return &operationFailure{result: *result}
		}
	} else if result := validateNewEntryWithSchema(
		*entry, dn, runtime.schema,
	); result != nil {
		return &operationFailure{result: *result}
	}
	if isConfigurationDN(dn) {
		return nil
	}
	if options.SkipSchema {
		if options.SkipValueValidation {
			return nil
		}
		for _, attribute := range entry.Attributes {
			if err := validateOfflineAttributeValueSyntax(
				runtime.schema,
				attribute,
			); err != nil {
				return err
			}
		}
		return nil
	}
	if err := runtime.schema.ValidateEntryWithOptions(*entry, schema.EntryValidationOptions{
		SkipValueSyntax: options.SkipValueValidation,
	}); err != nil {
		return operationFailureFromSchema(err)
	}
	parent, err := schemaParentEntry(reader, dn)
	if err != nil {
		return err
	}
	if err := server.applyDITStructureRuleOperationalAttribute(runtime, entry, parent, false); err != nil {
		return operationFailureFromSchema(err)
	}
	if err := server.applySchemaOperationalAttributes(runtime, entry); err != nil {
		return err
	}
	if err := runtime.schema.ValidateEntryWithOptions(*entry, schema.EntryValidationOptions{
		SkipValueSyntax: options.SkipValueValidation,
	}); err != nil {
		return operationFailureFromSchema(err)
	}
	return nil
}

func validateOfflineAttributeValueSyntax(
	registry *schema.Registry,
	attribute directory.Attribute,
) error {
	if registry == nil || !registry.HasAttributeType(attribute.Description) {
		return nil
	}
	for _, value := range attribute.Values {
		if err := registry.ValidateAttributeValue(attribute.Description, value); err != nil {
			return operationFailed(ldapwire.ResultInvalidAttributeSyntax, err.Error())
		}
	}
	return nil
}

// ReindexOffline rebuilds configured indexes for one database and its glued
// subordinates. Attribute-selective rebuild is intentionally left to the CLI
// rejection path because storage publishes each partition index atomically.
func ReindexOffline(
	ctx context.Context,
	store storage.Store,
	databaseSelector string,
	includeSubordinates bool,
) (int, error) {
	reindexed := 0
	err := storage.UpdateBulk(ctx, store, func(writer storage.Writer) error {
		_, runtime, err := buildOfflineRuntime(writer, store)
		if err != nil {
			return err
		}
		indexes, err := selectOfflineDatabases(runtime, databaseSelector, includeSubordinates)
		if err != nil {
			return err
		}
		for _, index := range indexes {
			database := runtime.databases[index]
			normalizer, ok := database.dnNormalizer.(storage.EqualityIndexSchema)
			if !ok || !databaseUsesLocalContentStorage(database) {
				return fmt.Errorf("database %q does not support local index rebuild", database.name)
			}
			if err := storage.RebuildEqualityIndexes(writer, database.partition, normalizer); err != nil {
				return fmt.Errorf("reindex database %q: %w", database.name, err)
			}
			if err := markOfflineDNIdentitySchemaCurrent(writer, runtime, database); err != nil {
				return err
			}
			reindexed++
		}
		return nil
	})
	return reindexed, err
}

type OfflineReindexOptions struct {
	Database            string
	IncludeSubordinates bool
	Attributes          []string
	Quick               bool
}

// ReindexOfflineSelected rebuilds all configured indexes or only the requested
// AttributeDescriptions. Quick mode commits each selected database separately,
// matching slapindex's partial-progress behavior while retaining atomic index
// publication within each database partition.
func ReindexOfflineSelected(
	ctx context.Context,
	store storage.Store,
	options OfflineReindexOptions,
) (int, error) {
	if !options.Quick {
		reindexed := 0
		err := storage.UpdateBulk(ctx, store, func(writer storage.Writer) error {
			_, runtime, err := buildOfflineRuntime(writer, store)
			if err != nil {
				return err
			}
			indexes, err := selectOfflineDatabases(
				runtime, options.Database, options.IncludeSubordinates,
			)
			if err != nil {
				return err
			}
			reindexed, err = reindexOfflineDatabases(
				writer, runtime, indexes, options.Attributes,
			)
			return err
		})
		return reindexed, err
	}

	var databaseNames []string
	err := store.View(ctx, func(reader storage.Reader) error {
		_, runtime, err := buildOfflineRuntime(reader, store)
		if err != nil {
			return err
		}
		indexes, err := selectOfflineDatabases(
			runtime, options.Database, options.IncludeSubordinates,
		)
		if err != nil {
			return err
		}
		for _, index := range indexes {
			databaseNames = append(databaseNames, runtime.databases[index].name)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	reindexed := 0
	for _, databaseName := range databaseNames {
		err := storage.UpdateBulk(ctx, store, func(writer storage.Writer) error {
			_, runtime, err := buildOfflineRuntime(writer, store)
			if err != nil {
				return err
			}
			indexes, err := selectOfflineDatabases(runtime, databaseName, false)
			if err != nil {
				return err
			}
			count, err := reindexOfflineDatabases(
				writer, runtime, indexes, options.Attributes,
			)
			reindexed += count
			return err
		})
		if err != nil {
			return reindexed, err
		}
	}
	return reindexed, nil
}

func reindexOfflineDatabases(
	writer storage.Writer,
	runtime *runtimeState,
	indexes []int,
	attributes []string,
) (int, error) {
	reindexed := 0
	for _, index := range indexes {
		database := runtime.databases[index]
		normalizer, ok := database.dnNormalizer.(*databaseEqualityIndexNormalizer)
		if !ok || !databaseUsesLocalContentStorage(database) {
			return reindexed, fmt.Errorf(
				"database %q does not support local index rebuild",
				database.name,
			)
		}
		selected, err := offlineIndexAttributes(normalizer, attributes)
		if err != nil {
			return reindexed, fmt.Errorf("database %q: %w", database.name, err)
		}
		if err := storage.RebuildSelectedEqualityIndexes(
			writer, database.partition, normalizer, selected,
		); err != nil {
			return reindexed, fmt.Errorf("reindex database %q: %w", database.name, err)
		}
		if err := markOfflineDNIdentitySchemaCurrent(writer, runtime, database); err != nil {
			return reindexed, err
		}
		reindexed++
	}
	return reindexed, nil
}

func markOfflineDNIdentitySchemaCurrent(
	writer storage.Writer,
	runtime *runtimeState,
	database runtimeDatabase,
) error {
	if runtime == nil || runtime.schema == nil ||
		!databaseUsesLocalContentStorage(database) ||
		database.partition == configurationStoragePartition {
		return nil
	}
	if err := storage.ValidateSchemaAwareDNIdentities(
		writer,
		database.partition,
		database.dnNormalizer,
	); err != nil {
		if !errors.Is(err, storage.ErrDNIdentityMigrationRequired) {
			return fmt.Errorf("validate database %q DN identities: %w", database.name, err)
		}
		if _, migrateErr := storage.MigrateSchemaAwareDNIdentities(
			writer,
			database.partition,
			database.dnNormalizer,
		); migrateErr != nil {
			return fmt.Errorf("migrate database %q DN identities: %w", database.name, migrateErr)
		}
		if validateErr := storage.ValidateSchemaAwareDNIdentities(
			writer,
			database.partition,
			database.dnNormalizer,
		); validateErr != nil {
			return fmt.Errorf("validate migrated database %q DN identities: %w", database.name, validateErr)
		}
	}
	fingerprint := runtime.schema.DNIdentityFingerprint()
	if err := writer.SetMetadata(
		runtimeDNIdentityFingerprintMetadataKey(database.partition),
		fingerprint[:],
	); err != nil {
		return fmt.Errorf("store database %q DN identity fingerprint: %w", database.name, err)
	}
	return nil
}

func offlineIndexAttributes(
	normalizer *databaseEqualityIndexNormalizer,
	attributes []string,
) ([]string, error) {
	if len(attributes) == 0 {
		return nil, nil
	}
	selected := make([]string, 0, len(attributes))
	seen := make(map[string]struct{}, len(attributes))
	for _, description := range attributes {
		canonical, _, _, err := canonicalDatabaseIndexAttributeDescription(
			normalizer.registry, description,
		)
		if err != nil {
			return nil, fmt.Errorf("attribute %q: %w", description, err)
		}
		if _, configured := normalizer.indexAttributeDefinition(canonical); !configured {
			return nil, fmt.Errorf("no index configured for attribute %q", description)
		}
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		selected = append(selected, canonical)
	}
	sort.Strings(selected)
	return selected, nil
}

func buildOfflineRuntime(
	reader storage.Reader,
	store storage.Store,
) (*Server, *runtimeState, error) {
	instance, err := newOfflineServer(store)
	if err != nil {
		return nil, nil, err
	}
	runtime, err := buildOfflineRuntimeWithServer(instance, reader)
	return instance, runtime, err
}

func newOfflineServer(store storage.Store) (*Server, error) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		return nil, err
	}
	instance := &Server{
		config: Config{
			Store:  store,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Clock:  time.Now,
		},
		baseSchema: registry,
		clock:      time.Now,
	}
	return instance, nil
}

func buildOfflineRuntimeWithServer(
	instance *Server,
	reader storage.Reader,
) (*runtimeState, error) {
	runtime, err := instance.buildRuntimeState(reader)
	if err != nil {
		return nil, err
	}
	for index := range runtime.databases {
		database := &runtime.databases[index]
		if !databaseUsesLocalContentStorage(*database) {
			continue
		}
		database.dnNormalizer = &databaseEqualityIndexNormalizer{
			registry: runtime.schema,
			config:   database.equalityIndexes,
		}
	}
	return runtime, nil
}

func PrepareOfflineDNIdentities(
	ctx context.Context,
	store storage.Store,
) error {
	if ctx == nil {
		return errors.New("offline preparation context is required")
	}
	instance, err := newOfflineServer(store)
	if err != nil {
		return err
	}
	var runtime *runtimeState
	if err := store.View(ctx, func(reader storage.Reader) error {
		var buildErr error
		runtime, buildErr = buildOfflineRuntimeWithServer(instance, reader)
		return buildErr
	}); err != nil {
		return err
	}
	if err := instance.partitionDefaultEntries(ctx, runtime); err != nil {
		return err
	}
	return instance.migrateRuntimeDNIdentities(ctx, runtime)
}

func selectOfflineDatabases(
	runtime *runtimeState,
	selector string,
	includeSubordinates bool,
) ([]int, error) {
	primary := -1
	selector = strings.TrimSpace(selector)
	for index := range runtime.databases {
		database := runtime.databases[index]
		if selector == "" {
			if primary < 0 && !database.hidden && !database.disabled &&
				!database.subordinate && databaseUsesLocalContentStorage(database) {
				primary = index
			}
			continue
		}
		if offlineDatabaseSelectorMatches(database, selector) {
			if primary >= 0 {
				return nil, fmt.Errorf("database selector %q is ambiguous", selector)
			}
			primary = index
		}
	}
	if primary < 0 {
		return nil, fmt.Errorf("OpenLDAP database %q is not present in cn=config", selector)
	}
	result := []int{primary}
	if !includeSubordinates || runtime.databases[primary].subordinate {
		return result, nil
	}
	for index := range runtime.databases {
		if index != primary && runtime.databases[index].subordinate &&
			glueSuperiorDatabaseIndex(runtime.databases, index) == primary {
			result = append(result, index)
		}
	}
	return result, nil
}

func offlineDatabaseSelectorMatches(database runtimeDatabase, selector string) bool {
	if strings.EqualFold(database.name, selector) {
		return true
	}
	if isConfigDatabase(database) && (selector == "0" || strings.EqualFold(selector, "config") || strings.EqualFold(selector, "cn=config")) {
		return true
	}
	requested, err := strconv.Atoi(selector)
	if err != nil || requested < 0 || !strings.HasPrefix(database.name, "{") {
		return false
	}
	end := strings.IndexByte(database.name, '}')
	if end < 2 {
		return false
	}
	actual, err := strconv.Atoi(database.name[1:end])
	return err == nil && actual == requested
}

func offlineDatabaseReadable(database runtimeDatabase) bool {
	return isConfigDatabase(database) || databaseUsesLocalContentStorage(database)
}

func offlineDatabaseWritable(database runtimeDatabase) bool {
	return isConfigDatabase(database) || databaseUsesLocalContentStorage(database)
}

type offlineRawRecord struct {
	line int
	raw  []byte
}

func parseOfflineChanges(
	reader io.Reader,
	continueOnError bool,
	resumeLine int,
) ([]offlineChange, []OfflineModifyFailure, error) {
	if reader == nil {
		return nil, nil, errors.New("LDIF reader is required")
	}
	input, err := io.ReadAll(io.LimitReader(reader, maxOfflineLDIFSize+1))
	if err != nil {
		return nil, nil, err
	}
	if len(input) > maxOfflineLDIFSize {
		return nil, nil, fmt.Errorf("LDIF input exceeds %d bytes", maxOfflineLDIFSize)
	}
	records, err := splitOfflineLDIFRecords(input)
	if err != nil {
		return nil, nil, err
	}
	changes := make([]offlineChange, 0, len(records))
	var failures []OfflineModifyFailure
	sawVersion := false
	for _, record := range records {
		if record.line < resumeLine {
			continue
		}
		change, skip, parseErr := parseOfflineChangeRecord(record, &sawVersion)
		if parseErr != nil {
			failure := OfflineModifyFailure{Line: record.line, Err: parseErr}
			failures = append(failures, failure)
			if continueOnError {
				continue
			}
			return nil, failures, fmt.Errorf("line %d: %w", record.line, parseErr)
		}
		if !skip {
			changes = append(changes, change)
		}
	}
	return changes, failures, nil
}

func splitOfflineLDIFRecords(input []byte) ([]offlineRawRecord, error) {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64<<10), maxOfflineLDIFLine)
	line := 0
	start := 1
	var buffer bytes.Buffer
	var records []offlineRawRecord
	flush := func() error {
		if buffer.Len() == 0 {
			return nil
		}
		if buffer.Len() > maxOfflineLDIFRecord {
			return fmt.Errorf("LDIF record at line %d exceeds %d bytes", start, maxOfflineLDIFRecord)
		}
		records = append(records, offlineRawRecord{line: start, raw: bytes.Clone(buffer.Bytes())})
		buffer.Reset()
		return nil
	}
	for scanner.Scan() {
		line++
		text := strings.TrimSuffix(scanner.Text(), "\r")
		if text == "" {
			if err := flush(); err != nil {
				return nil, err
			}
			start = line + 1
			continue
		}
		if buffer.Len() == 0 {
			start = line
		}
		buffer.WriteString(text)
		buffer.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return records, nil
}

func parseOfflineChangeRecord(
	record offlineRawRecord,
	sawVersion *bool,
) (offlineChange, bool, error) {
	lines, err := unfoldOfflineLDIF(record.raw)
	if err != nil {
		return offlineChange{}, false, err
	}
	if len(lines) == 0 {
		return offlineChange{}, true, nil
	}
	name, value, err := parseOfflineLDIFLine(lines[0])
	if err != nil {
		return offlineChange{}, false, err
	}
	if strings.EqualFold(name, "version") {
		if *sawVersion || string(value) != "1" {
			return offlineChange{}, false, errors.New("invalid or duplicate LDIF version")
		}
		*sawVersion = true
		lines = lines[1:]
		if len(lines) == 0 {
			return offlineChange{}, true, nil
		}
		name, value, err = parseOfflineLDIFLine(lines[0])
		if err != nil {
			return offlineChange{}, false, err
		}
	}
	if !strings.EqualFold(name, "dn") {
		return offlineChange{}, false, errors.New("change record must begin with dn")
	}
	change := offlineChange{line: record.line, dn: string(value)}
	index := 1
	changeType := "add"
	if index < len(lines) {
		lineName, lineValue, lineErr := parseOfflineLDIFLine(lines[index])
		if lineErr != nil {
			return offlineChange{}, false, lineErr
		}
		if strings.EqualFold(lineName, "control") {
			return offlineChange{}, false, errors.New("LDIF controls are not supported by offline slapmodify")
		}
		if strings.EqualFold(lineName, "changetype") {
			changeType = strings.ToLower(strings.TrimSpace(string(lineValue)))
			index++
		}
	}
	switch changeType {
	case "add":
		change.kind = offlineChangeAdd
		change.entry = directory.Entry{DN: change.dn}
		for ; index < len(lines); index++ {
			attribute, raw, parseErr := parseOfflineLDIFLine(lines[index])
			if parseErr != nil {
				return offlineChange{}, false, parseErr
			}
			appendOfflineAttribute(&change.entry, attribute, raw)
		}
		if len(change.entry.Attributes) == 0 {
			return offlineChange{}, false, errors.New("add record requires attributes")
		}
	case "delete":
		if index != len(lines) {
			return offlineChange{}, false, errors.New("delete record must not contain attributes")
		}
		change.kind = offlineChangeDelete
	case "modify":
		change.kind = offlineChangeModify
		for index < len(lines) {
			if lines[index] == "-" {
				index++
				continue
			}
			opName, attributeValue, parseErr := parseOfflineLDIFLine(lines[index])
			if parseErr != nil {
				return offlineChange{}, false, parseErr
			}
			operation, ok := offlineModificationOperation(strings.ToLower(opName))
			if !ok {
				return offlineChange{}, false, fmt.Errorf("unsupported modify operation %q", opName)
			}
			attribute := string(attributeValue)
			index++
			var values [][]byte
			for index < len(lines) && lines[index] != "-" {
				valueName, raw, valueErr := parseOfflineLDIFLine(lines[index])
				if valueErr != nil || !strings.EqualFold(valueName, attribute) {
					return offlineChange{}, false, fmt.Errorf("invalid value for modify attribute %q", attribute)
				}
				values = append(values, raw)
				index++
			}
			if operation == ldapwire.ModificationIncrement && len(values) != 1 {
				return offlineChange{}, false, fmt.Errorf("increment %q requires exactly one value", attribute)
			}
			change.modifications = append(change.modifications, ldapwire.Modification{
				Operation: operation,
				Attribute: directory.Attribute{Description: attribute, Values: values},
			})
		}
	case "moddn", "modrdn":
		change.kind = offlineChangeModifyDN
		if index >= len(lines) {
			return offlineChange{}, false, errors.New("moddn record requires newrdn")
		}
		field, raw, parseErr := parseOfflineLDIFLine(lines[index])
		if parseErr != nil || !strings.EqualFold(field, "newrdn") || len(raw) == 0 {
			return offlineChange{}, false, errors.New("moddn record requires a non-empty newrdn")
		}
		change.newRDN = string(raw)
		index++
		if index >= len(lines) {
			return offlineChange{}, false, errors.New("moddn record requires deleteoldrdn")
		}
		field, raw, parseErr = parseOfflineLDIFLine(lines[index])
		if parseErr != nil || !strings.EqualFold(field, "deleteoldrdn") {
			return offlineChange{}, false, errors.New("moddn record requires deleteoldrdn after newrdn")
		}
		switch strings.TrimSpace(string(raw)) {
		case "0":
			change.deleteOldRDN = false
		case "1":
			change.deleteOldRDN = true
		default:
			return offlineChange{}, false, errors.New("moddn deleteoldrdn must be 0 or 1")
		}
		index++
		if index < len(lines) {
			field, raw, parseErr = parseOfflineLDIFLine(lines[index])
			if parseErr != nil || !strings.EqualFold(field, "newsuperior") {
				return offlineChange{}, false, errors.New("moddn newsuperior must follow deleteoldrdn")
			}
			change.newSuperior = string(raw)
			change.hasSuperior = true
			index++
		}
		if index != len(lines) {
			return offlineChange{}, false, errors.New("moddn record has extra fields")
		}
	default:
		return offlineChange{}, false, fmt.Errorf("unsupported changetype %q", changeType)
	}
	return change, false, nil
}

func unfoldOfflineLDIF(raw []byte) ([]string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64<<10), maxOfflineLDIFLine)
	var lines []string
	comment := false
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		switch line[0] {
		case '#':
			comment = true
		case ' ':
			if comment {
				continue
			}
			if len(lines) == 0 {
				return nil, errors.New("orphan LDIF continuation line")
			}
			lines[len(lines)-1] += line[1:]
		default:
			comment = false
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func parseOfflineLDIFLine(line string) (string, []byte, error) {
	colon := strings.IndexByte(line, ':')
	if colon <= 0 {
		return "", nil, errors.New("invalid LDIF value line")
	}
	name := line[:colon]
	remainder := line[colon+1:]
	if remainder == "" {
		return name, nil, nil
	}
	switch remainder[0] {
	case ':':
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimLeft(remainder[1:], " "))
		if err != nil {
			return "", nil, errors.New("invalid base64 LDIF value")
		}
		return name, decoded, nil
	case '<':
		external, err := readOfflineFileURL(strings.TrimSpace(remainder[1:]))
		if err != nil {
			return "", nil, err
		}
		return name, external, nil
	default:
		return name, []byte(strings.TrimLeft(remainder, " ")), nil
	}
}

func readOfflineFileURL(rawURL string) ([]byte, error) {
	if rawURL == "" {
		return nil, errors.New("external LDIF value requires a file:// URL")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid external LDIF value URL: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "file") || parsed.Opaque != "" ||
		parsed.Host != "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return nil, errors.New("external LDIF value must use a local file:// absolute path")
	}
	path := parsed.Path
	if path == "" || strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) {
		return nil, errors.New("external LDIF file path must be absolute")
	}
	path = filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("open external LDIF value directory: %w", err)
	}
	defer root.Close()
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, fmt.Errorf("open external LDIF value: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat external LDIF value: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("external LDIF value must be a regular file")
	}
	if info.Size() < 0 || info.Size() > maxOfflineURLValue {
		return nil, fmt.Errorf("external LDIF value exceeds %d bytes", maxOfflineURLValue)
	}
	value, err := io.ReadAll(io.LimitReader(file, maxOfflineURLValue+1))
	if err != nil {
		return nil, fmt.Errorf("read external LDIF value: %w", err)
	}
	if len(value) > maxOfflineURLValue {
		return nil, fmt.Errorf("external LDIF value exceeds %d bytes", maxOfflineURLValue)
	}
	return value, nil
}

func appendOfflineAttribute(entry *directory.Entry, description string, value []byte) {
	for index := range entry.Attributes {
		if strings.EqualFold(entry.Attributes[index].Description, description) {
			entry.Attributes[index].Values = append(entry.Attributes[index].Values, bytes.Clone(value))
			return
		}
	}
	entry.Attributes = append(entry.Attributes, directory.Attribute{
		Description: description, Values: [][]byte{bytes.Clone(value)},
	})
}

func offlineModificationOperation(value string) (ldapwire.ModificationOperation, bool) {
	switch value {
	case "add":
		return ldapwire.ModificationAdd, true
	case "delete":
		return ldapwire.ModificationDelete, true
	case "replace":
		return ldapwire.ModificationReplace, true
	case "increment":
		return ldapwire.ModificationIncrement, true
	default:
		return 0, false
	}
}
