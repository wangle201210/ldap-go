package migration

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

// ContinueImportFailure describes one LDIF record rejected by slapadd -c.
// Line is the one-based first line of the record, or the parser's more precise
// line when available.
type ContinueImportFailure struct {
	Line int
	DN   string
	Err  error
}

// ContinueImportResult reports committed entries and recoverable record
// failures from a slapadd -c import.
type ContinueImportResult struct {
	ImportResult
	Failures []ContinueImportFailure
}

type continueImportRecord struct {
	line  int
	dn    directory.DN
	entry *ldap.Entry
}

// ImportLDIFContinue implements the non-atomic, content-database subset used
// by slapadd -c. The regular ImportLDIF API remains atomic. Records are ordered
// by DN depth so children that precede their parents in the input can still be
// imported. A failed depth batch is retried one record at a time to retain
// independent successes and produce precise diagnostics.
//
// Configuration database imports are deliberately rejected. Their schema and
// database definitions have cross-record ordering requirements that cannot be
// made partially visible safely.
func ImportLDIFContinue(
	ctx context.Context,
	store storage.Store,
	reader io.Reader,
	options ImportOptions,
) (ContinueImportResult, error) {
	return importLDIFContinue(
		ctx,
		store,
		reader,
		options,
		&importCSNGenerator{},
	)
}

func importLDIFContinue(
	ctx context.Context,
	store storage.Store,
	reader io.Reader,
	options ImportOptions,
	csns *importCSNGenerator,
) (ContinueImportResult, error) {
	if reader == nil {
		return ContinueImportResult{}, errors.New("LDIF reader is required")
	}
	if options.DryRun {
		return ContinueImportResult{}, errors.New(
			"continued dry-run import requires a disposable destination store",
		)
	}

	if options.ResumeLine < 0 {
		return ContinueImportResult{}, errors.New("LDIF resume line must be non-negative")
	}
	records, failures, containsConfiguration, err := parseContinueImportRecords(
		reader,
		options.ResumeLine,
	)
	if err != nil {
		return ContinueImportResult{}, err
	}
	if err := rejectContinuedConfigurationImport(
		ctx,
		store,
		options,
		containsConfiguration,
	); err != nil {
		return ContinueImportResult{}, err
	}

	result := ContinueImportResult{Failures: failures}
	baseOptions := options
	baseOptions.DryRun = false
	baseOptions.Replace = false
	baseOptions.ResumeLine = 0
	if options.Replace {
		clearOptions := baseOptions
		clearOptions.Replace = true
		cleared, err := importLDIF(
			ctx,
			store,
			strings.NewReader(""),
			clearOptions,
			csns,
		)
		if err != nil {
			return ContinueImportResult{}, fmt.Errorf(
				"prepare continued import replacement: %w",
				err,
			)
		}
		result.ImportResult = cleared
	}

	sort.SliceStable(records, func(left, right int) bool {
		return records[left].dn.Depth() < records[right].dn.Depth()
	})
	for first := 0; first < len(records); {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		last := first + 1
		depth := records[first].dn.Depth()
		for last < len(records) && records[last].dn.Depth() == depth {
			last++
		}
		batch := records[first:last]
		imported, batchErr := importContinueRecordBatch(
			ctx,
			store,
			batch,
			baseOptions,
			csns,
		)
		if batchErr == nil {
			result.Entries += imported.Entries
			result.NamingContexts = imported.NamingContexts
			first = last
			continue
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}

		for _, record := range batch {
			imported, recordErr := importContinueRecordBatch(
				ctx,
				store,
				[]continueImportRecord{record},
				baseOptions,
				csns,
			)
			if recordErr != nil {
				if err := ctx.Err(); err != nil {
					return result, err
				}
				result.Failures = append(result.Failures, ContinueImportFailure{
					Line: record.line,
					DN:   record.entry.DN,
					Err:  recordErr,
				})
				continue
			}
			result.Entries += imported.Entries
			result.NamingContexts = imported.NamingContexts
		}
		first = last
	}

	if len(result.NamingContexts) == 0 {
		if err := store.View(ctx, func(reader storage.Reader) error {
			contexts, err := reader.NamingContexts()
			if err != nil {
				return err
			}
			result.NamingContexts = contexts
			return nil
		}); err != nil {
			return result, fmt.Errorf("read continued import naming contexts: %w", err)
		}
	}
	sort.SliceStable(result.Failures, func(left, right int) bool {
		return result.Failures[left].Line < result.Failures[right].Line
	})
	return result, nil
}

func parseContinueImportRecords(
	reader io.Reader,
	resumeLine int,
) ([]continueImportRecord, []ContinueImportFailure, bool, error) {
	buffered := bufio.NewReader(reader)
	var records []continueImportRecord
	var failures []ContinueImportFailure
	containsConfiguration := false
	line := 0
	recordLine := 1
	var raw bytes.Buffer

	flush := func() {
		if raw.Len() == 0 {
			return
		}
		if recordLine < resumeLine {
			raw.Reset()
			return
		}
		parsed, parseFailures, configuration := parseContinueImportRecord(
			raw.Bytes(),
			recordLine,
		)
		records = append(records, parsed...)
		failures = append(failures, parseFailures...)
		containsConfiguration = containsConfiguration || configuration
		raw.Reset()
	}

	for {
		value, readErr := buffered.ReadString('\n')
		if len(value) > 0 {
			line++
			if raw.Len() == 0 {
				recordLine = line
			}
			raw.WriteString(value)
			if strings.TrimRight(value, "\r\n") == "" {
				flush()
			}
		}
		if readErr == nil {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			flush()
			break
		}
		return nil, nil, false, fmt.Errorf("read LDIF at line %d: %w", line+1, readErr)
	}
	return records, failures, containsConfiguration, nil
}

func parseContinueImportRecord(
	raw []byte,
	startLine int,
) ([]continueImportRecord, []ContinueImportFailure, bool) {
	var records []continueImportRecord
	var failures []ContinueImportFailure
	containsConfiguration := false
	document := &ldif.LDIF{}
	for record, parseErr := range ldif.UnmarshalEntries(bytes.NewReader(raw), document) {
		if parseErr != nil {
			line := startLine
			var detailed *ldif.ParseError
			if errors.As(parseErr, &detailed) && detailed.Line > 0 {
				line += detailed.Line - 1
			}
			failures = append(failures, ContinueImportFailure{
				Line: line,
				Err:  fmt.Errorf("parse LDIF: %w", parseErr),
			})
			continue
		}
		if record == nil {
			continue
		}
		if record.Entry == nil {
			failures = append(failures, ContinueImportFailure{
				Line: startLine,
				Err: errors.New(
					"LDIF change records are not accepted by content import",
				),
			})
			continue
		}
		configuration, err := isConfigurationDN(record.Entry.DN)
		if err != nil {
			failures = append(failures, ContinueImportFailure{
				Line: startLine,
				DN:   record.Entry.DN,
				Err:  err,
			})
			continue
		}
		if configuration {
			containsConfiguration = true
		}
		dn, err := directory.ParseDN(record.Entry.DN)
		if err != nil {
			failures = append(failures, ContinueImportFailure{
				Line: startLine,
				DN:   record.Entry.DN,
				Err:  err,
			})
			continue
		}
		records = append(records, continueImportRecord{
			line:  startLine,
			dn:    dn,
			entry: record.Entry,
		})
	}
	return records, failures, containsConfiguration
}

func rejectContinuedConfigurationImport(
	ctx context.Context,
	store storage.Store,
	options ImportOptions,
	containsConfiguration bool,
) error {
	selectedConfiguration := false
	if strings.TrimSpace(options.Database) != "" {
		if err := store.View(ctx, func(reader storage.Reader) error {
			target, err := resolveDatabaseTarget(reader, options.Database)
			if err != nil {
				return err
			}
			selectedConfiguration = target.config
			return nil
		}); err != nil {
			return err
		}
	}
	if !selectedConfiguration && !containsConfiguration {
		return nil
	}
	return errors.New(
		"slapadd -c does not support cn=config imports because partial schema and database definitions cannot be published safely",
	)
}

func importContinueRecordBatch(
	ctx context.Context,
	store storage.Store,
	records []continueImportRecord,
	options ImportOptions,
	csns *importCSNGenerator,
) (ImportResult, error) {
	var input bytes.Buffer
	for _, record := range records {
		if err := ldif.Dump(&input, 76, record.entry); err != nil {
			return ImportResult{}, fmt.Errorf(
				"encode LDIF record at line %d: %w",
				record.line,
				err,
			)
		}
	}
	return importLDIF(ctx, store, &input, options, csns)
}
