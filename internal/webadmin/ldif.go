package webadmin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
)

var errExportTooLarge = errors.New("LDIF export exceeds the configured byte limit")

const maximumLDIFDocumentLogicalLines = 1 << 19

type ldifImportRecord struct {
	entry     *ldif.Entry
	modifyDN  *ldap.ModifyDNRequest
	dn        string
	operation string
}

type ldifImportResponse struct {
	Results     []ldifImportResult `json:"results"`
	Applied     int                `json:"applied"`
	Failed      int                `json:"failed"`
	Unknown     int                `json:"unknown"`
	Aborted     bool               `json:"aborted"`
	AbortReason string             `json:"abort_reason"`
	Error       *apiError          `json:"error,omitempty"`
}

type ldifImportResult struct {
	Record    int       `json:"record"`
	DN        string    `json:"dn"`
	Operation string    `json:"operation"`
	Success   bool      `json:"success"`
	Status    string    `json:"status"`
	Error     *apiError `json:"error,omitempty"`
}

type ldifValueEncoding uint8

const (
	ldifValuePlain ldifValueEncoding = iota
	ldifValueBase64
	ldifValueURL
)

type contextCheckingReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextCheckingReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	count, err := reader.reader.Read(buffer)
	if contextErr := reader.ctx.Err(); contextErr != nil {
		return count, contextErr
	}
	return count, err
}

type boundedBuffer struct {
	bytes.Buffer
	maximum int64
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	if int64(buffer.Len())+int64(len(value)) > buffer.maximum {
		return 0, errExportTooLarge
	}
	return buffer.Buffer.Write(value)
}

func (application *Application) handleExport(response http.ResponseWriter, request *http.Request) {
	if !methodAllowed(response, request, http.MethodGet) {
		return
	}
	current, ok := application.acquireSession(response, request)
	if !ok {
		return
	}
	defer application.releaseSession(current)
	base := request.URL.Query().Get("base_dn")
	if err := validateDN(base, true); err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_dn", Message: err.Error()})
		return
	}
	filter := request.URL.Query().Get("filter")
	if filter == "" {
		filter = "(objectClass=*)"
	}
	if err := validateFilter(filter, application.config); err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_filter", Message: err.Error()})
		return
	}
	scope, err := parseScope(request.URL.Query().Get("scope"))
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_scope", Message: err.Error()})
		return
	}
	limit := application.config.MaxExportEntries
	if raw := request.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > application.config.MaxExportEntries {
			writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_limit", Message: "limit is outside the configured bounds"})
			return
		}
		limit = parsed
	}
	ldapRequest := ldap.NewSearchRequest(
		base, scope, ldap.NeverDerefAliases, limit+1,
		application.config.MaxSearchSeconds, false, filter, []string{"*", "+"}, nil,
	)
	ldapRequest.EnforceSizeLimit = true
	result, release, err := application.search(current.client, ldapRequest)
	if err != nil {
		writeLDAPError(response, err)
		return
	}
	defer release()
	if rejectIncompleteReferrals(response, result) {
		return
	}
	if len(result.Entries) > limit {
		writeAPIError(response, http.StatusRequestEntityTooLarge, apiError{
			Code: "export_entry_limit", Message: "LDIF export exceeds the configured entry limit",
		})
		return
	}
	output := &boundedBuffer{maximum: application.config.MaxExportBytes}
	for _, entry := range result.Entries {
		if entry == nil {
			continue
		}
		if err := ldif.Dump(output, 76, entry); err != nil {
			if errors.Is(err, errExportTooLarge) {
				writeAPIError(response, http.StatusRequestEntityTooLarge, apiError{
					Code: "export_byte_limit", Message: errExportTooLarge.Error(),
				})
				return
			}
			writeAPIError(response, http.StatusInternalServerError, apiError{
				Code: "ldif_encoding_failed", Message: "unable to encode LDAP entries as LDIF",
			})
			return
		}
	}
	response.Header().Set("Content-Type", "application/ldif; charset=utf-8")
	response.Header().Set("Content-Disposition", `attachment; filename="directory-export.ldif"`)
	response.Header().Set("X-LDIF-Entry-Count", strconv.Itoa(len(result.Entries)))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(output.Bytes())
}

func (application *Application) handleImport(response http.ResponseWriter, request *http.Request) {
	if !methodAllowed(response, request, http.MethodPost) {
		return
	}
	current, ok := application.acquireSession(response, request)
	if !ok {
		return
	}
	defer application.releaseSession(current)
	if !application.requireMutationSecurity(response, request, current) {
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/ldif" && mediaType != "text/plain") {
		writeAPIError(response, http.StatusUnsupportedMediaType, apiError{
			Code: "invalid_content_type", Message: "Content-Type must be application/ldif or text/plain",
		})
		return
	}
	if writeLDIFRequestContextError(response, request.Context()) {
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, application.config.RequestBodyLimit)
	data, err := io.ReadAll(contextCheckingReader{ctx: request.Context(), reader: request.Body})
	if err != nil {
		if writeLDIFRequestContextError(response, request.Context()) {
			return
		}
		var maximumError *http.MaxBytesError
		if errors.As(err, &maximumError) {
			writeAPIError(response, http.StatusRequestEntityTooLarge, apiError{
				Code: "request_body_too_large", Message: "request body exceeds the configured limit",
			})
			return
		}
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_ldif", Message: "unable to read LDIF request"})
		return
	}
	if writeLDIFRequestContextError(response, request.Context()) {
		return
	}

	records, err := application.parseLDIFChangesContext(request.Context(), data)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			writeLDIFRequestContextError(response, request.Context())
			return
		}
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_ldif", Message: err.Error()})
		return
	}
	result := ldifImportResponse{Results: make([]ldifImportResult, 0, len(records))}
	status := http.StatusOK
	batchContext, cancel := context.WithTimeout(request.Context(), application.config.OperationTimeout)
	defer cancel()
	for index, record := range records {
		if reason := batchAbortReason(batchContext); reason != "" {
			result.Aborted = true
			result.AbortReason = reason
			appendLDIFNotAttempted(&result, records[index:], index+1)
			failure := ldifImportAbortFailure(batchContext, result.Applied)
			result.Error = &failure
			status = ldifImportAbortHTTPStatus(batchContext)
			break
		}

		// Client writes do not accept context. Cancellation stops waiting and
		// reports an unknown result, but cleanup must wait for the write to return.
		err, interrupted := executeBatchWrite(batchContext, application, current, func(client Client) error {
			return applyLDIFRecord(client, record)
		})
		if errors.Is(err, errBatchApplicationClosed) {
			result.Aborted = true
			result.AbortReason = "administration service is closing"
			appendLDIFNotAttempted(&result, records[index:], index+1)
			failure := apiError{Code: "administration_closing", Message: result.AbortReason}
			failure.Applied = intPointer(result.Applied)
			result.Error = &failure
			status = http.StatusServiceUnavailable
			break
		}
		if interrupted {
			failure := apiError{
				Code:    "ldap_result_unknown",
				Message: "LDAP write result is unknown because the LDIF import was canceled during the operation",
			}
			result.Unknown++
			result.Aborted = true
			result.AbortReason = batchAbortReason(batchContext)
			result.Results = append(result.Results, newLDIFImportResult(index+1, record, "unknown", &failure))
			appendLDIFNotAttempted(&result, records[index+1:], index+2)
			failure.Applied = intPointer(result.Applied)
			result.Error = &failure
			status = ldifImportAbortHTTPStatus(batchContext)
			break
		}
		if err == nil {
			result.Applied++
			result.Results = append(result.Results, newLDIFImportResult(index+1, record, "applied", nil))
			continue
		}

		failure, unknown := ldapWriteFailure(err)
		if unknown {
			application.scheduleSessionClose(current, nil)
			result.Unknown++
			result.Aborted = true
			result.AbortReason = "LDAP write result is unknown; remaining LDIF records were not attempted"
			result.Results = append(result.Results, newLDIFImportResult(index+1, record, "unknown", &failure))
			appendLDIFNotAttempted(&result, records[index+1:], index+2)
			failure.Applied = intPointer(result.Applied)
			result.Error = &failure
			status = http.StatusBadGateway
			break
		}

		result.Failed++
		result.Results = append(result.Results, newLDIFImportResult(index+1, record, "failed", &failure))
		remaining := records[index+1:]
		if len(remaining) != 0 {
			result.Aborted = true
			result.AbortReason = fmt.Sprintf(
				"LDAP operation failed at record %d; remaining LDIF records were not attempted",
				index+1,
			)
			appendLDIFNotAttempted(&result, remaining, index+2)
		}
		status = ldapHTTPStatus(*failure.LDAPResultCode)
		failure.Applied = intPointer(result.Applied)
		result.Error = &failure
		break
	}
	writeJSON(response, status, result)
}

func (application *Application) parseLDIFChanges(data []byte) ([]ldifImportRecord, error) {
	return application.parseLDIFChangesContext(context.Background(), data)
}

func (application *Application) parseLDIFChangesContext(ctx context.Context, data []byte) ([]ldifImportRecord, error) {
	if err := checkLDIFContext(ctx); err != nil {
		return nil, err
	}
	if int64(len(data)) > application.config.RequestBodyLimit {
		return nil, errors.New("LDIF exceeds the configured request body limit")
	}
	records := make([]ldifImportRecord, 0)
	sawVersion := false
	rawRecords, err := splitLDIFRecords(ctx, data, application.config.MaxImportChanges)
	if err != nil {
		return nil, err
	}
	remainingLines := maximumLDIFLogicalLines(application.config.RequestBodyLimit)
	perRecordLines := maximumLDIFRecordLogicalLines(application.config.MaxAttributes, remainingLines)
	for _, rawRecord := range rawRecords {
		if err := checkLDIFContext(ctx); err != nil {
			return nil, err
		}
		lineLimit := perRecordLines
		if remainingLines < lineLimit {
			lineLimit = remainingLines
		}
		lines, err := logicalLDIFLines(ctx, rawRecord, lineLimit)
		if err != nil {
			return nil, fmt.Errorf("parse LDIF: %w", err)
		}
		remainingLines -= len(lines)
		if len(lines) == 0 {
			continue
		}
		if err := rejectWebLDIFExternalValues(ctx, lines); err != nil {
			return nil, err
		}
		prepared, err := prepareLDIFRecord(lines)
		if err != nil {
			return nil, fmt.Errorf("parse LDIF: %w", err)
		}
		if prepared.hasVersion {
			if sawVersion || len(records) != 0 {
				return nil, errors.New("parse LDIF: version must appear once before all records")
			}
			sawVersion = true
		}
		if prepared.versionOnly {
			continue
		}
		if prepared.changeType == "moddn" || prepared.changeType == "modrdn" {
			record, err := parseLDIFModifyDN(lines)
			if err != nil {
				return nil, fmt.Errorf("parse LDIF: %w", err)
			}
			if err := application.appendValidatedLDIFRecord(&records, record); err != nil {
				return nil, err
			}
			continue
		}

		document := &ldif.LDIF{}
		reader := contextCheckingReader{ctx: ctx, reader: bytes.NewReader(prepared.document)}
		parsedEntries := 0
		for parsed, parseErr := range ldif.UnmarshalEntries(reader, document) {
			if err := checkLDIFContext(ctx); err != nil {
				return nil, err
			}
			if parseErr != nil {
				return nil, fmt.Errorf("parse LDIF: %w", parseErr)
			}
			if parsed == nil {
				continue
			}
			parsedEntries++
			if parsedEntries > 1 {
				return nil, errors.New("parse LDIF: record contains more than one entry")
			}
			record, err := newLDIFImportRecord(parsed)
			if err != nil {
				return nil, err
			}
			if err := application.appendValidatedLDIFRecord(&records, record); err != nil {
				return nil, err
			}
		}
		if err := checkLDIFContext(ctx); err != nil {
			return nil, err
		}
		if parsedEntries != 1 {
			return nil, errors.New("parse LDIF: record does not contain an entry or change")
		}
	}
	if len(records) == 0 {
		return nil, errors.New("LDIF contains no entries or changes")
	}
	return records, nil
}

type preparedLDIFRecord struct {
	document    []byte
	changeType  string
	hasVersion  bool
	versionOnly bool
}

func splitLDIFRecords(ctx context.Context, data []byte, maximumChanges int) ([][]byte, error) {
	initialCapacity := 16
	if maximumChanges < initialCapacity {
		initialCapacity = maximumChanges + 1
	}
	records := make([][]byte, 0, initialCapacity)
	recordStart := -1
	changeRecords := 0
	flush := func(end int) error {
		if recordStart < 0 {
			return nil
		}
		record := data[recordStart:end]
		recordStart = -1
		hasContent, countsAsChange := classifyLDIFRecord(record)
		if !hasContent {
			return nil
		}
		if countsAsChange {
			changeRecords++
			if changeRecords > maximumChanges {
				return fmt.Errorf("LDIF exceeds the limit of %d changes", maximumChanges)
			}
		}
		records = append(records, record)
		return nil
	}
	for start := 0; start < len(data); {
		if err := checkLDIFContext(ctx); err != nil {
			return nil, err
		}
		lineStart := start
		if offset := bytes.IndexByte(data[start:], '\n'); offset >= 0 {
			start += offset + 1
		} else {
			start = len(data)
		}
		lineEnd := start
		if lineEnd > lineStart && data[lineEnd-1] == '\n' {
			lineEnd--
		}
		if lineEnd > lineStart && data[lineEnd-1] == '\r' {
			lineEnd--
		}
		if lineEnd == lineStart {
			if err := flush(lineStart); err != nil {
				return nil, err
			}
			continue
		}
		if recordStart < 0 {
			recordStart = lineStart
		}
	}
	if err := flush(len(data)); err != nil {
		return nil, err
	}
	return records, nil
}

func classifyLDIFRecord(record []byte) (bool, bool) {
	logicalLines := 0
	firstIsVersion := false
	hasInvalidContinuation := false
	comment := false
	for start := 0; start < len(record); {
		lineStart := start
		if offset := bytes.IndexByte(record[start:], '\n'); offset >= 0 {
			start += offset + 1
		} else {
			start = len(record)
		}
		lineEnd := start
		if lineEnd > lineStart && record[lineEnd-1] == '\n' {
			lineEnd--
		}
		if lineEnd > lineStart && record[lineEnd-1] == '\r' {
			lineEnd--
		}
		line := record[lineStart:lineEnd]
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' {
			comment = true
			continue
		}
		if line[0] == ' ' {
			if !comment && logicalLines == 0 {
				hasInvalidContinuation = true
			}
			continue
		}
		comment = false
		logicalLines++
		if logicalLines == 1 {
			if colon := bytes.IndexByte(line, ':'); colon > 0 {
				firstIsVersion = strings.EqualFold(string(line[:colon]), "version")
			}
		}
	}
	hasContent := logicalLines != 0 || hasInvalidContinuation
	return hasContent, hasContent && (hasInvalidContinuation || logicalLines != 1 || !firstIsVersion)
}

func maximumLDIFLogicalLines(bodyLimit int64) int {
	limit := bodyLimit/2 + 1
	if limit > maximumLDIFDocumentLogicalLines {
		limit = maximumLDIFDocumentLogicalLines
	}
	if limit < 1 {
		limit = 1
	}
	return int(limit)
}

func maximumLDIFRecordLogicalLines(maximumAttributes, documentLimit int) int {
	const structuralLinesPerAttribute = maximumValuesPerAttribute + 2
	if documentLimit <= 8 || maximumAttributes > (documentLimit-8)/structuralLinesPerAttribute {
		return documentLimit
	}
	return maximumAttributes*structuralLinesPerAttribute + 8
}

func logicalLDIFLines(ctx context.Context, record []byte, maximumLines int) ([]string, error) {
	lines := make([]string, 0, min(maximumLines, 64))
	var current strings.Builder
	haveCurrent := false
	comment := false
	flush := func() error {
		if !haveCurrent {
			return nil
		}
		if len(lines) >= maximumLines {
			return fmt.Errorf("LDIF record exceeds the structural limit of %d logical lines", maximumLines)
		}
		lines = append(lines, current.String())
		current.Reset()
		haveCurrent = false
		return nil
	}
	for start := 0; start < len(record); {
		if err := checkLDIFContext(ctx); err != nil {
			return nil, err
		}
		lineStart := start
		if offset := bytes.IndexByte(record[start:], '\n'); offset >= 0 {
			start += offset + 1
		} else {
			start = len(record)
		}
		lineEnd := start
		if lineEnd > lineStart && record[lineEnd-1] == '\n' {
			lineEnd--
		}
		if lineEnd > lineStart && record[lineEnd-1] == '\r' {
			lineEnd--
		}
		line := record[lineStart:lineEnd]
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' {
			comment = true
			continue
		}
		if line[0] == ' ' {
			if comment {
				continue
			}
			if !haveCurrent {
				return nil, errors.New("LDIF continuation line has no preceding value")
			}
			_, _ = current.Write(line[1:])
			continue
		}
		comment = false
		if err := flush(); err != nil {
			return nil, err
		}
		_, _ = current.Write(line)
		haveCurrent = true
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return lines, nil
}

func decodeLDIFLine(line string) (string, string, ldifValueEncoding, error) {
	colon := strings.IndexByte(line, ':')
	if colon <= 0 {
		return "", "", ldifValuePlain, fmt.Errorf("invalid LDIF line %q", line)
	}
	encoding := ldifValuePlain
	if colon+1 < len(line) {
		switch line[colon+1] {
		case ':':
			encoding = ldifValueBase64
		case '<':
			encoding = ldifValueURL
		}
	}
	name := strings.ToLower(line[:colon])
	synthetic := "dn: cn=web-ldif-parser\nwebValue" + line[colon:] + "\n\n"
	parsed, err := ldif.Parse(synthetic)
	if err != nil || len(parsed.Entries) != 1 || parsed.Entries[0].Entry == nil {
		if err == nil {
			err = errors.New("value could not be decoded")
		}
		return "", "", encoding, fmt.Errorf("invalid %s value: %w", name, err)
	}
	values := parsed.Entries[0].Entry.GetAttributeValues("webValue")
	if len(values) != 1 {
		return "", "", encoding, fmt.Errorf("%s must contain exactly one value", name)
	}
	return name, values[0], encoding, nil
}

func prepareLDIFRecord(lines []string) (preparedLDIFRecord, error) {
	prepared := preparedLDIFRecord{}
	var document strings.Builder
	index := 0
	name, value, encoding, err := decodeLDIFLine(lines[index])
	if err != nil {
		return prepared, err
	}
	if name == "version" {
		if encoding != ldifValuePlain {
			return prepared, errors.New("version must use plain string form")
		}
		if value != "1" {
			return prepared, fmt.Errorf("invalid version %q", value)
		}
		prepared.hasVersion = true
		writeLDIFLogicalLine(&document, "version: 1")
		index++
		if index >= len(lines) {
			prepared.versionOnly = true
			return prepared, nil
		}
		name, _, _, err = decodeLDIFLine(lines[index])
		if err != nil {
			return prepared, err
		}
	}
	if name != "dn" {
		return prepared, fmt.Errorf("record must begin with dn, got %q", name)
	}
	writeLDIFLogicalLine(&document, canonicalLDIFLineName(lines[index], "dn"))
	index++
	if index >= len(lines) {
		return prepared, errors.New("record contains only a dn line")
	}

	name, value, encoding, err = decodeLDIFLine(lines[index])
	if err != nil {
		return prepared, err
	}
	if name == "changetype" {
		if encoding != ldifValuePlain {
			return prepared, errors.New("changetype must use plain string form")
		}
		prepared.changeType = strings.ToLower(value)
		writeLDIFLogicalLine(&document, "changetype: "+prepared.changeType)
		index++
	}

	switch prepared.changeType {
	case "":
		if index >= len(lines) {
			return prepared, errors.New("content entry contains no attributes")
		}
		if err := normalizeLDIFAttributeLines(&document, lines[index:]); err != nil {
			return prepared, err
		}
	case "add":
		if index >= len(lines) {
			return prepared, errors.New("changetype add requires at least one attribute")
		}
		if err := normalizeLDIFAttributeLines(&document, lines[index:]); err != nil {
			return prepared, err
		}
	case "delete":
		if index != len(lines) {
			field, fieldErr := ldifLineName(lines[index])
			if fieldErr != nil {
				return prepared, fieldErr
			}
			return prepared, fmt.Errorf("unexpected field %q after changetype delete", field)
		}
	case "modify":
		if err := normalizeLDIFModifyLines(&document, lines[index:]); err != nil {
			return prepared, err
		}
	case "moddn", "modrdn":
		return prepared, nil
	default:
		return prepared, fmt.Errorf("invalid changetype %s", prepared.changeType)
	}
	document.WriteByte('\n')
	prepared.document = []byte(document.String())
	return prepared, nil
}

func normalizeLDIFAttributeLines(document *strings.Builder, lines []string) error {
	for _, line := range lines {
		name, err := ldifLineName(line)
		if err != nil {
			return err
		}
		writeLDIFLogicalLine(document, canonicalLDIFLineName(line, name))
	}
	return nil
}

func normalizeLDIFModifyLines(document *strings.Builder, lines []string) error {
	if len(lines) == 0 {
		return errors.New("changetype modify requires at least one modification")
	}
	operations := 0
	for index := 0; index < len(lines); {
		if lines[index] == "-" {
			return errors.New("empty operation in modify record")
		}
		operation, attribute, encoding, err := decodeLDIFLine(lines[index])
		if err != nil {
			return err
		}
		if operation != "add" && operation != "delete" && operation != "replace" {
			return fmt.Errorf("invalid operation %s in modify record", operation)
		}
		if encoding != ldifValuePlain {
			return errors.New("modify operation attribute must use plain string form")
		}
		attribute = strings.ToLower(attribute)
		if err := validateAttribute(attribute, false); err != nil {
			return err
		}
		writeLDIFLogicalLine(document, operation+": "+attribute)
		index++
		for index < len(lines) && lines[index] != "-" {
			valueName, err := ldifLineName(lines[index])
			if err != nil {
				return err
			}
			if !strings.EqualFold(valueName, attribute) {
				return fmt.Errorf("unexpected field %q in %s modification for %s", valueName, operation, attribute)
			}
			writeLDIFLogicalLine(document, canonicalLDIFLineName(lines[index], attribute))
			index++
		}
		if index >= len(lines) {
			return errors.New("modify operation does not close with a single dash")
		}
		writeLDIFLogicalLine(document, "-")
		index++
		operations++
	}
	if operations == 0 {
		return errors.New("changetype modify requires at least one modification")
	}
	return nil
}

func ldifLineName(line string) (string, error) {
	colon := strings.IndexByte(line, ':')
	if colon <= 0 {
		return "", fmt.Errorf("invalid LDIF line %q", line)
	}
	return strings.ToLower(line[:colon]), nil
}

func canonicalLDIFLineName(line, name string) string {
	return name + line[strings.IndexByte(line, ':'):]
}

func writeLDIFLogicalLine(document *strings.Builder, line string) {
	document.WriteString(line)
	document.WriteByte('\n')
}

func parseLDIFModifyDN(lines []string) (ldifImportRecord, error) {
	index := 0
	name, _, _, err := decodeLDIFLine(lines[index])
	if err != nil {
		return ldifImportRecord{}, err
	}
	if name == "version" {
		index++
	}
	if len(lines)-index < 4 {
		return ldifImportRecord{}, errors.New("ModifyDN record is incomplete")
	}
	dn, _, err := decodeLDIFModifyDNField(lines[index], "dn")
	if err != nil {
		return ldifImportRecord{}, err
	}
	if err := validateDN(dn, false); err != nil {
		return ldifImportRecord{}, err
	}
	index++

	changeType, encoding, err := decodeLDIFModifyDNField(lines[index], "changetype")
	if err != nil {
		return ldifImportRecord{}, err
	}
	if encoding != ldifValuePlain {
		return ldifImportRecord{}, errors.New("ModifyDN changetype must use plain string form")
	}
	if !strings.EqualFold(changeType, "moddn") && !strings.EqualFold(changeType, "modrdn") {
		return ldifImportRecord{}, errors.New("invalid ModifyDN changetype")
	}
	index++

	newRDN, _, err := decodeLDIFModifyDNField(lines[index], "newrdn")
	if err != nil {
		return ldifImportRecord{}, err
	}
	if err := validateRDN(newRDN); err != nil {
		return ldifImportRecord{}, err
	}
	index++

	deleteOldValue, encoding, err := decodeLDIFModifyDNField(lines[index], "deleteoldrdn")
	if err != nil {
		return ldifImportRecord{}, err
	}
	if encoding != ldifValuePlain {
		return ldifImportRecord{}, errors.New("ModifyDN deleteoldrdn must use plain string form")
	}
	if deleteOldValue != "0" && deleteOldValue != "1" {
		return ldifImportRecord{}, errors.New("ModifyDN deleteoldrdn must be 0 or 1")
	}
	index++

	newSuperior := ""
	if index < len(lines) {
		newSuperior, _, err = decodeLDIFModifyDNField(lines[index], "newsuperior")
		if err != nil {
			return ldifImportRecord{}, err
		}
		if err := validateDN(newSuperior, false); err != nil {
			return ldifImportRecord{}, fmt.Errorf("invalid newsuperior: %w", err)
		}
		index++
	}
	if index != len(lines) {
		field, _, _, err := decodeLDIFLine(lines[index])
		if err != nil {
			return ldifImportRecord{}, err
		}
		return ldifImportRecord{}, fmt.Errorf("unexpected ModifyDN field %q", field)
	}
	request := ldap.NewModifyDNRequest(dn, newRDN, deleteOldValue == "1", newSuperior)
	return ldifImportRecord{modifyDN: request, dn: dn, operation: "moddn"}, nil
}

func decodeLDIFModifyDNField(line, expected string) (string, ldifValueEncoding, error) {
	name, value, encoding, err := decodeLDIFLine(line)
	if err != nil {
		return "", encoding, err
	}
	if !strings.EqualFold(name, expected) {
		return "", encoding, fmt.Errorf("ModifyDN field %q must appear here, got %q", expected, name)
	}
	return value, encoding, nil
}

func newLDIFImportRecord(entry *ldif.Entry) (ldifImportRecord, error) {
	switch {
	case entry.Entry != nil:
		return ldifImportRecord{entry: entry, dn: entry.Entry.DN, operation: "add"}, nil
	case entry.Add != nil:
		return ldifImportRecord{entry: entry, dn: entry.Add.DN, operation: "add"}, nil
	case entry.Del != nil:
		return ldifImportRecord{entry: entry, dn: entry.Del.DN, operation: "delete"}, nil
	case entry.Modify != nil:
		return ldifImportRecord{entry: entry, dn: entry.Modify.DN, operation: "modify"}, nil
	default:
		return ldifImportRecord{}, errors.New("unsupported LDIF record")
	}
}

func (application *Application) appendValidatedLDIFRecord(records *[]ldifImportRecord, record ldifImportRecord) error {
	if len(*records) >= application.config.MaxImportChanges {
		return fmt.Errorf("LDIF exceeds the limit of %d changes", application.config.MaxImportChanges)
	}
	if err := application.validateLDIFRecord(record); err != nil {
		return err
	}
	*records = append(*records, record)
	return nil
}

func rejectWebLDIFExternalValues(ctx context.Context, logicalLines []string) error {
	for _, line := range logicalLines {
		if err := checkLDIFContext(ctx); err != nil {
			return err
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		if strings.EqualFold(name, "control") {
			return errors.New("LDIF controls are not accepted by Web import")
		}
		if colon+1 < len(line) && line[colon+1] == '<' {
			return errors.New("LDIF URL values are not accepted by Web import")
		}
	}
	return nil
}

func checkLDIFContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (application *Application) validateLDIFRecord(record ldifImportRecord) error {
	if record.modifyDN != nil {
		if len(record.modifyDN.Controls) != 0 {
			return errors.New("LDIF controls are not accepted")
		}
		return nil
	}
	if record.entry == nil {
		return errors.New("unsupported LDIF record")
	}
	entry := record.entry
	switch {
	case entry.Entry != nil:
		if err := validateDN(entry.Entry.DN, false); err != nil {
			return err
		}
		if len(entry.Entry.Attributes) == 0 || len(entry.Entry.Attributes) > application.config.MaxAttributes {
			return errors.New("LDIF add entry has an invalid attribute count")
		}
		for _, attribute := range entry.Entry.Attributes {
			if err := validateAttribute(attribute.Name, false); err != nil {
				return err
			}
			if len(attribute.Values) > maximumValuesPerAttribute {
				return errors.New("LDIF attribute has too many values")
			}
		}
	case entry.Add != nil:
		if err := validateDN(entry.Add.DN, false); err != nil {
			return err
		}
		if len(entry.Add.Controls) != 0 || len(entry.Add.Attributes) == 0 || len(entry.Add.Attributes) > application.config.MaxAttributes {
			return errors.New("LDIF add has controls or an invalid attribute count")
		}
		for _, attribute := range entry.Add.Attributes {
			if err := validateAttribute(attribute.Type, false); err != nil {
				return err
			}
			if len(attribute.Vals) > maximumValuesPerAttribute {
				return errors.New("LDIF attribute has too many values")
			}
		}
	case entry.Del != nil:
		if len(entry.Del.Controls) != 0 {
			return errors.New("LDIF controls are not accepted")
		}
		return validateDN(entry.Del.DN, false)
	case entry.Modify != nil:
		if err := validateDN(entry.Modify.DN, false); err != nil {
			return err
		}
		if len(entry.Modify.Controls) != 0 || len(entry.Modify.Changes) == 0 || len(entry.Modify.Changes) > application.config.MaxAttributes {
			return errors.New("LDIF modify has controls or an invalid change count")
		}
		for _, change := range entry.Modify.Changes {
			if err := validateAttribute(change.Modification.Type, false); err != nil {
				return err
			}
			if len(change.Modification.Vals) > maximumValuesPerAttribute {
				return errors.New("LDIF modification has too many values")
			}
		}
	default:
		return errors.New("unsupported LDIF record")
	}
	return nil
}

func applyLDIFRecord(client Client, record ldifImportRecord) error {
	if record.modifyDN != nil {
		return client.ModifyDN(record.modifyDN)
	}
	if record.entry == nil {
		return errors.New("unsupported LDIF record")
	}
	entry := record.entry
	switch {
	case entry.Entry != nil:
		request := ldap.NewAddRequest(entry.Entry.DN, nil)
		for _, attribute := range entry.Entry.Attributes {
			request.Attribute(attribute.Name, attribute.Values)
		}
		return client.Add(request)
	case entry.Add != nil:
		return client.Add(entry.Add)
	case entry.Del != nil:
		return client.Del(entry.Del)
	case entry.Modify != nil:
		return client.Modify(entry.Modify)
	default:
		return errors.New("unsupported LDIF record")
	}
}

func newLDIFImportResult(recordNumber int, record ldifImportRecord, status string, failure *apiError) ldifImportResult {
	return ldifImportResult{
		Record: recordNumber, DN: record.dn, Operation: record.operation,
		Success: status == "applied", Status: status, Error: failure,
	}
}

func appendLDIFNotAttempted(result *ldifImportResponse, records []ldifImportRecord, firstRecord int) {
	for index, record := range records {
		result.Results = append(result.Results, newLDIFImportResult(firstRecord+index, record, "not_attempted", nil))
	}
}

func ldifImportAbortFailure(ctx context.Context, applied int) apiError {
	code := "import_canceled"
	message := "LDIF import was canceled"
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		code = "import_deadline_exceeded"
		message = "LDIF import exceeded the operation deadline"
	}
	return apiError{Code: code, Message: message, Applied: intPointer(applied)}
}

func ldifImportAbortHTTPStatus(ctx context.Context) int {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return http.StatusGatewayTimeout
	}
	return http.StatusRequestTimeout
}

func writeLDIFRequestContextError(response http.ResponseWriter, ctx context.Context) bool {
	if ctx.Err() == nil {
		return false
	}
	failure := ldifImportAbortFailure(ctx, 0)
	writeAPIError(response, ldifImportAbortHTTPStatus(ctx), failure)
	return true
}

func intPointer(value int) *int {
	return &value
}
