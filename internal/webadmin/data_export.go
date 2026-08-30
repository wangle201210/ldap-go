package webadmin

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

var errDataExportTooLarge = errors.New("directory export exceeds the configured byte limit")

type dataExportFormat struct {
	contentType string
	filename    string
	encode      func(io.Writer, []entryResponse, []string) error
}

type dataExportDocument struct {
	Entries []entryResponse `json:"entries"`
}

type dataExportCSVCell struct {
	Text         []string `json:"text,omitempty"`
	BinaryBase64 []string `json:"binary_base64,omitempty"`
}

type limitedExportWriter struct {
	destination io.Writer
	maximum     int64
	written     int64
}

func (writer *limitedExportWriter) Write(value []byte) (int, error) {
	if int64(len(value)) > writer.maximum-writer.written {
		return 0, errDataExportTooLarge
	}
	written, err := writer.destination.Write(value)
	writer.written += int64(written)
	if written != len(value) && err == nil {
		return written, io.ErrShortWrite
	}
	return written, err
}

// handleDataExport exports one bounded LDAP Search result as CSV or JSON.
// It is intentionally separate from handleExport, which remains the LDIF endpoint.
func (application *Application) handleDataExport(response http.ResponseWriter, request *http.Request) {
	if !methodAllowed(response, request, http.MethodGet) {
		return
	}
	current, ok := application.acquireSession(response, request)
	if !ok {
		return
	}
	defer application.releaseSession(current)
	format, ok := parseDataExportFormat(request.URL.Query().Get("format"))
	if !ok {
		writeAPIError(response, http.StatusBadRequest, apiError{
			Code: "invalid_format", Message: "format must be csv or json",
		})
		return
	}

	input, err := searchRequestFromQuery(request)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_search", Message: err.Error()})
		return
	}
	if input.PageSize != 0 || input.PageCookie != "" {
		writeAPIError(response, http.StatusBadRequest, apiError{
			Code: "invalid_search", Message: "paging is not supported for directory export",
		})
		return
	}
	if input.TypesOnly {
		writeAPIError(response, http.StatusBadRequest, apiError{
			Code: "invalid_search", Message: "types_only is not supported for directory export",
		})
		return
	}
	maximumEntries := min(application.config.MaxSearchSize, application.config.MaxExportEntries)
	if input.SizeLimit == 0 {
		input.SizeLimit = maximumEntries
	}
	if input.SizeLimit > maximumEntries {
		writeAPIError(response, http.StatusBadRequest, apiError{
			Code: "invalid_search", Message: "size_limit is outside the configured export bounds",
		})
		return
	}
	ldapRequest, err := application.buildSearchRequest(input)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_search", Message: err.Error()})
		return
	}
	result, release, err := application.search(current.client, ldapRequest)
	if err != nil {
		writeLDAPError(response, err)
		return
	}
	defer release()
	if result == nil {
		writeAPIError(response, http.StatusBadGateway, apiError{
			Code: "ldap_transport_error", Message: "LDAP operation returned no result",
		})
		return
	}
	if rejectIncompleteReferrals(response, result) {
		return
	}

	entries := stableDataExportEntries(result.Entries)
	if len(entries) > input.SizeLimit || len(entries) > application.config.MaxExportEntries {
		writeAPIError(response, http.StatusRequestEntityTooLarge, apiError{
			Code: "export_entry_limit", Message: "directory export exceeds the configured entry limit",
		})
		return
	}
	columns := dataExportColumns(input.Attributes, entries)
	if err := validateAttributes(columns, application.config.MaxAttributes, false); err != nil {
		writeAPIError(response, http.StatusRequestEntityTooLarge, apiError{
			Code: "export_attribute_limit", Message: "directory export contains too many attributes",
		})
		return
	}

	file, err := os.CreateTemp("", "ldap-go-directory-export-*")
	if err != nil {
		writeAPIError(response, http.StatusInternalServerError, apiError{
			Code: "export_encoding_failed", Message: "unable to prepare directory export",
		})
		return
	}
	name := file.Name()
	defer func() {
		_ = file.Close()
		_ = os.Remove(name)
	}()
	output := &limitedExportWriter{destination: file, maximum: application.config.MaxExportBytes}
	if err := format.encode(output, entries, columns); err != nil {
		if errors.Is(err, errDataExportTooLarge) {
			writeAPIError(response, http.StatusRequestEntityTooLarge, apiError{
				Code: "export_byte_limit", Message: errDataExportTooLarge.Error(),
			})
			return
		}
		writeAPIError(response, http.StatusInternalServerError, apiError{
			Code: "export_encoding_failed", Message: "unable to encode directory export",
		})
		return
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		writeAPIError(response, http.StatusInternalServerError, apiError{
			Code: "export_encoding_failed", Message: "unable to prepare directory export response",
		})
		return
	}

	response.Header().Set("Content-Type", format.contentType)
	response.Header().Set("Content-Disposition", `attachment; filename="`+format.filename+`"`)
	response.Header().Set("Content-Length", strconv.FormatInt(output.written, 10))
	response.Header().Set("X-Directory-Entry-Count", strconv.Itoa(len(entries)))
	response.WriteHeader(http.StatusOK)
	_, _ = io.CopyN(response, file, output.written)
}

func parseDataExportFormat(value string) (dataExportFormat, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "csv":
		return dataExportFormat{
			contentType: "text/csv; charset=utf-8",
			filename:    "directory-export.csv",
			encode:      encodeDataExportCSV,
		}, true
	case "json":
		return dataExportFormat{
			contentType: "application/json; charset=utf-8",
			filename:    "directory-export.json",
			encode:      encodeDataExportJSON,
		}, true
	default:
		return dataExportFormat{}, false
	}
}

func stableDataExportEntries(source []*ldap.Entry) []entryResponse {
	entries := make([]entryResponse, 0, len(source))
	for _, entry := range source {
		if entry == nil {
			continue
		}
		converted := convertEntry(entry)
		for _, values := range converted.Attributes {
			sort.Strings(values)
		}
		for _, values := range converted.BinaryAttributes {
			sort.Strings(values)
		}
		entries = append(entries, converted)
	}
	sort.SliceStable(entries, func(left, right int) bool {
		leftFolded := strings.ToLower(entries[left].DN)
		rightFolded := strings.ToLower(entries[right].DN)
		if leftFolded == rightFolded {
			return entries[left].DN < entries[right].DN
		}
		return leftFolded < rightFolded
	})
	return entries
}

func dataExportColumns(requested []string, entries []entryResponse) []string {
	columns := make([]string, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for _, attribute := range requested {
		if attribute == "*" || attribute == "+" {
			continue
		}
		if attribute == "1.1" {
			continue
		}
		key := strings.ToLower(attribute)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		columns = append(columns, attribute)
	}
	discovered := make(map[string]string)
	for _, entry := range entries {
		for name := range entry.Attributes {
			rememberDataExportColumn(discovered, seen, name)
		}
		for name := range entry.BinaryAttributes {
			rememberDataExportColumn(discovered, seen, name)
		}
	}
	additional := make([]string, 0, len(discovered))
	for _, name := range discovered {
		additional = append(additional, name)
	}
	sort.Slice(additional, func(left, right int) bool {
		leftFolded := strings.ToLower(additional[left])
		rightFolded := strings.ToLower(additional[right])
		if leftFolded == rightFolded {
			return additional[left] < additional[right]
		}
		return leftFolded < rightFolded
	})
	return append(columns, additional...)
}

func rememberDataExportColumn(discovered map[string]string, seen map[string]struct{}, name string) {
	key := strings.ToLower(name)
	if _, exists := seen[key]; exists {
		return
	}
	if current, exists := discovered[key]; !exists || name < current {
		discovered[key] = name
	}
}

func encodeDataExportJSON(writer io.Writer, entries []entryResponse, _ []string) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(dataExportDocument{Entries: entries})
}

func encodeDataExportCSV(writer io.Writer, entries []entryResponse, columns []string) error {
	encoder := csv.NewWriter(writer)
	encoder.UseCRLF = true
	header := append([]string{"dn"}, columns...)
	if err := encoder.Write(header); err != nil {
		return err
	}
	for _, entry := range entries {
		record := make([]string, 1, len(columns)+1)
		record[0] = entry.DN
		for _, column := range columns {
			textValues := lookupDataExportValues(entry.Attributes, column)
			binaryValues := lookupDataExportValues(entry.BinaryAttributes, column)
			if len(textValues) == 0 && len(binaryValues) == 0 {
				record = append(record, "")
				continue
			}
			value, err := json.Marshal(dataExportCSVCell{
				Text: textValues, BinaryBase64: binaryValues,
			})
			if err != nil {
				return err
			}
			record = append(record, string(value))
		}
		if err := encoder.Write(record); err != nil {
			return err
		}
	}
	encoder.Flush()
	return encoder.Error()
}

func lookupDataExportValues(attributes map[string][]string, requested string) []string {
	if values, exists := attributes[requested]; exists {
		return values
	}
	for name, values := range attributes {
		if strings.EqualFold(name, requested) {
			return values
		}
	}
	return nil
}
