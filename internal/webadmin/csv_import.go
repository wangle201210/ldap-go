package webadmin

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"
)

const maximumCSVImportValueBytes = 64 << 10

type csvImportText string

func (value *csvImportText) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if !utf8.Valid(data) {
		return errors.New("csv must be valid UTF-8")
	}
	if len(data) == 0 || data[0] != '"' {
		return errors.New("csv must be a string")
	}
	var decoded string
	if err := json.Unmarshal(data, &decoded); err != nil {
		return errors.New("csv must be a string")
	}
	if !utf8.ValidString(decoded) {
		return errors.New("csv must be valid UTF-8")
	}
	*value = csvImportText(decoded)
	return nil
}

type csvImportMapping map[string]string

func (mapping *csvImportMapping) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode mapping: %w", err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return errors.New("mapping must be an object")
	}
	decoded := make(csvImportMapping)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("decode mapping header: %w", err)
		}
		header, ok := key.(string)
		if !ok {
			return errors.New("mapping headers must be strings")
		}
		if _, duplicate := decoded[header]; duplicate {
			return fmt.Errorf("mapping contains duplicate header %q", header)
		}
		value, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("mapping value for %q must be a string", header)
		}
		attribute, ok := value.(string)
		if !ok {
			return fmt.Errorf("mapping value for %q must be a string", header)
		}
		decoded[header] = attribute
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("decode mapping: %w", err)
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return errors.New("mapping must contain one JSON object")
	}
	*mapping = decoded
	return nil
}

type csvImportRequestBody struct {
	CSV             csvImportText    `json:"csv"`
	BaseDN          string           `json:"base_dn"`
	RDNAttribute    string           `json:"rdn_attribute"`
	ObjectClasses   []string         `json:"object_classes"`
	Mapping         csvImportMapping `json:"mapping"`
	ContinueOnError bool             `json:"continue_on_error"`
}

type csvImportResponse struct {
	Results     []csvImportResult `json:"results"`
	Applied     int               `json:"applied"`
	Failed      int               `json:"failed"`
	Unknown     int               `json:"unknown"`
	Aborted     bool              `json:"aborted,omitempty"`
	AbortReason string            `json:"abort_reason,omitempty"`
}

type csvImportResult struct {
	Row     int       `json:"row"`
	DN      string    `json:"dn"`
	Success bool      `json:"success"`
	Status  string    `json:"status"`
	Error   *apiError `json:"error,omitempty"`
}

type csvImportColumn struct {
	index     int
	attribute string
}

type csvImportEntry struct {
	row     int
	dn      string
	request *ldap.AddRequest
}

// handleCSVImport validates the complete CSV document before issuing ordered,
// independent LDAP Add operations through the authenticated session.
func (application *Application) handleCSVImport(response http.ResponseWriter, request *http.Request) {
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

	var input csvImportRequestBody
	if err := application.decodeJSON(response, request, &input); err != nil {
		writeJSONRequestError(response, err)
		return
	}
	entries, err := application.prepareCSVImport(input)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{
			Code: "invalid_csv_import", Message: err.Error(),
		})
		return
	}

	result := csvImportResponse{Results: make([]csvImportResult, 0, len(entries))}
	batchContext, cancel := context.WithTimeout(request.Context(), application.config.OperationTimeout)
	defer cancel()
	for index, entry := range entries {
		if reason := batchAbortReason(batchContext); reason != "" {
			result.Aborted = true
			result.AbortReason = reason
			appendCSVNotAttempted(&result, entries[index:])
			break
		}
		err, interrupted := executeBatchWrite(batchContext, application, current, func(client Client) error {
			return client.Add(entry.request)
		})
		if errors.Is(err, errBatchApplicationClosed) {
			result.Aborted = true
			result.AbortReason = "administration service is closing"
			appendCSVNotAttempted(&result, entries[index:])
			break
		}
		if interrupted {
			result.Unknown++
			result.Aborted = true
			result.AbortReason = batchAbortReason(batchContext)
			failure := apiError{Code: "ldap_result_unknown", Message: "LDAP write result is unknown because the batch was canceled during the operation"}
			result.Results = append(result.Results, csvImportResult{Row: entry.row, DN: entry.dn, Status: "unknown", Error: &failure})
			appendCSVNotAttempted(&result, entries[index+1:])
			break
		}
		if err == nil {
			result.Applied++
			result.Results = append(result.Results, csvImportResult{
				Row: entry.row, DN: entry.dn, Success: true, Status: "applied",
			})
			continue
		}

		failure, unknown := ldapWriteFailure(err)
		if unknown {
			application.scheduleSessionClose(current, nil)
			result.Unknown++
			result.Results = append(result.Results, csvImportResult{
				Row: entry.row, DN: entry.dn, Status: "unknown", Error: &failure,
			})
			appendCSVNotAttempted(&result, entries[index+1:])
			break
		}
		result.Failed++
		result.Results = append(result.Results, csvImportResult{
			Row: entry.row, DN: entry.dn, Status: "failed", Error: &failure,
		})
		if input.ContinueOnError {
			continue
		}
		appendCSVNotAttempted(&result, entries[index+1:])
		break
	}
	writeJSON(response, http.StatusOK, result)
}

func (application *Application) prepareCSVImport(input csvImportRequestBody) ([]csvImportEntry, error) {
	if err := validateDN(input.BaseDN, false); err != nil {
		return nil, fmt.Errorf("base_dn: %w", err)
	}
	if err := validateCSVImportLDAPType(input.RDNAttribute, "rdn_attribute"); err != nil {
		return nil, err
	}
	objectClasses, err := validateCSVImportObjectClasses(input.ObjectClasses)
	if err != nil {
		return nil, err
	}

	text := string(input.CSV)
	if strings.HasPrefix(text, "\uFEFF") {
		text = strings.TrimPrefix(text, "\uFEFF")
	}
	if text == "" {
		return nil, errors.New("csv is required")
	}
	reader := csv.NewReader(strings.NewReader(text))
	header, err := reader.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("csv must contain a header row")
		}
		return nil, fmt.Errorf("parse CSV header: %w", err)
	}
	if err := validateCSVImportHeader(header); err != nil {
		return nil, err
	}
	columns, rdnColumn, err := application.validateCSVImportMapping(header, input.Mapping, input.RDNAttribute)
	if err != nil {
		return nil, err
	}

	entries := make([]csvImportEntry, 0)
	for {
		record, readErr := reader.Read()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("parse CSV: %w", readErr)
		}
		row, _ := reader.FieldPos(0)
		if len(entries) >= application.config.MaxImportChanges {
			return nil, fmt.Errorf("csv exceeds the limit of %d data rows", application.config.MaxImportChanges)
		}
		for column, value := range record {
			if len(value) > maximumCSVImportValueBytes {
				return nil, fmt.Errorf("CSV row %d column %q exceeds %d bytes", row, header[column], maximumCSVImportValueBytes)
			}
			if !utf8.ValidString(value) {
				return nil, fmt.Errorf("CSV row %d column %q is not valid UTF-8", row, header[column])
			}
		}
		rdnValue := record[rdnColumn]
		if rdnValue == "" {
			return nil, fmt.Errorf("CSV row %d has an empty RDN value", row)
		}
		dn := input.RDNAttribute + "=" + ldap.EscapeDN(rdnValue) + "," + input.BaseDN
		if err := validateDN(dn, false); err != nil {
			return nil, fmt.Errorf("CSV row %d generated an invalid DN: %w", row, err)
		}

		add := ldap.NewAddRequest(dn, nil)
		add.Attribute("objectClass", objectClasses)
		for _, column := range columns {
			if value := record[column.index]; value != "" {
				add.Attribute(column.attribute, []string{value})
			}
		}
		entries = append(entries, csvImportEntry{row: row, dn: dn, request: add})
	}
	if len(entries) == 0 {
		return nil, errors.New("csv contains no data rows")
	}
	return entries, nil
}

func validateCSVImportHeader(header []string) error {
	if len(header) == 0 {
		return errors.New("csv header is empty")
	}
	seen := make(map[string]struct{}, len(header))
	for index, value := range header {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("CSV header column %d is empty", index+1)
		}
		if len(value) > maximumCSVImportValueBytes {
			return fmt.Errorf("CSV header %q exceeds %d bytes", value, maximumCSVImportValueBytes)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("CSV header %q is duplicated", value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func (application *Application) validateCSVImportMapping(
	header []string,
	mapping csvImportMapping,
	rdnAttribute string,
) ([]csvImportColumn, int, error) {
	if len(mapping) == 0 {
		return nil, 0, errors.New("mapping must contain at least one header")
	}
	if len(mapping)+1 > application.config.MaxAttributes {
		return nil, 0, fmt.Errorf("mapping and objectClass exceed the limit of %d attributes", application.config.MaxAttributes)
	}
	headerIndex := make(map[string]int, len(header))
	for index, value := range header {
		headerIndex[value] = index
	}
	for value := range mapping {
		if _, exists := headerIndex[value]; !exists {
			return nil, 0, fmt.Errorf("mapping references unknown CSV header %q", value)
		}
	}

	columns := make([]csvImportColumn, 0, len(mapping))
	seenAttributes := make(map[string]string, len(mapping))
	rdnColumn := -1
	for index, value := range header {
		attribute, exists := mapping[value]
		if !exists {
			continue
		}
		if err := validateAttribute(attribute, false); err != nil {
			return nil, 0, fmt.Errorf("mapping for header %q: %w", value, err)
		}
		key := strings.ToLower(attribute)
		if key == "objectclass" {
			return nil, 0, errors.New("mapping must not target objectClass; use object_classes")
		}
		if previous, duplicate := seenAttributes[key]; duplicate {
			return nil, 0, fmt.Errorf("headers %q and %q map to the same LDAP attribute %q", previous, value, attribute)
		}
		seenAttributes[key] = value
		if strings.EqualFold(attribute, rdnAttribute) {
			rdnColumn = index
		}
		columns = append(columns, csvImportColumn{index: index, attribute: attribute})
	}
	if rdnColumn < 0 {
		return nil, 0, fmt.Errorf("rdn_attribute %q is not present in mapping", rdnAttribute)
	}
	return columns, rdnColumn, nil
}

func validateCSVImportObjectClasses(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("object_classes must contain at least one value")
	}
	if len(values) > maximumValuesPerAttribute {
		return nil, fmt.Errorf("object_classes exceeds the limit of %d values", maximumValuesPerAttribute)
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if err := validateCSVImportLDAPType(value, "object_classes value"); err != nil {
			return nil, err
		}
		key := strings.ToLower(value)
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("object_classes contains duplicate value %q", value)
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func validateCSVImportLDAPType(value, field string) error {
	if value == "" || len(value) > maximumAttributeLength ||
		(!attributeDescriptorPattern.MatchString(value) && !attributeOIDPattern.MatchString(value)) {
		return fmt.Errorf("%s contains invalid LDAP type %q", field, value)
	}
	return nil
}

func csvImportLDAPError(err error) apiError {
	failure, _ := ldapWriteFailure(err)
	return failure
}

func appendCSVNotAttempted(result *csvImportResponse, remaining []csvImportEntry) {
	for _, entry := range remaining {
		result.Results = append(result.Results, csvImportResult{
			Row: entry.row, DN: entry.dn, Status: "not_attempted",
		})
	}
}
