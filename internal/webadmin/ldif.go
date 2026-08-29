package webadmin

import (
	"bytes"
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
	request.Body = http.MaxBytesReader(response, request.Body, application.config.RequestBodyLimit)
	data, err := io.ReadAll(request.Body)
	if err != nil {
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

	records, err := application.parseLDIFChanges(data)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_ldif", Message: err.Error()})
		return
	}
	applied := 0
	for _, record := range records {
		if err := applyLDIFRecord(current.client, record); err != nil {
			application.writeLDIFApplyError(response, err, applied)
			return
		}
		applied++
	}
	writeJSON(response, http.StatusOK, map[string]int{"applied": applied})
}

func (application *Application) parseLDIFChanges(data []byte) ([]*ldif.Entry, error) {
	if err := rejectWebLDIFExternalValues(data); err != nil {
		return nil, err
	}
	document := &ldif.LDIF{}
	records := make([]*ldif.Entry, 0)
	for record, err := range ldif.UnmarshalEntries(bytes.NewReader(data), document) {
		if err != nil {
			return nil, fmt.Errorf("parse LDIF: %w", err)
		}
		if record == nil {
			continue
		}
		if len(records) >= application.config.MaxImportChanges {
			return nil, fmt.Errorf("LDIF exceeds the limit of %d changes", application.config.MaxImportChanges)
		}
		if err := application.validateLDIFRecord(record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if len(records) == 0 {
		return nil, errors.New("LDIF contains no entries or changes")
	}
	return records, nil
}

func rejectWebLDIFExternalValues(data []byte) error {
	logicalLines := make([]string, 0)
	for _, raw := range bytes.Split(data, []byte{'\n'}) {
		line := strings.TrimSuffix(string(raw), "\r")
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && len(logicalLines) > 0 {
			logicalLines[len(logicalLines)-1] += line[1:]
			continue
		}
		logicalLines = append(logicalLines, line)
	}
	for _, line := range logicalLines {
		if line == "" || line[0] == '#' {
			continue
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

func (application *Application) validateLDIFRecord(record *ldif.Entry) error {
	switch {
	case record.Entry != nil:
		if err := validateDN(record.Entry.DN, false); err != nil {
			return err
		}
		if len(record.Entry.Attributes) == 0 || len(record.Entry.Attributes) > application.config.MaxAttributes {
			return errors.New("LDIF add entry has an invalid attribute count")
		}
		for _, attribute := range record.Entry.Attributes {
			if err := validateAttribute(attribute.Name, false); err != nil {
				return err
			}
			if len(attribute.Values) > maximumValuesPerAttribute {
				return errors.New("LDIF attribute has too many values")
			}
		}
	case record.Add != nil:
		if err := validateDN(record.Add.DN, false); err != nil {
			return err
		}
		if len(record.Add.Controls) != 0 || len(record.Add.Attributes) == 0 || len(record.Add.Attributes) > application.config.MaxAttributes {
			return errors.New("LDIF add has controls or an invalid attribute count")
		}
		for _, attribute := range record.Add.Attributes {
			if err := validateAttribute(attribute.Type, false); err != nil {
				return err
			}
			if len(attribute.Vals) > maximumValuesPerAttribute {
				return errors.New("LDIF attribute has too many values")
			}
		}
	case record.Del != nil:
		if len(record.Del.Controls) != 0 {
			return errors.New("LDIF controls are not accepted")
		}
		return validateDN(record.Del.DN, false)
	case record.Modify != nil:
		if err := validateDN(record.Modify.DN, false); err != nil {
			return err
		}
		if len(record.Modify.Controls) != 0 || len(record.Modify.Changes) == 0 || len(record.Modify.Changes) > application.config.MaxAttributes {
			return errors.New("LDIF modify has controls or an invalid change count")
		}
		for _, change := range record.Modify.Changes {
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

func applyLDIFRecord(client Client, record *ldif.Entry) error {
	switch {
	case record.Entry != nil:
		request := ldap.NewAddRequest(record.Entry.DN, nil)
		for _, attribute := range record.Entry.Attributes {
			request.Attribute(attribute.Name, attribute.Values)
		}
		return client.Add(request)
	case record.Add != nil:
		return client.Add(record.Add)
	case record.Del != nil:
		return client.Del(record.Del)
	case record.Modify != nil:
		return client.Modify(record.Modify)
	default:
		return errors.New("unsupported LDIF record")
	}
}

func (application *Application) writeLDIFApplyError(response http.ResponseWriter, err error, applied int) {
	var ldapError *ldap.Error
	if errors.As(err, &ldapError) {
		code := ldapError.ResultCode
		writeAPIError(response, ldapHTTPStatus(code), apiError{
			Code: "ldap_error", Message: ldap.LDAPResultCodeMap[code],
			LDAPResultCode: &code, LDAPResultName: ldap.LDAPResultCodeMap[code],
			MatchedDN: ldapError.MatchedDN, Applied: &applied,
		})
		return
	}
	writeAPIError(response, http.StatusBadGateway, apiError{
		Code: "ldap_transport_error", Message: "LDAP operation failed", Applied: &applied,
	})
}
