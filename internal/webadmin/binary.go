package webadmin

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

const (
	maximumBinaryAttributeValues = 32
	maximumBinaryValueBytes      = 1 << 20
	maximumBinaryTotalBytes      = 4 << 20
)

type binaryAttributeRequest struct {
	DN           string   `json:"dn"`
	Attribute    string   `json:"attribute"`
	ValuesBase64 []string `json:"values_base64"`
}

type binaryAttributeResponse struct {
	DN           string   `json:"dn"`
	Attribute    string   `json:"attribute"`
	ValuesBase64 []string `json:"values_base64"`
	SizesBytes   []int    `json:"sizes_bytes"`
	MIMETypes    []string `json:"mime_types"`
	TotalBytes   int      `json:"total_bytes"`
}

type binaryAttributeMutationResponse struct {
	DN         string `json:"dn"`
	Attribute  string `json:"attribute"`
	ValueCount int    `json:"value_count"`
	TotalBytes int    `json:"total_bytes"`
}

type binaryAttributeLimitError struct {
	message string
}

func (failure *binaryAttributeLimitError) Error() string {
	return failure.message
}

// handleBinaryAttribute reads or replaces one explicitly base64-encoded LDAP
// attribute. LDAP schema and ACL enforcement remain authoritative on the bound
// session because binary syntax cannot be inferred reliably from a name alone.
func (application *Application) handleBinaryAttribute(response http.ResponseWriter, request *http.Request) {
	if !methodAllowed(response, request, http.MethodGet, http.MethodPut, http.MethodDelete) {
		return
	}
	if !application.acquireBinaryOperation(response) {
		return
	}
	defer func() { <-application.operations }()

	current, ok := application.acquireSession(response, request)
	if !ok {
		return
	}
	defer application.releaseSession(current)

	switch request.Method {
	case http.MethodGet:
		application.getBinaryAttribute(response, request, current.client)
	case http.MethodPut:
		application.putBinaryAttribute(response, request, current)
	case http.MethodDelete:
		application.deleteBinaryAttribute(response, request, current)
	}
}

func (application *Application) acquireBinaryOperation(response http.ResponseWriter) bool {
	select {
	case application.operations <- struct{}{}:
		return true
	default:
		writeAPIError(response, http.StatusServiceUnavailable, apiError{
			Code:    "operation_capacity_reached",
			Message: "Web administration LDAP operation capacity reached",
		})
		return false
	}
}

func (application *Application) getBinaryAttribute(
	response http.ResponseWriter,
	request *http.Request,
	client Client,
) {
	dn, attribute, err := binaryAttributeQuery(request)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateBinaryDNAndAttribute(dn, attribute); err != nil {
		writeBinaryValidationError(response, err)
		return
	}

	ldapRequest := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		application.config.MaxSearchSeconds,
		false,
		"(objectClass=*)",
		[]string{attribute},
		nil,
	)
	ldapRequest.EnforceSizeLimit = true
	result, release, err := application.search(client, ldapRequest)
	if err != nil {
		writeLDAPError(response, err)
		return
	}
	defer release()
	if result == nil {
		writeAPIError(response, http.StatusBadGateway, apiError{
			Code: "invalid_ldap_response", Message: "LDAP server returned an invalid base search result",
		})
		return
	}
	if rejectIncompleteReferrals(response, result) {
		return
	}
	if len(result.Entries) == 0 {
		code := uint16(ldap.LDAPResultNoSuchObject)
		writeAPIError(response, http.StatusNotFound, apiError{
			Code: "ldap_error", Message: ldap.LDAPResultCodeMap[code],
			LDAPResultCode: &code, LDAPResultName: ldap.LDAPResultCodeMap[code],
		})
		return
	}
	if len(result.Entries) != 1 || result.Entries[0] == nil {
		writeAPIError(response, http.StatusBadGateway, apiError{
			Code: "invalid_ldap_response", Message: "LDAP server returned an invalid base search result",
		})
		return
	}

	values := findBinaryAttributeValues(result.Entries[0], attribute)
	output, err := encodeBinaryAttributeResponse(dn, attribute, values)
	if err != nil {
		writeAPIError(response, http.StatusRequestEntityTooLarge, apiError{
			Code: "binary_attribute_too_large", Message: err.Error(),
		})
		return
	}
	writeJSON(response, http.StatusOK, output)
}

func (application *Application) putBinaryAttribute(
	response http.ResponseWriter,
	request *http.Request,
	current *session,
) {
	if !application.requireMutationSecurity(response, request, current) {
		return
	}
	var input binaryAttributeRequest
	if err := application.decodeJSON(response, request, &input); err != nil {
		writeJSONRequestError(response, err)
		return
	}
	if err := validateBinaryDNAndAttribute(input.DN, input.Attribute); err != nil {
		writeBinaryValidationError(response, err)
		return
	}
	values, total, err := decodeBinaryValues(input.ValuesBase64)
	if err != nil {
		var limit *binaryAttributeLimitError
		if errors.As(err, &limit) {
			writeAPIError(response, http.StatusRequestEntityTooLarge, apiError{
				Code: "binary_attribute_too_large", Message: err.Error(),
			})
		} else {
			writeAPIError(response, http.StatusBadRequest, apiError{
				Code: "invalid_binary_values", Message: err.Error(),
			})
		}
		return
	}

	ldapRequest := ldap.NewModifyRequest(input.DN, nil)
	ldapRequest.Replace(input.Attribute, values)
	if err := current.client.Modify(ldapRequest); err != nil {
		writeLDAPError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, binaryAttributeMutationResponse{
		DN: input.DN, Attribute: input.Attribute, ValueCount: len(values), TotalBytes: total,
	})
}

func (application *Application) deleteBinaryAttribute(
	response http.ResponseWriter,
	request *http.Request,
	current *session,
) {
	if !application.requireMutationSecurity(response, request, current) {
		return
	}
	dn, attribute, err := binaryAttributeQuery(request)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_request", Message: err.Error()})
		return
	}
	if err := validateBinaryDNAndAttribute(dn, attribute); err != nil {
		writeBinaryValidationError(response, err)
		return
	}

	ldapRequest := ldap.NewModifyRequest(dn, nil)
	ldapRequest.Delete(attribute, nil)
	if err := current.client.Modify(ldapRequest); err != nil {
		writeLDAPError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, binaryAttributeMutationResponse{
		DN: dn, Attribute: attribute,
	})
}

func binaryAttributeQuery(request *http.Request) (string, string, error) {
	query := request.URL.Query()
	for key := range query {
		if key != "dn" && key != "attribute" {
			return "", "", fmt.Errorf("unexpected query parameter %q", key)
		}
	}
	dns, hasDN := query["dn"]
	attributes, hasAttribute := query["attribute"]
	if !hasDN || len(dns) != 1 || !hasAttribute || len(attributes) != 1 {
		return "", "", errors.New("exactly one dn and attribute query parameter is required")
	}
	return dns[0], attributes[0], nil
}

func validateBinaryDNAndAttribute(dn, attribute string) error {
	if err := validateDN(dn, false); err != nil {
		return fmt.Errorf("dn: %w", err)
	}
	if err := validateBinaryAttribute(attribute); err != nil {
		return fmt.Errorf("attribute: %w", err)
	}
	return nil
}

func validateBinaryAttribute(attribute string) error {
	if err := validateAttribute(attribute, false); err != nil {
		return err
	}
	parts := strings.Split(attribute, ";")
	if len(parts) == 1 {
		return nil
	}
	if len(parts) == 2 && strings.EqualFold(parts[1], "binary") {
		return nil
	}
	return errors.New("only the binary attribute option is allowed")
}

func writeBinaryValidationError(response http.ResponseWriter, err error) {
	code := "invalid_attribute"
	if strings.HasPrefix(err.Error(), "dn: ") {
		code = "invalid_dn"
	}
	writeAPIError(response, http.StatusBadRequest, apiError{Code: code, Message: err.Error()})
}

func decodeBinaryValues(encoded []string) ([]string, int, error) {
	if len(encoded) == 0 {
		return nil, 0, errors.New("values_base64 must contain at least one value")
	}
	if len(encoded) > maximumBinaryAttributeValues {
		return nil, 0, binaryLimitErrorf("values_base64 exceeds the limit of %d values", maximumBinaryAttributeValues)
	}

	values := make([]string, len(encoded))
	total := 0
	for index, current := range encoded {
		if len(current) > base64.StdEncoding.EncodedLen(maximumBinaryValueBytes) {
			return nil, 0, binaryLimitErrorf("values_base64[%d] exceeds %d decoded bytes", index, maximumBinaryValueBytes)
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(current)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != current {
			return nil, 0, fmt.Errorf("values_base64[%d] is not canonical standard base64", index)
		}
		if len(decoded) > maximumBinaryValueBytes {
			return nil, 0, binaryLimitErrorf("values_base64[%d] exceeds %d decoded bytes", index, maximumBinaryValueBytes)
		}
		if total > maximumBinaryTotalBytes-len(decoded) {
			return nil, 0, binaryLimitErrorf("values_base64 exceeds the total limit of %d decoded bytes", maximumBinaryTotalBytes)
		}
		total += len(decoded)
		values[index] = string(decoded)
	}
	return values, total, nil
}

func binaryLimitErrorf(format string, arguments ...any) error {
	return &binaryAttributeLimitError{message: fmt.Sprintf(format, arguments...)}
}

func findBinaryAttributeValues(entry *ldap.Entry, requested string) [][]byte {
	for _, attribute := range entry.Attributes {
		if attribute != nil && strings.EqualFold(attribute.Name, requested) {
			return rawLDAPAttributeValues(attribute)
		}
	}
	requestedBase := strings.Split(requested, ";")[0]
	for _, attribute := range entry.Attributes {
		if attribute == nil || validateBinaryAttribute(attribute.Name) != nil {
			continue
		}
		if strings.EqualFold(strings.Split(attribute.Name, ";")[0], requestedBase) {
			return rawLDAPAttributeValues(attribute)
		}
	}
	return [][]byte{}
}

func rawLDAPAttributeValues(attribute *ldap.EntryAttribute) [][]byte {
	if len(attribute.ByteValues) != 0 {
		return attribute.ByteValues
	}
	values := make([][]byte, len(attribute.Values))
	for index, value := range attribute.Values {
		values[index] = []byte(value)
	}
	return values
}

func encodeBinaryAttributeResponse(
	dn string,
	attribute string,
	values [][]byte,
) (binaryAttributeResponse, error) {
	output := binaryAttributeResponse{
		DN: dn, Attribute: attribute,
		ValuesBase64: make([]string, len(values)),
		SizesBytes:   make([]int, len(values)),
		MIMETypes:    make([]string, len(values)),
	}
	if len(values) > maximumBinaryAttributeValues {
		return binaryAttributeResponse{}, binaryLimitErrorf("attribute exceeds the limit of %d values", maximumBinaryAttributeValues)
	}
	for index, value := range values {
		if len(value) > maximumBinaryValueBytes {
			return binaryAttributeResponse{}, binaryLimitErrorf("attribute value %d exceeds %d bytes", index, maximumBinaryValueBytes)
		}
		if output.TotalBytes > maximumBinaryTotalBytes-len(value) {
			return binaryAttributeResponse{}, binaryLimitErrorf("attribute exceeds the total limit of %d bytes", maximumBinaryTotalBytes)
		}
		output.TotalBytes += len(value)
		output.ValuesBase64[index] = base64.StdEncoding.EncodeToString(value)
		output.SizesBytes[index] = len(value)
		output.MIMETypes[index] = http.DetectContentType(value)
	}
	return output, nil
}
