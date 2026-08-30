package webadmin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

type bulkRequestBody struct {
	Action          string         `json:"action"`
	DNs             []string       `json:"dns"`
	Changes         []modifyChange `json:"changes,omitempty"`
	ContinueOnError bool           `json:"continue_on_error,omitempty"`
}

type bulkResponse struct {
	Action      string       `json:"action"`
	Results     []bulkResult `json:"results"`
	Applied     int          `json:"applied"`
	Failed      int          `json:"failed"`
	Unknown     int          `json:"unknown"`
	Aborted     bool         `json:"aborted,omitempty"`
	AbortReason string       `json:"abort_reason,omitempty"`
}

type bulkResult struct {
	DN      string    `json:"dn"`
	Success bool      `json:"success"`
	Status  string    `json:"status"`
	Error   *apiError `json:"error,omitempty"`
}

type validatedBulkDN struct {
	value string
	depth int
}

var errBatchApplicationClosed = errors.New("administration service closed before batch write started")

func (application *Application) handleBulk(response http.ResponseWriter, request *http.Request) {
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

	var input bulkRequestBody
	if err := application.decodeJSON(response, request, &input); err != nil {
		writeJSONRequestError(response, err)
		return
	}
	action := strings.ToLower(input.Action)
	if action != "modify" && action != "delete" {
		writeAPIError(response, http.StatusBadRequest, apiError{
			Code: "invalid_action", Message: "action must be modify or delete",
		})
		return
	}
	dns, err := application.validateBulkDNs(input.DNs)
	if err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{
			Code: "invalid_dns", Message: err.Error(),
		})
		return
	}
	if action == "modify" {
		if err := application.validateBulkChanges(input.Changes); err != nil {
			writeAPIError(response, http.StatusBadRequest, apiError{
				Code: "invalid_changes", Message: err.Error(),
			})
			return
		}
	} else if len(input.Changes) != 0 {
		writeAPIError(response, http.StatusBadRequest, apiError{
			Code: "invalid_changes", Message: "changes are only valid for the modify action",
		})
		return
	}

	if action == "delete" {
		sort.SliceStable(dns, func(left, right int) bool {
			return dns[left].depth > dns[right].depth
		})
	}

	result := bulkResponse{
		Action: action, Results: make([]bulkResult, 0, len(dns)),
	}
	batchContext, cancel := context.WithTimeout(request.Context(), application.config.OperationTimeout)
	defer cancel()
	for index, dn := range dns {
		if reason := batchAbortReason(batchContext); reason != "" {
			result.Aborted = true
			result.AbortReason = reason
			appendBulkNotAttempted(&result, dns[index:])
			break
		}
		err, interrupted := executeBatchWrite(batchContext, application, current, func(client Client) error {
			return applyBulkOperation(client, action, dn.value, input.Changes)
		})
		if errors.Is(err, errBatchApplicationClosed) {
			result.Aborted = true
			result.AbortReason = "administration service is closing"
			appendBulkNotAttempted(&result, dns[index:])
			break
		}
		if interrupted {
			result.Unknown++
			result.Aborted = true
			result.AbortReason = batchAbortReason(batchContext)
			failure := apiError{Code: "ldap_result_unknown", Message: "LDAP write result is unknown because the batch was canceled during the operation"}
			result.Results = append(result.Results, bulkResult{DN: dn.value, Status: "unknown", Error: &failure})
			appendBulkNotAttempted(&result, dns[index+1:])
			break
		}
		if err == nil {
			result.Applied++
			result.Results = append(result.Results, bulkResult{
				DN: dn.value, Success: true, Status: "applied",
			})
			continue
		}

		failure, unknown := ldapWriteFailure(err)
		if unknown {
			application.scheduleSessionClose(current, nil)
			result.Unknown++
			result.Results = append(result.Results, bulkResult{
				DN: dn.value, Status: "unknown", Error: &failure,
			})
			appendBulkNotAttempted(&result, dns[index+1:])
			break
		}
		result.Failed++
		result.Results = append(result.Results, bulkResult{
			DN: dn.value, Status: "failed", Error: &failure,
		})
		if input.ContinueOnError {
			continue
		}
		appendBulkNotAttempted(&result, dns[index+1:])
		break
	}
	writeJSON(response, http.StatusOK, result)
}

func (application *Application) validateBulkDNs(values []string) ([]validatedBulkDN, error) {
	if len(values) == 0 {
		return nil, errors.New("dns must contain at least one DN")
	}
	if len(values) > application.config.MaxImportChanges {
		return nil, fmt.Errorf("dns exceeds the limit of %d entries", application.config.MaxImportChanges)
	}

	result := make([]validatedBulkDN, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	folded := make(map[string]string, len(values))
	for index, value := range values {
		parsed, err := ldap.ParseDN(value)
		if err != nil || len(parsed.RDNs) == 0 {
			if value == "" {
				return nil, fmt.Errorf("dns[%d]: DN is required", index)
			}
			if err == nil {
				err = errors.New("empty DN is not allowed")
			}
			return nil, fmt.Errorf("dns[%d]: invalid DN: %w", index, err)
		}
		key := parsed.String()
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		foldedKey := strings.ToLower(key)
		if previous, ambiguous := folded[foldedKey]; ambiguous && previous != key {
			return nil, fmt.Errorf("dns[%d]: DN differs from %q only by case; submit case-sensitive naming values in separate batches", index, previous)
		}
		seen[key] = struct{}{}
		folded[foldedKey] = key
		result = append(result, validatedBulkDN{value: value, depth: len(parsed.RDNs)})
	}
	return result, nil
}

func (application *Application) validateBulkChanges(changes []modifyChange) error {
	if len(changes) == 0 || len(changes) > application.config.MaxAttributes {
		return errors.New("changes are empty or exceed the configured limit")
	}
	for _, change := range changes {
		if err := validateAttribute(change.Attribute, false); err != nil {
			return err
		}
		if len(change.Values) > maximumValuesPerAttribute {
			return errors.New("invalid modify attribute or value count")
		}
		switch strings.ToLower(change.Operation) {
		case "add", "delete", "replace":
		case "increment":
			if len(change.Values) != 1 {
				return errors.New("increment requires exactly one value")
			}
		default:
			return errors.New("operation must be add, delete, replace, or increment")
		}
	}
	return nil
}

func applyBulkOperation(client Client, action, dn string, changes []modifyChange) error {
	if action == "delete" {
		return client.Del(ldap.NewDelRequest(dn, nil))
	}
	request := ldap.NewModifyRequest(dn, nil)
	for _, change := range changes {
		switch strings.ToLower(change.Operation) {
		case "add":
			request.Add(change.Attribute, change.Values)
		case "delete":
			request.Delete(change.Attribute, change.Values)
		case "replace":
			request.Replace(change.Attribute, change.Values)
		case "increment":
			request.Increment(change.Attribute, change.Values[0])
		}
	}
	return client.Modify(request)
}

func executeBatchWrite(ctx context.Context, application *Application, current *session, operation func(Client) error) (error, bool) {
	application.batchTaskMu.Lock()
	application.mu.Lock()
	closed := application.closed
	if !closed {
		application.batchOperations.Add(1)
	}
	application.mu.Unlock()
	application.batchTaskMu.Unlock()
	if closed {
		return errBatchApplicationClosed, false
	}
	completed := make(chan error, 1)
	go func() {
		defer application.batchOperations.Done()
		defer func() {
			if recover() != nil {
				application.panics.Add(1)
				application.config.Logger.Printf("webadmin panic during batch LDAP write")
				completed <- errors.New("LDAP client panicked during batch write")
			}
		}()
		completed <- operation(current.client)
	}()
	select {
	case err := <-completed:
		return err, false
	case <-ctx.Done():
		application.scheduleSessionClose(current, completed)
		return ctx.Err(), true
	}
}

func bulkLDAPError(err error) apiError {
	failure, _ := ldapWriteFailure(err)
	return failure
}

func ldapWriteFailure(err error) (apiError, bool) {
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		return apiError{Code: "ldap_result_unknown", Message: "LDAP write result is unknown after a transport failure"}, true
	}
	code := ldapError.ResultCode
	if code == ldap.ErrorNetwork || (code >= ldap.LDAPResultServerDown && code <= ldap.LDAPResultReferralLimitExceeded) || code >= 200 {
		return apiError{Code: "ldap_result_unknown", Message: "LDAP write result is unknown after a client or transport failure"}, true
	}
	message := ldap.LDAPResultCodeMap[code]
	if message == "" {
		message = "LDAP operation failed"
	}
	return apiError{
		Code: "ldap_error", Message: message, LDAPResultCode: &code,
		LDAPResultName: ldap.LDAPResultCodeMap[code], MatchedDN: ldapError.MatchedDN,
	}, false
}

func batchAbortReason(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "batch operation deadline exceeded"
	}
	if ctx.Err() != nil {
		return "batch operation canceled"
	}
	return ""
}

func appendBulkNotAttempted(result *bulkResponse, remaining []validatedBulkDN) {
	for _, item := range remaining {
		result.Results = append(result.Results, bulkResult{DN: item.value, Status: "not_attempted"})
	}
}
