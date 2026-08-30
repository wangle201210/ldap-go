package webadmin

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

type searchRequestBody struct {
	BaseDN     string   `json:"base_dn"`
	Scope      string   `json:"scope"`
	Filter     string   `json:"filter"`
	Attributes []string `json:"attributes"`
	SizeLimit  int      `json:"size_limit"`
	TimeLimit  int      `json:"time_limit_seconds"`
	TypesOnly  bool     `json:"types_only"`
	PageSize   int      `json:"page_size"`
	PageCookie string   `json:"page_cookie"`
}

type searchResponse struct {
	Entries    []entryResponse `json:"entries"`
	Referrals  []string        `json:"referrals,omitempty"`
	PageCookie string          `json:"page_cookie,omitempty"`
}

type addRequestBody struct {
	DN         string              `json:"dn"`
	Attributes map[string][]string `json:"attributes"`
}

type modifyRequestBody struct {
	DN      string         `json:"dn"`
	Changes []modifyChange `json:"changes"`
}

type modifyChange struct {
	Operation string   `json:"operation"`
	Attribute string   `json:"attribute"`
	Values    []string `json:"values"`
}

type deleteRequestBody struct {
	DN string `json:"dn"`
}

type renameRequestBody struct {
	DN           string `json:"dn"`
	NewRDN       string `json:"new_rdn"`
	DeleteOldRDN bool   `json:"delete_old_rdn"`
	NewSuperior  string `json:"new_superior,omitempty"`
}

type passwordModifyRequestBody struct {
	UserIdentity string `json:"user_identity,omitempty"`
	OldPassword  string `json:"old_password,omitempty"`
	NewPassword  string `json:"new_password,omitempty"`
}

func (application *Application) handleSearch(response http.ResponseWriter, request *http.Request) {
	if !methodAllowed(response, request, http.MethodGet, http.MethodPost) {
		return
	}
	current, ok := application.acquireSession(response, request)
	if !ok {
		return
	}
	defer application.releaseSession(current)
	input := searchRequestBody{}
	if request.Method == http.MethodGet {
		var err error
		input, err = searchRequestFromQuery(request)
		if err != nil {
			writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_search", Message: err.Error()})
			return
		}
	} else {
		if err := application.decodeJSON(response, request, &input); err != nil {
			writeJSONRequestError(response, err)
			return
		}
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
	if rejectIncompleteReferrals(response, result) {
		return
	}
	writeJSON(response, http.StatusOK, convertSearchResult(result))
}

func searchRequestFromQuery(request *http.Request) (searchRequestBody, error) {
	query := request.URL.Query()
	input := searchRequestBody{
		BaseDN: query.Get("base_dn"), Scope: query.Get("scope"),
		Filter: query.Get("filter"), PageCookie: query.Get("page_cookie"),
	}
	if input.BaseDN == "" {
		input.BaseDN = query.Get("base")
	}
	input.Attributes = append([]string(nil), query["attribute"]...)
	if len(input.Attributes) == 0 && query.Get("attributes") != "" {
		for _, attribute := range strings.Split(query.Get("attributes"), ",") {
			if trimmed := strings.TrimSpace(attribute); trimmed != "" {
				input.Attributes = append(input.Attributes, trimmed)
			}
		}
	}
	if input.Filter == "" {
		input.Filter = "(objectClass=*)"
	}
	var err error
	if input.SizeLimit, err = parseOptionalPositiveInteger(query.Get("size_limit")); err != nil {
		return searchRequestBody{}, errors.New("invalid size_limit")
	}
	if input.SizeLimit == 0 {
		input.SizeLimit, err = parseOptionalPositiveInteger(query.Get("limit"))
		if err != nil {
			return searchRequestBody{}, errors.New("invalid limit")
		}
	}
	if input.TimeLimit, err = parseOptionalPositiveInteger(query.Get("time_limit_seconds")); err != nil {
		return searchRequestBody{}, errors.New("invalid time_limit_seconds")
	}
	if input.PageSize, err = parseOptionalPositiveInteger(query.Get("page_size")); err != nil {
		return searchRequestBody{}, errors.New("invalid page_size")
	}
	if raw := query.Get("types_only"); raw != "" {
		input.TypesOnly, err = strconv.ParseBool(raw)
		if err != nil {
			return searchRequestBody{}, errors.New("invalid types_only")
		}
	}
	return input, nil
}

func parseOptionalPositiveInteger(value string) (int, error) {
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return 0, errors.New("value must be a positive integer")
	}
	return parsed, nil
}

func (application *Application) buildSearchRequest(input searchRequestBody) (*ldap.SearchRequest, error) {
	if err := validateDN(input.BaseDN, true); err != nil {
		return nil, err
	}
	scope, err := parseScope(input.Scope)
	if err != nil {
		return nil, err
	}
	if err := validateFilter(input.Filter, application.config); err != nil {
		return nil, err
	}
	if err := validateAttributes(input.Attributes, application.config.MaxAttributes, true); err != nil {
		return nil, err
	}
	if input.SizeLimit == 0 {
		input.SizeLimit = application.config.MaxSearchSize
	}
	if input.SizeLimit < 1 || input.SizeLimit > application.config.MaxSearchSize {
		return nil, errors.New("size_limit is outside the configured bounds")
	}
	if input.TimeLimit == 0 {
		input.TimeLimit = application.config.MaxSearchSeconds
	}
	if input.TimeLimit < 1 || input.TimeLimit > application.config.MaxSearchSeconds {
		return nil, errors.New("time_limit_seconds is outside the configured bounds")
	}
	request := ldap.NewSearchRequest(
		input.BaseDN, scope, ldap.NeverDerefAliases, input.SizeLimit, input.TimeLimit,
		input.TypesOnly, input.Filter, input.Attributes, nil,
	)
	request.EnforceSizeLimit = true
	if input.PageSize != 0 || input.PageCookie != "" {
		if input.PageSize < 1 || input.PageSize > input.SizeLimit {
			return nil, errors.New("page_size must be positive and no larger than size_limit")
		}
		cookie, err := decodePageCookie(input.PageCookie)
		if err != nil {
			return nil, err
		}
		paging := ldap.NewControlPaging(uint32(input.PageSize))
		paging.SetCookie(cookie)
		request.Controls = []ldap.Control{paging}
	}
	return request, nil
}

func parseScope(value string) (int, error) {
	switch strings.ToLower(value) {
	case "base":
		return ldap.ScopeBaseObject, nil
	case "one", "onelevel":
		return ldap.ScopeSingleLevel, nil
	case "sub", "subtree", "":
		return ldap.ScopeWholeSubtree, nil
	default:
		return 0, errors.New("scope must be base, one, or sub")
	}
}

func convertSearchResult(result *ldap.SearchResult) searchResponse {
	converted := searchResponse{
		Entries:   make([]entryResponse, 0, len(result.Entries)),
		Referrals: append([]string(nil), result.Referrals...),
	}
	for _, entry := range result.Entries {
		if entry != nil {
			converted.Entries = append(converted.Entries, convertEntry(entry))
		}
	}
	if control := ldap.FindControl(result.Controls, ldap.ControlTypePaging); control != nil {
		if paging, ok := control.(*ldap.ControlPaging); ok {
			converted.PageCookie = encodePageCookie(paging.Cookie)
		}
	}
	return converted
}

func (application *Application) handleEntries(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		application.handleGetEntry(response, request)
	case http.MethodPost:
		application.handleAddEntry(response, request)
	case http.MethodPatch:
		application.handleModifyEntry(response, request)
	case http.MethodDelete:
		application.handleDeleteEntry(response, request)
	default:
		methodAllowed(response, request, http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete)
	}
}

func (application *Application) handleGetEntry(response http.ResponseWriter, request *http.Request) {
	current, ok := application.acquireSession(response, request)
	if !ok {
		return
	}
	defer application.releaseSession(current)
	dn := request.URL.Query().Get("dn")
	if err := validateDN(dn, false); err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_dn", Message: err.Error()})
		return
	}
	attributes := request.URL.Query()["attribute"]
	if len(attributes) == 0 {
		attributes = []string{"*", "+"}
	}
	if err := validateAttributes(attributes, application.config.MaxAttributes, true); err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_attributes", Message: err.Error()})
		return
	}
	result, release, err := application.search(current.client, ldap.NewSearchRequest(
		dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
		application.config.MaxSearchSeconds, false, "(objectClass=*)", attributes, nil,
	))
	if err != nil {
		writeLDAPError(response, err)
		return
	}
	defer release()
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
	writeJSON(response, http.StatusOK, convertEntry(result.Entries[0]))
}

func (application *Application) handleAddEntry(response http.ResponseWriter, request *http.Request) {
	current, ok := application.acquireSession(response, request)
	if !ok {
		return
	}
	defer application.releaseSession(current)
	if !application.requireMutationSecurity(response, request, current) {
		return
	}
	var input addRequestBody
	if err := application.decodeJSON(response, request, &input); err != nil {
		writeJSONRequestError(response, err)
		return
	}
	if err := validateDN(input.DN, false); err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_dn", Message: err.Error()})
		return
	}
	if err := validateAttributeMap(input.Attributes, application.config.MaxAttributes); err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_attributes", Message: err.Error()})
		return
	}
	ldapRequest := ldap.NewAddRequest(input.DN, nil)
	for attribute, values := range input.Attributes {
		ldapRequest.Attribute(attribute, values)
	}
	if failure, status := application.executeLDAPWrite(request.Context(), current, func(client Client) error {
		return client.Add(ldapRequest)
	}); failure != nil {
		writeAPIError(response, status, *failure)
		return
	}
	writeJSON(response, http.StatusCreated, map[string]string{"dn": input.DN})
}

func (application *Application) handleModifyEntry(response http.ResponseWriter, request *http.Request) {
	current, ok := application.acquireSession(response, request)
	if !ok {
		return
	}
	defer application.releaseSession(current)
	if !application.requireMutationSecurity(response, request, current) {
		return
	}
	var input modifyRequestBody
	if err := application.decodeJSON(response, request, &input); err != nil {
		writeJSONRequestError(response, err)
		return
	}
	if err := validateDN(input.DN, false); err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_dn", Message: err.Error()})
		return
	}
	if len(input.Changes) == 0 || len(input.Changes) > application.config.MaxAttributes {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_changes", Message: "changes are empty or exceed the configured limit"})
		return
	}
	ldapRequest := ldap.NewModifyRequest(input.DN, nil)
	for _, change := range input.Changes {
		if err := validateAttribute(change.Attribute, false); err != nil || len(change.Values) > maximumValuesPerAttribute {
			message := "invalid modify attribute or value count"
			if err != nil {
				message = err.Error()
			}
			writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_changes", Message: message})
			return
		}
		switch strings.ToLower(change.Operation) {
		case "add":
			ldapRequest.Add(change.Attribute, change.Values)
		case "delete":
			ldapRequest.Delete(change.Attribute, change.Values)
		case "replace":
			ldapRequest.Replace(change.Attribute, change.Values)
		case "increment":
			if len(change.Values) != 1 {
				writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_changes", Message: "increment requires exactly one value"})
				return
			}
			ldapRequest.Increment(change.Attribute, change.Values[0])
		default:
			writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_changes", Message: "operation must be add, delete, replace, or increment"})
			return
		}
	}
	if failure, status := application.executeLDAPWrite(request.Context(), current, func(client Client) error {
		return client.Modify(ldapRequest)
	}); failure != nil {
		writeAPIError(response, status, *failure)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"dn": input.DN})
}

func (application *Application) handleDeleteEntry(response http.ResponseWriter, request *http.Request) {
	current, ok := application.acquireSession(response, request)
	if !ok {
		return
	}
	defer application.releaseSession(current)
	if !application.requireMutationSecurity(response, request, current) {
		return
	}
	dn := request.URL.Query().Get("dn")
	if dn == "" && request.Body != nil && request.ContentLength != 0 {
		var input deleteRequestBody
		if err := application.decodeJSON(response, request, &input); err != nil {
			writeJSONRequestError(response, err)
			return
		}
		dn = input.DN
	}
	if err := validateDN(dn, false); err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_dn", Message: err.Error()})
		return
	}
	ldapRequest := ldap.NewDelRequest(dn, nil)
	if failure, status := application.executeLDAPWrite(request.Context(), current, func(client Client) error {
		return client.Del(ldapRequest)
	}); failure != nil {
		writeAPIError(response, status, *failure)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"dn": dn})
}

func (application *Application) handleRename(response http.ResponseWriter, request *http.Request) {
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
	var input renameRequestBody
	if err := application.decodeJSON(response, request, &input); err != nil {
		writeJSONRequestError(response, err)
		return
	}
	if err := validateDN(input.DN, false); err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_dn", Message: err.Error()})
		return
	}
	if err := validateRDN(input.NewRDN); err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_rdn", Message: err.Error()})
		return
	}
	if input.NewSuperior != "" {
		if err := validateDN(input.NewSuperior, false); err != nil {
			writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_new_superior", Message: err.Error()})
			return
		}
	}
	ldapRequest := ldap.NewModifyDNRequest(
		input.DN, input.NewRDN, input.DeleteOldRDN, input.NewSuperior,
	)
	if failure, status := application.executeLDAPWrite(request.Context(), current, func(client Client) error {
		return client.ModifyDN(ldapRequest)
	}); failure != nil {
		writeAPIError(response, status, *failure)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"dn": input.DN})
}

func (application *Application) handlePasswordModify(response http.ResponseWriter, request *http.Request) {
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
	var input passwordModifyRequestBody
	if err := application.decodeJSON(response, request, &input); err != nil {
		writeJSONRequestError(response, err)
		return
	}
	defer func() {
		input.OldPassword = ""
		input.NewPassword = ""
	}()
	userIdentity := input.UserIdentity
	oldPassword := input.OldPassword
	newPassword := input.NewPassword
	var result *ldap.PasswordModifyResult
	failure, status := application.executeLDAPWrite(request.Context(), current, func(client Client) error {
		ldapRequest := ldap.NewPasswordModifyRequest(userIdentity, oldPassword, newPassword)
		var err error
		result, err = client.PasswordModify(ldapRequest)
		ldapRequest.OldPassword = ""
		ldapRequest.NewPassword = ""
		return err
	})
	if failure != nil {
		if failure.LDAPResultCode != nil && *failure.LDAPResultCode == ldap.LDAPResultInvalidCredentials {
			status = http.StatusUnprocessableEntity
		}
		writeAPIError(response, status, *failure)
		return
	}
	generated := ""
	if result != nil && result.GeneratedPassword != "" {
		generated = result.GeneratedPassword
	}
	writeJSON(response, http.StatusOK, map[string]string{
		"generated_password":        generated,
		"generated_password_base64": base64.StdEncoding.EncodeToString([]byte(generated)),
	})
}
