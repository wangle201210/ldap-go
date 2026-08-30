package webadmin

import (
	"net/http"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

var passwordHashSchemes = auth.PasswordHashSelectionSchemes()

type passwordSetHashRequest struct {
	UserIdentity string `json:"user_identity"`
	OldPassword  string `json:"old_password"`
	NewPassword  string `json:"new_password"`
	HashScheme   string `json:"hash_scheme"`
}

type passwordSetHashResponse struct {
	DN         string `json:"dn"`
	HashScheme string `json:"hash_scheme"`
}

func (application *Application) handlePasswordSetHash(response http.ResponseWriter, request *http.Request) {
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

	var input passwordSetHashRequest
	if err := application.decodeJSON(response, request, &input); err != nil {
		writeJSONRequestError(response, err)
		return
	}
	defer func() {
		input.OldPassword = ""
		input.NewPassword = ""
	}()

	if err := validateDN(input.UserIdentity, false); err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{
			Code: "invalid_dn", Message: err.Error(),
		})
		return
	}
	if len(input.NewPassword) == 0 {
		writeAPIError(response, http.StatusBadRequest, apiError{
			Code: "invalid_request", Message: "new_password is required",
		})
		return
	}
	if len(input.NewPassword) > ldapwire.PasswordHashSelectionMaxPasswordBytes {
		writeAPIError(response, http.StatusBadRequest, apiError{
			Code: "invalid_request", Message: "new_password exceeds the selected-hash input limit",
		})
		return
	}
	hashScheme, ok := passwordSetHashScheme(input.HashScheme)
	if !ok {
		code := "unsupported_hash_scheme"
		message := "hash_scheme is not supported"
		if strings.TrimSpace(input.HashScheme) == "" {
			code = "invalid_request"
			message = "hash_scheme is required"
		}
		writeAPIError(response, http.StatusBadRequest, apiError{Code: code, Message: message})
		return
	}
	supportedSchemes, err := application.passwordHashSchemesForClient(current.client)
	if err != nil {
		writeLDAPError(response, err)
		return
	}
	if !containsPasswordHashScheme(supportedSchemes, hashScheme) {
		writeAPIError(response, http.StatusUnprocessableEntity, apiError{
			Code:    "password_hash_target_unsupported",
			Message: "target LDAP server does not advertise the password hash selection control",
		})
		return
	}

	failure, status := application.executeLDAPWrite(request.Context(), current, func(client Client) error {
		ldapRequest := ldap.NewPasswordModifyRequest(
			input.UserIdentity,
			input.OldPassword,
			input.NewPassword,
		)
		defer func() {
			ldapRequest.OldPassword = ""
			ldapRequest.NewPassword = ""
		}()
		return client.PasswordModifyWithHashScheme(ldapRequest, hashScheme)
	})
	if failure != nil {
		if failure.LDAPResultCode != nil && *failure.LDAPResultCode == ldap.LDAPResultInvalidCredentials {
			status = http.StatusUnprocessableEntity
			failure.Code = "invalid_old_password"
			failure.Message = "old password is invalid"
		}
		writeAPIError(response, status, *failure)
		return
	}

	writeJSON(response, http.StatusOK, passwordSetHashResponse{
		DN: input.UserIdentity, HashScheme: hashScheme,
	})
}

func passwordSetHashScheme(value string) (string, bool) {
	return auth.NormalizePasswordHashSelectionScheme(value)
}

func (application *Application) passwordHashSchemesForClient(client Client) ([]string, error) {
	result, release, err := application.search(client, ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
		application.config.MaxSearchSeconds, false, "(objectClass=*)", []string{"supportedControl"}, nil,
	))
	if err != nil {
		return nil, err
	}
	defer release()
	if result == nil || len(result.Entries) != 1 || result.Entries[0] == nil {
		return []string{}, nil
	}
	for _, oid := range result.Entries[0].GetEqualFoldAttributeValues("supportedControl") {
		if strings.TrimSpace(oid) == ldapwire.PasswordHashSchemeControlOID {
			return append([]string(nil), passwordHashSchemes...), nil
		}
	}
	return []string{}, nil
}

func containsPasswordHashScheme(schemes []string, candidate string) bool {
	for _, scheme := range schemes {
		if scheme == candidate {
			return true
		}
	}
	return false
}
