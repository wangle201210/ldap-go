package webadmin

import (
	"context"
	"errors"
	"net/http"
	"sync"

	ldap "github.com/go-ldap/ldap/v3"
)

type passwordVerifyRequest struct {
	UserIdentity string `json:"user_identity"`
	Password     string `json:"password"`
}

func (application *Application) handlePasswordVerify(response http.ResponseWriter, request *http.Request) {
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

	var input passwordVerifyRequest
	if err := application.decodeJSON(response, request, &input); err != nil {
		writeJSONRequestError(response, err)
		return
	}
	password := input.Password
	input.Password = ""
	defer func() { password = "" }()
	if err := validateDN(input.UserIdentity, false); err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{
			Code: "invalid_request", Message: "user_identity must be a valid DN: " + err.Error(),
		})
		return
	}
	if password == "" {
		writeAPIError(response, http.StatusBadRequest, apiError{
			Code: "invalid_request", Message: "password is required",
		})
		return
	}

	allowed, retryAfter := application.allowLogin(request)
	if !allowed {
		response.Header().Set("Retry-After", retryAfterSeconds(retryAfter))
		writeAPIError(response, http.StatusTooManyRequests, apiError{
			Code: "login_rate_limited", Message: "too many authentication attempts",
		})
		return
	}
	if authorized, err := passwordVerificationAuthorized(current, input.UserIdentity); err != nil {
		writeLDAPError(response, err)
		return
	} else if !authorized {
		writeAPIError(response, http.StatusForbidden, apiError{
			Code: "password_verification_forbidden", Message: "bound identity is not authorized to verify this user's password",
		})
		return
	}

	connectContext, cancelConnect := context.WithTimeout(request.Context(), application.config.DialTimeout)
	temporary, err := application.config.Connector.Connect(connectContext, ConnectConfig{
		URL:              application.config.LDAPURL,
		StartTLS:         application.config.StartTLS,
		TLSConfig:        cloneTLSConfig(application.config.TLSConfig),
		DialTimeout:      application.config.DialTimeout,
		OperationTimeout: application.config.OperationTimeout,
	})
	connectContextError := connectContext.Err()
	cancelConnect()
	var closeOnce sync.Once
	closeTemporary := func() {
		if temporary == nil {
			return
		}
		closeOnce.Do(func() {
			if err := temporary.Close(); err != nil {
				application.config.Logger.Printf("webadmin temporary LDAP connection close after password verification failed")
			}
		})
	}
	defer closeTemporary()
	if err != nil {
		closeTemporary()
		if connectContextError != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			if connectContextError == nil {
				connectContextError = err
			}
			writePasswordVerifyContextError(response, connectContextError, "LDAP connection")
			return
		}
		writeAPIError(response, http.StatusBadGateway, apiError{
			Code: "ldap_unavailable", Message: "LDAP server is unavailable",
		})
		return
	}
	if temporary == nil {
		writeAPIError(response, http.StatusBadGateway, apiError{
			Code: "ldap_unavailable", Message: "LDAP server is unavailable",
		})
		return
	}
	if connectContextError != nil {
		writePasswordVerifyContextError(response, connectContextError, "LDAP connection")
		return
	}

	operationContext, cancelOperation := context.WithTimeout(request.Context(), application.config.OperationTimeout)
	defer cancelOperation()
	if err := operationContext.Err(); err != nil {
		writePasswordVerifyContextError(response, err, "LDAP bind")
		return
	}

	completed := make(chan error, 1)
	go func(userIdentity, secret string) {
		defer func() {
			secret = ""
			if recover() != nil {
				application.panics.Add(1)
				application.config.Logger.Printf("webadmin panic during temporary LDAP password verification")
				completed <- errors.New("LDAP client panicked during password verification")
			}
		}()
		completed <- temporary.Bind(userIdentity, secret)
	}(input.UserIdentity, password)

	select {
	case err := <-completed:
		closeTemporary()
		if contextError := operationContext.Err(); contextError != nil {
			writePasswordVerifyContextError(response, contextError, "LDAP bind")
			return
		}
		if err == nil {
			writeJSON(response, http.StatusOK, map[string]bool{"verified": true})
			return
		}
		var ldapError *ldap.Error
		if errors.As(err, &ldapError) && ldapError.ResultCode == ldap.LDAPResultInvalidCredentials {
			writeJSON(response, http.StatusOK, map[string]bool{"verified": false})
			return
		}
		writeLDAPError(response, err)
	case <-operationContext.Done():
		closeTemporary()
		writePasswordVerifyContextError(response, operationContext.Err(), "LDAP bind")
	}
}

func passwordVerificationAuthorized(current *session, target string) (bool, error) {
	boundDN, boundErr := ldap.ParseDN(current.bindDN)
	targetDN, targetErr := ldap.ParseDN(target)
	if boundErr == nil && targetErr == nil && boundDN.EqualFold(targetDN) {
		return true, nil
	}
	for _, attribute := range []string{"userPassword", "authPassword"} {
		_, err := current.client.Compare(target, attribute, "ldap-go-password-verification-authorization-probe")
		if err == nil {
			return true, nil
		}
		var ldapError *ldap.Error
		if errors.As(err, &ldapError) {
			switch ldapError.ResultCode {
			case ldap.LDAPResultInsufficientAccessRights, ldap.LDAPResultNoSuchAttribute,
				ldap.LDAPResultUndefinedAttributeType, ldap.LDAPResultInappropriateMatching:
				continue
			}
		}
		return false, err
	}
	return false, nil
}

func writePasswordVerifyContextError(response http.ResponseWriter, err error, operation string) {
	if errors.Is(err, context.DeadlineExceeded) {
		writeAPIError(response, http.StatusGatewayTimeout, apiError{
			Code: "operation_deadline_exceeded", Message: operation + " exceeded the configured deadline",
		})
		return
	}
	writeAPIError(response, http.StatusRequestTimeout, apiError{
		Code: "request_canceled", Message: operation + " was canceled",
	})
}
