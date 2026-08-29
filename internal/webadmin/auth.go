package webadmin

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

type loginRequest struct {
	BindDN   string `json:"bind_dn"`
	DN       string `json:"dn"`
	Password string `json:"password"`
}

type sessionResponse struct {
	Authenticated bool      `json:"authenticated"`
	BindDN        string    `json:"bind_dn"`
	CSRFToken     string    `json:"csrf_token"`
	CreatedAt     time.Time `json:"created_at"`
	IdleExpiresAt time.Time `json:"idle_expires_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (application *Application) handleLogin(response http.ResponseWriter, request *http.Request) {
	if !methodAllowed(response, request, http.MethodPost) {
		return
	}
	if !application.requireMutationSecurity(response, request, nil) {
		return
	}
	if application.isClosed() {
		writeAPIError(response, http.StatusServiceUnavailable, apiError{
			Code: "application_closed", Message: "administration service is closed",
		})
		return
	}
	allowed, retryAfter := application.allowLogin(request)
	if !allowed {
		response.Header().Set("Retry-After", retryAfterSeconds(retryAfter))
		writeAPIError(response, http.StatusTooManyRequests, apiError{
			Code: "login_rate_limited", Message: "too many login attempts",
		})
		return
	}

	var input loginRequest
	if err := application.decodeJSON(response, request, &input); err != nil {
		writeJSONRequestError(response, err)
		return
	}
	password := input.Password
	input.Password = ""
	defer func() { password = "" }()
	if input.BindDN == "" {
		input.BindDN = input.DN
	}
	if input.BindDN == "" || password == "" {
		writeAPIError(response, http.StatusBadRequest, apiError{
			Code: "invalid_request", Message: "bind_dn and password are required",
		})
		return
	}

	application.pruneExpiredSessions(application.config.Clock())
	if !application.hasLoginCapacity(request) {
		writeAPIError(response, http.StatusServiceUnavailable, apiError{
			Code: "session_capacity_reached", Message: "session capacity reached",
		})
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), application.config.DialTimeout)
	defer cancel()
	client, err := application.config.Connector.Connect(ctx, ConnectConfig{
		URL:              application.config.LDAPURL,
		StartTLS:         application.config.StartTLS,
		TLSConfig:        cloneTLSConfig(application.config.TLSConfig),
		DialTimeout:      application.config.DialTimeout,
		OperationTimeout: application.config.OperationTimeout,
	})
	if err != nil {
		application.loginFailures.Add(1)
		writeAPIError(response, http.StatusBadGateway, apiError{
			Code: "ldap_unavailable", Message: "LDAP server is unavailable",
		})
		return
	}
	if err := client.Bind(input.BindDN, password); err != nil {
		application.loginFailures.Add(1)
		_ = client.Close()
		application.writeLoginFailure(response, err)
		return
	}

	token, tokenKey, err := application.newOpaqueToken()
	if err != nil {
		_ = client.Close()
		writeAPIError(response, http.StatusInternalServerError, apiError{
			Code: "session_creation_failed", Message: "unable to create session",
		})
		return
	}
	csrf, _, err := application.newOpaqueToken()
	if err != nil {
		_ = client.Close()
		writeAPIError(response, http.StatusInternalServerError, apiError{
			Code: "session_creation_failed", Message: "unable to create session",
		})
		return
	}

	now := application.config.Clock()
	current := &session{
		client: client, bindDN: input.BindDN, csrf: csrf,
		created: now, lastSeen: now,
	}
	oldKey, hasOldKey := application.sessionKey(request)
	var previous *session
	application.mu.Lock()
	if application.closed {
		application.mu.Unlock()
		_ = client.Close()
		writeAPIError(response, http.StatusServiceUnavailable, apiError{
			Code: "application_closed", Message: "administration service is closed",
		})
		return
	}
	if _, collision := application.sessions[tokenKey]; collision {
		application.mu.Unlock()
		_ = client.Close()
		writeAPIError(response, http.StatusInternalServerError, apiError{
			Code: "session_creation_failed", Message: "unable to create session",
		})
		return
	}
	if hasOldKey {
		previous = application.sessions[oldKey]
	}
	effectiveSessions := len(application.sessions)
	if previous != nil {
		effectiveSessions--
	}
	if effectiveSessions >= application.config.MaxSessions {
		application.mu.Unlock()
		_ = client.Close()
		writeAPIError(response, http.StatusServiceUnavailable, apiError{
			Code: "session_capacity_reached", Message: "session capacity reached",
		})
		return
	}
	if previous != nil {
		delete(application.sessions, oldKey)
	}
	application.sessions[tokenKey] = current
	application.mu.Unlock()
	if previous != nil {
		previous.mu.Lock()
		_ = previous.closeLocked()
		previous.mu.Unlock()
	}

	application.setSessionCookie(response, request, token, now)
	application.loginSuccesses.Add(1)
	writeJSON(response, http.StatusOK, application.sessionView(current))
}

func (application *Application) isClosed() bool {
	application.mu.Lock()
	defer application.mu.Unlock()
	return application.closed
}

func (application *Application) hasLoginCapacity(request *http.Request) bool {
	oldKey, hasOldKey := application.sessionKey(request)
	application.mu.Lock()
	defer application.mu.Unlock()
	count := len(application.sessions)
	if hasOldKey && application.sessions[oldKey] != nil {
		count--
	}
	return !application.closed && count < application.config.MaxSessions
}

func cloneTLSConfig(config *tls.Config) *tls.Config {
	if config == nil {
		return nil
	}
	return config.Clone()
}

func (application *Application) writeLoginFailure(response http.ResponseWriter, err error) {
	var ldapError *ldap.Error
	if errors.As(err, &ldapError) {
		code := ldapError.ResultCode
		writeAPIError(response, http.StatusUnauthorized, apiError{
			Code: "authentication_failed", Message: "authentication failed",
			LDAPResultCode: &code, LDAPResultName: ldap.LDAPResultCodeMap[code],
		})
		return
	}
	writeAPIError(response, http.StatusBadGateway, apiError{
		Code: "ldap_unavailable", Message: "LDAP server is unavailable",
	})
}

func (application *Application) handleLogout(response http.ResponseWriter, request *http.Request) {
	if !methodAllowed(response, request, http.MethodPost) {
		return
	}
	current, ok := application.acquireSession(response, request)
	if !ok {
		return
	}
	if !application.requireMutationSecurity(response, request, current) {
		application.releaseSession(current)
		return
	}
	key, _ := application.sessionKey(request)
	application.removeSession(key, current)
	closeErr := current.closeLocked()
	current.mu.Unlock()
	application.clearSessionCookie(response, request)
	if closeErr != nil {
		application.config.Logger.Printf("webadmin LDAP connection close after logout failed")
	}
	writeJSON(response, http.StatusOK, map[string]bool{"logged_out": true})
}

func (application *Application) handleSession(response http.ResponseWriter, request *http.Request) {
	if !methodAllowed(response, request, http.MethodGet) {
		return
	}
	current, ok := application.acquireSession(response, request)
	if !ok {
		return
	}
	view := application.sessionView(current)
	application.releaseSession(current)
	writeJSON(response, http.StatusOK, view)
}

func (application *Application) sessionView(current *session) sessionResponse {
	return sessionResponse{
		Authenticated: true,
		BindDN:        current.bindDN,
		CSRFToken:     current.csrf,
		CreatedAt:     current.created,
		IdleExpiresAt: current.lastSeen.Add(application.config.SessionIdleTimeout),
		ExpiresAt:     current.created.Add(application.config.SessionMaxLifetime),
	}
}
