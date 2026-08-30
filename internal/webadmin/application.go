package webadmin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

type Application struct {
	config  normalizedConfig
	handler http.Handler

	mu              sync.Mutex
	sessions        map[[sha256.Size]byte]*session
	rates           map[string]loginRate
	closed          bool
	sweepStop       chan struct{}
	sweepDone       chan struct{}
	readiness       chan struct{}
	requests        atomic.Uint64
	loginSuccesses  atomic.Uint64
	loginFailures   atomic.Uint64
	panics          atomic.Uint64
	operations      chan struct{}
	responseBytes   atomic.Int64
	responseRejects atomic.Uint64
	closeOnce       sync.Once
	closeDone       chan struct{}
	closeErr        error
	closeTaskMu     sync.Mutex
	closeTasks      sync.WaitGroup
	batchTaskMu     sync.Mutex
	batchOperations sync.WaitGroup
	closingSessions int
	asyncCloseErrs  []error
}

type session struct {
	mu        sync.Mutex
	client    Client
	bindDN    string
	csrf      string
	created   time.Time
	lastSeen  time.Time
	closed    bool
	closeOnce sync.Once
	closeErr  error
	asyncOnce sync.Once
}

type loginRate struct {
	window time.Time
	count  int
}

type apiErrorBody struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code           string  `json:"code"`
	Message        string  `json:"message"`
	LDAPResultCode *uint16 `json:"ldap_result_code,omitempty"`
	LDAPResultName string  `json:"ldap_result_name,omitempty"`
	MatchedDN      string  `json:"matched_dn,omitempty"`
	Applied        *int    `json:"applied,omitempty"`
}

func New(input Config) (*Application, error) {
	config, err := normalizeConfig(input)
	if err != nil {
		return nil, err
	}
	if err := validatePositiveConfig(config); err != nil {
		return nil, err
	}
	application := &Application{
		config:     config,
		sessions:   make(map[[sha256.Size]byte]*session),
		rates:      make(map[string]loginRate),
		sweepStop:  make(chan struct{}),
		sweepDone:  make(chan struct{}),
		readiness:  make(chan struct{}, 1),
		closeDone:  make(chan struct{}),
		operations: make(chan struct{}, config.MaxConcurrentOperations),
	}
	application.handler = application.routes()
	go application.sweepSessions()
	return application, nil
}

func (application *Application) Handler() http.Handler {
	return application.handler
}

func (application *Application) Close() error {
	return application.CloseContext(context.Background())
}

func (application *Application) CloseContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("web administration close context is required")
	}
	application.closeOnce.Do(func() {
		application.batchTaskMu.Lock()
		application.mu.Lock()
		application.closed = true
		close(application.sweepStop)
		sessions := make([]*session, 0, len(application.sessions))
		for _, current := range application.sessions {
			sessions = append(sessions, current)
		}
		clear(application.sessions)
		clear(application.rates)
		application.mu.Unlock()
		application.batchTaskMu.Unlock()

		go func() {
			var closeErrors []error
			for _, current := range sessions {
				if err := application.safeForceClose(current); err != nil {
					closeErrors = append(closeErrors, err)
				}
			}
			<-application.sweepDone
			application.closeTaskMu.Lock()
			application.closeTaskMu.Unlock()
			application.closeTasks.Wait()
			application.batchOperations.Wait()
			application.mu.Lock()
			closeErrors = append(closeErrors, application.asyncCloseErrs...)
			application.mu.Unlock()
			for _, current := range sessions {
				current.mu.Lock()
				current.closed = true
				current.mu.Unlock()
			}
			application.closeErr = errors.Join(closeErrors...)
			close(application.closeDone)
		}()
	})
	select {
	case <-application.closeDone:
		return application.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (application *Application) sweepSessions() {
	ticker := time.NewTicker(application.config.SessionSweepInterval)
	defer func() {
		ticker.Stop()
		close(application.sweepDone)
	}()
	for {
		select {
		case <-ticker.C:
			application.pruneExpiredSessions(application.config.Clock())
		case <-application.sweepStop:
			return
		}
	}
}

func (application *Application) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", application.handleLogin)
	mux.HandleFunc("/api/logout", application.handleLogout)
	mux.HandleFunc("/api/session", application.handleSession)
	mux.HandleFunc("/api/capabilities", application.handleCapabilities)
	mux.HandleFunc("/api/root-dse", application.handleRootDSE)
	mux.HandleFunc("/api/root", application.handleRootDSE)
	mux.HandleFunc("/api/search", application.handleSearch)
	mux.HandleFunc("/api/entries", application.handleEntries)
	mux.HandleFunc("/api/entry", application.handleEntries)
	mux.HandleFunc("/api/entries/rename", application.handleRename)
	mux.HandleFunc("/api/rename", application.handleRename)
	mux.HandleFunc("/api/password-modify", application.handlePasswordModify)
	mux.HandleFunc("/api/password", application.handlePasswordModify)
	mux.HandleFunc("/api/password-verify", application.handlePasswordVerify)
	mux.HandleFunc("/api/password-set-hash", application.handlePasswordSetHash)
	mux.HandleFunc("/api/schema", application.handleSchema)
	mux.HandleFunc("/api/monitor", application.handleMonitor)
	mux.HandleFunc("/api/export", application.handleExport)
	mux.HandleFunc("/api/data-export", application.handleDataExport)
	mux.HandleFunc("/api/import", application.handleImport)
	mux.HandleFunc("/api/bulk", application.handleBulk)
	mux.HandleFunc("/api/groups", application.handleGroups)
	mux.HandleFunc("/api/binary", application.handleBinaryAttribute)
	mux.HandleFunc("/api/csv-import", application.handleCSVImport)
	mux.HandleFunc("/livez", application.handleLiveness)
	mux.HandleFunc("/readyz", application.handleReadiness)
	mux.HandleFunc("/metrics", application.handleMetrics)
	mux.Handle("/", application.staticHandler())
	return application.securityHeaders(
		application.recoverPanics(application.admitLDAPOperations(mux)),
	)
}

func (application *Application) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		application.requests.Add(1)
		headers := response.Header()
		headers.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' blob:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
		headers.Set("Cross-Origin-Opener-Policy", "same-origin")
		headers.Set("Cross-Origin-Resource-Policy", "same-origin")
		headers.Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		headers.Set("Referrer-Policy", "no-referrer")
		headers.Set("X-Content-Type-Options", "nosniff")
		headers.Set("X-Frame-Options", "DENY")
		headers.Set("X-Permitted-Cross-Domain-Policies", "none")
		if strings.HasPrefix(request.URL.Path, "/api/") ||
			request.URL.Path == "/livez" || request.URL.Path == "/readyz" ||
			request.URL.Path == "/metrics" {
			headers.Set("Cache-Control", "no-store")
		}
		if request.TLS != nil || application.externalHTTPS() {
			headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if application.config.externalURL != nil &&
			!equalHTTPHost(request.Host, application.config.externalURL.Host, application.config.externalURL.Scheme) {
			writeAPIError(response, http.StatusMisdirectedRequest, apiError{
				Code: "invalid_host", Message: "request Host does not match the configured Web origin",
			})
			return
		}
		next.ServeHTTP(response, request)
	})
}

func (application *Application) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				application.panics.Add(1)
				application.config.Logger.Printf("webadmin panic on %s %s", request.Method, request.URL.Path)
				writeAPIError(response, http.StatusInternalServerError, apiError{
					Code: "internal_error", Message: "internal server error",
				})
			}
		}()
		next.ServeHTTP(response, request)
	})
}

func (current *session) closeLocked() error {
	if current.closed {
		return nil
	}
	current.closed = true
	current.csrf = ""
	return current.forceClose()
}

func (current *session) forceClose() error {
	current.closeOnce.Do(func() {
		if current.client != nil {
			current.closeErr = current.client.Close()
		}
	})
	return current.closeErr
}

func (application *Application) safeForceClose(current *session) (err error) {
	defer func() {
		if recover() != nil {
			application.panics.Add(1)
			application.config.Logger.Printf("webadmin panic while closing LDAP client")
			err = errors.New("LDAP client panicked while closing")
		}
	}()
	return current.forceClose()
}

func (application *Application) scheduleSessionClose(current *session, operationDone <-chan error) {
	current.closed = true
	current.asyncOnce.Do(func() {
		application.closeTaskMu.Lock()
		application.mu.Lock()
		if application.closed {
			application.mu.Unlock()
			application.closeTaskMu.Unlock()
			return
		}
		for key, candidate := range application.sessions {
			if candidate == current {
				delete(application.sessions, key)
				break
			}
		}
		application.closingSessions++
		application.closeTasks.Add(1)
		application.mu.Unlock()
		application.closeTaskMu.Unlock()

		go func() {
			err := application.safeForceClose(current)
			if operationDone != nil {
				<-operationDone
			}
			application.mu.Lock()
			application.closingSessions--
			if err != nil && len(application.asyncCloseErrs) < application.config.MaxSessions {
				application.asyncCloseErrs = append(application.asyncCloseErrs, err)
			}
			application.mu.Unlock()
			application.closeTasks.Done()
		}()
	})
}

func (application *Application) acquireSession(
	response http.ResponseWriter,
	request *http.Request,
) (*session, bool) {
	key, ok := application.sessionKey(request)
	if !ok {
		writeAPIError(response, http.StatusUnauthorized, apiError{
			Code: "authentication_required", Message: "authentication required",
		})
		return nil, false
	}
	application.mu.Lock()
	current := application.sessions[key]
	application.mu.Unlock()
	if current == nil {
		application.clearSessionCookie(response, request)
		writeAPIError(response, http.StatusUnauthorized, apiError{
			Code: "authentication_required", Message: "authentication required",
		})
		return nil, false
	}

	if !current.mu.TryLock() {
		response.Header().Set("Retry-After", "1")
		writeAPIError(response, http.StatusConflict, apiError{
			Code: "session_busy", Message: "another LDAP operation is active in this session",
		})
		return nil, false
	}
	application.mu.Lock()
	stillCurrent := application.sessions[key] == current && !application.closed
	application.mu.Unlock()
	if !stillCurrent {
		current.mu.Unlock()
		application.clearSessionCookie(response, request)
		writeAPIError(response, http.StatusUnauthorized, apiError{
			Code: "authentication_required", Message: "authentication required",
		})
		return nil, false
	}
	now := application.config.Clock()
	if current.closed || sessionExpired(current, now, application.config) {
		_ = current.closeLocked()
		current.mu.Unlock()
		application.removeSession(key, current)
		application.clearSessionCookie(response, request)
		writeAPIError(response, http.StatusUnauthorized, apiError{
			Code: "session_expired", Message: "session expired",
		})
		return nil, false
	}
	current.lastSeen = now
	return current, true
}

func sessionExpired(current *session, now time.Time, config normalizedConfig) bool {
	return !now.Before(current.lastSeen.Add(config.SessionIdleTimeout)) ||
		!now.Before(current.created.Add(config.SessionMaxLifetime))
}

func (application *Application) releaseSession(current *session) {
	if !current.closed {
		current.lastSeen = application.config.Clock()
	}
	current.mu.Unlock()
}

func (application *Application) removeSession(key [sha256.Size]byte, expected *session) {
	application.mu.Lock()
	if application.sessions[key] == expected {
		delete(application.sessions, key)
	}
	application.mu.Unlock()
}

func (application *Application) sessionKey(request *http.Request) ([sha256.Size]byte, bool) {
	var empty [sha256.Size]byte
	cookie, err := request.Cookie(application.config.CookieName)
	if err != nil {
		return empty, false
	}
	token, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(token) != sha256.Size {
		return empty, false
	}
	return sha256.Sum256(token), true
}

func (application *Application) newOpaqueToken() (string, [sha256.Size]byte, error) {
	var raw [sha256.Size]byte
	if _, err := io.ReadFull(application.config.Random, raw[:]); err != nil {
		return "", [sha256.Size]byte{}, fmt.Errorf("generate secure token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), sha256.Sum256(raw[:]), nil
}

func (application *Application) setSessionCookie(
	response http.ResponseWriter,
	request *http.Request,
	token string,
	created time.Time,
) {
	http.SetCookie(response, &http.Cookie{
		Name:     application.config.CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   request.TLS != nil || application.externalHTTPS(),
		SameSite: http.SameSiteStrictMode,
		Expires:  created.Add(application.config.SessionMaxLifetime),
		MaxAge:   int(application.config.SessionMaxLifetime / time.Second),
	})
}

func (application *Application) clearSessionCookie(response http.ResponseWriter, request *http.Request) {
	http.SetCookie(response, &http.Cookie{
		Name:     application.config.CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   request.TLS != nil || application.externalHTTPS(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
}

func (application *Application) checkOrigin(request *http.Request) error {
	origin := request.Header.Get("Origin")
	if origin == "" {
		origin = request.Header.Get("Referer")
	}
	if origin == "" || origin == "null" {
		return errors.New("missing request origin")
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return errors.New("invalid request origin")
	}
	expectedHost := request.Host
	expectedScheme := "http"
	if request.TLS != nil {
		expectedScheme = "https"
	}
	if application.config.externalURL != nil {
		expectedHost = application.config.externalURL.Host
		expectedScheme = application.config.externalURL.Scheme
	}
	if !equalHTTPHost(parsed.Host, expectedHost, parsed.Scheme) {
		return errors.New("request origin does not match Host")
	}
	if parsed.Scheme != expectedScheme {
		return errors.New("request origin scheme does not match transport")
	}
	return nil
}

func (application *Application) externalHTTPS() bool {
	return application.config.externalURL != nil &&
		application.config.externalURL.Scheme == "https"
}

func equalHTTPHost(left, right, scheme string) bool {
	normalize := func(value string) string {
		value = strings.ToLower(strings.TrimSuffix(value, "."))
		host, port, err := net.SplitHostPort(value)
		if err == nil {
			if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
				return strings.TrimSuffix(host, ".")
			}
		}
		return value
	}
	return normalize(left) == normalize(right)
}

func (application *Application) requireMutationSecurity(
	response http.ResponseWriter,
	request *http.Request,
	current *session,
) bool {
	if err := application.checkOrigin(request); err != nil {
		writeAPIError(response, http.StatusForbidden, apiError{
			Code: "invalid_origin", Message: err.Error(),
		})
		return false
	}
	if current == nil {
		return true
	}
	provided := request.Header.Get("X-CSRF-Token")
	if provided == "" || len(provided) != len(current.csrf) ||
		subtle.ConstantTimeCompare([]byte(provided), []byte(current.csrf)) != 1 {
		writeAPIError(response, http.StatusForbidden, apiError{
			Code: "invalid_csrf_token", Message: "invalid CSRF token",
		})
		return false
	}
	return true
}

func (application *Application) allowLogin(request *http.Request) (bool, time.Duration) {
	now := application.config.Clock()
	client := request.RemoteAddr
	if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		client = host
	}
	if client == "" {
		client = "unknown"
	}

	application.mu.Lock()
	defer application.mu.Unlock()
	if application.closed {
		return false, application.config.LoginRateWindow
	}
	entry, exists := application.rates[client]
	if !exists && len(application.rates) >= application.config.LoginRateMaxClients {
		for key, candidate := range application.rates {
			if !now.Before(candidate.window.Add(application.config.LoginRateWindow)) {
				delete(application.rates, key)
			}
		}
		if len(application.rates) >= application.config.LoginRateMaxClients {
			return false, application.config.LoginRateWindow
		}
	}
	if !exists || !now.Before(entry.window.Add(application.config.LoginRateWindow)) {
		entry = loginRate{window: now}
	}
	if entry.count >= application.config.LoginRateLimit {
		return false, entry.window.Add(application.config.LoginRateWindow).Sub(now)
	}
	entry.count++
	application.rates[client] = entry
	return true, 0
}

func (application *Application) pruneExpiredSessions(now time.Time) {
	application.mu.Lock()
	snapshot := make(map[[sha256.Size]byte]*session, len(application.sessions))
	for key, current := range application.sessions {
		snapshot[key] = current
	}
	application.mu.Unlock()

	for key, current := range snapshot {
		if !current.mu.TryLock() {
			continue
		}
		if !current.closed && !sessionExpired(current, now, application.config) {
			current.mu.Unlock()
			continue
		}
		_ = current.closeLocked()
		current.mu.Unlock()
		application.removeSession(key, current)
	}
}

func methodAllowed(response http.ResponseWriter, request *http.Request, allowed ...string) bool {
	for _, method := range allowed {
		if request.Method == method {
			return true
		}
	}
	response.Header().Set("Allow", strings.Join(allowed, ", "))
	writeAPIError(response, http.StatusMethodNotAllowed, apiError{
		Code: "method_not_allowed", Message: "method not allowed",
	})
	return false
}

func (application *Application) decodeJSON(
	response http.ResponseWriter,
	request *http.Request,
	destination any,
) error {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]))
	if mediaType != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	request.Body = http.MaxBytesReader(response, request.Body, application.config.RequestBodyLimit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain one JSON value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func writeJSONRequestError(response http.ResponseWriter, err error) {
	var maximumError *http.MaxBytesError
	if errors.As(err, &maximumError) {
		writeAPIError(response, http.StatusRequestEntityTooLarge, apiError{
			Code: "request_body_too_large", Message: "request body exceeds the configured limit",
		})
		return
	}
	writeAPIError(response, http.StatusBadRequest, apiError{
		Code: "invalid_request", Message: err.Error(),
	})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeAPIError(response http.ResponseWriter, status int, failure apiError) {
	writeJSON(response, status, apiErrorBody{Error: failure})
}

func writeLDAPError(response http.ResponseWriter, err error) {
	if writeLDAPResponseLimitError(response, err) {
		return
	}
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		writeAPIError(response, http.StatusBadGateway, apiError{
			Code: "ldap_transport_error", Message: "LDAP operation failed",
		})
		return
	}
	code := ldapError.ResultCode
	status := ldapHTTPStatus(code)
	message := ldap.LDAPResultCodeMap[code]
	if message == "" {
		message = "LDAP operation failed"
	}
	writeAPIError(response, status, apiError{
		Code: "ldap_error", Message: message, LDAPResultCode: &code,
		LDAPResultName: ldap.LDAPResultCodeMap[code], MatchedDN: ldapError.MatchedDN,
	})
}

func (application *Application) executeLDAPWrite(
	ctx context.Context,
	current *session,
	operation func(Client) error,
) (*apiError, int) {
	operationContext, cancel := context.WithTimeout(ctx, application.config.OperationTimeout)
	defer cancel()
	if err := operationContext.Err(); err != nil {
		failure := apiError{Code: "request_canceled", Message: "LDAP write was canceled before it started"}
		status := http.StatusRequestTimeout
		if errors.Is(err, context.DeadlineExceeded) {
			failure.Code = "operation_deadline_exceeded"
			failure.Message = "LDAP write exceeded the operation deadline before it started"
			status = http.StatusGatewayTimeout
		}
		return &failure, status
	}

	err, interrupted := executeBatchWrite(operationContext, application, current, operation)
	if err == nil {
		return nil, 0
	}
	if errors.Is(err, errBatchApplicationClosed) {
		return &apiError{
			Code: "administration_closing", Message: "administration service is closing",
		}, http.StatusServiceUnavailable
	}
	if interrupted {
		failure := apiError{
			Code:    "ldap_result_unknown",
			Message: "LDAP write result is unknown because the request was canceled during the operation",
		}
		status := http.StatusRequestTimeout
		if errors.Is(operationContext.Err(), context.DeadlineExceeded) {
			failure.Message = "LDAP write result is unknown because the operation deadline was exceeded"
			status = http.StatusGatewayTimeout
		}
		return &failure, status
	}

	failure, unknown := ldapWriteFailure(err)
	if unknown {
		application.scheduleSessionClose(current, nil)
		return &failure, http.StatusBadGateway
	}
	return &failure, ldapHTTPStatus(*failure.LDAPResultCode)
}

func ldapHTTPStatus(code uint16) int {
	switch code {
	case ldap.LDAPResultInvalidCredentials:
		return http.StatusUnauthorized
	case ldap.LDAPResultInsufficientAccessRights:
		return http.StatusForbidden
	case ldap.LDAPResultNoSuchObject:
		return http.StatusNotFound
	case ldap.LDAPResultEntryAlreadyExists:
		return http.StatusConflict
	case ldap.LDAPResultBusy, ldap.LDAPResultUnavailable:
		return http.StatusServiceUnavailable
	case ldap.LDAPResultProtocolError, ldap.LDAPResultInvalidDNSyntax,
		ldap.LDAPResultUndefinedAttributeType, ldap.LDAPResultInappropriateMatching,
		ldap.LDAPResultConstraintViolation, ldap.LDAPResultAttributeOrValueExists,
		ldap.LDAPResultNoSuchAttribute, ldap.LDAPResultObjectClassViolation,
		ldap.LDAPResultNotAllowedOnNonLeaf, ldap.LDAPResultNotAllowedOnRDN,
		ldap.LDAPResultNamingViolation, ldap.LDAPResultUnwillingToPerform:
		return http.StatusUnprocessableEntity
	default:
		return http.StatusBadGateway
	}
}

func retryAfterSeconds(delay time.Duration) string {
	seconds := int(delay.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return strconv.Itoa(seconds)
}
