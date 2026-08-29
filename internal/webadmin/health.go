package webadmin

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

func (application *Application) handleLiveness(
	response http.ResponseWriter,
	request *http.Request,
) {
	if !methodAllowed(response, request, http.MethodGet, http.MethodHead) {
		return
	}
	if application.isClosed() {
		http.Error(response, "closed", http.StatusServiceUnavailable)
		return
	}
	writeHealthText(response, request, http.StatusOK, "ok\n")
}

func (application *Application) handleReadiness(
	response http.ResponseWriter,
	request *http.Request,
) {
	if !methodAllowed(response, request, http.MethodGet, http.MethodHead) {
		return
	}
	if application.isClosed() {
		http.Error(response, "closed", http.StatusServiceUnavailable)
		return
	}
	select {
	case application.readiness <- struct{}{}:
		defer func() { <-application.readiness }()
	default:
		http.Error(response, "readiness probe busy", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), application.config.DialTimeout)
	defer cancel()
	client, err := application.config.Connector.Connect(ctx, ConnectConfig{
		URL: application.config.LDAPURL, StartTLS: application.config.StartTLS,
		TLSConfig:        cloneTLSConfig(application.config.TLSConfig),
		DialTimeout:      application.config.DialTimeout,
		OperationTimeout: min(application.config.OperationTimeout, 5*time.Second),
	})
	var result *ldap.SearchResult
	if err == nil {
		result, err = client.Search(ldap.NewSearchRequest(
			"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5,
			false, "(objectClass=*)", []string{"supportedLDAPVersion"}, nil,
		))
		closeErr := client.Close()
		if err == nil {
			err = closeErr
		}
	}
	if err != nil || result == nil || len(result.Entries) == 0 {
		http.Error(response, "LDAP unavailable", http.StatusServiceUnavailable)
		return
	}
	writeHealthText(response, request, http.StatusOK, "ready\n")
}

func writeHealthText(
	response http.ResponseWriter,
	request *http.Request,
	status int,
	value string,
) {
	response.Header().Set("Content-Type", "text/plain; charset=utf-8")
	response.WriteHeader(status)
	if request.Method != http.MethodHead {
		_, _ = response.Write([]byte(value))
	}
}

func (application *Application) handleMetrics(
	response http.ResponseWriter,
	request *http.Request,
) {
	if !methodAllowed(response, request, http.MethodGet, http.MethodHead) {
		return
	}
	if application.config.externalURL != nil &&
		!webOriginIsLoopback(application.config.externalURL.Hostname()) &&
		!application.config.PublicMetrics {
		http.NotFound(response, request)
		return
	}
	application.mu.Lock()
	sessions := len(application.sessions)
	rateClients := len(application.rates)
	closed := application.closed
	application.mu.Unlock()
	up := 1
	if closed {
		up = 0
	}
	response.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	if request.Method == http.MethodHead {
		return
	}
	_, _ = fmt.Fprintf(response,
		"# TYPE ldap_go_web_admin_up gauge\nldap_go_web_admin_up %d\n"+
			"# TYPE ldap_go_web_admin_sessions gauge\nldap_go_web_admin_sessions %d\n"+
			"# TYPE ldap_go_web_admin_session_limit gauge\nldap_go_web_admin_session_limit %d\n"+
			"# TYPE ldap_go_web_admin_http_requests_total counter\nldap_go_web_admin_http_requests_total %d\n"+
			"# TYPE ldap_go_web_admin_login_success_total counter\nldap_go_web_admin_login_success_total %d\n"+
			"# TYPE ldap_go_web_admin_login_failure_total counter\nldap_go_web_admin_login_failure_total %d\n"+
			"# TYPE ldap_go_web_admin_panics_total counter\nldap_go_web_admin_panics_total %d\n"+
			"# TYPE ldap_go_web_admin_login_rate_clients gauge\nldap_go_web_admin_login_rate_clients %d\n"+
			"# TYPE ldap_go_web_admin_ldap_operations gauge\nldap_go_web_admin_ldap_operations %d\n"+
			"# TYPE ldap_go_web_admin_response_bytes gauge\nldap_go_web_admin_response_bytes %d\n"+
			"# TYPE ldap_go_web_admin_response_rejections_total counter\nldap_go_web_admin_response_rejections_total %d\n",
		up, sessions, application.config.MaxSessions, application.requests.Load(),
		application.loginSuccesses.Load(), application.loginFailures.Load(),
		application.panics.Load(), rateClients, len(application.operations),
		application.responseBytes.Load(), application.responseRejects.Load(),
	)
}

func webOriginIsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
