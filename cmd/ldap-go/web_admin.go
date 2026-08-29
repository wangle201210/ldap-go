package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/webadmin"
)

func runWebAdmin(
	ctx context.Context,
	args []string,
	stdout,
	stderr io.Writer,
) (runErr error) {
	if ctx == nil {
		return errors.New("web-admin context is required")
	}
	flags := flag.NewFlagSet("web-admin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listenAddress := flags.String("listen", "127.0.0.1:8080", "Web administration listen address")
	ldapURL := flags.String("ldap-url", "ldap://127.0.0.1:1389", "LDAP server URL")
	ldapStartTLS := flags.Bool("ldap-starttls", false, "require StartTLS before LDAP Bind")
	ldapCAFile := flags.String("ldap-tls-ca", "", "PEM CA bundle for the LDAP server")
	ldapServerName := flags.String("ldap-tls-server-name", "", "LDAP TLS server name override")
	publicURL := flags.String("public-url", "", "canonical browser origin, required for non-loopback listeners")
	publicMetrics := flags.Bool("public-metrics", false, "expose aggregate Prometheus metrics on a non-loopback public origin")
	httpsCertificate := flags.String("tls-cert", "", "PEM HTTPS server certificate")
	httpsPrivateKey := flags.String("tls-key", "", "PEM HTTPS server private key")
	sessionIdle := flags.Duration("session-idle-timeout", 30*time.Minute, "inactive session timeout")
	sessionLifetime := flags.Duration("session-max-lifetime", 12*time.Hour, "absolute session lifetime")
	maxSessions := flags.Int("max-sessions", 1000, "maximum active Web sessions")
	loginRate := flags.Int("login-rate-limit", 8, "login attempts allowed per client window")
	loginWindow := flags.Duration("login-rate-window", time.Minute, "login rate-limit window")
	requestBodyLimit := flags.Int64("request-body-limit", 2<<20, "maximum JSON or LDIF request body bytes")
	operationTimeout := flags.Duration("operation-timeout", 30*time.Second, "LDAP operation timeout")
	maxSearchSize := flags.Int("max-search-size", 5000, "maximum entries across a paged interactive search")
	maxImportChanges := flags.Int("max-import-changes", 1000, "maximum LDIF changes per import")
	maxExportEntries := flags.Int("max-export-entries", 5000, "maximum entries per LDIF export")
	maxConcurrentOperations := flags.Int("max-concurrent-operations", 32, "maximum concurrent LDAP operations from Web sessions")
	maxLDAPResponseBytes := flags.Int64("max-ldap-response-bytes", 32<<20, "maximum retained bytes in one LDAP Search response")
	maxProcessResponseBytes := flags.Int64("max-process-response-bytes", 128<<20, "maximum retained LDAP Search response bytes across Web sessions")
	shutdownTimeout := flags.Duration("shutdown-timeout", 30*time.Second, "maximum graceful shutdown duration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if err := validateWebAdminTransport(
		*listenAddress,
		*httpsCertificate,
		*httpsPrivateKey,
	); err != nil {
		return err
	}
	if err := validateWebAdminLDAPTransport(*ldapURL, *ldapStartTLS); err != nil {
		return err
	}
	secure := *httpsCertificate != ""
	if !webAdminListenIsLoopback(*listenAddress) && *publicURL == "" {
		return errors.New("web-admin -public-url is required for a non-loopback listener")
	}
	if err := validateWebAdminPublicURL(*publicURL, secure, webAdminListenIsLoopback(*listenAddress)); err != nil {
		return err
	}
	if shutdownTimeout == nil || *shutdownTimeout <= 0 {
		return errors.New("web-admin -shutdown-timeout must be positive")
	}

	ldapTLS, err := loadWebAdminClientTLSConfig(
		*ldapCAFile,
		*ldapServerName,
	)
	if err != nil {
		return err
	}
	ldapTLS.ServerName = webAdminLDAPServerName(*ldapURL, ldapTLS.ServerName)

	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return fmt.Errorf("listen for Web administration: %w", err)
	}
	defer listener.Close()
	externalURL := *publicURL
	if externalURL == "" {
		scheme := "http"
		if secure {
			scheme = "https"
		}
		externalURL = scheme + "://" + listener.Addr().String()
	}
	application, err := webadmin.New(webadmin.Config{
		LDAPURL:                 *ldapURL,
		StartTLS:                *ldapStartTLS,
		TLSConfig:               ldapTLS,
		ExternalURL:             externalURL,
		PublicMetrics:           *publicMetrics,
		SessionIdleTimeout:      *sessionIdle,
		SessionMaxLifetime:      *sessionLifetime,
		MaxSessions:             *maxSessions,
		LoginRateLimit:          *loginRate,
		LoginRateWindow:         *loginWindow,
		RequestBodyLimit:        *requestBodyLimit,
		OperationTimeout:        *operationTimeout,
		MaxSearchSize:           *maxSearchSize,
		MaxImportChanges:        *maxImportChanges,
		MaxExportEntries:        *maxExportEntries,
		MaxConcurrentOperations: *maxConcurrentOperations,
		MaxLDAPResponseBytes:    *maxLDAPResponseBytes,
		MaxProcessResponseBytes: *maxProcessResponseBytes,
		Logger:                  log.New(stderr, "web-admin: ", log.LstdFlags),
	})
	if err != nil {
		return err
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), *shutdownTimeout)
		defer cancel()
		runErr = errors.Join(runErr, application.CloseContext(closeCtx))
	}()

	httpServer := &http.Server{
		Handler:           application.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	if secure {
		httpServer.TLSConfig, err = loadServerTLSConfig(
			*httpsCertificate,
			*httpsPrivateKey,
		)
		if err != nil {
			return fmt.Errorf("load Web administration HTTPS configuration: %w", err)
		}
	}

	serveDone := make(chan error, 1)
	go func() {
		if secure {
			serveDone <- httpServer.ServeTLS(listener, "", "")
			return
		}
		serveDone <- httpServer.Serve(listener)
	}()
	if _, err := fmt.Fprintf(stdout, "Web administration listening at %s\n", externalURL); err != nil {
		return err
	}

	select {
	case err := <-serveDone:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), *shutdownTimeout)
	defer cancel()
	if err := application.CloseContext(shutdownCtx); err != nil {
		_ = httpServer.Close()
		return fmt.Errorf("close Web administration LDAP sessions: %w", err)
	}
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		_ = httpServer.Close()
		return fmt.Errorf("shut down Web administration: %w", err)
	}
	err = <-serveDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func webAdminLDAPServerName(rawURL, override string) string {
	if value := strings.TrimSpace(override); value != "" {
		return value
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func validateWebAdminLDAPTransport(rawURL string, startTLS bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("web-admin LDAP URL: %w", err)
	}
	if parsed.Scheme == "ldaps" {
		if startTLS {
			return errors.New("web-admin -ldap-starttls cannot be combined with an ldaps URL")
		}
		return nil
	}
	if parsed.Scheme != "ldap" {
		return errors.New("web-admin LDAP URL scheme must be ldap or ldaps")
	}
	if startTLS {
		return nil
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New(
			"web-admin plaintext LDAP is restricted to loopback; use ldaps:// or -ldap-starttls for remote servers",
		)
	}
	return nil
}

func loadWebAdminClientTLSConfig(
	caFile,
	serverName string,
) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: strings.TrimSpace(serverName),
	}
	if caFile == "" {
		return config, nil
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read Web administration LDAP CA bundle: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(data) {
		return nil, errors.New("Web administration LDAP CA bundle contains no certificates")
	}
	config.RootCAs = roots
	return config, nil
}
