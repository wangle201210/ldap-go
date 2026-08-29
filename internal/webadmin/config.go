package webadmin

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	defaultSessionIdleTimeout      = 30 * time.Minute
	defaultSessionMaxLifetime      = 12 * time.Hour
	defaultMaxSessions             = 1000
	defaultLoginRateLimit          = 8
	defaultLoginRateWindow         = time.Minute
	defaultRequestBodyLimit        = int64(2 << 20)
	defaultDialTimeout             = 10 * time.Second
	defaultOperationTimeout        = 30 * time.Second
	defaultMaxSearchSize           = 5000
	defaultMaxSearchSeconds        = 15
	defaultMaxAttributes           = 64
	defaultMaxFilterLength         = 4096
	defaultMaxFilterDepth          = 32
	defaultMaxImportChanges        = 1000
	defaultMaxExportEntries        = 5000
	defaultMaxExportBytes          = int64(32 << 20)
	defaultMaxMonitorEntries       = 1000
	defaultMaxConcurrentOperations = 32
	defaultMaxLDAPResponseBytes    = int64(32 << 20)
	defaultMaxProcessResponseBytes = int64(128 << 20)
	defaultRateClientCapacity      = 4096
)

// Logger is deliberately compatible with log.Logger without coupling callers
// to a logging implementation.
type Logger interface {
	Printf(format string, args ...any)
}

// Config controls the administration application's LDAP transport, sessions,
// and request resource limits. Zero values select conservative defaults.
type Config struct {
	LDAPURL       string
	StartTLS      bool
	TLSConfig     *tls.Config
	ExternalURL   string
	PublicMetrics bool

	SessionIdleTimeout   time.Duration
	SessionMaxLifetime   time.Duration
	SessionSweepInterval time.Duration
	MaxSessions          int

	LoginRateLimit      int
	LoginRateWindow     time.Duration
	LoginRateMaxClients int

	RequestBodyLimit int64
	DialTimeout      time.Duration
	OperationTimeout time.Duration

	MaxSearchSize           int
	MaxSearchSeconds        int
	MaxAttributes           int
	MaxFilterLength         int
	MaxFilterDepth          int
	MaxImportChanges        int
	MaxExportEntries        int
	MaxExportBytes          int64
	MaxMonitorEntries       int
	MaxConcurrentOperations int
	MaxLDAPResponseBytes    int64
	MaxProcessResponseBytes int64

	CookieName string
	Logger     Logger
	Clock      func() time.Time
	Random     io.Reader
	Connector  Connector
}

type normalizedConfig struct {
	Config
	ldapURL     *url.URL
	externalURL *url.URL
}

var cookieNamePattern = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]+$`)

func normalizeConfig(input Config) (normalizedConfig, error) {
	if input.LDAPURL == "" {
		return normalizedConfig{}, errors.New("LDAP URL is required")
	}
	parsed, err := url.Parse(input.LDAPURL)
	if err != nil {
		return normalizedConfig{}, fmt.Errorf("parse LDAP URL: %w", err)
	}
	if parsed.Scheme != "ldap" && parsed.Scheme != "ldaps" {
		return normalizedConfig{}, fmt.Errorf("LDAP URL scheme must be ldap or ldaps")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return normalizedConfig{}, errors.New("LDAP URL must contain only a scheme, host, port, and optional base path")
	}
	if input.StartTLS && parsed.Scheme != "ldap" {
		return normalizedConfig{}, errors.New("StartTLS requires an ldap URL")
	}
	var externalURL *url.URL
	if input.ExternalURL != "" {
		externalURL, err = url.Parse(input.ExternalURL)
		if err != nil || (externalURL.Scheme != "http" && externalURL.Scheme != "https") ||
			externalURL.Host == "" || externalURL.User != nil || externalURL.RawQuery != "" ||
			externalURL.Fragment != "" || (externalURL.Path != "" && externalURL.Path != "/") {
			return normalizedConfig{}, errors.New("external Web URL must contain only http(s) scheme and host")
		}
		input.ExternalURL = strings.TrimSuffix(externalURL.String(), "/")
	}

	setDurationDefault(&input.SessionIdleTimeout, defaultSessionIdleTimeout)
	setDurationDefault(&input.SessionMaxLifetime, defaultSessionMaxLifetime)
	if input.SessionSweepInterval == 0 {
		input.SessionSweepInterval = input.SessionIdleTimeout / 2
		if input.SessionSweepInterval > time.Minute {
			input.SessionSweepInterval = time.Minute
		}
		if input.SessionSweepInterval < time.Second {
			input.SessionSweepInterval = time.Second
		}
	}
	setIntDefault(&input.MaxSessions, defaultMaxSessions)
	setIntDefault(&input.LoginRateLimit, defaultLoginRateLimit)
	setDurationDefault(&input.LoginRateWindow, defaultLoginRateWindow)
	setIntDefault(&input.LoginRateMaxClients, defaultRateClientCapacity)
	setInt64Default(&input.RequestBodyLimit, defaultRequestBodyLimit)
	setDurationDefault(&input.DialTimeout, defaultDialTimeout)
	setDurationDefault(&input.OperationTimeout, defaultOperationTimeout)
	setIntDefault(&input.MaxSearchSize, defaultMaxSearchSize)
	setIntDefault(&input.MaxSearchSeconds, defaultMaxSearchSeconds)
	setIntDefault(&input.MaxAttributes, defaultMaxAttributes)
	setIntDefault(&input.MaxFilterLength, defaultMaxFilterLength)
	setIntDefault(&input.MaxFilterDepth, defaultMaxFilterDepth)
	setIntDefault(&input.MaxImportChanges, defaultMaxImportChanges)
	setIntDefault(&input.MaxExportEntries, defaultMaxExportEntries)
	setInt64Default(&input.MaxExportBytes, defaultMaxExportBytes)
	setIntDefault(&input.MaxMonitorEntries, defaultMaxMonitorEntries)
	setIntDefault(&input.MaxConcurrentOperations, defaultMaxConcurrentOperations)
	setInt64Default(&input.MaxLDAPResponseBytes, defaultMaxLDAPResponseBytes)
	setInt64Default(&input.MaxProcessResponseBytes, defaultMaxProcessResponseBytes)
	if input.CookieName == "" {
		input.CookieName = "ldap_admin_session"
	}
	if !cookieNamePattern.MatchString(input.CookieName) {
		return normalizedConfig{}, errors.New("invalid session cookie name")
	}
	if input.SessionIdleTimeout > input.SessionMaxLifetime {
		return normalizedConfig{}, errors.New("session idle timeout cannot exceed maximum lifetime")
	}
	if input.MaxProcessResponseBytes < input.MaxLDAPResponseBytes {
		return normalizedConfig{}, errors.New("process LDAP response byte limit cannot be lower than the per-operation limit")
	}
	if input.Logger == nil {
		input.Logger = log.Default()
	}
	if input.Clock == nil {
		input.Clock = time.Now
	}
	if input.Random == nil {
		input.Random = defaultRandomReader
	}
	if input.Connector == nil {
		input.Connector = realConnector{}
	}
	if input.TLSConfig != nil {
		input.TLSConfig = input.TLSConfig.Clone()
		if input.TLSConfig.MinVersion == 0 {
			input.TLSConfig.MinVersion = tls.VersionTLS12
		}
	}
	return normalizedConfig{Config: input, ldapURL: parsed, externalURL: externalURL}, nil
}

func setDurationDefault(value *time.Duration, fallback time.Duration) {
	if *value == 0 {
		*value = fallback
	}
}

func setIntDefault(value *int, fallback int) {
	if *value == 0 {
		*value = fallback
	}
}

func setInt64Default(value *int64, fallback int64) {
	if *value == 0 {
		*value = fallback
	}
}

func validatePositiveConfig(config normalizedConfig) error {
	checks := []struct {
		name  string
		value int64
	}{
		{"session idle timeout", int64(config.SessionIdleTimeout)},
		{"session maximum lifetime", int64(config.SessionMaxLifetime)},
		{"session sweep interval", int64(config.SessionSweepInterval)},
		{"maximum sessions", int64(config.MaxSessions)},
		{"login rate limit", int64(config.LoginRateLimit)},
		{"login rate window", int64(config.LoginRateWindow)},
		{"login rate client capacity", int64(config.LoginRateMaxClients)},
		{"request body limit", config.RequestBodyLimit},
		{"dial timeout", int64(config.DialTimeout)},
		{"operation timeout", int64(config.OperationTimeout)},
		{"maximum search size", int64(config.MaxSearchSize)},
		{"maximum search time", int64(config.MaxSearchSeconds)},
		{"maximum attributes", int64(config.MaxAttributes)},
		{"maximum filter length", int64(config.MaxFilterLength)},
		{"maximum filter depth", int64(config.MaxFilterDepth)},
		{"maximum import changes", int64(config.MaxImportChanges)},
		{"maximum export entries", int64(config.MaxExportEntries)},
		{"maximum export bytes", config.MaxExportBytes},
		{"maximum monitor entries", int64(config.MaxMonitorEntries)},
		{"maximum concurrent operations", int64(config.MaxConcurrentOperations)},
		{"maximum LDAP response bytes", config.MaxLDAPResponseBytes},
		{"maximum process LDAP response bytes", config.MaxProcessResponseBytes},
	}
	for _, check := range checks {
		if check.value <= 0 {
			return fmt.Errorf("%s must be positive", check.name)
		}
	}
	return nil
}
