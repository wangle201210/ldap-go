// Package lloadd contains the standalone LDAP load-balancer configuration
// model. The defaults and accepted directives are based on OpenLDAP 2.6.13.
package lloadd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// OpenLDAPSourceCommit is the fixed OpenLDAP 2.6.13 compatibility target.
	OpenLDAPSourceCommit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

	// These hashes pin the files from which the parser defaults and policies
	// were derived. They are also checked by the source-contract test.
	OpenLDAPConfigSourceSHA256  = "5f71fccca7e06f9c7d6693327856bfb72ecd91659ecf767248660e8147fc1c0e"
	OpenLDAPHeaderSourceSHA256  = "1c3996f0e309bde64ac4d401e211af26f1a2921f3cebb731ccd87fa7aecb1ff5"
	OpenLDAPBackendSourceSHA256 = "fed8ad8953c6e8fc2789f3e44ef3272c6293c2fe82b5d691d7d70589598590ed"
	OpenLDAPTiersSourceSHA256   = "fe271f8d4cdacf9f3104673fef7dc69b866698ae6ce0e01893ddad3a0d4c17fd"
	OpenLDAPDaemonSourceSHA256  = "ab6f24de5818edcecb6ec30a9918e3da1c96fd008d0a84b926bc3bf9949fe9b1"

	DefaultListenURL           = "ldap:///"
	DefaultMaxIncomingClient   = (1 << 24) - 1
	DefaultMaxIncomingUpstream = (1 << 24) - 1
	DefaultClientMaxPending    = 0
	DefaultBackendNumConns     = 1
	DefaultBackendBindConns    = 1
	DefaultBackendMaxPending   = 0
	DefaultBackendConnPending  = 0
	DefaultBackendWeight       = 1

	DefaultIOTimeout      = 10 * time.Second
	DefaultIdleTimeout    = 0
	DefaultNetworkTimeout = 0
	DefaultWriteCoherence = 0
	DefaultBackendRetry   = 5 * time.Second

	maxConfigLineBytes = 4 << 20
	maxIncludeDepth    = 64
)

// Config is the runtime-facing representation of a standalone lloadd.conf.
// NetworkTimeout is configured by bindconf's network-timeout option but is
// promoted because it controls every upstream connection.
type Config struct {
	ListenURLs          []string
	GentleHUP           bool
	Access              []string
	MaxIncomingClient   int
	MaxIncomingUpstream int
	ClientMaxPending    int
	WriteCoherence      time.Duration
	IOTimeout           time.Duration
	IdleTimeout         time.Duration
	NetworkTimeout      time.Duration
	ProxyAuthz          bool
	Features            []Feature
	BindConf            BindConfig
	Restrictions        []Restriction
	Tiers               []TierConfig
}

// TierConfig preserves declaration order. Backends also remain in source
// order, which is significant for round-robin and fallback behavior.
type TierConfig struct {
	Name     string
	Policy   TierPolicy
	Backends []BackendConfig
}

// BackendConfig maps directly to backend-server compound parameters.
type BackendConfig struct {
	URI            string
	NumConns       int
	BindConns      int
	Retry          time.Duration
	MaxPendingOps  int
	ConnMaxPending int
	StartTLS       StartTLSMode
	Weight         int
}

// BindConfig contains the service identity and outbound connection options
// shared by regular upstream connections.
type BindConfig struct {
	Method             BindMethod
	BindDN             string
	Credentials        string
	SASLMechanism      string
	AuthCID            string
	AuthZID            string
	Realm              string
	SecurityProperties string
	Timeout            time.Duration
	KeepAlive          KeepAliveConfig
	TCPUserTimeout     time.Duration
	TLS                BindTLSConfig
}

type KeepAliveConfig struct {
	Set      bool
	Idle     int
	Probes   int
	Interval int
}

type BindTLSConfig struct {
	CertificateFile  string
	KeyFile          string
	CACertificate    string
	CACertificateDir string
	RequireCert      string
	RequireSAN       string
	CipherSuite      string
	CRLCheck         string
	ProtocolMin      string
	ECName           string
}

type TierPolicy string

const (
	TierRoundRobin TierPolicy = "roundrobin"
	TierWeighted   TierPolicy = "weighted"
	TierBestOf     TierPolicy = "bestof"
)

type Feature string

const (
	FeatureProxyAuthz        Feature = "proxyauthz"
	FeatureVerifyCredentials Feature = "vc"
	FeatureReadPause         Feature = "read_pause"
)

type BindMethod string

const (
	BindNone   BindMethod = "none"
	BindSimple BindMethod = "simple"
	BindSASL   BindMethod = "sasl"
)

type StartTLSMode string

const (
	StartTLSDisabled StartTLSMode = "no"
	StartTLSOptional StartTLSMode = "yes"
	StartTLSCritical StartTLSMode = "critical"
	// StartTLSImplicit is the effective mode for an ldaps:// backend. In
	// OpenLDAP, the URI overrides an explicit starttls parameter.
	StartTLSImplicit StartTLSMode = "ldaps"
)

type RestrictionKind string

const (
	RestrictionExtendedOperation RestrictionKind = "extended-operation"
	RestrictionControl           RestrictionKind = "control"
)

type RestrictionAction string

const (
	RestrictionIgnore     RestrictionAction = "ignore"
	RestrictionWrite      RestrictionAction = "write"
	RestrictionBackend    RestrictionAction = "backend"
	RestrictionConnection RestrictionAction = "connection"
	RestrictionIsolate    RestrictionAction = "isolate"
	RestrictionReject     RestrictionAction = "reject"

	RestrictionActionIgnore     = RestrictionIgnore
	RestrictionActionWrite      = RestrictionWrite
	RestrictionActionBackend    = RestrictionBackend
	RestrictionActionConnection = RestrictionConnection
	RestrictionActionIsolate    = RestrictionIsolate
	RestrictionActionReject     = RestrictionReject
)

type Restriction struct {
	Kind   RestrictionKind
	OID    string
	Action RestrictionAction
}

// Priority follows OpenLDAP's op_restriction enum. When several controls are
// present, the action with the greatest priority wins.
func (action RestrictionAction) Priority() int {
	switch action {
	case RestrictionActionIgnore:
		return 0
	case RestrictionActionWrite:
		return 1
	case RestrictionActionBackend:
		return 2
	case RestrictionActionConnection:
		return 3
	case RestrictionActionIsolate:
		return 4
	case RestrictionActionReject:
		return 5
	default:
		return -1
	}
}

// ParseError identifies the physical source line that introduced an invalid
// logical directive. Included-file errors retain the included filename.
type ParseError struct {
	File      string
	Line      int
	Directive string
	Err       error
}

func (err *ParseError) Error() string {
	location := err.File
	if location == "" {
		location = "<input>"
	}
	if err.Line > 0 {
		location += ":" + strconv.Itoa(err.Line)
	}
	if err.Directive != "" {
		return fmt.Sprintf("%s: %s: %v", location, err.Directive, err.Err)
	}
	return fmt.Sprintf("%s: %v", location, err.Err)
}

func (err *ParseError) Unwrap() error { return err.Err }

func DefaultConfig() Config {
	return Config{
		ListenURLs:          []string{DefaultListenURL},
		MaxIncomingClient:   DefaultMaxIncomingClient,
		MaxIncomingUpstream: DefaultMaxIncomingUpstream,
		ClientMaxPending:    DefaultClientMaxPending,
		WriteCoherence:      DefaultWriteCoherence,
		IOTimeout:           DefaultIOTimeout,
		IdleTimeout:         DefaultIdleTimeout,
		NetworkTimeout:      DefaultNetworkTimeout,
		BindConf:            BindConfig{Method: BindNone},
	}
}

func DefaultBackendConfig() BackendConfig {
	return BackendConfig{
		NumConns:       DefaultBackendNumConns,
		BindConns:      DefaultBackendBindConns,
		Retry:          DefaultBackendRetry,
		MaxPendingOps:  DefaultBackendMaxPending,
		ConnMaxPending: DefaultBackendConnPending,
		StartTLS:       StartTLSDisabled,
		Weight:         DefaultBackendWeight,
	}
}

// Parse reads configuration from an unnamed stream. Relative includes are
// resolved from the current working directory.
func Parse(reader io.Reader) (*Config, error) {
	return ParseReader("<input>", reader)
}

// ParseReader is Parse with a source name used in diagnostics. If sourceName
// is a filesystem path, relative includes are resolved beside it.
func ParseReader(sourceName string, reader io.Reader) (*Config, error) {
	if reader == nil {
		return nil, errors.New("lloadd config reader is nil")
	}
	if sourceName == "" {
		sourceName = "<input>"
	}
	state := newParser()
	baseDir := "."
	if sourceName != "<input>" {
		baseDir = filepath.Dir(sourceName)
	}
	if err := state.parseReader(sourceName, baseDir, reader, 0); err != nil {
		return nil, err
	}
	if err := state.config.Validate(); err != nil {
		return nil, err
	}
	return &state.config, nil
}

func ParseFile(path string) (*Config, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("lloadd config path is empty")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve lloadd config %q: %w", path, err)
	}
	state := newParser()
	if err := state.parseFile(absPath, 0, sourceLocation{}); err != nil {
		return nil, err
	}
	if err := state.config.Validate(); err != nil {
		return nil, err
	}
	return &state.config, nil
}

// ParseConfigFile is the explicit standalone-runtime spelling of ParseFile.
func ParseConfigFile(path string) (*Config, error) {
	return ParseFile(path)
}

func newParser() *configParser {
	return &configParser{
		config:      DefaultConfig(),
		currentTier: -1,
		seen:        make(map[string]sourceLocation),
		activeFiles: make(map[string]struct{}),
	}
}

type sourceLocation struct {
	file string
	line int
}

type configParser struct {
	config      Config
	currentTier int
	seen        map[string]sourceLocation
	activeFiles map[string]struct{}
}

type logicalLine struct {
	text string
	line int
}

func (parser *configParser) parseFile(path string, depth int, from sourceLocation) error {
	if depth > maxIncludeDepth {
		return parser.errorAt(from, "include", fmt.Errorf("include depth exceeds %d", maxIncludeDepth))
	}
	canonical, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return parser.errorAt(from, "include", fmt.Errorf("resolve %q: %w", path, err))
	}
	if _, exists := parser.activeFiles[canonical]; exists {
		return parser.errorAt(from, "include", fmt.Errorf("include cycle involving %q", canonical))
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return parser.errorAt(from, "include", fmt.Errorf("open %q: %w", canonical, err))
	}
	if !info.Mode().IsRegular() {
		return parser.errorAt(from, "include", fmt.Errorf("%q is not a regular file", canonical))
	}
	file, err := os.Open(canonical)
	if err != nil {
		return parser.errorAt(from, "include", fmt.Errorf("open %q: %w", canonical, err))
	}
	defer file.Close()
	parser.activeFiles[canonical] = struct{}{}
	defer delete(parser.activeFiles, canonical)
	return parser.parseReader(canonical, filepath.Dir(canonical), file, depth)
}

func (parser *configParser) parseReader(name, baseDir string, reader io.Reader, depth int) error {
	lines, err := readLogicalLines(reader)
	if err != nil {
		return &ParseError{File: name, Err: err}
	}
	for _, line := range lines {
		words, err := splitWords(line.text)
		if err != nil {
			return &ParseError{File: name, Line: line.line, Err: err}
		}
		if len(words) == 0 {
			continue
		}
		location := sourceLocation{file: name, line: line.line}
		if err := parser.parseDirective(words, baseDir, depth, location); err != nil {
			var parseErr *ParseError
			if errors.As(err, &parseErr) {
				return err
			}
			return parser.errorAt(location, words[0], err)
		}
	}
	return nil
}

func (parser *configParser) parseDirective(words []string, baseDir string, depth int, location sourceLocation) error {
	directive := strings.ToLower(words[0])
	args := words[1:]
	switch directive {
	case "include":
		if err := requireArgumentCount(directive, args, 1, 1); err != nil {
			return err
		}
		path := args[0]
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDir, path)
		}
		return parser.parseFile(path, depth+1, location)
	case "listen":
		if err := parser.markSingleton(directive, location); err != nil {
			return err
		}
		if len(args) == 0 {
			return errors.New("listen requires at least one LDAP URL")
		}
		var listeners []string
		for _, arg := range args {
			listeners = append(listeners, strings.Fields(arg)...)
		}
		if len(listeners) == 0 {
			return errors.New("listen requires at least one LDAP URL")
		}
		seen := make(map[string]struct{}, len(listeners))
		for _, listener := range listeners {
			if err := validateListenerURL(listener); err != nil {
				return fmt.Errorf("invalid listener URL %q: %w", listener, err)
			}
			key := strings.ToLower(listener)
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate listener URL %q", listener)
			}
			seen[key] = struct{}{}
		}
		parser.config.ListenURLs = listeners
		return nil
	case "gentlehup":
		if err := parser.markSingleton(directive, location); err != nil {
			return err
		}
		if err := requireArgumentCount(directive, args, 1, 1); err != nil {
			return err
		}
		enabled, err := parseOnOff(args[0])
		if err != nil {
			return fmt.Errorf("invalid gentlehup: %w", err)
		}
		parser.config.GentleHUP = enabled
		return nil
	case "access":
		if len(args) == 0 {
			return errors.New("access requires an OpenLDAP ACL rule")
		}
		parser.config.Access = append(parser.config.Access, strings.Join(args, " "))
		return nil
	case "sockbuf_max_incoming_client":
		return parser.parseLimitSingleton(directive, args, location, &parser.config.MaxIncomingClient)
	case "sockbuf_max_incoming_upstream":
		return parser.parseLimitSingleton(directive, args, location, &parser.config.MaxIncomingUpstream)
	case "client_max_pending":
		return parser.parseLimitSingleton(directive, args, location, &parser.config.ClientMaxPending)
	case "write_coherence":
		if err := parser.markSingleton(directive, location); err != nil {
			return err
		}
		if err := requireArgumentCount(directive, args, 1, 1); err != nil {
			return err
		}
		value, err := parseIntegerDuration(args[0], time.Second, true)
		if err != nil {
			return fmt.Errorf("invalid write_coherence: %w", err)
		}
		parser.config.WriteCoherence = value
		return nil
	case "iotimeout":
		if err := parser.markSingleton(directive, location); err != nil {
			return err
		}
		if err := requireArgumentCount(directive, args, 1, 1); err != nil {
			return err
		}
		value, err := parseIntegerDuration(args[0], time.Millisecond, false)
		if err != nil {
			return fmt.Errorf("invalid iotimeout: %w", err)
		}
		parser.config.IOTimeout = value
		return nil
	case "idletimeout":
		if err := parser.markSingleton(directive, location); err != nil {
			return err
		}
		if err := requireArgumentCount(directive, args, 1, 1); err != nil {
			return err
		}
		value, err := parseIntegerDuration(args[0], time.Second, false)
		if err != nil {
			return fmt.Errorf("invalid idletimeout: %w", err)
		}
		parser.config.IdleTimeout = value
		return nil
	case "feature":
		if len(args) == 0 {
			return errors.New("feature requires at least one name")
		}
		for _, value := range args {
			feature, err := parseFeature(value)
			if err != nil {
				return err
			}
			if !containsFeature(parser.config.Features, feature) {
				parser.config.Features = append(parser.config.Features, feature)
			}
			if feature == FeatureProxyAuthz {
				parser.config.ProxyAuthz = true
			}
		}
		return nil
	case "restrict_exop":
		return parser.parseRestriction(RestrictionExtendedOperation, args)
	case "restrict_control":
		return parser.parseRestriction(RestrictionControl, args)
	case "bindconf":
		if err := parser.markSingleton(directive, location); err != nil {
			return err
		}
		return parser.parseBindConf(args)
	case "tier":
		if err := requireArgumentCount(directive, args, 1, 1); err != nil {
			return err
		}
		policy, err := parseTierPolicy(args[0])
		if err != nil {
			return err
		}
		parser.config.Tiers = append(parser.config.Tiers, TierConfig{
			Name:   fmt.Sprintf("tier %d", len(parser.config.Tiers)+1),
			Policy: policy,
		})
		parser.currentTier = len(parser.config.Tiers) - 1
		return nil
	case "backend-server":
		if parser.currentTier < 0 {
			return errors.New("backend-server requires a preceding tier")
		}
		backend, err := parseBackend(args)
		if err != nil {
			return err
		}
		tier := &parser.config.Tiers[parser.currentTier]
		tier.Backends = append(tier.Backends, backend)
		return nil
	default:
		return fmt.Errorf("unknown directive %q", words[0])
	}
}

func (parser *configParser) parseLimitSingleton(name string, args []string, location sourceLocation, target *int) error {
	if err := parser.markSingleton(name, location); err != nil {
		return err
	}
	if err := requireArgumentCount(name, args, 1, 1); err != nil {
		return err
	}
	value, err := parseLimit(args[0])
	if err != nil {
		return fmt.Errorf("invalid %s: %w", name, err)
	}
	*target = value
	return nil
}

func (parser *configParser) markSingleton(name string, location sourceLocation) error {
	if previous, exists := parser.seen[name]; exists {
		return fmt.Errorf("directive already set at %s:%d", previous.file, previous.line)
	}
	parser.seen[name] = location
	return nil
}

func (parser *configParser) parseRestriction(kind RestrictionKind, args []string) error {
	if err := requireArgumentCount(string(kind), args, 2, 2); err != nil {
		return err
	}
	if err := validateNumericOID(args[0]); err != nil {
		return fmt.Errorf("invalid restriction OID %q: %w", args[0], err)
	}
	action, err := parseRestrictionAction(args[1])
	if err != nil {
		return err
	}
	for _, restriction := range parser.config.Restrictions {
		if restriction.Kind == kind && restriction.OID == args[0] {
			return fmt.Errorf("%s OID %s is already restricted", kind, args[0])
		}
	}
	parser.config.Restrictions = append(parser.config.Restrictions, Restriction{
		Kind: kind, OID: args[0], Action: action,
	})
	return nil
}

func (parser *configParser) parseBindConf(args []string) error {
	if len(args) == 0 {
		return errors.New("bindconf requires at least one parameter")
	}
	conf := BindConfig{Method: BindNone}
	seen := make(map[string]bool, len(args))
	for _, argument := range args {
		key, value, ok := strings.Cut(argument, "=")
		key = strings.ToLower(key)
		if !ok || key == "" {
			return errors.New("invalid bindconf parameter; expected key=value")
		}
		if seen[key] {
			return fmt.Errorf("duplicate bindconf parameter %q", key)
		}
		seen[key] = true
		switch key {
		case "bindmethod":
			switch strings.ToLower(value) {
			case string(BindNone):
				conf.Method = BindNone
			case string(BindSimple):
				conf.Method = BindSimple
			case string(BindSASL):
				conf.Method = BindSASL
			default:
				return fmt.Errorf("invalid bindmethod %q", value)
			}
		case "binddn":
			conf.BindDN = value
		case "credentials":
			conf.Credentials = value
		case "saslmech":
			conf.SASLMechanism = value
		case "authcid":
			conf.AuthCID = value
		case "authzid":
			conf.AuthZID = value
		case "realm":
			conf.Realm = value
		case "secprops":
			conf.SecurityProperties = value
		case "timeout":
			duration, err := parseIntegerDuration(value, time.Second, false)
			if err != nil {
				return fmt.Errorf("invalid bindconf timeout: %w", err)
			}
			conf.Timeout = duration
		case "network-timeout":
			duration, err := parseIntegerDuration(value, time.Second, false)
			if err != nil {
				return fmt.Errorf("invalid bindconf network-timeout: %w", err)
			}
			parser.config.NetworkTimeout = duration
		case "keepalive":
			keepAlive, err := parseKeepAlive(value)
			if err != nil {
				return fmt.Errorf("invalid bindconf keepalive: %w", err)
			}
			conf.KeepAlive = keepAlive
		case "tcp-user-timeout":
			duration, err := parseIntegerDuration(value, time.Millisecond, false)
			if err != nil {
				return fmt.Errorf("invalid bindconf tcp-user-timeout: %w", err)
			}
			conf.TCPUserTimeout = duration
		case "tls_cert":
			conf.TLS.CertificateFile = value
		case "tls_key":
			conf.TLS.KeyFile = value
		case "tls_cacert":
			conf.TLS.CACertificate = value
		case "tls_cacertdir":
			conf.TLS.CACertificateDir = value
		case "tls_reqcert":
			if !oneOfFold(value, "never", "allow", "try", "demand", "hard", "true") {
				return fmt.Errorf("invalid tls_reqcert policy %q", value)
			}
			conf.TLS.RequireCert = strings.ToLower(value)
		case "tls_reqsan":
			if !oneOfFold(value, "never", "allow", "try", "demand", "hard") {
				return fmt.Errorf("invalid tls_reqsan policy %q", value)
			}
			conf.TLS.RequireSAN = strings.ToLower(value)
		case "tls_cipher_suite":
			conf.TLS.CipherSuite = value
		case "tls_crlcheck":
			if !oneOfFold(value, "none", "peer", "all") {
				return fmt.Errorf("invalid tls_crlcheck policy %q", value)
			}
			conf.TLS.CRLCheck = strings.ToLower(value)
		case "tls_protocol_min":
			if err := validateTLSProtocol(value); err != nil {
				return err
			}
			conf.TLS.ProtocolMin = value
		case "tls_ecname":
			conf.TLS.ECName = value
		default:
			return fmt.Errorf("unknown bindconf parameter %q", key)
		}
	}
	if conf.Method == BindSimple && (!seen["binddn"] || !seen["credentials"]) {
		return errors.New("bindmethod=simple requires binddn and credentials")
	}
	if conf.Method == BindSASL && strings.TrimSpace(conf.SASLMechanism) == "" {
		return errors.New("bindmethod=sasl requires saslmech")
	}
	parser.config.BindConf = conf
	return nil
}

func parseBackend(args []string) (BackendConfig, error) {
	if len(args) == 0 {
		return BackendConfig{}, errors.New("backend-server requires parameters")
	}
	backend := DefaultBackendConfig()
	seen := make(map[string]bool, len(args))
	for _, argument := range args {
		key, value, ok := strings.Cut(argument, "=")
		key = strings.ToLower(key)
		if !ok || key == "" {
			return BackendConfig{}, fmt.Errorf("invalid backend parameter %q; expected key=value", argument)
		}
		if seen[key] {
			return BackendConfig{}, fmt.Errorf("duplicate backend parameter %q", key)
		}
		seen[key] = true
		switch key {
		case "uri":
			if err := validateBackendURL(value); err != nil {
				return BackendConfig{}, fmt.Errorf("invalid backend URI %q: %w", value, err)
			}
			backend.URI = value
		case "numconns":
			parsed, err := parseLimit(value)
			if err != nil || parsed == 0 {
				return BackendConfig{}, fmt.Errorf("numconns must be a positive integer")
			}
			backend.NumConns = parsed
		case "bindconns":
			parsed, err := parseLimit(value)
			if err != nil || parsed == 0 {
				return BackendConfig{}, fmt.Errorf("bindconns must be a positive integer")
			}
			backend.BindConns = parsed
		case "retry":
			parsed, err := parseIntegerDuration(value, time.Millisecond, false)
			if err != nil {
				return BackendConfig{}, fmt.Errorf("invalid retry: %w", err)
			}
			backend.Retry = parsed
		case "max-pending-ops":
			parsed, err := parseLimit(value)
			if err != nil {
				return BackendConfig{}, fmt.Errorf("invalid max-pending-ops: %w", err)
			}
			backend.MaxPendingOps = parsed
		case "conn-max-pending":
			parsed, err := parseLimit(value)
			if err != nil {
				return BackendConfig{}, fmt.Errorf("invalid conn-max-pending: %w", err)
			}
			backend.ConnMaxPending = parsed
		case "starttls":
			switch strings.ToLower(value) {
			case string(StartTLSDisabled):
				backend.StartTLS = StartTLSDisabled
			case string(StartTLSOptional):
				backend.StartTLS = StartTLSOptional
			case string(StartTLSCritical):
				backend.StartTLS = StartTLSCritical
			default:
				return BackendConfig{}, fmt.Errorf("invalid starttls policy %q", value)
			}
		case "weight":
			parsed, err := parseLimit(value)
			if err != nil {
				return BackendConfig{}, fmt.Errorf("invalid weight: %w", err)
			}
			backend.Weight = parsed
		default:
			return BackendConfig{}, fmt.Errorf("unknown backend parameter %q", key)
		}
	}
	if !seen["uri"] {
		return BackendConfig{}, errors.New("backend-server is missing uri")
	}
	if strings.HasPrefix(strings.ToLower(backend.URI), "ldaps://") {
		backend.StartTLS = StartTLSImplicit
	}
	return backend, nil
}

func readLogicalLines(reader io.Reader) ([]logicalLine, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), maxConfigLineBytes)
	var lines []logicalLine
	var current strings.Builder
	startLine := 0
	haveCurrent := false
	forced := false
	flush := func() {
		if !haveCurrent {
			return
		}
		text := current.String()
		if strings.TrimSpace(text) != "" {
			lines = append(lines, logicalLine{text: text, line: startLine})
		}
		current.Reset()
		haveCurrent = false
		forced = false
	}
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		physical := strings.TrimSuffix(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(physical)
		isComment := strings.HasPrefix(trimmed, "#")
		isBlank := trimmed == ""
		indented := len(physical) > 0 && (physical[0] == ' ' || physical[0] == '\t')

		if haveCurrent && !forced && !indented {
			flush()
		}
		if isBlank || isComment {
			continue
		}
		if !haveCurrent {
			startLine = lineNumber
			haveCurrent = true
		} else if current.Len() > 0 {
			current.WriteByte(' ')
		}
		continued := hasContinuation(physical)
		if continued {
			physical = physical[:len(physical)-1]
		}
		current.WriteString(physical)
		forced = continued
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	if forced {
		return nil, fmt.Errorf("line %d ends with an unterminated continuation", startLine)
	}
	flush()
	return lines, nil
}

func hasContinuation(line string) bool {
	if line == "" || line[len(line)-1] != '\\' {
		return false
	}
	count := 0
	for index := len(line) - 1; index >= 0 && line[index] == '\\'; index-- {
		count++
	}
	return count%2 == 1
}

func splitWords(line string) ([]string, error) {
	var words []string
	var word strings.Builder
	started := false
	inQuote := false
	for index := 0; index < len(line); index++ {
		character := line[index]
		switch character {
		case '\\':
			started = true
			if index+1 < len(line) {
				index++
				word.WriteByte(line[index])
			} else {
				word.WriteByte(character)
			}
		case '"':
			started = true
			inQuote = !inQuote
		case ' ', '\t':
			if inQuote {
				word.WriteByte(character)
			} else if started {
				words = append(words, word.String())
				word.Reset()
				started = false
			}
		default:
			started = true
			word.WriteByte(character)
		}
	}
	if inQuote {
		return nil, errors.New("unterminated double quote")
	}
	if started {
		words = append(words, word.String())
	}
	return words, nil
}

func parseOnOff(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "on", "yes", "true", "1":
		return true, nil
	case "off", "no", "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("expected on or off, got %q", raw)
	}
}

func (config Config) Validate() error {
	if len(config.ListenURLs) == 0 {
		return errors.New("lloadd config has no listener URLs")
	}
	listeners := make(map[string]struct{}, len(config.ListenURLs))
	for _, listener := range config.ListenURLs {
		if err := validateListenerURL(listener); err != nil {
			return fmt.Errorf("invalid listener URL %q: %w", listener, err)
		}
		key := strings.ToLower(listener)
		if _, exists := listeners[key]; exists {
			return fmt.Errorf("duplicate listener URL %q", listener)
		}
		listeners[key] = struct{}{}
	}
	for name, value := range map[string]int{
		"MaxIncomingClient":   config.MaxIncomingClient,
		"MaxIncomingUpstream": config.MaxIncomingUpstream,
		"ClientMaxPending":    config.ClientMaxPending,
	} {
		if value < 0 {
			return fmt.Errorf("%s cannot be negative", name)
		}
	}
	if config.IOTimeout < 0 || config.IdleTimeout < 0 || config.NetworkTimeout < 0 {
		return errors.New("I/O, idle, and network timeouts cannot be negative")
	}
	features := make(map[Feature]struct{}, len(config.Features))
	for _, feature := range config.Features {
		if _, err := parseFeature(string(feature)); err != nil {
			return err
		}
		if _, exists := features[feature]; exists {
			return fmt.Errorf("duplicate feature %q", feature)
		}
		features[feature] = struct{}{}
	}
	if _, hasProxyFeature := features[FeatureProxyAuthz]; hasProxyFeature && !config.ProxyAuthz {
		return errors.New("proxyauthz feature requires ProxyAuthz")
	}
	if err := validateBindConfig(config.BindConf); err != nil {
		return err
	}
	restrictions := make(map[string]struct{}, len(config.Restrictions))
	for _, restriction := range config.Restrictions {
		if restriction.Kind != RestrictionExtendedOperation && restriction.Kind != RestrictionControl {
			return fmt.Errorf("invalid restriction kind %q", restriction.Kind)
		}
		if err := validateNumericOID(restriction.OID); err != nil {
			return fmt.Errorf("invalid restriction OID %q: %w", restriction.OID, err)
		}
		if restriction.Action.Priority() < 0 {
			return fmt.Errorf("invalid restriction action %q", restriction.Action)
		}
		key := string(restriction.Kind) + "\x00" + restriction.OID
		if _, exists := restrictions[key]; exists {
			return fmt.Errorf("duplicate restriction for %s %s", restriction.Kind, restriction.OID)
		}
		restrictions[key] = struct{}{}
	}
	for tierIndex, tier := range config.Tiers {
		if _, err := parseTierPolicy(string(tier.Policy)); err != nil {
			return fmt.Errorf("tier %d: %w", tierIndex+1, err)
		}
		for backendIndex, backend := range tier.Backends {
			if err := validateBackendConfig(backend); err != nil {
				return fmt.Errorf("tier %d backend %d: %w", tierIndex+1, backendIndex+1, err)
			}
		}
	}
	return nil
}

func validateBindConfig(config BindConfig) error {
	switch config.Method {
	case BindNone:
	case BindSimple:
		// Presence of empty values cannot be distinguished on a manually built
		// Config, so only parsed input enforces both option tokens.
	case BindSASL:
		if strings.TrimSpace(config.SASLMechanism) == "" {
			return errors.New("bindmethod=sasl requires saslmech")
		}
		if strings.EqualFold(strings.TrimSpace(config.SASLMechanism), "GSSAPI") {
			if err := validateServiceGSSAPIStaticConfig(
				config.AuthCID,
				config.Realm,
				config.SecurityProperties,
				[]byte(config.Credentials),
			); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid bind method %q", config.Method)
	}
	if config.Timeout < 0 || config.TCPUserTimeout < 0 {
		return errors.New("bindconf timeouts cannot be negative")
	}
	if config.KeepAlive.Set && (config.KeepAlive.Idle < 0 || config.KeepAlive.Probes < 0 || config.KeepAlive.Interval < 0) {
		return errors.New("bindconf keepalive values cannot be negative")
	}
	if config.TLS.RequireCert != "" && !oneOfFold(config.TLS.RequireCert, "never", "allow", "try", "demand", "hard", "true") {
		return fmt.Errorf("invalid tls_reqcert policy %q", config.TLS.RequireCert)
	}
	if config.TLS.RequireSAN != "" && !oneOfFold(config.TLS.RequireSAN, "never", "allow", "try", "demand", "hard") {
		return fmt.Errorf("invalid tls_reqsan policy %q", config.TLS.RequireSAN)
	}
	if config.TLS.CRLCheck != "" && !oneOfFold(config.TLS.CRLCheck, "none", "peer", "all") {
		return fmt.Errorf("invalid tls_crlcheck policy %q", config.TLS.CRLCheck)
	}
	if config.TLS.ProtocolMin != "" {
		return validateTLSProtocol(config.TLS.ProtocolMin)
	}
	return nil
}

func validateBackendConfig(config BackendConfig) error {
	if err := validateBackendURL(config.URI); err != nil {
		return err
	}
	if config.NumConns <= 0 || config.BindConns <= 0 {
		return errors.New("numconns and bindconns must be positive")
	}
	if config.Retry < 0 || config.MaxPendingOps < 0 || config.ConnMaxPending < 0 || config.Weight < 0 {
		return errors.New("retry, pending limits, and weight cannot be negative")
	}
	if config.StartTLS != StartTLSDisabled && config.StartTLS != StartTLSOptional &&
		config.StartTLS != StartTLSCritical && config.StartTLS != StartTLSImplicit {
		return fmt.Errorf("invalid StartTLS mode %q", config.StartTLS)
	}
	if strings.HasPrefix(strings.ToLower(config.URI), "ldaps://") && config.StartTLS != StartTLSImplicit {
		return errors.New("ldaps backend must use the implicit TLS mode")
	}
	return nil
}

func (config Config) HasFeature(feature Feature) bool {
	if feature == FeatureProxyAuthz {
		return config.ProxyAuthz
	}
	return containsFeature(config.Features, feature)
}

// LookupRestriction returns the exact restriction or, for an unknown extended
// operation, the action configured with the special 1.1 OID.
func (config Config) LookupRestriction(kind RestrictionKind, oid string) (RestrictionAction, bool) {
	for _, restriction := range config.Restrictions {
		if restriction.Kind == kind && restriction.OID == oid {
			return restriction.Action, true
		}
	}
	if kind == RestrictionExtendedOperation && oid != "1.1" {
		for _, restriction := range config.Restrictions {
			if restriction.Kind == kind && restriction.OID == "1.1" {
				return restriction.Action, true
			}
		}
	}
	return RestrictionActionIgnore, false
}

func requireArgumentCount(directive string, args []string, minimum, maximum int) error {
	if len(args) < minimum || (maximum >= 0 && len(args) > maximum) {
		if minimum == maximum {
			return fmt.Errorf("%s requires exactly %d argument(s), got %d", directive, minimum, len(args))
		}
		return fmt.Errorf("%s requires %d..%d arguments, got %d", directive, minimum, maximum, len(args))
	}
	return nil
}

func parseLimit(value string) (int, error) {
	if value == "" {
		return 0, errors.New("empty integer")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, fmt.Errorf("%q is not an unsigned decimal integer", value)
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed > uint64(maxInt()) {
		return 0, fmt.Errorf("integer %q is out of range", value)
	}
	return int(parsed), nil
}

func parseIntegerDuration(value string, unit time.Duration, allowNegative bool) (time.Duration, error) {
	if value == "" {
		return 0, errors.New("empty duration")
	}
	start := 0
	if value[0] == '-' {
		if !allowNegative || len(value) == 1 {
			return 0, fmt.Errorf("%q must be a non-negative integer", value)
		}
		start = 1
	}
	for _, character := range value[start:] {
		if character < '0' || character > '9' {
			return 0, fmt.Errorf("%q must be an integer in source units", value)
		}
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("duration %q is out of range", value)
	}
	if parsed > int64(^uint64(0)>>1)/int64(unit) || parsed < -int64(^uint64(0)>>1)/int64(unit) {
		return 0, fmt.Errorf("duration %q overflows time.Duration", value)
	}
	return time.Duration(parsed) * unit, nil
}

func parseKeepAlive(value string) (KeepAliveConfig, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 3 {
		return KeepAliveConfig{}, errors.New("expected idle:probes:interval")
	}
	values := [3]int{}
	for index, part := range parts {
		if part == "" {
			continue
		}
		parsed, err := parseLimit(part)
		if err != nil {
			return KeepAliveConfig{}, err
		}
		values[index] = parsed
	}
	return KeepAliveConfig{Set: true, Idle: values[0], Probes: values[1], Interval: values[2]}, nil
}

func parseTierPolicy(value string) (TierPolicy, error) {
	switch strings.ToLower(value) {
	case string(TierRoundRobin):
		return TierRoundRobin, nil
	case string(TierWeighted):
		return TierWeighted, nil
	case string(TierBestOf):
		return TierBestOf, nil
	default:
		return "", fmt.Errorf("unknown tier policy %q", value)
	}
}

func parseFeature(value string) (Feature, error) {
	switch strings.ToLower(value) {
	case string(FeatureProxyAuthz):
		return FeatureProxyAuthz, nil
	case string(FeatureVerifyCredentials):
		return FeatureVerifyCredentials, nil
	case string(FeatureReadPause):
		return FeatureReadPause, nil
	default:
		return "", fmt.Errorf("unknown lloadd feature %q", value)
	}
}

func containsFeature(features []Feature, feature Feature) bool {
	for _, candidate := range features {
		if candidate == feature {
			return true
		}
	}
	return false
}

func parseRestrictionAction(value string) (RestrictionAction, error) {
	switch strings.ToLower(value) {
	case string(RestrictionActionIgnore):
		return RestrictionActionIgnore, nil
	case string(RestrictionActionWrite):
		return RestrictionActionWrite, nil
	case string(RestrictionActionBackend):
		return RestrictionActionBackend, nil
	case string(RestrictionActionConnection):
		return RestrictionActionConnection, nil
	case string(RestrictionActionIsolate):
		return RestrictionActionIsolate, nil
	case string(RestrictionActionReject):
		return RestrictionActionReject, nil
	default:
		return "", fmt.Errorf("unknown restriction action %q", value)
	}
}

func validateNumericOID(oid string) error {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return errors.New("numeric OID needs at least two arcs")
	}
	values := make([]uint64, len(parts))
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return fmt.Errorf("invalid arc %q", part)
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return fmt.Errorf("invalid arc %q", part)
			}
		}
		parsed, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return fmt.Errorf("arc %q is out of range", part)
		}
		values[index] = parsed
	}
	if values[0] > 2 {
		return errors.New("first OID arc must be 0, 1, or 2")
	}
	if values[0] < 2 && values[1] > 39 {
		return errors.New("second OID arc must be below 40 when the first arc is 0 or 1")
	}
	return nil
}

func validateListenerURL(value string) error {
	return validateLDAPURL(value, true)
}

func validateBackendURL(value string) error {
	return validateLDAPURL(value, false)
}

func validateLDAPURL(value string, listener bool) error {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, " \t\r\n") {
		return errors.New("URL is empty or contains whitespace")
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "ldapi://") {
		_, err := ParseLDAPIAddress(value)
		return err
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return err
	}
	scheme := strings.ToLower(parsed.Scheme)
	allowed := scheme == "ldap" || scheme == "ldaps"
	if listener {
		allowed = allowed || scheme == "pldap" || scheme == "pldaps"
	}
	if !allowed {
		return fmt.Errorf("unsupported LDAP URL scheme %q", parsed.Scheme)
	}
	if !strings.HasPrefix(value[len(parsed.Scheme):], "://") {
		return errors.New("LDAP URL must use // authority syntax")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return errors.New("userinfo, query, and fragment components are not allowed")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return errors.New("LDAP DN/path components are not allowed")
	}
	if !listener && parsed.Hostname() == "" {
		return errors.New("backend URL is missing a hostname")
	}
	return nil
}

// ParseLDAPIAddress accepts OpenLDAP's escaped-authority form
// (ldapi://%2Fpath%2Fto%2Fsocket/) and the conventional three-slash form.
func ParseLDAPIAddress(value string) (string, error) {
	const prefix = "ldapi://"
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return "", errors.New("LDAPI URL must start with ldapi://")
	}
	if value == "" || strings.TrimSpace(value) != value ||
		strings.ContainsAny(value, " \t\r\n") {
		return "", errors.New("URL is empty or contains whitespace")
	}
	remainder := value[len(prefix):]
	if strings.ContainsAny(remainder, "?#") {
		return "", errors.New("ldapi URL cannot contain query or fragment components")
	}
	encodedAddress := remainder
	if !strings.HasPrefix(remainder, "/") {
		if separator := strings.IndexByte(remainder, '/'); separator >= 0 {
			if remainder[separator:] != "/" {
				return "", errors.New("ldapi URL cannot contain DN/path components")
			}
			encodedAddress = remainder[:separator]
		}
	}
	address, err := url.PathUnescape(encodedAddress)
	if err != nil {
		return "", fmt.Errorf("invalid ldapi escape: %w", err)
	}
	return address, nil
}

func validateTLSProtocol(value string) error {
	parts := strings.Split(value, ".")
	if len(parts) > 2 || len(parts) == 0 {
		return fmt.Errorf("invalid tls_protocol_min %q", value)
	}
	for _, part := range parts {
		parsed, err := parseLimit(part)
		if err != nil || parsed > 255 {
			return fmt.Errorf("invalid tls_protocol_min %q", value)
		}
	}
	return nil
}

func oneOfFold(value string, choices ...string) bool {
	for _, choice := range choices {
		if strings.EqualFold(value, choice) {
			return true
		}
	}
	return false
}

func maxInt() int { return int(^uint(0) >> 1) }

func (parser *configParser) errorAt(location sourceLocation, directive string, err error) error {
	return &ParseError{File: location.file, Line: location.line, Directive: directive, Err: err}
}
