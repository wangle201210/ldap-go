package lloadd

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
)

const (
	defaultClientMessageSize   = int64((1 << 24) - 1)
	defaultUpstreamMessageSize = int64((1 << 24) - 1)
	defaultBackendRetry        = 5 * time.Second
	serviceBindMessageID       = int64(1)
	upstreamStartTLSOID        = "1.3.6.1.4.1.1466.20037"
	verifyCredentialsOID       = "1.3.6.1.4.1.4203.666.6.5"
)

var ErrProxyClosed = errors.New("lloadd proxy is closed")

type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// RuntimeConfig is the validated, transport-ready form of a standalone
// lloadd configuration. ParseConfigFile converts OpenLDAP's text format into
// this form without exposing credentials through logs or diagnostics.
type RuntimeConfig struct {
	ClientMaxMessageSize   int64
	UpstreamMaxMessageSize int64
	ClientMaxPending       int
	WriteCoherence         time.Duration
	NetworkTimeout         time.Duration
	IOTimeout              time.Duration
	ClientIdleTimeout      time.Duration
	ProxyAuthz             bool
	VerifyCredentials      bool
	ReadPause              bool
	MonitorAccess          []string
	PrivilegedIdentity     string
	UpstreamKeepAliveSet   bool
	UpstreamKeepAlive      net.KeepAliveConfig
	UpstreamTCPUserTimeout time.Duration
	RestrictExtended       map[string]RuntimeRestriction
	RestrictControls       map[string]RuntimeRestriction
	Bind                   RuntimeBindConfig
	Tiers                  []RuntimeTierConfig
	ClientTLS              *tls.Config
	BackendTLS             *tls.Config
	Logger                 *slog.Logger
	DialContext            DialContextFunc
}

type RuntimeRestriction uint8

const (
	RuntimeRestrictionNone RuntimeRestriction = iota
	RuntimeRestrictionWrite
	RuntimeRestrictionBackend
	RuntimeRestrictionConnection
	RuntimeRestrictionIsolate
	RuntimeRestrictionReject
)

type RuntimeBindConfig struct {
	Method             string
	DN                 string
	Credentials        []byte
	SASLMechanism      string
	AuthenticationID   string
	AuthorizationID    string
	Realm              string
	SecurityProperties string
	Timeout            time.Duration
}

type RuntimeTierConfig struct {
	Strategy string
	Backends []RuntimeBackendConfig
}

type RuntimeBackendConfig struct {
	URI                  string
	RegularConnections   int
	BindConnections      int
	Retry                time.Duration
	MaxPendingOperations int
	ConnectionMaxPending int
	Weight               int
	StartTLS             bool
	StartTLSCritical     bool
}

type Proxy struct {
	config    RuntimeConfig
	codec     frameCodec
	tiers     []*runtimeTier
	scheduler *Scheduler

	ctx    context.Context
	cancel context.CancelFunc

	mu                   sync.Mutex
	listener             net.Listener
	clients              map[*clientConnection]struct{}
	clientWake           chan struct{}
	upstreams            map[string]*upstreamConnection
	started              bool
	draining             bool
	closed               bool
	connections          sync.WaitGroup
	backends             sync.WaitGroup
	shutdownOnce         sync.Once
	shutdownDone         chan struct{}
	nextClientID         atomic.Uint64
	operations           [2]monitorCounters
	monitorSchema        *schema.Registry
	monitorAccess        *acl.Policy
	monitorSnapshotBytes atomic.Int64
}

type runtimeTier struct {
	backends []*runtimeBackend
}

type runtimeBackend struct {
	proxy  *Proxy
	tier   *runtimeTier
	id     string
	index  int
	config RuntimeBackendConfig

	mu      sync.RWMutex
	regular []*upstreamConnection
	bind    []*upstreamConnection
	closed  bool
	done    chan struct{}
	monitor monitorCounters
}

type upstreamConnection struct {
	backend *runtimeBackend
	id      string
	bind    bool
	conn    net.Conn

	mu              sync.Mutex
	writeMu         sync.Mutex
	pending         map[int64]*proxyOperation
	nextID          int64
	owner           *clientConnection
	ownerGeneration uint64
	closed          bool
	once            sync.Once
	done            chan struct{}
	retired         chan struct{}
	monitor         monitorCounters
	created         time.Time
}

type backendConnectFunc func(
	context.Context,
	string,
	bool,
) (*upstreamConnection, error)

type clientConnection struct {
	proxy *Proxy
	conn  net.Conn

	metadata             ConnectionMetadata
	id                   uint64
	created              time.Time
	monitor              monitorCounters
	monitorSnapshots     map[string]*monitorSnapshot
	monitorSnapshotBytes int64

	writeMu      sync.Mutex
	mu           sync.Mutex
	closed       bool
	draining     bool
	done         chan struct{}
	readWake     chan struct{}
	binding      bool
	bindPin      *upstreamConnection
	authzID      []byte
	authcID      []byte
	saslMech     string
	transportSSF int
	saslSSF      int
	ops          map[int64]*proxyOperation

	restriction      RuntimeRestriction
	backendAffinity  *runtimeBackend
	upstreamAffinity *upstreamConnection
	writeInflight    int
	writeCompletedAt time.Time
	bindGeneration   uint64
	protocolVersion  int
	tlsActive        bool
	tlsUpgrading     bool
	tlsSSF           int
}

type proxyOperation struct {
	mu                sync.Mutex
	responseMu        sync.Mutex
	client            *clientConnection
	clientID          int64
	requestTag        uint64
	upstream          *upstreamConnection
	upstreamID        int64
	lease             *Lease
	restriction       RuntimeRestriction
	bind              bool
	bindSASL          bool
	bindAuthcID       string
	bindAuthzID       string
	bindSASLMechanism string
	verifyCredentials bool
	bindDN            string
	bindGeneration    uint64
	cancel            bool
	cancelTarget      *proxyOperation
	cancelInFlight    bool
	requestSent       bool
	abandoning        bool
	started           time.Time
	firstSeen         atomic.Bool
	finished          atomic.Bool
}

type frameCodec interface {
	Read(io.Reader, int64) (proxyFrame, error)
	RewriteMessageID(proxyFrame, int64) ([]byte, error)
	RewriteAbandon(proxyFrame, int64, int64) ([]byte, error)
	RewriteExtendedRequestValue(proxyFrame, int64, []byte) ([]byte, error)
	EncodeAbandon(int64, int64) ([]byte, error)
	PrependProxyAuthz(proxyFrame, int64, []byte) ([]byte, error)
	EncodeResult(int64, uint64, ldapwire.ResultCode, string) ([]byte, error)
}

type proxyFrame struct {
	Raw              []byte
	MessageID        int64
	ProtocolTag      uint64
	Controls         []string
	ExtendedOID      string
	ExtendedValue    RawBER
	HasExtendedValue bool
	AbandonID        int64
	BindVersion      int
	BindDN           string
	BindSASL         bool
	BindMechanism    string
	BindAuthcID      string
	BindAuthzID      string
	ResultCode       ldapwire.ResultCode
	HasResultCode    bool
	FinalResponse    bool
}

type trackedUpstreamConnection struct {
	net.Conn
	upstream *upstreamConnection
}

func (connection *trackedUpstreamConnection) NetConn() net.Conn {
	return connection.Conn
}

// runtimeFrameCodec translates the experimental Verify Credentials exchange
// at the transport boundary. The ordinary response state machine therefore
// continues to see a strict BindResponse and cannot accidentally forward an
// ExtendedResponse to a Bind request.
type runtimeFrameCodec struct {
	frameCodec
}

func (codec runtimeFrameCodec) Read(reader io.Reader, max int64) (proxyFrame, error) {
	frame, err := codec.frameCodec.Read(reader, max)
	if err != nil {
		return proxyFrame{}, err
	}
	connection, ok := reader.(*trackedUpstreamConnection)
	if !ok || connection.upstream == nil || frame.MessageID == 0 {
		return frame, nil
	}
	connection.upstream.mu.Lock()
	operation := connection.upstream.pending[frame.MessageID]
	connection.upstream.mu.Unlock()
	if operation == nil || !operation.verifyCredentials {
		return frame, nil
	}
	return translateVerifyCredentialsResponse(frame, operation)
}

func translateVerifyCredentialsResponse(
	frame proxyFrame,
	operation *proxyOperation,
) (proxyFrame, error) {
	if frame.ProtocolTag != ldapwire.ApplicationExtendedResponse || !frame.HasResultCode {
		return proxyFrame{}, errors.New("Verify Credentials backend returned a non-ExtendedResponse")
	}
	parsed, err := parseProxyFrame(frame)
	if err != nil {
		return proxyFrame{}, fmt.Errorf("parse Verify Credentials response: %w", err)
	}
	protocol := []byte(parsed.ProtocolOp)
	outer, next, err := parseElement(protocol, 0)
	if err != nil || next != len(protocol) ||
		!elementIs(outer, berClassApplication, true, ldapwire.ApplicationExtendedResponse) {
		return proxyFrame{}, errors.New("Verify Credentials backend returned a malformed ExtendedResponse")
	}
	cursor := outer.contentStart
	resultStart := cursor
	for index, expectedTag := range []uint64{berTagEnumerated, berTagOctetString, berTagOctetString} {
		field, fieldEnd, fieldErr := parseElement(protocol, cursor)
		if fieldErr != nil || !elementIs(field, berClassUniversal, false, expectedTag) {
			return proxyFrame{}, fmt.Errorf("Verify Credentials response has invalid LDAPResult field %d", index)
		}
		cursor = fieldEnd
	}
	resultEnd := cursor
	if frame.ResultCode != ldapwire.ResultSuccess {
		if cursor < outer.end {
			referral, referralEnd, referralErr := parseElement(protocol, cursor)
			if referralErr == nil && elementIs(referral, berClassContext, true, 3) {
				resultEnd = referralEnd
			}
		}
		return readTranslatedBindResponse(encodeFrame(
			frame.MessageID,
			encodeTLV(0x61, bytes.Clone(protocol[resultStart:resultEnd])),
			bytes.Clone(parsed.ControlsRaw),
		))
	}
	if len(parsed.ControlsRaw) != 0 {
		return proxyFrame{}, errors.New("Verify Credentials response contains unsupported outer controls")
	}

	var responseValue []byte
	seenName := false
	for cursor < outer.end {
		field, fieldEnd, fieldErr := parseElement(protocol, cursor)
		if fieldErr != nil {
			return proxyFrame{}, fmt.Errorf("parse Verify Credentials response field: %w", fieldErr)
		}
		switch {
		case elementIs(field, berClassContext, false, 10):
			if seenName || responseValue != nil {
				return proxyFrame{}, errors.New("Verify Credentials response has duplicate or out-of-order responseName")
			}
			seenName = true
			name := string(protocol[field.contentStart:field.end])
			if name != "" && name != verifyCredentialsOID {
				return proxyFrame{}, fmt.Errorf("Verify Credentials responseName %q is not supported", name)
			}
		case elementIs(field, berClassContext, false, 11):
			if responseValue != nil {
				return proxyFrame{}, errors.New("Verify Credentials response has duplicate responseValue")
			}
			responseValue = bytes.Clone(protocol[field.contentStart:field.end])
		default:
			return proxyFrame{}, errors.New("Verify Credentials response contains an unexpected field")
		}
		cursor = fieldEnd
	}
	if responseValue == nil {
		return proxyFrame{}, errors.New("Verify Credentials success response has no responseValue")
	}
	return translateVerifyCredentialsValue(frame.MessageID, responseValue, operation)
}

func translateVerifyCredentialsValue(
	messageID int64,
	value []byte,
	operation *proxyOperation,
) (proxyFrame, error) {
	sequence, next, err := parseElement(value, 0)
	if err != nil || next != len(value) ||
		!elementIs(sequence, berClassUniversal, true, berTagSequence) {
		return proxyFrame{}, errors.New("Verify Credentials responseValue is not a BER sequence")
	}
	cursor := sequence.contentStart
	result, fieldEnd, err := parseElement(value, cursor)
	if err != nil || result.class != berClassUniversal || result.constructed ||
		(result.tag != berTagInteger && result.tag != berTagEnumerated) {
		return proxyFrame{}, errors.New("Verify Credentials responseValue has an invalid resultCode")
	}
	code, err := decodeNonnegativeInteger(value[result.contentStart:result.end], MaxMessageID)
	if err != nil {
		return proxyFrame{}, errors.New("Verify Credentials responseValue has an invalid resultCode")
	}
	cursor = fieldEnd
	diagnostic, fieldEnd, err := parseElement(value, cursor)
	if err != nil || !elementIs(diagnostic, berClassUniversal, false, berTagOctetString) ||
		!utf8.Valid(value[diagnostic.contentStart:diagnostic.end]) {
		return proxyFrame{}, errors.New("Verify Credentials responseValue has an invalid diagnosticMessage")
	}
	diagnosticValue := bytes.Clone(value[diagnostic.contentStart:diagnostic.end])
	cursor = fieldEnd

	var cookie, serverCredentials, controls []byte
	for cursor < sequence.end {
		field, nextField, fieldErr := parseElement(value, cursor)
		if fieldErr != nil {
			return proxyFrame{}, fmt.Errorf("parse Verify Credentials responseValue: %w", fieldErr)
		}
		switch {
		case elementIs(field, berClassContext, false, 0) && cookie == nil && serverCredentials == nil && controls == nil:
			cookie = bytes.Clone(value[field.contentStart:field.end])
		case elementIs(field, berClassContext, false, 1) && serverCredentials == nil && controls == nil:
			serverCredentials = bytes.Clone(value[field.contentStart:field.end])
		case elementIs(field, berClassContext, true, 2) && controls == nil:
			controls = encodeTLV(0xa0, bytes.Clone(value[field.contentStart:field.end]))
		default:
			return proxyFrame{}, errors.New("Verify Credentials responseValue has duplicate or out-of-order fields")
		}
		cursor = nextField
	}
	resultCode := ldapwire.ResultCode(code)
	if resultCode == ldapwire.ResultSASLBindInProgress {
		return proxyFrame{}, errors.New("Verify Credentials SASL continuation is outside the supported simple-Bind subset")
	}
	bindFields := joinBER(
		encodeTLV(0x0a, encodeNonnegativeInteger(code)),
		encodeTLV(0x04, nil),
		encodeTLV(0x04, diagnosticValue),
	)
	if serverCredentials != nil {
		bindFields = append(bindFields, encodeTLV(0x87, serverCredentials)...)
	}
	return readTranslatedBindResponse(encodeFrame(
		messageID,
		encodeTLV(0x61, bindFields),
		controls,
	))
}

func readTranslatedBindResponse(encoded []byte) (proxyFrame, error) {
	translated, err := (berFrameCodec{}).Read(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		return proxyFrame{}, fmt.Errorf("encode Verify Credentials BindResponse: %w", err)
	}
	return translated, nil
}

func NewProxy(config RuntimeConfig) (*Proxy, error) {
	if config.ClientMaxMessageSize < 0 {
		return nil, errors.New("client maximum message size cannot be negative")
	}
	if config.ClientMaxMessageSize == 0 {
		config.ClientMaxMessageSize = defaultClientMessageSize
	}
	if config.UpstreamMaxMessageSize < 0 {
		return nil, errors.New("upstream maximum message size cannot be negative")
	}
	if config.UpstreamMaxMessageSize == 0 {
		config.UpstreamMaxMessageSize = defaultUpstreamMessageSize
	}
	if config.ClientMaxPending < 0 {
		return nil, errors.New("client maximum pending operations cannot be negative")
	}
	if config.WriteCoherence < 0 && config.WriteCoherence != -1 {
		return nil, errors.New("write coherence must be non-negative or -1")
	}
	if config.NetworkTimeout < 0 {
		return nil, errors.New("network timeout cannot be negative")
	}
	if config.IOTimeout < 0 {
		return nil, errors.New("I/O timeout cannot be negative")
	}
	if config.ClientIdleTimeout < 0 {
		return nil, errors.New("client idle timeout cannot be negative")
	}
	if config.Bind.Timeout < 0 {
		return nil, errors.New("upstream bind timeout cannot be negative")
	}
	if err := validateRuntimeSocketOptions(config); err != nil {
		return nil, err
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if config.DialContext == nil {
		dialer := &net.Dialer{Timeout: config.NetworkTimeout}
		config.DialContext = dialer.DialContext
	}
	if config.BackendTLS != nil {
		config.BackendTLS = config.BackendTLS.Clone()
	}
	if config.ClientTLS != nil {
		clientTLS, err := cloneClientTLSConfig(config.ClientTLS)
		if err != nil {
			return nil, err
		}
		config.ClientTLS = clientTLS
	}
	config.Bind.Credentials = append([]byte(nil), config.Bind.Credentials...)
	normalizedBind, bindErr := normalizeRuntimeServiceBind(config.Bind)
	if bindErr != nil {
		clear(config.Bind.Credentials)
		return nil, bindErr
	}
	config.Bind = normalizedBind
	config.RestrictExtended = cloneRuntimeRestrictions(config.RestrictExtended)
	config.RestrictControls = cloneRuntimeRestrictions(config.RestrictControls)
	for oid, restriction := range config.RestrictExtended {
		if restriction > RuntimeRestrictionReject {
			return nil, fmt.Errorf("extended-operation restriction %s is invalid", oid)
		}
	}
	for oid, restriction := range config.RestrictControls {
		if restriction > RuntimeRestrictionReject {
			return nil, fmt.Errorf("control restriction %s is invalid", oid)
		}
	}
	if config.Bind.Method != "" && !config.ProxyAuthz {
		return nil, errors.New("upstream service bind requires ProxyAuthz")
	}
	if config.VerifyCredentials && !config.ProxyAuthz {
		return nil, errors.New("Verify Credentials requires ProxyAuthz")
	}
	monitorSchema, monitorAccess, err := newMonitorRuntime(config.MonitorAccess)
	if err != nil {
		return nil, err
	}

	proxy := &Proxy{
		config:        config,
		clients:       make(map[*clientConnection]struct{}),
		clientWake:    make(chan struct{}),
		upstreams:     make(map[string]*upstreamConnection),
		shutdownDone:  make(chan struct{}),
		monitorSchema: monitorSchema,
		monitorAccess: monitorAccess,
	}
	proxy.codec = runtimeFrameCodec{frameCodec: berFrameCodec{}}
	schedulerConfig := SchedulerConfig{}
	for tierIndex, tierConfig := range config.Tiers {
		strategy := strings.ToLower(strings.TrimSpace(tierConfig.Strategy))
		switch strategy {
		case "roundrobin", "weighted", "bestof":
		default:
			return nil, fmt.Errorf("tier %d has unsupported strategy %q", tierIndex, tierConfig.Strategy)
		}
		tier := &runtimeTier{}
		schedulerTier := SchedulerTierConfig{
			ID:     fmt.Sprintf("tier-%d", tierIndex),
			Policy: Policy(strategy),
		}
		for backendIndex, backendConfig := range tierConfig.Backends {
			normalized, err := normalizeRuntimeBackendConfig(backendConfig)
			if err != nil {
				return nil, fmt.Errorf("tier %d backend %d: %w", tierIndex, backendIndex, err)
			}
			if (runtimeLDAPURLScheme(normalized.URI) == "ldaps" || normalized.StartTLS) &&
				config.BackendTLS == nil {
				return nil, fmt.Errorf(
					"tier %d backend %d: TLS requires a backend TLS configuration",
					tierIndex,
					backendIndex,
				)
			}
			if runtimeLDAPURLScheme(normalized.URI) != "ldapi" &&
				config.UpstreamTCPUserTimeout > 0 && runtime.GOOS != "linux" {
				return nil, fmt.Errorf(
					"tier %d backend %d: TCP_USER_TIMEOUT is not supported on %s",
					tierIndex,
					backendIndex,
					runtime.GOOS,
				)
			}
			backendID := fmt.Sprintf("%s-backend-%d", schedulerTier.ID, backendIndex)
			backend := &runtimeBackend{
				proxy:  proxy,
				tier:   tier,
				id:     backendID,
				index:  backendIndex,
				config: normalized,
				done:   make(chan struct{}),
			}
			schedulerBackend := SchedulerBackendConfig{
				ID:         backendID,
				Weight:     normalized.Weight,
				MaxPending: normalized.MaxPendingOperations,
			}
			for connectionIndex := 0; connectionIndex < normalized.RegularConnections; connectionIndex++ {
				schedulerBackend.Connections = append(
					schedulerBackend.Connections,
					SchedulerConnectionConfig{
						ID:         backendConnectionID(backendID, false, connectionIndex),
						Pool:       PoolRegular,
						State:      ConnectionUnavailable,
						MaxPending: normalized.ConnectionMaxPending,
					},
				)
			}
			bindConnections := normalized.BindConnections
			if config.VerifyCredentials {
				bindConnections = 0
			}
			for connectionIndex := 0; connectionIndex < bindConnections; connectionIndex++ {
				schedulerBackend.Connections = append(
					schedulerBackend.Connections,
					SchedulerConnectionConfig{
						ID:         backendConnectionID(backendID, true, connectionIndex),
						Pool:       PoolBind,
						State:      ConnectionUnavailable,
						MaxPending: 1,
					},
				)
			}
			schedulerTier.Backends = append(schedulerTier.Backends, schedulerBackend)
			tier.backends = append(tier.backends, backend)
		}
		schedulerConfig.Tiers = append(schedulerConfig.Tiers, schedulerTier)
		proxy.tiers = append(proxy.tiers, tier)
	}
	proxy.scheduler, err = NewScheduler(schedulerConfig)
	if err != nil {
		return nil, err
	}
	return proxy, nil
}

func cloneClientTLSConfig(config *tls.Config) (*tls.Config, error) {
	cloned := config.Clone()
	if len(cloned.Certificates) == 0 && cloned.GetCertificate == nil &&
		cloned.GetConfigForClient == nil {
		return nil, errors.New("client TLS configuration requires a server certificate")
	}
	for index, certificate := range cloned.Certificates {
		if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
			return nil, fmt.Errorf("client TLS certificate %d is incomplete", index)
		}
	}
	if !supportedTLSVersion(cloned.MinVersion) {
		return nil, fmt.Errorf("client TLS minimum version 0x%04x is invalid", cloned.MinVersion)
	}
	if !supportedTLSVersion(cloned.MaxVersion) {
		return nil, fmt.Errorf("client TLS maximum version 0x%04x is invalid", cloned.MaxVersion)
	}
	if cloned.MinVersion != 0 && cloned.MaxVersion != 0 &&
		cloned.MinVersion > cloned.MaxVersion {
		return nil, errors.New("client TLS minimum version exceeds maximum version")
	}
	return cloned, nil
}

func supportedTLSVersion(version uint16) bool {
	switch version {
	case 0, tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13:
		return true
	default:
		return false
	}
}

func cloneRuntimeRestrictions(
	source map[string]RuntimeRestriction,
) map[string]RuntimeRestriction {
	if len(source) == 0 {
		return nil
	}
	cloned := make(map[string]RuntimeRestriction, len(source))
	for oid, restriction := range source {
		cloned[oid] = restriction
	}
	return cloned
}

func backendConnectionID(backendID string, bind bool, index int) string {
	pool := "regular"
	if bind {
		pool = "bind"
	}
	return fmt.Sprintf("%s-%s-%d", backendID, pool, index)
}

func normalizeRuntimeBackendConfig(config RuntimeBackendConfig) (RuntimeBackendConfig, error) {
	scheme := runtimeLDAPURLScheme(config.URI)
	var parsed *url.URL
	var err error
	if scheme == "ldapi" {
		if _, err := ParseLDAPIAddress(config.URI); err != nil {
			return config, fmt.Errorf("parse URI: %w", err)
		}
	} else {
		parsed, err = url.Parse(config.URI)
		if err != nil {
			return config, fmt.Errorf("parse URI: %w", err)
		}
	}
	switch scheme {
	case "ldap", "ldaps", "ldapi":
	default:
		return config, fmt.Errorf("unsupported URI scheme %q", scheme)
	}
	if scheme != "ldapi" && parsed.Host == "" {
		return config, errors.New("backend URI has no host")
	}
	if config.RegularConnections < 0 || config.BindConnections < 0 {
		return config, errors.New("connection counts cannot be negative")
	}
	if config.RegularConnections == 0 {
		config.RegularConnections = 1
	}
	if config.BindConnections == 0 {
		config.BindConnections = 1
	}
	if config.Retry < 0 {
		return config, errors.New("retry interval cannot be negative")
	}
	if config.Retry == 0 {
		config.Retry = defaultBackendRetry
	}
	if config.MaxPendingOperations < 0 || config.ConnectionMaxPending < 0 {
		return config, errors.New("pending limits cannot be negative")
	}
	if config.Weight < 0 {
		return config, errors.New("weight cannot be negative")
	}
	if config.StartTLS && scheme != "ldap" {
		return config, errors.New("StartTLS requires an ldap URI")
	}
	if config.StartTLSCritical && !config.StartTLS {
		return config, errors.New("critical StartTLS requires StartTLS to be enabled")
	}
	return config, nil
}

func runtimeLDAPURLScheme(raw string) string {
	separator := strings.IndexByte(raw, ':')
	if separator <= 0 {
		return ""
	}
	return strings.ToLower(raw[:separator])
}

// Start activates the upstream topology without owning a listener. It is used
// by the standalone daemon so listener ownership can be swapped independently
// from connections already assigned to this proxy generation.
func (proxy *Proxy) Start(ctx context.Context) error {
	return proxy.start(ctx, nil)
}

func (proxy *Proxy) start(ctx context.Context, listener net.Listener) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	proxy.mu.Lock()
	if proxy.started {
		proxy.mu.Unlock()
		return errors.New("lloadd proxy has already been started")
	}
	if proxy.closed || proxy.draining {
		proxy.mu.Unlock()
		return ErrProxyClosed
	}
	proxy.started = true
	proxy.listener = listener
	proxy.ctx, proxy.cancel = context.WithCancel(ctx)
	proxy.mu.Unlock()

	for _, tier := range proxy.tiers {
		for _, backend := range tier.backends {
			proxy.backends.Add(1)
			go func(backend *runtimeBackend) {
				defer proxy.backends.Done()
				backend.maintain(proxy.ctx)
			}(backend)
		}
	}
	return nil
}

// ServeConnection assigns one accepted client connection to this proxy
// generation. The connection remains attached to this generation until it
// closes, even when the daemon publishes a newer topology.
func (proxy *Proxy) ServeConnection(connection net.Conn) error {
	if connection == nil {
		return errors.New("client connection is required")
	}
	proxy.mu.Lock()
	if !proxy.started {
		proxy.mu.Unlock()
		return errors.New("lloadd proxy has not been started")
	}
	if proxy.closed || proxy.draining {
		proxy.mu.Unlock()
		return ErrProxyClosed
	}
	ctx := proxy.ctx
	proxy.mu.Unlock()

	metadata, hasMetadata := MetadataFromConnection(connection)
	if !hasMetadata {
		metadata = ConnectionMetadata{
			SourceAddress:               connection.RemoteAddr(),
			DestinationAddress:          connection.LocalAddr(),
			TransportSourceAddress:      connection.RemoteAddr(),
			TransportDestinationAddress: connection.LocalAddr(),
		}
	}
	client := &clientConnection{
		proxy:            proxy,
		conn:             connection,
		metadata:         metadata,
		id:               proxy.nextClientID.Add(1),
		created:          time.Now().UTC(),
		ops:              make(map[int64]*proxyOperation),
		monitorSnapshots: make(map[string]*monitorSnapshot),
		done:             make(chan struct{}),
		readWake:         make(chan struct{}),
		protocolVersion:  3,
		transportSSF:     connectionTransportSSF(metadata.TransportSourceAddress),
	}
	client.tlsActive = connectionUsesTLS(connection)
	if hasMetadata {
		proxy.config.Logger.Debug(
			"accepted proxied lloadd client",
			"source", addressString(metadata.SourceAddress),
			"destination", addressString(metadata.DestinationAddress),
			"transport_source", addressString(metadata.TransportSourceAddress),
			"transport_destination", addressString(metadata.TransportDestinationAddress),
			"local", metadata.ProxyProtocolLocal,
		)
	}
	proxy.mu.Lock()
	if proxy.closed || proxy.draining {
		proxy.mu.Unlock()
		return ErrProxyClosed
	}
	proxy.clients[client] = struct{}{}
	proxy.signalClientChangeLocked()
	proxy.connections.Add(1)
	proxy.mu.Unlock()
	go client.runMonitorSnapshotJanitor(monitorSnapshotCleanupInterval)
	go func() {
		defer proxy.connections.Done()
		client.serve(ctx)
	}()
	return nil
}

func (proxy *Proxy) signalClientChangeLocked() {
	close(proxy.clientWake)
	proxy.clientWake = make(chan struct{})
}

// WaitForIdle waits until all client sessions assigned to this generation have
// ended. It does not count upstream maintenance connections.
func (proxy *Proxy) WaitForIdle(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	for {
		proxy.mu.Lock()
		if len(proxy.clients) == 0 {
			proxy.mu.Unlock()
			return nil
		}
		wake := proxy.clientWake
		proxy.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
		}
	}
}

// Drain prevents new sessions, closes idle sessions immediately and lets
// already forwarded operations deliver their final responses. The context is
// the hard drain deadline; once it expires all remaining sessions are closed.
func (proxy *Proxy) Drain(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	proxy.mu.Lock()
	proxy.draining = true
	clients := make([]*clientConnection, 0, len(proxy.clients))
	for client := range proxy.clients {
		clients = append(clients, client)
	}
	proxy.mu.Unlock()
	for _, client := range clients {
		client.beginDrain()
	}
	if err := proxy.WaitForIdle(ctx); err != nil {
		proxy.mu.Lock()
		clients = clients[:0]
		for client := range proxy.clients {
			clients = append(clients, client)
		}
		proxy.mu.Unlock()
		for _, client := range clients {
			client.close()
		}
		return err
	}
	return nil
}

// Serve retains the original single-listener API.
func (proxy *Proxy) Serve(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("listener is required")
	}
	if err := proxy.start(ctx, listener); err != nil {
		return err
	}

	stopAccept := make(chan struct{})
	go func() {
		select {
		case <-proxy.ctx.Done():
			_ = listener.Close()
		case <-stopAccept:
		}
	}()
	defer close(stopAccept)

	for {
		connection, err := listener.Accept()
		if err != nil {
			if proxy.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				proxy.shutdown()
				return nil
			}
			proxy.shutdown()
			return fmt.Errorf("accept lloadd client: %w", err)
		}
		if err := proxy.ServeConnection(connection); err != nil {
			_ = connection.Close()
			if errors.Is(err, ErrProxyClosed) {
				continue
			}
			proxy.shutdown()
			return err
		}
	}
}

func connectionUsesTLS(connection net.Conn) bool {
	_, ok := connectionTLSState(connection)
	return ok
}

func connectionTLSState(connection net.Conn) (tls.ConnectionState, bool) {
	const maximumWrappers = 16
	for depth := 0; depth < maximumWrappers && connection != nil; depth++ {
		if secured, ok := connection.(*tls.Conn); ok {
			return secured.ConnectionState(), true
		}
		var next net.Conn
		switch wrapped := connection.(type) {
		case interface{ NetConn() net.Conn }:
			next = wrapped.NetConn()
		case interface{ Unwrap() net.Conn }:
			next = wrapped.Unwrap()
		default:
			return tls.ConnectionState{}, false
		}
		if next == nil || next == connection {
			return tls.ConnectionState{}, false
		}
		connection = next
	}
	return tls.ConnectionState{}, false
}

func tlsCipherSecurityStrength(state tls.ConnectionState) int {
	name := tls.CipherSuiteName(state.CipherSuite)
	switch {
	case strings.Contains(name, "CHACHA20"), strings.Contains(name, "AES_256"):
		return 256
	case strings.Contains(name, "AES_128"), strings.Contains(name, "RC4"):
		return 128
	case strings.Contains(name, "3DES"):
		return 112
	default:
		return 0
	}

}

func (client *clientConnection) refreshTLSSecurityStrength() {
	client.mu.Lock()
	connection := client.conn
	client.mu.Unlock()
	state, ok := connectionTLSState(connection)
	if !ok || !state.HandshakeComplete {
		return
	}
	client.mu.Lock()
	client.tlsActive = true
	client.tlsSSF = tlsCipherSecurityStrength(state)
	client.mu.Unlock()
}

func addressString(address net.Addr) string {
	if address == nil {
		return ""
	}
	return address.String()
}

func (proxy *Proxy) Close() error {
	proxy.mu.Lock()
	if proxy.closed {
		proxy.mu.Unlock()
		return nil
	}
	proxy.closed = true
	clearCredentials := !proxy.started
	listener := proxy.listener
	cancel := proxy.cancel
	proxy.mu.Unlock()
	if clearCredentials {
		clear(proxy.config.Bind.Credentials)
		proxy.config.Bind.Credentials = nil
	}
	if cancel != nil {
		cancel()
	}
	var err error
	if listener != nil {
		err = listener.Close()
	}
	proxy.shutdown()
	return err
}

func (proxy *Proxy) shutdown() {
	proxy.shutdownOnce.Do(func() {
		defer close(proxy.shutdownDone)
		proxy.mu.Lock()
		cancel := proxy.cancel
		if !proxy.closed {
			proxy.closed = true
		}
		clients := make([]*clientConnection, 0, len(proxy.clients))
		for client := range proxy.clients {
			clients = append(clients, client)
		}
		proxy.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		for _, client := range clients {
			client.close()
		}
		for _, tier := range proxy.tiers {
			for _, backend := range tier.backends {
				backend.close()
			}
		}
		proxy.connections.Wait()
		proxy.backends.Wait()
		clear(proxy.config.Bind.Credentials)
		proxy.config.Bind.Credentials = nil
	})
	<-proxy.shutdownDone
}

func (backend *runtimeBackend) maintain(ctx context.Context) {
	backend.maintainConnections(ctx, backend.connect)
}

func (backend *runtimeBackend) maintainConnections(
	ctx context.Context,
	connect backendConnectFunc,
) {
	maintainCtx, cancel := context.WithCancel(ctx)
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-maintainCtx.Done():
		case <-backend.done:
			cancel()
		}
	}()
	defer func() {
		cancel()
		<-watcherDone
	}()

	var workers sync.WaitGroup
	start := func(connectionID string, bind bool) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			backend.maintainConnection(maintainCtx, connectionID, bind, connect)
		}()
	}
	for index := 0; index < backend.config.RegularConnections; index++ {
		start(backendConnectionID(backend.id, false, index), false)
	}
	if !backend.proxy.config.VerifyCredentials {
		for index := 0; index < backend.config.BindConnections; index++ {
			start(backendConnectionID(backend.id, true, index), true)
		}
	}
	workers.Wait()
}

func (backend *runtimeBackend) maintainConnection(
	ctx context.Context,
	connectionID string,
	bind bool,
	connect backendConnectFunc,
) {
	for {
		backend.mu.RLock()
		closed := backend.closed
		backend.mu.RUnlock()
		if closed || ctx.Err() != nil {
			return
		}

		upstream, err := connect(ctx, connectionID, bind)
		if err == nil && upstream == nil {
			err = errors.New("backend connector returned a nil connection")
		}
		if err == nil {
			if upstream.retired == nil {
				upstream.retired = make(chan struct{})
			}
			backend.add(upstream)
			go upstream.readLoop(ctx)
			select {
			case <-ctx.Done():
				return
			case <-upstream.retired:
				continue
			}
		}
		if ctx.Err() != nil {
			return
		}
		backend.mu.RLock()
		closed = backend.closed
		backend.mu.RUnlock()
		if closed {
			return
		}
		backend.proxy.config.Logger.Debug(
			"lloadd backend connection failed",
			"uri", backend.config.URI,
			"connection", connectionID,
			"bind_pool", bind,
			"error", err,
		)
		timer := time.NewTimer(backend.config.Retry)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-timer.C:
		}
	}
}

func (backend *runtimeBackend) connect(
	ctx context.Context,
	connectionID string,
	bind bool,
) (*upstreamConnection, error) {
	connection, nextID, err := backend.dialForConnect(ctx)
	if err != nil {
		return nil, err
	}
	stopCancellation := interruptConnectionOnContext(ctx, connection)
	defer stopCancellation()
	if !bind && backend.proxy.config.Bind.Method != "" {
		if timeout := backend.proxy.config.Bind.Timeout; timeout > 0 {
			if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
				_ = connection.Close()
				return nil, fmt.Errorf("set service Bind deadline: %w", err)
			}
			defer connection.SetDeadline(time.Time{})
		}
		switch backend.proxy.config.Bind.Method {
		case "simple":
			bindCredentials := append([]byte(nil), backend.proxy.config.Bind.Credentials...)
			bindRequest, encodeErr := ldapwire.EncodeRequestMessage(ldapwire.Message{
				ID: nextID,
				Request: ldapwire.BindRequest{
					Version: 3,
					Name:    backend.proxy.config.Bind.DN,
					Authentication: ldapwire.Authentication{
						Simple: bindCredentials,
					},
				},
			})
			clear(bindCredentials)
			if encodeErr != nil {
				_ = connection.Close()
				return nil, fmt.Errorf("encode service Bind: %w", encodeErr)
			}
			if err := writeConnection(connection, bindRequest, backend.proxy.config.IOTimeout); err != nil {
				clear(bindRequest)
				_ = connection.Close()
				return nil, fmt.Errorf("write service Bind: %w", err)
			}
			clear(bindRequest)
			response, readErr := backend.proxy.codec.Read(
				connection,
				backend.proxy.config.UpstreamMaxMessageSize,
			)
			if readErr != nil {
				_ = connection.Close()
				return nil, fmt.Errorf("read service Bind: %w", readErr)
			}
			if response.MessageID != nextID {
				_ = connection.Close()
				return nil, fmt.Errorf(
					"service Bind response message ID %d does not match request %d",
					response.MessageID,
					nextID,
				)
			}
			if response.ProtocolTag != ldapwire.ApplicationBindResponse ||
				!response.HasResultCode || response.ResultCode != ldapwire.ResultSuccess {
				_ = connection.Close()
				return nil, fmt.Errorf("service Bind failed with LDAP result %d", response.ResultCode)
			}
			nextID++
		case "sasl":
			if err := backend.bindServiceSASL(connection, &nextID); err != nil {
				_ = connection.Close()
				return nil, err
			}
		}
	}
	upstream := &upstreamConnection{
		backend: backend,
		id:      connectionID,
		bind:    bind,
		conn:    connection,
		pending: make(map[int64]*proxyOperation),
		nextID:  nextID,
		done:    make(chan struct{}),
		retired: make(chan struct{}),
		created: time.Now().UTC(),
	}
	upstream.conn = &trackedUpstreamConnection{Conn: connection, upstream: upstream}
	return upstream, nil
}

func (backend *runtimeBackend) dial(ctx context.Context) (net.Conn, error) {
	connection, _, err := backend.dialForConnect(ctx)
	return connection, err
}

func (backend *runtimeBackend) dialForConnect(ctx context.Context) (net.Conn, int64, error) {
	scheme := runtimeLDAPURLScheme(backend.config.URI)
	var parsed *url.URL
	var err error
	if scheme != "ldapi" {
		parsed, err = url.Parse(backend.config.URI)
		if err != nil {
			return nil, 0, err
		}
	}
	var network, address string
	switch scheme {
	case "ldap", "ldaps":
		network = "tcp"
		address = parsed.Host
		if _, _, err := net.SplitHostPort(address); err != nil {
			port := "389"
			if scheme == "ldaps" {
				port = "636"
			}
			address = net.JoinHostPort(parsed.Hostname(), port)
		}
	case "ldapi":
		network = "unix"
		address, err = ParseLDAPIAddress(backend.config.URI)
		if err != nil {
			return nil, 0, fmt.Errorf("decode ldapi path: %w", err)
		}
		if address == "" {
			address = filepath.FromSlash("/var/run/slapd/ldapi")
		}
	}
	connection, err := backend.proxy.config.DialContext(ctx, network, address)
	if err != nil {
		return nil, 0, err
	}
	if connection == nil {
		return nil, 0, errors.New("backend dial returned a nil connection")
	}
	if scheme != "ldapi" {
		if err := backend.configureTCPSocket(connection); err != nil {
			_ = connection.Close()
			return nil, 0, fmt.Errorf("configure backend TCP socket: %w", err)
		}
	}
	nextID := serviceBindMessageID
	stopCancellation := interruptConnectionOnContext(ctx, connection)
	defer stopCancellation()
	if scheme == "ldaps" {
		secured, err := backend.secureConnection(ctx, connection, parsed.Hostname(), "LDAPS")
		if err != nil {
			_ = connection.Close()
			return nil, 0, err
		}
		connection = secured
	}
	if backend.config.StartTLS {
		secured, accepted, err := backend.startTLS(ctx, connection, parsed.Hostname(), nextID)
		if err != nil {
			_ = connection.Close()
			return nil, 0, err
		}
		nextID++
		if accepted {
			connection = secured
		}
	}
	return connection, nextID, nil
}

func validateRuntimeSocketOptions(config RuntimeConfig) error {
	if config.UpstreamKeepAliveSet {
		keepalive := config.UpstreamKeepAlive
		if !keepalive.Enable {
			return errors.New("upstream keepalive configuration must enable keepalive")
		}
		if keepalive.Idle < -1 || keepalive.Interval < -1 || keepalive.Count < -1 {
			return errors.New("upstream keepalive values must be positive, zero, or -1")
		}
	}
	timeout := config.UpstreamTCPUserTimeout
	if timeout < 0 {
		return errors.New("upstream TCP user timeout cannot be negative")
	}
	if timeout == 0 {
		return nil
	}
	if timeout%time.Millisecond != 0 || timeout < time.Millisecond {
		return errors.New("upstream TCP user timeout must be a positive whole number of milliseconds")
	}
	if timeout/time.Millisecond > time.Duration(math.MaxInt32) {
		return errors.New("upstream TCP user timeout exceeds the platform integer limit")
	}
	return nil
}

func (backend *runtimeBackend) configureTCPSocket(connection net.Conn) error {
	config := backend.proxy.config
	if !config.UpstreamKeepAliveSet && config.UpstreamTCPUserTimeout == 0 {
		return nil
	}
	tcpConnection, err := unwrapTCPConnection(connection)
	if err != nil {
		return err
	}
	if config.UpstreamKeepAliveSet {
		if err := tcpConnection.SetKeepAliveConfig(config.UpstreamKeepAlive); err != nil {
			return fmt.Errorf("set keepalive: %w", err)
		}
	}
	if config.UpstreamTCPUserTimeout > 0 {
		if err := setTCPUserTimeout(tcpConnection, config.UpstreamTCPUserTimeout); err != nil {
			return fmt.Errorf("set TCP_USER_TIMEOUT: %w", err)
		}
	}
	return nil
}

func unwrapTCPConnection(connection net.Conn) (*net.TCPConn, error) {
	const maximumWrappers = 16
	for depth := 0; depth < maximumWrappers; depth++ {
		if connection == nil {
			return nil, errors.New("connection wrapper returned a nil connection")
		}
		if tcpConnection, ok := connection.(*net.TCPConn); ok {
			return tcpConnection, nil
		}
		var next net.Conn
		switch wrapped := connection.(type) {
		case interface{ NetConn() net.Conn }:
			next = wrapped.NetConn()
		case interface{ Unwrap() net.Conn }:
			next = wrapped.Unwrap()
		default:
			return nil, fmt.Errorf("connection type %T does not expose an underlying *net.TCPConn", connection)
		}
		if next == connection {
			return nil, fmt.Errorf("connection type %T unwraps to itself", connection)
		}
		connection = next
	}
	return nil, errors.New("connection wrapper depth exceeds 16")
}

func setTCPUserTimeout(connection *net.TCPConn, timeout time.Duration) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("TCP_USER_TIMEOUT is not supported on %s", runtime.GOOS)
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return fmt.Errorf("access socket descriptor: %w", err)
	}
	var optionErr error
	if err := raw.Control(func(fileDescriptor uintptr) {
		setter, ok := any(syscall.SetsockoptInt).(func(int, int, int, int) error)
		if !ok {
			optionErr = errors.New("platform setsockopt ABI is not supported")
			return
		}
		const (
			ipProtocolTCP        = 6
			tcpUserTimeoutOption = 18
		)
		optionErr = setter(
			int(fileDescriptor),
			ipProtocolTCP,
			tcpUserTimeoutOption,
			int(timeout/time.Millisecond),
		)
	}); err != nil {
		return err
	}
	return optionErr
}

func (backend *runtimeBackend) startTLS(
	ctx context.Context,
	connection net.Conn,
	serverName string,
	messageID int64,
) (net.Conn, bool, error) {
	request, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: messageID,
		Request: ldapwire.ExtendedRequest{
			Name: upstreamStartTLSOID,
		},
	})
	if err != nil {
		return nil, false, fmt.Errorf("encode StartTLS request: %w", err)
	}
	clearDeadline, err := setConnectionNegotiationDeadline(
		ctx,
		connection,
		backend.proxy.config.IOTimeout,
	)
	if err != nil {
		return nil, false, fmt.Errorf("set StartTLS deadline: %w", err)
	}
	defer clearDeadline()
	if err := ldapwire.Write(connection, request); err != nil {
		return nil, false, fmt.Errorf("write StartTLS request: %w", err)
	}
	response, err := backend.proxy.codec.Read(
		connection,
		backend.proxy.config.UpstreamMaxMessageSize,
	)
	if err != nil {
		return nil, false, fmt.Errorf("read StartTLS response: %w", err)
	}
	if response.MessageID != messageID {
		return nil, false, fmt.Errorf(
			"StartTLS response message ID %d does not match request %d",
			response.MessageID,
			messageID,
		)
	}
	if response.ProtocolTag != ldapwire.ApplicationExtendedResponse || !response.HasResultCode {
		return nil, false, errors.New("StartTLS response is not a valid ExtendedResponse")
	}
	if err := validateStartTLSResponseName(response.Raw); err != nil {
		return nil, false, err
	}
	if response.ResultCode != ldapwire.ResultSuccess {
		if backend.config.StartTLSCritical {
			return nil, false, fmt.Errorf(
				"critical StartTLS failed with LDAP result %d",
				response.ResultCode,
			)
		}
		return connection, false, nil
	}
	secured, err := backend.secureConnection(ctx, connection, serverName, "StartTLS")
	if err != nil {
		return nil, false, err
	}
	return secured, true, nil
}

func (backend *runtimeBackend) secureConnection(
	ctx context.Context,
	connection net.Conn,
	serverName string,
	label string,
) (net.Conn, error) {
	if backend.proxy.config.BackendTLS == nil {
		return nil, fmt.Errorf("%s backend requires a TLS configuration", label)
	}
	tlsConfig := backend.proxy.config.BackendTLS.Clone()
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = serverName
	}
	if verifyConnection := tlsConfig.VerifyConnection; verifyConnection != nil {
		expectedServerName := tlsConfig.ServerName
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if state.ServerName == "" {
				state.ServerName = expectedServerName
			}
			return verifyConnection(state)
		}
	}
	secured := tls.Client(connection, tlsConfig)
	clearDeadline, err := setConnectionNegotiationDeadline(
		ctx,
		secured,
		backend.proxy.config.IOTimeout,
	)
	if err != nil {
		return nil, fmt.Errorf("set %s handshake deadline: %w", label, err)
	}
	defer clearDeadline()
	if err := secured.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("%s handshake: %w", label, err)
	}
	return secured, nil
}

func setConnectionNegotiationDeadline(
	ctx context.Context,
	connection net.Conn,
	timeout time.Duration,
) (func(), error) {
	deadline, hasDeadline := ctx.Deadline()
	if timeout > 0 {
		ioDeadline := time.Now().Add(timeout)
		if !hasDeadline || ioDeadline.Before(deadline) {
			deadline = ioDeadline
			hasDeadline = true
		}
	}
	if !hasDeadline {
		return func() {}, nil
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	return func() { _ = connection.SetDeadline(time.Time{}) }, nil
}

func validateStartTLSResponseName(raw []byte) error {
	frame, err := ParseFrame(raw, defaultUpstreamMessageSize)
	if err != nil {
		return fmt.Errorf("parse StartTLS response: %w", err)
	}
	protocol, next, err := parseElement(frame.ProtocolOp, 0)
	if err != nil || next != len(frame.ProtocolOp) ||
		!elementIs(protocol, berClassApplication, true, TagExtendedResponse) {
		return errors.New("StartTLS response is not a valid ExtendedResponse")
	}
	cursor := protocol.contentStart
	for index, expectedTag := range []uint64{berTagEnumerated, berTagOctetString, berTagOctetString} {
		field, fieldEnd, fieldErr := parseElement(frame.ProtocolOp, cursor)
		if fieldErr != nil || !elementIs(field, berClassUniversal, false, expectedTag) {
			return fmt.Errorf("StartTLS response has invalid LDAPResult field %d", index)
		}
		cursor = fieldEnd
	}
	seenReferral := false
	seenResponseName := false
	seenResponseValue := false
	for cursor < protocol.end {
		field, fieldEnd, fieldErr := parseElement(frame.ProtocolOp, cursor)
		if fieldErr != nil {
			return fmt.Errorf("parse StartTLS response field: %w", fieldErr)
		}
		switch {
		case elementIs(field, berClassContext, true, 3):
			if seenReferral || seenResponseName || seenResponseValue {
				return errors.New("StartTLS response contains an out-of-order referral")
			}
			seenReferral = true
		case elementIs(field, berClassContext, false, 10):
			if seenResponseName || seenResponseValue {
				return errors.New("StartTLS response contains an invalid responseName")
			}
			if string(frame.ProtocolOp[field.contentStart:field.end]) != upstreamStartTLSOID {
				return fmt.Errorf(
					"StartTLS response OID %q does not match %s",
					string(frame.ProtocolOp[field.contentStart:field.end]),
					upstreamStartTLSOID,
				)
			}
			seenResponseName = true
		case elementIs(field, berClassContext, false, 11):
			if seenResponseValue {
				return errors.New("StartTLS response contains duplicate responseValue")
			}
			seenResponseValue = true
		default:
			return errors.New("StartTLS response contains an unexpected field")
		}
		cursor = fieldEnd
	}
	return nil
}

func (backend *runtimeBackend) add(upstream *upstreamConnection) {
	backend.mu.Lock()
	if backend.closed {
		backend.mu.Unlock()
		_ = upstream.conn.Close()
		return
	}
	if upstream.bind {
		backend.bind = append(backend.bind, upstream)
	} else {
		backend.regular = append(backend.regular, upstream)
	}
	backend.mu.Unlock()
	backend.proxy.mu.Lock()
	backend.proxy.upstreams[upstream.id] = upstream
	backend.proxy.mu.Unlock()
	if err := backend.proxy.scheduler.SetConnectionState(upstream.id, ConnectionReady); err != nil {
		upstream.closeWithError(err)
	}
}

func (backend *runtimeBackend) remove(upstream *upstreamConnection) {
	_ = backend.proxy.scheduler.SetConnectionState(upstream.id, ConnectionUnavailable)
	backend.proxy.mu.Lock()
	if backend.proxy.upstreams[upstream.id] == upstream {
		delete(backend.proxy.upstreams, upstream.id)
	}
	backend.proxy.mu.Unlock()
	backend.mu.Lock()
	pool := &backend.regular
	if upstream.bind {
		pool = &backend.bind
	}
	for index, candidate := range *pool {
		if candidate == upstream {
			copy((*pool)[index:], (*pool)[index+1:])
			*pool = (*pool)[:len(*pool)-1]
			break
		}
	}
	backend.mu.Unlock()
	if upstream.retired != nil {
		close(upstream.retired)
	}
}

func (backend *runtimeBackend) close() {
	backend.mu.Lock()
	if backend.closed {
		backend.mu.Unlock()
		return
	}
	backend.closed = true
	if backend.done != nil {
		close(backend.done)
	}
	connections := append([]*upstreamConnection(nil), backend.regular...)
	connections = append(connections, backend.bind...)
	backend.regular = nil
	backend.bind = nil
	backend.mu.Unlock()
	for _, connection := range connections {
		connection.closeWithError(ErrProxyClosed)
	}
}

func writeConnection(connection net.Conn, encoded []byte, timeout time.Duration) error {
	if timeout > 0 {
		if err := connection.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		defer connection.SetWriteDeadline(time.Time{})
	}
	return ldapwire.Write(connection, encoded)
}

func interruptConnectionOnContext(ctx context.Context, connection net.Conn) func() {
	stopped := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-stopped:
		}
	}()
	return func() {
		close(stopped)
		<-exited
	}
}
