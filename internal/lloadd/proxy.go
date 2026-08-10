package lloadd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	defaultClientMessageSize   = int64((1 << 24) - 1)
	defaultUpstreamMessageSize = int64((1 << 24) - 1)
	defaultBackendRetry        = 5 * time.Second
	serviceBindMessageID       = int64(1)
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
	ProxyAuthz             bool
	PrivilegedIdentity     string
	RestrictExtended       map[string]RuntimeRestriction
	RestrictControls       map[string]RuntimeRestriction
	Bind                   RuntimeBindConfig
	Tiers                  []RuntimeTierConfig
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
	Method      string
	DN          string
	Credentials []byte
	Timeout     time.Duration
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
}

type Proxy struct {
	config    RuntimeConfig
	codec     frameCodec
	tiers     []*runtimeTier
	scheduler *Scheduler

	ctx    context.Context
	cancel context.CancelFunc

	mu          sync.Mutex
	listener    net.Listener
	clients     map[*clientConnection]struct{}
	upstreams   map[string]*upstreamConnection
	started     bool
	closed      bool
	connections sync.WaitGroup
	backends    sync.WaitGroup
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
}

type backendConnectFunc func(
	context.Context,
	string,
	bool,
) (*upstreamConnection, error)

type clientConnection struct {
	proxy *Proxy
	conn  net.Conn

	writeMu sync.Mutex
	mu      sync.Mutex
	closed  bool
	done    chan struct{}
	binding bool
	bindPin *upstreamConnection
	authzID []byte
	ops     map[int64]*proxyOperation

	restriction      RuntimeRestriction
	backendAffinity  *runtimeBackend
	upstreamAffinity *upstreamConnection
	writeInflight    int
	writeCompletedAt time.Time
	bindGeneration   uint64
}

type proxyOperation struct {
	mu             sync.Mutex
	responseMu     sync.Mutex
	client         *clientConnection
	clientID       int64
	requestTag     uint64
	upstream       *upstreamConnection
	upstreamID     int64
	lease          *Lease
	restriction    RuntimeRestriction
	bind           bool
	bindSASL       bool
	bindDN         string
	bindGeneration uint64
	cancel         bool
	cancelTarget   *proxyOperation
	cancelInFlight bool
	requestSent    bool
	abandoning     bool
	started        time.Time
	firstSeen      atomic.Bool
	finished       atomic.Bool
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
	ResultCode       ldapwire.ResultCode
	HasResultCode    bool
	FinalResponse    bool
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
	if config.Bind.Timeout < 0 {
		return nil, errors.New("upstream bind timeout cannot be negative")
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
	config.Bind.Credentials = append([]byte(nil), config.Bind.Credentials...)
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
	if config.Bind.Method != "" && !strings.EqualFold(config.Bind.Method, "simple") {
		return nil, fmt.Errorf("unsupported upstream bind method %q", config.Bind.Method)
	}
	if config.Bind.DN != "" && len(config.Bind.Credentials) == 0 {
		return nil, errors.New("upstream simple bind credentials are required")
	}
	if config.Bind.DN != "" && !config.ProxyAuthz {
		return nil, errors.New("upstream service bind requires ProxyAuthz")
	}

	proxy := &Proxy{
		config:    config,
		codec:     berFrameCodec{},
		clients:   make(map[*clientConnection]struct{}),
		upstreams: make(map[string]*upstreamConnection),
	}
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
			if runtimeLDAPURLScheme(normalized.URI) == "ldaps" && config.BackendTLS == nil {
				return nil, fmt.Errorf(
					"tier %d backend %d: ldaps requires a backend TLS configuration",
					tierIndex,
					backendIndex,
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
			for connectionIndex := 0; connectionIndex < normalized.BindConnections; connectionIndex++ {
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
	var err error
	proxy.scheduler, err = NewScheduler(schedulerConfig)
	if err != nil {
		return nil, err
	}
	return proxy, nil
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
	if config.StartTLS {
		return config, errors.New("backend StartTLS is not implemented")
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

func (proxy *Proxy) Serve(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("listener is required")
	}
	proxy.mu.Lock()
	if proxy.started {
		proxy.mu.Unlock()
		return errors.New("lloadd proxy has already been started")
	}
	if proxy.closed {
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
		client := &clientConnection{
			proxy: proxy,
			conn:  connection,
			ops:   make(map[int64]*proxyOperation),
			done:  make(chan struct{}),
		}
		proxy.mu.Lock()
		if proxy.closed {
			proxy.mu.Unlock()
			_ = connection.Close()
			continue
		}
		proxy.clients[client] = struct{}{}
		proxy.mu.Unlock()
		proxy.connections.Add(1)
		go func() {
			defer proxy.connections.Done()
			client.serve(proxy.ctx)
		}()
	}
}

func (proxy *Proxy) Close() error {
	proxy.mu.Lock()
	if proxy.closed {
		proxy.mu.Unlock()
		return nil
	}
	proxy.closed = true
	listener := proxy.listener
	cancel := proxy.cancel
	proxy.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if listener != nil {
		return listener.Close()
	}
	return nil
}

func (proxy *Proxy) shutdown() {
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
	for index := 0; index < backend.config.BindConnections; index++ {
		start(backendConnectionID(backend.id, true, index), true)
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
	connection, err := backend.dial(ctx)
	if err != nil {
		return nil, err
	}
	stopCancellation := interruptConnectionOnContext(ctx, connection)
	defer stopCancellation()
	nextID := serviceBindMessageID
	if !bind && backend.proxy.config.Bind.DN != "" {
		if timeout := backend.proxy.config.Bind.Timeout; timeout > 0 {
			if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
				_ = connection.Close()
				return nil, fmt.Errorf("set service Bind deadline: %w", err)
			}
			defer connection.SetDeadline(time.Time{})
		}
		bindRequest, encodeErr := ldapwire.EncodeRequestMessage(ldapwire.Message{
			ID: serviceBindMessageID,
			Request: ldapwire.BindRequest{
				Version: 3,
				Name:    backend.proxy.config.Bind.DN,
				Authentication: ldapwire.Authentication{
					Simple: append([]byte(nil), backend.proxy.config.Bind.Credentials...),
				},
			},
		})
		if encodeErr != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("encode service Bind: %w", encodeErr)
		}
		if err := writeConnection(connection, bindRequest, backend.proxy.config.IOTimeout); err != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("write service Bind: %w", err)
		}
		response, readErr := backend.proxy.codec.Read(
			connection,
			backend.proxy.config.UpstreamMaxMessageSize,
		)
		if readErr != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("read service Bind: %w", readErr)
		}
		if response.MessageID != serviceBindMessageID {
			_ = connection.Close()
			return nil, fmt.Errorf(
				"service Bind response message ID %d does not match request %d",
				response.MessageID,
				serviceBindMessageID,
			)
		}
		if response.ProtocolTag != ldapwire.ApplicationBindResponse ||
			!response.HasResultCode || response.ResultCode != ldapwire.ResultSuccess {
			_ = connection.Close()
			return nil, fmt.Errorf("service Bind failed with LDAP result %d", response.ResultCode)
		}
		nextID = serviceBindMessageID + 1
	}
	return &upstreamConnection{
		backend: backend,
		id:      connectionID,
		bind:    bind,
		conn:    connection,
		pending: make(map[int64]*proxyOperation),
		nextID:  nextID,
		done:    make(chan struct{}),
		retired: make(chan struct{}),
	}, nil
}

func (backend *runtimeBackend) dial(ctx context.Context) (net.Conn, error) {
	scheme := runtimeLDAPURLScheme(backend.config.URI)
	var parsed *url.URL
	var err error
	if scheme != "ldapi" {
		parsed, err = url.Parse(backend.config.URI)
		if err != nil {
			return nil, err
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
			return nil, fmt.Errorf("decode ldapi path: %w", err)
		}
		if address == "" {
			address = filepath.FromSlash("/var/run/slapd/ldapi")
		}
	}
	connection, err := backend.proxy.config.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if connection == nil {
		return nil, errors.New("backend dial returned a nil connection")
	}
	if scheme == "ldaps" {
		if backend.proxy.config.BackendTLS == nil {
			_ = connection.Close()
			return nil, errors.New("ldaps backend requires a TLS configuration")
		}
		tlsConfig := backend.proxy.config.BackendTLS.Clone()
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = parsed.Hostname()
		}
		secured := tls.Client(connection, tlsConfig)
		if deadline, ok := ctx.Deadline(); ok {
			_ = secured.SetDeadline(deadline)
		}
		if err := secured.HandshakeContext(ctx); err != nil {
			_ = connection.Close()
			return nil, fmt.Errorf("LDAPS handshake: %w", err)
		}
		_ = secured.SetDeadline(time.Time{})
		connection = secured
	}
	if backend.config.StartTLS {
		_ = connection.Close()
		return nil, errors.New("backend StartTLS is not implemented")
	}
	return connection, nil
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
