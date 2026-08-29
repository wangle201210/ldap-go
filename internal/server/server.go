package server

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
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/audit"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/saslkrb5"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	defaultSearchLimit                = 1000
	defaultTransactionMaxOperations   = 1000
	defaultTransactionMaxQueuedBytes  = int64(16 << 20)
	defaultShutdownTimeout            = 30 * time.Second
	defaultMaxConnections             = 4096
	defaultMaxConcurrentOperations    = 256
	defaultMaxConcurrentHandshakes    = 64
	defaultMaxSearchCandidates        = 100000
	defaultMaxSearchCandidateBytes    = 64 << 20
	defaultMaxOperationsPerConnection = 8
)

var ErrShutdownTimeout = errors.New("graceful shutdown timed out")

type Config struct {
	Store                       storage.Store
	ListenerURLs                []string
	MaxMessageSize              int64
	MaxSearchEntries            int
	MaxTransactionOperations    int
	MaxTransactionQueuedBytes   int64
	MaxConnections              int
	MaxConcurrentOperations     int
	MaxConcurrentHandshakes     int
	MaxSearchCandidates         int
	MaxSearchCandidateBytes     int64
	MaxOperationsPerConnection  int
	RootDN                      string
	RootPassword                []byte
	Logger                      *slog.Logger
	AuditSink                   audit.Sink
	Schema                      *schema.Registry
	AccessPolicy                *acl.Policy
	TLSConfig                   *tls.Config
	SecureTransport             SecureTransport
	ImplicitTLS                 bool
	ImplicitTLSForConnection    func(net.Conn) bool
	ListenerSchemeForConnection func(net.Conn) string
	SecureHandshakeTimeout      time.Duration
	ShutdownTimeout             time.Duration
	Clock                       func() time.Time
	RADIUSConfigPath            string
	RADIUSNASIdentifier         string
	// GSSAPIKeytabPath enables the SASL GSSAPI acceptor. FILE: paths are
	// accepted for parity with KRB5_KTNAME.
	GSSAPIKeytabPath string
	// GSSAPIChannelBinding enables an explicit non-RFC4752 extension. The
	// empty value uses the RFC-mandated NULL channel binding.
	GSSAPIChannelBinding string
	// SQLDriver selects the database/sql driver used by OpenLDAP back-sql
	// databases. The default is "odbc"; tests and embedded deployments may
	// register and select another compatible driver.
	SQLDriver string
	// DNSSRVResolver overrides the system resolver for back-dnssrv. It is
	// primarily useful to embedded deployments and deterministic tests.
	DNSSRVResolver DNSSRVResolver
	// ReverseLookupResolver overrides reverse DNS for olcReverseLookup.
	// The system resolver is used when this field is nil.
	ReverseLookupResolver ReverseLookupResolver
	// Ready is called once Serve has initialized background consumers and is
	// ready to accept LDAP connections.
	Ready           func()
	OnlineBackupDir string
	OnlineBackup    OnlineBackupFunc
}

type Server struct {
	config          Config
	baseSchema      *schema.Registry
	secureTransport SecureTransport
	clock           func() time.Time
	runtime         atomic.Pointer[runtimeState]

	mu                   sync.Mutex
	connections          map[net.Conn]struct{}
	connectionOperations map[net.Conn]*operationRegistry
	wg                   sync.WaitGroup
	configMu             sync.Mutex
	runtimeActivationMu  sync.Mutex
	draining             atomic.Bool
	gentleDraining       atomic.Bool

	csnMu                 sync.Mutex
	lastCSN               time.Time
	csnCounter            uint32
	accesslogMu           sync.Mutex
	lastAccesslogTime     time.Time
	auditlogMu            sync.Mutex
	homedirMu             sync.Mutex
	syncChanges           *syncChangeHub
	syncConsumers         *syncConsumerManager
	ddsWake               chan struct{}
	accesslogWake         chan struct{}
	nextConnectionID      atomic.Uint64
	monitor               *monitorState
	metaRoutes            *metaDNRouteCache
	metaTransports        *metaTransportPool
	metaTransportCachesMu sync.Mutex
	metaTransportCaches   map[*metaTransportCache]struct{}
	sqlBackendsMu         sync.Mutex
	sqlBackends           map[*sqlBackendRuntimeConfiguration]struct{}
	runtimeSequence       atomic.Uint64
	metaTransportSequence atomic.Uint64
	gssapiKeytab          *keytab.Keytab
	operationLimiter      resourceLimiter
	handshakeLimiter      resourceLimiter
	rejectedConnections   atomic.Uint64
	onlineBackupMu        sync.Mutex
}

func New(config Config) (*Server, error) {
	if config.Store == nil {
		return nil, errors.New("store is required")
	}
	if (config.OnlineBackupDir == "") != (config.OnlineBackup == nil) {
		return nil, errors.New("online backup directory and callback must be configured together")
	}
	if config.OnlineBackupDir != "" && !filepath.IsAbs(config.OnlineBackupDir) {
		return nil, errors.New("online backup directory must be absolute")
	}
	if config.MaxMessageSize < 0 {
		return nil, errors.New("maximum message size cannot be negative")
	}
	if config.MaxMessageSize == 0 {
		config.MaxMessageSize = math.MaxInt64
	}
	if config.MaxSearchEntries <= 0 {
		config.MaxSearchEntries = defaultSearchLimit
	}
	if config.MaxTransactionOperations < 0 {
		return nil, errors.New("maximum transaction operations cannot be negative")
	}
	if config.MaxTransactionOperations == 0 {
		config.MaxTransactionOperations = defaultTransactionMaxOperations
	}
	if config.MaxTransactionQueuedBytes < 0 {
		return nil, errors.New("maximum transaction queued bytes cannot be negative")
	}
	if config.MaxTransactionQueuedBytes == 0 {
		config.MaxTransactionQueuedBytes = defaultTransactionMaxQueuedBytes
	}
	if config.MaxConnections < 0 {
		return nil, errors.New("maximum connections cannot be negative")
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = defaultMaxConnections
	}
	if config.MaxConcurrentOperations < 0 {
		return nil, errors.New("maximum concurrent operations cannot be negative")
	}
	if config.MaxConcurrentOperations == 0 {
		config.MaxConcurrentOperations = defaultMaxConcurrentOperations
	}
	if config.MaxConcurrentHandshakes < 0 {
		return nil, errors.New("maximum concurrent handshakes cannot be negative")
	}
	if config.MaxConcurrentHandshakes == 0 {
		config.MaxConcurrentHandshakes = defaultMaxConcurrentHandshakes
	}
	if config.MaxSearchCandidates < 0 {
		return nil, errors.New("maximum search candidates cannot be negative")
	}
	if config.MaxSearchCandidates == 0 {
		config.MaxSearchCandidates = defaultMaxSearchCandidates
	}
	if config.MaxSearchCandidateBytes < 0 {
		return nil, errors.New("maximum search candidate bytes cannot be negative")
	}
	if config.MaxSearchCandidateBytes == 0 {
		config.MaxSearchCandidateBytes = defaultMaxSearchCandidateBytes
	}
	if config.MaxOperationsPerConnection < 0 {
		return nil, errors.New("maximum operations per connection cannot be negative")
	}
	if config.MaxOperationsPerConnection == 0 {
		config.MaxOperationsPerConnection = defaultMaxOperationsPerConnection
	}
	if config.ShutdownTimeout < 0 {
		return nil, errors.New("shutdown timeout cannot be negative")
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = defaultShutdownTimeout
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	monitor := newMonitorState()
	config.Logger = slog.New(&monitorLogHandler{
		next:    config.Logger.Handler(),
		monitor: monitor,
	})
	baseSchema := config.Schema
	if baseSchema == nil {
		var err error
		baseSchema, err = schema.NewBuiltinRegistry()
		if err != nil {
			return nil, fmt.Errorf("initialize built-in schema: %w", err)
		}
	}
	if config.RootDN != "" {
		if len(config.RootPassword) == 0 {
			return nil, errors.New("root password is required when root DN is configured")
		}
	}
	var gssapiKeytab *keytab.Keytab
	gssapiChannelBinding, err := saslkrb5.NormalizeChannelBinding(
		config.GSSAPIChannelBinding,
	)
	if err != nil {
		return nil, err
	}
	config.GSSAPIChannelBinding = gssapiChannelBinding
	if config.GSSAPIKeytabPath != "" {
		path, err := parseSyncConsumerKerberosFileCredential(
			config.GSSAPIKeytabPath,
			"GSSAPI keytab",
			true,
		)
		if err != nil {
			return nil, err
		}
		gssapiKeytab, err = keytab.Load(path)
		if err != nil {
			return nil, fmt.Errorf("load GSSAPI acceptor keytab: %w", err)
		}
	}
	secureTransport := config.SecureTransport
	if config.TLSConfig != nil {
		if secureTransport != nil {
			return nil, errors.New("TLS config and secure transport are mutually exclusive")
		}
		secureTransport = standardTLSTransport{config: config.TLSConfig.Clone()}
	}
	staticSecureTransport := secureTransport != nil
	config.ListenerURLs = append([]string(nil), config.ListenerURLs...)
	if secureTransport != nil && config.SecureHandshakeTimeout <= 0 {
		config.SecureHandshakeTimeout = defaultSecureHandshakeTimeout
	}
	config.Store = &accessContextStore{Store: config.Store}

	server := &Server{
		config:               config,
		baseSchema:           baseSchema.Clone(),
		secureTransport:      secureTransport,
		clock:                config.Clock,
		connections:          make(map[net.Conn]struct{}),
		connectionOperations: make(map[net.Conn]*operationRegistry),
		metaRoutes:           newMetaDNRouteCache(time.Now),
		metaTransports:       newMetaTransportPool(time.Now),
		metaTransportCaches:  make(map[*metaTransportCache]struct{}),
		sqlBackends:          make(map[*sqlBackendRuntimeConfiguration]struct{}),
		syncChanges:          newSyncChangeHub(),
		ddsWake:              make(chan struct{}, 1),
		accesslogWake:        make(chan struct{}, 1),
		monitor:              monitor,
		gssapiKeytab:         gssapiKeytab,
		operationLimiter:     newResourceLimiter(config.MaxConcurrentOperations),
		handshakeLimiter:     newResourceLimiter(config.MaxConcurrentHandshakes),
	}
	started := false
	defer func() {
		if !started {
			server.closeSQLBackends()
		}
	}()
	server.config.Store = &homedirEffectStore{
		Store:  server.config.Store,
		server: server,
	}
	config.Store = server.config.Store
	server.syncConsumers = newSyncConsumerManager(server)
	var runtime *runtimeState
	err = config.Store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		runtime, err = server.buildRuntimeState(reader)
		return err
	})
	if err != nil {
		return nil, err
	}
	if server.secureTransport == nil {
		server.secureTransport = runtimeTLSTransport{server: server}
	}
	if server.requiresImplicitTLS() &&
		!staticSecureTransport &&
		runtime.secureTransport == nil {
		return nil, errors.New("implicit TLS requires a secure transport")
	}
	if server.secureTransport != nil &&
		server.config.SecureHandshakeTimeout <= 0 {
		server.config.SecureHandshakeTimeout = defaultSecureHandshakeTimeout
	}
	if err := server.validateSQLBackends(context.Background(), runtime); err != nil {
		return nil, fmt.Errorf("initialize SQL backend: %w", err)
	}
	if err := normalizeDefaultSearchBaseConfigurationWithNormalizer(
		context.Background(),
		config.Store,
		runtime.schema,
	); err != nil {
		return nil, fmt.Errorf("normalize default search base: %w", err)
	}
	if err := server.partitionDefaultEntries(context.Background(), runtime); err != nil {
		return nil, err
	}
	if err := config.Store.Update(
		context.Background(),
		func(writer storage.Writer) error {
			if err := server.ensureAutoCAAuthorities(writer, runtime); err != nil {
				return err
			}
			if err := server.ensureAccesslogContainers(writer, runtime); err != nil {
				return err
			}
			return server.ensurePcachePersistence(writer, runtime)
		},
	); err != nil {
		return nil, fmt.Errorf("initialize runtime-owned entries: %w", err)
	}
	previousRuntime := runtime
	err = config.Store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		runtime, err = server.buildRuntimeState(reader)
		return err
	})
	if err != nil {
		return nil, err
	}
	reuseSQLBackendOnlineConfigurationState(previousRuntime, runtime)
	if err := server.validateSQLBackends(context.Background(), runtime); err != nil {
		return nil, fmt.Errorf("initialize SQL backend: %w", err)
	}
	server.retireSQLBackends(previousRuntime, runtime)
	for _, database := range runtime.databases {
		if isMonitorDatabase(database) {
			server.monitor.enableLogRouting()
			break
		}
	}
	if err := server.seedCSNClock(runtime); err != nil {
		return nil, fmt.Errorf("initialize CSN clock: %w", err)
	}
	if err := server.seedAccesslogClock(runtime); err != nil {
		return nil, fmt.Errorf("initialize accesslog clock: %w", err)
	}
	runtime.revision = server.nextRuntimeRevision()
	server.activateRuntime(runtime)
	started = true
	return server, nil
}

func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	if ctx == nil {
		return errors.New("serve context is required")
	}
	if listener == nil {
		return errors.New("listener is required")
	}
	if err := server.syncConsumers.start(ctx); err != nil {
		return err
	}
	server.draining.Store(false)
	defer server.gentleDraining.Store(false)
	defer server.closeSQLBackends()
	defer server.metaTransports.close()
	defer server.syncConsumers.stop()

	ddsContext, stopDDS := context.WithCancel(ctx)
	ddsDone := make(chan struct{})
	go func() {
		defer close(ddsDone)
		server.runDDSExpiration(ddsContext)
	}()
	defer func() {
		stopDDS()
		<-ddsDone
	}()

	accesslogContext, stopAccesslog := context.WithCancel(ctx)
	accesslogDone := make(chan struct{})
	go func() {
		defer close(accesslogDone)
		server.runAccesslogPurge(accesslogContext)
	}()
	defer func() {
		stopAccesslog()
		<-accesslogDone
	}()

	operationContext, forceOperations := context.WithCancel(
		context.WithoutCancel(ctx),
	)
	defer forceOperations()

	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			server.draining.Store(true)
			_ = listener.Close()
			server.beginConnectionDrain()
		case <-stop:
		}
	}()
	defer close(stop)
	if server.config.Ready != nil {
		server.config.Ready()
	}

	for {
		connection, err := listener.Accept()
		if err != nil {
			if server.gentleDraining.Load() && ctx.Err() == nil && errors.Is(err, net.ErrClosed) {
				return server.waitForGentleConnectionClose(ctx, forceOperations)
			}
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				server.draining.Store(true)
				server.beginConnectionDrain()
				return server.waitForConnectionDrain(forceOperations)
			}
			forceOperations()
			server.closeConnections()
			server.wg.Wait()
			return fmt.Errorf("accept LDAP connection: %w", err)
		}

		server.mu.Lock()
		if server.draining.Load() || server.gentleDraining.Load() ||
			len(server.connections) >= server.config.MaxConnections {
			rejected := !server.draining.Load() && !server.gentleDraining.Load()
			server.mu.Unlock()
			if rejected {
				server.rejectedConnections.Add(1)
			}
			_ = connection.Close()
			continue
		}
		server.connections[connection] = struct{}{}
		server.mu.Unlock()
		server.wg.Add(1)
		go server.serveConnection(operationContext, connection)
	}
}

func (server *Server) serveConnection(ctx context.Context, connection net.Conn) {
	defer server.wg.Done()
	networkConnection := connection
	listenerScheme := server.listenerSchemeForConnection(networkConnection)
	implicitTLS := listenerScheme == "ldaps" || listenerScheme == "ldap+tlcp"
	transportSSF := server.connectionTransportSecurityStrength(networkConnection)
	domainName := server.connectionDomainName(ctx, networkConnection.RemoteAddr())
	externalDN, peercredErr := peercredExternalIdentity(networkConnection)
	if peercredErr != nil {
		server.config.Logger.Debug("LDAPI peer credential lookup failed", "error", peercredErr)
	}
	activity := newConnectionActivity()
	connection = &activityTrackingConnection{
		Conn:     networkConnection,
		activity: activity,
	}
	state := connectionState{
		connectionID:    server.nextConnectionID.Add(1),
		connection:      connection,
		externalSSF:     transportSSF,
		externalDN:      externalDN,
		transportSSF:    transportSSF,
		domainName:      domainName,
		auditIdentity:   &connectionAuditIdentityState{},
		metaTransports:  newMetaTransportCache(time.Now),
		gssapiAvailable: server.gssapiKeytab != nil,
		implicitTLS:     implicitTLS,
		listenerScheme:  listenerScheme,
		writeFailed:     &atomic.Bool{},
	}
	state.maxIncoming = server.connectionIncomingLimit(false)
	server.registerMetaTransportCache(state.metaTransports)
	defer func() {
		server.unregisterMetaTransportCache(state.metaTransports)
		state.metaTransports.close()
	}()
	state.publishAuditIdentity()
	state.monitor = server.monitor.registerConnectionWithScheme(
		state.connectionID,
		connection,
		listenerScheme,
	)
	defer server.monitor.unregisterConnection(state.connectionID)
	defer func() {
		_ = state.connection.Close()
		server.mu.Lock()
		delete(server.connections, networkConnection)
		delete(server.connectionOperations, networkConnection)
		server.mu.Unlock()
	}()

	if implicitTLS {
		secured, err := server.secureHandshake(ctx, state.connection)
		if err != nil {
			server.config.Logger.Debug("TLS handshake failed", "error", err)
			return
		}
		if secured == nil {
			server.config.Logger.Debug("secure transport returned a nil connection")
			return
		}
		state.connection = secured
		state.secure = true
		state.tlsSSF = connectionSecurityStrength(secured, true)
		state.externalSSF = max(state.transportSSF, state.tlsSSF)
		if tlsIdentity := externalIdentityDN(secured); tlsIdentity != "" {
			state.externalDN = tlsIdentity
		}
		server.monitor.updateConnectionState(state.monitor, &state)
	}

	connectionContext, cancelConnection := context.WithCancel(ctx)
	operations := newOperationRegistry()
	server.trackConnectionOperations(networkConnection, operations)
	idleContext, stopIdleWatcher := context.WithCancel(connectionContext)
	idleWatcherDone := make(chan struct{})
	go func() {
		defer close(idleWatcherDone)
		server.watchConnectionIdleTimeout(
			idleContext,
			cancelConnection,
			networkConnection,
			activity,
			operations,
		)
	}()
	queue := newOperationQueue(server.config.MaxOperationsPerConnection)
	state.operationQueue = queue
	writeMutex := &sync.Mutex{}
	workerDone := make(chan struct{})
	var operationWorkers sync.WaitGroup
	for range server.config.MaxOperationsPerConnection {
		operationWorkers.Add(1)
		go func() {
			defer operationWorkers.Done()
			server.runConnectionOperations(
				connectionContext,
				&state,
				operations,
				queue,
				writeMutex,
			)
		}()
	}
	go func() {
		operationWorkers.Wait()
		close(workerDone)
	}()

	readConnection := state.connection
	defer func() {
		if server.draining.Load() {
			queue.closeAndDrain()
			operations.abandonLongLived()
			<-workerDone
			cancelConnection()
			operations.shutdown()
		} else {
			cancelConnection()
			queue.close()
			operations.shutdown()
			_ = connection.Close()
			<-workerDone
		}
		clearSearchSessions(&state)
		clearLDAPTransaction(state.transaction)
		clearBindCredentials(&state)
	}()
	defer func() {
		stopIdleWatcher()
		<-idleWatcherDone
	}()

	for {
		if server.draining.Load() {
			return
		}
		message, err := ldapwire.ReadMessageWithDynamicFilterDepth(
			readConnection,
			server.config.MaxMessageSize,
			state.maxIncoming,
			server.currentMaxFilterDepth,
		)
		if err != nil {
			_, recoverV2Bind := message.Request.(ldapwire.BindRequest)
			recoverV2Bind = recoverV2Bind && ldapV2RequestHasControls(&state, message)
			if !recoverV2Bind && message.Request != nil &&
				ldapV2RequestHasControls(&state, message) {
				server.monitor.observeRequest(state.monitor, message)
				server.rejectLDAPv2Controls(
					readConnection,
					&state,
					message,
					writeMutex,
				)
				return
			}
			if recoverV2Bind {
				// Preserve the parsed Bind envelope; dispatch performs the Bind
				// barrier and anonymous identity demotion before responding.
			} else if errors.Is(err, ldapwire.ErrMessageTooLarge) {
				return
			} else if errors.Is(err, ldapwire.ErrFilterTooDeep) {
				server.writeMalformedMessageAudit(&state)
				responseConnection := &serializedResponseConnection{
					Conn:              readConnection,
					mu:                writeMutex,
					monitor:           server.monitor,
					monitorConnection: state.monitor,
					writeTimeout:      server.currentConnectionWriteTimeout,
					terminal:          state.writeFailed,
				}
				_ = ldapwire.Write(responseConnection, ldapwire.EncodeNoticeOfDisconnection(
					ldapwire.ResultError(
						ldapwire.ResultProtocolError,
						ldapwire.ErrFilterTooDeep.Error(),
					),
				))
				return
			} else if server.draining.Load() {
				return
			} else if errors.Is(err, io.EOF) ||
				errors.Is(err, net.ErrClosed) ||
				connectionContext.Err() != nil ||
				channelClosed(workerDone) {
				return
			} else {
				server.config.Logger.Debug("closing malformed LDAP connection", "error", err)
				server.writeMalformedMessageAudit(&state)
				responseConnection := &serializedResponseConnection{
					Conn:              readConnection,
					mu:                writeMutex,
					monitor:           server.monitor,
					monitorConnection: state.monitor,
					writeTimeout:      server.currentConnectionWriteTimeout,
					terminal:          state.writeFailed,
				}
				_ = ldapwire.Write(responseConnection, ldapwire.EncodeNoticeOfDisconnection(
					ldapwire.ResultError(ldapwire.ResultProtocolError, "malformed LDAP message"),
				))
				return
			}
		}

		server.monitor.observeRequest(state.monitor, message)

		if _, ok := message.Request.(ldapwire.UnbindRequest); ok {
			server.notifySockBackends(connectionContext, &state, message)
			observation := server.newImmediateAuditObservation(&state, message)
			server.finishOperationAudit(
				observation,
				&state,
				operationRunning,
				nil,
			)
			server.monitor.completeImmediateOperation(state.monitor, message.Request)
			return
		}
		if ldapV2RequestHasControls(&state, message) {
			if _, bind := message.Request.(ldapwire.BindRequest); bind {
				// Bind is a queue barrier and performs identity demotion in dispatch.
			} else {
				server.rejectLDAPv2Controls(
					readConnection,
					&state,
					message,
					writeMutex,
				)
				return
			}
		}
		if operations.contains(message.ID) {
			observation := server.newImmediateAuditObservation(&state, message)
			observation.setResult(ldapwire.ResultProtocolError)
			server.finishOperationAudit(
				observation,
				&state,
				operationRunning,
				nil,
			)
			server.monitor.completeImmediateOperation(state.monitor, message.Request)
			responseConnection := &serializedResponseConnection{
				Conn:              readConnection,
				mu:                writeMutex,
				monitor:           server.monitor,
				monitorConnection: state.monitor,
				writeTimeout:      server.currentConnectionWriteTimeout,
				terminal:          state.writeFailed,
			}
			_ = ldapwire.Write(responseConnection, ldapwire.EncodeNoticeOfDisconnection(
				ldapwire.ResultError(
					ldapwire.ResultProtocolError,
					"message ID is already in use",
				),
			))
			return
		}

		switch request := message.Request.(type) {
		case ldapwire.AbandonRequest:
			if !hasUnsupportedCriticalControl(message.Controls) {
				if discarded := queue.remove(request.MessageID); discarded != nil {
					discarded.operation.requestAbandon()
					operations.finish(discarded.operation)
					discardedState := discarded.state
					if discardedState == nil {
						discardedState = &state
					}
					discardedAudit := server.newOperationAuditObservation(
						discardedState,
						discarded.message,
					)
					server.finishOperationAudit(
						discardedAudit,
						discardedState,
						operationAbandoned,
						nil,
					)
					server.monitor.startOperation(state.monitor, false)
					server.monitor.completeOperation(
						state.monitor,
						discarded.message.Request,
						false,
					)
				} else {
					operations.abandon(request.MessageID)
				}
			}
			observation := server.newImmediateAuditObservation(&state, message)
			server.finishOperationAudit(
				observation,
				&state,
				operationRunning,
				nil,
			)
			server.monitor.completeImmediateOperation(state.monitor, message.Request)
			continue
		case ldapwire.ExtendedRequest:
			if result := server.startTLSOutstandingResult(
				&state,
				operations,
				message,
				request,
			); result != nil {
				baseConnection := &serializedResponseConnection{
					Conn:              readConnection,
					mu:                writeMutex,
					monitor:           server.monitor,
					monitorConnection: state.monitor,
					writeTimeout:      server.currentConnectionWriteTimeout,
					terminal:          state.writeFailed,
				}
				observation := server.newImmediateAuditObservation(&state, message)
				observation.setResult(result.Code)
				err := writeResultForMessage(baseConnection, message, *result)
				server.finishOperationAudit(
					observation,
					&state,
					operationRunning,
					err,
				)
				server.monitor.completeImmediateOperation(state.monitor, message.Request)
				if err != nil {
					return
				}
				continue
			}
			if request.Name == cancelOID {
				baseConnection := &serializedResponseConnection{
					Conn:              readConnection,
					mu:                writeMutex,
					monitor:           server.monitor,
					monitorConnection: state.monitor,
					writeTimeout:      server.currentConnectionWriteTimeout,
					terminal:          state.writeFailed,
				}
				observation := server.newImmediateAuditObservation(&state, message)
				responseConnection := &auditResponseConnection{
					Conn:        baseConnection,
					observation: observation,
				}
				err := server.handleCancel(
					connectionContext,
					responseConnection,
					operations,
					message,
					request,
				)
				server.finishOperationAudit(
					observation,
					&state,
					operationRunning,
					err,
				)
				server.monitor.completeImmediateOperation(state.monitor, message.Request)
				if err != nil {
					if connectionContext.Err() == nil {
						server.config.Logger.Debug(
							"LDAP Cancel request failed",
							"message_id",
							message.ID,
							"error",
							err,
						)
					}
					return
				}
				continue
			}
		}
		if _, bind := message.Request.(ldapwire.BindRequest); bind {
			operations.abandonForBind()
			for _, discarded := range queue.discardPending() {
				if discarded == nil {
					continue
				}
				operations.finish(discarded.operation)
				discardedState := discarded.state
				if discardedState == nil {
					discardedState = &state
				}
				discardedAudit := server.newOperationAuditObservation(
					discardedState,
					discarded.message,
				)
				server.finishOperationAudit(
					discardedAudit,
					discardedState,
					operationAbandoned,
					nil,
				)
				server.monitor.startOperation(state.monitor, false)
				server.monitor.completeOperation(
					state.monitor,
					discarded.message.Request,
					false,
				)
			}
		}

		operation, registered := operations.register(connectionContext, message)
		if !registered {
			return
		}
		concurrent := connectionOperationCanRunConcurrent(&state, message)
		queued := &queuedOperation{
			message:    message,
			operation:  operation,
			completion: make(chan operationCompletion, 1),
			state:      &state,
			concurrent: concurrent,
		}
		server.monitor.queueOperation(state.monitor)
		pushResult := queue.push(
			queued,
			server.connectionMaxPending(&state),
		)
		if pushResult != operationQueuePushed {
			server.monitor.startOperation(state.monitor, false)
			operations.finish(operation)
			if pushResult == operationQueueClosed {
				server.monitor.completeOperation(state.monitor, message.Request, false)
			}
			return
		}
		if !connectionReadBarrier(message) {
			continue
		}

		select {
		case completion := <-queued.completion:
			if completion.err != nil || completion.closeConnection {
				return
			}
			readConnection = completion.connection
		case <-workerDone:
			return
		case <-connectionContext.Done():
			return
		}
	}
}

func ldapV2RequestHasControls(
	state *connectionState,
	message ldapwire.Message,
) bool {
	if !message.ControlsPresent && len(message.Controls) == 0 {
		return false
	}
	if bind, ok := message.Request.(ldapwire.BindRequest); ok {
		return bind.Version < 3
	}
	return state != nil && state.protocolVersion > 0 && state.protocolVersion < 3
}

func (server *Server) rejectLDAPv2Controls(
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	writeMutex *sync.Mutex,
) {
	observation := server.newImmediateAuditObservation(state, message)
	if _, abandon := message.Request.(ldapwire.AbandonRequest); abandon {
		server.finishOperationAudit(
			observation,
			state,
			operationRunning,
			nil,
		)
		server.monitor.completeImmediateOperation(state.monitor, message.Request)
		return
	}
	observation.setResult(ldapwire.ResultProtocolError)
	server.finishOperationAudit(
		observation,
		state,
		operationRunning,
		nil,
	)
	server.monitor.completeImmediateOperation(state.monitor, message.Request)
	responseConnection := &serializedResponseConnection{
		Conn:              connection,
		mu:                writeMutex,
		monitor:           server.monitor,
		monitorConnection: state.monitor,
		writeTimeout:      server.currentConnectionWriteTimeout,
		terminal:          state.writeFailed,
	}
	_ = writeResultForMessage(
		responseConnection,
		message,
		ldapwire.ResultError(
			ldapwire.ResultProtocolError,
			"controls require LDAPv3",
		),
	)
}

func (server *Server) runConnectionOperations(
	ctx context.Context,
	sharedState *connectionState,
	operations *operationRegistry,
	queue *operationQueue,
	writeMutex *sync.Mutex,
) {
	for {
		queued, ok := queue.pop()
		if !ok {
			return
		}
		state := sharedState
		var concurrentState connectionState
		if queued.concurrent {
			concurrentState = cloneConcurrentConnectionState(sharedState)
			state = &concurrentState
		} else if queued.state != nil {
			state = queued.state
		}

		baseConnection := &serializedResponseConnection{
			Conn:              state.connection,
			mu:                writeMutex,
			monitor:           server.monitor,
			monitorConnection: state.monitor,
			writeTimeout:      server.currentConnectionWriteTimeout,
			terminal:          state.writeFailed,
		}
		responseConnection := &operationResponseConnection{
			Conn:      baseConnection,
			operation: queued.operation,
			audit:     server.newOperationAuditObservation(state, queued.message),
		}

		var (
			closeConnection bool
			err             error
		)
		searchSessions := snapshotSearchSessions(state, queued.message)
		boundDNBeforeOperation := state.boundDN
		acquired := server.operationLimiter.acquire(queued.operation.ctx)
		started := false
		if acquired {
			started = queued.operation.start()
			server.monitor.startOperation(state.monitor, started)
			if started {
				closeConnection, err = server.dispatch(
					queued.operation.ctx,
					responseConnection,
					state,
					queued.message,
				)
			}
			server.operationLimiter.release()
		}
		state.publishAuditIdentity()
		if operationRefreshesIncomingLimit(
			queued.message.Request,
			boundDNBeforeOperation != state.boundDN,
		) {
			state.maxIncoming = server.connectionIncomingLimit(state.boundDN != "")
		}

		stopMode := queued.operation.stopMode()
		switch stopMode {
		case operationAbandoned:
			server.clearStoppedSearchState(state, queued.message, searchSessions)
			closeConnection = false
			err = nil
		case operationCanceled:
			server.clearStoppedSearchState(state, queued.message, searchSessions)
			closeConnection = false
			err = ldapwire.Write(
				baseConnection,
				ldapwire.EncodeSearchResultDone(
					queued.message.ID,
					ldapwire.Result{Code: ldapwire.ResultCanceled},
					nil,
				),
			)
		}
		server.finishOperationAudit(responseConnection.audit, state, stopMode, err)
		server.monitor.updateConnectionState(state.monitor, state)
		server.monitor.completeOperation(
			state.monitor,
			queued.message.Request,
			started,
		)

		operations.finish(queued.operation)
		queue.complete()
		queued.completion <- operationCompletion{
			closeConnection: closeConnection,
			connection:      sharedState.connection,
			err:             err,
		}
		if queued.concurrent {
			clearConcurrentConnectionState(state)
		}

		if ctx.Err() != nil {
			return
		}
		if err != nil {
			server.config.Logger.Debug(
				"LDAP request failed",
				"message_id",
				queued.message.ID,
				"error",
				err,
			)
			_ = sharedState.connection.Close()
			return
		}
		if closeConnection {
			_ = sharedState.connection.Close()
			return
		}
	}
}

func connectionOperationCanRunConcurrent(
	state *connectionState,
	message ldapwire.Message,
) bool {
	if state == nil || state.transaction != nil || state.saslSession != nil {
		return false
	}
	for _, control := range message.Controls {
		switch control.OID {
		case pagedResultsControlOID, vlvRequestControlOID,
			transactionSpecificationControlOID:
			return false
		}
	}
	switch message.Request.(type) {
	case ldapwire.SearchRequest, ldapwire.CompareRequest:
		return true
	default:
		return false
	}
}

func cloneConcurrentConnectionState(state *connectionState) connectionState {
	cloned := *state
	cloned.bindCredentials = bytes.Clone(state.bindCredentials)
	cloned.pagedSearch = nil
	cloned.virtualListViews = nil
	cloned.sortSessionCounts = nil
	cloned.transaction = nil
	cloned.saslSession = nil
	cloned.auditIdentity = &connectionAuditIdentityState{}
	cloned.publishAuditIdentity()
	return cloned
}

func clearConcurrentConnectionState(state *connectionState) {
	if state == nil {
		return
	}
	clearSearchSessions(state)
	clearBindCredentials(state)
	state.auditIdentity = nil
}

func (server *Server) connectionMaxPending(state *connectionState) int {
	limits := connectionPendingRuntimeConfiguration{
		maxPending:     defaultConnectionMaxPending,
		maxPendingAuth: defaultConnectionMaxPendingAuth,
	}
	if runtime := server.runtime.Load(); runtime != nil {
		limits = runtime.connectionPending
	}
	if state != nil && state.loadAuditIdentity().boundDN != "" {
		return limits.maxPendingAuth
	}
	return limits.maxPending
}

type searchSessionSnapshot struct {
	virtualListViews map[string]*virtualListViewState
}

func snapshotSearchSessions(
	state *connectionState,
	message ldapwire.Message,
) searchSessionSnapshot {
	if _, ok := message.Request.(ldapwire.SearchRequest); !ok {
		return searchSessionSnapshot{}
	}
	snapshot := searchSessionSnapshot{}
	for _, control := range message.Controls {
		if control.OID != vlvRequestControlOID {
			continue
		}
		snapshot.virtualListViews = make(
			map[string]*virtualListViewState,
			len(state.virtualListViews),
		)
		for key, view := range state.virtualListViews {
			snapshot.virtualListViews[key] = view
		}
		break
	}
	return snapshot
}

func (server *Server) clearStoppedSearchState(
	state *connectionState,
	message ldapwire.Message,
	snapshot searchSessionSnapshot,
) {
	if _, ok := message.Request.(ldapwire.SearchRequest); !ok {
		return
	}
	for _, control := range message.Controls {
		switch control.OID {
		case pagedResultsControlOID:
			clearPagedSearch(state)
		case vlvRequestControlOID:
			for key, view := range state.virtualListViews {
				if snapshot.virtualListViews[key] != view {
					discardVirtualListView(state, view)
				}
			}
		}
	}
}

func connectionReadBarrier(message ldapwire.Message) bool {
	switch request := message.Request.(type) {
	case ldapwire.BindRequest:
		return true
	case ldapwire.UnsupportedRequest:
		return true
	case ldapwire.ExtendedRequest:
		return request.Name == startTLSOID
	default:
		return false
	}
}

func (server *Server) startTLSOutstandingResult(
	state *connectionState,
	operations *operationRegistry,
	message ldapwire.Message,
	request ldapwire.ExtendedRequest,
) *ldapwire.Result {
	if request.Name != startTLSOID || !operations.hasOutstanding() {
		return nil
	}
	// Preserve the existing extended-operation validation order. Only take
	// the immediate path when outstanding operations are the first failure.
	if state.transaction != nil ||
		state.saslSession != nil ||
		message.ControlsPresent || len(message.Controls) != 0 ||
		frontendRestricts(server.runtime.Load(), requestDatabaseRestriction(request)) ||
		request.HasValue || state.secure || state.saslSSF > 0 {
		return nil
	}
	result := ldapwire.ResultError(
		ldapwire.ResultOperationsError,
		"cannot start TLS when operations are outstanding",
	)
	return &result
}

func channelClosed(channel <-chan struct{}) bool {
	select {
	case <-channel:
		return true
	default:
		return false
	}
}

func (server *Server) dispatch(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
) (bool, error) {
	runtime := server.retainActiveRuntime()
	if runtime == nil {
		return false, writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(
				ldapwire.ResultUnavailable,
				"runtime configuration is unavailable",
			),
		)
	}
	defer server.releaseRuntimeSQLBackends(runtime)
	if state.runtime != nil && state.runtime != runtime {
		clearSearchSessions(state)
	}
	state.runtime = runtime
	refreshPasswordPolicyRestriction(state)
	message = withEffectiveDefaultSearchBase(runtime, message)
	if assertionFilterExceedsRuntimeDepth(message.Controls, runtime.maxFilterDepth) {
		return true, ldapwire.Write(
			connection,
			ldapwire.EncodeNoticeOfDisconnection(ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				ldapwire.ErrFilterTooDeep.Error(),
			)),
		)
	}
	if bind, ok := message.Request.(ldapwire.BindRequest); ok &&
		bind.Version < 3 &&
		(message.ControlsPresent || len(message.Controls) != 0) {
		clearLDAPTransaction(state.transaction)
		state.transaction = nil
		clearBindCredentials(state)
		state.boundDN = ""
		state.authMechanism = ""
		state.passwordPolicyRestrictedDN = ""
		clearSearchSessions(state)
		clearSASLSession(state)
		setAuditAuthorizationDN(connection, "")
		return true, writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"controls require LDAPv3",
			),
		)
	}
	if search, ok := message.Request.(ldapwire.SearchRequest); ok {
		if failure := invalidSearchParameterResult(search); failure != nil {
			return false, writeResultForMessage(connection, message, *failure)
		}
	}
	if failure := prevalidateLazyCommitControls(message.Request, message.Controls); failure != nil {
		return false, writeResultForMessage(connection, message, *failure)
	}
	sessionTracking, sessionTrackingFailure := parseSessionTrackingControls(
		message.Request,
		message.Controls,
	)
	if len(sessionTracking) != 0 {
		setAuditSessionTracking(connection, sessionTracking)
		logged := make([]string, len(sessionTracking))
		for index := range sessionTracking {
			logged[index] = sessionTrackingLogValue(sessionTracking[index])
		}
		server.config.Logger.Debug(
			"LDAP session tracking",
			"message_id", message.ID,
			"session_tracking_count", len(logged),
			"session_tracking", logged,
		)
	}
	if sessionTrackingFailure != nil {
		return false, writeResultForMessage(connection, message, *sessionTrackingFailure)
	}
	switch message.Request.(type) {
	case ldapwire.UnbindRequest, ldapwire.AbandonRequest:
	default:
		if _, failure := parseChainingBehaviorControls(message.Controls); failure != nil {
			return false, writeResultForMessage(connection, message, *failure)
		}
	}
	if state.saslSession != nil {
		switch message.Request.(type) {
		case ldapwire.BindRequest, ldapwire.UnbindRequest:
		default:
			return false, server.rejectOperationDuringSASLBind(
				connection,
				message,
			)
		}
	}
	originalBoundDN := state.boundDN
	previousOperationRealDN := state.operationRealDN
	state.operationRealDN = originalBoundDN
	defer func() {
		state.operationRealDN = previousOperationRealDN
	}()
	ctx = withACLSubject(ctx, server.connectionACLSubject(state))
	message, effectiveBoundDN, proxied, proxyFailure :=
		server.applyProxyAuthorization(ctx, state, message)
	if proxyFailure != nil {
		return false, writeResultForMessage(
			connection,
			message,
			*proxyFailure,
		)
	}
	if proxied {
		setAuditAuthorizationDN(connection, effectiveBoundDN)
		state.boundDN = effectiveBoundDN
		defer func() {
			state.boundDN = originalBoundDN
		}()
	}
	ctx = withACLSubject(ctx, server.connectionACLSubject(state))
	domainScope := false
	noOpSearch := false
	var noOpSearchResponse *noOpSearchResponseConnection
	if request, ok := message.Request.(ldapwire.SearchRequest); ok {
		request = applyAllOperationalAttributesOverlay(state.runtime, request)
		request.Attributes = expandObjectClassAttributeSelection(
			state.runtime.schema,
			request.Attributes,
		)
		message.Request = request
		parsedControls, privateSearch, failure := prevalidateSearchRequestControls(
			state.runtime,
			message.Controls,
		)
		if failure != nil {
			if failure.Code == ldapwire.ResultProtocolError &&
				failure.DiagnosticMessage == "valuesReturnFilter control could not be decoded" {
				return true, ldapwire.Write(
					connection,
					ldapwire.EncodeNoticeOfDisconnection(*failure),
				)
			}
			return false, writeResultForMessage(connection, message, *failure)
		}
		if parsedControls.noOpSearch && noOpSearchEnabledForRequest(state.runtime, request) {
			noOpSearch = true
			noOpSearchResponse = newNoOpSearchResponseConnection(
				connection,
				message.ID,
				request.SizeLimit,
			)
			connection = noOpSearchResponse
			request.Attributes = []string{"1.1"}
			message.Controls = withoutNoOpSearchControl(message.Controls)
			message.Request = request
		}
		if !privateSearch && parsedControls.matchedValues != nil {
			connection = &matchedValuesConnection{
				Conn:      connection,
				messageID: message.ID,
				registry:  state.runtime.schema,
				request:   parsedControls.matchedValues,
				typesOnly: request.TypesOnly,
			}
			message.Controls = withoutMatchedValuesControl(message.Controls)
		}
		if !privateSearch {
			message.Controls = withoutDomainScopeControls(message.Controls)
			if parsedControls.domainScope {
				domainScope = true
				connection = &domainScopeConnection{
					Conn:      connection,
					messageID: message.ID,
				}
			}
		}
		if failure := requestSecurityResult(state, message.Request); failure != nil {
			return false, writeResultForMessage(connection, message, *failure)
		}
		database := searchRequestDatabase(state.runtime, request)
		if database != nil {
			if databaseSearchCandidatesAreDelegated(state.runtime, *database) {
				if failure := server.delegatedSearchPreflight(
					state,
					*database,
					request,
					message.Controls,
				); failure != nil {
					return false, writeResultForMessage(connection, message, *failure)
				}
				message = applyDatabaseSearchLimits(
					state,
					message,
					server.config.MaxSearchEntries,
				)
			} else {
				var failure *ldapwire.Result
				message, failure = server.applyLocalSearchLimitsBeforeDispatch(
					ctx,
					state,
					message,
					*database,
				)
				if failure != nil {
					return false, writeResultForMessage(connection, message, *failure)
				}
			}
		}
		if noOpSearch {
			request = message.Request.(ldapwire.SearchRequest)
			noOpSearchResponse.sizeLimit = request.SizeLimit
			request.SizeLimit = 0
			message.Request = request
			ctx = withNoOpSearch(ctx, noOpSearchResponse.sizeLimit)
		}
	}
	if _, search := message.Request.(ldapwire.SearchRequest); !search {
		switch request := message.Request.(type) {
		case ldapwire.ExtendedRequest:
			if failure := extendedRequestSecurityResult(state, request); failure != nil {
				if controlFailure := requestControlFailureBeforeSecurity(
					state,
					message,
				); controlFailure != nil {
					return false, writeResultForMessage(connection, message, *controlFailure)
				}
				return false, writeResultForMessage(connection, message, *failure)
			}
		case ldapwire.BindRequest:
			if failure, controlsFirst := bindPreDelegationResult(state, request); failure != nil {
				clearSockOverlayBindState(state)
				if controlsFirst {
					if controlFailure := requestControlFailureBeforeSecurity(
						state,
						message,
					); controlFailure != nil {
						return false, writeResultForMessage(connection, message, *controlFailure)
					}
				}
				return false, writeResultForMessage(connection, message, *failure)
			}
		case ldapwire.UnbindRequest, ldapwire.AbandonRequest:
		default:
			if failure := requestSecurityResult(state, message.Request); failure != nil {
				if controlFailure := requestControlFailureBeforeSecurity(
					state,
					message,
				); controlFailure != nil {
					return false, writeResultForMessage(connection, message, *controlFailure)
				}
				return false, writeResultForMessage(connection, message, *failure)
			}
		}
	}
	if failure := server.gentleShutdownRequestResult(message.Request); failure != nil {
		if controlFailure := requestControlFailureBeforeSecurity(
			state,
			message,
		); controlFailure != nil {
			return false, writeResultForMessage(connection, message, *controlFailure)
		}
		return false, writeResultForMessage(connection, message, *failure)
	}
	overlayMessage := message
	overlayMessage.Controls = withoutSessionTrackingControls(message.Controls)
	overlayMessage.Controls = withoutLazyCommitControls(overlayMessage.Controls)
	overlayConnection, handled, err := server.trySockOverlayOperation(
		ctx,
		connection,
		state,
		overlayMessage,
	)
	if handled {
		return false, err
	}
	connection = overlayConnection
	if domainScope {
		connection = &domainScopeConnection{
			Conn:      connection,
			messageID: message.ID,
		}
	}
	consumedControlMessage := message
	consumedControlMessage.Controls = withoutSessionTrackingControls(message.Controls)
	consumedControlMessage.Controls = withoutLazyCommitControls(consumedControlMessage.Controls)
	switch request := message.Request.(type) {
	case ldapwire.SearchRequest:
		if handled, err := server.tryPcachePrivateSearch(
			connection,
			state,
			consumedControlMessage,
			request,
		); handled {
			return false, err
		}
	case ldapwire.CompareRequest:
		if handled, err := server.tryPcachePrivateCompare(
			connection,
			state,
			consumedControlMessage,
			request,
		); handled {
			return false, err
		}
	}
	if handled, err := server.tryUnsupportedPcachePrivateOperation(
		ctx,
		connection,
		state,
		consumedControlMessage,
	); handled {
		return false, err
	}
	if handled, err := server.tryMetaBackendOperation(
		ctx,
		connection,
		state,
		message,
	); handled {
		return false, err
	}
	if handled, err := server.tryDNSSRVBackendOperation(
		ctx,
		connection,
		state,
		message,
	); handled {
		return false, err
	}
	if handled, err := server.tryLDAPBackendOperation(
		ctx,
		connection,
		state,
		message,
	); handled {
		return false, err
	}
	if handled, err := server.tryPasswdBackendOperation(
		ctx,
		connection,
		state,
		message,
	); handled {
		return false, err
	}
	if handled, err := server.trySockBackendOperation(
		ctx,
		connection,
		state,
		message,
	); handled {
		return false, err
	}
	if handled, err := server.handleTransactionSpecification(
		connection,
		state,
		message,
	); handled {
		return false, err
	}
	if handled, err := server.tryChainOperation(
		ctx,
		connection,
		state,
		message,
	); handled {
		return false, err
	}
	switch request := message.Request.(type) {
	case ldapwire.UnbindRequest:
		return true, nil
	case ldapwire.BindRequest:
		return false, server.handleBind(
			ctx,
			&lastBindResponseConnection{
				Conn:   connection,
				ctx:    ctx,
				server: server,
				state:  state,
			},
			state,
			message,
			request,
		)
	case ldapwire.SearchRequest:
		return false, server.handleSearch(ctx, connection, state, message, request)
	case ldapwire.AddRequest:
		return false, server.handleAdd(ctx, connection, state, message, request)
	case ldapwire.ModifyRequest:
		return false, server.handleModify(ctx, connection, state, message, request)
	case ldapwire.DeleteRequest:
		return false, server.handleDelete(ctx, connection, state, message, request)
	case ldapwire.ModifyDNRequest:
		return false, server.handleModifyDN(ctx, connection, state, message, request)
	case ldapwire.CompareRequest:
		return false, server.handleCompare(ctx, connection, state, message, request)
	case ldapwire.AbandonRequest:
		// Abandon is handled by the connection reader so it can interrupt
		// an active operation worker.
		return false, nil
	case ldapwire.ExtendedRequest:
		return false, server.handleExtended(
			ctx,
			connection,
			state,
			message,
			request,
		)
	case ldapwire.UnsupportedRequest:
		return true, ldapwire.Write(
			connection,
			ldapwire.EncodeNoticeOfDisconnection(
				ldapwire.ResultError(
					ldapwire.ResultProtocolError,
					"unknown LDAP request",
				),
			),
		)
	default:
		return false, errors.New("unknown request type")
	}
}

func (server *Server) applyLocalSearchLimitsBeforeDispatch(
	ctx context.Context,
	state *connectionState,
	message ldapwire.Message,
	database runtimeDatabase,
) (ldapwire.Message, *ldapwire.Result) {
	request, ok := message.Request.(ldapwire.SearchRequest)
	if !ok {
		return message, nil
	}
	hasGroupRule := false
	for _, rule := range database.searchSizeLimits {
		if rule.selector == databaseSearchLimitGroup {
			hasGroupRule = true
			break
		}
	}
	if !hasGroupRule {
		return applyDatabaseSearchLimits(
			state,
			message,
			server.config.MaxSearchEntries,
		), nil
	}
	base, err := normalizeSearchRequestBase(state.runtime, request.BaseDN)
	if err != nil {
		return message, nil
	}
	var limits databaseSearchExecutionLimits
	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		databaseReader := readerForDatabase(reader, database, ctx)
		requestDN, normalizeErr := storage.NormalizeReaderDN(databaseReader, base)
		if normalizeErr != nil {
			return normalizeErr
		}
		limits, normalizeErr = server.effectiveDatabaseSearchLimitsForRequest(
			state.runtime,
			database,
			state.boundDN,
			requestDN,
			reader,
			server.config.MaxSearchEntries,
			request.SizeLimit,
			request.TimeLimit,
		)
		return normalizeErr
	})
	if err != nil {
		server.config.Logger.Warn(
			"rejecting search after limit policy evaluation failed",
			"database", database.name,
			"base_dn", request.BaseDN,
			"error", err,
		)
		failure := ldapwire.ResultError(
			ldapwire.ResultAdminLimitExceeded,
			"search limit policy evaluation failed",
		)
		return message, &failure
	}
	return applyDatabaseSearchExecutionLimits(message, limits), nil
}

func (server *Server) delegatedSearchPreflight(
	state *connectionState,
	database runtimeDatabase,
	request ldapwire.SearchRequest,
	controls []ldapwire.Control,
) *ldapwire.Result {
	parsed, privateSearch, failure := prevalidateSearchRequestControls(
		state.runtime,
		controls,
	)
	if failure != nil || privateSearch {
		return failure
	}
	return server.delegatedSearchLimitFailure(
		state,
		database,
		request,
		parsed.paging,
	)
}

func (server *Server) delegatedSearchLimitFailure(
	state *connectionState,
	database runtimeDatabase,
	request ldapwire.SearchRequest,
	paging *pagedResultsRequest,
) *ldapwire.Result {
	requestDN, err := parseRuntimeDN(request.BaseDN, database.dnNormalizer)
	if err != nil {
		return nil
	}
	limits, err := server.effectiveDatabaseSearchLimitsForRequest(
		state.runtime,
		database,
		state.boundDN,
		requestDN,
		nil,
		server.config.MaxSearchEntries,
		request.SizeLimit,
		request.TimeLimit,
	)
	if errors.Is(err, errDatabaseSearchLimitGroupUnverifiable) {
		server.config.Logger.Warn(
			"rejecting delegated search with unverifiable group limit",
			"database", database.name,
			"base_dn", request.BaseDN,
		)
		result := ldapwire.ResultError(
			ldapwire.ResultAdminLimitExceeded,
			"group limit membership unavailable for delegated backend",
		)
		return &result
	}
	if err != nil {
		result := ldapwire.ResultError(ldapwire.ResultAdminLimitExceeded, "")
		return &result
	}
	if limits.unchecked == 0 {
		result := ldapwire.ResultError(ldapwire.ResultAdminLimitExceeded, "")
		return &result
	}
	if limits.unchecked > 0 {
		server.config.Logger.Warn(
			"rejecting delegated search with unverifiable candidate limit",
			"database", database.name,
			"base_dn", request.BaseDN,
			"size_unchecked", limits.unchecked,
		)
		result := ldapwire.ResultError(
			ldapwire.ResultAdminLimitExceeded,
			"candidate estimate unavailable for delegated backend",
		)
		return &result
	}
	if paging != nil {
		switch {
		case limits.pageTotal == -2:
			result := ldapwire.ResultError(
				ldapwire.ResultAdminLimitExceeded,
				"pagedResults control not allowed",
			)
			return &result
		case limits.pageSize > 0 && paging.size > limits.pageSize:
			result := ldapwire.ResultError(
				ldapwire.ResultAdminLimitExceeded,
				"illegal pagedResults page size",
			)
			return &result
		}
	}
	return nil
}

func prevalidateSearchRequestControls(
	runtime *runtimeState,
	controls []ldapwire.Control,
) (requestControls, bool, *ldapwire.Result) {
	privateSearch, _ := parsePcachePrivateDBControl(controls)
	if privateSearch {
		return requestControls{}, true, nil
	}
	disallows := disallowsRuntimeConfiguration{}
	if runtime != nil {
		disallows = runtime.disallows
	}
	parsed, failure := parseRequestControlsWithDisallows(
		controls,
		searchRequestControlSupport(runtime),
		disallows,
	)
	return parsed, false, failure
}

func (server *Server) handleBind(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.BindRequest,
) error {
	clearLDAPTransaction(state.transaction)
	state.transaction = nil
	clearBindCredentials(state)
	state.boundDN = ""
	state.authMechanism = ""
	state.passwordPolicyRestrictedDN = ""
	clearSearchSessions(state)
	controls, controlFailure := parseRequestControls(
		message.Controls,
		supportsPasswordPolicy,
	)
	if controlFailure != nil {
		clearSASLSession(state)
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			*controlFailure,
			nil,
		))
	}
	requestDN, err := parseRuntimeConnectionDN(state.runtime, request.Name)
	if err != nil {
		clearSASLSession(state)
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultInvalidDNSyntax,
				"invalid DN",
			),
			nil,
		))
	}
	switch {
	case request.Version < 2 || request.Version > 3:
		clearSASLSession(state)
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"requested protocol version not supported",
			),
			nil,
		))
	case request.Version == 2 && !state.runtime.allows.bindV2:
		clearSASLSession(state)
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"historical protocol version requested, use LDAPv3 instead",
			),
			nil,
		))
	}
	state.protocolVersion = request.Version
	password := request.Authentication.Simple
	anonymous := !request.Authentication.IsSASL &&
		(requestDN.Depth() == 0 || len(password) == 0)
	if anonymous {
		var result *ldapwire.Result
		switch {
		case requestDN.Depth() == 0 && len(password) != 0 &&
			!state.runtime.allows.bindAnonymousCredentials:
			failure := ldapwire.ResultError(ldapwire.ResultInvalidCredentials, "")
			result = &failure
		case requestDN.Depth() != 0 && len(password) == 0 &&
			!state.runtime.allows.bindAnonymousDN:
			failure := ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"unauthenticated bind (DN with no password) disallowed",
			)
			result = &failure
		case state.runtime.disallows.anonymousBind:
			failure := ldapwire.ResultError(
				ldapwire.ResultInappropriateAuthentication,
				"anonymous bind disallowed",
			)
			result = &failure
		}
		if result != nil {
			clearSASLSession(state)
			return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
				message.ID,
				*result,
				nil,
			))
		}
	}
	if !request.Authentication.IsSASL && !anonymous &&
		state.runtime.disallows.simpleBind {
		clearSASLSession(state)
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"unwilling to perform simple authentication",
			),
			nil,
		))
	}
	if request.Authentication.IsSASL &&
		strings.TrimSpace(request.Authentication.SASLMechanism) == "" {
		return server.handleSASLBind(
			ctx,
			connection,
			state,
			message,
			request,
		)
	}

	var policyDatabase *runtimeDatabase
	policyKind := policySimpleBind
	if anonymous {
		policyKind = policyAnonymousBind
	} else if request.Authentication.IsSASL {
		policyKind = policySASLBind
	} else if !anonymous {
		policyDatabase = databaseForDN(state.runtime, requestDN)
	}
	if anonymous || request.Authentication.IsSASL || policyDatabase != nil {
		if result := operationSecurityResult(state, policyDatabase, policyKind); result != nil {
			clearSASLSession(state)
			return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
				message.ID,
				*result,
				nil,
			))
		}
	}

	bindRestricted := false
	if anonymous || requestDN.Depth() == 0 {
		bindRestricted = frontendRestricts(state.runtime, restrictBind)
	} else if policyDatabase != nil {
		bindRestricted = databaseRestricts(*policyDatabase, restrictBind)
	}
	if bindRestricted {
		clearSASLSession(state)
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"operation restricted",
			),
			nil,
		))
	}
	if !anonymous {
		if handled, err := server.tryRetcodeOperation(
			ctx,
			connection,
			state,
			message,
			requestDN,
			retcodeOperationBind,
			false,
			nil,
		); handled {
			clearSASLSession(state)
			return err
		}
	}
	if request.Authentication.IsSASL {
		return server.handleSASLBind(
			ctx,
			connection,
			state,
			message,
			request,
		)
	}
	clearSASLSession(state)
	if anonymous {
		state.authMechanism = "SIMPLE"
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		))
	}
	if handled, err := server.tryTranslucentBind(
		ctx,
		connection,
		state,
		message,
		request,
		requestDN,
	); handled {
		canonicalizeBindEntryState(state, requestDN)
		return err
	}
	if handled, err := server.tryMetaBackendBind(
		ctx,
		connection,
		state,
		message,
		request,
		requestDN,
	); handled {
		canonicalizeBindEntryState(state, requestDN)
		return err
	}
	if handled, err := server.tryPcacheBind(
		ctx,
		connection,
		state,
		message,
		request,
		requestDN,
	); handled {
		canonicalizeBindEntryState(state, requestDN)
		return err
	}
	if handled, err := server.tryLDAPBackendBind(
		ctx,
		connection,
		state,
		message,
		request,
		requestDN,
	); handled {
		canonicalizeBindEntryState(state, requestDN)
		return err
	}
	if handled, err := server.trySockBackendBind(
		ctx,
		connection,
		state,
		message,
		request,
		requestDN,
	); handled {
		canonicalizeBindEntryState(state, requestDN)
		return err
	}
	if handled, err := server.tryDNSSRVBackendBind(
		ctx,
		connection,
		state,
		message,
		request,
		requestDN,
	); handled {
		canonicalizeBindEntryState(state, requestDN)
		return err
	}
	if handled, err := server.tryPasswdBackendBind(
		connection,
		state,
		message,
		requestDN,
	); handled {
		return err
	}
	if database := databaseForDN(state.runtime, requestDN); database != nil &&
		database.remoteAuth != nil {
		handled, result, responseControls := server.remoteAuthSimpleBind(
			ctx,
			state.runtime,
			*database,
			requestDN,
			password,
		)
		if handled {
			if result.Code == ldapwire.ResultSuccess {
				server.runtimeActivationMu.Lock()
				current := server.remoteAuthConfigurationCurrent(
					requestDN,
					database.remoteAuth.connections,
				)
				if current {
					state.boundDN = requestDN.String()
					state.authMechanism = "SIMPLE"
					state.bindCredentialDN = requestDN.String()
					state.bindCredentials = append([]byte(nil), password...)
				} else {
					result = ldapwire.ResultError(
						ldapwire.ResultOperationsError,
						"remoteauth configuration changed",
					)
				}
				server.runtimeActivationMu.Unlock()
			}
			return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
				message.ID,
				result,
				responseControls,
			))
		}
	}
	if database := databaseForDN(state.runtime, requestDN); database != nil &&
		database.pbind != nil {
		result, responseControls := server.proxySimpleBind(
			ctx,
			*database.pbind,
			message,
			request,
		)
		if result.Code == ldapwire.ResultSuccess {
			server.runtimeActivationMu.Lock()
			current := server.pbindConfigurationCurrent(
				requestDN.String(),
				database.pbind.identity,
			)
			if current {
				state.boundDN = requestDN.String()
				state.authMechanism = "SIMPLE"
				state.bindCredentialDN = requestDN.String()
				state.bindCredentials = append([]byte(nil), password...)
			} else {
				result = ldapwire.ResultError(
					ldapwire.ResultUnavailable,
					"proxy bind target configuration changed",
				)
			}
			server.runtimeActivationMu.Unlock()
		}
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			result,
			responseControls,
		))
	}
	if database := databaseForDN(state.runtime, requestDN); database != nil &&
		databaseUsesNullBackend(state.runtime, *database) {
		authenticated := database.nullBindAllowed
		if !authenticated {
			if rootPassword, ok := databaseAuthenticationRoot(
				state.runtime,
				*database,
				requestDN,
			); ok {
				authenticated = server.verifyStoredPassword(
					ctx,
					state.runtime,
					rootPassword,
					password,
				)
			}
		}
		if !authenticated {
			return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
				message.ID,
				ldapwire.ResultError(ldapwire.ResultInvalidCredentials, ""),
				nil,
			))
		}
		state.boundDN = requestDN.String()
		state.authMechanism = "SIMPLE"
		state.bindCredentialDN = requestDN.String()
		state.bindCredentials = append([]byte(nil), password...)
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
			nil,
		))
	}
	if database := databaseForDN(state.runtime, requestDN); database != nil &&
		activeOTPConfiguration(database) != nil {
		if _, root := databaseAuthenticationRoot(
			state.runtime,
			*database,
			requestDN,
		); !root {
			handled, staticPassword, result := server.prepareOTPBind(
				ctx,
				state.runtime,
				*database,
				requestDN,
				password,
			)
			if handled {
				if result.Code != ldapwire.ResultSuccess {
					return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
						message.ID,
						result,
						nil,
					))
				}
				password = staticPassword
			}
		}
	}

	bindResult, err := server.authenticatePasswordBind(
		ctx,
		state.runtime,
		requestDN.String(),
		password,
		controls.passwordPolicy,
	)
	if err != nil {
		if failure := asOperationFailure(err); failure != nil {
			return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
				message.ID,
				failure.result,
				failure.controls,
			))
		}
		return err
	}
	if !bindResult.authenticated {
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(ldapwire.ResultInvalidCredentials, ""),
			bindResult.controls,
		))
	}
	state.boundDN = requestDN.String()
	state.authMechanism = "SIMPLE"
	state.bindCredentialDN = requestDN.String()
	state.bindCredentials = append([]byte(nil), password...)
	if bindResult.restricted {
		state.passwordPolicyRestrictedDN = requestDN.String()
	}
	return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
		message.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		bindResult.controls,
	))
}

func (server *Server) authenticate(
	ctx context.Context,
	runtime *runtimeState,
	rawDN string,
	password []byte,
) (bool, error) {
	if rawDN == "" {
		return len(password) == 0, nil
	}
	if len(password) == 0 {
		return false, nil
	}
	dn, err := parseRuntimeConnectionDN(runtime, rawDN)
	if err != nil {
		return false, nil
	}

	database := databaseForDN(runtime, dn)
	if database == nil {
		return false, nil
	}
	if rootPassword, ok := databaseAuthenticationRoot(runtime, *database, dn); ok {
		return server.verifyStoredPassword(ctx, runtime, rootPassword, password), nil
	}

	var storedPasswords [][]byte
	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, *database, ctx)
		entry, err := tx.Get(dn)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if runtime.schema.EntryHasObjectClass(entry, "subentry") ||
			runtime.schema.EntryHasObjectClass(entry, "alias") ||
			runtime.schema.EntryHasObjectClass(entry, "referral") {
			return nil
		}
		if !server.allowed(runtime, tx, "", entry, "userPassword", nil, acl.Auth) {
			return nil
		}
		for _, stored := range entry.Values("userPassword") {
			storedPasswords = append(storedPasswords, append([]byte(nil), stored...))
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	for _, stored := range storedPasswords {
		if server.verifyStoredPassword(ctx, runtime, stored, password) {
			return true, nil
		}
	}
	return false, nil
}

func (server *Server) closeConnections() {
	server.mu.Lock()
	connections := make([]net.Conn, 0, len(server.connections))
	for connection := range server.connections {
		connections = append(connections, connection)
	}
	server.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func (server *Server) trackConnectionOperations(
	connection net.Conn,
	operations *operationRegistry,
) {
	server.mu.Lock()
	server.connectionOperations[connection] = operations
	draining := server.draining.Load()
	server.mu.Unlock()
	if draining {
		_ = connection.SetReadDeadline(time.Now())
		operations.abandonLongLived()
	}
}

func (server *Server) beginConnectionDrain() {
	server.mu.Lock()
	connections := make([]net.Conn, 0, len(server.connections))
	operations := make([]*operationRegistry, 0, len(server.connectionOperations))
	for connection := range server.connections {
		connections = append(connections, connection)
	}
	for _, registry := range server.connectionOperations {
		operations = append(operations, registry)
	}
	server.mu.Unlock()

	now := time.Now()
	for _, connection := range connections {
		_ = connection.SetReadDeadline(now)
	}
	for _, registry := range operations {
		registry.abandonLongLived()
	}
}

func (server *Server) waitForConnectionDrain(force context.CancelFunc) error {
	done := make(chan struct{})
	go func() {
		server.wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(server.config.ShutdownTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		force()
		server.closeConnections()
		<-done
		return fmt.Errorf(
			"%w after %s",
			ErrShutdownTimeout,
			server.config.ShutdownTimeout,
		)
	}
}

type connectionState struct {
	connectionID               uint64
	boundDN                    string
	operationRealDN            string
	authMechanism              string
	protocolVersion            int
	bindCredentialDN           string
	bindCredentials            []byte
	metaBindDatabaseKey        string
	metaBindTargetKey          string
	metaTransports             *metaTransportCache
	operationQueue             *operationQueue
	runtime                    *runtimeState
	connection                 net.Conn
	secure                     bool
	implicitTLS                bool
	listenerScheme             string
	writeFailed                *atomic.Bool
	externalSSF                uint32
	transportSSF               uint32
	tlsSSF                     uint32
	saslSSF                    uint32
	domainName                 string
	gssapiAvailable            bool
	externalDN                 string
	saslSession                *serverSASLSession
	pagedSearch                *pagedSearchState
	virtualListViews           map[string]*virtualListViewState
	sortSessionCounts          map[*serverSideSortLimiter]int
	transaction                *ldapTransaction
	transactionPreflight       bool
	passwordPolicyRestrictedDN string
	accountUsabilityRequested  bool
	monitor                    *monitorConnection
	auditIdentity              *connectionAuditIdentityState
	maxIncoming                uint64
}

func (server *Server) connectionIncomingLimit(authenticated bool) uint64 {
	runtime := server.runtime.Load()
	if runtime == nil {
		if authenticated {
			return defaultIncomingLimitAuthenticated
		}
		return defaultIncomingLimitAnonymous
	}
	if authenticated {
		return runtime.incomingLimits.authenticated
	}
	return runtime.incomingLimits.anonymous
}

func operationRefreshesIncomingLimit(
	request ldapwire.Request,
	identityChanged bool,
) bool {
	switch value := request.(type) {
	case ldapwire.BindRequest:
		return true
	case ldapwire.ExtendedRequest:
		return value.Name == startTLSOID && identityChanged
	default:
		return false
	}
}

type connectionAuditIdentity struct {
	boundDN       string
	authMechanism string
}

type connectionAuditIdentityState struct {
	current atomic.Pointer[connectionAuditIdentity]
}

func (state *connectionState) publishAuditIdentity() {
	if state.auditIdentity == nil {
		state.auditIdentity = &connectionAuditIdentityState{}
	}
	state.auditIdentity.current.Store(&connectionAuditIdentity{
		boundDN:       state.boundDN,
		authMechanism: state.authMechanism,
	})
}

func (state *connectionState) loadAuditIdentity() connectionAuditIdentity {
	if state.auditIdentity == nil {
		return connectionAuditIdentity{
			boundDN:       state.boundDN,
			authMechanism: state.authMechanism,
		}
	}
	identity := state.auditIdentity.current.Load()
	if identity == nil {
		return connectionAuditIdentity{
			boundDN:       state.boundDN,
			authMechanism: state.authMechanism,
		}
	}
	return *identity
}

func clearBindCredentials(state *connectionState) {
	clear(state.bindCredentials)
	state.bindCredentials = nil
	state.bindCredentialDN = ""
	state.metaBindDatabaseKey = ""
	state.metaBindTargetKey = ""
}

func canonicalizeBindEntryState(state *connectionState, dn directory.DN) {
	if state == nil || state.boundDN == "" {
		return
	}
	canonical := dn.String()
	state.boundDN = canonical
	if state.bindCredentialDN != "" {
		state.bindCredentialDN = canonical
	}
	if state.passwordPolicyRestrictedDN != "" {
		state.passwordPolicyRestrictedDN = canonical
	}
}

func clearSearchSessions(state *connectionState) {
	clearPagedSearch(state)
	clearVirtualListViews(state)
}

func hasUnsupportedCriticalControl(controls []ldapwire.Control) bool {
	for _, control := range controls {
		if control.Critical && control.OID != chainingBehaviorControlOID {
			return true
		}
	}
	return false
}

func responseTagFor(requestTag uint64) (uint64, bool) {
	switch requestTag {
	case ldapwire.ApplicationBindRequest:
		return ldapwire.ApplicationBindResponse, true
	case ldapwire.ApplicationModifyRequest,
		ldapwire.ApplicationAddRequest,
		ldapwire.ApplicationDeleteRequest,
		ldapwire.ApplicationModifyDNRequest,
		ldapwire.ApplicationCompareRequest:
		return requestTag + 1, true
	case ldapwire.ApplicationExtendedRequest:
		return ldapwire.ApplicationExtendedResponse, true
	default:
		return 0, false
	}
}

func effectiveSearchLimit(serverLimit, requestLimit int) int {
	if requestLimit > 0 && requestLimit < serverLimit {
		return requestLimit
	}
	return serverLimit
}

func timeLimitDeadline(seconds int) time.Time {
	if seconds <= 0 {
		return time.Time{}
	}
	return time.Now().Add(time.Duration(seconds) * time.Second)
}

func expired(deadline time.Time) bool {
	return !deadline.IsZero() && time.Now().After(deadline)
}

func (server *Server) isRoot(
	runtime *runtimeState,
	rawDN, targetDN, attribute string,
) bool {
	if rawDN == "" {
		return false
	}
	subject, err := parseRuntimeConnectionDN(runtime, rawDN)
	if err != nil {
		return false
	}
	if targetDN == "" {
		return attribute == "children" && isAnyDatabaseRoot(runtime, subject)
	}
	target, err := parseRuntimeConnectionDN(runtime, targetDN)
	if err != nil {
		return false
	}
	database := databaseForDN(runtime, target)
	return database != nil && databaseRootMatches(runtime, *database, subject)
}

func isAnyDatabaseRoot(runtime *runtimeState, subject directory.DN) bool {
	for index := range runtime.databases {
		if databaseRootMatches(runtime, runtime.databases[index], subject) {
			return true
		}
	}
	return false
}

func databaseForDN(runtime *runtimeState, dn directory.DN) *runtimeDatabase {
	index := databaseIndexForDN(runtime.databases, dn)
	if index < 0 {
		return nil
	}
	return &runtime.databases[index]
}
