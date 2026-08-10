package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/audit"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	defaultSearchLimit               = 1000
	defaultTransactionMaxOperations  = 1000
	defaultTransactionMaxQueuedBytes = int64(16 << 20)
	defaultShutdownTimeout           = 30 * time.Second
)

var ErrShutdownTimeout = errors.New("graceful shutdown timed out")

type Config struct {
	Store                     storage.Store
	ListenerURLs              []string
	MaxMessageSize            int64
	MaxSearchEntries          int
	MaxTransactionOperations  int
	MaxTransactionQueuedBytes int64
	RootDN                    string
	RootPassword              []byte
	Logger                    *slog.Logger
	AuditSink                 audit.Sink
	Schema                    *schema.Registry
	AccessPolicy              *acl.Policy
	TLSConfig                 *tls.Config
	SecureTransport           SecureTransport
	ImplicitTLS               bool
	SecureHandshakeTimeout    time.Duration
	ShutdownTimeout           time.Duration
	Clock                     func() time.Time
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
	runtimeSequence       atomic.Uint64
	metaTransportSequence atomic.Uint64
}

func New(config Config) (*Server, error) {
	if config.Store == nil {
		return nil, errors.New("store is required")
	}
	if config.MaxMessageSize <= 0 {
		config.MaxMessageSize = ldapwire.DefaultMaxMessageSize
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
	secureTransport := config.SecureTransport
	if config.TLSConfig != nil {
		if secureTransport != nil {
			return nil, errors.New("TLS config and secure transport are mutually exclusive")
		}
		secureTransport = standardTLSTransport{config: config.TLSConfig.Clone()}
	}
	if config.ImplicitTLS && secureTransport == nil {
		return nil, errors.New("implicit TLS requires a secure transport")
	}
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
		syncChanges:          newSyncChangeHub(),
		ddsWake:              make(chan struct{}, 1),
		accesslogWake:        make(chan struct{}, 1),
		monitor:              newMonitorState(),
	}
	server.config.Store = &homedirEffectStore{
		Store:  server.config.Store,
		server: server,
	}
	config.Store = server.config.Store
	server.syncConsumers = newSyncConsumerManager(server)
	var runtime *runtimeState
	err := config.Store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		runtime, err = server.buildRuntimeState(reader)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := normalizeDefaultSearchBaseConfiguration(
		context.Background(),
		config.Store,
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
			return server.ensureAccesslogContainers(writer, runtime)
		},
	); err != nil {
		return nil, fmt.Errorf("initialize runtime-owned entries: %w", err)
	}
	err = config.Store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		runtime, err = server.buildRuntimeState(reader)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := server.seedCSNClock(runtime); err != nil {
		return nil, fmt.Errorf("initialize CSN clock: %w", err)
	}
	if err := server.seedAccesslogClock(runtime); err != nil {
		return nil, fmt.Errorf("initialize accesslog clock: %w", err)
	}
	runtime.revision = server.nextRuntimeRevision()
	server.activateRuntime(runtime)
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
	defer server.syncConsumers.stop()
	defer server.metaTransports.close()

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

	for {
		connection, err := listener.Accept()
		if err != nil {
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
		if server.draining.Load() {
			server.mu.Unlock()
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
	state := connectionState{
		connectionID:   server.nextConnectionID.Add(1),
		connection:     connection,
		externalSSF:    connectionSecurityStrength(connection, false),
		auditIdentity:  &connectionAuditIdentityState{},
		metaTransports: newMetaTransportCache(time.Now),
	}
	server.registerMetaTransportCache(state.metaTransports)
	defer func() {
		server.unregisterMetaTransportCache(state.metaTransports)
		state.metaTransports.close()
	}()
	state.publishAuditIdentity()
	state.monitor = server.monitor.registerConnection(
		state.connectionID,
		connection,
		server.config.ImplicitTLS,
	)
	defer server.monitor.unregisterConnection(state.connectionID)
	defer func() {
		_ = state.connection.Close()
		server.mu.Lock()
		delete(server.connections, connection)
		delete(server.connectionOperations, connection)
		server.mu.Unlock()
	}()

	if server.config.ImplicitTLS {
		secured, err := server.secureHandshake(ctx, connection)
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
		state.externalSSF = connectionSecurityStrength(secured, true)
		state.externalDN = externalIdentityDN(secured)
		server.monitor.updateConnectionState(state.monitor, &state)
	}

	connectionContext, cancelConnection := context.WithCancel(ctx)
	operations := newOperationRegistry()
	server.trackConnectionOperations(connection, operations)
	queue := newOperationQueue()
	state.operationQueue = queue
	writeMutex := &sync.Mutex{}
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		server.runConnectionOperations(
			connectionContext,
			&state,
			operations,
			queue,
			writeMutex,
		)
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

	for {
		if server.draining.Load() {
			return
		}
		message, err := ldapwire.ReadMessage(
			readConnection,
			server.config.MaxMessageSize,
		)
		if err != nil {
			if server.draining.Load() {
				return
			}
			if errors.Is(err, io.EOF) ||
				errors.Is(err, net.ErrClosed) ||
				connectionContext.Err() != nil ||
				channelClosed(workerDone) {
				return
			}
			server.config.Logger.Debug("closing malformed LDAP connection", "error", err)
			server.writeMalformedMessageAudit(&state)
			responseConnection := &serializedResponseConnection{
				Conn:              readConnection,
				mu:                writeMutex,
				monitor:           server.monitor,
				monitorConnection: state.monitor,
			}
			_ = ldapwire.Write(responseConnection, ldapwire.EncodeNoticeOfDisconnection(
				ldapwire.ResultError(ldapwire.ResultProtocolError, "malformed LDAP message"),
			))
			return
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
				operations.abandon(request.MessageID)
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
			if request.Name == cancelOID {
				baseConnection := &serializedResponseConnection{
					Conn:              readConnection,
					mu:                writeMutex,
					monitor:           server.monitor,
					monitorConnection: state.monitor,
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

		operation, registered := operations.register(connectionContext, message)
		if !registered {
			return
		}
		queued := &queuedOperation{
			message:    message,
			operation:  operation,
			completion: make(chan operationCompletion, 1),
		}
		server.monitor.queueOperation(state.monitor)
		if !queue.push(queued) {
			server.monitor.startOperation(state.monitor, false)
			server.monitor.completeOperation(state.monitor, message.Request, false)
			operations.finish(operation)
			return
		}
		if !connectionBarrier(message) {
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

func (server *Server) runConnectionOperations(
	ctx context.Context,
	state *connectionState,
	operations *operationRegistry,
	queue *operationQueue,
	writeMutex *sync.Mutex,
) {
	for {
		queued, ok := queue.pop()
		if !ok {
			return
		}

		baseConnection := &serializedResponseConnection{
			Conn:              state.connection,
			mu:                writeMutex,
			monitor:           server.monitor,
			monitorConnection: state.monitor,
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
		started := queued.operation.start()
		server.monitor.startOperation(state.monitor, started)
		if started {
			closeConnection, err = server.dispatch(
				queued.operation.ctx,
				responseConnection,
				state,
				queued.message,
			)
		}
		state.publishAuditIdentity()

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
		queued.completion <- operationCompletion{
			closeConnection: closeConnection,
			connection:      state.connection,
			err:             err,
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
			_ = state.connection.Close()
			return
		}
		if closeConnection {
			_ = state.connection.Close()
			return
		}
	}
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

func connectionBarrier(message ldapwire.Message) bool {
	switch request := message.Request.(type) {
	case ldapwire.BindRequest:
		return true
	case ldapwire.ExtendedRequest:
		return request.Name == startTLSOID
	default:
		return false
	}
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
	runtime := server.runtime.Load()
	if state.runtime != nil && state.runtime != runtime {
		clearSearchSessions(state)
	}
	state.runtime = runtime
	refreshPasswordPolicyRestriction(state)
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
	if handled, err := server.tryMetaBackendOperation(
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
		return false, server.handleBind(ctx, connection, state, message, request)
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
		// the serial operation worker.
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
		responseTag, responds := responseTagFor(request.Tag)
		if !responds {
			return false, nil
		}
		return false, ldapwire.Write(connection, ldapwire.EncodeResultResponse(
			message.ID,
			responseTag,
			ldapwire.ResultError(ldapwire.ResultUnwillingToPerform, "operation is not implemented"),
			nil,
		))
	default:
		return false, errors.New("unknown request type")
	}
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
	requestDN, err := directory.ParseDN(request.Name)
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
	if database := databaseForDN(state.runtime, requestDN); database != nil &&
		databaseRestricts(*database, restrictBind) {
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
	if requestDN.Depth() == 0 && frontendRestricts(state.runtime, restrictBind) {
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

	password := request.Authentication.Simple
	anonymous := requestDN.Depth() == 0 || len(password) == 0
	if anonymous {
		var result ldapwire.Result
		switch {
		case requestDN.Depth() == 0 &&
			len(password) != 0 &&
			!state.runtime.allows.bindAnonymousCredentials:
			result = ldapwire.ResultError(
				ldapwire.ResultInvalidCredentials,
				"",
			)
		case requestDN.Depth() != 0 &&
			len(password) == 0 &&
			!state.runtime.allows.bindAnonymousDN:
			result = ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"unauthenticated bind (DN with no password) disallowed",
			)
		case state.runtime.disallows.anonymousBind:
			result = ldapwire.ResultError(
				ldapwire.ResultInappropriateAuthentication,
				"anonymous bind disallowed",
			)
		default:
			result = ldapwire.Result{Code: ldapwire.ResultSuccess}
		}
		if result.Code == ldapwire.ResultSuccess {
			state.authMechanism = "SIMPLE"
		}
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			result,
			nil,
		))
	}
	if state.runtime.disallows.simpleBind {
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"unwilling to perform simple authentication",
			),
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
				state.boundDN = request.Name
				state.authMechanism = "SIMPLE"
				state.bindCredentialDN = request.Name
				state.bindCredentials = append([]byte(nil), password...)
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
			state.boundDN = request.Name
			state.authMechanism = "SIMPLE"
			state.bindCredentialDN = request.Name
			state.bindCredentials = append([]byte(nil), password...)
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
				authenticated = auth.VerifyPassword(rootPassword, password)
			}
		}
		if !authenticated {
			return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
				message.ID,
				ldapwire.ResultError(ldapwire.ResultInvalidCredentials, ""),
				nil,
			))
		}
		state.boundDN = request.Name
		state.authMechanism = "SIMPLE"
		state.bindCredentialDN = request.Name
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
		request.Name,
		password,
		controls.passwordPolicy,
	)
	if err != nil {
		return err
	}
	if !bindResult.authenticated {
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(ldapwire.ResultInvalidCredentials, ""),
			bindResult.controls,
		))
	}
	state.boundDN = request.Name
	state.authMechanism = "SIMPLE"
	state.bindCredentialDN = request.Name
	state.bindCredentials = append([]byte(nil), password...)
	if bindResult.restricted {
		state.passwordPolicyRestrictedDN = request.Name
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
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		return false, nil
	}

	database := databaseForDN(runtime, dn)
	if database == nil {
		return false, nil
	}
	if rootPassword, ok := databaseAuthenticationRoot(runtime, *database, dn); ok {
		return auth.VerifyPassword(rootPassword, password), nil
	}

	var authenticated bool
	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, *database)
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
			if auth.VerifyPassword(stored, password) {
				authenticated = true
			}
		}
		return nil
	})
	return authenticated, err
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
	externalSSF                uint32
	externalDN                 string
	saslSession                *serverSASLSession
	pagedSearch                *pagedSearchState
	virtualListViews           map[string]*virtualListViewState
	sortSessionCounts          map[*serverSideSortLimiter]int
	transaction                *ldapTransaction
	passwordPolicyRestrictedDN string
	accountUsabilityRequested  bool
	monitor                    *monitorConnection
	auditIdentity              *connectionAuditIdentityState
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
	subject, err := directory.ParseDN(rawDN)
	if err != nil {
		return false
	}
	if targetDN == "" {
		return attribute == "children" && isAnyDatabaseRoot(runtime, subject)
	}
	target, err := directory.ParseDN(targetDN)
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
