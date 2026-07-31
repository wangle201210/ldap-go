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
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const defaultSearchLimit = 1000

type Config struct {
	Store                  storage.Store
	ListenerURLs           []string
	MaxMessageSize         int64
	MaxSearchEntries       int
	RootDN                 string
	RootPassword           []byte
	Logger                 *slog.Logger
	Schema                 *schema.Registry
	AccessPolicy           *acl.Policy
	TLSConfig              *tls.Config
	SecureTransport        SecureTransport
	ImplicitTLS            bool
	SecureHandshakeTimeout time.Duration
}

type Server struct {
	config          Config
	baseSchema      *schema.Registry
	secureTransport SecureTransport
	runtime         atomic.Pointer[runtimeState]

	mu          sync.Mutex
	connections map[net.Conn]struct{}
	wg          sync.WaitGroup
	configMu    sync.Mutex

	csnMu         sync.Mutex
	lastCSN       time.Time
	csnCounter    uint32
	syncChanges   *syncChangeHub
	syncConsumers *syncConsumerManager
	ddsWake       chan struct{}
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

	server := &Server{
		config:          config,
		baseSchema:      baseSchema.Clone(),
		secureTransport: secureTransport,
		connections:     make(map[net.Conn]struct{}),
		syncChanges:     newSyncChangeHub(),
		ddsWake:         make(chan struct{}, 1),
	}
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
	if err := server.partitionDefaultEntries(context.Background(), runtime); err != nil {
		return nil, err
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
	server.activateRuntime(runtime)
	return server, nil
}

func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("listener is required")
	}
	if err := server.syncConsumers.start(ctx); err != nil {
		return err
	}
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

	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
			server.closeConnections()
		case <-stop:
		}
	}()
	defer close(stop)

	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				server.wg.Wait()
				return nil
			}
			return fmt.Errorf("accept LDAP connection: %w", err)
		}

		server.mu.Lock()
		server.connections[connection] = struct{}{}
		server.mu.Unlock()
		server.wg.Add(1)
		go server.serveConnection(ctx, connection)
	}
}

func (server *Server) serveConnection(ctx context.Context, connection net.Conn) {
	defer server.wg.Done()
	state := connectionState{
		connection:  connection,
		externalSSF: connectionSecurityStrength(connection, false),
	}
	defer func() {
		_ = state.connection.Close()
		server.mu.Lock()
		delete(server.connections, connection)
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
	}

	connectionContext, cancelConnection := context.WithCancel(ctx)
	operations := newOperationRegistry()
	queue := newOperationQueue()
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
		cancelConnection()
		queue.close()
		operations.shutdown()
		_ = connection.Close()
		<-workerDone
		clearSearchSessions(&state)
		clearLDAPTransaction(state.transaction)
	}()

	for {
		message, err := ldapwire.ReadMessage(
			readConnection,
			server.config.MaxMessageSize,
		)
		if err != nil {
			if errors.Is(err, io.EOF) ||
				errors.Is(err, net.ErrClosed) ||
				connectionContext.Err() != nil ||
				channelClosed(workerDone) {
				return
			}
			server.config.Logger.Debug("closing malformed LDAP connection", "error", err)
			responseConnection := &serializedResponseConnection{
				Conn: readConnection,
				mu:   writeMutex,
			}
			_ = ldapwire.Write(responseConnection, ldapwire.EncodeNoticeOfDisconnection(
				ldapwire.ResultError(ldapwire.ResultProtocolError, "malformed LDAP message"),
			))
			return
		}

		if _, ok := message.Request.(ldapwire.UnbindRequest); ok {
			return
		}
		if operations.contains(message.ID) {
			responseConnection := &serializedResponseConnection{
				Conn: readConnection,
				mu:   writeMutex,
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
			continue
		case ldapwire.ExtendedRequest:
			if request.Name == cancelOID {
				responseConnection := &serializedResponseConnection{
					Conn: readConnection,
					mu:   writeMutex,
				}
				if err := server.handleCancel(
					connectionContext,
					responseConnection,
					operations,
					message,
					request,
				); err != nil {
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
		if !queue.push(queued) {
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
			Conn: state.connection,
			mu:   writeMutex,
		}
		responseConnection := &operationResponseConnection{
			Conn:      baseConnection,
			operation: queued.operation,
		}

		var (
			closeConnection bool
			err             error
		)
		searchSessions := snapshotSearchSessions(state, queued.message)
		if queued.operation.start() {
			closeConnection, err = server.dispatch(
				queued.operation.ctx,
				responseConnection,
				state,
				queued.message,
			)
		}

		switch queued.operation.stopMode() {
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
		state.boundDN = effectiveBoundDN
		defer func() {
			state.boundDN = originalBoundDN
		}()
	}
	if handled, err := server.handleTransactionSpecification(
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
	state.boundDN = ""
	state.authMechanism = ""
	clearSearchSessions(state)
	if hasUnsupportedCriticalControl(message.Controls) {
		clearSASLSession(state)
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(ldapwire.ResultUnavailableCriticalExtension, "unsupported critical control"),
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

	authenticated, err := server.authenticate(
		ctx,
		state.runtime,
		request.Name,
		password,
	)
	if err != nil {
		return err
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
	return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
		message.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		nil,
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
	if database.rootDN != nil &&
		database.rootDN.Equal(dn) &&
		database.rootPasswordSet {
		return auth.VerifyPassword(database.rootPassword, password), nil
	}

	var authenticated bool
	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := storage.ReaderInPartition(reader, database.partition)
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
	defer server.mu.Unlock()
	for connection := range server.connections {
		_ = connection.Close()
	}
}

type connectionState struct {
	boundDN           string
	authMechanism     string
	runtime           *runtimeState
	connection        net.Conn
	secure            bool
	externalSSF       uint32
	externalDN        string
	saslSession       *serverSASLSession
	pagedSearch       *pagedSearchState
	virtualListViews  map[string]*virtualListViewState
	sortSessionCounts map[*serverSideSortLimiter]int
	transaction       *ldapTransaction
}

func clearSearchSessions(state *connectionState) {
	clearPagedSearch(state)
	clearVirtualListViews(state)
}

func hasUnsupportedCriticalControl(controls []ldapwire.Control) bool {
	for _, control := range controls {
		if control.Critical {
			return true
		}
	}
	return false
}

func responseTagFor(requestTag uint64) (uint64, bool) {
	switch requestTag {
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
	return database != nil && database.rootDN != nil && database.rootDN.Equal(subject)
}

func isAnyDatabaseRoot(runtime *runtimeState, subject directory.DN) bool {
	for index := range runtime.databases {
		if runtime.databases[index].rootDN != nil &&
			runtime.databases[index].rootDN.Equal(subject) {
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
