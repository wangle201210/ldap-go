package server

import (
	"context"
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
	Store            storage.Store
	MaxMessageSize   int64
	MaxSearchEntries int
	RootDN           string
	RootPassword     []byte
	Logger           *slog.Logger
	Schema           *schema.Registry
	AccessPolicy     *acl.Policy
}

type Server struct {
	config     Config
	baseSchema *schema.Registry
	runtime    atomic.Pointer[runtimeState]

	mu          sync.Mutex
	connections map[net.Conn]struct{}
	wg          sync.WaitGroup
	configMu    sync.Mutex

	csnMu      sync.Mutex
	lastCSN    time.Time
	csnCounter uint32
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

	server := &Server{
		config:      config,
		baseSchema:  baseSchema.Clone(),
		connections: make(map[net.Conn]struct{}),
	}
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
	server.runtime.Store(runtime)
	return server, nil
}

func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("listener is required")
	}

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
	defer func() {
		server.mu.Lock()
		delete(server.connections, connection)
		server.mu.Unlock()
		_ = connection.Close()
	}()

	state := connectionState{}
	for {
		message, err := ldapwire.ReadMessage(connection, server.config.MaxMessageSize)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			server.config.Logger.Debug("closing malformed LDAP connection", "error", err)
			_ = ldapwire.Write(connection, ldapwire.EncodeNoticeOfDisconnection(
				ldapwire.ResultError(ldapwire.ResultProtocolError, "malformed LDAP message"),
			))
			return
		}

		closeConnection, err := server.dispatch(ctx, connection, &state, message)
		if err != nil {
			server.config.Logger.Debug("LDAP request failed", "message_id", message.ID, "error", err)
			return
		}
		if closeConnection {
			return
		}
	}
}

func (server *Server) dispatch(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
) (bool, error) {
	state.runtime = server.runtime.Load()
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
		// Requests are currently dispatched serially per connection, so there
		// is no outstanding operation to cancel yet.
		return false, nil
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
	state.boundDN = ""
	if hasUnsupportedCriticalControl(message.Controls) {
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(ldapwire.ResultUnavailableCriticalExtension, "unsupported critical control"),
			nil,
		))
	}
	if request.Version != 3 {
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(ldapwire.ResultProtocolError, "only LDAPv3 is supported"),
			nil,
		))
	}
	if request.Authentication.IsSASL {
		return ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(ldapwire.ResultAuthMethodNotSupported, "SASL is not implemented"),
			nil,
		))
	}

	authenticated, err := server.authenticate(
		ctx,
		state.runtime,
		request.Name,
		request.Authentication.Simple,
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
	boundDN string
	runtime *runtimeState
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
