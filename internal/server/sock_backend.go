package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	sockBackendOpenDiagnostic        = "could not open socket"
	sockBackendFailureDiagnostic     = "external socket service failed"
	sockBackendTransactionDiagnostic = "sock backend cannot atomically participate in transactions"
	sockSimpleAuthenticationMethod   = 0x80
)

type sockBackendExtension uint8

const (
	sockExtensionBindDN sockBackendExtension = 1 << iota
	sockExtensionPeerName
	sockExtensionSSF
	sockExtensionConnectionID
)

type sockBackendRuntimeConfiguration struct {
	path       string
	extensions sockBackendExtension
}

func loadSockBackendRuntimeConfiguration(
	entry directory.Entry,
) (*sockBackendRuntimeConfiguration, error) {
	pathValues := entry.Values("olcDbSocketPath")
	if len(pathValues) != 1 {
		return nil, fmt.Errorf("%s olcDbSocketPath must have exactly one value", entry.DN)
	}
	path := string(pathValues[0])
	if path == "" || !utf8.ValidString(path) || strings.IndexByte(path, 0) >= 0 {
		return nil, fmt.Errorf("%s olcDbSocketPath is invalid", entry.DN)
	}

	configuration := &sockBackendRuntimeConfiguration{path: path}
	extensionValues := make([]string, 0, len(entry.Values("olcDbSocketExtensions")))
	for _, raw := range entry.Values("olcDbSocketExtensions") {
		value := string(raw)
		if strings.HasPrefix(value, "{") {
			end := strings.IndexByte(value, '}')
			if end < 2 {
				return nil, fmt.Errorf(
					"%s olcDbSocketExtensions has invalid ordering prefix",
					entry.DN,
				)
			}
			for _, character := range value[1:end] {
				if character < '0' || character > '9' {
					return nil, fmt.Errorf(
						"%s olcDbSocketExtensions has invalid ordering prefix",
						entry.DN,
					)
				}
			}
			value = value[end+1:]
		}
		extensionValues = append(extensionValues, value)
	}
	if err := schema.ValidateOpenLDAPSockExtensions(extensionValues...); err != nil {
		return nil, fmt.Errorf("%s: %w", entry.DN, err)
	}
	for _, value := range extensionValues {
		for _, extension := range strings.Fields(value) {
			switch strings.ToLower(extension) {
			case "binddn":
				configuration.extensions |= sockExtensionBindDN
			case "peername":
				configuration.extensions |= sockExtensionPeerName
			case "ssf":
				configuration.extensions |= sockExtensionSSF
			case "connid":
				configuration.extensions |= sockExtensionConnectionID
			default:
				return nil, fmt.Errorf(
					"%s olcDbSocketExtensions contains unknown extension %q",
					entry.DN,
					extension,
				)
			}
		}
	}
	return configuration, nil
}

func (server *Server) trySockBackendOperation(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
) (bool, error) {
	database := sockBackendDatabaseForMessage(state, message)
	if database == nil {
		return false, nil
	}
	message.Controls = withoutSessionTrackingControls(message.Controls)
	message.Controls = withoutLazyCommitControls(message.Controls)
	if hasLDAPControl(message.Controls, transactionSpecificationControlOID) {
		// RFC 5805 controls belong to the transaction queue layer. Yield before
		// opening a socket so malformed controls retain their RFC result codes
		// and valid controls are rejected as non-atomic during queueing.
		return false, nil
	}
	if failure := sockBackendGlobalControlFailure(message.Controls, false); failure != nil {
		return true, writeResultForMessage(connection, message, *failure)
	}
	controls, failure := parseRequestControlsWithDisallows(
		message.Controls,
		sockBackendControlSupport(message.Request),
		state.runtime.disallows,
	)
	if failure != nil {
		return true, writeResultForMessage(connection, message, *failure)
	}
	validatedRequest, failure := validateSockBackendFrontend(
		state.runtime,
		*database,
		message.Request,
		controls,
	)
	if failure != nil {
		return true, writeResultForMessage(connection, message, *failure)
	}
	message.Request = validatedRequest
	generatedPassword, failure, err := prepareSockPasswordModify(state, message)
	if err != nil {
		return true, err
	}
	if generatedPassword != nil {
		defer clear(generatedPassword)
	}
	if failure != nil {
		return true, writeResultForMessage(connection, message, *failure)
	}
	target, writeOperation, _, _ := chainOperationTarget(state, message.Request)
	if writeOperation {
		if failure := updateOperationPrecondition(
			state.runtime,
			state.boundDN,
			target,
		); failure != nil {
			return true, writeResultForMessage(connection, message, *failure)
		}
	}
	if databaseRestricts(*database, requestDatabaseRestriction(message.Request)) {
		return true, writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"operation restricted",
			),
		)
	}
	allowed, err := server.sockBackendAccessAllowed(
		ctx,
		state,
		*database,
		message.Request,
		controls.relax,
	)
	if err != nil {
		return true, err
	}
	if !allowed {
		return true, writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(ldapwire.ResultInsufficientAccessRights, ""),
		)
	}

	operation, ok := sockOperationForLDAPRequest(message.Request)
	if !ok {
		return false, nil
	}
	if request, search := operation.(SockSearchRequest); search {
		request.SizeLimit = effectiveDatabaseSearchLimit(
			state.runtime,
			*database,
			state.boundDN,
			server.config.MaxSearchEntries,
			request.SizeLimit,
		)
		operation = request
	}
	request := sockRequestForOperation(
		state,
		*database,
		message.ID,
		state.operationRealDN,
		operation,
	)
	search, isSearch := message.Request.(ldapwire.SearchRequest)
	if isSearch {
		sockSearch := operation.(SockSearchRequest)
		result, err := server.executeSockBackendSearch(
			ctx,
			connection,
			state,
			*database,
			search,
			request,
			sockSearch.SizeLimit,
		)
		if err != nil {
			return true, err
		}
		return true, server.writeSearchDone(connection, message.ID, result)
	}

	response, failure, err := server.executeSockBackendRequest(
		ctx,
		database.sockBackend,
		request,
		true,
	)
	if err != nil {
		return true, err
	}
	if failure != nil {
		return true, writeResultForMessage(connection, message, *failure)
	}

	if len(response.Entries) != 0 || len(response.References) != 0 {
		return true, writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(
				ldapwire.ResultOther,
				sockBackendFailureDiagnostic,
			),
		)
	}
	if request, ok := message.Request.(ldapwire.ExtendedRequest); ok &&
		request.Name == passwordModifyOID &&
		response.Result.Code == ldapwire.ResultSuccess &&
		generatedPassword != nil {
		return true, server.writePasswordModifyResult(
			connection,
			message.ID,
			response.Result,
			ldapwire.EncodePasswordModifyResponseValue(generatedPassword),
		)
	}
	return true, writeResultForMessage(connection, message, response.Result)
}

func prepareSockPasswordModify(
	state *connectionState,
	message ldapwire.Message,
) ([]byte, *ldapwire.Result, error) {
	request, ok := message.Request.(ldapwire.ExtendedRequest)
	if !ok || request.Name != passwordModifyOID {
		return nil, nil, nil
	}
	if state.boundDN == "" {
		result := ldapwire.ResultError(
			ldapwire.ResultStrongerAuthRequired,
			"only authenticated users may change passwords",
		)
		return nil, &result, nil
	}
	decoded, err := ldapwire.DecodePasswordModifyRequestValue(
		request.Value,
		request.HasValue,
	)
	if err != nil {
		result := ldapwire.ResultError(
			ldapwire.ResultProtocolError,
			"data decoding error",
		)
		return nil, &result, nil
	}
	defer clear(decoded.OldPassword)
	defer clear(decoded.NewPassword)
	if decoded.HasOldPassword && len(decoded.OldPassword) == 0 {
		result := ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"old password value is empty",
		)
		return nil, &result, nil
	}
	if decoded.HasNewPassword && len(decoded.NewPassword) == 0 {
		result := ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"new password value is empty",
		)
		return nil, &result, nil
	}
	if decoded.HasNewPassword {
		return nil, nil, nil
	}
	password, err := generatePassword()
	if err != nil {
		return nil, nil, err
	}
	return password, nil, nil
}

func (server *Server) trySockBackendBind(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.BindRequest,
	requestDN directory.DN,
) (bool, error) {
	database := databaseForDN(state.runtime, requestDN)
	if database == nil || database.sockBackend == nil {
		return false, nil
	}
	if failure := sockBackendGlobalControlFailure(message.Controls, true); failure != nil {
		return true, ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			*failure,
			nil,
		))
	}
	allowed, err := server.sockBackendAccessAllowed(
		ctx,
		state,
		*database,
		request,
		false,
	)
	if err != nil {
		return true, err
	}
	if !allowed {
		return true, ldapwire.Write(connection, ldapwire.EncodeBindResponse(
			message.ID,
			ldapwire.ResultError(ldapwire.ResultInsufficientAccessRights, ""),
			nil,
		))
	}

	sockRequest := sockRequestForOperation(
		state,
		*database,
		message.ID,
		state.boundDN,
		SockBindRequest{
			DN:          request.Name,
			Method:      sockSimpleAuthenticationMethod,
			Credentials: request.Authentication.Simple,
		},
	)
	response, failure, err := server.executeSockBackendRequest(
		ctx,
		database.sockBackend,
		sockRequest,
		true,
	)
	if err != nil {
		return true, err
	}
	if failure != nil {
		response.Result = *failure
	} else if len(response.Entries) != 0 || len(response.References) != 0 {
		response.Result = ldapwire.ResultError(
			ldapwire.ResultOther,
			sockBackendFailureDiagnostic,
		)
	}
	if response.Result.Code == ldapwire.ResultSuccess {
		state.boundDN = request.Name
		state.authMechanism = "SIMPLE"
		state.bindCredentialDN = request.Name
		state.bindCredentials = append([]byte(nil), request.Authentication.Simple...)
	}
	return true, ldapwire.Write(connection, ldapwire.EncodeBindResponse(
		message.ID,
		response.Result,
		nil,
	))
}

func sockBackendGlobalControlFailure(
	controls []ldapwire.Control,
	bind bool,
) *ldapwire.Result {
	for _, control := range controls {
		if !control.Critical {
			continue
		}
		switch control.OID {
		case chainingBehaviorControlOID:
			result := ldapwire.ResultError(
				ldapwire.ResultUnavailableCriticalExtension,
				"chaining behavior control is not supported by sock backend",
			)
			return &result
		case passwordPolicyControlOID:
			if bind {
				result := ldapwire.ResultError(
					ldapwire.ResultUnavailableCriticalExtension,
					"password policy control is not supported by sock backend Bind",
				)
				return &result
			}
		}
	}
	return nil
}

func sockBackendTransactionResult() ldapwire.Result {
	return ldapwire.ResultError(
		ldapwire.ResultUnwillingToPerform,
		sockBackendTransactionDiagnostic,
	)
}

func (server *Server) notifySockBackends(
	ctx context.Context,
	state *connectionState,
	message ldapwire.Message,
) {
	runtime := server.runtime.Load()
	if runtime == nil {
		return
	}
	for index := range runtime.databases {
		database := runtime.databases[index]
		if database.sockBackend == nil {
			continue
		}
		request := sockRequestForOperation(
			state,
			database,
			message.ID,
			state.boundDN,
			SockUnbindRequest{},
		)
		_, _, _ = server.executeSockBackendRequest(
			ctx,
			database.sockBackend,
			request,
			false,
		)
	}
}

func sockBackendDatabaseForMessage(
	state *connectionState,
	message ldapwire.Message,
) *runtimeDatabase {
	switch message.Request.(type) {
	case ldapwire.BindRequest, ldapwire.UnbindRequest, ldapwire.AbandonRequest:
		return nil
	}
	target, _, _, ok := chainOperationTarget(state, message.Request)
	if !ok {
		return nil
	}
	database := databaseForDN(state.runtime, target)
	if database == nil || database.sockBackend == nil {
		return nil
	}
	return database
}

func sockOperationForLDAPRequest(request ldapwire.Request) (SockOperation, bool) {
	switch request := request.(type) {
	case ldapwire.AddRequest:
		return SockAddRequest{Entry: request.Entry}, true
	case ldapwire.SearchRequest:
		return SockSearchRequest{
			BaseDN:       request.BaseDN,
			Scope:        request.Scope,
			DerefAliases: request.DerefAliases,
			SizeLimit:    request.SizeLimit,
			TimeLimit:    request.TimeLimit,
			Filter:       request.Filter,
			TypesOnly:    request.TypesOnly,
			Attributes:   append([]string(nil), request.Attributes...),
		}, true
	case ldapwire.CompareRequest:
		return SockCompareRequest{
			DN:        request.DN,
			Attribute: request.Attribute,
			Assertion: append([]byte(nil), request.Assertion...),
		}, true
	case ldapwire.ModifyRequest:
		return SockModifyRequest{
			DN:      request.DN,
			Changes: request.Changes,
		}, true
	case ldapwire.ModifyDNRequest:
		return SockModifyDNRequest{
			DN:             request.DN,
			NewRDN:         request.NewRDN,
			DeleteOldRDN:   request.DeleteOldRDN,
			NewSuperior:    request.NewSuperior,
			HasNewSuperior: request.HasNewSuperior,
		}, true
	case ldapwire.DeleteRequest:
		return SockDeleteRequest{DN: request.DN}, true
	case ldapwire.ExtendedRequest:
		return SockExtendedRequest{
			OID:      request.Name,
			Value:    append([]byte(nil), request.Value...),
			HasValue: request.HasValue,
		}, true
	default:
		return nil, false
	}
}

func sockRequestForOperation(
	state *connectionState,
	database runtimeDatabase,
	messageID int64,
	connectionBindDN string,
	operation SockOperation,
) SockRequest {
	request := SockRequest{
		MessageID: messageID,
		Operation: operation,
		Connection: SockConnectionFields{
			IncludeBindDN:   database.sockBackend.extensions&sockExtensionBindDN != 0,
			BindDN:          connectionBindDN,
			IncludePeerName: database.sockBackend.extensions&sockExtensionPeerName != 0,
			PeerName:        openLDAPConnectionName(remoteAddress(state.connection)),
			IncludeSSF:      database.sockBackend.extensions&sockExtensionSSF != 0,
			SSF:             int(connectionOverallSSF(state)),
			IncludeConnID:   database.sockBackend.extensions&sockExtensionConnectionID != 0,
			ConnID:          state.connectionID,
		},
	}
	request.Suffixes = make([]string, len(database.suffixes))
	for index := range database.suffixes {
		request.Suffixes[index] = database.suffixes[index].String()
	}
	return request
}

func (server *Server) executeSockBackendRequest(
	ctx context.Context,
	configuration *sockBackendRuntimeConfiguration,
	request SockRequest,
	expectResponse bool,
) (SockResponse, *ldapwire.Result, error) {
	connection, closeConnection, failure, err := server.openSockBackendRequest(
		ctx,
		configuration,
		request,
	)
	if err != nil || failure != nil {
		return SockResponse{}, failure, err
	}
	defer closeConnection()
	if !expectResponse {
		return SockResponse{}, nil, nil
	}

	response, err := ParseSockResponse(connection, SockProtocolLimits{})
	if err != nil {
		if ctx.Err() != nil {
			return SockResponse{}, nil, ctx.Err()
		}
		server.logSockBackendResponseFailure(configuration, request, err)
		result := ldapwire.ResultError(
			ldapwire.ResultOther,
			sockBackendFailureDiagnostic,
		)
		return SockResponse{}, &result, nil
	}
	return response, nil, nil
}

func (server *Server) openSockBackendRequest(
	ctx context.Context,
	configuration *sockBackendRuntimeConfiguration,
	request SockRequest,
) (net.Conn, func(), *ldapwire.Result, error) {
	encoded, err := EncodeSockRequest(request, SockProtocolLimits{})
	if err != nil {
		server.config.Logger.Debug(
			"back-sock request encoding failed",
			"path", configuration.path,
			"message_id", request.MessageID,
			"error", err,
		)
		result := ldapwire.ResultError(
			ldapwire.ResultOther,
			sockBackendFailureDiagnostic,
		)
		return nil, nil, &result, nil
	}

	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", configuration.path)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, nil, ctx.Err()
		}
		result := ldapwire.ResultError(
			ldapwire.ResultOther,
			sockBackendOpenDiagnostic,
		)
		return nil, nil, &result, nil
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.Close()
	})
	closeConnection := func() {
		stopCancellation()
		_ = connection.Close()
	}

	if err := writeAll(connection, encoded); err != nil {
		closeConnection()
		if ctx.Err() != nil {
			return nil, nil, nil, ctx.Err()
		}
		server.config.Logger.Debug(
			"back-sock request write failed",
			"path", configuration.path,
			"message_id", request.MessageID,
			"error", err,
		)
		result := ldapwire.ResultError(
			ldapwire.ResultOther,
			sockBackendFailureDiagnostic,
		)
		return nil, nil, &result, nil
	}
	return connection, closeConnection, nil, nil
}

func (server *Server) logSockBackendResponseFailure(
	configuration *sockBackendRuntimeConfiguration,
	request SockRequest,
	err error,
) {
	server.config.Logger.Debug(
		"back-sock response parsing failed",
		"path", configuration.path,
		"message_id", request.MessageID,
		"error", err,
	)
}

var errSockBackendSearchSizeLimit = errors.New("back-sock Search size limit reached")

func (server *Server) executeSockBackendSearch(
	ctx context.Context,
	clientConnection net.Conn,
	state *connectionState,
	database runtimeDatabase,
	search ldapwire.SearchRequest,
	request SockRequest,
	sizeLimit int,
) (ldapwire.Result, error) {
	connection, closeConnection, failure, err := server.openSockBackendRequest(
		ctx,
		database.sockBackend,
		request,
	)
	if err != nil {
		return ldapwire.Result{}, err
	}
	if failure != nil {
		return *failure, nil
	}
	defer closeConnection()

	delivered := 0
	var emitFailure error
	result, err := StreamSockResponse(
		connection,
		SockProtocolLimits{},
		func(record SockResponseRecord) error {
			if record.Entry != nil {
				selected, selectErr := server.sockBackendSearchEntry(
					ctx,
					state,
					database,
					search,
					*record.Entry,
				)
				if selectErr != nil {
					emitFailure = selectErr
					return selectErr
				}
				if selected == nil {
					return nil
				}
				if sizeLimit > 0 && delivered >= sizeLimit {
					emitFailure = errSockBackendSearchSizeLimit
					return emitFailure
				}
				controls := server.passwordPolicySearchEntryControls(ctx, state, *selected)
				writeErr := ldapwire.Write(
					clientConnection,
					ldapwire.EncodeSearchResultEntry(
						request.MessageID,
						*selected,
						controls,
					),
				)
				if writeErr != nil {
					emitFailure = writeErr
					return writeErr
				}
				delivered++
				return nil
			}

			writeErr := ldapwire.Write(
				clientConnection,
				ldapwire.EncodeSearchResultReference(
					request.MessageID,
					record.Referrals,
					nil,
				),
			)
			if writeErr != nil {
				emitFailure = writeErr
			}
			return writeErr
		},
	)
	if err == nil {
		return result, nil
	}
	if ctx.Err() != nil {
		return ldapwire.Result{}, ctx.Err()
	}
	if errors.Is(err, errSockBackendSearchSizeLimit) {
		return ldapwire.Result{Code: ldapwire.ResultSizeLimitExceeded}, nil
	}
	if emitFailure != nil {
		return ldapwire.Result{}, emitFailure
	}
	server.logSockBackendResponseFailure(database.sockBackend, request, err)
	return ldapwire.ResultError(
		ldapwire.ResultOther,
		sockBackendFailureDiagnostic,
	), nil
}

func (server *Server) sockBackendAccessAllowed(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	request ldapwire.Request,
	relax bool,
) (bool, error) {
	var (
		entry     directory.Entry
		privilege acl.Privilege
		check     bool
	)
	switch request := request.(type) {
	case ldapwire.AddRequest:
		entry = request.Entry
		privilege = acl.WriteAdd
		check = true
	case ldapwire.BindRequest:
		entry = directory.Entry{DN: request.Name}
		privilege = acl.Auth
		check = true
	case ldapwire.CompareRequest:
		entry = directory.Entry{DN: request.DN}
		privilege = acl.Compare
		check = true
	case ldapwire.DeleteRequest:
		entry = directory.Entry{DN: request.DN}
		privilege = acl.WriteDelete
		check = true
	case ldapwire.ModifyRequest:
		entry = directory.Entry{DN: request.DN}
		privilege = acl.Write
		check = true
	case ldapwire.ModifyDNRequest:
		entry = directory.Entry{DN: request.DN}
		privilege = acl.Write
		if request.HasNewSuperior {
			privilege = acl.WriteDelete
		}
		check = true
	}
	if !check {
		return true, nil
	}
	if relax {
		switch request.(type) {
		case ldapwire.AddRequest,
			ldapwire.DeleteRequest,
			ldapwire.ModifyRequest,
			ldapwire.ModifyDNRequest:
			privilege = acl.Manage
		}
	}

	allowed := false
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		allowed = server.allowed(
			state.runtime,
			readerForDatabase(reader, database),
			state.boundDN,
			entry,
			"entry",
			nil,
			privilege,
		)
		return nil
	})
	return allowed, err
}

func (server *Server) sockBackendSearchEntry(
	ctx context.Context,
	state *connectionState,
	database runtimeDatabase,
	request ldapwire.SearchRequest,
	entry directory.Entry,
) (*directory.Entry, error) {
	var selected *directory.Entry
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := readerForDatabase(reader, database)
		if !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			"entry",
			nil,
			acl.Read,
		) {
			return nil
		}
		readable := server.attributesWithPrivilege(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			acl.Read,
			request.TypesOnly,
		)
		value := server.selectEntry(
			state.runtime,
			readable,
			request.Attributes,
			request.TypesOnly,
		)
		selected = &value
		return nil
	})
	return selected, err
}
