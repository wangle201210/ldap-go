package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	sockOverlayFailureDiagnostic      = "external socket overlay service failed"
	sockOverlayTransactionDiagnostic  = "socket overlay cannot atomically participate in transactions"
	sockOverlayDefaultCallbackTimeout = 5 * time.Second
	sockOverlayMinimumCallbackTimeout = time.Millisecond
	sockOverlayMaximumCallbackTimeout = 5 * time.Minute
)

type sockOverlayOperationMask uint16

const (
	sockOverlayBind sockOverlayOperationMask = 1 << iota
	sockOverlayUnbind
	sockOverlaySearch
	sockOverlayCompare
	sockOverlayModify
	sockOverlayModifyDN
	sockOverlayAdd
	sockOverlayDelete
	sockOverlayExtended
)

type sockOverlayResponseMask uint8

const (
	sockOverlayResponseResult sockOverlayResponseMask = 1 << iota
	sockOverlayResponseSearch
)

type sockOverlayRuntimeConfiguration struct {
	backend         sockBackendRuntimeConfiguration
	operations      sockOverlayOperationMask
	responses       sockOverlayResponseMask
	dnPattern       *regexp.Regexp
	callbackTimeout time.Duration
	configDNKey     string
}

func loadSockOverlayRuntimeConfiguration(
	entry directory.Entry,
) (sockOverlayRuntimeConfiguration, error) {
	backend, err := loadSockBackendRuntimeConfiguration(entry)
	if err != nil {
		return sockOverlayRuntimeConfiguration{}, err
	}
	configuration := sockOverlayRuntimeConfiguration{
		backend:         *backend,
		callbackTimeout: sockOverlayDefaultCallbackTimeout,
		configDNKey:     entry.DN,
	}
	timeouts := entry.Values("olcOvSocketCallbackTimeout")
	if len(timeouts) > 1 {
		return sockOverlayRuntimeConfiguration{}, fmt.Errorf(
			"%s olcOvSocketCallbackTimeout must be single-valued",
			entry.DN,
		)
	}
	if len(timeouts) == 1 {
		value := strings.TrimSpace(string(timeouts[0]))
		timeout, parseErr := time.ParseDuration(value)
		if parseErr != nil || timeout < sockOverlayMinimumCallbackTimeout ||
			timeout > sockOverlayMaximumCallbackTimeout {
			return sockOverlayRuntimeConfiguration{}, fmt.Errorf(
				"%s olcOvSocketCallbackTimeout must be a duration from %s through %s",
				entry.DN,
				sockOverlayMinimumCallbackTimeout,
				sockOverlayMaximumCallbackTimeout,
			)
		}
		configuration.callbackTimeout = timeout
	}
	operationNames := map[string]sockOverlayOperationMask{
		"bind":     sockOverlayBind,
		"unbind":   sockOverlayUnbind,
		"search":   sockOverlaySearch,
		"compare":  sockOverlayCompare,
		"modify":   sockOverlayModify,
		"modrdn":   sockOverlayModifyDN,
		"add":      sockOverlayAdd,
		"delete":   sockOverlayDelete,
		"extended": sockOverlayExtended,
	}
	for _, name := range sockOverlayConfigurationFields(entry.Values("olcOvSocketOps")) {
		mask, ok := operationNames[strings.ToLower(name)]
		if !ok {
			return sockOverlayRuntimeConfiguration{}, fmt.Errorf(
				"%s olcOvSocketOps contains unknown operation %q",
				entry.DN,
				name,
			)
		}
		configuration.operations |= mask
	}
	responseNames := map[string]sockOverlayResponseMask{
		"result": sockOverlayResponseResult,
		"search": sockOverlayResponseSearch,
	}
	for _, name := range sockOverlayConfigurationFields(entry.Values("olcOvSocketResps")) {
		mask, ok := responseNames[strings.ToLower(name)]
		if !ok {
			return sockOverlayRuntimeConfiguration{}, fmt.Errorf(
				"%s olcOvSocketResps contains unknown response %q",
				entry.DN,
				name,
			)
		}
		configuration.responses |= mask
	}

	patterns := entry.Values("olcOvSocketDNpat")
	if len(patterns) > 1 {
		return sockOverlayRuntimeConfiguration{}, fmt.Errorf(
			"%s olcOvSocketDNpat must be single-valued",
			entry.DN,
		)
	}
	if len(patterns) == 1 {
		pattern := string(patterns[0])
		if !utf8.ValidString(pattern) || strings.IndexByte(pattern, 0) >= 0 {
			return sockOverlayRuntimeConfiguration{}, fmt.Errorf(
				"%s olcOvSocketDNpat is invalid",
				entry.DN,
			)
		}
		if _, compileErr := regexp.CompilePOSIX(pattern); compileErr != nil {
			return sockOverlayRuntimeConfiguration{}, fmt.Errorf(
				"%s olcOvSocketDNpat is not a portable POSIX ERE: %w",
				entry.DN,
				compileErr,
			)
		}
		compiled, compileErr := regexp.Compile("(?i:" + pattern + ")")
		if compileErr != nil {
			return sockOverlayRuntimeConfiguration{}, fmt.Errorf(
				"%s olcOvSocketDNpat: %w",
				entry.DN,
				compileErr,
			)
		}
		configuration.dnPattern = compiled
	}
	return configuration, nil
}

func sockOverlayConfigurationFields(values [][]byte) []string {
	var fields []string
	for _, raw := range values {
		value := string(raw)
		if strings.HasPrefix(value, "{") {
			if end := strings.IndexByte(value, '}'); end >= 2 {
				ordered := true
				for _, character := range value[1:end] {
					if character < '0' || character > '9' {
						ordered = false
						break
					}
				}
				if ordered {
					value = value[end+1:]
				}
			}
		}
		fields = append(fields, strings.Fields(value)...)
	}
	return fields
}

func (server *Server) trySockOverlayOperation(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
) (net.Conn, bool, error) {
	if _, unbind := message.Request.(ldapwire.UnbindRequest); unbind {
		return connection, false, server.notifySockOverlayUnbind(ctx, state, message)
	}
	if bind, ok := message.Request.(ldapwire.BindRequest); ok &&
		bind.Authentication.IsSASL &&
		runtimeRejectsSockOverlaySASLBind(state.runtime) {
		clearSockOverlayBindState(state)
		result := ldapwire.ResultError(
			ldapwire.ResultAuthMethodNotSupported,
			"socket overlay protocol cannot represent SASL bind mechanisms",
		)
		return connection, true, writeResultForMessage(connection, message, result)
	}
	database := sockOverlayDatabaseForMessage(state, message)
	if database == nil || len(database.sockOverlays) == 0 {
		return connection, false, nil
	}

	operation, operationMask, supported := sockOverlayOperationForLDAPRequest(message.Request)
	matching := make([]sockOverlayRuntimeConfiguration, 0, len(database.sockOverlays))
	callbacks := make([]sockOverlayRuntimeConfiguration, 0, len(database.sockOverlays))
	requestDN := sockOverlayRequestDN(state.runtime, *database, message.Request)
	for _, configuration := range database.sockOverlays {
		if configuration.responses != 0 {
			callbacks = append(callbacks, configuration)
		}
		if supported && configuration.operations&operationMask != 0 &&
			(configuration.dnPattern == nil || configuration.dnPattern.MatchString(requestDN)) {
			matching = append(matching, configuration)
		}
	}
	if len(matching) == 0 && len(callbacks) == 0 {
		return connection, false, nil
	}
	if _, bind := message.Request.(ldapwire.BindRequest); bind {
		clearSockOverlayBindState(state)
	}
	if hasLDAPControl(message.Controls, transactionSpecificationControlOID) {
		result := ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			sockOverlayTransactionDiagnostic,
		)
		return connection, true, writeResultForMessage(connection, message, result)
	}
	if len(message.Controls) != 0 {
		code := ldapwire.ResultUnwillingToPerform
		for _, control := range message.Controls {
			if control.Critical {
				code = ldapwire.ResultUnavailableCriticalExtension
				break
			}
		}
		result := ldapwire.ResultError(
			code,
			"socket overlay protocol cannot represent LDAP controls",
		)
		return connection, true, writeResultForMessage(connection, message, result)
	}
	if bind, ok := message.Request.(ldapwire.BindRequest); ok && bind.Authentication.IsSASL && len(matching) != 0 {
		result := ldapwire.ResultError(
			ldapwire.ResultAuthMethodNotSupported,
			"socket overlay protocol cannot represent SASL bind mechanisms",
		)
		return connection, true, writeResultForMessage(connection, message, result)
	}

	for _, configuration := range matching {
		request := sockRequestForOverlayOperation(
			state,
			*database,
			configuration,
			message.ID,
			state.operationRealDN,
			operation,
		)
		response, failure, err := server.executeSockOverlayRequest(
			ctx,
			configuration,
			request,
		)
		if err != nil {
			return connection, true, err
		}
		if failure != nil {
			return connection, true, writeResultForMessage(connection, message, *failure)
		}
		if response.Continue {
			continue
		}
		return connection, true, server.writeSockOverlayShortCircuitResponse(
			ctx,
			connection,
			state,
			*database,
			message,
			response.Response,
		)
	}

	if len(callbacks) != 0 {
		connection = &sockOverlayResponseConnection{
			Conn:           connection,
			ctx:            ctx,
			server:         server,
			state:          state,
			messageID:      message.ID,
			configurations: callbacks,
		}
	}
	return connection, false, nil
}

func runtimeRejectsSockOverlaySASLBind(runtime *runtimeState) bool {
	if runtime == nil {
		return false
	}
	for databaseIndex := range runtime.databases {
		for _, configuration := range runtime.databases[databaseIndex].sockOverlays {
			if configuration.operations&sockOverlayBind != 0 &&
				(configuration.dnPattern == nil || configuration.dnPattern.MatchString("")) {
				return true
			}
		}
	}
	return false
}

func clearSockOverlayBindState(state *connectionState) {
	clearLDAPTransaction(state.transaction)
	state.transaction = nil
	clearBindCredentials(state)
	state.boundDN = ""
	state.authMechanism = ""
	state.passwordPolicyRestrictedDN = ""
	clearSearchSessions(state)
	clearSASLSession(state)
}

func sockOverlayDatabaseForMessage(
	state *connectionState,
	message ldapwire.Message,
) *runtimeDatabase {
	switch request := message.Request.(type) {
	case ldapwire.BindRequest:
		dn, err := parseRuntimeConnectionDN(state.runtime, request.Name)
		if err != nil {
			return nil
		}
		return databaseForDN(state.runtime, dn)
	case ldapwire.AbandonRequest:
		return nil
	}
	target, _, _, ok := chainOperationTarget(state, message.Request)
	if !ok {
		return nil
	}
	return databaseForDN(state.runtime, target)
}

func sockOverlayRequestDN(
	runtime *runtimeState,
	database runtimeDatabase,
	request ldapwire.Request,
) string {
	var value string
	switch request := request.(type) {
	case ldapwire.BindRequest:
		value = request.Name
	case ldapwire.SearchRequest:
		value = request.BaseDN
	case ldapwire.AddRequest:
		value = request.Entry.DN
	case ldapwire.CompareRequest:
		value = request.DN
	case ldapwire.ModifyRequest:
		value = request.DN
	case ldapwire.ModifyDNRequest:
		value = request.DN
	case ldapwire.DeleteRequest:
		value = request.DN
	}
	dn, err := parseRuntimeDN(value, database.dnNormalizer)
	if err != nil && runtime != nil && runtime.schema != nil {
		dn, err = parseRuntimeDN(value, runtime.schema)
	}
	if err != nil {
		return value
	}
	return dn.NormalizedString()
}

func sockOverlayOperationForLDAPRequest(
	request ldapwire.Request,
) (SockOperation, sockOverlayOperationMask, bool) {
	if bind, ok := request.(ldapwire.BindRequest); ok {
		credentials := bind.Authentication.Simple
		if bind.Authentication.IsSASL {
			credentials = bind.Authentication.SASLCredentials
		}
		return SockBindRequest{
			DN:          bind.Name,
			Method:      sockSimpleAuthenticationMethod,
			Credentials: append([]byte(nil), credentials...),
		}, sockOverlayBind, true
	}
	operation, ok := sockOperationForLDAPRequest(request)
	if !ok {
		return nil, 0, false
	}
	switch operation.(type) {
	case SockSearchRequest:
		return operation, sockOverlaySearch, true
	case SockCompareRequest:
		return operation, sockOverlayCompare, true
	case SockModifyRequest:
		return operation, sockOverlayModify, true
	case SockModifyDNRequest:
		return operation, sockOverlayModifyDN, true
	case SockAddRequest:
		return operation, sockOverlayAdd, true
	case SockDeleteRequest:
		return operation, sockOverlayDelete, true
	case SockExtendedRequest:
		return operation, sockOverlayExtended, true
	default:
		return nil, 0, false
	}
}

func sockRequestForOverlayOperation(
	state *connectionState,
	database runtimeDatabase,
	configuration sockOverlayRuntimeConfiguration,
	messageID int64,
	connectionBindDN string,
	operation SockOperation,
) SockRequest {
	request := SockRequest{
		MessageID: messageID,
		Operation: operation,
		Connection: SockConnectionFields{
			IncludeBindDN:   configuration.backend.extensions&sockExtensionBindDN != 0,
			BindDN:          connectionBindDN,
			IncludePeerName: configuration.backend.extensions&sockExtensionPeerName != 0,
			PeerName:        openLDAPConnectionName(remoteAddress(state.connection)),
			IncludeSSF:      configuration.backend.extensions&sockExtensionSSF != 0,
			SSF:             int(connectionOverallSSF(state)),
			IncludeConnID:   configuration.backend.extensions&sockExtensionConnectionID != 0,
			ConnID:          state.connectionID,
		},
	}
	if sockOperationIncludesSuffixes(operation) {
		request.Suffixes = make([]string, len(database.suffixes))
		for index := range database.suffixes {
			request.Suffixes[index] = database.suffixes[index].String()
		}
	}
	return request
}

func (server *Server) executeSockOverlayRequest(
	ctx context.Context,
	configuration sockOverlayRuntimeConfiguration,
	request SockRequest,
) (SockOverlayOperationResponse, *ldapwire.Result, error) {
	connection, closeConnection, failure, err := server.openSockBackendRequest(
		ctx,
		&configuration.backend,
		request,
	)
	if err != nil || failure != nil {
		return SockOverlayOperationResponse{}, failure, err
	}
	defer closeConnection()
	response, err := ParseSockOverlayOperationResponse(connection, SockProtocolLimits{})
	if err == nil {
		return response, nil, nil
	}
	if ctx.Err() != nil {
		return SockOverlayOperationResponse{}, nil, ctx.Err()
	}
	server.logSockBackendResponseFailure(&configuration.backend, request, err)
	result := ldapwire.ResultError(ldapwire.ResultOther, sockOverlayFailureDiagnostic)
	return SockOverlayOperationResponse{}, &result, nil
}

func (server *Server) writeSockOverlayShortCircuitResponse(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	database runtimeDatabase,
	message ldapwire.Message,
	response SockResponse,
) error {
	if len(response.References) != 0 || len(response.Result.Referrals) != 0 {
		return writeResultForMessage(connection, message, ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"socket overlay protocol cannot preserve LDAP referrals",
		))
	}
	if search, ok := message.Request.(ldapwire.SearchRequest); ok {
		for _, entry := range response.Entries {
			selected, err := server.sockBackendSearchEntry(ctx, state, database, search, entry)
			if err != nil {
				return err
			}
			if selected == nil {
				continue
			}
			if err := server.writeSearchEntry(
				connection,
				message.ID,
				*selected,
				nil,
			); err != nil {
				return err
			}
		}
		return server.writeSearchDone(connection, message.ID, response.Result)
	}
	if len(response.Entries) != 0 {
		return writeResultForMessage(connection, message, ldapwire.ResultError(
			ldapwire.ResultOther,
			sockOverlayFailureDiagnostic,
		))
	}
	if bind, ok := message.Request.(ldapwire.BindRequest); ok &&
		response.Result.Code == ldapwire.ResultSuccess {
		state.boundDN = bind.Name
		state.authMechanism = "SIMPLE"
		state.bindCredentialDN = bind.Name
		state.bindCredentials = append([]byte(nil), bind.Authentication.Simple...)
	}
	return writeResultForMessage(connection, message, response.Result)
}

func (server *Server) notifySockOverlayUnbind(
	ctx context.Context,
	state *connectionState,
	message ldapwire.Message,
) error {
	if state.runtime == nil {
		return nil
	}
	for databaseIndex := range state.runtime.databases {
		database := state.runtime.databases[databaseIndex]
		for _, configuration := range database.sockOverlays {
			if configuration.operations&sockOverlayUnbind == 0 ||
				(configuration.dnPattern != nil && !configuration.dnPattern.MatchString("")) {
				continue
			}
			request := sockRequestForOverlayOperation(
				state,
				database,
				configuration,
				message.ID,
				state.boundDN,
				SockUnbindRequest{},
			)
			if err := server.sendSockOverlayNotification(ctx, configuration, request); err != nil {
				return err
			}
		}
	}
	return nil
}

func (server *Server) sendSockOverlayNotification(
	ctx context.Context,
	configuration sockOverlayRuntimeConfiguration,
	request SockRequest,
) error {
	timeout := configuration.callbackTimeout
	if timeout <= 0 {
		timeout = sockOverlayDefaultCallbackTimeout
	}
	callbackContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, closeConnection, failure, err := server.openSockBackendRequest(
		callbackContext,
		&configuration.backend,
		request,
	)
	if err != nil {
		if ctx.Err() == nil && errors.Is(callbackContext.Err(), context.DeadlineExceeded) {
			return fmt.Errorf(
				"socket overlay callback timed out after %s",
				timeout,
			)
		}
		return err
	}
	if failure != nil {
		return fmt.Errorf("%s: %s", sockOverlayFailureDiagnostic, failure.DiagnosticMessage)
	}
	defer closeConnection()
	closeWriter, ok := connection.(interface{ CloseWrite() error })
	if !ok {
		return errors.New("socket overlay notification connection cannot close its write side")
	}
	if err := closeWriter.CloseWrite(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(callbackContext.Err(), context.DeadlineExceeded) {
			return fmt.Errorf(
				"socket overlay callback timed out after %s",
				timeout,
			)
		}
		return fmt.Errorf("finish socket overlay notification: %w", err)
	}
	var unexpected [1]byte
	count, err := connection.Read(unexpected[:])
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(callbackContext.Err(), context.DeadlineExceeded) {
		return fmt.Errorf(
			"socket overlay callback timed out after %s",
			timeout,
		)
	}
	if count != 0 {
		return errors.New("socket overlay notification received an unexpected response")
	}
	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("wait for socket overlay notification consumer: %w", err)
	}
	return nil
}

type sockOverlayResponseConnection struct {
	net.Conn
	ctx            context.Context
	server         *Server
	state          *connectionState
	messageID      int64
	configurations []sockOverlayRuntimeConfiguration
	failed         bool
}

func (connection *sockOverlayResponseConnection) Write(value []byte) (int, error) {
	if connection.failed {
		return len(value), nil
	}
	packet, err := ber.DecodePacketErr(value)
	if err != nil {
		return 0, fmt.Errorf("inspect socket overlay LDAP response: %w", err)
	}
	if err := connection.notify(packet); err != nil {
		if connection.server != nil && connection.server.config.Logger != nil {
			connection.server.config.Logger.Debug(
				"socket overlay response callback failed closed",
				"message_id", connection.messageID,
				"error", err,
			)
		}
		connection.failed = true
		if err := connection.writeFailure(packet); err != nil {
			return 0, err
		}
		return len(value), nil
	}
	return connection.Conn.Write(value)
}

func (connection *sockOverlayResponseConnection) writeFailure(packet *ber.Packet) error {
	if packet == nil || len(packet.Children) < 2 {
		return errors.New("socket overlay cannot encode callback failure for malformed response")
	}
	tag := uint64(packet.Children[1].Tag)
	if tag == ldapwire.ApplicationSearchResultEntry ||
		tag == ldapwire.ApplicationSearchResultReference {
		tag = ldapwire.ApplicationSearchResultDone
	}
	if !sockOverlayResultResponseTag(tag) {
		return fmt.Errorf("socket overlay cannot encode callback failure for response tag %d", tag)
	}
	if tag == ldapwire.ApplicationBindResponse {
		clearSockOverlayBindState(connection.state)
	}
	return ldapwire.Write(connection.Conn, ldapwire.EncodeResultResponse(
		connection.messageID,
		tag,
		ldapwire.ResultError(ldapwire.ResultOther, sockOverlayFailureDiagnostic),
		nil,
	))
}

func (connection *sockOverlayResponseConnection) notify(packet *ber.Packet) error {
	if packet == nil || len(packet.Children) < 2 {
		return errors.New("socket overlay observed malformed LDAP response")
	}
	tag := uint64(packet.Children[1].Tag)
	for _, configuration := range connection.configurations {
		var operation SockOperation
		switch {
		case tag == ldapwire.ApplicationSearchResultEntry &&
			configuration.responses&sockOverlayResponseSearch != 0:
			if len(packet.Children) == 3 {
				return errors.New("socket overlay ENTRY callback cannot represent LDAP controls")
			}
			entry, err := decodeTranslucentSearchEntry(packet)
			if err != nil {
				return err
			}
			operation = SockOverlayEntryNotification{Entry: entry}
		case tag == ldapwire.ApplicationSearchResultReference &&
			configuration.responses&sockOverlayResponseSearch != 0:
			return errors.New("socket overlay callback cannot represent SearchResultReference")
		case sockOverlayResultResponseTag(tag) &&
			configuration.responses&sockOverlayResponseResult != 0:
			if len(packet.Children) == 3 {
				return errors.New("socket overlay RESULT callback cannot represent LDAP controls")
			}
			result, err := chainLDAPResult(packet, connection.messageID, tag)
			if err != nil {
				return err
			}
			if len(result.Referrals) != 0 {
				return errors.New("socket overlay RESULT callback cannot represent LDAP referrals")
			}
			if sockOverlayResultHasExtraFields(packet, tag) {
				return errors.New("socket overlay RESULT callback cannot represent extended response fields")
			}
			operation = SockOverlayResultNotification{Result: result}
		default:
			continue
		}
		request := SockRequest{
			MessageID: connection.messageID,
			Connection: SockConnectionFields{
				IncludeBindDN:   configuration.backend.extensions&sockExtensionBindDN != 0,
				BindDN:          connection.state.boundDN,
				IncludePeerName: configuration.backend.extensions&sockExtensionPeerName != 0,
				PeerName:        openLDAPConnectionName(remoteAddress(connection.state.connection)),
				IncludeSSF:      configuration.backend.extensions&sockExtensionSSF != 0,
				SSF:             int(connectionOverallSSF(connection.state)),
				IncludeConnID:   configuration.backend.extensions&sockExtensionConnectionID != 0,
				ConnID:          connection.state.connectionID,
			},
			Operation: operation,
		}
		if err := connection.server.sendSockOverlayNotification(
			connection.ctx,
			configuration,
			request,
		); err != nil {
			return err
		}
	}
	return nil
}

func sockOverlayResultResponseTag(tag uint64) bool {
	switch tag {
	case ldapwire.ApplicationBindResponse,
		ldapwire.ApplicationSearchResultDone,
		ldapwire.ApplicationModifyResponse,
		ldapwire.ApplicationAddResponse,
		ldapwire.ApplicationDeleteResponse,
		ldapwire.ApplicationModifyDNResponse,
		ldapwire.ApplicationCompareResponse,
		ldapwire.ApplicationExtendedResponse:
		return true
	default:
		return false
	}
}

func sockOverlayResultHasExtraFields(packet *ber.Packet, tag uint64) bool {
	if len(packet.Children) < 2 {
		return true
	}
	operation := packet.Children[1]
	for _, child := range operation.Children[3:] {
		if child.ClassType == ber.ClassContext && child.Tag == 3 {
			continue
		}
		if tag == ldapwire.ApplicationExtendedResponse || tag == ldapwire.ApplicationBindResponse {
			return true
		}
	}
	return false
}

func (connection *sockOverlayResponseConnection) beginFinalResponse() error {
	if finalizer, ok := connection.Conn.(interface{ beginFinalResponse() error }); ok {
		return finalizer.beginFinalResponse()
	}
	return nil
}
