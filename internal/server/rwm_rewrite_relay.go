package server

import (
	"context"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

// A DSL can rewrite each operation differently. Apply it once at the relay
// boundary, then let the selected database operate in its own namespace.
func (server *Server) tryRWMRewriteRelayOperation(ctx context.Context, connection net.Conn, state *connectionState, message ldapwire.Message) (bool, error) {
	if !state.runtime.features.rwmRewriteRelay {
		return false, nil
	}
	target, ok := rwmRewriteRequestTarget(state, message.Request)
	if !ok {
		return false, nil
	}
	database := databaseForDN(state.runtime, target)
	if database == nil || database.relay == nil || database.rwm == nil || !database.rwm.rewrite.active() {
		return false, nil
	}
	if result := rwmRewriteRelayRestrictionResult(state, message, *database); result != nil {
		return true, writeResultForMessage(connection, message, *result)
	}
	mapping := database.rwm
	fail := func(err error) (bool, error) {
		failure := asOperationFailure(err)
		result := ldapwire.ResultError(ldapwire.ResultOther, err.Error())
		if failure != nil {
			result = failure.result
		}
		if _, bind := message.Request.(ldapwire.BindRequest); bind {
			clearSockOverlayBindState(state)
		}
		return true, writeResultForMessage(connection, message, result)
	}
	mapped, err := mapMetaRequestToRemote(mapping, message)
	if err != nil {
		return fail(err)
	}
	remoteDN, ok := rwmRewriteRequestTarget(state, mapped.Request)
	if !ok {
		return fail(operationFailed(ldapwire.ResultOther, "RWM relay produced an invalid operation target"))
	}
	remote := databaseForDN(state.runtime, remoteDN)
	if remote == nil || remote.relay != nil {
		return fail(operationFailed(ldapwire.ResultNoSuchObject, "RWM relay has no target database"))
	}
	if index := database.relay.targetDatabaseIndex; index >= 0 && remote != &state.runtime.databases[index] {
		return fail(operationFailed(ldapwire.ResultUnwillingToPerform, "RWM relay target is outside its configured database"))
	}

	originalBoundDN, originalCredentialDN := state.boundDN, state.bindCredentialDN
	_, binding := message.Request.(ldapwire.BindRequest)
	if !binding && state.boundDN != "" {
		state.boundDN, err = mapMetaDNStringContext(mapping, state.boundDN, true, "bindDN")
		if err != nil {
			state.boundDN = originalBoundDN
			return fail(err)
		}
	}
	defer func() {
		if binding {
			if state.boundDN != "" {
				state.boundDN = message.Request.(ldapwire.BindRequest).Name
				state.bindCredentialDN = state.boundDN
			}
		} else {
			state.boundDN = originalBoundDN
			state.bindCredentialDN = originalCredentialDN
		}
	}()
	response := &rwmRewriteRelayConnection{Conn: connection, mapping: mapping, message: message}
	if remote.ldapBackend != nil {
		if handled, err := server.tryLDAPBackendOperation(ctx, response, state, mapped); handled {
			return true, err
		}
	}
	if remote.metaBackend != nil {
		if handled, err := server.tryMetaBackendOperation(ctx, response, state, mapped); handled {
			return true, err
		}
	}
	switch request := mapped.Request.(type) {
	case ldapwire.BindRequest:
		err = server.handleBind(ctx, response, state, mapped, request)
	case ldapwire.SearchRequest:
		err = server.handleSearch(ctx, response, state, mapped, request)
	case ldapwire.AddRequest:
		err = server.handleAdd(ctx, response, state, mapped, request)
	case ldapwire.ModifyRequest:
		err = server.handleModify(ctx, response, state, mapped, request)
	case ldapwire.DeleteRequest:
		err = server.handleDelete(ctx, response, state, mapped, request)
	case ldapwire.ModifyDNRequest:
		err = server.handleModifyDN(ctx, response, state, mapped, request)
	case ldapwire.CompareRequest:
		err = server.handleCompare(ctx, response, state, mapped, request)
	case ldapwire.ExtendedRequest:
		err = server.handleExtended(ctx, response, state, mapped, request)
	}
	return true, err
}

func rwmRewriteRelayRestrictionResult(
	state *connectionState,
	message ldapwire.Message,
	database runtimeDatabase,
) *ldapwire.Result {
	if failure := requestControlFailureBeforeSecurity(state, message); failure != nil {
		return failure
	}
	restriction := requestDatabaseRestriction(message.Request)
	if databaseRestricts(database, restriction) ||
		database.readOnly && rwmRewriteUpdateRequest(message.Request) {
		result := ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"operation restricted",
		)
		return &result
	}
	return nil
}

func rwmRewriteUpdateRequest(request ldapwire.Request) bool {
	switch request := request.(type) {
	case ldapwire.AddRequest, ldapwire.ModifyRequest,
		ldapwire.DeleteRequest, ldapwire.ModifyDNRequest:
		return true
	case ldapwire.ExtendedRequest:
		return request.Name != startTLSOID && request.Name != whoAmIOID &&
			request.Name != cancelOID
	default:
		return false
	}
}

func prepareRWMRewriteTransactionOperations(
	runtime *runtimeState,
	operations []ldapTransactionOperation,
) ([]ldapTransactionOperation, func(), *transactionCommitFailure) {
	effective := make([]ldapTransactionOperation, len(operations))
	for index, operation := range operations {
		effective[index] = operation
		effective[index].message = cloneTransactionReplayMessage(operation.message)
	}
	cleanup := func() {
		for index := range effective {
			clearLDAPTransactionOperation(&effective[index])
		}
	}
	fail := func(operation ldapTransactionOperation, result ldapwire.Result) (
		[]ldapTransactionOperation,
		func(),
		*transactionCommitFailure,
	) {
		return effective, cleanup, &transactionCommitFailure{
			messageID: operation.message.ID,
			result:    result,
		}
	}

	for index, operation := range effective {
		state := &connectionState{
			runtime: runtime,
			boundDN: operation.boundDN,
		}
		target, ok := rwmRewriteRequestTarget(state, operation.message.Request)
		if !ok {
			continue
		}
		database := databaseForDN(runtime, target)
		if database == nil || database.relay == nil || database.rwm == nil ||
			!database.rwm.rewrite.active() {
			continue
		}
		if result := rwmRewriteRelayRestrictionResult(state, operation.message, *database); result != nil {
			return fail(operation, *result)
		}
		mapped, err := mapMetaRequestToRemote(database.rwm, operation.message)
		if err != nil {
			result := ldapwire.ResultError(
				ldapwire.ResultOther,
				"RWM transaction rewrite failed: "+err.Error(),
			)
			if failure := asOperationFailure(err); failure != nil {
				result = failure.result
			}
			return fail(operation, result)
		}
		remoteDN, ok := rwmRewriteRequestTarget(state, mapped.Request)
		if !ok {
			return fail(operation, ldapwire.ResultError(
				ldapwire.ResultOther,
				"RWM transaction rewrite produced an invalid operation target",
			))
		}
		remote := databaseForDN(runtime, remoteDN)
		targetIndex := database.relay.targetDatabaseIndex
		if remote == nil || targetIndex < 0 ||
			remote != &runtime.databases[targetIndex] ||
			remote.partition != database.partition {
			return fail(operation, ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"RWM transaction target is outside its configured database",
			))
		}
		if !databaseUsesLocalContentStorage(*remote) {
			result := transactionResult(
				ldapwire.ResultUnwillingToPerform,
				"backend doesn't support transactions",
			)
			return fail(operation, *result)
		}
		clearLDAPTransactionOperation(&effective[index])
		effective[index].message = mapped
		effective[index].boundDN = operation.boundDN
		effective[index].realDN = operation.realDN
		if operation.boundDN != "" {
			effective[index].boundDN, err = mapMetaDNStringContext(
				database.rwm,
				operation.boundDN,
				true,
				"bindDN",
			)
			if err != nil {
				result := ldapwire.ResultError(
					ldapwire.ResultOther,
					"RWM transaction bindDN rewrite failed: "+err.Error(),
				)
				if failure := asOperationFailure(err); failure != nil {
					result = failure.result
				}
				return fail(operation, result)
			}
		}
	}
	return effective, cleanup, nil
}

func rwmRewriteRequestTarget(state *connectionState, request ldapwire.Request) (directory.DN, bool) {
	if bind, ok := request.(ldapwire.BindRequest); ok {
		dn, err := directory.ParseDN(bind.Name)
		return dn, err == nil
	}
	dn, _, _, ok := chainOperationTarget(state, request)
	return dn, ok
}

type rwmRewriteRelayConnection struct {
	net.Conn
	mapping *rwmRuntimeConfiguration
	message ldapwire.Message
	failed  bool
}

func (connection *rwmRewriteRelayConnection) writeLDAPResultResponse(
	messageID int64,
	responseTag uint64,
	result ldapwire.Result,
	responseName string,
	responseValue []byte,
	controls []ldapwire.Control,
) error {
	mapped, err := mapMetaResult(connection.mapping, result)
	if err != nil {
		mapped = ldapwire.ResultError(ldapwire.ResultOther, err.Error())
		if failure := asOperationFailure(err); failure != nil {
			mapped = failure.result
		}
		responseName = ""
		responseValue = nil
		controls = nil
	}
	if writer, ok := connection.Conn.(ldapResultResponseWriter); ok {
		return writer.writeLDAPResultResponse(
			messageID,
			responseTag,
			mapped,
			responseName,
			responseValue,
			controls,
		)
	}
	if responseTag == ldapwire.ApplicationExtendedResponse {
		return ldapwire.Write(connection.Conn, ldapwire.EncodeExtendedResponse(
			messageID,
			mapped,
			responseName,
			responseValue,
			controls,
		))
	}
	return ldapwire.Write(
		connection.Conn,
		ldapwire.EncodeResultResponse(messageID, responseTag, mapped, controls),
	)
}

func (connection *rwmRewriteRelayConnection) Write(value []byte) (int, error) {
	if connection.failed {
		return len(value), nil
	}
	packet, err := ber.DecodePacketErr(value)
	if err != nil {
		return 0, err
	}
	tag := metaPacketTag(packet)
	var result ldapwire.Result
	if tag != ldapwire.ApplicationSearchResultEntry && tag != ldapwire.ApplicationSearchResultReference {
		result, err = chainLDAPResult(packet, connection.message.ID, tag)
		if err == nil {
			result, err = mapMetaResult(connection.mapping, result)
		}
	}
	var mapped *ber.Packet
	if err == nil {
		mapped, err = mapMetaResponsePacket(connection.mapping, packet, result)
	}
	if err != nil {
		if rwmRewriteDropsEntry(packet, err) {
			return len(value), nil
		}
		connection.failed = true
		result = ldapwire.ResultError(ldapwire.ResultOther, err.Error())
		if failure := asOperationFailure(err); failure != nil {
			result = failure.result
		}
		if err := writeResultForMessage(connection.Conn, connection.message, result); err != nil {
			return 0, err
		}
		return len(value), nil
	}
	mapped.Children[0] = ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, connection.message.ID, "messageID")
	rebuildChainedPacket(mapped)
	if err := ldapwire.Write(connection.Conn, mapped.Bytes()); err != nil {
		return 0, err
	}
	return len(value), nil
}
