package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	transactionStartOID                = "1.3.6.1.1.21.1"
	transactionSpecificationControlOID = "1.3.6.1.1.21.2"
	transactionEndOID                  = "1.3.6.1.1.21.3"
)

type ldapTransaction struct {
	identifier []byte
	runtime    *runtimeState
	partition  string
	operations []ldapTransactionOperation
	messageIDs map[int64]struct{}
}

type ldapTransactionOperation struct {
	message ldapwire.Message
	boundDN string
}

type transactionExecutionContextKey struct{}

type transactionExecution struct {
	writer      storage.Writer
	nextRuntime *runtimeState
	syncChanges []*syncChange
}

type capturedLDAPResult struct {
	messageID     int64
	responseTag   uint64
	result        ldapwire.Result
	responseName  string
	responseValue []byte
	controls      []ldapwire.Control
}

type ldapResultResponseWriter interface {
	writeLDAPResultResponse(
		messageID int64,
		responseTag uint64,
		result ldapwire.Result,
		responseName string,
		responseValue []byte,
		controls []ldapwire.Control,
	) error
}

type transactionResultCapture struct {
	net.Conn
	response *capturedLDAPResult
}

func (capture *transactionResultCapture) Write([]byte) (int, error) {
	return 0, errors.New("transaction operation wrote an uncaptured response")
}

func (capture *transactionResultCapture) writeLDAPResultResponse(
	messageID int64,
	responseTag uint64,
	result ldapwire.Result,
	responseName string,
	responseValue []byte,
	controls []ldapwire.Control,
) error {
	if capture.response != nil {
		return errors.New("transaction operation produced multiple final responses")
	}
	result.Referrals = append([]string(nil), result.Referrals...)
	capture.response = &capturedLDAPResult{
		messageID:     messageID,
		responseTag:   responseTag,
		result:        result,
		responseName:  responseName,
		responseValue: bytes.Clone(responseValue),
		controls:      cloneLDAPControls(controls),
	}
	return nil
}

type transactionCommitFailure struct {
	messageID int64
	result    ldapwire.Result
}

func (failure *transactionCommitFailure) Error() string {
	return fmt.Sprintf(
		"transaction operation %d failed with result %d",
		failure.messageID,
		failure.result.Code,
	)
}

func (server *Server) updateStorage(
	ctx context.Context,
	update func(storage.Writer) error,
) error {
	if execution, ok := ctx.Value(transactionExecutionContextKey{}).(*transactionExecution); ok {
		return update(execution.writer)
	}
	return server.config.Store.Update(ctx, update)
}

func (server *Server) viewStorage(
	ctx context.Context,
	view func(storage.Reader) error,
) error {
	if execution, ok := ctx.Value(transactionExecutionContextKey{}).(*transactionExecution); ok {
		return view(execution.writer)
	}
	return server.config.Store.View(ctx, view)
}

func (server *Server) finishWriteEffects(
	ctx context.Context,
	nextRuntime *runtimeState,
	change *syncChange,
) {
	if execution, ok := ctx.Value(transactionExecutionContextKey{}).(*transactionExecution); ok {
		if nextRuntime != nil {
			execution.nextRuntime = nextRuntime
		}
		if change != nil {
			execution.syncChanges = append(execution.syncChanges, change)
		}
		return
	}
	if nextRuntime != nil {
		server.activateRuntime(nextRuntime)
	}
	server.publishSyncChange(change)
}

func (server *Server) handleTransactionStart(
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.ExtendedRequest,
) error {
	var (
		result        ldapwire.Result
		responseValue []byte
	)
	switch {
	case request.HasValue:
		result = ldapwire.ResultError(
			ldapwire.ResultProtocolError,
			"no request data expected",
		)
	case state.transaction != nil:
		result = ldapwire.ResultError(
			ldapwire.ResultBusy,
			"Too many transactions",
		)
	default:
		identifier := make([]byte, 0)
		state.transaction = &ldapTransaction{
			identifier: identifier,
			runtime:    state.runtime,
			messageIDs: make(map[int64]struct{}),
		}
		result = ldapwire.Result{Code: ldapwire.ResultSuccess}
		responseValue = make([]byte, 0)
	}
	return server.writeLDAPResultResponse(
		connection,
		message.ID,
		ldapwire.ApplicationExtendedResponse,
		result,
		"",
		responseValue,
		nil,
	)
}

func (server *Server) handleTransactionEnd(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.ExtendedRequest,
) error {
	if !request.HasValue {
		return server.writeTransactionEndResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"request data expected",
			),
			ldapwire.TransactionEndResponseValue{},
		)
	}
	if len(request.Value) == 0 {
		return server.writeTransactionEndResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"empty request data",
			),
			ldapwire.TransactionEndResponseValue{},
		)
	}
	endRequest, err := ldapwire.DecodeTransactionEndRequestValue(request.Value)
	if err != nil {
		return server.writeTransactionEndResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"request data decoding error",
			),
			ldapwire.TransactionEndResponseValue{},
		)
	}
	transaction := state.transaction
	if transaction == nil ||
		!bytes.Equal(endRequest.Identifier, transaction.identifier) {
		return server.writeTransactionEndResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultTransactionIDInvalid,
				"invalid transaction identifier",
			),
			ldapwire.TransactionEndResponseValue{},
		)
	}

	state.transaction = nil
	defer clearLDAPTransaction(transaction)
	if !endRequest.Commit {
		return server.writeTransactionEndResult(
			connection,
			message.ID,
			ldapwire.Result{
				Code:              ldapwire.ResultSuccess,
				DiagnosticMessage: "transaction aborted",
			},
			ldapwire.TransactionEndResponseValue{},
		)
	}
	if len(transaction.operations) == 0 {
		return server.writeTransactionEndResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultOperationsError,
				"no updates to commit",
			),
			ldapwire.TransactionEndResponseValue{},
		)
	}

	result, response := server.commitLDAPTransaction(ctx, state, transaction)
	return server.writeTransactionEndResult(
		connection,
		message.ID,
		result,
		response,
	)
}

func (server *Server) writeTransactionEndResult(
	connection net.Conn,
	messageID int64,
	result ldapwire.Result,
	response ldapwire.TransactionEndResponseValue,
) error {
	return server.writeLDAPResultResponse(
		connection,
		messageID,
		ldapwire.ApplicationExtendedResponse,
		result,
		"",
		ldapwire.EncodeTransactionEndResponseValue(response),
		nil,
	)
}

func (server *Server) handleTransactionSpecification(
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
) (bool, error) {
	supported, controlIndex := transactionCapableRequest(message)
	if !supported || controlIndex < 0 {
		return false, nil
	}

	result := validateTransactionSpecificationControl(
		state.transaction,
		message.Controls,
		controlIndex,
	)
	if result == nil {
		result = validateTransactionOperationControls(message, controlIndex)
	}
	var database *runtimeDatabase
	if result == nil {
		database, result = server.transactionOperationDatabase(
			state,
			message,
		)
	}
	if result == nil && database.partition == configurationStoragePartition {
		result = transactionResult(
			ldapwire.ResultUnwillingToPerform,
			"backend doesn't support transactions",
		)
	}
	if result == nil &&
		state.transaction.partition != "" &&
		state.transaction.partition != database.partition {
		result = transactionResult(
			ldapwire.ResultAffectsMultipleDSAs,
			"transaction cannot span multiple database contexts",
		)
	}
	if result == nil {
		if _, exists := state.transaction.messageIDs[message.ID]; exists {
			result = transactionResult(
				ldapwire.ResultProtocolError,
				"transaction update message ID is already in use",
			)
		}
	}
	if result != nil {
		return true, server.writeTransactionOperationResult(
			connection,
			message,
			*result,
		)
	}

	if state.transaction.partition == "" {
		state.transaction.partition = database.partition
	}
	state.transaction.messageIDs[message.ID] = struct{}{}
	state.transaction.operations = append(
		state.transaction.operations,
		ldapTransactionOperation{
			message: cloneTransactionMessage(message, controlIndex),
			boundDN: state.boundDN,
		},
	)
	return true, server.writeTransactionOperationResult(
		connection,
		message,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
	)
}

func transactionCapableRequest(message ldapwire.Message) (bool, int) {
	supported := false
	switch request := message.Request.(type) {
	case ldapwire.AddRequest,
		ldapwire.ModifyRequest,
		ldapwire.DeleteRequest,
		ldapwire.ModifyDNRequest:
		supported = true
	case ldapwire.ExtendedRequest:
		supported = request.Name == passwordModifyOID
	}
	if !supported {
		return false, -1
	}
	for index, control := range message.Controls {
		if control.OID == transactionSpecificationControlOID {
			return true, index
		}
	}
	return true, -1
}

func validateTransactionSpecificationControl(
	transaction *ldapTransaction,
	controls []ldapwire.Control,
	controlIndex int,
) *ldapwire.Result {
	control := controls[controlIndex]
	for index := controlIndex + 1; index < len(controls); index++ {
		if controls[index].OID == transactionSpecificationControlOID {
			return transactionResult(
				ldapwire.ResultProtocolError,
				"txnSpec control provided multiple times",
			)
		}
	}
	if !control.Critical {
		return transactionResult(
			ldapwire.ResultProtocolError,
			"txnSpec control must be marked critical",
		)
	}
	if !control.HasValue {
		return transactionResult(
			ldapwire.ResultProtocolError,
			"no transaction identifier provided",
		)
	}
	if transaction == nil ||
		!bytes.Equal(control.Value, transaction.identifier) {
		return transactionResult(
			ldapwire.ResultTransactionIDInvalid,
			"invalid transaction identifier",
		)
	}
	return nil
}

func validateTransactionOperationControls(
	message ldapwire.Message,
	transactionControlIndex int,
) *ldapwire.Result {
	controls := withoutControl(message.Controls, transactionControlIndex)
	for _, control := range controls {
		if control.OID == preReadControlOID {
			return transactionResult(
				ldapwire.ResultUnwillingToPerform,
				"cannot perform pre-read in transaction",
			)
		}
		if control.OID == postReadControlOID {
			return transactionResult(
				ldapwire.ResultUnwillingToPerform,
				"cannot perform post-read in transaction",
			)
		}
	}

	var supported requestControlSupport
	switch request := message.Request.(type) {
	case ldapwire.AddRequest:
		supported = supportsAssertion |
			supportsPostRead |
			supportsManageDsaIT |
			supportsPasswordPolicy |
			supportsRelax
	case ldapwire.ModifyRequest:
		supported = supportsAssertion |
			supportsPreRead |
			supportsPostRead |
			supportsManageDsaIT |
			supportsPasswordPolicy |
			supportsRelax
	case ldapwire.DeleteRequest:
		supported = supportsAssertion | supportsPreRead | supportsManageDsaIT | supportsRelax
	case ldapwire.ModifyDNRequest:
		supported = supportsAssertion |
			supportsPreRead |
			supportsPostRead |
			supportsManageDsaIT |
			supportsRelax
	case ldapwire.ExtendedRequest:
		if request.Name == passwordModifyOID {
			supported = supportsManageDsaIT | supportsPasswordPolicy
		}
	}
	_, result := parseRequestControls(controls, supported)
	return result
}

func (server *Server) transactionOperationDatabase(
	state *connectionState,
	message ldapwire.Message,
) (*runtimeDatabase, *ldapwire.Result) {
	runtime := state.transaction.runtime
	var target directory.DN

	switch request := message.Request.(type) {
	case ldapwire.AddRequest:
		dn, err := directory.ParseDN(request.Entry.DN)
		if err != nil || dn.Depth() == 0 {
			return nil, transactionResult(ldapwire.ResultInvalidDNSyntax, "")
		}
		if isSubschemaDN(dn) {
			return nil, transactionResult(ldapwire.ResultEntryAlreadyExists, "")
		}
		if result := validateNewEntry(request.Entry, dn); result != nil {
			return nil, result
		}
		target = dn
	case ldapwire.ModifyRequest:
		dn, err := directory.ParseDN(request.DN)
		if err != nil || dn.Depth() == 0 {
			return nil, transactionResult(ldapwire.ResultInvalidDNSyntax, "")
		}
		if isSubschemaDN(dn) {
			return nil, transactionResult(
				ldapwire.ResultUnwillingToPerform,
				"subschema is read-only",
			)
		}
		target = dn
	case ldapwire.DeleteRequest:
		dn, err := directory.ParseDN(request.DN)
		if err != nil || dn.Depth() == 0 {
			return nil, transactionResult(ldapwire.ResultInvalidDNSyntax, "")
		}
		if isSubschemaDN(dn) {
			return nil, transactionResult(
				ldapwire.ResultUnwillingToPerform,
				"subschema is read-only",
			)
		}
		target = dn
	case ldapwire.ModifyDNRequest:
		oldDN, err := directory.ParseDN(request.DN)
		if err != nil || oldDN.Depth() == 0 {
			return nil, transactionResult(ldapwire.ResultInvalidDNSyntax, "")
		}
		var superior directory.DN
		if request.HasNewSuperior {
			superior, err = directory.ParseDN(request.NewSuperior)
		} else {
			var ok bool
			superior, ok = oldDN.Parent()
			if !ok {
				err = errors.New("root DSE cannot be renamed")
			}
		}
		if err != nil {
			return nil, transactionResult(ldapwire.ResultInvalidDNSyntax, "")
		}
		newDN, err := directory.ComposeDN(request.NewRDN, superior)
		if err != nil {
			return nil, transactionResult(ldapwire.ResultInvalidDNSyntax, "")
		}
		source := databaseForDN(runtime, oldDN)
		destination := databaseForDN(runtime, newDN)
		if source == nil {
			return nil, transactionResult(
				ldapwire.ResultUnwillingToPerform,
				"no global superior knowledge",
			)
		}
		if destination == nil || destination.partition != source.partition {
			return nil, transactionResult(
				ldapwire.ResultAffectsMultipleDSAs,
				"cannot rename between DSAs",
			)
		}
		target = oldDN
	case ldapwire.ExtendedRequest:
		passwordRequest, err := ldapwire.DecodePasswordModifyRequestValue(
			request.Value,
			request.HasValue,
		)
		if err != nil {
			return nil, transactionResult(
				ldapwire.ResultProtocolError,
				"data decoding error",
			)
		}
		defer clear(passwordRequest.OldPassword)
		defer clear(passwordRequest.NewPassword)
		if state.boundDN == "" {
			return nil, transactionResult(
				ldapwire.ResultStrongerAuthRequired,
				"only authenticated users may change passwords",
			)
		}
		if passwordRequest.HasOldPassword && len(passwordRequest.OldPassword) == 0 {
			return nil, transactionResult(
				ldapwire.ResultUnwillingToPerform,
				"old password value is empty",
			)
		}
		if passwordRequest.HasNewPassword && len(passwordRequest.NewPassword) == 0 {
			return nil, transactionResult(
				ldapwire.ResultUnwillingToPerform,
				"new password value is empty",
			)
		}
		if !passwordRequest.HasNewPassword {
			return nil, transactionResult(
				ldapwire.ResultUnwillingToPerform,
				"generated passwords cannot be returned from a transaction",
			)
		}
		targetName := state.boundDN
		if passwordRequest.HasUserIdentity && len(passwordRequest.UserIdentity) > 0 {
			targetName = string(passwordRequest.UserIdentity)
		}
		target, err = directory.ParseDN(targetName)
		if err != nil {
			return nil, transactionResult(
				ldapwire.ResultInvalidDNSyntax,
				"Invalid DN",
			)
		}
		if target.Depth() == 0 {
			return nil, transactionResult(
				ldapwire.ResultUnwillingToPerform,
				"no password is associated with the Root DSE",
			)
		}
	default:
		return nil, transactionResult(
			ldapwire.ResultUnwillingToPerform,
			"operation cannot be performed in a transaction",
		)
	}

	database := databaseForDN(runtime, target)
	if database == nil {
		return nil, transactionResult(
			ldapwire.ResultUnwillingToPerform,
			"no global superior knowledge",
		)
	}
	if result := updateOperationPrecondition(runtime, state.boundDN, target); result != nil {
		return nil, result
	}
	return database, nil
}

func (server *Server) writeTransactionOperationResult(
	connection net.Conn,
	message ldapwire.Message,
	result ldapwire.Result,
) error {
	responseTag, ok := responseTagFor(message.Request.ApplicationTag())
	if !ok {
		return errors.New("transaction operation has no response type")
	}
	return server.writeLDAPResultResponse(
		connection,
		message.ID,
		responseTag,
		result,
		"",
		nil,
		nil,
	)
}

func (server *Server) commitLDAPTransaction(
	ctx context.Context,
	state *connectionState,
	transaction *ldapTransaction,
) (ldapwire.Result, ldapwire.TransactionEndResponseValue) {
	var (
		execution                          transactionExecution
		endResponse                        ldapwire.TransactionEndResponseValue
		committedPasswordPolicyRestriction string
	)
	err := server.config.Store.Update(ctx, func(writer storage.Writer) error {
		execution.writer = writer
		transactionContext := context.WithValue(
			ctx,
			transactionExecutionContextKey{},
			&execution,
		)
		transactionState := *state
		transactionState.runtime = transaction.runtime
		transactionState.transaction = nil

		for _, operation := range transaction.operations {
			message := operation.message
			transactionState.boundDN = operation.boundDN
			capture := &transactionResultCapture{}
			if err := server.executeTransactionOperation(
				transactionContext,
				capture,
				&transactionState,
				message,
			); err != nil {
				return err
			}
			response := capture.response
			if response == nil {
				return errors.New("transaction operation produced no final response")
			}
			expectedTag, _ := responseTagFor(message.Request.ApplicationTag())
			if response.messageID != message.ID || response.responseTag != expectedTag {
				return errors.New("transaction operation produced an invalid final response")
			}
			if response.responseName != "" || response.responseValue != nil {
				return errors.New("transaction operation produced unsupported response data")
			}
			if len(response.controls) > 0 {
				endResponse.UpdateControls = append(
					endResponse.UpdateControls,
					ldapwire.TransactionUpdateControls{
						MessageID: message.ID,
						Controls:  response.controls,
					},
				)
			}
			if response.result.Code != ldapwire.ResultSuccess {
				endResponse.FailedMessageID = message.ID
				endResponse.HasFailedMessageID = true
				return &transactionCommitFailure{
					messageID: message.ID,
					result:    response.result,
				}
			}
		}
		committedPasswordPolicyRestriction =
			transactionState.passwordPolicyRestrictedDN
		return nil
	})
	if err != nil {
		var failure *transactionCommitFailure
		if errors.As(err, &failure) {
			return failure.result, endResponse
		}
		server.config.Logger.Error("LDAP transaction failed", "error", err)
		return ldapwire.ResultError(
			ldapwire.ResultOperationsError,
			"internal transaction error",
		), ldapwire.TransactionEndResponseValue{}
	}

	if execution.nextRuntime != nil {
		server.activateRuntime(execution.nextRuntime)
	}
	for _, change := range execution.syncChanges {
		server.publishSyncChange(change)
	}
	state.passwordPolicyRestrictedDN = committedPasswordPolicyRestriction
	return ldapwire.Result{Code: ldapwire.ResultSuccess}, endResponse
}

func (server *Server) executeTransactionOperation(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
) error {
	switch request := message.Request.(type) {
	case ldapwire.AddRequest:
		return server.handleAdd(ctx, connection, state, message, request)
	case ldapwire.ModifyRequest:
		return server.handleModify(ctx, connection, state, message, request)
	case ldapwire.DeleteRequest:
		return server.handleDelete(ctx, connection, state, message, request)
	case ldapwire.ModifyDNRequest:
		return server.handleModifyDN(ctx, connection, state, message, request)
	case ldapwire.ExtendedRequest:
		if request.Name == passwordModifyOID {
			return server.handlePasswordModify(
				ctx,
				connection,
				state,
				message,
				request,
			)
		}
	}
	return errors.New("unsupported transaction operation")
}

func cloneTransactionMessage(
	message ldapwire.Message,
	transactionControlIndex int,
) ldapwire.Message {
	cloned := ldapwire.Message{
		ID:       message.ID,
		Controls: cloneLDAPControls(withoutControl(message.Controls, transactionControlIndex)),
	}
	switch request := message.Request.(type) {
	case ldapwire.AddRequest:
		cloned.Request = ldapwire.AddRequest{Entry: request.Entry.Clone()}
	case ldapwire.ModifyRequest:
		changes := make([]ldapwire.Modification, len(request.Changes))
		for index, change := range request.Changes {
			changes[index] = ldapwire.Modification{
				Operation: change.Operation,
				Attribute: directory.Attribute{
					Description: change.Attribute.Description,
					Values:      cloneByteValues(change.Attribute.Values),
				},
			}
		}
		cloned.Request = ldapwire.ModifyRequest{
			DN:      request.DN,
			Changes: changes,
		}
	case ldapwire.DeleteRequest:
		cloned.Request = request
	case ldapwire.ModifyDNRequest:
		cloned.Request = request
	case ldapwire.ExtendedRequest:
		request.Value = bytes.Clone(request.Value)
		cloned.Request = request
	default:
		cloned.Request = request
	}
	return cloned
}

func clearLDAPTransaction(transaction *ldapTransaction) {
	if transaction == nil {
		return
	}
	clear(transaction.identifier)
	for messageIndex := range transaction.operations {
		operation := &transaction.operations[messageIndex]
		message := &operation.message
		for controlIndex := range message.Controls {
			clear(message.Controls[controlIndex].Value)
		}
		switch request := message.Request.(type) {
		case ldapwire.AddRequest:
			clearEntryValues(request.Entry)
		case ldapwire.ModifyRequest:
			for changeIndex := range request.Changes {
				for valueIndex := range request.Changes[changeIndex].Attribute.Values {
					clear(request.Changes[changeIndex].Attribute.Values[valueIndex])
				}
			}
		case ldapwire.ExtendedRequest:
			clear(request.Value)
		}
		*message = ldapwire.Message{}
		operation.boundDN = ""
	}
	transaction.identifier = nil
	transaction.operations = nil
	transaction.messageIDs = nil
}

func clearEntryValues(entry directory.Entry) {
	for attributeIndex := range entry.Attributes {
		for valueIndex := range entry.Attributes[attributeIndex].Values {
			clear(entry.Attributes[attributeIndex].Values[valueIndex])
		}
	}
}

func cloneLDAPControls(controls []ldapwire.Control) []ldapwire.Control {
	cloned := make([]ldapwire.Control, len(controls))
	for index, control := range controls {
		cloned[index] = control
		cloned[index].Value = bytes.Clone(control.Value)
	}
	return cloned
}

func cloneByteValues(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index, value := range values {
		cloned[index] = bytes.Clone(value)
	}
	return cloned
}

func withoutControl(
	controls []ldapwire.Control,
	index int,
) []ldapwire.Control {
	result := make([]ldapwire.Control, 0, len(controls)-1)
	result = append(result, controls[:index]...)
	result = append(result, controls[index+1:]...)
	return result
}

func transactionResult(
	code ldapwire.ResultCode,
	diagnostic string,
) *ldapwire.Result {
	result := ldapwire.ResultError(code, diagnostic)
	return &result
}
