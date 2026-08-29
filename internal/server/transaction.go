package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	transactionStartOID                = "1.3.6.1.1.21.1"
	transactionSpecificationControlOID = "1.3.6.1.1.21.2"
	transactionEndOID                  = "1.3.6.1.1.21.3"
	transactionAbortedNoticeOID        = "1.3.6.1.1.21.4"
)

type ldapTransaction struct {
	identifier          []byte
	runtime             *runtimeState
	partition           string
	operations          []ldapTransactionOperation
	messageIDs          map[int64]struct{}
	queuedBytes         int64
	retainedBytes       int64
	releaseRetained     func(int64)
	releaseRetainedOnce sync.Once
}

type ldapTransactionOperation struct {
	message ldapwire.Message
	boundDN string
	realDN  string
}

type transactionExecutionContextKey struct{}

type transactionPreflightClockContextKey struct{}

type transactionPreflightClock struct {
	now               time.Time
	lastCSN           time.Time
	csnCounter        uint32
	lastAccesslogTime time.Time
}

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
		return update(accessWriterFromContext(ctx, execution.writer))
	}
	return server.config.Store.Update(ctx, func(writer storage.Writer) error {
		if err := update(writer); err != nil {
			return err
		}
		return markTrackedOperationCommitPoint(ctx)
	})
}

func (server *Server) viewStorage(
	ctx context.Context,
	view func(storage.Reader) error,
) error {
	if execution, ok := ctx.Value(transactionExecutionContextKey{}).(*transactionExecution); ok {
		return view(accessWriterFromContext(ctx, execution.writer))
	}
	return server.config.Store.View(ctx, view)
}

func (server *Server) finishWriteEffects(
	ctx context.Context,
	nextRuntime *runtimeState,
	changes ...*syncChange,
) {
	if execution, ok := ctx.Value(transactionExecutionContextKey{}).(*transactionExecution); ok {
		if nextRuntime != nil {
			execution.nextRuntime = nextRuntime
		}
		for _, change := range changes {
			if change != nil {
				execution.syncChanges = append(execution.syncChanges, change)
			}
		}
		return
	}
	if nextRuntime != nil {
		server.activateRuntime(nextRuntime)
	}
	for _, change := range changes {
		server.publishSyncChange(change)
	}
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
	securityFailure := operationSecurityResult(state, nil, policyUpdate)
	switch {
	case request.HasValue:
		result = ldapwire.ResultError(
			ldapwire.ResultProtocolError,
			"no request data expected",
		)
	case securityFailure != nil:
		result = *securityFailure
	case frontendRestricts(state.runtime, restrictExtended):
		result = ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"operation restricted",
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
	if result := operationSecurityResult(state, nil, policyUpdate); result != nil {
		return server.writeTransactionEndResult(
			connection,
			message.ID,
			*result,
			ldapwire.TransactionEndResponseValue{},
		)
	}
	if frontendRestricts(state.runtime, restrictExtended) {
		return server.writeTransactionEndResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"operation restricted",
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
	if endRequest.Commit && server.gentleDraining.Load() {
		return server.writeTransactionEndResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"operation restricted",
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
	if result == nil && database.sockBackend != nil {
		value := sockBackendTransactionResult()
		result = &value
	}
	if result == nil &&
		(database.partition == configurationStoragePartition ||
			databaseUsesNullBackend(state.transaction.runtime, *database) ||
			database.sqlBackend != nil) {
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
			nil,
		)
	}

	queuedMessage, responseValue, err := prepareTransactionOperation(
		message,
		controlIndex,
	)
	if err != nil {
		server.config.Logger.Error(
			"LDAP transaction operation preparation failed",
			"message_id",
			message.ID,
			"error",
			err,
		)
		return true, server.abortLDAPTransactionWithNotice(
			connection,
			state,
			ldapwire.ResultError(
				ldapwire.ResultOther,
				"cannot queue transaction operation",
			),
		)
	}
	defer clear(responseValue)
	queuedBytes, err := transactionOperationQueuedBytes(queuedMessage)
	if err != nil {
		clearLDAPTransactionOperation(&ldapTransactionOperation{message: queuedMessage})
		server.config.Logger.Error(
			"LDAP transaction operation accounting failed",
			"message_id",
			message.ID,
			"error",
			err,
		)
		return true, server.abortLDAPTransactionWithNotice(
			connection,
			state,
			ldapwire.ResultError(
				ldapwire.ResultOther,
				"cannot queue transaction operation",
			),
		)
	}
	transaction := state.transaction
	limitDiagnostic := ""
	if len(transaction.operations) >= server.config.MaxTransactionOperations {
		limitDiagnostic = "transaction operation limit exceeded"
	} else if queuedBytes > server.config.MaxTransactionQueuedBytes-transaction.queuedBytes {
		limitDiagnostic = "transaction queued byte limit exceeded"
	}
	if limitDiagnostic != "" {
		clearLDAPTransactionOperation(&ldapTransactionOperation{message: queuedMessage})
		return true, server.abortLDAPTransactionWithNotice(
			connection,
			state,
			ldapwire.ResultError(
				ldapwire.ResultAdminLimitExceeded,
				limitDiagnostic,
			),
		)
	}
	if !server.pendingByteLimiter.tryAcquire(queuedBytes) {
		clearLDAPTransactionOperation(&ldapTransactionOperation{message: queuedMessage})
		return true, server.abortLDAPTransactionWithNotice(
			connection,
			state,
			ldapwire.ResultError(
				ldapwire.ResultAdminLimitExceeded,
				"process pending operation byte budget exceeded",
			),
		)
	}
	transaction.retainedBytes += queuedBytes
	transaction.releaseRetained = server.pendingByteLimiter.release

	if state.transaction.partition == "" {
		state.transaction.partition = database.partition
	}
	state.transaction.messageIDs[message.ID] = struct{}{}
	state.transaction.queuedBytes += queuedBytes
	state.transaction.operations = append(
		state.transaction.operations,
		ldapTransactionOperation{
			message: queuedMessage,
			boundDN: state.boundDN,
			realDN:  state.operationRealDN,
		},
	)
	return true, server.writeTransactionOperationResult(
		connection,
		message,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		responseValue,
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
			supportsRelax |
			supportsLazyCommit |
			supportsNoOp
	case ldapwire.ModifyRequest:
		supported = supportsAssertion |
			supportsPreRead |
			supportsPostRead |
			supportsManageDsaIT |
			supportsPasswordPolicy |
			supportsRelax |
			supportsLazyCommit |
			supportsNoOp |
			supportsPermissiveModify
	case ldapwire.DeleteRequest:
		supported = supportsAssertion |
			supportsPreRead |
			supportsManageDsaIT |
			supportsRelax |
			supportsLazyCommit |
			supportsNoOp
	case ldapwire.ModifyDNRequest:
		supported = supportsAssertion |
			supportsPreRead |
			supportsPostRead |
			supportsManageDsaIT |
			supportsRelax |
			supportsLazyCommit |
			supportsNoOp
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
		if len(request.Entry.Attributes) == 0 {
			return nil, transactionResult(
				ldapwire.ResultProtocolError,
				"no attributes provided",
			)
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
		source := databaseForDN(runtime, oldDN)
		if source == nil {
			if referral, ok := globalReferralResult(
				runtime,
				&oldDN,
				referralScopeDefault,
			); ok {
				return nil, &referral
			}
			return nil, transactionResult(
				ldapwire.ResultUnwillingToPerform,
				"no global superior knowledge",
			)
		}
		oldDN, err = normalizeRuntimeDatabaseDN(*source, oldDN)
		if err != nil {
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
		destination := databaseForDN(runtime, newDN)
		if destination == nil || destination.partition != source.partition {
			return nil, transactionResult(
				ldapwire.ResultAffectsMultipleDSAs,
				"cannot rename between DSAs",
			)
		}
		if _, err := normalizeRuntimeDatabaseDN(*destination, newDN); err != nil {
			return nil, transactionResult(ldapwire.ResultInvalidDNSyntax, "")
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
		if _, passwordModify := message.Request.(ldapwire.ExtendedRequest); !passwordModify {
			if referral, ok := globalReferralResult(
				runtime,
				&target,
				referralScopeDefault,
			); ok {
				return nil, &referral
			}
		}
		return nil, transactionResult(
			ldapwire.ResultUnwillingToPerform,
			"no global superior knowledge",
		)
	}
	var err error
	target, err = normalizeRuntimeDatabaseDN(*database, target)
	if err != nil {
		return nil, transactionResult(ldapwire.ResultInvalidDNSyntax, "")
	}
	if result := updateOperationPrecondition(runtime, state.boundDN, target); result != nil {
		return nil, result
	}
	if result := databaseRestrictionResult(
		runtime,
		target,
		requestDatabaseRestriction(message.Request),
	); result != nil {
		return nil, result
	}
	if runtime.externalPasswords.radiusEnabled &&
		ldapTransactionMayVerifyExternalPasswords([]ldapTransactionOperation{{
			message: message,
		}}) {
		if activeTranslucentConfiguration(database) != nil {
			return nil, transactionResult(
				ldapwire.ResultUnwillingToPerform,
				"RADIUS password verification is not supported in translucent LDAP transactions",
			)
		}
		if effectiveChainConfiguration(runtime, database) != nil {
			return nil, transactionResult(
				ldapwire.ResultUnwillingToPerform,
				"RADIUS password verification is not supported in chained LDAP transactions",
			)
		}
	}
	return database, nil
}

func (server *Server) writeTransactionOperationResult(
	connection net.Conn,
	message ldapwire.Message,
	result ldapwire.Result,
	responseValue []byte,
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
		responseValue,
		nil,
	)
}

func prepareTransactionOperation(
	message ldapwire.Message,
	transactionControlIndex int,
) (ldapwire.Message, []byte, error) {
	queued := cloneTransactionMessage(message, transactionControlIndex)
	request, ok := queued.Request.(ldapwire.ExtendedRequest)
	if !ok || request.Name != passwordModifyOID {
		return queued, nil, nil
	}

	passwordRequest, err := ldapwire.DecodePasswordModifyRequestValue(
		request.Value,
		request.HasValue,
	)
	if err != nil {
		clearLDAPTransactionOperation(&ldapTransactionOperation{message: queued})
		return ldapwire.Message{}, nil, err
	}
	defer func() {
		clear(passwordRequest.UserIdentity)
		clear(passwordRequest.OldPassword)
		clear(passwordRequest.NewPassword)
	}()
	if passwordRequest.HasNewPassword {
		return queued, nil, nil
	}

	generatedPassword, err := generatePassword()
	if err != nil {
		clearLDAPTransactionOperation(&ldapTransactionOperation{message: queued})
		return ldapwire.Message{}, nil, err
	}
	defer clear(generatedPassword)
	passwordRequest.NewPassword = generatedPassword
	passwordRequest.HasNewPassword = true
	clear(request.Value)
	request.Value = encodeChainedPasswordModifyValue(passwordRequest)
	request.HasValue = true
	queued.Request = request
	return queued, ldapwire.EncodePasswordModifyResponseValue(generatedPassword), nil
}

func transactionOperationQueuedBytes(message ldapwire.Message) (int64, error) {
	encoded, err := ldapwire.EncodeRequestMessage(message)
	if err != nil {
		return 0, err
	}
	defer clear(encoded)
	return ldapMessageRetainedBytes(message, int64(len(encoded))), nil
}

func (server *Server) abortLDAPTransactionWithNotice(
	connection net.Conn,
	state *connectionState,
	result ldapwire.Result,
) error {
	transaction := state.transaction
	if transaction == nil {
		return errors.New("cannot abort an inactive LDAP transaction")
	}
	identifier := make([]byte, len(transaction.identifier))
	copy(identifier, transaction.identifier)
	state.transaction = nil
	clearLDAPTransaction(transaction)
	defer clear(identifier)
	return server.writeLDAPResultResponse(
		connection,
		0,
		ldapwire.ApplicationExtendedResponse,
		result,
		transactionAbortedNoticeOID,
		identifier,
		nil,
	)
}

type ldapTransactionSeqmodLock struct {
	configuration *seqmodRuntimeConfiguration
	lock          seqmodHeldLock
	sortKey       string
}

var errLDAPTransactionPreflightRollback = errors.New(
	"roll back LDAP transaction external password preflight",
)

func (server *Server) prepareLDAPTransactionExternalPasswords(
	ctx context.Context,
	state *connectionState,
	transaction *ldapTransaction,
) (map[int64]externalPasswordMatches, error) {
	if !transaction.runtime.externalPasswords.radiusEnabled ||
		!ldapTransactionMayVerifyExternalPasswords(transaction.operations) {
		return nil, nil
	}
	prepared := make(map[int64]externalPasswordMatches, len(transaction.operations))
	for _, operation := range transaction.operations {
		prepared[operation.message.ID] = newExternalPasswordMatches()
	}
	preflightTime := time.Now().UTC().Truncate(time.Microsecond)
	for {
		var pendingMessageID int64
		var pending *externalPasswordVerificationSequence
		err := server.config.Store.Update(ctx, func(writer storage.Writer) error {
			execution := transactionExecution{writer: writer}
			transactionContext := context.WithValue(
				ctx,
				transactionExecutionContextKey{},
				&execution,
			)
			transactionContext = context.WithValue(
				transactionContext,
				transactionPreflightClockContextKey{},
				&transactionPreflightClock{now: preflightTime},
			)
			transactionState := cloneLDAPTransactionConnectionState(state)
			defer clear(transactionState.bindCredentials)
			transactionState.runtime = transaction.runtime
			transactionState.transaction = nil
			transactionState.transactionPreflight = true

			for _, operation := range transaction.operations {
				message := cloneTransactionReplayMessage(operation.message)
				messageID := message.ID
				requestTag := message.Request.ApplicationTag()
				transactionState.boundDN = operation.boundDN
				transactionState.operationRealDN = operation.realDN
				collector := &externalPasswordVerificationCollector{
					matches: prepared[messageID],
				}
				operationContext := context.WithValue(
					transactionContext,
					collectExternalPasswordVerificationContextKey{},
					collector,
				)
				operationContext = withACLSubject(
					operationContext,
					server.connectionACLSubject(&transactionState),
				)
				capture := &transactionResultCapture{}
				if err := server.executeTransactionOperation(
					operationContext,
					capture,
					&transactionState,
					message,
				); err != nil {
					clearLDAPTransactionOperation(&ldapTransactionOperation{message: message})
					return err
				}
				clearLDAPTransactionOperation(&ldapTransactionOperation{message: message})
				response := capture.response
				if response == nil {
					return errors.New("transaction preflight produced no final response")
				}
				expectedTag, _ := responseTagFor(requestTag)
				if response.messageID != messageID || response.responseTag != expectedTag {
					return errors.New("transaction preflight produced an invalid final response")
				}
				if response.responseName != "" || response.responseValue != nil {
					return errors.New("transaction preflight produced unsupported response data")
				}
				if collector.request != nil {
					pendingMessageID = messageID
					pending = collector.request
					return errLDAPTransactionPreflightRollback
				}
				if response.result.Code != ldapwire.ResultSuccess {
					return &transactionCommitFailure{
						messageID: messageID,
						result:    response.result,
					}
				}
			}
			return errLDAPTransactionPreflightRollback
		})
		if pending != nil {
			matches := prepared[pendingMessageID]
			before := len(matches.values)
			server.preverifyOrderedPasswords(
				ctx,
				transaction.runtime,
				pending.stored,
				pending.supplied,
				matches,
			)
			clearExternalPasswordVerificationSequence(pending)
			if len(matches.values) == before {
				return nil, errors.New(
					"transaction external password preflight made no progress",
				)
			}
			continue
		}
		var operationFailure *transactionCommitFailure
		if err != nil &&
			!errors.Is(err, errLDAPTransactionPreflightRollback) &&
			!errors.As(err, &operationFailure) {
			return nil, err
		}
		return prepared, nil
	}
}

func ldapTransactionMayVerifyExternalPasswords(
	operations []ldapTransactionOperation,
) bool {
	for _, operation := range operations {
		switch request := operation.message.Request.(type) {
		case ldapwire.ModifyRequest:
			return true
		case ldapwire.ExtendedRequest:
			if request.Name == passwordModifyOID {
				return true
			}
		}
	}
	return false
}

func cloneLDAPTransactionConnectionState(state *connectionState) connectionState {
	cloned := *state
	cloned.bindCredentials = bytes.Clone(state.bindCredentials)
	return cloned
}

func clearExternalPasswordVerificationSequence(
	sequence *externalPasswordVerificationSequence,
) {
	if sequence == nil {
		return
	}
	for _, stored := range sequence.stored {
		clear(stored)
	}
	clear(sequence.supplied)
	sequence.stored = nil
	sequence.supplied = nil
}

func acquireLDAPTransactionSeqmods(
	ctx context.Context,
	runtime *runtimeState,
	operations []ldapTransactionOperation,
) (context.Context, func(), error) {
	unique := make(map[seqmodHeldLock]ldapTransactionSeqmodLock)
	appendLock := func(configuration *seqmodRuntimeConfiguration, target directory.DN) {
		if configuration == nil || configuration.disabled || configuration.coordinator == nil {
			return
		}
		lock := seqmodHeldLock{
			coordinator: configuration.coordinator,
			targetKey:   target.NormalizedString(),
		}
		if _, exists := unique[lock]; exists {
			return
		}
		unique[lock] = ldapTransactionSeqmodLock{
			configuration: configuration,
			lock:          lock,
			sortKey:       configuration.configDNKey + "\x00" + lock.targetKey,
		}
	}
	var frontend *seqmodRuntimeConfiguration
	for index := range runtime.databases {
		if databaseType(runtime.databases[index].name) == "frontend" {
			frontend = runtime.databases[index].seqmod
			break
		}
	}
	for _, operation := range operations {
		targets, err := ldapTransactionSeqmodTargets(runtime, operation)
		if err != nil {
			return ctx, seqmodNoopRelease, err
		}
		for _, target := range targets {
			if target.frontendLock {
				appendLock(frontend, target.dn)
			}
			if target.databaseLock && target.database != nil {
				appendLock(target.database.seqmod, target.dn)
			}
		}
	}
	ordered := make([]ldapTransactionSeqmodLock, 0, len(unique))
	for _, lock := range unique {
		ordered = append(ordered, lock)
	}
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left].sortKey < ordered[right].sortKey
	})
	held := make(map[seqmodHeldLock]struct{}, len(ordered))
	releases := make([]func(), 0, len(ordered))
	for _, request := range ordered {
		release, err := request.configuration.coordinator.acquire(
			ctx,
			request.lock.targetKey,
		)
		if err != nil {
			for index := len(releases) - 1; index >= 0; index-- {
				releases[index]()
			}
			return ctx, seqmodNoopRelease, err
		}
		held[request.lock] = struct{}{}
		releases = append(releases, release)
	}
	var releaseOnce sync.Once
	releaseAll := func() {
		releaseOnce.Do(func() {
			for index := len(releases) - 1; index >= 0; index-- {
				releases[index]()
			}
		})
	}
	return context.WithValue(ctx, seqmodHeldContextKey{}, held), releaseAll, nil
}

type ldapTransactionSeqmodTarget struct {
	dn           directory.DN
	database     *runtimeDatabase
	frontendLock bool
	databaseLock bool
}

func ldapTransactionSeqmodTargets(
	runtime *runtimeState,
	operation ldapTransactionOperation,
) ([]ldapTransactionSeqmodTarget, error) {
	appendTarget := func(
		targets []ldapTransactionSeqmodTarget,
		dn directory.DN,
		frontendLock bool,
		databaseLock bool,
	) ([]ldapTransactionSeqmodTarget, error) {
		database := databaseForDN(runtime, dn)
		var err error
		if database != nil {
			dn, err = normalizeRuntimeDatabaseDN(*database, dn)
		} else {
			dn, err = normalizeSeqmodRuntimeTarget(runtime, dn)
		}
		if err != nil {
			return nil, err
		}
		return append(targets, ldapTransactionSeqmodTarget{
			dn:           dn,
			database:     database,
			frontendLock: frontendLock,
			databaseLock: databaseLock,
		}), nil
	}

	switch request := operation.message.Request.(type) {
	case ldapwire.ModifyRequest:
		target, err := directory.ParseDN(request.DN)
		if err != nil {
			return nil, err
		}
		return appendTarget(nil, target, true, true)
	case ldapwire.ModifyDNRequest:
		oldDN, err := directory.ParseDN(request.DN)
		if err != nil {
			return nil, err
		}
		targets, err := appendTarget(nil, oldDN, true, true)
		if err != nil {
			return nil, err
		}
		var superior directory.DN
		if request.HasNewSuperior {
			superior, err = directory.ParseDN(request.NewSuperior)
		} else {
			var ok bool
			superior, ok = oldDN.Parent()
			if !ok {
				return nil, errors.New("root DSE cannot be renamed")
			}
		}
		if err != nil {
			return nil, err
		}
		newDN, err := directory.ComposeDN(request.NewRDN, superior)
		if err != nil {
			return nil, err
		}
		return appendTarget(targets, newDN, true, true)
	case ldapwire.ExtendedRequest:
		if request.Name != passwordModifyOID {
			return nil, nil
		}
		passwordRequest, err := ldapwire.DecodePasswordModifyRequestValue(
			request.Value,
			request.HasValue,
		)
		if err != nil {
			return nil, err
		}
		defer clear(passwordRequest.UserIdentity)
		defer clear(passwordRequest.OldPassword)
		defer clear(passwordRequest.NewPassword)
		targetName := operation.boundDN
		if passwordRequest.HasUserIdentity && len(passwordRequest.UserIdentity) > 0 {
			targetName = string(passwordRequest.UserIdentity)
		}
		target, err := directory.ParseDN(targetName)
		if err != nil {
			return nil, err
		}
		return appendTarget(nil, target, false, true)
	default:
		return nil, nil
	}
}

func (server *Server) commitLDAPTransaction(
	ctx context.Context,
	state *connectionState,
	transaction *ldapTransaction,
) (ldapwire.Result, ldapwire.TransactionEndResponseValue) {
	if failure := sockBackendTransactionCommitFailure(transaction); failure != nil {
		return failure.result, ldapwire.TransactionEndResponseValue{
			FailedMessageID:    failure.messageID,
			HasFailedMessageID: true,
		}
	}
	transactionContext, releaseSeqmods, err := acquireLDAPTransactionSeqmods(
		ctx,
		transaction.runtime,
		transaction.operations,
	)
	if err != nil {
		server.config.Logger.Error("LDAP transaction seqmod acquisition failed", "error", err)
		return ldapwire.ResultError(
			ldapwire.ResultOperationsError,
			"internal transaction error",
		), ldapwire.TransactionEndResponseValue{}
	}
	defer releaseSeqmods()
	ctx = transactionContext
	preparedExternalPasswords, err :=
		server.prepareLDAPTransactionExternalPasswords(ctx, state, transaction)
	if err != nil {
		server.config.Logger.Error(
			"LDAP transaction external password verification failed",
			"error",
			err,
		)
		return ldapwire.ResultError(
			ldapwire.ResultOperationsError,
			"internal transaction error",
		), ldapwire.TransactionEndResponseValue{}
	}
	var (
		execution                          transactionExecution
		endResponse                        ldapwire.TransactionEndResponseValue
		committedPasswordPolicyRestriction string
		committedBindCredentialDN          string
		committedBindCredentials           []byte
	)
	defer clear(committedBindCredentials)
	err = server.config.Store.Update(ctx, func(writer storage.Writer) error {
		execution.writer = writer
		transactionContext := context.WithValue(
			ctx,
			transactionExecutionContextKey{},
			&execution,
		)
		transactionState := cloneLDAPTransactionConnectionState(state)
		defer clear(transactionState.bindCredentials)
		transactionState.runtime = transaction.runtime
		transactionState.transaction = nil

		for _, operation := range transaction.operations {
			message := operation.message
			transactionState.boundDN = operation.boundDN
			transactionState.operationRealDN = operation.realDN
			operationContext := transactionContext
			if matches, present := preparedExternalPasswords[message.ID]; present {
				operationContext = context.WithValue(
					operationContext,
					preparedExternalPasswordVerificationContextKey{},
					preparedExternalPasswordVerification{matches: matches},
				)
			}
			operationContext = withACLSubject(
				operationContext,
				server.connectionACLSubject(&transactionState),
			)
			capture := &transactionResultCapture{}
			if err := server.executeTransactionOperation(
				operationContext,
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
		committedBindCredentialDN = transactionState.bindCredentialDN
		committedBindCredentials = bytes.Clone(transactionState.bindCredentials)
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
	clear(state.bindCredentials)
	state.bindCredentialDN = committedBindCredentialDN
	state.bindCredentials = bytes.Clone(committedBindCredentials)
	return ldapwire.Result{Code: ldapwire.ResultSuccess}, endResponse
}

// sockBackendTransactionCommitFailure is a final fail-closed guard for queued
// state assembled by older code or tests. It scans the entire queue before a
// storage transaction, password preflight, or external call can begin.
func sockBackendTransactionCommitFailure(
	transaction *ldapTransaction,
) *transactionCommitFailure {
	if transaction == nil || transaction.runtime == nil {
		return nil
	}
	state := &connectionState{runtime: transaction.runtime}
	for _, operation := range transaction.operations {
		state.boundDN = operation.boundDN
		target, _, _, ok := chainOperationTarget(state, operation.message.Request)
		if !ok {
			continue
		}
		database := databaseForDN(transaction.runtime, target)
		if database == nil || database.sockBackend == nil {
			continue
		}
		return &transactionCommitFailure{
			messageID: operation.message.ID,
			result:    sockBackendTransactionResult(),
		}
	}
	return nil
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
	return cloneTransactionMessageWithControls(
		message,
		withoutControl(message.Controls, transactionControlIndex),
	)
}

func cloneTransactionReplayMessage(message ldapwire.Message) ldapwire.Message {
	return cloneTransactionMessageWithControls(message, message.Controls)
}

func cloneTransactionMessageWithControls(
	message ldapwire.Message,
	controls []ldapwire.Control,
) ldapwire.Message {
	cloned := ldapwire.Message{
		ID:       message.ID,
		Controls: cloneLDAPControls(controls),
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
		clearLDAPTransactionOperation(&transaction.operations[messageIndex])
	}
	transaction.identifier = nil
	transaction.operations = nil
	transaction.messageIDs = nil
	transaction.queuedBytes = 0
	transaction.releaseRetainedOnce.Do(func() {
		if transaction.retainedBytes > 0 && transaction.releaseRetained != nil {
			transaction.releaseRetained(transaction.retainedBytes)
		}
	})
	transaction.retainedBytes = 0
	transaction.releaseRetained = nil
}

func clearLDAPTransactionOperation(operation *ldapTransactionOperation) {
	if operation == nil {
		return
	}
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
	operation.realDN = ""
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
