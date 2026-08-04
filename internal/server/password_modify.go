package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	generatedPasswordLength   = 8
	generatedPasswordAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

func (server *Server) handlePasswordModify(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.ExtendedRequest,
) error {
	defer clear(request.Value)
	controls, controlFailure := parseRequestControls(
		message.Controls,
		supportsManageDsaIT|supportsPasswordPolicy,
	)
	if controlFailure != nil {
		return server.writePasswordModifyResult(
			connection,
			message.ID,
			*controlFailure,
			nil,
		)
	}
	if state.boundDN == "" {
		return server.writePasswordModifyResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultStrongerAuthRequired,
				"only authenticated users may change passwords",
			),
			nil,
		)
	}

	passwordRequest, err := ldapwire.DecodePasswordModifyRequestValue(
		request.Value,
		request.HasValue,
	)
	if err != nil {
		return server.writePasswordModifyResult(
			connection,
			message.ID,
			ldapwire.ResultError(ldapwire.ResultProtocolError, "data decoding error"),
			nil,
		)
	}
	defer clear(passwordRequest.OldPassword)
	defer clear(passwordRequest.NewPassword)
	if passwordRequest.HasOldPassword && len(passwordRequest.OldPassword) == 0 {
		return server.writePasswordModifyResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"old password value is empty",
			),
			nil,
		)
	}
	if passwordRequest.HasNewPassword && len(passwordRequest.NewPassword) == 0 {
		return server.writePasswordModifyResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"new password value is empty",
			),
			nil,
		)
	}

	targetName := state.boundDN
	if passwordRequest.HasUserIdentity && len(passwordRequest.UserIdentity) > 0 {
		targetName = string(passwordRequest.UserIdentity)
	}
	target, err := directory.ParseDN(targetName)
	if err != nil {
		return server.writePasswordModifyResult(
			connection,
			message.ID,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, "Invalid DN"),
			nil,
		)
	}
	if target.Depth() == 0 {
		return server.writePasswordModifyResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"no password is associated with the Root DSE",
			),
			nil,
		)
	}
	database := databaseForDN(state.runtime, target)
	if database == nil {
		return server.writePasswordModifyResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"no authz backend",
			),
			nil,
		)
	}
	seqmodRelease, err := acquireDatabaseSeqmod(ctx, *database, target)
	if err != nil {
		return err
	}
	defer seqmodRelease()
	if len(retcodeConfigurationsForDatabase(state.runtime.databases, *database)) > 0 {
		retcodeTargetExists, err := server.retcodeStoredEntryExists(ctx, *database, target)
		if err != nil {
			return server.internalPasswordModifyError(connection, message.ID, err)
		}
		if retcodeTargetExists {
			if handled, err := server.tryRetcodeOperation(
				ctx,
				connection,
				state,
				message,
				target,
				retcodeOperationExtended,
				controls.manageDsaIT,
				nil,
			); handled {
				return err
			}
		}
	}
	if result := updateOperationPrecondition(state.runtime, state.boundDN, target); result != nil {
		return server.writePasswordModifyResult(connection, message.ID, *result, nil)
	}
	if result := databaseRestrictionResult(
		state.runtime,
		target,
		restrictPasswordModify,
	); result != nil {
		return server.writePasswordModifyResult(connection, message.ID, *result, nil)
	}
	if handled, err := server.tryTranslucentPasswordModify(
		ctx,
		connection,
		state,
		message,
		target,
		*database,
		passwordRequest,
	); handled {
		return err
	}

	newPassword := passwordRequest.NewPassword
	generated := false
	if !passwordRequest.HasNewPassword {
		newPassword, err = generatePassword()
		if err != nil {
			return server.internalPasswordModifyError(connection, message.ID, err)
		}
		defer clear(newPassword)
		generated = true
	}

	hashes := make([][]byte, 0, len(state.runtime.passwordHashSchemes))
	for _, scheme := range state.runtime.passwordHashSchemes {
		stored, err := auth.HashPassword(newPassword, scheme, nil)
		if err != nil {
			return server.internalPasswordModifyError(connection, message.ID, err)
		}
		hashes = append(hashes, stored)
	}
	changes := []ldapwire.Modification{{
		Operation: ldapwire.ModificationReplace,
		Attribute: directory.Attribute{
			Description: "userPassword",
			Values:      hashes,
		},
	}}
	var precondition entryModificationPrecondition
	if passwordRequest.HasOldPassword {
		precondition = func(reader storage.Reader, entry directory.Entry) error {
			if server.entryPasswordMatches(
				state.runtime,
				reader,
				state.boundDN,
				entry,
				passwordRequest.OldPassword,
			) {
				return nil
			}
			if database.ppolicy != nil && !database.ppolicy.disableWrite {
				return passwordPolicyOperationFailed(
					ldapwire.ResultUnwillingToPerform,
					"Must supply correct old password to change to new one",
					controls.passwordPolicy,
					passwordPolicyMustSupplyOldPassword,
				)
			}
			return operationFailed(
				ldapwire.ResultUnwillingToPerform,
				"unwilling to verify old password",
			)
		}
	}
	writeRecord := &accesslogWriteRecord{
		operation:       accesslogModify,
		session:         state.connectionID,
		authorizationDN: state.boundDN,
		requestDN:       target,
	}
	if isConfigurationDN(target) {
		server.configMu.Lock()
		defer server.configMu.Unlock()
	}
	nextRuntime, syncChanges, err := server.modifyEntry(
		ctx,
		state.runtime,
		state.boundDN,
		target,
		*database,
		changes,
		controls.manageDsaIT,
		false,
		false,
		false,
		precondition,
		server.passwordPolicyModificationProcessor(
			state.runtime,
			state.boundDN,
			*database,
			passwordPolicyModificationOptions{
				requestControl: controls.passwordPolicy,
				passwordModify: true,
				hasOldPassword: passwordRequest.HasOldPassword,
				oldPassword:    passwordRequest.OldPassword,
				newPassword:    newPassword,
			},
		),
		nil,
		writeRecord,
	)
	if err != nil {
		return server.finishPasswordModify(connection, message.ID, nil, err)
	}
	server.finishWriteEffects(ctx, nextRuntime, syncChanges...)
	server.finishAuditlogWrite(state, *database, *writeRecord)
	state.passwordPolicyRestrictedDN = ""

	var responseValue []byte
	if generated {
		responseValue = ldapwire.EncodePasswordModifyResponseValue(newPassword)
	}
	return server.writePasswordModifyResult(
		connection,
		message.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		responseValue,
	)
}

func (server *Server) entryPasswordMatches(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	entry directory.Entry,
	password []byte,
) bool {
	matched := false
	for _, stored := range entry.Values("userPassword") {
		if server.allowed(
			runtime,
			reader,
			boundDN,
			entry,
			"userPassword",
			stored,
			acl.Auth,
		) && auth.VerifyPassword(stored, password) {
			matched = true
		}
	}
	return matched
}

func generatePassword() ([]byte, error) {
	entropy := make([]byte, generatedPasswordLength)
	if _, err := rand.Read(entropy); err != nil {
		return nil, fmt.Errorf("generate password: %w", err)
	}
	password := make([]byte, len(entropy))
	for index, value := range entropy {
		password[index] = generatedPasswordAlphabet[int(value)&0x3f]
	}
	clear(entropy)
	return password, nil
}

func (server *Server) finishPasswordModify(
	connection net.Conn,
	messageID int64,
	responseValue []byte,
	err error,
) error {
	if failure := asOperationFailure(err); failure != nil {
		return server.writePasswordModifyResultWithControls(
			connection,
			messageID,
			failure.result,
			nil,
			failure.controls,
		)
	}
	if err != nil {
		return server.internalPasswordModifyError(connection, messageID, err)
	}
	return server.writePasswordModifyResult(
		connection,
		messageID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		responseValue,
	)
}

func (server *Server) internalPasswordModifyError(
	connection net.Conn,
	messageID int64,
	err error,
) error {
	server.config.Logger.Error("LDAP operation failed", "message_id", messageID, "error", err)
	return server.writePasswordModifyResult(
		connection,
		messageID,
		ldapwire.ResultError(
			ldapwire.ResultOperationsError,
			"internal operation error",
		),
		nil,
	)
}

func (server *Server) writePasswordModifyResult(
	connection net.Conn,
	messageID int64,
	result ldapwire.Result,
	responseValue []byte,
) error {
	return server.writePasswordModifyResultWithControls(
		connection,
		messageID,
		result,
		responseValue,
		nil,
	)
}

func (server *Server) writePasswordModifyResultWithControls(
	connection net.Conn,
	messageID int64,
	result ldapwire.Result,
	responseValue []byte,
	controls []ldapwire.Control,
) error {
	return server.writeLDAPResultResponse(
		connection,
		messageID,
		ldapwire.ApplicationExtendedResponse,
		result,
		"",
		responseValue,
		controls,
	)
}
