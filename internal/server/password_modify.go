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
		supportsManageDsaIT,
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
	if result := updateOperationPrecondition(state.runtime, state.boundDN, target); result != nil {
		return server.writePasswordModifyResult(connection, message.ID, *result, nil)
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
			return operationFailed(
				ldapwire.ResultUnwillingToPerform,
				"unwilling to verify old password",
			)
		}
	}
	nextRuntime, syncChange, err := server.modifyEntry(
		ctx,
		state.runtime,
		state.boundDN,
		target,
		*database,
		changes,
		controls.manageDsaIT,
		precondition,
		nil,
	)
	if err != nil {
		return server.finishPasswordModify(connection, message.ID, nil, err)
	}
	if nextRuntime != nil {
		server.activateRuntime(nextRuntime)
	}
	server.publishSyncChange(syncChange)

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
		return server.writePasswordModifyResult(
			connection,
			messageID,
			failure.result,
			nil,
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
	return ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
		messageID,
		result,
		"",
		responseValue,
		nil,
	))
}
