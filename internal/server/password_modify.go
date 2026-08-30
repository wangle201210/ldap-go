package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
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
		supportsManageDsaIT|supportsPasswordPolicy|supportsPasswordHashScheme,
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
	target, err := normalizePasswordModifyDN(state.runtime, targetName, nil)
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
	target, err = normalizePasswordModifyDN(state.runtime, target.String(), database)
	if err != nil {
		return server.writePasswordModifyResult(
			connection,
			message.ID,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, "Invalid DN"),
			nil,
		)
	}
	bound, err := normalizePasswordModifyDN(state.runtime, state.boundDN, database)
	if err != nil {
		return server.internalPasswordModifyError(connection, message.ID, err)
	}
	if result := operationSecurityResult(state, database, policyUpdate); result != nil {
		return server.writePasswordModifyResult(connection, message.ID, *result, nil)
	}
	authorizationDN := bound.NormalizedString()
	accessSubject := server.connectionACLSubject(state)
	accessSubject.DN = authorizationDN
	if accessSubject.RealDN != "" {
		realDN, normalizeErr := normalizePasswordModifyDN(
			state.runtime,
			accessSubject.RealDN,
			nil,
		)
		if normalizeErr != nil {
			return server.internalPasswordModifyError(
				connection,
				message.ID,
				normalizeErr,
			)
		}
		accessSubject.RealDN = realDN.NormalizedString()
	}
	ctx = withACLSubject(ctx, accessSubject)
	originalBoundDN := state.boundDN
	originalRealDN := state.operationRealDN
	state.boundDN = authorizationDN
	state.operationRealDN = accessSubject.RealDN
	defer func() {
		state.boundDN = originalBoundDN
		state.operationRealDN = originalRealDN
	}()
	if passwordModifyLegacyIdentityCollision(bound, target) &&
		!databaseRootMatches(state.runtime, *database, bound) {
		return server.writePasswordModifyResult(
			connection,
			message.ID,
			ldapwire.ResultError(ldapwire.ResultInsufficientAccessRights, ""),
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
	if result := updateOperationPrecondition(state.runtime, authorizationDN, target); result != nil {
		return server.writePasswordModifyResult(connection, message.ID, *result, nil)
	}
	if result := databaseRestrictionResult(
		state.runtime,
		target,
		restrictPasswordModify,
	); result != nil {
		return server.writePasswordModifyResult(connection, message.ID, *result, nil)
	}
	if controls.passwordHashSchemePresent && activeTranslucentConfiguration(database) != nil {
		return server.writePasswordModifyResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnavailableCriticalExtension,
				"password hash scheme control is not supported by the translucent backend",
			),
			nil,
		)
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
	if controls.passwordHashSchemePresent {
		if len(newPassword) > ldapwire.PasswordHashSelectionMaxPasswordBytes {
			return server.writePasswordModifyResult(
				connection,
				message.ID,
				ldapwire.ResultError(
					ldapwire.ResultConstraintViolation,
					"password exceeds the selected-hash input limit",
				),
				nil,
			)
		}
		authorized, authorizationErr := server.passwordHashSelectionAuthorized(
			ctx,
			state.runtime,
			authorizationDN,
			*database,
			target,
		)
		if authorizationErr != nil {
			return server.internalPasswordModifyError(connection, message.ID, authorizationErr)
		}
		if !authorized {
			return server.writePasswordModifyResult(
				connection,
				message.ID,
				ldapwire.ResultError(ldapwire.ResultInsufficientAccessRights, ""),
				nil,
			)
		}
	}
	changes := []ldapwire.Modification{{
		Operation: ldapwire.ModificationReplace,
		Attribute: directory.Attribute{
			Description: "userPassword",
			Values:      [][]byte{bytes.Clone(newPassword)},
		},
	}}
	defer clear(changes[0].Attribute.Values[0])
	policyOptions := passwordPolicyModificationOptions{
		requestControl:           controls.passwordPolicy,
		passwordModify:           true,
		hasOldPassword:           passwordRequest.HasOldPassword,
		enforceQualityAndHistory: controls.passwordHashSchemePresent,
		oldPassword:              passwordRequest.OldPassword,
		newPassword:              newPassword,
	}
	policyOptions.externalMatches, err = server.preverifyPasswordModification(
		ctx,
		state.runtime,
		authorizationDN,
		*database,
		target,
		changes,
		nil,
		policyOptions,
	)
	if err != nil {
		return server.finishPasswordModify(connection, message.ID, nil, err)
	}
	clear(changes[0].Attribute.Values[0])
	hashSchemes := state.runtime.passwordHashSchemes
	if controls.passwordHashSchemePresent {
		hashSchemes = []string{controls.passwordHashScheme}
	}
	hashes := make([][]byte, 0, len(hashSchemes))
	defer func() {
		for _, hash := range hashes {
			clear(hash)
		}
	}()
	for _, scheme := range hashSchemes {
		stored, hashErr := hashPasswordForRuntime(state.runtime, newPassword, scheme)
		if hashErr != nil {
			return server.internalPasswordModifyError(connection, message.ID, hashErr)
		}
		hashes = append(hashes, stored)
	}
	changes[0].Attribute.Values = hashes
	var precondition entryModificationPrecondition
	if passwordRequest.HasOldPassword {
		precondition = func(reader storage.Reader, entry directory.Entry) error {
			if err := validateExternalPasswordMatches(
				policyOptions.externalMatches,
				state.runtime.schema.AttributeValues(entry, "userPassword"),
				passwordRequest.OldPassword,
			); err != nil {
				return err
			}
			if server.entryPasswordMatches(
				state.runtime,
				reader,
				authorizationDN,
				entry,
				passwordRequest.OldPassword,
				policyOptions.externalMatches,
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
		authorizationDN: authorizationDN,
		requestDN:       target,
	}
	if isConfigurationDN(target) {
		server.configMu.Lock()
		defer server.configMu.Unlock()
	}
	nextRuntime, syncChanges, err := server.modifyEntry(
		ctx,
		state.runtime,
		authorizationDN,
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
			authorizationDN,
			*database,
			policyOptions,
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

func normalizePasswordModifyDN(
	runtime *runtimeState,
	value string,
	database *runtimeDatabase,
) (directory.DN, error) {
	var normalizer directory.DNAttributeNormalizer
	if runtime != nil {
		normalizer = runtime.schema
	}
	dn, err := parseRuntimeDN(value, normalizer)
	if err != nil {
		return directory.DN{}, err
	}
	if database == nil && runtime != nil {
		database = databaseForDN(runtime, dn)
	}
	if database == nil {
		return dn, nil
	}
	return normalizeRuntimeDatabaseDN(*database, dn)
}

func (server *Server) passwordHashSelectionAuthorized(
	ctx context.Context,
	runtime *runtimeState,
	boundDN string,
	database runtimeDatabase,
	target directory.DN,
) (bool, error) {
	authorized := false
	err := server.viewStorage(ctx, func(reader storage.Reader) error {
		databaseReader := readerForDatabase(reader, database)
		entry, err := databaseReader.Get(target)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		authorized = server.allowed(
			runtime,
			databaseReader,
			boundDN,
			entry,
			"userPassword",
			nil,
			acl.Manage,
		)
		return nil
	})
	return authorized, err
}

func passwordModifyLegacyIdentityCollision(left, right directory.DN) bool {
	if left.Equal(right) {
		return false
	}
	// Legacy ACL self matching folds case. Fail closed only when that legacy
	// identity would collapse two DNs that the active schema keeps distinct.
	legacyLeft, leftErr := directory.ParseDN(left.String())
	legacyRight, rightErr := directory.ParseDN(right.String())
	return leftErr == nil && rightErr == nil && legacyLeft.Equal(legacyRight)
}

func (server *Server) entryPasswordMatches(
	runtime *runtimeState,
	reader storage.Reader,
	boundDN string,
	entry directory.Entry,
	password []byte,
	externalMatches externalPasswordMatches,
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
		) && verifyStoredPasswordWithExternalMatches(
			stored,
			password,
			externalMatches,
		) {
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
	if errors.Is(err, auth.ErrPasswordHashUnavailable) {
		return server.writePasswordModifyResult(
			connection,
			messageID,
			ldapwire.ResultError(
				ldapwire.ResultOther,
				auth.ErrPasswordHashUnavailable.Error(),
			),
			nil,
		)
	}
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
