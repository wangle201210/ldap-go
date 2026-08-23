package server

import (
	"context"
	"errors"
	"net"
	"sort"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const translucentWriteDeniedDiagnostic = "user modification of overlay database not permitted"

func (server *Server) tryTranslucentBind(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.BindRequest,
	requestDN directory.DN,
) (bool, error) {
	database := databaseForDN(state.runtime, requestDN)
	configuration := activeTranslucentConfiguration(database)
	if configuration == nil {
		return false, nil
	}

	attempt := server.executeTranslucentBind(ctx, state, *configuration, message)
	if attempt.hasResult && attempt.result.Code == ldapwire.ResultSuccess {
		state.boundDN = request.Name
		state.authMechanism = "SIMPLE"
		state.bindCredentialDN = request.Name
		state.bindCredentials = append([]byte(nil), request.Authentication.Simple...)
		return true, server.writeLDAPBackendAttempt(connection, message, attempt)
	}
	if !configuration.bindLocal {
		return true, server.writeLDAPBackendAttempt(connection, message, attempt)
	}
	return false, nil
}

func (server *Server) executeTranslucentBind(
	ctx context.Context,
	state *connectionState,
	configuration translucentRuntimeConfiguration,
	message ldapwire.Message,
) chainAttempt {
	return server.executeLDAPBackendBind(
		ctx,
		state,
		&configuration.backend,
		message,
	)
}

func (server *Server) tryTranslucentAdd(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	dn directory.DN,
	controls requestControls,
) (bool, error) {
	database := databaseForDN(state.runtime, dn)
	configuration := activeTranslucentConfiguration(database)
	if configuration == nil {
		return false, nil
	}
	if !translucentRootOperation(state.runtime, *database, state.boundDN) {
		return true, server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationAddResponse,
			ldapwire.ResultError(
				ldapwire.ResultInsufficientAccessRights,
				translucentWriteDeniedDiagnostic,
			),
		)
	}

	request := message.Request.(ldapwire.AddRequest)
	validationEntry := request.Entry.Clone()
	if !validationEntry.HasAttribute("objectClass") {
		validationEntry.Attributes = append(validationEntry.Attributes, directory.Attribute{
			Description: "objectClass",
			Values:      stringValues("top"),
		})
	}
	if result := validateNewEntry(validationEntry, dn); result != nil {
		return true, server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationAddResponse,
			*result,
		)
	}
	if controls.assertion != nil {
		matches, err := controls.assertion.MatchWith(
			validationEntry,
			state.runtime.schema,
		)
		if err != nil {
			return true, server.writeOperationResult(
				connection,
				message.ID,
				ldapwire.ApplicationAddResponse,
				ldapwire.ResultError(
					ldapwire.ResultInappropriateMatching,
					err.Error(),
				),
			)
		}
		if !matches {
			return true, server.writeOperationResult(
				connection,
				message.ID,
				ldapwire.ApplicationAddResponse,
				ldapwire.ResultError(ldapwire.ResultAssertionFailed, ""),
			)
		}
	}
	err := server.updateStorage(ctx, func(writer storage.Writer) error {
		tx := writerForDatabase(writer, *database)
		if _, err := tx.Get(dn); err == nil {
			return operationFailed(ldapwire.ResultEntryAlreadyExists, "")
		} else if !errors.Is(err, storage.ErrEntryNotFound) {
			return err
		}
		if err := ensureTranslucentParents(tx, *database, dn, configuration.noGlue); err != nil {
			return err
		}
		if err := tx.Put(request.Entry.Clone(), false); err != nil {
			if errors.Is(err, storage.ErrEntryExists) {
				return operationFailed(ldapwire.ResultEntryAlreadyExists, "")
			}
			return err
		}
		if controls.noOp {
			return noOperationFailure()
		}
		return refreshNamingContexts(writer)
	})
	return true, server.finishOperation(
		connection,
		message.ID,
		ldapwire.ApplicationAddResponse,
		err,
	)
}

func (server *Server) tryTranslucentModify(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	dn directory.DN,
	controls requestControls,
) (bool, error) {
	database := databaseForDN(state.runtime, dn)
	configuration := activeTranslucentConfiguration(database)
	if configuration == nil {
		return false, nil
	}
	if !translucentRootOperation(state.runtime, *database, state.boundDN) {
		return true, server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			ldapwire.ResultError(
				ldapwire.ResultInsufficientAccessRights,
				translucentWriteDeniedDiagnostic,
			),
		)
	}

	remote, failure, err := server.translucentRemoteBase(
		ctx,
		state,
		*database,
		message.ID,
		dn,
		ldapwire.NeverDerefAliases,
		0,
	)
	if err != nil {
		return true, server.internalOperationError(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			err,
		)
	}
	if failure != nil {
		return true, server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			*failure,
		)
	}
	if remote == nil {
		return true, server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			ldapwire.ResultError(
				ldapwire.ResultNoSuchObject,
				"attempt to modify nonexistent local record",
			),
		)
	}

	request := message.Request.(ldapwire.ModifyRequest)
	err = server.updateStorage(ctx, func(writer storage.Writer) error {
		tx := writerForDatabase(writer, *database)
		local, getErr := tx.Get(dn)
		localExists := getErr == nil
		if getErr != nil && !errors.Is(getErr, storage.ErrEntryNotFound) {
			return getErr
		}
		if controls.assertion != nil {
			merged := remote.Clone()
			if localExists {
				merged = mergeTranslucentEntry(*remote, local)
			}
			matches, matchErr := controls.assertion.MatchWith(merged, state.runtime.schema)
			if matchErr != nil {
				return operationFailed(ldapwire.ResultInappropriateMatching, matchErr.Error())
			}
			if !matches {
				return operationFailed(ldapwire.ResultAssertionFailed, "")
			}
		}

		changed, changeErr := applyTranslucentModifications(
			*remote,
			&local,
			localExists,
			request.Changes,
			configuration.strict,
			controls.permissiveModify,
		)
		if changeErr != nil {
			return changeErr
		}
		if !changed {
			if controls.noOp {
				return noOperationFailure()
			}
			return nil
		}
		if !localExists {
			local.DN = dn.String()
			if err := ensureTranslucentParents(tx, *database, dn, false); err != nil {
				return err
			}
		}
		if err := tx.Put(local, localExists); err != nil {
			return err
		}
		if controls.noOp {
			return noOperationFailure()
		}
		return refreshNamingContexts(writer)
	})
	return true, server.finishOperation(
		connection,
		message.ID,
		ldapwire.ApplicationModifyResponse,
		err,
	)
}

func applyTranslucentModifications(
	remote directory.Entry,
	local *directory.Entry,
	localExists bool,
	changes []ldapwire.Modification,
	strict bool,
	permissive bool,
) (bool, error) {
	if localExists {
		changed := false
		for _, change := range changes {
			if local.HasAttribute(change.Attribute.Description) {
				if err := applyModificationWithPermissive(local, change, permissive); err != nil {
					return false, err
				}
				changed = true
				continue
			}
			if change.Operation == ldapwire.ModificationDelete {
				if !remote.HasAttribute(change.Attribute.Description) {
					return false, operationFailed(
						ldapwire.ResultNoSuchAttribute,
						"attempt to delete nonexistent attribute",
					)
				}
				if strict {
					return false, operationFailed(
						ldapwire.ResultConstraintViolation,
						"attempt to delete nonexistent attribute",
					)
				}
				continue
			}
			localChange := change
			localChange.Operation = ldapwire.ModificationAdd
			if err := applyModificationWithPermissive(local, localChange, permissive); err != nil {
				return false, err
			}
			changed = true
		}
		return changed, nil
	}

	created := directory.Entry{DN: remote.DN}
	deletions := 0
	for _, change := range changes {
		switch change.Operation {
		case ldapwire.ModificationAdd, ldapwire.ModificationReplace:
			if err := applyModificationWithPermissive(&created, change, permissive); err != nil {
				return false, err
			}
		case ldapwire.ModificationDelete:
			deletions++
		default:
			continue
		}
	}
	if strict && deletions > 0 {
		return false, operationFailed(
			ldapwire.ResultConstraintViolation,
			"attempt to delete attributes from local database",
		)
	}
	if len(created.Attributes) == 0 {
		if strict {
			return false, operationFailed(
				ldapwire.ResultConstraintViolation,
				"modification contained other than ADD or REPLACE",
			)
		}
		return false, nil
	}
	*local = created
	return true, nil
}

func (server *Server) tryTranslucentDelete(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	dn directory.DN,
	controls requestControls,
) (bool, error) {
	database := databaseForDN(state.runtime, dn)
	if activeTranslucentConfiguration(database) == nil {
		return false, nil
	}
	if !translucentRootOperation(state.runtime, *database, state.boundDN) {
		return true, server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationDeleteResponse,
			ldapwire.ResultError(
				ldapwire.ResultInsufficientAccessRights,
				translucentWriteDeniedDiagnostic,
			),
		)
	}

	err := server.updateStorage(ctx, func(writer storage.Writer) error {
		tx := writerForDatabase(writer, *database)
		entry, err := tx.Get(dn)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return operationFailed(ldapwire.ResultNoSuchObject, "")
		}
		if err != nil {
			return err
		}
		if controls.assertion != nil {
			matches, matchErr := controls.assertion.MatchWith(entry, state.runtime.schema)
			if matchErr != nil {
				return operationFailed(ldapwire.ResultInappropriateMatching, matchErr.Error())
			}
			if !matches {
				return operationFailed(ldapwire.ResultAssertionFailed, "")
			}
		}
		comparisonDN, err := storage.NormalizeReaderDN(tx, dn)
		if err != nil {
			return err
		}
		hasChildren := false
		if err := tx.ForEach(func(candidate directory.Entry) error {
			candidateDN, err := directory.ParseDN(candidate.DN)
			if err != nil {
				return err
			}
			candidateDN, err = storage.NormalizeReaderDN(tx, candidateDN)
			if err != nil {
				return err
			}
			if comparisonDN.AncestorOf(candidateDN) {
				hasChildren = true
			}
			return nil
		}); err != nil {
			return err
		}
		if hasChildren {
			return operationFailed(
				ldapwire.ResultNotAllowedOnNonLeaf,
				"subordinate objects must be deleted first",
			)
		}
		if err := tx.Delete(dn); err != nil {
			return err
		}
		if controls.noOp {
			return noOperationFailure()
		}
		return refreshNamingContexts(writer)
	})
	return true, server.finishOperation(
		connection,
		message.ID,
		ldapwire.ApplicationDeleteResponse,
		err,
	)
}

func (server *Server) tryTranslucentModifyDN(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	oldDN,
	newDN directory.DN,
	controls requestControls,
) (bool, error) {
	database := databaseForDN(state.runtime, oldDN)
	configuration := activeTranslucentConfiguration(database)
	if configuration == nil {
		return false, nil
	}
	if !translucentRootOperation(state.runtime, *database, state.boundDN) {
		return true, server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(
				ldapwire.ResultInsufficientAccessRights,
				translucentWriteDeniedDiagnostic,
			),
		)
	}

	request := message.Request.(ldapwire.ModifyDNRequest)
	err := server.updateStorage(ctx, func(writer storage.Writer) error {
		tx := writerForDatabase(writer, *database)
		comparisonOldDN, err := storage.NormalizeReaderDN(tx, oldDN)
		if err != nil {
			return err
		}
		comparisonNewDN, err := storage.NormalizeReaderDN(tx, newDN)
		if err != nil {
			return err
		}
		source, err := tx.Get(oldDN)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return operationFailed(ldapwire.ResultNoSuchObject, "")
		}
		if err != nil {
			return err
		}
		storedOldDN, err := directory.ParseDN(source.DN)
		if err != nil {
			return err
		}
		storedOldDN, err = storage.NormalizeReaderDN(tx, storedOldDN)
		if err != nil {
			return err
		}
		if controls.assertion != nil {
			matches, matchErr := controls.assertion.MatchWith(source, state.runtime.schema)
			if matchErr != nil {
				return operationFailed(ldapwire.ResultInappropriateMatching, matchErr.Error())
			}
			if !matches {
				return operationFailed(ldapwire.ResultAssertionFailed, "")
			}
		}
		if request.DeleteOldRDN {
			for _, value := range storedOldDN.RDNValues() {
				if !source.HasValue(value.Type, value.Value) {
					return operationFailed(
						ldapwire.ResultNoSuchAttribute,
						"old RDN value is not present in the local entry",
					)
				}
			}
		}
		if err := ensureTranslucentParents(tx, *database, newDN, configuration.noGlue); err != nil {
			return err
		}
		storedNewDN, err := translucentStoredDestinationDN(
			tx,
			newDN,
			request.NewRDN,
		)
		if err != nil {
			return err
		}
		if !storedNewDN.Equal(comparisonNewDN) {
			return errors.New("resolved translucent destination has a different DN identity")
		}

		type move struct {
			oldDN directory.DN
			newDN directory.DN
			entry directory.Entry
		}
		var moves []move
		oldKeys := make(map[string]struct{})
		if err := tx.ForEach(func(entry directory.Entry) error {
			candidate, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			candidate, err = storage.NormalizeReaderDN(tx, candidate)
			if err != nil {
				return err
			}
			if !comparisonOldDN.Equal(candidate) &&
				!comparisonOldDN.AncestorOf(candidate) {
				return nil
			}
			replaced, err := candidate.ReplaceAncestor(
				comparisonOldDN,
				storedNewDN,
			)
			if err != nil {
				return err
			}
			moves = append(moves, move{oldDN: candidate, newDN: replaced, entry: entry})
			oldKeys[candidate.Key()] = struct{}{}
			return nil
		}); err != nil {
			return err
		}
		for _, item := range moves {
			if _, err := tx.Get(item.newDN); err == nil {
				if _, moving := oldKeys[item.newDN.Key()]; !moving {
					return operationFailed(ldapwire.ResultEntryAlreadyExists, "")
				}
			} else if !errors.Is(err, storage.ErrEntryNotFound) {
				return err
			}
		}
		sort.Slice(moves, func(left, right int) bool {
			return moves[left].oldDN.Depth() > moves[right].oldDN.Depth()
		})
		for _, item := range moves {
			if err := tx.Delete(item.oldDN); err != nil {
				return err
			}
		}
		sort.Slice(moves, func(left, right int) bool {
			return moves[left].newDN.Depth() < moves[right].newDN.Depth()
		})
		for _, item := range moves {
			item.entry.DN = item.newDN.String()
			if item.oldDN.Equal(comparisonOldDN) {
				if request.DeleteOldRDN {
					item.entry.DeleteRDNValues(storedOldDN)
				}
				item.entry.EnsureRDNValues(storedNewDN)
			}
			if err := tx.Put(item.entry, false); err != nil {
				return err
			}
		}
		if controls.noOp {
			return noOperationFailure()
		}
		return refreshNamingContexts(writer)
	})
	return true, server.finishOperation(
		connection,
		message.ID,
		ldapwire.ApplicationModifyDNResponse,
		err,
	)
}

func translucentStoredDestinationDN(
	reader storage.Reader,
	requested directory.DN,
	newRDN string,
) (directory.DN, error) {
	superior, ok := requested.Parent()
	if !ok {
		return directory.DN{}, errors.New("translucent destination has no superior")
	}
	if superior.Depth() > 0 {
		parent, err := reader.Get(superior)
		if err != nil {
			return directory.DN{}, err
		}
		superior, err = directory.ParseDN(parent.DN)
		if err != nil {
			return directory.DN{}, err
		}
		superior, err = storage.NormalizeReaderDN(reader, superior)
		if err != nil {
			return directory.DN{}, err
		}
	}
	localName, err := directory.ParseDN(newRDN)
	if err != nil {
		return directory.DN{}, err
	}
	localName, err = storage.NormalizeReaderDN(reader, localName)
	if err != nil {
		return directory.DN{}, err
	}
	return directory.ComposeLocalName(localName, superior)
}

func (server *Server) tryTranslucentPasswordModify(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	target directory.DN,
	database runtimeDatabase,
	request ldapwire.PasswordModifyRequestValue,
) (bool, error) {
	configuration := activeTranslucentConfiguration(&database)
	if configuration == nil {
		return false, nil
	}
	if !configuration.pwmodLocal {
		return true, server.writePasswordModifyResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultConstraintViolation,
				"attempt to modify password in local database",
			),
			nil,
		)
	}
	if !translucentPasswordModifyAuthorized(state.runtime, database, state.boundDN, target) {
		return true, server.writePasswordModifyResult(
			connection,
			message.ID,
			ldapwire.ResultError(ldapwire.ResultInsufficientAccessRights, ""),
			nil,
		)
	}

	remote, failure, err := server.translucentRemoteBase(
		ctx,
		state,
		database,
		message.ID,
		target,
		ldapwire.NeverDerefAliases,
		0,
	)
	if err != nil {
		return true, server.internalPasswordModifyError(connection, message.ID, err)
	}
	if failure != nil {
		return true, server.writePasswordModifyResult(connection, message.ID, *failure, nil)
	}
	if remote == nil {
		return true, server.writePasswordModifyResult(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultNoSuchObject,
				"attempt to modify nonexistent local record",
			),
			nil,
		)
	}

	newPassword := request.NewPassword
	generated := false
	if !request.HasNewPassword {
		newPassword, err = generatePassword()
		if err != nil {
			return true, server.internalPasswordModifyError(connection, message.ID, err)
		}
		defer clear(newPassword)
		generated = true
	}
	hashes := make([][]byte, 0, len(state.runtime.passwordHashSchemes))
	for _, scheme := range state.runtime.passwordHashSchemes {
		stored, err := hashPasswordForRuntime(state.runtime, newPassword, scheme)
		if err != nil {
			return true, server.internalPasswordModifyError(connection, message.ID, err)
		}
		hashes = append(hashes, stored)
	}
	var externalMatches externalPasswordMatches
	if request.HasOldPassword {
		externalMatches, err = server.preverifyEntryPasswords(
			ctx,
			state.runtime,
			database,
			target,
			"userPassword",
			request.OldPassword,
		)
		if err != nil {
			return true, server.internalPasswordModifyError(connection, message.ID, err)
		}
	}

	err = server.updateStorage(ctx, func(writer storage.Writer) error {
		tx := writerForDatabase(writer, database)
		local, getErr := tx.Get(target)
		localExists := getErr == nil
		if getErr != nil && !errors.Is(getErr, storage.ErrEntryNotFound) {
			return getErr
		}
		if request.HasOldPassword {
			if err := validateExternalPasswordMatches(
				externalMatches,
				local.Values("userPassword"),
				request.OldPassword,
			); err != nil {
				return err
			}
			matched := false
			for _, stored := range local.Values("userPassword") {
				if verifyStoredPasswordWithExternalMatches(
					stored,
					request.OldPassword,
					externalMatches,
				) {
					matched = true
				}
			}
			if !matched {
				return operationFailed(
					ldapwire.ResultUnwillingToPerform,
					"unwilling to verify old password",
				)
			}
		}
		if !localExists {
			local = directory.Entry{DN: target.String()}
			if err := ensureTranslucentParents(tx, database, target, false); err != nil {
				return err
			}
		}
		local.ReplaceValues("userPassword", hashes)
		return tx.Put(local, localExists)
	})
	if err != nil {
		return true, server.finishPasswordModify(connection, message.ID, nil, err)
	}
	state.passwordPolicyRestrictedDN = ""
	if credentialDN, parseErr := directory.ParseDN(state.bindCredentialDN); parseErr == nil && credentialDN.Equal(target) {
		clear(state.bindCredentials)
		state.bindCredentials = append([]byte(nil), newPassword...)
	}
	var responseValue []byte
	if generated {
		responseValue = ldapwire.EncodePasswordModifyResponseValue(newPassword)
	}
	return true, server.writePasswordModifyResult(
		connection,
		message.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		responseValue,
	)
}

func translucentRootOperation(
	runtime *runtimeState,
	database runtimeDatabase,
	boundDN string,
) bool {
	dn, err := directory.ParseDN(boundDN)
	return err == nil && databaseRootMatches(runtime, database, dn)
}

func translucentPasswordModifyAuthorized(
	runtime *runtimeState,
	database runtimeDatabase,
	boundDN string,
	target directory.DN,
) bool {
	dn, err := directory.ParseDN(boundDN)
	if err != nil {
		return false
	}
	return dn.Equal(target) || databaseRootMatches(runtime, database, dn)
}

func ensureTranslucentParents(
	writer storage.Writer,
	database runtimeDatabase,
	target directory.DN,
	noGlue bool,
) error {
	suffix, ok := translucentSuffixForDN(database, target)
	if !ok || target.Equal(suffix) {
		return nil
	}
	parent, ok := target.Parent()
	if !ok || parent.Depth() < suffix.Depth() {
		return nil
	}
	if noGlue {
		if _, err := writer.Get(parent); errors.Is(err, storage.ErrEntryNotFound) {
			return operationFailed(ldapwire.ResultNoSuchObject, "")
		} else if err != nil {
			return err
		}
		return nil
	}

	var missing []directory.DN
	for current := parent; current.Depth() >= suffix.Depth(); {
		if _, err := writer.Get(current); errors.Is(err, storage.ErrEntryNotFound) {
			missing = append(missing, current)
		} else if err != nil {
			return err
		}
		if current.Equal(suffix) {
			break
		}
		next, exists := current.Parent()
		if !exists {
			break
		}
		current = next
	}
	for index := len(missing) - 1; index >= 0; index-- {
		entry := directory.Entry{
			DN: missing[index].String(),
			Attributes: []directory.Attribute{
				{Description: "structuralObjectClass", Values: stringValues("glue")},
				{Description: "objectClass", Values: stringValues("top", "glue")},
			},
		}
		if err := writer.Put(entry, false); err != nil && !errors.Is(err, storage.ErrEntryExists) {
			return err
		}
	}
	return nil
}

func translucentSuffixForDN(
	database runtimeDatabase,
	dn directory.DN,
) (directory.DN, bool) {
	var selected directory.DN
	found := false
	for _, suffix := range database.suffixes {
		if !suffix.Equal(dn) && !suffix.AncestorOf(dn) {
			continue
		}
		if !found || suffix.Depth() > selected.Depth() {
			selected = suffix
			found = true
		}
	}
	return selected, found
}
