package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var protectedOperationalAttributes = map[string]string{
	"createtimestamp":       "createTimestamp",
	"creatorsname":          "creatorsName",
	"entrycsn":              "entryCSN",
	"entryuuid":             "entryUUID",
	"modifiersname":         "modifiersName",
	"modifytimestamp":       "modifyTimestamp",
	"structuralobjectclass": "structuralObjectClass",
	"subschemasubentry":     "subschemaSubentry",
}

func (server *Server) handleAdd(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.AddRequest,
) error {
	controls, result := parseRequestControls(
		message.Controls,
		supportsAssertion|supportsPostRead|supportsManageDsaIT,
	)
	if result != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationAddResponse, *result)
	}

	dn, err := directory.ParseDN(request.Entry.DN)
	if err != nil || dn.Depth() == 0 {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationAddResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
		)
	}
	if isSubschemaDN(dn) {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationAddResponse,
			ldapwire.ResultError(ldapwire.ResultEntryAlreadyExists, ""),
		)
	}
	database := databaseForDN(state.runtime, dn)
	if database == nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationAddResponse,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"no global superior knowledge",
			),
		)
	}
	if result := updateOperationPrecondition(state.runtime, state.boundDN, dn); result != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationAddResponse,
			*result,
		)
	}
	if result := validateNewEntry(request.Entry, dn); result != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationAddResponse, *result)
	}
	configurationWrite := isConfigurationDN(dn)
	if configurationWrite {
		server.configMu.Lock()
		defer server.configMu.Unlock()
	}

	entry := request.Entry.Clone()
	if err := server.applyCreateOperationalAttributes(
		&entry,
		state.boundDN,
		lastModEnabled(state.runtime, dn),
	); err != nil {
		return server.internalOperationError(connection, message.ID, ldapwire.ApplicationAddResponse, err)
	}
	if !configurationWrite {
		if err := state.runtime.schema.ValidateEntry(entry); err != nil {
			result := schemaValidationResult(err)
			return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationAddResponse, result)
		}
		if err := server.applySchemaOperationalAttributes(state.runtime, &entry); err != nil {
			return server.internalOperationError(connection, message.ID, ldapwire.ApplicationAddResponse, err)
		}
	}

	var (
		nextRuntime      *runtimeState
		responseControls []ldapwire.Control
	)
	err = server.config.Store.Update(ctx, func(writer storage.Writer) error {
		tx := storage.WriterInPartition(writer, database.partition)
		if _, err := server.entryOrReferral(
			state.runtime,
			tx,
			state.boundDN,
			dn,
			controls.manageDsaIT,
		); err == nil {
			return operationFailed(ldapwire.ResultEntryAlreadyExists, "")
		} else if !errors.Is(err, storage.ErrEntryNotFound) {
			return err
		}
		if err := server.checkAssertion(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			controls.assertion,
		); err != nil {
			return err
		}

		if parent, ok := dn.Parent(); ok && parent.Depth() > 0 {
			if _, err := tx.Get(parent); err != nil {
				if !errors.Is(err, storage.ErrEntryNotFound) {
					return err
				}
				if !databaseOwnsSuffix(*database, dn) {
					belowContext, err := belowKnownNamingContext(tx, dn)
					if err != nil {
						return err
					}
					if belowContext {
						return operationFailed(
							ldapwire.ResultNoSuchObject,
							server.disclosedAncestor(state.runtime, tx, state.boundDN, dn),
						)
					}
				}
			}
		}
		parent := directory.Entry{DN: ""}
		if parentDN, ok := dn.Parent(); ok {
			parent.DN = parentDN.String()
			if storedParent, getErr := tx.Get(parentDN); getErr == nil {
				parent = storedParent
			} else if !errors.Is(getErr, storage.ErrEntryNotFound) {
				return getErr
			}
		}
		if !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			parent,
			"children",
			nil,
			acl.WriteAdd,
		) || !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			"entry",
			nil,
			acl.WriteAdd,
		) {
			return operationFailed(ldapwire.ResultInsufficientAccessRights, "")
		}
		if state.runtime.access.RequiresAddContentACL(dn) {
			for _, attribute := range request.Entry.Attributes {
				if !server.canAccessAttribute(
					state.runtime,
					tx,
					state.boundDN,
					entry,
					attribute,
					acl.WriteAdd,
				) {
					return operationFailed(ldapwire.ResultInsufficientAccessRights, "")
				}
			}
		}
		if err := tx.Put(entry, false); err != nil {
			return err
		}
		postRead, err := server.readResponseControl(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			controls.postRead,
			postReadControlOID,
		)
		if err != nil {
			return err
		}
		if postRead != nil {
			responseControls = append(responseControls, *postRead)
		}
		if err := refreshNamingContexts(writer); err != nil {
			return err
		}
		if configurationWrite {
			var validationErr error
			nextRuntime, validationErr = server.validateRuntimeConfiguration(writer)
			return validationErr
		}
		return nil
	})
	if err == nil && nextRuntime != nil {
		server.runtime.Store(nextRuntime)
	}
	return server.finishOperationWithControls(
		connection,
		message.ID,
		ldapwire.ApplicationAddResponse,
		err,
		responseControls,
	)
}

func (server *Server) handleModify(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.ModifyRequest,
) error {
	controls, result := parseRequestControls(
		message.Controls,
		supportsAssertion|
			supportsPreRead|
			supportsPostRead|
			supportsManageDsaIT,
	)
	if result != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyResponse, *result)
	}
	dn, err := directory.ParseDN(request.DN)
	if err != nil || dn.Depth() == 0 {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
		)
	}
	if isSubschemaDN(dn) {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			ldapwire.ResultError(ldapwire.ResultUnwillingToPerform, "subschema is read-only"),
		)
	}
	database := databaseForDN(state.runtime, dn)
	if database == nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"no global superior knowledge",
			),
		)
	}
	if result := updateOperationPrecondition(state.runtime, state.boundDN, dn); result != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			*result,
		)
	}
	var responseControls []ldapwire.Control
	nextRuntime, err := server.modifyEntry(
		ctx,
		state.runtime,
		state.boundDN,
		dn,
		*database,
		request.Changes,
		controls.manageDsaIT,
		func(reader storage.Reader, entry directory.Entry) error {
			if err := server.checkAssertion(
				state.runtime,
				reader,
				state.boundDN,
				entry,
				controls.assertion,
			); err != nil {
				return err
			}
			preRead, err := server.readResponseControl(
				state.runtime,
				reader,
				state.boundDN,
				entry,
				controls.preRead,
				preReadControlOID,
			)
			if err != nil {
				return err
			}
			if preRead != nil {
				responseControls = append(responseControls, *preRead)
			}
			return nil
		},
		func(reader storage.Reader, entry directory.Entry) error {
			postRead, err := server.readResponseControl(
				state.runtime,
				reader,
				state.boundDN,
				entry,
				controls.postRead,
				postReadControlOID,
			)
			if err != nil {
				return err
			}
			if postRead != nil {
				responseControls = append(responseControls, *postRead)
			}
			return nil
		},
	)
	if err == nil && nextRuntime != nil {
		server.runtime.Store(nextRuntime)
	}
	return server.finishOperationWithControls(
		connection,
		message.ID,
		ldapwire.ApplicationModifyResponse,
		err,
		responseControls,
	)
}

type entryModificationPrecondition func(
	reader storage.Reader,
	entry directory.Entry,
) error

type entryModificationPostcondition func(
	reader storage.Reader,
	entry directory.Entry,
) error

func (server *Server) modifyEntry(
	ctx context.Context,
	runtime *runtimeState,
	boundDN string,
	dn directory.DN,
	database runtimeDatabase,
	changes []ldapwire.Modification,
	manageDsaIT bool,
	precondition entryModificationPrecondition,
	postcondition entryModificationPostcondition,
) (*runtimeState, error) {
	configurationWrite := isConfigurationDN(dn)
	if configurationWrite {
		server.configMu.Lock()
		defer server.configMu.Unlock()
	}

	var nextRuntime *runtimeState
	err := server.config.Store.Update(ctx, func(writer storage.Writer) error {
		tx := storage.WriterInPartition(writer, database.partition)
		entry, err := server.entryOrReferral(
			runtime,
			tx,
			boundDN,
			dn,
			manageDsaIT,
		)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return operationFailed(
				ldapwire.ResultNoSuchObject,
				server.disclosedAncestor(runtime, tx, boundDN, dn),
			)
		}
		if err != nil {
			return err
		}
		if precondition != nil {
			if err := precondition(tx, entry); err != nil {
				return err
			}
		}

		if !server.canApplyModifications(
			runtime,
			tx,
			boundDN,
			entry,
			changes,
		) {
			return operationFailed(ldapwire.ResultInsufficientAccessRights, "")
		}
		for _, change := range changes {
			if isProtectedOperationalAttribute(change.Attribute.Description) {
				return operationFailed(ldapwire.ResultConstraintViolation, "operational attribute is not user modifiable")
			}
			if failure := applyModification(&entry, change); failure != nil {
				return failure
			}
		}
		for _, rdnValue := range dn.RDNValues() {
			if !entry.HasValue(rdnValue.Type, rdnValue.Value) {
				return operationFailed(ldapwire.ResultNotAllowedOnRDN, "")
			}
		}
		if lastModEnabled(runtime, dn) {
			server.applyModifyOperationalAttributes(&entry, boundDN)
		}
		if !configurationWrite {
			if err := runtime.schema.ValidateEntry(entry); err != nil {
				return operationFailureFromSchema(err)
			}
			if err := server.applySchemaOperationalAttributes(runtime, &entry); err != nil {
				return err
			}
		}
		if err := tx.Put(entry, true); err != nil {
			return err
		}
		if postcondition != nil {
			if err := postcondition(tx, entry); err != nil {
				return err
			}
		}
		if configurationWrite {
			var err error
			nextRuntime, err = server.validateRuntimeConfiguration(writer)
			return err
		}
		return nil
	})
	return nextRuntime, err
}

func (server *Server) handleDelete(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.DeleteRequest,
) error {
	controls, result := parseRequestControls(
		message.Controls,
		supportsAssertion|supportsPreRead|supportsManageDsaIT,
	)
	if result != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationDeleteResponse, *result)
	}
	dn, err := directory.ParseDN(request.DN)
	if err != nil || dn.Depth() == 0 {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationDeleteResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
		)
	}
	if isSubschemaDN(dn) {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationDeleteResponse,
			ldapwire.ResultError(ldapwire.ResultUnwillingToPerform, "subschema is read-only"),
		)
	}
	database := databaseForDN(state.runtime, dn)
	if database == nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationDeleteResponse,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"no global superior knowledge",
			),
		)
	}
	if result := updateOperationPrecondition(state.runtime, state.boundDN, dn); result != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationDeleteResponse,
			*result,
		)
	}
	configurationWrite := isConfigurationDN(dn)
	if configurationWrite {
		server.configMu.Lock()
		defer server.configMu.Unlock()
	}

	var (
		nextRuntime      *runtimeState
		responseControls []ldapwire.Control
	)
	err = server.config.Store.Update(ctx, func(writer storage.Writer) error {
		tx := storage.WriterInPartition(writer, database.partition)
		entry, err := server.entryOrReferral(
			state.runtime,
			tx,
			state.boundDN,
			dn,
			controls.manageDsaIT,
		)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return operationFailed(
				ldapwire.ResultNoSuchObject,
				server.disclosedAncestor(state.runtime, tx, state.boundDN, dn),
			)
		}
		if err != nil {
			return err
		}
		if err := server.checkAssertion(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			controls.assertion,
		); err != nil {
			return err
		}

		parent, err := parentEntry(tx, dn)
		if err != nil {
			return err
		}
		if !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			parent,
			"children",
			nil,
			acl.WriteDelete,
		) || !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			"entry",
			nil,
			acl.WriteDelete,
		) {
			return operationFailed(ldapwire.ResultInsufficientAccessRights, "")
		}
		preRead, err := server.readResponseControl(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			controls.preRead,
			preReadControlOID,
		)
		if err != nil {
			return err
		}
		if preRead != nil {
			responseControls = append(responseControls, *preRead)
		}

		hasChildren := false
		if err := tx.ForEach(func(entry directory.Entry) error {
			candidate, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			if dn.AncestorOf(candidate) {
				hasChildren = true
			}
			return nil
		}); err != nil {
			return err
		}
		if hasChildren {
			return operationFailed(ldapwire.ResultNotAllowedOnNonLeaf, "")
		}
		if err := tx.Delete(dn); err != nil {
			return err
		}
		if err := refreshNamingContexts(writer); err != nil {
			return err
		}
		if configurationWrite {
			var err error
			nextRuntime, err = server.validateRuntimeConfiguration(writer)
			return err
		}
		return nil
	})
	if err == nil && nextRuntime != nil {
		server.runtime.Store(nextRuntime)
	}
	return server.finishOperationWithControls(
		connection,
		message.ID,
		ldapwire.ApplicationDeleteResponse,
		err,
		responseControls,
	)
}

func (server *Server) handleModifyDN(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.ModifyDNRequest,
) error {
	controls, result := parseRequestControls(
		message.Controls,
		supportsAssertion|
			supportsPreRead|
			supportsPostRead|
			supportsManageDsaIT,
	)
	if result != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyDNResponse, *result)
	}
	oldDN, err := directory.ParseDN(request.DN)
	if err != nil || oldDN.Depth() == 0 {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
		)
	}
	if isSubschemaDN(oldDN) {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultUnwillingToPerform, "subschema is read-only"),
		)
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
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
		)
	}
	newDN, err := directory.ComposeDN(request.NewRDN, superior)
	if err != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
		)
	}
	database := databaseForDN(state.runtime, oldDN)
	destinationDatabase := databaseForDN(state.runtime, newDN)
	if database == nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"no global superior knowledge",
			),
		)
	}
	if destinationDatabase == nil ||
		destinationDatabase.partition != database.partition {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(
				ldapwire.ResultAffectsMultipleDSAs,
				"cannot rename between DSAs",
			),
		)
	}
	if result := updateOperationPrecondition(
		state.runtime,
		state.boundDN,
		oldDN,
	); result != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			*result,
		)
	}
	configurationWrite := isConfigurationDN(oldDN)
	if configurationWrite != isConfigurationDN(newDN) {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultAffectsMultipleDSAs, ""),
		)
	}
	if configurationWrite {
		server.configMu.Lock()
		defer server.configMu.Unlock()
	}
	if oldDN.Equal(newDN) {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultEntryAlreadyExists, ""),
		)
	}
	if oldDN.Equal(superior) || oldDN.AncestorOf(superior) {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultLoopDetect, ""),
		)
	}

	var (
		nextRuntime      *runtimeState
		responseControls []ldapwire.Control
	)
	err = server.config.Store.Update(ctx, func(writer storage.Writer) error {
		tx := storage.WriterInPartition(writer, database.partition)
		sourceEntry, err := server.entryOrReferral(
			state.runtime,
			tx,
			state.boundDN,
			oldDN,
			controls.manageDsaIT,
		)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return operationFailed(
				ldapwire.ResultNoSuchObject,
				server.disclosedAncestor(state.runtime, tx, state.boundDN, oldDN),
			)
		}
		if err != nil {
			return err
		}
		if err := server.checkAssertion(
			state.runtime,
			tx,
			state.boundDN,
			sourceEntry,
			controls.assertion,
		); err != nil {
			return err
		}
		newParent := directory.Entry{DN: superior.String()}
		if superior.Depth() > 0 {
			newParent, err = tx.Get(superior)
			if errors.Is(err, storage.ErrEntryNotFound) {
				return operationFailed(
					ldapwire.ResultNoSuchObject,
					server.disclosedAncestor(state.runtime, tx, state.boundDN, superior),
				)
			}
			if err != nil {
				return err
			}
			if state.runtime.schema.EntryHasObjectClass(
				newParent,
				"referral",
			) {
				return operationFailed(
					ldapwire.ResultAffectsMultipleDSAs,
					"new superior is a referral",
				)
			}
		}
		oldParent, err := parentEntry(tx, oldDN)
		if err != nil {
			return err
		}
		newRDNAttributes := make([]directory.Attribute, 0, len(newDN.RDNValues()))
		for _, value := range newDN.RDNValues() {
			newRDNAttributes = append(newRDNAttributes, directory.Attribute{
				Description: value.Type,
				Values:      [][]byte{value.Value},
			})
		}
		oldRDNAttributes := make([]directory.Attribute, 0, len(oldDN.RDNValues()))
		for _, value := range oldDN.RDNValues() {
			oldRDNAttributes = append(oldRDNAttributes, directory.Attribute{
				Description: value.Type,
				Values:      [][]byte{value.Value},
			})
		}
		if !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			sourceEntry,
			"entry",
			nil,
			acl.Write,
		) || !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			oldParent,
			"children",
			nil,
			acl.WriteDelete,
		) || !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			newParent,
			"children",
			nil,
			acl.WriteAdd,
		) {
			return operationFailed(ldapwire.ResultInsufficientAccessRights, "")
		}
		for _, attribute := range newRDNAttributes {
			if !server.canAccessAttribute(
				state.runtime,
				tx,
				state.boundDN,
				sourceEntry,
				attribute,
				acl.WriteAdd,
			) {
				return operationFailed(ldapwire.ResultInsufficientAccessRights, "")
			}
		}
		if request.DeleteOldRDN {
			for _, attribute := range oldRDNAttributes {
				if !server.canAccessAttribute(
					state.runtime,
					tx,
					state.boundDN,
					sourceEntry,
					attribute,
					acl.WriteDelete,
				) {
					return operationFailed(ldapwire.ResultInsufficientAccessRights, "")
				}
			}
		}
		preRead, err := server.readResponseControl(
			state.runtime,
			tx,
			state.boundDN,
			sourceEntry,
			controls.preRead,
			preReadControlOID,
		)
		if err != nil {
			return err
		}
		if preRead != nil {
			responseControls = append(responseControls, *preRead)
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
			if !oldDN.Equal(candidate) && !oldDN.AncestorOf(candidate) {
				return nil
			}
			replaced, err := candidate.ReplaceAncestor(oldDN, newDN)
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

		sort.Slice(moves, func(i, j int) bool {
			return moves[i].oldDN.Depth() > moves[j].oldDN.Depth()
		})
		for _, item := range moves {
			if err := tx.Delete(item.oldDN); err != nil {
				return err
			}
		}
		for i := range moves {
			item := &moves[i]
			item.entry.DN = item.newDN.String()
			if item.oldDN.Equal(oldDN) {
				if request.DeleteOldRDN {
					item.entry.DeleteRDNValues(oldDN)
				}
				item.entry.EnsureRDNValues(newDN)
				if lastModEnabled(state.runtime, oldDN) {
					server.applyModifyOperationalAttributes(&item.entry, state.boundDN)
				}
				if !configurationWrite {
					if err := state.runtime.schema.ValidateEntry(item.entry); err != nil {
						return operationFailureFromSchema(err)
					}
					if err := server.applySchemaOperationalAttributes(
						state.runtime,
						&item.entry,
					); err != nil {
						return err
					}
				}
			}
			if err := tx.Put(item.entry, false); err != nil {
				return err
			}
			if item.oldDN.Equal(oldDN) {
				postRead, err := server.readResponseControl(
					state.runtime,
					tx,
					state.boundDN,
					item.entry,
					controls.postRead,
					postReadControlOID,
				)
				if err != nil {
					return err
				}
				if postRead != nil {
					responseControls = append(responseControls, *postRead)
				}
			}
		}
		if err := refreshNamingContexts(writer); err != nil {
			return err
		}
		if configurationWrite {
			var err error
			nextRuntime, err = server.validateRuntimeConfiguration(writer)
			return err
		}
		return nil
	})
	if err == nil && nextRuntime != nil {
		server.runtime.Store(nextRuntime)
	}
	return server.finishOperationWithControls(
		connection,
		message.ID,
		ldapwire.ApplicationModifyDNResponse,
		err,
		responseControls,
	)
}

func (server *Server) handleCompare(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.CompareRequest,
) error {
	controls, controlFailure := parseRequestControls(
		message.Controls,
		supportsAssertion|supportsManageDsaIT,
	)
	if controlFailure != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationCompareResponse,
			*controlFailure,
		)
	}
	dn, err := directory.ParseDN(request.DN)
	if err != nil || dn.Depth() == 0 {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationCompareResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
		)
	}
	var database *runtimeDatabase
	if !isSubschemaDN(dn) {
		database = databaseForDN(state.runtime, dn)
		if database == nil {
			return server.writeOperationResult(
				connection,
				message.ID,
				ldapwire.ApplicationCompareResponse,
				ldapwire.Result{Code: ldapwire.ResultReferral},
			)
		}
	}

	result := ldapwire.Result{Code: ldapwire.ResultCompareFalse}
	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := reader
		if database != nil {
			tx = storage.ReaderInPartition(reader, database.partition)
		}
		var entry directory.Entry
		if isSubschemaDN(dn) {
			entry = server.subschemaEntry(state.runtime)
		} else {
			var getErr error
			entry, getErr = server.entryOrReferral(
				state.runtime,
				tx,
				state.boundDN,
				dn,
				controls.manageDsaIT,
			)
			if errors.Is(getErr, storage.ErrEntryNotFound) {
				return operationFailed(
					ldapwire.ResultNoSuchObject,
					server.disclosedAncestor(state.runtime, tx, state.boundDN, dn),
				)
			}
			if getErr != nil {
				return getErr
			}
			entry = withSubschemaReference(entry)
		}
		if err := server.checkAssertion(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			controls.assertion,
		); err != nil {
			return err
		}
		if !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			entry,
			request.Attribute,
			request.Assertion,
			acl.Compare,
		) {
			return operationFailed(ldapwire.ResultInsufficientAccessRights, "")
		}
		if !entry.HasAttribute(request.Attribute) {
			return operationFailed(ldapwire.ResultNoSuchAttribute, "")
		}
		for _, value := range entry.Values(request.Attribute) {
			comparison, compareErr := state.runtime.schema.Compare(
				request.Attribute,
				"",
				value,
				request.Assertion,
			)
			if compareErr != nil {
				return operationFailed(ldapwire.ResultInappropriateMatching, compareErr.Error())
			}
			if comparison == 0 {
				result.Code = ldapwire.ResultCompareTrue
				break
			}
		}
		return nil
	})
	if failure := asOperationFailure(err); failure != nil {
		result = failure.result
	} else if err != nil {
		return server.internalOperationError(connection, message.ID, ldapwire.ApplicationCompareResponse, err)
	}
	return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationCompareResponse, result)
}

func validateNewEntry(entry directory.Entry, dn directory.DN) *ldapwire.Result {
	if len(entry.Attributes) == 0 || !entry.HasAttribute("objectClass") {
		result := ldapwire.ResultError(ldapwire.ResultObjectClassViolation, "objectClass is required")
		return &result
	}
	attributeNames := make(map[string]struct{}, len(entry.Attributes))
	for _, attribute := range entry.Attributes {
		name := strings.ToLower(attribute.Description)
		if _, exists := attributeNames[name]; exists {
			result := ldapwire.ResultError(ldapwire.ResultAttributeOrValueExists, "")
			return &result
		}
		attributeNames[name] = struct{}{}
		if len(attribute.Values) == 0 {
			result := ldapwire.ResultError(ldapwire.ResultConstraintViolation, "attribute requires at least one value")
			return &result
		}
		for i, value := range attribute.Values {
			for j := 0; j < i; j++ {
				if directory.EqualValue(attribute.Values[j], value) {
					result := ldapwire.ResultError(ldapwire.ResultAttributeOrValueExists, "")
					return &result
				}
			}
		}
	}
	for _, rdnValue := range dn.RDNValues() {
		if !entry.HasValue(rdnValue.Type, rdnValue.Value) {
			result := ldapwire.ResultError(ldapwire.ResultNamingViolation, "RDN value is missing from entry")
			return &result
		}
	}
	return nil
}

func applyModification(entry *directory.Entry, change ldapwire.Modification) error {
	var err error
	switch change.Operation {
	case ldapwire.ModificationAdd:
		err = entry.AddValues(change.Attribute.Description, change.Attribute.Values)
	case ldapwire.ModificationDelete:
		err = entry.DeleteValues(change.Attribute.Description, change.Attribute.Values)
	case ldapwire.ModificationReplace:
		entry.ReplaceValues(change.Attribute.Description, change.Attribute.Values)
	case ldapwire.ModificationIncrement:
		if len(change.Attribute.Values) != 1 {
			return operationFailed(ldapwire.ResultConstraintViolation, "increment requires one value")
		}
		err = entry.Increment(change.Attribute.Description, change.Attribute.Values[0])
	default:
		return operationFailed(ldapwire.ResultProtocolError, "unknown modify operation")
	}
	switch {
	case errors.Is(err, directory.ErrNoSuchAttribute):
		return operationFailed(ldapwire.ResultNoSuchAttribute, "")
	case errors.Is(err, directory.ErrAttributeValueExists):
		return operationFailed(ldapwire.ResultAttributeOrValueExists, "")
	case errors.Is(err, directory.ErrInvalidIncrementValue):
		return operationFailed(ldapwire.ResultConstraintViolation, "")
	default:
		return err
	}
}

func schemaValidationResult(err error) ldapwire.Result {
	var violation *schema.Violation
	if !errors.As(err, &violation) {
		return ldapwire.ResultError(ldapwire.ResultOther, err.Error())
	}
	switch violation.Kind {
	case schema.ViolationUndefinedAttribute:
		return ldapwire.ResultError(ldapwire.ResultUndefinedAttributeType, violation.Error())
	case schema.ViolationSyntax:
		return ldapwire.ResultError(ldapwire.ResultInvalidAttributeSyntax, violation.Error())
	case schema.ViolationSingleValue:
		return ldapwire.ResultError(ldapwire.ResultConstraintViolation, violation.Error())
	default:
		return ldapwire.ResultError(ldapwire.ResultObjectClassViolation, violation.Error())
	}
}

func operationFailureFromSchema(err error) error {
	result := schemaValidationResult(err)
	return &operationFailure{result: result}
}

func (server *Server) applyCreateOperationalAttributes(
	entry *directory.Entry,
	actor string,
	lastMod bool,
) error {
	for _, description := range protectedOperationalAttributes {
		entry.ReplaceValues(description, nil)
	}
	if !lastMod {
		return nil
	}
	uuid, err := randomUUID()
	if err != nil {
		return err
	}
	timestamp := time.Now().UTC().Format("20060102150405Z")
	entry.ReplaceValues("entryUUID", [][]byte{[]byte(uuid)})
	entry.ReplaceValues("entryCSN", [][]byte{[]byte(server.nextCSN())})
	entry.ReplaceValues("createTimestamp", [][]byte{[]byte(timestamp)})
	entry.ReplaceValues("modifyTimestamp", [][]byte{[]byte(timestamp)})
	entry.ReplaceValues("creatorsName", [][]byte{[]byte(actor)})
	entry.ReplaceValues("modifiersName", [][]byte{[]byte(actor)})
	return nil
}

func (server *Server) applyModifyOperationalAttributes(entry *directory.Entry, actor string) {
	timestamp := time.Now().UTC().Format("20060102150405Z")
	entry.ReplaceValues("entryCSN", [][]byte{[]byte(server.nextCSN())})
	entry.ReplaceValues("modifyTimestamp", [][]byte{[]byte(timestamp)})
	entry.ReplaceValues("modifiersName", [][]byte{[]byte(actor)})
}

func (server *Server) applySchemaOperationalAttributes(
	runtime *runtimeState,
	entry *directory.Entry,
) error {
	structuralObjectClass, err := runtime.schema.StructuralObjectClass(*entry)
	if err != nil {
		return fmt.Errorf("resolve structural object class: %w", err)
	}
	entry.ReplaceValues("structuralObjectClass", stringValues(structuralObjectClass))
	entry.ReplaceValues("subschemaSubentry", stringValues("cn=Subschema"))
	return nil
}

func (server *Server) nextCSN() string {
	server.csnMu.Lock()
	defer server.csnMu.Unlock()

	now := time.Now().UTC().Truncate(time.Microsecond)
	if server.lastCSN.IsZero() || now.After(server.lastCSN) {
		server.lastCSN = now
		server.csnCounter = 0
	} else {
		server.csnCounter++
	}
	return fmt.Sprintf(
		"%s#%06x#000#000000",
		server.lastCSN.Format("20060102150405.000000Z"),
		server.csnCounter,
	)
}

func randomUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate entry UUID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		value[0:4],
		value[4:6],
		value[6:8],
		value[8:10],
		value[10:16],
	), nil
}

func isProtectedOperationalAttribute(description string) bool {
	_, protected := protectedOperationalAttributes[strings.ToLower(description)]
	return protected
}

func belowKnownNamingContext(reader storage.Reader, dn directory.DN) (bool, error) {
	contexts, err := reader.NamingContexts()
	if err != nil {
		return false, err
	}
	for _, rawContext := range contexts {
		contextDN, err := directory.ParseDN(rawContext)
		if err != nil {
			return false, err
		}
		if contextDN.Equal(dn) || contextDN.AncestorOf(dn) {
			return true, nil
		}
	}
	return false, nil
}

func refreshNamingContexts(writer storage.Writer) error {
	contexts, err := storage.InferNamingContexts(writer)
	if err != nil {
		return err
	}
	return writer.SetNamingContexts(contexts)
}

func (server *Server) finishOperation(
	connection net.Conn,
	messageID int64,
	responseTag uint64,
	err error,
) error {
	return server.finishOperationWithControls(
		connection,
		messageID,
		responseTag,
		err,
		nil,
	)
}

func (server *Server) finishOperationWithControls(
	connection net.Conn,
	messageID int64,
	responseTag uint64,
	err error,
	controls []ldapwire.Control,
) error {
	if failure := asOperationFailure(err); failure != nil {
		return server.writeOperationResult(connection, messageID, responseTag, failure.result)
	}
	if err != nil {
		return server.internalOperationError(connection, messageID, responseTag, err)
	}
	return server.writeOperationResultWithControls(
		connection,
		messageID,
		responseTag,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		controls,
	)
}

func (server *Server) internalOperationError(
	connection net.Conn,
	messageID int64,
	responseTag uint64,
	err error,
) error {
	server.config.Logger.Error("LDAP operation failed", "message_id", messageID, "error", err)
	return server.writeOperationResult(
		connection,
		messageID,
		responseTag,
		ldapwire.ResultError(ldapwire.ResultOperationsError, "internal operation error"),
	)
}

func (server *Server) writeOperationResult(
	connection net.Conn,
	messageID int64,
	responseTag uint64,
	result ldapwire.Result,
) error {
	return server.writeOperationResultWithControls(
		connection,
		messageID,
		responseTag,
		result,
		nil,
	)
}

func (server *Server) writeOperationResultWithControls(
	connection net.Conn,
	messageID int64,
	responseTag uint64,
	result ldapwire.Result,
	controls []ldapwire.Control,
) error {
	return ldapwire.Write(
		connection,
		ldapwire.EncodeResultResponse(messageID, responseTag, result, controls),
	)
}

type operationFailure struct {
	result ldapwire.Result
}

func (failure *operationFailure) Error() string {
	return fmt.Sprintf("LDAP operation failed with result %d", failure.result.Code)
}

func operationFailed(code ldapwire.ResultCode, diagnostic string) error {
	return &operationFailure{result: ldapwire.ResultError(code, diagnostic)}
}

func asOperationFailure(err error) *operationFailure {
	var failure *operationFailure
	if errors.As(err, &failure) {
		return failure
	}
	return nil
}
