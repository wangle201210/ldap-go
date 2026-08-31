package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

var protectedOperationalAttributes = map[string]string{
	"2.5.18.1":                      "createTimestamp",
	"2.5.18.2":                      "modifyTimestamp",
	"2.5.18.3":                      "creatorsName",
	"2.5.18.4":                      "modifiersName",
	"2.5.18.10":                     "subschemaSubentry",
	"2.5.18.12":                     "collectiveAttributeSubentries",
	"2.5.21.9":                      "structuralObjectClass",
	"2.5.21.10":                     "governingStructureRule",
	"1.3.6.1.1.16.4":                "entryUUID",
	"1.3.6.1.4.1.1466.101.119.3":    "entryTtl",
	"1.3.6.1.4.1.4203.666.1.7":      "entryCSN",
	"1.3.6.1.4.1.4203.666.1.25":     "contextCSN",
	"1.3.6.1.4.1.4203.666.1.57":     "entryExpireTimestamp",
	"1.3.6.1.4.1.42.2.27.8.1.16":    "pwdChangedTime",
	"1.3.6.1.4.1.42.2.27.8.1.19":    "pwdFailureTime",
	"1.3.6.1.4.1.42.2.27.8.1.20":    "pwdHistory",
	"1.3.6.1.4.1.42.2.27.8.1.21":    "pwdGraceUseTime",
	"1.3.6.1.4.1.42.2.27.8.1.29":    "pwdLastSuccess",
	"1.3.6.1.4.1.42.2.27.8.1.33":    "pwdAccountTmpLockoutEnd",
	"1.3.6.1.4.1.453.16.2.188":      "authTimestamp",
	"1.2.840.113556.1.2.102":        "memberOf",
	"authtimestamp":                 "authTimestamp",
	"createtimestamp":               "createTimestamp",
	"creatorsname":                  "creatorsName",
	"collectiveattributesubentries": "collectiveAttributeSubentries",
	"contextcsn":                    "contextCSN",
	"entrycsn":                      "entryCSN",
	"entryexpiretimestamp":          "entryExpireTimestamp",
	"entryttl":                      "entryTtl",
	"entryuuid":                     "entryUUID",
	"governingstructurerule":        "governingStructureRule",
	"modifiersname":                 "modifiersName",
	"memberof":                      "memberOf",
	"modifytimestamp":               "modifyTimestamp",
	"pwdaccounttmplockoutend":       "pwdAccountTmpLockoutEnd",
	"pwdchangedtime":                "pwdChangedTime",
	"pwdfailuretime":                "pwdFailureTime",
	"pwdgraceusetime":               "pwdGraceUseTime",
	"pwdhistory":                    "pwdHistory",
	"pwdlastsuccess":                "pwdLastSuccess",
	"structuralobjectclass":         "structuralObjectClass",
	"subschemasubentry":             "subschemaSubentry",
}

var manageableOperationalAttributes = map[string]struct{}{
	"1.3.6.1.4.1.42.2.27.8.1.16": {},
	"1.3.6.1.4.1.42.2.27.8.1.19": {},
	"1.3.6.1.4.1.42.2.27.8.1.20": {},
	"1.3.6.1.4.1.42.2.27.8.1.21": {},
	"1.3.6.1.4.1.42.2.27.8.1.29": {},
	"1.3.6.1.4.1.42.2.27.8.1.33": {},
	"1.3.6.1.4.1.453.16.2.188":   {},
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
		supportsAssertion|
			supportsPostRead|
			supportsManageDsaIT|
			supportsPasswordPolicy|
			supportsRelax|
			supportsLazyCommit|
			supportsNoOp,
	)
	if result != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationAddResponse, *result)
	}
	if state.passwordPolicyRestrictedDN != "" {
		return server.writePasswordPolicyRestriction(
			connection,
			message.ID,
			ldapwire.ApplicationAddResponse,
			controls.passwordPolicy,
		)
	}

	dn, err := parseCoreWriteDN(state.runtime, request.Entry.DN)
	if err != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationAddResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
		)
	}
	if len(request.Entry.Attributes) == 0 {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationAddResponse,
			ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"no attributes provided",
			),
		)
	}
	if dn.Depth() == 0 {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationAddResponse,
			ldapwire.ResultError(
				ldapwire.ResultEntryAlreadyExists,
				"root DSE already exists",
			),
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
	database := databaseForNormalizedDN(state.runtime, dn)
	if database == nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationAddResponse,
			globalReferralOrResult(
				state.runtime,
				&dn,
				referralScopeDefault,
				ldapwire.ResultError(
					ldapwire.ResultUnwillingToPerform,
					"no global superior knowledge",
				),
			),
		)
	}
	if handled, err := server.tryRetcodeOperation(
		ctx,
		connection,
		state,
		message,
		dn,
		retcodeOperationAdd,
		controls.manageDsaIT,
		&request.Entry,
	); handled {
		return err
	}
	if result := updateOperationPrecondition(state.runtime, state.boundDN, dn); result != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationAddResponse,
			*result,
		)
	}
	if result := databaseRestrictionResult(state.runtime, dn, restrictAdd); result != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationAddResponse,
			*result,
		)
	}
	if databaseUsesNullBackend(state.runtime, *database) {
		return server.writeNullOperationResult(
			ctx,
			connection,
			state,
			message.ID,
			ldapwire.ApplicationAddResponse,
			dn,
			controls,
			false,
			true,
		)
	}
	if handled, err := server.tryTranslucentAdd(
		ctx,
		connection,
		state,
		message,
		dn,
		controls,
	); handled {
		return err
	}
	configurationWrite := isConfigurationDN(dn)
	validationResult := validateNewEntry(request.Entry, dn)
	if !configurationWrite {
		validationResult = validateNewEntryWithSchema(
			request.Entry,
			dn,
			state.runtime.schema,
		)
	}
	if validationResult != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationAddResponse,
			*validationResult,
		)
	}
	if configurationWrite {
		server.configMu.Lock()
		defer server.configMu.Unlock()
	}

	entry := request.Entry.Clone()
	entry.DN = dn.String()
	writeRecord := accesslogWriteRecord{
		operation:       accesslogAdd,
		session:         state.connectionID,
		authorizationDN: state.boundDN,
		requestDN:       dn,
	}

	var (
		nextRuntime      *runtimeState
		responseControls []ldapwire.Control
		syncChanges      []*syncChange
	)
	err = server.updateStorage(ctx, func(writer storage.Writer) error {
		tx := writerForDatabase(writer, *database)
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
		if configurationWrite {
			if err := validateOpenLDAPModuleOnlineAdd(state.runtime, entry); err != nil {
				return err
			}
		}
		if err := server.applyCreateOperationalAttributesContext(
			ctx,
			&entry,
			state.boundDN,
			lastModEnabled(state.runtime, dn),
			state.runtime.serverID,
			state.runtime.schema,
		); err != nil {
			return err
		}
		if !configurationWrite {
			if err := prepareDDSAdd(
				state.runtime,
				*database,
				&entry,
				time.Now(),
			); err != nil {
				return err
			}
		}
		if !configurationWrite {
			if err := server.applyPasswordPolicyAdd(
				state.runtime,
				writer,
				tx,
				state.boundDN,
				*database,
				&entry,
				controls.passwordPolicy,
			); err != nil {
				return err
			}
		}
		if !configurationWrite {
			if err := prepareMemberOfAdd(
				state.runtime,
				tx,
				*database,
				dn,
				&entry,
				controls.relax,
			); err != nil {
				return err
			}
		}
		if !configurationWrite {
			if err := validateValueSortAdd(
				state.runtime,
				*database,
				entry,
			); err != nil {
				return err
			}
		}
		if !configurationWrite {
			if err := server.validateConstraintAdd(
				state.runtime,
				writer,
				state.boundDN,
				*database,
				entry,
				controls.relax,
			); err != nil {
				return err
			}
		}
		if !configurationWrite {
			if err := server.validateUniqueAdd(
				state.runtime,
				writer,
				state.boundDN,
				*database,
				entry,
				controls.relax,
			); err != nil {
				return err
			}
		}
		if !configurationWrite {
			if err := state.runtime.schema.ValidateEntry(entry); err != nil {
				return operationFailureFromSchema(err)
			}
			if err := server.applySchemaOperationalAttributes(
				state.runtime,
				&entry,
			); err != nil {
				return err
			}
		}
		collectivePlan, err := runtimeCollectiveAttributePlan(
			state.runtime,
			database.partition,
			tx,
		)
		if err != nil {
			return err
		}
		logicalEntry, err := collectivePlan.apply(entry)
		if err != nil {
			return err
		}
		for _, attribute := range request.Entry.Attributes {
			if isAuthTimestampAttribute(
				state.runtime.schema,
				attribute.Description,
			) && (!controls.relax || !server.allowed(
				state.runtime,
				tx,
				state.boundDN,
				logicalEntry,
				attribute.Description,
				nil,
				acl.Manage,
			)) {
				return operationFailed(
					ldapwire.ResultConstraintViolation,
					"operational attribute is not user modifiable",
				)
			}
		}
		if err := server.checkAssertion(
			state.runtime,
			tx,
			state.boundDN,
			logicalEntry,
			controls.assertion,
		); err != nil {
			return err
		}

		if parent, ok := dn.Parent(); ok && parent.Depth() > 0 {
			storedParent, err := tx.Get(parent)
			if err == nil {
				if state.runtime.schema.EntryHasObjectClass(
					storedParent,
					"subentry",
				) {
					return operationFailed(
						ldapwire.ResultObjectClassViolation,
						"parent is a subentry",
					)
				}
				if state.runtime.schema.EntryHasObjectClass(
					storedParent,
					"alias",
				) {
					return operationFailed(
						ldapwire.ResultAliasProblem,
						"parent is an alias",
					)
				}
			} else {
				if !errors.Is(err, storage.ErrEntryNotFound) {
					return err
				}
				ancestor, found, ancestorErr := closestExistingAncestor(
					tx,
					dn,
				)
				if ancestorErr != nil {
					return ancestorErr
				}
				if found && state.runtime.schema.EntryHasObjectClass(
					ancestor,
					"alias",
				) {
					return operationFailed(
						ldapwire.ResultAliasProblem,
						"parent is an alias",
					)
				}
				if !databaseOwnsSuffix(*database, dn) {
					belowContext, err := belowKnownNamingContext(tx, dn)
					if err != nil {
						return err
					}
					if belowContext {
						return operationFailedWithMatchedDN(
							ldapwire.ResultNoSuchObject,
							server.disclosedAncestor(state.runtime, tx, state.boundDN, dn),
							"",
						)
					}
				}
			}
		}
		parent := directory.Entry{DN: ""}
		var structureParent *directory.Entry
		if parentDN, ok := dn.Parent(); ok {
			parent.DN = parentDN.String()
			if storedParent, getErr := tx.Get(parentDN); getErr == nil {
				parent = storedParent
				structureParent = &parent
			} else if !errors.Is(getErr, storage.ErrEntryNotFound) {
				return getErr
			}
		}
		if !configurationWrite {
			if err := server.applyDITStructureRuleOperationalAttribute(
				state.runtime,
				&entry,
				structureParent,
				controls.relax,
			); err != nil {
				return operationFailureFromSchema(err)
			}
			logicalEntry, err = collectivePlan.apply(entry)
			if err != nil {
				return err
			}
		}
		logicalParent, err := collectivePlan.apply(parent)
		if err != nil {
			return err
		}
		if !configurationWrite {
			if err := server.validateDDSAddParent(
				state.runtime,
				tx,
				state.boundDN,
				*database,
				logicalEntry,
				logicalParent,
			); err != nil {
				return err
			}
			if err := enforceDDSDynamicObjectLimit(
				state.runtime,
				tx,
				*database,
				dn,
				entry,
			); err != nil {
				return err
			}
		}
		if !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			logicalParent,
			"children",
			nil,
			acl.WriteAdd,
		) || !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			logicalEntry,
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
					logicalEntry,
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
		if !configurationWrite {
			if err := applyMemberOfAdd(
				state.runtime,
				tx,
				*database,
				entry,
			); err != nil {
				return err
			}
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
		if controls.noOp {
			return noOperationFailure()
		}
		if err := refreshRuntimeNamingContexts(writer, state.runtime); err != nil {
			return err
		}
		if configurationWrite {
			var validationErr error
			nextRuntime, validationErr = server.validateRuntimeConfiguration(writer)
			if validationErr != nil {
				return validationErr
			}
		}
		sourceChange, changeErr := server.recordSyncChangeContext(
			ctx,
			writer,
			state.runtime,
			*database,
			nil,
			&entry,
		)
		if changeErr != nil {
			return changeErr
		}
		syncChanges = appendSyncChanges(syncChanges, sourceChange)
		writeRecord.after = &entry
		logChanges, logErr := server.recordAccesslogWrite(
			ctx,
			writer,
			state.runtime,
			*database,
			writeRecord,
			sourceChange,
		)
		if logErr != nil {
			return logErr
		}
		syncChanges = append(syncChanges, logChanges...)
		return nil
	})
	if err == nil {
		server.finishWriteEffects(ctx, nextRuntime, syncChanges...)
		server.finishAuditlogWrite(state, *database, writeRecord)
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
			supportsManageDsaIT|
			supportsPasswordPolicy|
			supportsRelax|
			supportsLazyCommit|
			supportsNoOp|
			supportsPermissiveModify,
	)
	if result != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyResponse, *result)
	}
	dn, err := parseCoreWriteDN(state.runtime, request.DN)
	if err != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
		)
	}
	for _, change := range request.Changes {
		if attributeDescriptionUsesTagRange(change.Attribute.Description) {
			return server.writeOperationResult(
				connection,
				message.ID,
				ldapwire.ApplicationModifyResponse,
				ldapwire.ResultError(
					ldapwire.ResultUndefinedAttributeType,
					fmt.Sprintf(
						"%s: inappropriate use of tag range option",
						change.Attribute.Description,
					),
				),
			)
		}
	}
	if dn.Depth() == 0 {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"modify upon the root DSE not supported",
			),
		)
	}
	frontendSeqmodRelease, err := acquireFrontendSeqmod(ctx, state.runtime, dn)
	if err != nil {
		return err
	}
	defer frontendSeqmodRelease()
	if isSubschemaDN(dn) {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			ldapwire.ResultError(ldapwire.ResultUnwillingToPerform, "subschema is read-only"),
		)
	}
	database := databaseForNormalizedDN(state.runtime, dn)
	if database == nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			globalReferralOrResult(
				state.runtime,
				&dn,
				referralScopeDefault,
				ldapwire.ResultError(
					ldapwire.ResultUnwillingToPerform,
					"no global superior knowledge",
				),
			),
		)
	}
	databaseSeqmodRelease, err := acquireDatabaseSeqmod(ctx, *database, dn)
	if err != nil {
		return err
	}
	defer databaseSeqmodRelease()
	request, nopsOnly, err := server.applyNopsModify(
		ctx,
		state.runtime,
		*database,
		dn,
		request,
	)
	if err != nil {
		return server.internalOperationError(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			err,
		)
	}
	if nopsOnly {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			ldapwire.Result{Code: ldapwire.ResultSuccess},
		)
	}
	message.Request = request
	if handled, err := server.tryRetcodeOperation(
		ctx,
		connection,
		state,
		message,
		dn,
		retcodeOperationModify,
		controls.manageDsaIT,
		nil,
	); handled {
		return err
	}
	if state.passwordPolicyRestrictedDN != "" &&
		(database.ppolicy == nil ||
			!database.ppolicy.disableWrite) &&
		!passwordPolicyModificationAllowedWhileRestricted(
			state.runtime,
			request.Changes,
		) {
		return server.writePasswordPolicyRestriction(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			controls.passwordPolicy,
		)
	}
	if isMonitorDatabase(*database) {
		if state.boundDN == "" && !state.runtime.allows.anonymousUpdates {
			return server.writeOperationResult(
				connection,
				message.ID,
				ldapwire.ApplicationModifyResponse,
				ldapwire.ResultError(
					ldapwire.ResultStrongerAuthRequired,
					"modifications require authentication",
				),
			)
		}
		if database.readOnly {
			return server.writeOperationResult(
				connection,
				message.ID,
				ldapwire.ApplicationModifyResponse,
				ldapwire.ResultError(
					ldapwire.ResultUnwillingToPerform,
					"operation restricted",
				),
			)
		}
		if databaseRestricts(*database, restrictModify) {
			return server.writeOperationResult(
				connection,
				message.ID,
				ldapwire.ApplicationModifyResponse,
				ldapwire.ResultError(
					ldapwire.ResultUnwillingToPerform,
					"operation restricted",
				),
			)
		}
		return server.modifyMonitorEntry(
			ctx,
			connection,
			state,
			message.ID,
			dn,
			request.Changes,
			controls,
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
	if result := databaseRestrictionResult(state.runtime, dn, restrictModify); result != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			*result,
		)
	}
	if databaseUsesNullBackend(state.runtime, *database) {
		return server.writeNullOperationResult(
			ctx,
			connection,
			state,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			dn,
			controls,
			true,
			true,
		)
	}
	if handled, err := server.tryTranslucentModify(
		ctx,
		connection,
		state,
		message,
		dn,
		controls,
	); handled {
		return err
	}
	policyOptions := passwordPolicyModificationOptions{
		requestControl: controls.passwordPolicy,
	}
	policyOptions.externalMatches, err = server.preverifyPasswordModification(
		ctx,
		state.runtime,
		state.boundDN,
		*database,
		dn,
		request.Changes,
		controls.assertion,
		policyOptions,
	)
	if err != nil {
		return server.finishOperation(
			connection,
			message.ID,
			ldapwire.ApplicationModifyResponse,
			err,
		)
	}
	var responseControls []ldapwire.Control
	writeRecord := &accesslogWriteRecord{
		operation:       accesslogModify,
		session:         state.connectionID,
		authorizationDN: state.boundDN,
		requestDN:       dn,
	}
	configurationWrite := isConfigurationDN(dn)
	if configurationWrite {
		server.configMu.Lock()
		defer server.configMu.Unlock()
	}
	nextRuntime, syncChanges, err := server.modifyEntry(
		ctx,
		state.runtime,
		state.boundDN,
		dn,
		*database,
		request.Changes,
		controls.manageDsaIT,
		controls.relax,
		controls.permissiveModify,
		controls.noOp,
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
		server.passwordPolicyModificationProcessor(
			state.runtime,
			state.boundDN,
			*database,
			policyOptions,
		),
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
		writeRecord,
	)
	if err == nil {
		server.finishWriteEffects(ctx, nextRuntime, syncChanges...)
		server.finishAuditlogWrite(state, *database, *writeRecord)
		if passwordPolicyModifiesPassword(
			state.runtime,
			request.Changes,
		) {
			state.passwordPolicyRestrictedDN = ""
		}
	}
	return server.finishOperationWithControls(
		connection,
		message.ID,
		ldapwire.ApplicationModifyResponse,
		err,
		responseControls,
	)
}

func attributeDescriptionUsesTagRange(description string) bool {
	parts := strings.Split(description, ";")
	for _, option := range parts[1:] {
		if strings.HasSuffix(option, "-") || strings.Contains(option, "=") {
			return true
		}
	}
	return false
}

type entryModificationPrecondition func(
	reader storage.Reader,
	entry directory.Entry,
) error

type entryModificationPostcondition func(
	reader storage.Reader,
	entry directory.Entry,
) error

type entryModificationMutation func(entry *directory.Entry) error

type entryModificationProcessor func(
	reader storage.Reader,
	entry directory.Entry,
	changes []ldapwire.Modification,
) ([]ldapwire.Modification, entryModificationMutation, error)

func (server *Server) modifyEntry(
	ctx context.Context,
	runtime *runtimeState,
	boundDN string,
	dn directory.DN,
	database runtimeDatabase,
	changes []ldapwire.Modification,
	manageDsaIT bool,
	relax bool,
	permissiveModify bool,
	noOp bool,
	precondition entryModificationPrecondition,
	processor entryModificationProcessor,
	postcondition entryModificationPostcondition,
	accesslogRecord *accesslogWriteRecord,
) (*runtimeState, []*syncChange, error) {
	configurationWrite := isConfigurationDN(dn)
	var sqlModify *sqlBackendModifyContext
	if database.sqlBackend != nil {
		sqlModify = &sqlBackendModifyContext{dn: dn}
		ctx = withSQLBackendModify(ctx, sqlModify)
	}

	var (
		nextRuntime *runtimeState
		syncChanges []*syncChange
	)
	err := server.updateStorage(ctx, func(writer storage.Writer) error {
		tx := writerForDatabase(writer, database)
		entry, err := server.entryOrReferral(
			runtime,
			tx,
			boundDN,
			dn,
			manageDsaIT,
		)
		if errors.Is(err, storage.ErrEntryNotFound) {
			referral, referralErr := globalReferralForMissingTarget(
				runtime,
				tx,
				dn,
				referralScopeDefault,
			)
			if referralErr != nil {
				return referralErr
			}
			if referral != nil {
				return &operationFailure{result: *referral}
			}
			return operationFailedWithMatchedDN(
				ldapwire.ResultNoSuchObject,
				server.disclosedAncestor(runtime, tx, boundDN, dn),
				"",
			)
		}
		if err != nil {
			return err
		}
		if !configurationWrite {
			if err := validateCollectModify(runtime, database, dn, changes); err != nil {
				return err
			}
		}
		before := entry.Clone()
		collectivePlan, err := runtimeCollectiveAttributePlan(
			runtime,
			database.partition,
			tx,
		)
		if err != nil {
			return err
		}
		logicalEntry, err := collectivePlan.apply(entry)
		if err != nil {
			return err
		}
		if precondition != nil {
			if err := precondition(tx, logicalEntry); err != nil {
				return err
			}
		}

		processedChanges := changes
		var mutation entryModificationMutation
		if processor != nil {
			processedChanges, mutation, err = processor(
				tx,
				entry,
				changes,
			)
			if err != nil {
				return err
			}
		}
		if !configurationWrite {
			processedChanges, err = prepareMemberOfModify(
				runtime,
				tx,
				database,
				dn,
				before,
				processedChanges,
				relax,
			)
			if err != nil {
				return err
			}
		}
		if !configurationWrite {
			if err := validateValueSortModify(
				runtime,
				database,
				dn,
				processedChanges,
			); err != nil {
				return err
			}
		}
		if !server.canApplyModifications(
			runtime,
			tx,
			boundDN,
			logicalEntry,
			processedChanges,
		) {
			return operationFailed(ldapwire.ResultInsufficientAccessRights, "")
		}
		if configurationWrite {
			if err := validateGentleHUPOnlineChanges(
				entry,
				processedChanges,
			); err != nil {
				return err
			}
			if err := validateIncomingLimitOnlineChanges(
				entry,
				processedChanges,
			); err != nil {
				return err
			}
			if err := validateConnectionTimeoutOnlineChanges(
				entry,
				processedChanges,
			); err != nil {
				return err
			}
			if err := validateDefaultReferralOnlineChanges(
				entry,
				processedChanges,
			); err != nil {
				return err
			}
			if err := validateDefaultSearchBaseOnlineChanges(processedChanges); err != nil {
				return err
			}
			if err := validateOpenLDAPModuleOnlineModification(
				runtime,
				entry,
				processedChanges,
			); err != nil {
				return err
			}
		}
		for _, change := range processedChanges {
			if runtime.schema.IsCollective(change.Attribute.Description) &&
				!runtime.schema.EntryHasObjectClass(
					entry,
					"collectiveAttributeSubentry",
				) {
				return operationFailed(
					ldapwire.ResultObjectClassViolation,
					"collective attributes are modified through a collectiveAttributeSubentry",
				)
			}
			if isProtectedOperationalAttribute(
				runtime.schema,
				change.Attribute.Description,
			) && (!relax || !isManageableOperationalAttribute(
				runtime.schema,
				change.Attribute.Description,
			) || !server.allowed(
				runtime,
				tx,
				boundDN,
				logicalEntry,
				change.Attribute.Description,
				nil,
				acl.Manage,
			)) {
				return operationFailed(ldapwire.ResultConstraintViolation, "operational attribute is not user modifiable")
			}
			if sqlModify != nil &&
				change.Operation == ldapwire.ModificationIncrement &&
				!database.sqlBackend.failIfNoMapping {
				sqlModify.changes = append(
					sqlModify.changes,
					cloneLDAPModifications([]ldapwire.Modification{change})[0],
				)
				continue
			}
			beforeChange := entry.Clone()
			if failure := applyModificationWithPermissive(
				&entry,
				change,
				permissiveModify,
			); failure != nil {
				return failure
			}
			if sqlModify != nil {
				if effective, present := effectiveSQLModification(
					beforeChange,
					entry,
					change,
				); present {
					sqlModify.changes = append(sqlModify.changes, effective)
				}
			}
		}
		var sqlProcessedEntry directory.Entry
		if sqlModify != nil {
			sqlProcessedEntry = entry.Clone()
		}
		if mutation != nil {
			if err := mutation(&entry); err != nil {
				return err
			}
		}
		rdnRegistry := runtime.schema
		if configurationWrite {
			rdnRegistry = nil
		}
		if !entryHasSchemaRDNValues(entry, dn, rdnRegistry) {
			return operationFailed(ldapwire.ResultNotAllowedOnRDN, "")
		}
		if !configurationWrite {
			if err := server.validateConstraintModify(
				runtime,
				writer,
				boundDN,
				database,
				before,
				entry,
				processedChanges,
				relax,
			); err != nil {
				return err
			}
		}
		if !configurationWrite {
			if err := server.validateUniqueModify(
				runtime,
				writer,
				boundDN,
				database,
				before,
				processedChanges,
				relax,
			); err != nil {
				return err
			}
		}
		if !configurationWrite {
			if err := validateDDSModification(
				runtime,
				database,
				before,
				entry,
			); err != nil {
				return err
			}
		}
		if lastModEnabled(runtime, dn) {
			server.applyModifyOperationalAttributesContext(
				ctx,
				&entry,
				boundDN,
				runtime.serverID,
			)
		}
		if !configurationWrite {
			if err := runtime.schema.ValidateEntry(entry); err != nil {
				return operationFailureFromSchema(err)
			}
			parent, err := schemaParentEntry(tx, dn)
			if err != nil {
				return err
			}
			if err := server.applyDITStructureRuleOperationalAttribute(
				runtime,
				&entry,
				parent,
				relax,
			); err != nil {
				return operationFailureFromSchema(err)
			}
			if err := server.applySchemaOperationalAttributes(runtime, &entry); err != nil {
				return err
			}
		}
		if sqlModify != nil {
			sqlModify.changes = append(
				sqlModify.changes,
				syntheticSQLModifications(sqlProcessedEntry, entry)...,
			)
		}
		if err := tx.Put(entry, true); err != nil {
			return fmt.Errorf("store modified entry %q: %w", entry.DN, err)
		}
		if !configurationWrite {
			if err := applyMemberOfModify(
				runtime,
				tx,
				database,
				before,
				entry,
			); err != nil {
				return err
			}
		}
		if postcondition != nil {
			if err := postcondition(tx, entry); err != nil {
				return err
			}
		}
		if noOp {
			return noOperationFailure()
		}
		if configurationWrite {
			var err error
			nextRuntime, err = server.validateRuntimeConfiguration(writer)
			if err != nil {
				return fmt.Errorf("reload runtime after modifying %q: %w", entry.DN, err)
			}
			applyMetaBackendOnlineURIModification(nextRuntime, dn, processedChanges)
		}
		sourceChange, changeErr := server.recordSyncChangeContext(
			ctx,
			writer,
			runtime,
			database,
			&before,
			&entry,
		)
		if changeErr != nil {
			return changeErr
		}
		syncChanges = appendSyncChanges(syncChanges, sourceChange)
		if accesslogRecord == nil {
			return nil
		}
		record := *accesslogRecord
		record.before = &before
		record.after = &entry
		record.modifications = processedChanges
		logChanges, logErr := server.recordAccesslogWrite(
			ctx,
			writer,
			runtime,
			database,
			record,
			sourceChange,
		)
		if logErr != nil {
			return logErr
		}
		*accesslogRecord = record
		syncChanges = append(syncChanges, logChanges...)
		return nil
	})
	return nextRuntime, syncChanges, err
}

func effectiveSQLModification(
	before,
	after directory.Entry,
	change ldapwire.Modification,
) (ldapwire.Modification, bool) {
	effective := cloneLDAPModifications([]ldapwire.Modification{change})[0]
	switch change.Operation {
	case ldapwire.ModificationAdd:
		effective.Attribute.Values = nil
		for _, value := range change.Attribute.Values {
			if !before.HasValue(change.Attribute.Description, value) &&
				after.HasValue(change.Attribute.Description, value) {
				effective.Attribute.Values = append(
					effective.Attribute.Values,
					append([]byte(nil), value...),
				)
			}
		}
		return effective, len(effective.Attribute.Values) != 0
	case ldapwire.ModificationDelete:
		if len(change.Attribute.Values) == 0 {
			return effective, before.HasAttribute(change.Attribute.Description) &&
				!after.HasAttribute(change.Attribute.Description)
		}
		effective.Attribute.Values = nil
		for _, value := range change.Attribute.Values {
			if before.HasValue(change.Attribute.Description, value) &&
				!after.HasValue(change.Attribute.Description, value) {
				effective.Attribute.Values = append(
					effective.Attribute.Values,
					append([]byte(nil), value...),
				)
			}
		}
		return effective, len(effective.Attribute.Values) != 0
	case ldapwire.ModificationReplace, ldapwire.ModificationIncrement:
		return effective, true
	default:
		return ldapwire.Modification{}, false
	}
}

func syntheticSQLModifications(
	before,
	after directory.Entry,
) []ldapwire.Modification {
	names := make(map[string]string)
	for _, attribute := range before.Attributes {
		base := strings.Split(attribute.Description, ";")[0]
		names[strings.ToLower(base)] = attribute.Description
	}
	for _, attribute := range after.Attributes {
		base := strings.Split(attribute.Description, ";")[0]
		names[strings.ToLower(base)] = attribute.Description
	}
	keys := make([]string, 0, len(names))
	for name := range names {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	changes := make([]ldapwire.Modification, 0, len(keys))
	for _, name := range keys {
		description := names[name]
		beforeValues := before.Values(description)
		afterValues := after.Values(description)
		if sqlValuesEqual(beforeValues, afterValues) {
			continue
		}
		changes = append(changes, ldapwire.Modification{
			Operation: ldapwire.ModificationReplace,
			Attribute: directory.Attribute{
				Description: description,
				Values:      afterValues,
			},
		})
	}
	return changes
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
		supportsAssertion|
			supportsPreRead|
			supportsManageDsaIT|
			supportsRelax|
			supportsLazyCommit|
			supportsNoOp|
			supportsTreeDelete,
	)
	if result != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationDeleteResponse, *result)
	}
	if state.passwordPolicyRestrictedDN != "" {
		return server.writePasswordPolicyRestriction(
			connection,
			message.ID,
			ldapwire.ApplicationDeleteResponse,
			false,
		)
	}
	dn, err := parseCoreWriteDN(state.runtime, request.DN)
	if err != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationDeleteResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
		)
	}
	if dn.Depth() == 0 {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationDeleteResponse,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"cannot delete the root DSE",
			),
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
	database := databaseForNormalizedDN(state.runtime, dn)
	if database == nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationDeleteResponse,
			globalReferralOrResult(
				state.runtime,
				&dn,
				referralScopeDefault,
				ldapwire.ResultError(
					ldapwire.ResultUnwillingToPerform,
					"no global superior knowledge",
				),
			),
		)
	}
	if controls.treeDelete != nil && database.sqlBackend == nil {
		if controls.treeDelete.critical {
			return server.writeOperationResult(
				connection,
				message.ID,
				ldapwire.ApplicationDeleteResponse,
				ldapwire.ResultError(
					ldapwire.ResultUnavailableCriticalExtension,
					"critical extension is unavailable",
				),
			)
		}
		controls.treeDelete = nil
	}
	if controls.treeDelete != nil {
		ctx = withSQLBackendTreeDelete(ctx)
	}
	if handled, err := server.tryRetcodeOperation(
		ctx,
		connection,
		state,
		message,
		dn,
		retcodeOperationDelete,
		controls.manageDsaIT,
		nil,
	); handled {
		return err
	}
	if result := updateOperationPrecondition(state.runtime, state.boundDN, dn); result != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationDeleteResponse,
			*result,
		)
	}
	if result := databaseRestrictionResult(state.runtime, dn, restrictDelete); result != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationDeleteResponse,
			*result,
		)
	}
	if databaseUsesNullBackend(state.runtime, *database) {
		return server.writeNullOperationResult(
			ctx,
			connection,
			state,
			message.ID,
			ldapwire.ApplicationDeleteResponse,
			dn,
			controls,
			true,
			false,
		)
	}
	if handled, err := server.tryTranslucentDelete(
		ctx,
		connection,
		state,
		message,
		dn,
		controls,
	); handled {
		return err
	}
	configurationWrite := isConfigurationDN(dn)
	if configurationWrite {
		server.configMu.Lock()
		defer server.configMu.Unlock()
	}

	var (
		nextRuntime      *runtimeState
		responseControls []ldapwire.Control
		syncChanges      []*syncChange
	)
	writeRecord := accesslogWriteRecord{
		operation:       accesslogDelete,
		session:         state.connectionID,
		authorizationDN: state.boundDN,
		requestDN:       dn,
	}
	err = server.updateStorage(ctx, func(writer storage.Writer) error {
		tx := writerForDatabase(writer, *database)
		entry, err := server.entryOrReferral(
			state.runtime,
			tx,
			state.boundDN,
			dn,
			controls.manageDsaIT,
		)
		if errors.Is(err, storage.ErrEntryNotFound) {
			referral, referralErr := globalReferralForMissingTarget(
				state.runtime,
				tx,
				dn,
				referralScopeDefault,
			)
			if referralErr != nil {
				return referralErr
			}
			if referral != nil {
				return &operationFailure{result: *referral}
			}
			return operationFailedWithMatchedDN(
				ldapwire.ResultNoSuchObject,
				server.disclosedAncestor(state.runtime, tx, state.boundDN, dn),
				"",
			)
		}
		if err != nil {
			return err
		}
		collectivePlan, err := runtimeCollectiveAttributePlan(
			state.runtime,
			database.partition,
			tx,
		)
		if err != nil {
			return err
		}
		logicalEntry, err := collectivePlan.apply(entry)
		if err != nil {
			return err
		}
		if err := server.checkAssertion(
			state.runtime,
			tx,
			state.boundDN,
			logicalEntry,
			controls.assertion,
		); err != nil {
			return err
		}

		parent, err := parentEntry(tx, dn)
		if err != nil {
			return err
		}
		logicalParent, err := collectivePlan.apply(parent)
		if err != nil {
			return err
		}
		if !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			logicalParent,
			"children",
			nil,
			acl.WriteDelete,
		) || !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			logicalEntry,
			"entry",
			nil,
			acl.WriteDelete,
		) {
			return operationFailed(ldapwire.ResultInsufficientAccessRights, "")
		}
		if configurationWrite && isConfiguredMetaBackendTarget(state.runtime, entry, dn) {
			return operationFailed(
				ldapwire.ResultUnwillingToPerform,
				"online back-meta target deletion is not supported",
			)
		}
		if configurationWrite &&
			state.runtime.schema.EntryHasObjectClass(entry, "olcModuleList") {
			return operationFailed(
				ldapwire.ResultUnwillingToPerform,
				"online module deletion is not supported",
			)
		}
		preRead, err := server.readResponseControl(
			state.runtime,
			tx,
			state.boundDN,
			logicalEntry,
			controls.preRead,
			preReadControlOID,
		)
		if err != nil {
			return err
		}
		if preRead != nil {
			responseControls = append(responseControls, *preRead)
		}

		entriesToDelete := []directory.Entry{entry}
		if controls.treeDelete != nil {
			entriesToDelete, err = server.prepareSQLTreeDelete(
				state.runtime,
				tx,
				state.boundDN,
				dn,
				collectivePlan,
			)
			if err != nil {
				return err
			}
		}

		var hasChildren bool
		if controls.treeDelete == nil {
			if database.sqlBackend != nil {
				hasChildren, err = storageSQLBackendHasChildren(tx, dn)
				if err != nil {
					return err
				}
			} else {
				comparisonDN, err := storage.NormalizeReaderDN(tx, dn)
				if err != nil {
					return err
				}
				if err := tx.ForEach(func(entry directory.Entry) error {
					candidate, err := directory.ParseDN(entry.DN)
					if err != nil {
						return err
					}
					candidate, err = storage.NormalizeReaderDN(tx, candidate)
					if err != nil {
						return err
					}
					if comparisonDN.AncestorOf(candidate) {
						hasChildren = true
					}
					return nil
				}); err != nil {
					return err
				}
			}
		}
		if hasChildren {
			return operationFailed(
				ldapwire.ResultNotAllowedOnNonLeaf,
				"subordinate objects must be deleted first",
			)
		}
		if controls.treeDelete == nil {
			if err := tx.Delete(dn); err != nil {
				return err
			}
		} else {
			for _, deleteEntry := range entriesToDelete {
				deleteDN, parseErr := state.runtime.schema.NormalizeDN(deleteEntry.DN)
				if parseErr != nil {
					return parseErr
				}
				if err := tx.Delete(deleteDN); err != nil {
					return err
				}
			}
		}
		if !configurationWrite {
			if err := applyMemberOfDelete(
				state.runtime,
				tx,
				*database,
				entry,
			); err != nil {
				return err
			}
			if err := applyRefintDelete(
				state.runtime,
				tx,
				*database,
				dn,
			); err != nil {
				return err
			}
		}
		if controls.noOp {
			return noOperationFailure()
		}
		if err := refreshRuntimeNamingContexts(writer, state.runtime); err != nil {
			return err
		}
		if configurationWrite {
			var err error
			nextRuntime, err = server.validateRuntimeConfiguration(writer)
			if err != nil {
				return err
			}
		}
		sourceChange, changeErr := server.recordSyncChangeContext(
			ctx,
			writer,
			state.runtime,
			*database,
			&entry,
			nil,
		)
		if changeErr != nil {
			return changeErr
		}
		syncChanges = appendSyncChanges(syncChanges, sourceChange)
		before := entry.Clone()
		writeRecord.before = &before
		logChanges, logErr := server.recordAccesslogWrite(
			ctx,
			writer,
			state.runtime,
			*database,
			writeRecord,
			sourceChange,
		)
		if logErr != nil {
			return logErr
		}
		syncChanges = append(syncChanges, logChanges...)
		return nil
	})
	if err == nil {
		server.finishWriteEffects(ctx, nextRuntime, syncChanges...)
		server.finishAuditlogWrite(state, *database, writeRecord)
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
			supportsManageDsaIT|
			supportsRelax|
			supportsLazyCommit|
			supportsNoOp,
	)
	if result != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyDNResponse, *result)
	}
	oldDN, err := parseCoreWriteDN(state.runtime, request.DN)
	if err != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
		)
	}
	if oldDN.Depth() == 0 {
		if request.HasNewSuperior {
			if _, err := parseCoreWriteDN(state.runtime, request.NewSuperior); err != nil {
				return server.writeOperationResult(
					connection,
					message.ID,
					ldapwire.ApplicationModifyDNResponse,
					ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
				)
			}
		}
		newRDN, err := parseRuntimeDN(request.NewRDN, state.runtime.schema)
		if err != nil || newRDN.Depth() != 1 {
			return server.writeOperationResult(
				connection,
				message.ID,
				ldapwire.ApplicationModifyDNResponse,
				ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
			)
		}
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"cannot rename the root DSE",
			),
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

	database := databaseForNormalizedDN(state.runtime, oldDN)
	if database == nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			globalReferralOrResult(
				state.runtime,
				&oldDN,
				referralScopeDefault,
				ldapwire.ResultError(
					ldapwire.ResultUnwillingToPerform,
					"no global superior knowledge",
				),
			),
		)
	}

	var superior directory.DN
	if request.HasNewSuperior {
		superior, err = parseCoreWriteDN(state.runtime, request.NewSuperior)
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
	newRDN, err := parseRuntimeDN(request.NewRDN, database.dnNormalizer)
	if err != nil || newRDN.Depth() != 1 {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
		)
	}
	newDN, err := directory.ComposeLocalName(newRDN, superior)
	if err != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
		)
	}
	frontendSeqmodRelease, err := acquireFrontendSeqmod(ctx, state.runtime, oldDN)
	if err != nil {
		return err
	}
	defer frontendSeqmodRelease()
	destinationDatabase := databaseForNormalizedDN(state.runtime, newDN)
	databaseSeqmodRelease, err := acquireDatabaseSeqmod(ctx, *database, oldDN)
	if err != nil {
		return err
	}
	defer databaseSeqmodRelease()
	if handled, err := server.tryRetcodeOperation(
		ctx,
		connection,
		state,
		message,
		oldDN,
		retcodeOperationRename,
		controls.manageDsaIT,
		nil,
	); handled {
		return err
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
	if result := databaseRestrictionResult(state.runtime, oldDN, restrictRename); result != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			*result,
		)
	}
	if databaseUsesNullBackend(state.runtime, *database) {
		return server.writeNullOperationResult(
			ctx,
			connection,
			state,
			message.ID,
			ldapwire.ApplicationModifyDNResponse,
			oldDN,
			controls,
			true,
			true,
		)
	}
	if handled, err := server.tryTranslucentModifyDN(
		ctx,
		connection,
		state,
		message,
		oldDN,
		newDN,
		controls,
	); handled {
		return err
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
		syncChanges      []*syncChange
	)
	writeRecord := accesslogWriteRecord{
		operation:       accesslogModifyDN,
		session:         state.connectionID,
		authorizationDN: state.boundDN,
		requestDN:       oldDN,
		newRDN:          request.NewRDN,
		deleteOldRDN:    request.DeleteOldRDN,
	}
	if database.sqlBackend != nil {
		ctx = withSQLBackendRename(ctx, oldDN, newDN)
	}
	err = server.updateStorage(ctx, func(writer storage.Writer) error {
		tx := writerForDatabase(writer, *database)
		rdnRegistry := state.runtime.schema
		if configurationWrite {
			rdnRegistry = nil
		}
		comparisonOldDN, err := storage.NormalizeReaderDN(tx, oldDN)
		if err != nil {
			return err
		}
		comparisonNewDN, err := storage.NormalizeReaderDN(tx, newDN)
		if err != nil {
			return err
		}
		comparisonSuperior, err := storage.NormalizeReaderDN(tx, superior)
		if err != nil {
			return err
		}
		if comparisonOldDN.Equal(comparisonNewDN) {
			return operationFailed(ldapwire.ResultEntryAlreadyExists, "")
		}
		if comparisonOldDN.Equal(comparisonSuperior) ||
			comparisonOldDN.AncestorOf(comparisonSuperior) {
			return operationFailed(ldapwire.ResultLoopDetect, "")
		}
		sourceEntry, err := server.entryOrReferral(
			state.runtime,
			tx,
			state.boundDN,
			oldDN,
			controls.manageDsaIT,
		)
		if errors.Is(err, storage.ErrEntryNotFound) {
			referral, referralErr := globalReferralForMissingTarget(
				state.runtime,
				tx,
				oldDN,
				referralScopeDefault,
			)
			if referralErr != nil {
				return referralErr
			}
			if referral != nil {
				return &operationFailure{result: *referral}
			}
			return operationFailedWithMatchedDN(
				ldapwire.ResultNoSuchObject,
				server.disclosedAncestor(state.runtime, tx, state.boundDN, oldDN),
				"",
			)
		}
		if err != nil {
			return err
		}
		storedOldDN, err := directory.ParseDN(sourceEntry.DN)
		if err != nil {
			return err
		}
		storedOldDN, err = storage.NormalizeReaderDN(tx, storedOldDN)
		if err != nil {
			return err
		}
		if !storedOldDN.Equal(comparisonOldDN) {
			return errors.New("resolved source entry has a different DN identity")
		}
		sourceBefore := sourceEntry.Clone()
		collectivePlan, err := runtimeCollectiveAttributePlan(
			state.runtime,
			database.partition,
			tx,
		)
		if err != nil {
			return err
		}
		logicalSourceEntry, err := collectivePlan.apply(sourceEntry)
		if err != nil {
			return err
		}
		if err := server.checkAssertion(
			state.runtime,
			tx,
			state.boundDN,
			logicalSourceEntry,
			controls.assertion,
		); err != nil {
			return err
		}
		if database.sqlBackend != nil {
			hasChildren, err := storageSQLBackendHasChildren(tx, oldDN)
			if err != nil {
				return err
			}
			if hasChildren {
				return operationFailed(
					ldapwire.ResultNotAllowedOnNonLeaf,
					"subtree rename not supported",
				)
			}
		}
		newParent := directory.Entry{DN: superior.String()}
		if superior.Depth() > 0 {
			newParent, err = tx.Get(superior)
			if errors.Is(err, storage.ErrEntryNotFound) {
				return operationFailed(
					ldapwire.ResultNoSuchObject,
					"new superior not found",
				)
			}
			if err != nil {
				return err
			}
			if state.runtime.schema.EntryHasObjectClass(
				newParent,
				"alias",
			) {
				return operationFailed(
					ldapwire.ResultAliasProblem,
					"new superior is an alias",
				)
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
		logicalNewParent, err := collectivePlan.apply(newParent)
		if err != nil {
			return err
		}
		storedSuperior, err := directory.ParseDN(newParent.DN)
		if err != nil {
			return err
		}
		storedSuperior, err = storage.NormalizeReaderDN(tx, storedSuperior)
		if err != nil {
			return err
		}
		storedNewRDN, err := directory.ParseDN(request.NewRDN)
		if err != nil {
			return err
		}
		storedNewRDN, err = storage.NormalizeReaderDN(tx, storedNewRDN)
		if err != nil {
			return err
		}
		storedNewDN, err := directory.ComposeLocalName(
			storedNewRDN,
			storedSuperior,
		)
		if err != nil {
			return err
		}
		if !storedNewDN.Equal(comparisonNewDN) {
			return errors.New("resolved destination has a different DN identity")
		}
		if !configurationWrite {
			if err := server.validateDDSRename(
				state.runtime,
				tx,
				state.boundDN,
				*database,
				logicalSourceEntry,
				logicalNewParent,
				request.HasNewSuperior,
			); err != nil {
				return err
			}
		}
		oldParent, err := parentEntry(tx, oldDN)
		if err != nil {
			return err
		}
		logicalOldParent, err := collectivePlan.apply(oldParent)
		if err != nil {
			return err
		}
		newRDNAttributes := make([]directory.Attribute, 0, len(storedNewDN.RDNValues()))
		for _, value := range storedNewDN.RDNValues() {
			newRDNAttributes = append(newRDNAttributes, directory.Attribute{
				Description: value.Type,
				Values:      [][]byte{value.Value},
			})
		}
		oldRDNAttributes := make([]directory.Attribute, 0, len(storedOldDN.RDNValues()))
		for _, value := range storedOldDN.RDNValues() {
			oldRDNAttributes = append(oldRDNAttributes, directory.Attribute{
				Description: value.Type,
				Values:      [][]byte{value.Value},
			})
		}
		if !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			logicalSourceEntry,
			"entry",
			nil,
			acl.Write,
		) || !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			logicalOldParent,
			"children",
			nil,
			acl.WriteDelete,
		) || !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			logicalNewParent,
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
				logicalSourceEntry,
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
					logicalSourceEntry,
					attribute,
					acl.WriteDelete,
				) {
					return operationFailed(ldapwire.ResultInsufficientAccessRights, "")
				}
			}
		}
		if configurationWrite &&
			localDatabaseConfigurationWithoutEntryUUID(
				state.runtime,
				oldDN,
				sourceEntry,
			) {
			return operationFailed(
				ldapwire.ResultUnwillingToPerform,
				"cannot rename a local database configuration without entryUUID",
			)
		}
		preRead, err := server.readResponseControl(
			state.runtime,
			tx,
			state.boundDN,
			logicalSourceEntry,
			controls.preRead,
			preReadControlOID,
		)
		if err != nil {
			return err
		}
		if preRead != nil {
			responseControls = append(responseControls, *preRead)
		}
		if !configurationWrite {
			constraintEntry := sourceEntry.Clone()
			constraintEntry.DN = storedNewDN.String()
			constraintChanges := make([]ldapwire.Modification, 0,
				len(oldRDNAttributes)+len(newRDNAttributes))
			if request.DeleteOldRDN {
				deleteSchemaRDNValues(
					&constraintEntry,
					storedOldDN,
					rdnRegistry,
				)
				for _, attribute := range oldRDNAttributes {
					constraintChanges = append(
						constraintChanges,
						ldapwire.Modification{
							Operation: ldapwire.ModificationDelete,
							Attribute: attribute,
						},
					)
				}
			}
			ensureSchemaRDNValues(
				&constraintEntry,
				storedNewDN,
				rdnRegistry,
			)
			for _, attribute := range newRDNAttributes {
				constraintChanges = append(
					constraintChanges,
					ldapwire.Modification{
						Operation: ldapwire.ModificationAdd,
						Attribute: attribute,
					},
				)
			}
			if err := server.validateConstraintModify(
				state.runtime,
				writer,
				state.boundDN,
				*database,
				sourceBefore,
				constraintEntry,
				constraintChanges,
				controls.relax,
			); err != nil {
				return err
			}
			var uniqueNewSuperior *directory.DN
			if request.HasNewSuperior {
				uniqueNewSuperior = &superior
			}
			if err := server.validateUniqueModifyDN(
				state.runtime,
				writer,
				state.boundDN,
				*database,
				sourceBefore,
				uniqueNewSuperior,
				newRDNAttributes,
				controls.relax,
			); err != nil {
				return err
			}
		}

		type move struct {
			oldDN directory.DN
			newDN directory.DN
			entry directory.Entry
		}
		var moves []move
		oldKeys := make(map[string]struct{})
		if database.sqlBackend != nil {
			moves = append(moves, move{
				oldDN: comparisonOldDN,
				newDN: storedNewDN,
				entry: sourceEntry,
			})
			oldKeys[comparisonOldDN.Key()] = struct{}{}
		} else if err := tx.ForEach(func(entry directory.Entry) error {
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

		sort.Slice(moves, func(i, j int) bool {
			return moves[i].oldDN.Depth() > moves[j].oldDN.Depth()
		})
		for _, item := range moves {
			if err := tx.Delete(item.oldDN); err != nil {
				return err
			}
		}
		var renamedEntry *directory.Entry
		for i := range moves {
			item := &moves[i]
			item.entry.DN = item.newDN.String()
			if item.oldDN.Equal(comparisonOldDN) {
				if request.DeleteOldRDN {
					deleteSchemaRDNValues(
						&item.entry,
						storedOldDN,
						rdnRegistry,
					)
				}
				ensureSchemaRDNValues(
					&item.entry,
					storedNewDN,
					rdnRegistry,
				)
				if lastModEnabled(state.runtime, oldDN) {
					server.applyModifyOperationalAttributesContext(
						ctx,
						&item.entry,
						state.boundDN,
						state.runtime.serverID,
					)
				}
				if !configurationWrite {
					if err := state.runtime.schema.ValidateEntry(item.entry); err != nil {
						return operationFailureFromSchema(err)
					}
					var structureParent *directory.Entry
					if superior.Depth() > 0 {
						structureParent = &newParent
					}
					if err := server.applyDITStructureRuleOperationalAttribute(
						state.runtime,
						&item.entry,
						structureParent,
						controls.relax,
					); err != nil {
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
			if item.oldDN.Equal(comparisonOldDN) {
				renamed := item.entry.Clone()
				renamedEntry = &renamed
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
		if renamedEntry == nil {
			return errors.New("renamed entry is missing from move set")
		}
		if !configurationWrite {
			if err := applyMemberOfModifyDN(
				state.runtime,
				tx,
				*database,
				storedOldDN,
				storedNewDN,
				*renamedEntry,
			); err != nil {
				return err
			}
			if err := applyRefintModifyDN(
				state.runtime,
				tx,
				*database,
				storedOldDN,
				storedNewDN,
				len(moves) > 1,
			); err != nil {
				return err
			}
		}
		if controls.noOp {
			return noOperationFailure()
		}
		if err := refreshRuntimeNamingContexts(writer, state.runtime); err != nil {
			return err
		}
		if configurationWrite {
			var err error
			nextRuntime, err = server.validateRuntimeConfiguration(writer)
			if err != nil {
				return err
			}
		}
		sourceChange, changeErr := server.recordSyncChangeContext(
			ctx,
			writer,
			state.runtime,
			*database,
			&sourceBefore,
			renamedEntry,
		)
		if changeErr != nil {
			return changeErr
		}
		syncChanges = appendSyncChanges(syncChanges, sourceChange)
		var logSuperior *directory.DN
		if request.HasNewSuperior {
			value := superior
			logSuperior = &value
		}
		writeRecord.before = &sourceBefore
		writeRecord.after = renamedEntry
		writeRecord.newSuperior = logSuperior
		logChanges, logErr := server.recordAccesslogWrite(
			ctx,
			writer,
			state.runtime,
			*database,
			writeRecord,
			sourceChange,
		)
		if logErr != nil {
			return logErr
		}
		syncChanges = append(syncChanges, logChanges...)
		return nil
	})
	if err == nil {
		server.finishWriteEffects(ctx, nextRuntime, syncChanges...)
		server.finishAuditlogWrite(state, *database, writeRecord)
	}
	return server.finishOperationWithControls(
		connection,
		message.ID,
		ldapwire.ApplicationModifyDNResponse,
		err,
		responseControls,
	)
}

func localDatabaseConfigurationWithoutEntryUUID(
	runtime *runtimeState,
	dn directory.DN,
	entry directory.Entry,
) bool {
	for _, database := range runtime.databases {
		if database.configDNKey != dn.Key() ||
			!databaseUsesLocalContentStorage(database) {
			continue
		}
		values := entry.Values("entryUUID")
		return len(values) != 1 || strings.TrimSpace(string(values[0])) == ""
	}
	return false
}

func (server *Server) handleCompare(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.CompareRequest,
) error {
	if handled, err := server.tryPcachePrivateCompare(
		connection,
		state,
		message,
		request,
	); handled {
		return err
	}
	controls, controlFailure := parseRequestControlsWithDisallows(
		message.Controls,
		supportsAssertion|supportsManageDsaIT|supportsDontUseCopy|supportsNoOp|supportsLazyCommit,
		state.runtime.disallows,
	)
	if controlFailure != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationCompareResponse,
			*controlFailure,
		)
	}
	if state.passwordPolicyRestrictedDN != "" {
		return server.writePasswordPolicyRestriction(
			connection,
			message.ID,
			ldapwire.ApplicationCompareResponse,
			false,
		)
	}
	dn, err := parseCoreWriteDN(state.runtime, request.DN)
	if err != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationCompareResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""),
		)
	}
	request, compareFailure := validateCompareRequest(state.runtime.schema, request)
	if compareFailure != nil {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationCompareResponse,
			*compareFailure,
		)
	}
	rootDSETarget := dn.Depth() == 0
	subschemaTarget := isRuntimeSubschemaDN(state.runtime, dn)
	var database *runtimeDatabase
	if !rootDSETarget && !subschemaTarget {
		database = databaseForNormalizedDN(state.runtime, dn)
		if database == nil {
			return server.writeOperationResult(
				connection,
				message.ID,
				ldapwire.ApplicationCompareResponse,
				globalReferralOrResult(
					state.runtime,
					&dn,
					referralScopeDefault,
					ldapwire.Result{Code: ldapwire.ResultNoSuchObject},
				),
			)
		}
	}
	if (rootDSETarget || subschemaTarget) && frontendRestricts(state.runtime, restrictCompare) {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationCompareResponse,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"operation restricted",
			),
		)
	}
	if database != nil && databaseRestricts(*database, restrictCompare) {
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationCompareResponse,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"operation restricted",
			),
		)
	}
	if !rootDSETarget {
		if handled, err := server.tryRetcodeOperation(
			ctx,
			connection,
			state,
			message,
			dn,
			retcodeOperationCompare,
			controls.manageDsaIT,
			nil,
		); handled {
			return err
		}
	}
	if database != nil && databaseUsesNullBackend(state.runtime, *database) {
		result := ldapwire.Result{Code: ldapwire.ResultCompareFalse}
		if controls.assertion != nil {
			result.Code = ldapwire.ResultAssertionFailed
		}
		return server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationCompareResponse,
			result,
		)
	}
	if database != nil && !controls.manageDsaIT &&
		activeTranslucentConfiguration(database) != nil {
		remote, remoteErr := server.translucentCompareUsesRemote(
			ctx,
			*database,
			dn,
			request.Attribute,
		)
		if remoteErr != nil {
			return server.internalOperationError(
				connection,
				message.ID,
				ldapwire.ApplicationCompareResponse,
				remoteErr,
			)
		}
		if remote {
			attempt, failure := server.executeTranslucentOperation(
				ctx,
				state,
				*database,
				message,
			)
			if failure != nil {
				return server.writeOperationResult(
					connection,
					message.ID,
					ldapwire.ApplicationCompareResponse,
					*failure,
				)
			}
			return server.writeLDAPBackendAttempt(connection, message, attempt)
		}
	}
	var monitorEntries map[string]directory.Entry
	if database != nil && isMonitorDatabase(*database) {
		monitorEntries, _, err = server.monitorEntryIndex(state.runtime)
		if err != nil {
			return server.internalOperationError(
				connection,
				message.ID,
				ldapwire.ApplicationCompareResponse,
				err,
			)
		}
	}

	result := ldapwire.Result{Code: ldapwire.ResultCompareFalse}
	err = server.config.Store.View(ctx, func(reader storage.Reader) error {
		tx := reader
		if database != nil && !isMonitorDatabase(*database) {
			tx = readerForDatabase(reader, *database)
		}
		dn, err = storage.NormalizeReaderDN(tx, dn)
		if err != nil {
			return err
		}
		var entry directory.Entry
		if monitorEntries != nil {
			var exists bool
			entry, exists = monitorEntries[dn.Key()]
			if !exists {
				return operationFailedWithMatchedDN(
					ldapwire.ResultNoSuchObject,
					monitorMatchedDN(
						state.runtime,
						server,
						reader,
						state.boundDN,
						dn,
						monitorEntries,
					),
					"",
				)
			}
		} else if rootDSETarget {
			entry = server.rootDSE(state)
		} else if subschemaTarget {
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
				if controls.dontUseCopy && database.shadow {
					return operationFailed(
						ldapwire.ResultUnwillingToPerform,
						"copy not used",
					)
				}
				referral, referralErr := globalReferralForMissingTarget(
					state.runtime,
					tx,
					dn,
					referralScopeDefault,
				)
				if referralErr != nil {
					return referralErr
				}
				if referral != nil {
					return &operationFailure{result: *referral}
				}
				return operationFailedWithMatchedDN(
					ldapwire.ResultNoSuchObject,
					server.disclosedAncestor(state.runtime, tx, state.boundDN, dn),
					"",
				)
			}
			if getErr != nil {
				return getErr
			}
			if controls.dontUseCopy && database.shadow {
				return operationFailed(
					ldapwire.ResultUnwillingToPerform,
					"copy not used",
				)
			}
			entry = withSubschemaReference(entry)
			entry, getErr = withSyncProviderContextCSNs(
				reader,
				*database,
				entry,
			)
			if getErr != nil {
				return getErr
			}
			entry, getErr = withCollectiveAttributes(
				state.runtime.schema,
				tx,
				entry,
			)
			if getErr != nil {
				return getErr
			}
		}
		entry, err = normalizeCompareEntryDN(tx, entry)
		if err != nil {
			return err
		}
		var dynlistPlans *dynlistProjectionCache
		var dynlistCompareHandled bool
		var dynlistCompareMatched bool
		rawEntry := entry
		if database != nil && !controls.manageDsaIT {
			dynlistPlans = newDynlistProjectionCache(
				ctx,
				server,
				state.runtime,
				reader,
				state.boundDN,
				dynlistProjectionRequest{
					compareAttribute: request.Attribute,
				},
			)
			dynlistCompareHandled, dynlistCompareMatched, err =
				dynlistPlans.dynamicListDNCompare(
					*database,
					rawEntry,
					request.Attribute,
					request.Assertion,
				)
			if err != nil {
				return err
			}
			if !dynlistCompareHandled {
				entry, _, err = dynlistPlans.apply(*database, entry)
				if err != nil {
					return err
				}
			}
		}
		aclEntry, aclErr := normalizeCompareACLEntry(
			state.runtime,
			database,
			state.boundDN,
			entry,
		)
		if aclErr != nil {
			return aclErr
		}
		if !server.allowed(
			state.runtime,
			tx,
			state.boundDN,
			aclEntry,
			request.Attribute,
			request.Assertion,
			acl.Compare,
		) {
			return operationFailed(ldapwire.ResultInsufficientAccessRights, "")
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
		if dynlistCompareHandled {
			if dynlistCompareMatched {
				result.Code = ldapwire.ResultCompareTrue
			}
			return nil
		}
		if !state.runtime.schema.HasAttributeDescription(
			entry,
			request.Attribute,
		) {
			if dynlistPlans != nil {
				handled, matched, compareErr := dynlistPlans.dynamicGroupCompare(
					*database,
					rawEntry,
					request.Attribute,
					request.Assertion,
				)
				if compareErr != nil {
					return compareErr
				}
				if handled {
					if matched {
						result.Code = ldapwire.ResultCompareTrue
					}
					return nil
				}
			}
			return operationFailed(ldapwire.ResultNoSuchAttribute, "")
		}
		for _, value := range state.runtime.schema.AttributeValues(
			entry,
			request.Attribute,
		) {
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

func normalizeCompareEntryDN(
	reader storage.Reader,
	entry directory.Entry,
) (directory.Entry, error) {
	dn, err := directory.ParseDN(entry.DN)
	if err != nil {
		return directory.Entry{}, err
	}
	dn, err = storage.NormalizeReaderDN(reader, dn)
	if err != nil {
		return directory.Entry{}, err
	}
	entry.DN = dn.String()
	return entry, nil
}

func normalizeCompareACLEntry(
	runtime *runtimeState,
	database *runtimeDatabase,
	boundDN string,
	entry directory.Entry,
) (directory.Entry, error) {
	if runtime == nil || runtime.schema == nil || database == nil ||
		isConfigDatabase(*database) || isMonitorDatabase(*database) || boundDN == "" {
		return entry, nil
	}
	subject, err := runtime.schema.NormalizeDN(boundDN)
	if err != nil {
		return directory.Entry{}, err
	}
	target, err := runtime.schema.NormalizeDN(entry.DN)
	if err != nil {
		return directory.Entry{}, err
	}
	if subject.Equal(target) {
		return entry, nil
	}
	legacySubject, subjectErr := directory.ParseDN(boundDN)
	legacyTarget, targetErr := directory.ParseDN(entry.DN)
	if subjectErr != nil || targetErr != nil || !legacySubject.Equal(legacyTarget) {
		return entry, nil
	}

	// ACL self matching still accepts a display DN. Insert a deterministic
	// child RDN only when legacy identity collapses schema-distinct DNs so the
	// ACL evaluation fails closed instead of granting self privileges.
	entry.DN = fmt.Sprintf("cn=%x,%s", target.Key(), entry.DN)
	return entry, nil
}

func validateNewEntry(entry directory.Entry, dn directory.DN) *ldapwire.Result {
	if result := validateNewEntryAttributes(entry); result != nil {
		return result
	}
	for _, rdnValue := range dn.RDNValues() {
		if !entry.HasValue(rdnValue.Type, rdnValue.Value) {
			result := ldapwire.ResultError(ldapwire.ResultNamingViolation, "RDN value is missing from entry")
			return &result
		}
	}
	return nil
}

func validateNewEntryWithSchema(
	entry directory.Entry,
	dn directory.DN,
	registry *schema.Registry,
) *ldapwire.Result {
	if registry == nil {
		return validateNewEntry(entry, dn)
	}
	if result := validateNewEntryAttributes(entry); result != nil {
		return result
	}
	for _, rdnValue := range dn.RDNValues() {
		matched, err := entryHasSchemaAttributeValue(
			entry,
			rdnValue.Type,
			rdnValue.Value,
			registry,
		)
		if err != nil {
			result := schemaValidationResult(err)
			return &result
		}
		if !matched {
			result := ldapwire.ResultError(
				ldapwire.ResultNamingViolation,
				"RDN value is missing from entry",
			)
			return &result
		}
	}
	return nil
}

func entryHasSchemaRDNValues(
	entry directory.Entry,
	dn directory.DN,
	registry *schema.Registry,
) bool {
	if registry == nil {
		for _, value := range dn.RDNValues() {
			if !entry.HasValue(value.Type, value.Value) {
				return false
			}
		}
		return true
	}
	for _, value := range dn.RDNValues() {
		matched, err := entryHasSchemaAttributeValue(
			entry,
			value.Type,
			value.Value,
			registry,
		)
		if err != nil || !matched {
			return false
		}
	}
	return true
}

func entryHasSchemaAttributeValue(
	entry directory.Entry,
	description string,
	want []byte,
	registry *schema.Registry,
) (bool, error) {
	for _, value := range registry.AttributeValues(entry, description) {
		comparison, err := registry.Compare(description, "", value, want)
		if err != nil {
			return false, err
		}
		if comparison == 0 {
			return true, nil
		}
	}
	return false, nil
}

func deleteSchemaRDNValues(
	entry *directory.Entry,
	dn directory.DN,
	registry *schema.Registry,
) {
	if registry == nil {
		entry.DeleteRDNValues(dn)
		return
	}
	for _, rdnValue := range dn.RDNValues() {
		attributes := make([]directory.Attribute, 0, len(entry.Attributes))
		for _, attribute := range entry.Attributes {
			if !registry.AttributeDescriptionSubtype(
				attribute.Description,
				rdnValue.Type,
			) {
				attributes = append(attributes, attribute)
				continue
			}
			values := attribute.Values[:0]
			for _, value := range attribute.Values {
				comparison, err := registry.Compare(
					rdnValue.Type,
					"",
					value,
					rdnValue.Value,
				)
				if err != nil || comparison != 0 {
					values = append(values, value)
				}
			}
			if len(values) != 0 {
				attribute.Values = values
				attributes = append(attributes, attribute)
			}
		}
		entry.Attributes = attributes
	}
}

func ensureSchemaRDNValues(
	entry *directory.Entry,
	dn directory.DN,
	registry *schema.Registry,
) {
	if registry == nil {
		entry.EnsureRDNValues(dn)
		return
	}
	for _, rdnValue := range dn.RDNValues() {
		matched, err := entryHasSchemaAttributeValue(
			*entry,
			rdnValue.Type,
			rdnValue.Value,
			registry,
		)
		if err == nil && matched {
			continue
		}
		_ = entry.AddValues(rdnValue.Type, [][]byte{rdnValue.Value})
	}
}

func validateNewEntryAttributes(entry directory.Entry) *ldapwire.Result {
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
		diagnostic := ""
		if change.Operation == ldapwire.ModificationDelete {
			detail := "no such attribute"
			if entry.HasAttribute(change.Attribute.Description) {
				detail = "no such value"
			}
			diagnostic = fmt.Sprintf(
				"modify/delete: %s: %s",
				change.Attribute.Description,
				detail,
			)
		}
		return operationFailed(
			ldapwire.ResultNoSuchAttribute,
			diagnostic,
		)
	case errors.Is(err, directory.ErrAttributeValueExists):
		valueIndex := 0
		for index, value := range change.Attribute.Values {
			if entry.HasValue(change.Attribute.Description, value) {
				valueIndex = index
				break
			}
		}
		return operationFailed(
			ldapwire.ResultAttributeOrValueExists,
			fmt.Sprintf(
				"modify/add: %s: value #%d already exists",
				change.Attribute.Description,
				valueIndex,
			),
		)
	case errors.Is(err, directory.ErrInvalidIncrementValue):
		return operationFailed(ldapwire.ResultConstraintViolation, "")
	default:
		return err
	}
}

func applyModificationWithPermissive(
	entry *directory.Entry,
	change ldapwire.Modification,
	permissive bool,
) error {
	if !permissive {
		return applyModification(entry, change)
	}
	if len(change.Attribute.Values) == 0 {
		if change.Operation == ldapwire.ModificationDelete &&
			!entry.HasAttribute(change.Attribute.Description) {
			return nil
		}
		return applyModification(entry, change)
	}

	filtered := change
	filtered.Attribute.Values = nil
	switch change.Operation {
	case ldapwire.ModificationAdd:
		for _, value := range change.Attribute.Values {
			if !entry.HasValue(change.Attribute.Description, value) {
				filtered.Attribute.Values = append(
					filtered.Attribute.Values,
					value,
				)
			}
		}
	case ldapwire.ModificationDelete:
		if !entry.HasAttribute(change.Attribute.Description) {
			return nil
		}
		for _, value := range change.Attribute.Values {
			if entry.HasValue(change.Attribute.Description, value) {
				filtered.Attribute.Values = append(
					filtered.Attribute.Values,
					value,
				)
			}
		}
	default:
		return applyModification(entry, change)
	}
	if len(filtered.Attribute.Values) == 0 {
		return nil
	}
	return applyModification(entry, filtered)
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
	case schema.ViolationNaming:
		return ldapwire.ResultError(ldapwire.ResultNamingViolation, violation.Error())
	default:
		return ldapwire.ResultError(ldapwire.ResultObjectClassViolation, violation.Error())
	}
}

func operationFailureFromSchema(err error) error {
	result := schemaValidationResult(err)
	return &operationFailure{result: result}
}

func (server *Server) applyCreateOperationalAttributesContext(
	ctx context.Context,
	entry *directory.Entry,
	actor string,
	lastMod bool,
	serverID uint16,
	registry *schema.Registry,
) error {
	attributes := entry.Attributes[:0]
	for _, attribute := range entry.Attributes {
		if !isProtectedOperationalAttribute(registry, attribute.Description) {
			attributes = append(attributes, attribute)
		}
	}
	entry.Attributes = attributes
	if !lastMod {
		return nil
	}
	uuid, err := randomUUID()
	if err != nil {
		return err
	}
	timestamp := time.Now().UTC().Format("20060102150405Z")
	entry.ReplaceValues("entryUUID", [][]byte{[]byte(uuid)})
	entry.ReplaceValues("entryCSN", [][]byte{[]byte(server.nextCSNContext(ctx, serverID))})
	entry.ReplaceValues("createTimestamp", [][]byte{[]byte(timestamp)})
	entry.ReplaceValues("modifyTimestamp", [][]byte{[]byte(timestamp)})
	entry.ReplaceValues("creatorsName", [][]byte{[]byte(actor)})
	entry.ReplaceValues("modifiersName", [][]byte{[]byte(actor)})
	return nil
}

func (server *Server) applyModifyOperationalAttributes(
	entry *directory.Entry,
	actor string,
	serverID uint16,
) {
	server.applyModifyOperationalAttributesContext(
		context.Background(), entry, actor, serverID,
	)
}

func (server *Server) applyModifyOperationalAttributesContext(
	ctx context.Context,
	entry *directory.Entry,
	actor string,
	serverID uint16,
) {
	timestamp := time.Now().UTC().Format("20060102150405Z")
	entry.ReplaceValues("entryCSN", [][]byte{[]byte(server.nextCSNContext(ctx, serverID))})
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

func (server *Server) applyDITStructureRuleOperationalAttribute(
	runtime *runtimeState,
	entry *directory.Entry,
	parent *directory.Entry,
	relax bool,
) error {
	ruleID, governed, err := runtime.schema.GoverningStructureRule(
		*entry,
		parent,
	)
	if err != nil {
		var violation *schema.Violation
		if relax && errors.As(err, &violation) &&
			violation.Kind == schema.ViolationNaming {
			entry.ReplaceValues("governingStructureRule", nil)
			return nil
		}
		return err
	}
	if !governed {
		entry.ReplaceValues("governingStructureRule", nil)
		return nil
	}
	entry.ReplaceValues(
		"governingStructureRule",
		stringValues(strconv.Itoa(ruleID)),
	)
	return nil
}

func schemaParentEntry(
	reader storage.Reader,
	dn directory.DN,
) (*directory.Entry, error) {
	parentDN, ok := dn.Parent()
	if !ok || parentDN.Depth() == 0 {
		return nil, nil
	}
	parent, err := reader.Get(parentDN)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &parent, nil
}

func (server *Server) nextCSN(serverID uint16) string {
	server.csnMu.Lock()
	defer server.csnMu.Unlock()

	now := time.Now().UTC().Truncate(time.Microsecond)
	if server.lastCSN.IsZero() || now.After(server.lastCSN) {
		server.lastCSN = now
		server.csnCounter = 0
	} else {
		if server.csnCounter == openLDAPCSNCounterMax {
			server.lastCSN = server.lastCSN.Add(time.Microsecond)
			server.csnCounter = 0
		} else {
			server.csnCounter++
		}
	}
	return fmt.Sprintf(
		"%s#%06x#%03x#000000",
		server.lastCSN.Format("20060102150405.000000Z"),
		server.csnCounter,
		serverID,
	)
}

func (server *Server) nextCSNContext(ctx context.Context, serverID uint16) string {
	clock, ok := ctx.Value(transactionPreflightClockContextKey{}).(*transactionPreflightClock)
	if !ok {
		return server.nextCSN(serverID)
	}
	if clock.lastCSN.IsZero() || clock.now.After(clock.lastCSN) {
		clock.lastCSN = clock.now
		clock.csnCounter = 0
	} else if clock.csnCounter == openLDAPCSNCounterMax {
		clock.lastCSN = clock.lastCSN.Add(time.Microsecond)
		clock.csnCounter = 0
	} else {
		clock.csnCounter++
	}
	return fmt.Sprintf(
		"%s#%06x#%03x#000000",
		clock.lastCSN.Format("20060102150405.000000Z"),
		clock.csnCounter,
		serverID,
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

func isProtectedOperationalAttribute(
	registry *schema.Registry,
	description string,
) bool {
	base := description
	if index := strings.IndexByte(base, ';'); index >= 0 {
		base = base[:index]
	}
	key := strings.ToLower(strings.TrimSpace(base))
	if attributeType, ok := registry.AttributeType(base); ok {
		key = strings.ToLower(attributeType.OID)
	}
	_, protected := protectedOperationalAttributes[key]
	return protected
}

func isManageableOperationalAttribute(
	registry *schema.Registry,
	description string,
) bool {
	base := description
	if index := strings.IndexByte(base, ';'); index >= 0 {
		base = base[:index]
	}
	key := strings.ToLower(strings.TrimSpace(base))
	if attributeType, ok := registry.AttributeType(base); ok {
		key = strings.ToLower(attributeType.OID)
	}
	_, manageable := manageableOperationalAttributes[key]
	return manageable
}

func isAuthTimestampAttribute(
	registry *schema.Registry,
	description string,
) bool {
	base := description
	if index := strings.IndexByte(base, ';'); index >= 0 {
		base = base[:index]
	}
	if attributeType, ok := registry.AttributeType(base); ok {
		return attributeType.OID == "1.3.6.1.4.1.453.16.2.188"
	}
	return strings.EqualFold(strings.TrimSpace(base), "authTimestamp") ||
		strings.TrimSpace(base) == "1.3.6.1.4.1.453.16.2.188"
}

func belowKnownNamingContext(reader storage.Reader, dn directory.DN) (bool, error) {
	comparisonDN, err := storage.NormalizeReaderDN(reader, dn)
	if err != nil {
		return false, err
	}
	contexts, err := reader.NamingContexts()
	if err != nil {
		return false, err
	}
	for _, rawContext := range contexts {
		contextDN, err := directory.ParseDN(rawContext)
		if err != nil {
			return false, err
		}
		contextDN, err = storage.NormalizeReaderDN(reader, contextDN)
		if err != nil {
			return false, err
		}
		if contextDN.Equal(comparisonDN) || contextDN.AncestorOf(comparisonDN) {
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

func refreshRuntimeNamingContexts(
	writer storage.Writer,
	runtime *runtimeState,
) error {
	if runtime == nil || runtime.schema == nil {
		return refreshNamingContexts(writer)
	}
	contexts, err := storage.InferNamingContextsWithNormalizer(
		writer,
		runtime.schema,
	)
	if err != nil {
		return err
	}
	return writer.SetNamingContexts(contexts)
}

func parseCoreWriteDN(
	runtime *runtimeState,
	value string,
) (directory.DN, error) {
	legacy, err := directory.ParseDN(value)
	if err != nil || runtime == nil || isConfigurationDN(legacy) {
		return legacy, err
	}
	if database := databaseForDN(runtime, legacy); database != nil {
		if isMonitorDatabase(*database) {
			return legacy, nil
		}
		return parseRuntimeDN(value, database.dnNormalizer)
	}
	if runtime.schema != nil {
		return runtime.schema.NormalizeDN(value)
	}
	return legacy, nil
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
		if failure.result.Code == ldapwire.ResultNoOperation {
			controls = nil
		}
		responseControls := append(
			append([]ldapwire.Control(nil), controls...),
			failure.controls...,
		)
		return server.writeOperationResultWithControls(
			connection,
			messageID,
			responseTag,
			failure.result,
			responseControls,
		)
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
	return server.writeLDAPResultResponse(
		connection,
		messageID,
		responseTag,
		result,
		"",
		nil,
		controls,
	)
}

func (server *Server) writeLDAPResultResponse(
	connection net.Conn,
	messageID int64,
	responseTag uint64,
	result ldapwire.Result,
	responseName string,
	responseValue []byte,
	controls []ldapwire.Control,
) error {
	if err := beginOperationFinalResponse(connection); err != nil {
		return err
	}
	if writer, ok := connection.(ldapResultResponseWriter); ok {
		return writer.writeLDAPResultResponse(
			messageID,
			responseTag,
			result,
			responseName,
			responseValue,
			controls,
		)
	}
	if responseTag == ldapwire.ApplicationExtendedResponse {
		return ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
			messageID,
			result,
			responseName,
			responseValue,
			controls,
		))
	}
	return ldapwire.Write(
		connection,
		ldapwire.EncodeResultResponse(messageID, responseTag, result, controls),
	)
}

type operationFailure struct {
	result   ldapwire.Result
	controls []ldapwire.Control
}

func (failure *operationFailure) Error() string {
	return fmt.Sprintf("LDAP operation failed with result %d", failure.result.Code)
}

func operationFailed(code ldapwire.ResultCode, diagnostic string) error {
	return &operationFailure{result: ldapwire.ResultError(code, diagnostic)}
}

func operationFailedWithMatchedDN(
	code ldapwire.ResultCode,
	matchedDN,
	diagnostic string,
) error {
	return &operationFailure{result: ldapwire.Result{
		Code:              code,
		MatchedDN:         matchedDN,
		DiagnosticMessage: diagnostic,
	}}
}

func asOperationFailure(err error) *operationFailure {
	var failure *operationFailure
	if errors.As(err, &failure) {
		return failure
	}
	return nil
}
