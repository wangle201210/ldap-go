package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	pcacheQueryIDAttribute  = "pcacheQueryID"
	pcacheQueryURLAttribute = "pcacheQueryURL"
	pcacheQueryIDOID        = "1.3.6.1.4.1.4203.666.11.9.1.1"
	pcacheQueryURLOID       = "1.3.6.1.4.1.4203.666.11.9.1.2"
	pcacheNumQueriesOID     = "1.3.6.1.4.1.4203.666.11.9.1.3"
	pcacheNumEntriesOID     = "1.3.6.1.4.1.4203.666.11.9.1.4"

	pcacheQueryDeleteBaseTag = 0xa0
	pcacheQueryDeleteDNTag   = 0xa1
	pcacheQueryDeleteUUIDTag = 0xa2
)

type pcacheQueryDeleteRequest struct {
	tag        byte
	dn         []byte
	identifier string
}

func parsePcachePrivateDBControl(
	controls []ldapwire.Control,
) (bool, *ldapwire.Result) {
	found := false
	for _, control := range controls {
		if control.OID != pcachePrivateDBControl {
			continue
		}
		if found {
			return true, controlResult(
				ldapwire.ResultProtocolError,
				"privateDB control specified multiple times",
			)
		}
		found = true
		if control.HasValue {
			return true, controlResult(
				ldapwire.ResultProtocolError,
				"privateDB control value not absent",
			)
		}
		if !control.Critical {
			return true, controlResult(
				ldapwire.ResultProtocolError,
				"privateDB control criticality required",
			)
		}
	}
	return found, nil
}

func (server *Server) tryPcachePrivateSearch(
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.SearchRequest,
) (bool, error) {
	present, failure := parsePcachePrivateDBControl(message.Controls)
	if !present {
		return false, nil
	}
	if failure != nil {
		return true, server.writeSearchDone(connection, message.ID, *failure)
	}
	for _, control := range message.Controls {
		if control.OID != pcachePrivateDBControl && control.Critical {
			return true, server.writeSearchDone(
				connection,
				message.ID,
				ldapwire.ResultError(
					ldapwire.ResultUnavailableCriticalExtension,
					"unsupported critical control",
				),
			)
		}
	}
	base, err := state.runtime.schema.NormalizeDN(request.BaseDN)
	if err != nil {
		return true, server.writeSearchDone(
			connection,
			message.ID,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, "invalid DN"),
		)
	}
	database := databaseForDN(state.runtime, base)
	if database == nil || database.pcache == nil || database.pcache.disabled {
		return true, server.writeSearchDone(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnavailableCriticalExtension,
				"private database is not available",
			),
		)
	}
	if !pcachePrivateDBRoot(state.runtime, *database, state.boundDN) {
		return true, server.writeSearchDone(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"pcachePrivDB: operation not allowed",
			),
		)
	}
	if databaseRestricts(*database, restrictSearch) {
		return true, server.writeSearchDone(
			connection,
			message.ID,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"operation restricted",
			),
		)
	}
	if state.passwordPolicyRestrictedDN != "" {
		return true, server.writeSearchDone(
			connection,
			message.ID,
			passwordPolicyRestrictionResult(),
		)
	}
	entries, ok := database.pcache.state.privateEntries(
		state.runtime,
		*database,
		database.pcache.persist,
	)
	if !ok {
		return true, server.writeSearchDone(
			connection,
			message.ID,
			ldapwire.ResultError(ldapwire.ResultOther, "pcache persistence failed"),
		)
	}
	if _, exists := entries[base.Key()]; !exists {
		return true, server.writeSearchDone(
			connection,
			message.ID,
			ldapwire.ResultError(ldapwire.ResultNoSuchObject, ""),
		)
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	limit := effectiveSearchLimit(server.config.MaxSearchEntries, request.SizeLimit)
	count := 0
	for _, key := range keys {
		entry := entries[key]
		dn, err := state.runtime.schema.NormalizeDN(entry.DN)
		if err != nil || !directory.InScope(base, dn, request.Scope) {
			continue
		}
		matches, err := request.Filter.MatchWith(entry, state.runtime.schema)
		if err != nil {
			return true, server.writeSearchDone(
				connection,
				message.ID,
				ldapwire.ResultError(ldapwire.ResultOther, err.Error()),
			)
		}
		if !matches {
			continue
		}
		if limit > 0 && count >= limit {
			return true, server.writeSearchDone(
				connection,
				message.ID,
				ldapwire.ResultError(ldapwire.ResultSizeLimitExceeded, ""),
			)
		}
		selected := server.selectEntry(
			state.runtime,
			entry,
			request.Attributes,
			request.TypesOnly,
		)
		if err := server.writeSearchEntry(
			connection,
			message.ID,
			selected,
			nil,
		); err != nil {
			return true, err
		}
		count++
	}
	return true, server.writeSearchDone(
		connection,
		message.ID,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
	)
}

func (server *Server) tryPcachePrivateCompare(
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.CompareRequest,
) (bool, error) {
	present, failure := parsePcachePrivateDBControl(message.Controls)
	if !present {
		return false, nil
	}
	write := func(result ldapwire.Result) (bool, error) {
		return true, server.writeOperationResult(
			connection,
			message.ID,
			ldapwire.ApplicationCompareResponse,
			result,
		)
	}
	if failure != nil {
		return write(*failure)
	}
	for _, control := range message.Controls {
		if control.OID != pcachePrivateDBControl && control.Critical {
			return write(ldapwire.ResultError(
				ldapwire.ResultUnavailableCriticalExtension,
				"unsupported critical control",
			))
		}
	}
	dn, err := state.runtime.schema.NormalizeDN(request.DN)
	if err != nil {
		return write(ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, "invalid DN"))
	}
	database := databaseForDN(state.runtime, dn)
	if database == nil || database.pcache == nil || database.pcache.disabled {
		return write(ldapwire.ResultError(
			ldapwire.ResultUnavailableCriticalExtension,
			"private database is not available",
		))
	}
	if !pcachePrivateDBRoot(state.runtime, *database, state.boundDN) {
		return write(ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"pcachePrivDB: operation not allowed",
		))
	}
	if databaseRestricts(*database, restrictCompare) {
		return write(ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"operation restricted",
		))
	}
	if state.passwordPolicyRestrictedDN != "" {
		return write(passwordPolicyRestrictionResult())
	}
	entries, ok := database.pcache.state.privateEntries(
		state.runtime,
		*database,
		database.pcache.persist,
	)
	if !ok {
		return write(ldapwire.ResultError(ldapwire.ResultOther, "pcache persistence failed"))
	}
	entry, found := entries[dn.Key()]
	if !found {
		return write(ldapwire.ResultError(ldapwire.ResultNoSuchObject, ""))
	}
	filter := directory.Filter{
		Kind:      directory.FilterEquality,
		Attribute: request.Attribute,
		Assertion: bytes.Clone(request.Assertion),
	}
	matches, err := filter.MatchWith(entry, state.runtime.schema)
	if err != nil {
		return write(ldapwire.ResultError(ldapwire.ResultUndefinedAttributeType, err.Error()))
	}
	code := ldapwire.ResultCompareFalse
	if matches {
		code = ldapwire.ResultCompareTrue
	}
	return write(ldapwire.Result{Code: code})
}

func (server *Server) tryUnsupportedPcachePrivateOperation(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
) (bool, error) {
	present, failure := parsePcachePrivateDBControl(message.Controls)
	if !present {
		return false, nil
	}
	if request, bind := message.Request.(ldapwire.BindRequest); bind {
		resetPcachePrivateBindState(state)
		if failure != nil {
			return true, writeResultForMessage(connection, message, *failure)
		}
		return true, server.handlePcachePrivateBind(
			connection,
			state,
			message,
			request,
		)
	}
	if failure != nil {
		return true, writeResultForMessage(connection, message, *failure)
	}
	switch request := message.Request.(type) {
	case ldapwire.AddRequest:
		return true, server.handlePcachePrivateAdd(ctx, connection, state, message, request)
	case ldapwire.ModifyRequest:
		return true, server.handlePcachePrivateModify(ctx, connection, state, message, request)
	case ldapwire.DeleteRequest:
		return true, server.handlePcachePrivateDelete(ctx, connection, state, message, request)
	case ldapwire.ModifyDNRequest:
		return true, server.handlePcachePrivateModifyDN(ctx, connection, state, message, request)
	}
	target, _, _, ok := chainOperationTarget(state, message.Request)
	if !ok {
		return true, writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(
				ldapwire.ResultUnavailableCriticalExtension,
				"private database is not available",
			),
		)
	}
	database := databaseForDN(state.runtime, target)
	if database == nil || database.pcache == nil || database.pcache.disabled {
		return true, writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(
				ldapwire.ResultUnavailableCriticalExtension,
				"private database is not available",
			),
		)
	}
	if !pcachePrivateDBRoot(state.runtime, *database, state.boundDN) {
		return true, writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"pcachePrivDB: operation not allowed",
			),
		)
	}
	if databaseRestricts(*database, requestDatabaseRestriction(message.Request)) {
		return true, writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"operation restricted",
			),
		)
	}
	return true, writeResultForMessage(
		connection,
		message,
		ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"operation not supported with pcachePrivDB control",
		),
	)
}

func resetPcachePrivateBindState(state *connectionState) {
	clearLDAPTransaction(state.transaction)
	state.transaction = nil
	clearBindCredentials(state)
	state.boundDN = ""
	state.authMechanism = ""
	state.passwordPolicyRestrictedDN = ""
	clearSearchSessions(state)
	clearSASLSession(state)
}

func (server *Server) handlePcachePrivateBind(
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.BindRequest,
) error {
	requestDN, err := parseRuntimeConnectionDN(state.runtime, request.Name)
	if err != nil {
		return writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, "invalid DN"),
		)
	}
	if request.Version < 2 || request.Version > 3 {
		return writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"requested protocol version not supported",
			),
		)
	}
	if request.Version == 2 && !state.runtime.allows.bindV2 {
		return writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(
				ldapwire.ResultProtocolError,
				"historical protocol version requested, use LDAPv3 instead",
			),
		)
	}
	state.protocolVersion = request.Version

	if request.Authentication.IsSASL {
		if request.Version < 3 {
			return writeResultForMessage(
				connection,
				message,
				ldapwire.ResultError(
					ldapwire.ResultProtocolError,
					"SASL bind requires LDAPv3",
				),
			)
		}
		if request.Authentication.SASLMechanism == "" {
			return writeResultForMessage(
				connection,
				message,
				ldapwire.ResultError(
					ldapwire.ResultAuthMethodNotSupported,
					"no SASL mechanism provided",
				),
			)
		}
		return writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(
				ldapwire.ResultUnavailableCriticalExtension,
				"critical control unavailable in frontend database",
			),
		)
	}

	password := request.Authentication.Simple
	if requestDN.Depth() == 0 || len(password) == 0 {
		var result ldapwire.Result
		switch {
		case requestDN.Depth() == 0 && len(password) != 0 &&
			!state.runtime.allows.bindAnonymousCredentials:
			result = ldapwire.ResultError(ldapwire.ResultInvalidCredentials, "")
		case requestDN.Depth() != 0 && len(password) == 0 &&
			!state.runtime.allows.bindAnonymousDN:
			result = ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"unauthenticated bind (DN with no password) disallowed",
			)
		case state.runtime.disallows.anonymousBind:
			result = ldapwire.ResultError(
				ldapwire.ResultInappropriateAuthentication,
				"anonymous bind disallowed",
			)
		default:
			result = ldapwire.ResultError(
				ldapwire.ResultUnavailableCriticalExtension,
				"critical control unavailable in frontend database",
			)
		}
		return writeResultForMessage(connection, message, result)
	}
	if state.runtime.disallows.simpleBind {
		return writeResultForMessage(
			connection,
			message,
			ldapwire.ResultError(
				ldapwire.ResultUnwillingToPerform,
				"unwilling to perform simple authentication",
			),
		)
	}

	// OpenLDAP do_bind() clears o_dn/o_ndn before pcache_op_privdb() calls
	// be_isroot(). A wire Bind therefore cannot reach the cache backend's
	// be_bind/rootpw path, even when the connection was previously root.
	return writeResultForMessage(
		connection,
		message,
		ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"pcachePrivDB: operation not allowed",
		),
	)
}

func pcachePrivateWriteControls(
	controls []ldapwire.Control,
	supported requestControlSupport,
) (requestControls, *ldapwire.Result) {
	filtered := make([]ldapwire.Control, 0, len(controls))
	for _, control := range controls {
		if control.OID != pcachePrivateDBControl {
			filtered = append(filtered, control)
		}
	}
	return parseRequestControls(filtered, supported)
}

func (server *Server) pcachePrivateWriteDatabase(
	state *connectionState,
	dn directory.DN,
	operation databaseRestrictions,
) (*runtimeDatabase, *ldapwire.Result) {
	database := databaseForDN(state.runtime, dn)
	if database == nil || database.pcache == nil || database.pcache.disabled {
		result := ldapwire.ResultError(
			ldapwire.ResultUnavailableCriticalExtension,
			"private database is not available",
		)
		return nil, &result
	}
	if !pcachePrivateDBRoot(state.runtime, *database, state.boundDN) {
		result := ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"pcachePrivDB: operation not allowed",
		)
		return nil, &result
	}
	if frontendRestricts(state.runtime, operation) || databaseRestricts(*database, operation) {
		result := ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"operation restricted",
		)
		return nil, &result
	}
	if state.passwordPolicyRestrictedDN != "" {
		result := passwordPolicyRestrictionResult()
		return nil, &result
	}
	return database, nil
}

func pcachePrivateAssertionResult(
	runtime *runtimeState,
	entry directory.Entry,
	filter *directory.Filter,
) *ldapwire.Result {
	if filter == nil {
		return nil
	}
	matches, err := filter.MatchWith(entry, runtime.schema)
	if err != nil || !matches {
		result := ldapwire.ResultError(ldapwire.ResultAssertionFailed, "")
		return &result
	}
	return nil
}

func (server *Server) pcachePrivateReadControl(
	runtime *runtimeState,
	entry directory.Entry,
	request *readControlRequest,
	oid string,
) (*ldapwire.Control, *ldapwire.Result) {
	if request == nil {
		return nil, nil
	}
	attributes := expandObjectClassAttributeSelection(
		runtime.schema,
		request.attributes,
	)
	for _, attribute := range attributes {
		if isSpecialAttributeSelection(attribute) {
			continue
		}
		if _, exists := runtime.schema.AttributeType(attribute); !exists && request.critical {
			result := ldapwire.ResultError(
				ldapwire.ResultUndefinedAttributeType,
				"unknown attribute type in read control",
			)
			return nil, &result
		}
	}
	selected := server.selectEntry(runtime, entry, attributes, false)
	return &ldapwire.Control{
		OID: oid, Value: ldapwire.EncodeReadControlValue(selected), HasValue: true,
	}, nil
}

func pcachePrivateResultFromError(err error) ldapwire.Result {
	if failure := asOperationFailure(err); failure != nil {
		return failure.result
	}
	return ldapwire.ResultError(ldapwire.ResultOther, err.Error())
}

func pcachePrivateValidateAddEntry(entry directory.Entry) *ldapwire.Result {
	if len(entry.Attributes) == 0 {
		result := ldapwire.ResultError(ldapwire.ResultProtocolError, "no attributes provided")
		return &result
	}
	seen := make(map[string]struct{}, len(entry.Attributes))
	for _, attribute := range entry.Attributes {
		name := strings.ToLower(attribute.Description)
		if _, duplicate := seen[name]; duplicate {
			result := ldapwire.ResultError(ldapwire.ResultAttributeOrValueExists, "")
			return &result
		}
		seen[name] = struct{}{}
		if pcachePrivateProtectedAttribute(attribute.Description) {
			result := ldapwire.ResultError(
				ldapwire.ResultConstraintViolation,
				"pcache operational metadata is not user modifiable",
			)
			return &result
		}
		if len(attribute.Values) == 0 {
			result := ldapwire.ResultError(
				ldapwire.ResultConstraintViolation,
				"attribute requires at least one value",
			)
			return &result
		}
		for index, value := range attribute.Values {
			for previous := 0; previous < index; previous++ {
				if directory.EqualValue(attribute.Values[previous], value) {
					result := ldapwire.ResultError(ldapwire.ResultAttributeOrValueExists, "")
					return &result
				}
			}
		}
	}
	return nil
}

func pcachePrivateSchemaResult(
	runtime *runtimeState,
	entry directory.Entry,
	dn directory.DN,
) *ldapwire.Result {
	if runtime == nil || runtime.schema == nil {
		result := ldapwire.ResultError(ldapwire.ResultOther, "schema is unavailable")
		return &result
	}
	if result := validateNewEntryWithSchema(entry, dn, runtime.schema); result != nil {
		return result
	}
	if err := runtime.schema.ValidateEntry(entry); err != nil {
		result := schemaValidationResult(err)
		return &result
	}
	return nil
}

func pcachePrivateChangesProtected(changes []ldapwire.Modification) bool {
	for _, change := range changes {
		if pcachePrivateProtectedAttribute(change.Attribute.Description) {
			return true
		}
	}
	return false
}

func pcachePrivateProtectedRDN(dn directory.DN) bool {
	for _, value := range dn.RDNValues() {
		if pcachePrivateProtectedAttribute(value.Type) {
			return true
		}
	}
	return false
}

func (state *pcacheState) reconcilePrivateQueries(
	runtime *runtimeState,
	database runtimeDatabase,
	physical map[string]directory.Entry,
	nextGeneration uint64,
) *ldapwire.Result {
	keys := make([]string, 0, len(physical))
	for key := range physical {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	total := len(state.private) + len(state.binds)
	for key, query := range state.queries {
		request, ok := query.replay.Request.(ldapwire.SearchRequest)
		if !ok {
			result := ldapwire.ResultError(ldapwire.ResultOther, "pcache query replay is invalid")
			return &result
		}
		base, err := runtime.schema.NormalizeDN(request.BaseDN)
		if err != nil {
			result := ldapwire.ResultError(ldapwire.ResultOther, "pcache query base is invalid")
			return &result
		}
		controlsByDN := make(map[string][]ldapwire.Control)
		references := make([]pcacheSearchItem, 0)
		for _, item := range query.response.items {
			if item.entry == nil {
				references = append(references, pcacheSearchItem{
					references: append([]string(nil), item.references...),
					controls:   cloneLDAPControls(item.controls),
				})
				continue
			}
			dn, normalizeErr := runtime.schema.NormalizeDN(item.entry.DN)
			if normalizeErr == nil {
				controlsByDN[dn.Key()] = cloneLDAPControls(item.controls)
			}
		}
		items := make([]pcacheSearchItem, 0, len(keys)+len(references))
		for _, entryKey := range keys {
			entry := physical[entryKey]
			dn, normalizeErr := runtime.schema.NormalizeDN(entry.DN)
			if normalizeErr != nil || !directory.InScope(base, dn, request.Scope) {
				continue
			}
			matches, matchErr := request.Filter.MatchWith(entry, runtime.schema)
			if matchErr != nil {
				result := ldapwire.ResultError(ldapwire.ResultOther, matchErr.Error())
				return &result
			}
			if !matches {
				continue
			}
			cloned := entry.Clone()
			items = append(items, pcacheSearchItem{
				entry:    &cloned,
				controls: cloneLDAPControls(controlsByDN[entryKey]),
			})
		}
		items = append(items, references...)
		query.response.items = items
		query.entries = len(items) - len(references)
		if query.entries == 0 {
			query.identifier = ""
		} else if query.identifier == "" {
			query.identifier = newPcacheQueryIdentifier(query.entries)
		}
		query.generation = nextGeneration
		query.refreshing = false
		state.queries[key] = query
		total += query.entries
	}
	if database.pcache.maxEntries > 0 && total > database.pcache.maxEntries {
		result := ldapwire.ResultError(
			ldapwire.ResultAdminLimitExceeded,
			"private cache entry limit exceeded",
		)
		return &result
	}
	state.entries = total
	return nil
}

func pcachePrivateParentExists(
	database runtimeDatabase,
	dn directory.DN,
	entries map[string]directory.Entry,
) bool {
	for _, suffix := range database.suffixes {
		if dn.Equal(suffix) {
			return true
		}
	}
	parent, ok := dn.Parent()
	if !ok || parent.Depth() == 0 {
		return true
	}
	_, exists := entries[parent.Key()]
	return exists
}

func (server *Server) handlePcachePrivateAdd(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.AddRequest,
) error {
	controls, failure := pcachePrivateWriteControls(
		message.Controls,
		supportsAssertion|supportsPostRead|supportsManageDsaIT|supportsRelax|supportsNoOp,
	)
	if failure != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationAddResponse, *failure)
	}
	dn, err := parseCoreWriteDN(state.runtime, request.Entry.DN)
	if err != nil || dn.Depth() == 0 {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationAddResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""))
	}
	database, failure := server.pcachePrivateWriteDatabase(state, dn, restrictAdd)
	if failure != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationAddResponse, *failure)
	}
	request.Entry.DN = dn.String()
	if failure := pcachePrivateValidateAddEntry(request.Entry); failure != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationAddResponse, *failure)
	}
	if failure := pcachePrivateSchemaResult(state.runtime, request.Entry, dn); failure != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationAddResponse, *failure)
	}
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	var post *ldapwire.Control
	accepted := database.pcache.state.mutate(ctx, func(candidate *pcacheState) (bool, bool) {
		candidate.purgeExpired(candidate.clock())
		visible := candidate.privateEntriesUnlocked(state.runtime, *database, database.pcache.persist, candidate.clock())
		if _, exists := visible[dn.Key()]; exists {
			result = ldapwire.ResultError(ldapwire.ResultEntryAlreadyExists, "")
			return false, true
		}
		if !pcachePrivateParentExists(*database, dn, visible) {
			result = ldapwire.ResultError(ldapwire.ResultNoSuchObject, "")
			return false, true
		}
		if assertion := pcachePrivateAssertionResult(state.runtime, request.Entry, controls.assertion); assertion != nil {
			result = *assertion
			return false, true
		}
		if candidate.private == nil {
			candidate.private = make(map[string]directory.Entry)
		}
		candidate.private[dn.Key()] = request.Entry.Clone()
		physical := candidate.privatePhysicalEntriesUnlocked(state.runtime, candidate.clock())
		nextGeneration := candidate.generation + 1
		if failure := candidate.reconcilePrivateQueries(state.runtime, *database, physical, nextGeneration); failure != nil {
			result = *failure
			return false, true
		}
		after := candidate.privateEntriesUnlocked(state.runtime, *database, database.pcache.persist, candidate.clock())[dn.Key()]
		if control, controlFailure := server.pcachePrivateReadControl(state.runtime, after, controls.postRead, postReadControlOID); controlFailure != nil {
			result = *controlFailure
			return false, true
		} else {
			post = control
		}
		if controls.noOp {
			result.Code = ldapwire.ResultNoOperation
			return false, true
		}
		candidate.generation = nextGeneration
		return true, true
	})
	if !accepted {
		result = ldapwire.ResultError(ldapwire.ResultOther, "pcache persistence failed")
		post = nil
	}
	var responseControls []ldapwire.Control
	if result.Code == ldapwire.ResultSuccess && post != nil {
		responseControls = append(responseControls, *post)
	}
	return server.writeOperationResultWithControls(connection, message.ID, ldapwire.ApplicationAddResponse, result, responseControls)
}

func (server *Server) handlePcachePrivateModify(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.ModifyRequest,
) error {
	controls, failure := pcachePrivateWriteControls(message.Controls,
		supportsAssertion|supportsPreRead|supportsPostRead|supportsManageDsaIT|
			supportsRelax|supportsNoOp|supportsPermissiveModify)
	if failure != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyResponse, *failure)
	}
	dn, err := parseCoreWriteDN(state.runtime, request.DN)
	if err != nil || dn.Depth() == 0 {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""))
	}
	database, failure := server.pcachePrivateWriteDatabase(state, dn, restrictModify)
	if failure != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyResponse, *failure)
	}
	if pcachePrivateChangesProtected(request.Changes) {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyResponse,
			ldapwire.ResultError(ldapwire.ResultConstraintViolation, "pcache operational metadata is not user modifiable"))
	}
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	var pre, post *ldapwire.Control
	accepted := database.pcache.state.mutate(ctx, func(candidate *pcacheState) (bool, bool) {
		candidate.purgeExpired(candidate.clock())
		visible := candidate.privateEntriesUnlocked(state.runtime, *database, database.pcache.persist, candidate.clock())
		before, exists := visible[dn.Key()]
		if !exists {
			result = ldapwire.ResultError(ldapwire.ResultNoSuchObject, "")
			return false, true
		}
		if assertion := pcachePrivateAssertionResult(state.runtime, before, controls.assertion); assertion != nil {
			result = *assertion
			return false, true
		}
		if control, controlFailure := server.pcachePrivateReadControl(state.runtime, before, controls.preRead, preReadControlOID); controlFailure != nil {
			result = *controlFailure
			return false, true
		} else {
			pre = control
		}
		after := before.Clone()
		for _, change := range request.Changes {
			if err := applyModificationWithPermissive(&after, change, controls.permissiveModify); err != nil {
				result = pcachePrivateResultFromError(err)
				return false, true
			}
		}
		if !entryHasSchemaRDNValues(after, dn, state.runtime.schema) {
			result = ldapwire.ResultError(ldapwire.ResultNotAllowedOnRDN, "")
			return false, true
		}
		if failure := pcachePrivateSchemaResult(state.runtime, after, dn); failure != nil {
			result = *failure
			return false, true
		}
		physical := candidate.privatePhysicalEntriesUnlocked(state.runtime, candidate.clock())
		stored := pcachePrivateEntryWithoutProtectedMetadata(after)
		physical[dn.Key()] = stored.Clone()
		candidate.private[dn.Key()] = stored
		nextGeneration := candidate.generation + 1
		if failure := candidate.reconcilePrivateQueries(state.runtime, *database, physical, nextGeneration); failure != nil {
			result = *failure
			return false, true
		}
		updated := candidate.privateEntriesUnlocked(state.runtime, *database, database.pcache.persist, candidate.clock())[dn.Key()]
		if control, controlFailure := server.pcachePrivateReadControl(state.runtime, updated, controls.postRead, postReadControlOID); controlFailure != nil {
			result = *controlFailure
			return false, true
		} else {
			post = control
		}
		if controls.noOp {
			result.Code = ldapwire.ResultNoOperation
			return false, true
		}
		if before.Equal(after) {
			return false, true
		}
		candidate.generation = nextGeneration
		return true, true
	})
	if !accepted {
		result = ldapwire.ResultError(ldapwire.ResultOther, "pcache persistence failed")
		pre, post = nil, nil
	}
	var responseControls []ldapwire.Control
	if result.Code == ldapwire.ResultSuccess {
		if pre != nil {
			responseControls = append(responseControls, *pre)
		}
		if post != nil {
			responseControls = append(responseControls, *post)
		}
	}
	return server.writeOperationResultWithControls(connection, message.ID, ldapwire.ApplicationModifyResponse, result, responseControls)
}

func (server *Server) handlePcachePrivateDelete(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.DeleteRequest,
) error {
	controls, failure := pcachePrivateWriteControls(message.Controls,
		supportsAssertion|supportsPreRead|supportsManageDsaIT|supportsRelax|supportsNoOp)
	if failure != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationDeleteResponse, *failure)
	}
	dn, err := parseCoreWriteDN(state.runtime, request.DN)
	if err != nil || dn.Depth() == 0 {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationDeleteResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""))
	}
	database, failure := server.pcachePrivateWriteDatabase(state, dn, restrictDelete)
	if failure != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationDeleteResponse, *failure)
	}
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	var pre *ldapwire.Control
	accepted := database.pcache.state.mutate(ctx, func(candidate *pcacheState) (bool, bool) {
		candidate.purgeExpired(candidate.clock())
		visible := candidate.privateEntriesUnlocked(state.runtime, *database, database.pcache.persist, candidate.clock())
		before, exists := visible[dn.Key()]
		if !exists {
			result = ldapwire.ResultError(ldapwire.ResultNoSuchObject, "")
			return false, true
		}
		if assertion := pcachePrivateAssertionResult(state.runtime, before, controls.assertion); assertion != nil {
			result = *assertion
			return false, true
		}
		for key, entry := range visible {
			if key == dn.Key() {
				continue
			}
			child, parseErr := state.runtime.schema.NormalizeDN(entry.DN)
			if parseErr == nil && dn.AncestorOf(child) {
				result = ldapwire.ResultError(ldapwire.ResultNotAllowedOnNonLeaf, "subordinate objects must be deleted first")
				return false, true
			}
		}
		physical := candidate.privatePhysicalEntriesUnlocked(state.runtime, candidate.clock())
		if _, stored := physical[dn.Key()]; !stored {
			result = ldapwire.ResultError(ldapwire.ResultUnwillingToPerform, "pcache operational metadata entry cannot be deleted")
			return false, true
		}
		if control, controlFailure := server.pcachePrivateReadControl(state.runtime, before, controls.preRead, preReadControlOID); controlFailure != nil {
			result = *controlFailure
			return false, true
		} else {
			pre = control
		}
		delete(physical, dn.Key())
		delete(candidate.private, dn.Key())
		nextGeneration := candidate.generation + 1
		if failure := candidate.reconcilePrivateQueries(state.runtime, *database, physical, nextGeneration); failure != nil {
			result = *failure
			return false, true
		}
		if controls.noOp {
			result.Code = ldapwire.ResultNoOperation
			return false, true
		}
		candidate.generation = nextGeneration
		return true, true
	})
	if !accepted {
		result = ldapwire.ResultError(ldapwire.ResultOther, "pcache persistence failed")
		pre = nil
	}
	var responseControls []ldapwire.Control
	if result.Code == ldapwire.ResultSuccess && pre != nil {
		responseControls = append(responseControls, *pre)
	}
	return server.writeOperationResultWithControls(connection, message.ID, ldapwire.ApplicationDeleteResponse, result, responseControls)
}

func (server *Server) handlePcachePrivateModifyDN(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.ModifyDNRequest,
) error {
	controls, failure := pcachePrivateWriteControls(message.Controls,
		supportsAssertion|supportsPreRead|supportsPostRead|supportsManageDsaIT|supportsRelax|supportsNoOp)
	if failure != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyDNResponse, *failure)
	}
	oldDN, err := parseCoreWriteDN(state.runtime, request.DN)
	if err != nil || oldDN.Depth() == 0 {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""))
	}
	database, failure := server.pcachePrivateWriteDatabase(state, oldDN, restrictRename)
	if failure != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyDNResponse, *failure)
	}
	newRDN, err := parseRuntimeDN(request.NewRDN, database.dnNormalizer)
	if err != nil || newRDN.Depth() != 1 || pcachePrivateProtectedRDN(newRDN) {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""))
	}
	var superior directory.DN
	if request.HasNewSuperior {
		superior, err = parseCoreWriteDN(state.runtime, request.NewSuperior)
	} else {
		superior, _ = oldDN.Parent()
	}
	if err != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""))
	}
	newDN, err := directory.ComposeLocalName(newRDN, superior)
	if err != nil {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultInvalidDNSyntax, ""))
	}
	if oldDN.Equal(newDN) {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultEntryAlreadyExists, ""))
	}
	destination := databaseForDN(state.runtime, newDN)
	if destination == nil || destination.partition != database.partition {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultAffectsMultipleDSAs, "cannot rename between DSAs"))
	}
	if oldDN.Equal(superior) || oldDN.AncestorOf(superior) {
		return server.writeOperationResult(connection, message.ID, ldapwire.ApplicationModifyDNResponse,
			ldapwire.ResultError(ldapwire.ResultLoopDetect, ""))
	}
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	var pre, post *ldapwire.Control
	accepted := database.pcache.state.mutate(ctx, func(candidate *pcacheState) (bool, bool) {
		candidate.purgeExpired(candidate.clock())
		visible := candidate.privateEntriesUnlocked(state.runtime, *database, database.pcache.persist, candidate.clock())
		before, exists := visible[oldDN.Key()]
		if !exists {
			result = ldapwire.ResultError(ldapwire.ResultNoSuchObject, "")
			return false, true
		}
		if assertion := pcachePrivateAssertionResult(state.runtime, before, controls.assertion); assertion != nil {
			result = *assertion
			return false, true
		}
		if superior.Depth() > 0 {
			if _, exists := visible[superior.Key()]; !exists {
				result = ldapwire.ResultError(ldapwire.ResultNoSuchObject, "")
				return false, true
			}
		}
		if existing, exists := visible[newDN.Key()]; exists {
			existingDN, _ := state.runtime.schema.NormalizeDN(existing.DN)
			if !oldDN.Equal(existingDN) && !oldDN.AncestorOf(existingDN) {
				result = ldapwire.ResultError(ldapwire.ResultEntryAlreadyExists, "")
				return false, true
			}
		}
		if control, controlFailure := server.pcachePrivateReadControl(state.runtime, before, controls.preRead, preReadControlOID); controlFailure != nil {
			result = *controlFailure
			return false, true
		} else {
			pre = control
		}
		physical := candidate.privatePhysicalEntriesUnlocked(state.runtime, candidate.clock())
		if _, stored := physical[oldDN.Key()]; !stored {
			result = ldapwire.ResultError(ldapwire.ResultUnwillingToPerform, "pcache operational metadata entry cannot be renamed")
			return false, true
		}
		renamed := make(map[string]directory.Entry, len(physical))
		materialized := make(map[string]directory.Entry)
		for key, entry := range physical {
			entryDN, parseErr := state.runtime.schema.NormalizeDN(entry.DN)
			if parseErr != nil || (!oldDN.Equal(entryDN) && !oldDN.AncestorOf(entryDN)) {
				renamed[key] = entry
				continue
			}
			replacement, replaceErr := entryDN.ReplaceAncestor(oldDN, newDN)
			if replaceErr != nil {
				result = ldapwire.ResultError(ldapwire.ResultOther, replaceErr.Error())
				return false, true
			}
			entry.DN = replacement.String()
			if entryDN.Equal(oldDN) {
				if request.DeleteOldRDN {
					deleteSchemaRDNValues(&entry, oldDN, state.runtime.schema)
				}
				ensureSchemaRDNValues(&entry, newDN, state.runtime.schema)
			}
			if failure := pcachePrivateSchemaResult(state.runtime, entry, replacement); failure != nil {
				result = *failure
				return false, true
			}
			if _, collision := renamed[replacement.Key()]; collision {
				result = ldapwire.ResultError(ldapwire.ResultEntryAlreadyExists, "")
				return false, true
			}
			renamed[replacement.Key()] = entry
			materialized[replacement.Key()] = pcachePrivateEntryWithoutProtectedMetadata(entry)
		}
		movedPrivate := make(map[string]directory.Entry, len(candidate.private))
		for key, entry := range candidate.private {
			entryDN, parseErr := state.runtime.schema.NormalizeDN(entry.DN)
			if parseErr != nil || (!oldDN.Equal(entryDN) && !oldDN.AncestorOf(entryDN)) {
				movedPrivate[key] = entry
				continue
			}
			replacement, _ := entryDN.ReplaceAncestor(oldDN, newDN)
			entry = renamed[replacement.Key()].Clone()
			movedPrivate[replacement.Key()] = entry
		}
		for key, entry := range materialized {
			movedPrivate[key] = entry
		}
		candidate.private = movedPrivate
		nextGeneration := candidate.generation + 1
		if failure := candidate.reconcilePrivateQueries(state.runtime, *database, renamed, nextGeneration); failure != nil {
			result = *failure
			return false, true
		}
		after := candidate.privateEntriesUnlocked(state.runtime, *database, database.pcache.persist, candidate.clock())[newDN.Key()]
		if control, controlFailure := server.pcachePrivateReadControl(state.runtime, after, controls.postRead, postReadControlOID); controlFailure != nil {
			result = *controlFailure
			return false, true
		} else {
			post = control
		}
		if controls.noOp {
			result.Code = ldapwire.ResultNoOperation
			return false, true
		}
		candidate.generation = nextGeneration
		return true, true
	})
	if !accepted {
		result = ldapwire.ResultError(ldapwire.ResultOther, "pcache persistence failed")
		pre, post = nil, nil
	}
	var responseControls []ldapwire.Control
	if result.Code == ldapwire.ResultSuccess {
		if pre != nil {
			responseControls = append(responseControls, *pre)
		}
		if post != nil {
			responseControls = append(responseControls, *post)
		}
	}
	return server.writeOperationResultWithControls(connection, message.ID, ldapwire.ApplicationModifyDNResponse, result, responseControls)
}

func pcachePrivateDBRoot(
	runtime *runtimeState,
	database runtimeDatabase,
	boundDN string,
) bool {
	if boundDN == "" || database.rootDN == nil {
		return false
	}
	dn, err := parseRuntimeConnectionDN(runtime, boundDN)
	return err == nil && databaseRootMatches(runtime, database, dn)
}

func (state *pcacheState) privateEntries(
	runtime *runtimeState,
	database runtimeDatabase,
	persistQueries bool,
) (map[string]directory.Entry, bool) {
	// Mutations take the write side before mu, so waiting for a snapshot never
	// blocks ordinary cache operations on mu. Only shallow map copies happen
	// while mu is held; entry values are cloned by the unlocked snapshot below.
	state.privateSnapshotMu.RLock()
	defer state.privateSnapshotMu.RUnlock()
	state.mu.Lock()
	now := state.clock()
	persistent := state.persistence != nil && state.persistence.enabled &&
		state.persistence.store != nil
	if !persistent {
		state.purgeExpired(now)
	}
	snapshot := &pcacheState{
		queries: make(map[string]pcacheCachedQuery, len(state.queries)),
		private: make(map[string]directory.Entry, len(state.private)),
		entries: state.entries,
	}
	for key, query := range state.queries {
		snapshot.queries[key] = query
	}
	for key, entry := range state.private {
		snapshot.private[key] = entry
	}
	state.mu.Unlock()
	return snapshot.privateEntriesUnlocked(runtime, database, persistQueries, now), true
}

func (state *pcacheState) privateEntriesUnlocked(
	runtime *runtimeState,
	database runtimeDatabase,
	persistQueries bool,
	now time.Time,
) map[string]directory.Entry {
	entries := state.privatePhysicalEntriesUnlocked(runtime, now)
	visibleQueries := 0
	for _, query := range state.queries {
		if !now.Before(query.purgeAt) {
			continue
		}
		visibleQueries++
		for key, entry := range entries {
			if !pcacheQueryContainsDN(runtime, query, key) {
				continue
			}
			if query.identifier != "" {
				appendPcachePrivateValue(&entry, pcacheQueryIDAttribute, []byte(query.identifier))
			}
			entries[key] = entry
		}
	}
	if len(database.suffixes) != 0 && visibleQueries != 0 {
		suffix := database.suffixes[0]
		entry := entries[suffix.Key()]
		if entry.DN == "" {
			entry = directory.Entry{DN: suffix.String()}
			entry.ReplaceValues("objectClass", stringValues("top"))
		}
		if persistQueries {
			for _, query := range state.queries {
				if !now.Before(query.purgeAt) {
					continue
				}
				if value := pcacheQueryURL(query); value != "" {
					appendPcachePrivateValue(&entry, pcacheQueryURLAttribute, []byte(value))
				}
			}
		}
		entries[suffix.Key()] = entry
	}
	return entries
}

func (state *pcacheState) privatePhysicalEntriesUnlocked(
	runtime *runtimeState,
	now time.Time,
) map[string]directory.Entry {
	entries := make(map[string]directory.Entry, state.entries+len(state.private)+1)
	for key, entry := range state.private {
		clean := pcachePrivateEntryWithoutProtectedMetadata(entry)
		if clean.DN != "" {
			entries[key] = clean
		}
	}
	for _, query := range state.queries {
		if !now.Before(query.purgeAt) {
			continue
		}
		for _, item := range query.response.items {
			if item.entry == nil {
				continue
			}
			dn, err := runtime.schema.NormalizeDN(item.entry.DN)
			if err != nil {
				continue
			}
			entry := entries[dn.Key()]
			if entry.DN == "" {
				entry = directory.Entry{DN: dn.String()}
			}
			mergePcachePrivateEntry(&entry, *item.entry)
			entries[dn.Key()] = entry
		}
	}
	return entries
}

func pcacheQueryContainsDN(
	runtime *runtimeState,
	query pcacheCachedQuery,
	key string,
) bool {
	for _, item := range query.response.items {
		if item.entry == nil {
			continue
		}
		dn, err := runtime.schema.NormalizeDN(item.entry.DN)
		if err == nil && dn.Key() == key {
			return true
		}
	}
	return false
}

func mergePcachePrivateEntry(target *directory.Entry, source directory.Entry) {
	for _, attribute := range source.Attributes {
		if pcachePrivateProtectedAttribute(attribute.Description) {
			continue
		}
		for _, value := range attribute.Values {
			appendPcachePrivateValue(target, attribute.Description, value)
		}
	}
}

func pcachePrivateProtectedAttribute(description string) bool {
	name, _, _ := strings.Cut(strings.TrimSpace(description), ";")
	switch strings.ToLower(name) {
	case strings.ToLower(pcacheQueryIDAttribute),
		strings.ToLower(pcacheQueryURLAttribute),
		"pcachenumqueries",
		"pcachenumentries",
		pcacheQueryIDOID,
		pcacheQueryURLOID,
		pcacheNumQueriesOID,
		pcacheNumEntriesOID:
		return true
	default:
		return false
	}
}

func pcachePrivateEntryWithoutProtectedMetadata(entry directory.Entry) directory.Entry {
	clean := directory.Entry{DN: entry.DN}
	for _, attribute := range entry.Attributes {
		if pcachePrivateProtectedAttribute(attribute.Description) {
			continue
		}
		clean.Attributes = append(clean.Attributes, directory.Attribute{
			Description: attribute.Description,
			Values:      pcacheCloneValues(attribute.Values),
		})
	}
	return clean
}

func pcacheCloneValues(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index := range values {
		cloned[index] = bytes.Clone(values[index])
	}
	return cloned
}

func appendPcachePrivateValue(
	entry *directory.Entry,
	description string,
	value []byte,
) {
	for index := range entry.Attributes {
		if !strings.EqualFold(entry.Attributes[index].Description, description) {
			continue
		}
		for _, existing := range entry.Attributes[index].Values {
			if bytes.Equal(existing, value) {
				return
			}
		}
		entry.Attributes[index].Values = append(
			entry.Attributes[index].Values,
			bytes.Clone(value),
		)
		return
	}
	entry.Attributes = append(entry.Attributes, directory.Attribute{
		Description: description,
		Values:      [][]byte{bytes.Clone(value)},
	})
}

func pcacheQueryURL(query pcacheCachedQuery) string {
	request, ok := query.replay.Request.(ldapwire.SearchRequest)
	if !ok {
		return ""
	}
	filter, err := encodeSockFilter(request.Filter)
	if err != nil {
		return ""
	}
	scope := "base"
	switch request.Scope {
	case directory.ScopeSingleLevel:
		scope = "one"
	case directory.ScopeWholeSubtree:
		scope = "sub"
	case directory.ScopeChildren:
		scope = "children"
	}
	value := "ldap:///" + request.BaseDN + "??" + scope + "?" + filter +
		"?x-uuid=" + query.identifier +
		",x-attrset=" + strconv.Itoa(query.attrset) +
		",x-expiry=" + strconv.FormatInt(query.purgeAt.Unix(), 10) +
		",x-answerable=0"
	if !query.refreshAt.IsZero() {
		value += ",x-refresh=" + strconv.FormatInt(query.refreshAt.Unix(), 10)
	}
	return value
}

func decodePcacheQueryDeleteRequest(value []byte) (pcacheQueryDeleteRequest, error) {
	if len(value) == 0 {
		return pcacheQueryDeleteRequest{}, errors.New("empty request data field in queryDelete exop")
	}
	tag, content, rest, err := pcacheReadBERElement(value)
	if err != nil || tag != 0x30 || len(rest) != 0 {
		return pcacheQueryDeleteRequest{}, errors.New("queryDelete data decoding error")
	}
	request := pcacheQueryDeleteRequest{}
	tag, request.dn, content, err = pcacheReadBERElement(content)
	if err != nil || (tag != pcacheQueryDeleteBaseTag && tag != pcacheQueryDeleteDNTag) {
		return pcacheQueryDeleteRequest{}, errors.New("queryDelete data decoding error")
	}
	request.tag = tag
	if len(content) != 0 {
		var rawUUID []byte
		tag, rawUUID, content, err = pcacheReadBERElement(content)
		if err != nil || tag != pcacheQueryDeleteUUIDTag || len(rawUUID) != 16 {
			return pcacheQueryDeleteRequest{}, errors.New("queryDelete data decoding error")
		}
		identifier, err := uuid.FromBytes(rawUUID)
		if err != nil {
			return pcacheQueryDeleteRequest{}, errors.New("queryDelete data decoding error")
		}
		request.identifier = identifier.String()
	}
	if len(content) != 0 {
		return pcacheQueryDeleteRequest{}, errors.New("queryDelete data decoding error")
	}
	return request, nil
}

func pcacheReadBERElement(value []byte) (byte, []byte, []byte, error) {
	if len(value) < 2 {
		return 0, nil, nil, errors.New("truncated BER element")
	}
	tag := value[0]
	length := int(value[1])
	header := 2
	if value[1]&0x80 != 0 {
		count := int(value[1] & 0x7f)
		if count == 0 || count > 4 || len(value) < 2+count || value[2] == 0 {
			return 0, nil, nil, errors.New("invalid BER length")
		}
		length = 0
		for _, octet := range value[2 : 2+count] {
			length = length<<8 | int(octet)
		}
		if length < 128 {
			return 0, nil, nil, errors.New("non-minimal BER length")
		}
		header += count
	}
	if length < 0 || length > len(value)-header {
		return 0, nil, nil, errors.New("truncated BER value")
	}
	return tag, value[header : header+length], value[header+length:], nil
}

func (server *Server) handlePcacheQueryDelete(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.ExtendedRequest,
) error {
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	write := func() error {
		return ldapwire.Write(connection, ldapwire.EncodeExtendedResponse(
			message.ID,
			result,
			"",
			nil,
			nil,
		))
	}
	if !request.HasValue || len(request.Value) == 0 {
		result = ldapwire.ResultError(
			ldapwire.ResultProtocolError,
			"empty request data field in queryDelete exop",
		)
		return write()
	}
	decoded, err := decodePcacheQueryDeleteRequest(request.Value)
	if err != nil {
		result = ldapwire.ResultError(ldapwire.ResultProtocolError, err.Error())
		return write()
	}
	dn, err := state.runtime.schema.NormalizeDN(string(decoded.dn))
	if err != nil {
		result = ldapwire.ResultError(
			ldapwire.ResultInvalidDNSyntax,
			"invalid DN in queryDelete exop request data",
		)
		return write()
	}
	database := databaseForDN(state.runtime, dn)
	if database == nil {
		result = ldapwire.ResultError(
			ldapwire.ResultNoSuchObject,
			"no global superior knowledge",
		)
		return write()
	}
	if database.pcache == nil || database.pcache.disabled {
		result = ldapwire.ResultError(
			ldapwire.ResultUnavailableCriticalExtension,
			"backend does not support extended operations",
		)
		return write()
	}
	if state.boundDN == "" && !state.runtime.allows.anonymousUpdates {
		result = ldapwire.ResultError(
			ldapwire.ResultStrongerAuthRequired,
			"modifications require authentication",
		)
		return write()
	}
	if frontendRestricts(state.runtime, restrictModify) ||
		databaseRestricts(*database, restrictModify) {
		result = ldapwire.ResultError(
			ldapwire.ResultUnwillingToPerform,
			"operation restricted",
		)
		return write()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	result = database.pcache.state.deleteQueryRequestContext(
		ctx,
		state.runtime,
		*database,
		decoded,
	)
	return write()
}

func (state *pcacheState) deleteQueryRequest(
	runtime *runtimeState,
	database runtimeDatabase,
	request pcacheQueryDeleteRequest,
) ldapwire.Result {
	return state.deleteQueryRequestContext(
		context.Background(),
		runtime,
		database,
		request,
	)
}

func (state *pcacheState) deleteQueryRequestContext(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	request pcacheQueryDeleteRequest,
) ldapwire.Result {
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	accepted := state.mutate(ctx, func(candidate *pcacheState) (bool, bool) {
		keys := make(map[string]struct{})
		switch request.tag {
		case pcacheQueryDeleteBaseTag:
			if request.identifier == "" {
				result = ldapwire.ResultError(
					ldapwire.ResultUnwillingToPerform,
					"deletion of all queries not implemented",
				)
				return false, true
			}
			for key, query := range candidate.queries {
				if query.identifier == request.identifier {
					keys[key] = struct{}{}
				}
			}
		case pcacheQueryDeleteDNTag:
			dn, err := runtime.schema.NormalizeDN(string(request.dn))
			if err != nil || !databaseContainsDN(database, dn) {
				result = ldapwire.ResultError(ldapwire.ResultNoSuchObject, "")
				return false, true
			}
			foundEntry := false
			for key, query := range candidate.queries {
				for _, item := range query.response.items {
					if item.entry == nil {
						continue
					}
					entryDN, err := runtime.schema.NormalizeDN(item.entry.DN)
					if err == nil && entryDN.Equal(dn) {
						foundEntry = true
						if request.identifier == "" || query.identifier == request.identifier {
							keys[key] = struct{}{}
						}
						break
					}
				}
			}
			if !foundEntry {
				result = ldapwire.ResultError(ldapwire.ResultNoSuchObject, "")
				return false, true
			}
		}
		for key := range keys {
			query := candidate.queries[key]
			candidate.removeQueryLocked(key, query)
		}
		if len(keys) == 0 {
			return false, true
		}
		candidate.generation++
		return true, true
	})
	if !accepted {
		return ldapwire.ResultError(ldapwire.ResultOther, "pcache persistence failed")
	}
	return result
}

func pcacheEncodeQueryDeleteRequest(
	tag byte,
	dn string,
	identifier string,
) ([]byte, error) {
	content := pcacheEncodeBERElement(tag, []byte(dn))
	if identifier != "" {
		parsed, err := uuid.Parse(identifier)
		if err != nil {
			return nil, fmt.Errorf("parse query identifier: %w", err)
		}
		content = append(content, pcacheEncodeBERElement(pcacheQueryDeleteUUIDTag, parsed[:])...)
	}
	return pcacheEncodeBERElement(0x30, content), nil
}

func pcacheEncodeBERElement(tag byte, value []byte) []byte {
	encoded := []byte{tag}
	if len(value) < 128 {
		encoded = append(encoded, byte(len(value)))
	} else {
		length := strconv.FormatInt(int64(len(value)), 16)
		if len(length)%2 != 0 {
			length = "0" + length
		}
		bytesLength := len(length) / 2
		encoded = append(encoded, 0x80|byte(bytesLength))
		for index := 0; index < len(length); index += 2 {
			value, _ := strconv.ParseUint(length[index:index+2], 16, 8)
			encoded = append(encoded, byte(value))
		}
	}
	return append(encoded, value...)
}
