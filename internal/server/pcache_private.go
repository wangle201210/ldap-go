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

	"github.com/google/uuid"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	pcacheQueryIDAttribute  = "pcacheQueryID"
	pcacheQueryURLAttribute = "pcacheQueryURL"

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
		if err := ldapwire.Write(
			connection,
			ldapwire.EncodeSearchResultEntry(message.ID, selected, nil),
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
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
) (bool, error) {
	present, failure := parsePcachePrivateDBControl(message.Controls)
	if !present {
		return false, nil
	}
	if failure != nil {
		return true, writeResultForMessage(connection, message, *failure)
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
	state.mu.Lock()
	defer state.mu.Unlock()
	now := state.clock()
	persistent := state.persistence != nil && state.persistence.enabled &&
		state.persistence.store != nil
	if !persistent {
		state.purgeExpired(now)
	}
	entries := make(map[string]directory.Entry, state.entries+1)
	visibleQueries := 0
	for _, query := range state.queries {
		if persistent && !now.Before(query.purgeAt) {
			continue
		}
		visibleQueries++
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
			if query.identifier != "" {
				appendPcachePrivateValue(&entry, pcacheQueryIDAttribute, []byte(query.identifier))
			}
			entries[dn.Key()] = entry
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
				if persistent && !now.Before(query.purgeAt) {
					continue
				}
				if value := pcacheQueryURL(query); value != "" {
					appendPcachePrivateValue(&entry, pcacheQueryURLAttribute, []byte(value))
				}
			}
		}
		entries[suffix.Key()] = entry
	}
	return entries, true
}

func mergePcachePrivateEntry(target *directory.Entry, source directory.Entry) {
	for _, attribute := range source.Attributes {
		for _, value := range attribute.Values {
			appendPcachePrivateValue(target, attribute.Description, value)
		}
	}
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
