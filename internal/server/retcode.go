package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type retcodeOperation uint16

const (
	retcodeOperationAdd retcodeOperation = 1 << iota
	retcodeOperationBind
	retcodeOperationCompare
	retcodeOperationDelete
	retcodeOperationModify
	retcodeOperationRename
	retcodeOperationSearch
	retcodeOperationExtended
)

const (
	retcodeOperationRead  = retcodeOperationCompare | retcodeOperationSearch
	retcodeOperationWrite = retcodeOperationAdd | retcodeOperationDelete |
		retcodeOperationModify | retcodeOperationRename
	retcodeOperationAll = retcodeOperationBind | retcodeOperationRead |
		retcodeOperationWrite | retcodeOperationExtended
)

type retcodeItem struct {
	dn                 directory.DN
	entry              directory.Entry
	code               ldapwire.ResultCode
	operations         retcodeOperation
	text               string
	matchedDN          string
	referrals          []string
	sleepSeconds       int
	unsolicitedOID     string
	unsolicitedData    []byte
	hasUnsolicitedData bool
	preDisconnect      bool
	postDisconnect     bool
}

type retcodeRuntimeConfiguration struct {
	parent       directory.DN
	items        []retcodeItem
	inDirectory  bool
	sleepSeconds int
}

func loadRetcodeRuntimeConfiguration(
	entry directory.Entry,
	database runtimeDatabase,
) (retcodeRuntimeConfiguration, error) {
	emptyDN, err := parseRuntimeDN("", database.dnNormalizer)
	if err != nil {
		return retcodeRuntimeConfiguration{}, err
	}
	configuration := retcodeRuntimeConfiguration{parent: emptyDN}
	parentValues := entry.Values("olcRetcodeParent")
	if len(parentValues) > 1 {
		return configuration, fmt.Errorf(
			"%s olcRetcodeParent must be single-valued",
			entry.DN,
		)
	}
	if len(parentValues) == 1 {
		parent, err := parseRuntimeDN(
			string(parentValues[0]),
			database.dnNormalizer,
		)
		if err != nil {
			return configuration, fmt.Errorf(
				"%s olcRetcodeParent: %w",
				entry.DN,
				err,
			)
		}
		configuration.parent = parent
	}

	inDirectory, _, err := singleBoolean(entry, "olcRetcodeInDir")
	if err != nil {
		return configuration, err
	}
	configuration.inDirectory = inDirectory
	sleep, err := singleRetcodeInteger(entry, "olcRetcodeSleep")
	if err != nil {
		return configuration, err
	}
	configuration.sleepSeconds = sleep

	itemValues := entry.Values("olcRetcodeItem")
	if len(itemValues) > 0 && configuration.parent.Depth() == 0 {
		if len(database.suffixes) == 0 {
			return configuration, fmt.Errorf(
				"%s requires olcRetcodeParent or a database suffix",
				entry.DN,
			)
		}
		configuration.parent = database.suffixes[0]
	}
	configuration.items = make([]retcodeItem, 0, len(itemValues))
	for _, raw := range itemValues {
		value, err := stripRetcodeOrderingPrefix(string(raw))
		if err != nil {
			return retcodeRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRetcodeItem: %w",
				entry.DN,
				err,
			)
		}
		arguments, err := tokenizeOpenLDAPConfig(value)
		if err != nil {
			return retcodeRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRetcodeItem: %w",
				entry.DN,
				err,
			)
		}
		item, err := parseRetcodeItem(
			arguments,
			configuration.parent,
			database.dnNormalizer,
		)
		if err != nil {
			return retcodeRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRetcodeItem: %w",
				entry.DN,
				err,
			)
		}
		configuration.items = append(configuration.items, item)
	}
	return configuration, nil
}

func singleRetcodeInteger(entry directory.Entry, attribute string) (int, error) {
	values := entry.Values(attribute)
	if len(values) == 0 {
		return 0, nil
	}
	if len(values) != 1 {
		return 0, fmt.Errorf("%s %s must be single-valued", entry.DN, attribute)
	}
	value, err := strconv.Atoi(string(values[0]))
	if err != nil {
		return 0, fmt.Errorf("%s %s has invalid value %q", entry.DN, attribute, values[0])
	}
	return value, nil
}

func stripRetcodeOrderingPrefix(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{") {
		return value, nil
	}
	end := strings.IndexByte(value, '}')
	if end < 2 {
		return "", errors.New("invalid ordered retcode prefix")
	}
	order, err := strconv.Atoi(value[1:end])
	if err != nil || order < 0 {
		return "", fmt.Errorf("invalid ordered retcode prefix %q", value[:end+1])
	}
	return strings.TrimSpace(value[end+1:]), nil
}

func parseRetcodeItem(
	arguments []string,
	parent directory.DN,
	normalizer directory.DNAttributeNormalizer,
) (retcodeItem, error) {
	if len(arguments) < 2 {
		return retcodeItem{}, errors.New("item requires an RDN and result code")
	}
	rdn, err := parseRuntimeDN(arguments[0], normalizer)
	if err != nil || rdn.Depth() != 1 {
		return retcodeItem{}, fmt.Errorf("%q is not an RDN", arguments[0])
	}
	dn, err := directory.ComposeLocalName(rdn, parent)
	if err != nil {
		return retcodeItem{}, err
	}
	code, err := parseRetcodeResultCode(arguments[1])
	if err != nil {
		return retcodeItem{}, err
	}
	item := retcodeItem{
		dn:         dn,
		code:       code,
		operations: retcodeOperationAll,
	}
	var textSet, matchedSet, referralsSet, unsolicitedSet bool
	for _, argument := range arguments[2:] {
		name, value, found := strings.Cut(argument, "=")
		if !found {
			return retcodeItem{}, fmt.Errorf("unknown option %q", argument)
		}
		switch strings.ToLower(name) {
		case "op":
			operations, err := parseRetcodeOperations(value)
			if err != nil {
				return retcodeItem{}, err
			}
			item.operations = operations
		case "text":
			if textSet {
				return retcodeItem{}, errors.New("text already provided")
			}
			textSet = true
			item.text = value
		case "matched":
			if matchedSet {
				return retcodeItem{}, errors.New("matched already provided")
			}
			matchedSet = true
			matched, err := parseRuntimeDN(value, normalizer)
			if err != nil {
				return retcodeItem{}, fmt.Errorf("invalid matched DN %q: %w", value, err)
			}
			item.matchedDN = matched.String()
		case "ref":
			if referralsSet {
				return retcodeItem{}, errors.New("ref already provided")
			}
			referralsSet = true
			item.referrals = strings.Fields(value)
		case "sleeptime":
			if item.sleepSeconds != 0 {
				return retcodeItem{}, errors.New("sleeptime already provided")
			}
			sleep, err := strconv.Atoi(value)
			if err != nil {
				return retcodeItem{}, fmt.Errorf("unable to parse sleeptime=%q", value)
			}
			item.sleepSeconds = sleep
		case "unsolicited":
			if unsolicitedSet {
				return retcodeItem{}, errors.New("unsolicited already provided")
			}
			unsolicitedSet = true
			if err := parseRetcodeUnsolicited(&item, value); err != nil {
				return retcodeItem{}, err
			}
		case "flags":
			switch strings.ToLower(value) {
			case "disconnect", "pre-disconnect":
				item.preDisconnect = true
			case "post-disconnect":
				item.postDisconnect = true
			default:
				return retcodeItem{}, fmt.Errorf("unknown flag %q", value)
			}
		default:
			return retcodeItem{}, fmt.Errorf("unknown option %q", argument)
		}
	}
	item.entry = retcodeSyntheticEntry(item)
	return item, nil
}

func parseRetcodeResultCode(value string) (ldapwire.ResultCode, error) {
	parsed, consumed := parseCLongPrefix([]byte(value))
	if consumed == 0 || consumed != len(value) {
		return 0, fmt.Errorf("unable to parse return code %q", value)
	}
	return ldapwire.ResultCode(parsed), nil
}

func parseRetcodeOperations(value string) (retcodeOperation, error) {
	var result retcodeOperation
	for _, operation := range strings.Split(value, ",") {
		switch strings.ToLower(operation) {
		case "add":
			result |= retcodeOperationAdd
		case "bind", "auth":
			result |= retcodeOperationBind
		case "compare":
			result |= retcodeOperationCompare
		case "delete":
			result |= retcodeOperationDelete
		case "modify":
			result |= retcodeOperationModify
		case "rename", "modrdn":
			result |= retcodeOperationRename
		case "search":
			result |= retcodeOperationSearch
		case "extended":
			result |= retcodeOperationExtended
		case "read":
			result |= retcodeOperationRead
		case "write":
			result |= retcodeOperationWrite
		case "all":
			result |= retcodeOperationAll
		default:
			return 0, fmt.Errorf("unknown op %q", operation)
		}
	}
	return result, nil
}

func parseRetcodeUnsolicited(item *retcodeItem, value string) error {
	oid, encoded, hasData := strings.Cut(value, ":")
	if oid == "" {
		return errors.New("unsolicited OID is empty")
	}
	item.unsolicitedOID = oid
	if !hasData {
		return nil
	}
	item.hasUnsolicitedData = true
	if strings.HasPrefix(encoded, ":") {
		decoded, err := base64.StdEncoding.DecodeString(encoded[1:])
		if err != nil {
			return fmt.Errorf("unable to parse unsolicited data: %w", err)
		}
		item.unsolicitedData = decoded
		return nil
	}
	item.unsolicitedData = []byte(strings.TrimPrefix(encoded, " "))
	return nil
}

func retcodeSyntheticEntry(item retcodeItem) directory.Entry {
	entry := directory.Entry{
		DN: item.dn.String(),
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values:      stringValues("errObject", "extensibleObject"),
			},
			{
				Description: "errCode",
				Values: stringValues(strconv.FormatInt(
					int64(item.code),
					10,
				)),
			},
		},
	}
	entry.EnsureRDNValues(item.dn)
	if len(item.referrals) > 0 {
		entry.ReplaceValues("ref", stringValues(item.referrals...))
	}
	if item.text != "" {
		entry.ReplaceValues("errText", stringValues(item.text))
	}
	if item.matchedDN != "" {
		entry.ReplaceValues("errMatchedDN", stringValues(item.matchedDN))
	}
	if item.sleepSeconds != 0 {
		entry.ReplaceValues(
			"errSleepTime",
			stringValues(strconv.Itoa(item.sleepSeconds)),
		)
	}
	operations := []struct {
		mask retcodeOperation
		name string
	}{
		{retcodeOperationAdd, "add"},
		{retcodeOperationBind, "bind"},
		{retcodeOperationCompare, "compare"},
		{retcodeOperationDelete, "delete"},
		{retcodeOperationExtended, "extended"},
		{retcodeOperationModify, "modify"},
		{retcodeOperationRename, "rename"},
		{retcodeOperationSearch, "search"},
	}
	for _, operation := range operations {
		if item.operations&operation.mask != 0 {
			_ = entry.AddValues("errOp", stringValues(operation.name))
		}
	}
	return entry
}

func retcodeConfigurationsForDatabase(
	databases []runtimeDatabase,
	database runtimeDatabase,
) []retcodeRuntimeConfiguration {
	var configurations []retcodeRuntimeConfiguration
	for index := range databases {
		candidate := &databases[index]
		if databaseType(candidate.name) == "frontend" {
			configurations = append(configurations, candidate.retcodes...)
		}
	}
	if databaseType(database.name) != "frontend" {
		configurations = append(configurations, database.retcodes...)
	}
	return configurations
}

func retcodeInDirectoryEnabled(
	databases []runtimeDatabase,
	database runtimeDatabase,
) bool {
	for _, configuration := range retcodeConfigurationsForDatabase(
		databases,
		database,
	) {
		if configuration.inDirectory {
			return true
		}
	}
	return false
}

func (server *Server) retcodeStoredEntryExists(
	ctx context.Context,
	database runtimeDatabase,
	dn directory.DN,
) (bool, error) {
	found := false
	err := server.viewStorage(ctx, func(reader storage.Reader) error {
		_, err := readerForDatabase(reader, database).Get(dn)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	return found, err
}

func (server *Server) tryRetcodeOperation(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	target directory.DN,
	operation retcodeOperation,
	manageDsaIT bool,
	requestEntry *directory.Entry,
) (bool, error) {
	database := databaseForDN(state.runtime, target)
	placeholder := runtimeDatabase{}
	if database == nil {
		database = &placeholder
	}
	for _, configuration := range retcodeConfigurationsForDatabase(
		state.runtime.databases,
		*database,
	) {
		if !state.transactionPreflight {
			retcodeSleep(configuration.sleepSeconds)
		}
		if databaseDNAtOrBelow(*database, target, configuration.parent) {
			if request, ok := message.Request.(ldapwire.SearchRequest); ok &&
				databaseDNEqual(*database, configuration.parent, target) &&
				request.Scope != directory.ScopeBase {
				return true, server.writeRetcodeSyntheticSearch(
					ctx,
					connection,
					state,
					message.ID,
					request,
					configuration,
				)
			}
			if target.Depth() != configuration.parent.Depth()+1 {
				return true, server.writeRetcodeResult(
					connection,
					state.runtime,
					message,
					retcodeItem{
						code:      ldapwire.ResultNoSuchObject,
						matchedDN: configuration.parent.String(),
					},
				)
			}
			var selected *retcodeItem
			for index := range configuration.items {
				if databaseDNEqual(*database, configuration.items[index].dn, target) {
					selected = &configuration.items[index]
					break
				}
			}
			if selected == nil {
				return true, server.writeRetcodeResult(
					connection,
					state.runtime,
					message,
					retcodeItem{
						code:      ldapwire.ResultNoSuchObject,
						matchedDN: configuration.parent.String(),
						text:      "retcode not found",
					},
				)
			}
			if selected.operations&operation == 0 {
				continue
			}
			applySuccessfulRetcodeBind(state, message.Request, *selected)
			return true, server.writeRetcodeResult(
				connection,
				state.runtime,
				message,
				*selected,
			)
		}

		if !configuration.inDirectory || database == &placeholder {
			continue
		}
		if manageDsaIT && operation == retcodeOperationAdd {
			continue
		}
		if request, ok := message.Request.(ldapwire.SearchRequest); ok &&
			request.Scope != directory.ScopeBase {
			continue
		}
		if server.retcodeSuccessfulRootBind(
			ctx,
			state.runtime,
			*database,
			target,
			message.Request,
		) {
			continue
		}

		var entry directory.Entry
		if operation == retcodeOperationAdd && requestEntry != nil {
			entry = requestEntry.Clone()
		} else {
			found := false
			err := server.viewStorage(ctx, func(reader storage.Reader) error {
				stored, err := readerForDatabase(reader, *database).Get(target)
				if errors.Is(err, storage.ErrEntryNotFound) {
					return nil
				}
				if err != nil {
					return err
				}
				entry = stored
				found = true
				return nil
			})
			if err != nil {
				return true, fmt.Errorf("read in-directory retcode entry: %w", err)
			}
			if !found {
				continue
			}
		}
		item, applies := retcodeItemFromDirectoryEntry(
			state.runtime,
			entry,
			operation,
		)
		if operation != retcodeOperationAdd &&
			state.runtime.schema.EntryHasObjectClass(entry, "referral") {
			continue
		}
		if !applies {
			continue
		}
		if item.code == ldapwire.ResultSuccess && !item.preDisconnect {
			retcodeSleep(item.sleepSeconds)
			continue
		}
		return true, server.writeRetcodeResult(
			connection,
			state.runtime,
			message,
			item,
		)
	}
	return false, nil
}

func applySuccessfulRetcodeBind(
	state *connectionState,
	request ldapwire.Request,
	item retcodeItem,
) {
	bind, ok := request.(ldapwire.BindRequest)
	if !ok || item.code != ldapwire.ResultSuccess ||
		item.preDisconnect || item.postDisconnect {
		return
	}
	state.boundDN = bind.Name
	if bind.Authentication.IsSASL {
		state.authMechanism = strings.ToUpper(bind.Authentication.SASLMechanism)
		return
	}
	state.authMechanism = "SIMPLE"
	state.bindCredentialDN = bind.Name
	state.bindCredentials = append(
		state.bindCredentials[:0],
		bind.Authentication.Simple...,
	)
}

func (server *Server) tryRetcodeSearch(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	request ldapwire.SearchRequest,
	manageDsaIT bool,
) (bool, error) {
	base, err := directory.ParseDN(request.BaseDN)
	if err != nil {
		return false, nil
	}
	return server.tryRetcodeOperation(
		ctx,
		connection,
		state,
		message,
		base,
		retcodeOperationSearch,
		manageDsaIT,
		nil,
	)
}

func (server *Server) retcodeSuccessfulRootBind(
	ctx context.Context,
	runtime *runtimeState,
	database runtimeDatabase,
	target directory.DN,
	request ldapwire.Request,
) bool {
	bind, ok := request.(ldapwire.BindRequest)
	rootPassword, root := databaseAuthenticationRoot(runtime, database, target)
	return ok && !bind.Authentication.IsSASL && root &&
		server.verifyStoredPassword(
			ctx,
			runtime,
			rootPassword,
			bind.Authentication.Simple,
		)
}

func retcodeItemFromDirectoryEntry(
	runtime *runtimeState,
	entry directory.Entry,
	operation retcodeOperation,
) (retcodeItem, bool) {
	if !runtime.schema.EntryHasObjectClass(entry, "errAbsObject") ||
		!retcodeDirectoryOperationMatches(runtime, entry.Values("errOp"), operation) {
		return retcodeItem{}, false
	}
	codeValues := entry.Values("errCode")
	if len(codeValues) != 1 {
		return retcodeItem{}, false
	}
	code, consumed := parseCLongPrefix(codeValues[0])
	if consumed == 0 || consumed != len(codeValues[0]) {
		return retcodeItem{}, false
	}
	dn, err := runtime.schema.NormalizeDN(entry.DN)
	if err != nil {
		return retcodeItem{}, false
	}
	item := retcodeItem{
		dn:         dn,
		code:       ldapwire.ResultCode(code),
		operations: operation,
	}
	if values := entry.Values("errText"); len(values) > 0 {
		item.text = string(values[0])
	}
	if values := entry.Values("errMatchedDN"); len(values) > 0 {
		matched, err := runtime.schema.NormalizeDN(string(values[0]))
		if err != nil {
			return retcodeItem{}, false
		}
		item.matchedDN = matched.String()
	}
	for _, value := range entry.Values("ref") {
		item.referrals = append(item.referrals, string(value))
	}
	if values := entry.Values("errSleepTime"); len(values) > 0 && len(values[0]) > 0 && values[0][0] != '-' {
		if seconds, err := strconv.Atoi(string(values[0])); err == nil {
			item.sleepSeconds = seconds
		}
	}
	if values := entry.Values("errUnsolicitedOID"); len(values) > 0 {
		normalized, err := runtime.schema.NormalizeEqualityValue(
			"errUnsolicitedOID",
			values[0],
		)
		if err == nil {
			item.unsolicitedOID = string(normalized)
		}
	}
	if values := entry.Values("errUnsolicitedData"); len(values) > 0 {
		item.unsolicitedData = append([]byte(nil), values[0]...)
		item.hasUnsolicitedData = true
	}
	if values := entry.Values("errDisconnect"); len(values) > 0 {
		item.preDisconnect = strings.EqualFold(string(values[0]), "TRUE")
		item.postDisconnect = !item.preDisconnect
	}
	return item, true
}

func retcodeDirectoryOperationMatches(
	runtime *runtimeState,
	values [][]byte,
	operation retcodeOperation,
) bool {
	if len(values) == 0 {
		return true
	}
	want := ""
	switch operation {
	case retcodeOperationAdd:
		want = "add"
	case retcodeOperationBind:
		want = "bind"
	case retcodeOperationCompare:
		want = "compare"
	case retcodeOperationDelete:
		want = "delete"
	case retcodeOperationModify:
		want = "modify"
	case retcodeOperationRename:
		want = "modrdn"
	case retcodeOperationSearch:
		want = "search"
	case retcodeOperationExtended:
		want = "extended"
	}
	for _, value := range values {
		normalized, err := runtime.schema.NormalizeEqualityValue("errOp", value)
		if err == nil && string(normalized) == want {
			return true
		}
	}
	return false
}

func (server *Server) writeRetcodeSyntheticSearch(
	ctx context.Context,
	connection net.Conn,
	state *connectionState,
	messageID int64,
	request ldapwire.SearchRequest,
	configuration retcodeRuntimeConfiguration,
) error {
	limit := effectiveSearchLimit(server.config.MaxSearchEntries, request.SizeLimit)
	result := ldapwire.Result{Code: ldapwire.ResultSuccess}
	written := 0
	err := server.config.Store.View(ctx, func(reader storage.Reader) error {
		aclReader := reader
		if database := databaseForDN(state.runtime, configuration.parent); database != nil {
			aclReader = readerForDatabase(reader, *database)
		}
		for _, item := range configuration.items {
			matches, err := server.filterMatches(
				state.runtime,
				aclReader,
				state.boundDN,
				item.entry,
				request.Filter,
			)
			if err != nil {
				result = ldapwire.ResultError(
					ldapwire.ResultInappropriateMatching,
					err.Error(),
				)
				break
			}
			if !matches || !server.allowed(
				state.runtime,
				aclReader,
				state.boundDN,
				item.entry,
				"entry",
				nil,
				acl.Read,
			) {
				continue
			}
			if written >= limit {
				result.Code = ldapwire.ResultSizeLimitExceeded
				break
			}
			readable := server.attributesWithPrivilege(
				state.runtime,
				aclReader,
				state.boundDN,
				item.entry,
				acl.Read,
				request.TypesOnly,
			)
			selected := server.selectEntry(
				state.runtime,
				readable,
				request.Attributes,
				request.TypesOnly,
			)
			if err := ldapwire.Write(
				connection,
				ldapwire.EncodeSearchResultEntry(messageID, selected, nil),
			); err != nil {
				return err
			}
			written++
		}
		return nil
	})
	if err != nil {
		return err
	}
	return ldapwire.Write(
		connection,
		ldapwire.EncodeSearchResultDone(messageID, result, nil),
	)
}

func (server *Server) writeRetcodeInDirectorySearch(
	connection net.Conn,
	state *connectionState,
	message ldapwire.Message,
	candidates []searchCandidate,
	item retcodeItem,
) error {
	for _, candidate := range candidates {
		entryControls := server.passwordPolicySearchEntryControls(
			context.Background(),
			state,
			candidate.selected,
		)
		if err := ldapwire.Write(
			connection,
			ldapwire.EncodeSearchResultEntry(
				message.ID,
				candidate.selected,
				entryControls,
			),
		); err != nil {
			return err
		}
	}
	return server.writeRetcodeResult(connection, state.runtime, message, item)
}

func (server *Server) writeRetcodeResult(
	connection net.Conn,
	runtime *runtimeState,
	message ldapwire.Message,
	item retcodeItem,
) error {
	if item.preDisconnect {
		if _, capturing := connection.(ldapResultResponseWriter); capturing {
			return errors.New("retcode disconnect is unavailable in a transaction")
		}
		return connection.Close()
	}
	retcodeSleep(item.sleepSeconds)
	result := buildRetcodeResult(runtime, message.Request, item)

	messageID := message.ID
	responseTag, ok := retcodeResponseTag(message.Request)
	if !ok {
		return nil
	}
	var err error
	if item.unsolicitedOID != "" {
		messageID = 0
		if item.unsolicitedOID == "0" {
			err = server.writeLDAPResultResponse(
				connection,
				messageID,
				responseTag,
				result,
				"",
				nil,
				nil,
			)
		} else {
			var responseData []byte
			if item.hasUnsolicitedData {
				responseData = item.unsolicitedData
			}
			err = server.writeLDAPResultResponse(
				connection,
				messageID,
				ldapwire.ApplicationExtendedResponse,
				result,
				item.unsolicitedOID,
				responseData,
				nil,
			)
		}
	} else {
		err = server.writeLDAPResultResponse(
			connection,
			messageID,
			responseTag,
			result,
			"",
			nil,
			nil,
		)
	}
	if item.postDisconnect {
		if _, capturing := connection.(ldapResultResponseWriter); capturing {
			return errors.New("retcode disconnect is unavailable in a transaction")
		}
		closeErr := connection.Close()
		if err == nil {
			err = closeErr
		}
	}
	return err
}

func buildRetcodeResult(
	runtime *runtimeState,
	_ ldapwire.Request,
	item retcodeItem,
) ldapwire.Result {
	result := ldapwire.Result{
		Code:              item.code,
		MatchedDN:         item.matchedDN,
		DiagnosticMessage: item.text,
	}
	if result.Code == ldapwire.ResultReferral {
		scope := referralScopeDefault
		for _, raw := range item.referrals {
			rewritten, ok := rewriteReferralURL(
				raw,
				nil,
				&item.dn,
				scope,
			)
			if ok {
				result.Referrals = append(result.Referrals, rewritten)
			}
		}
		if len(result.Referrals) == 0 {
			if fallback, ok := globalReferralResult(runtime, &item.dn, scope); ok {
				result.Referrals = fallback.Referrals
			} else {
				result.Code = ldapwire.ResultOther
				result.DiagnosticMessage = "bad referral object"
			}
		}
	}
	return result
}

func retcodeResponseTag(request ldapwire.Request) (uint64, bool) {
	switch request.(type) {
	case ldapwire.BindRequest:
		return ldapwire.ApplicationBindResponse, true
	case ldapwire.SearchRequest:
		return ldapwire.ApplicationSearchResultDone, true
	case ldapwire.ExtendedRequest:
		return ldapwire.ApplicationExtendedResponse, true
	default:
		return responseTagFor(request.ApplicationTag())
	}
}

func retcodeSleep(seconds int) {
	if seconds < 0 {
		maximum := uint64(-(int64(seconds) + 1)) + 1
		if maximum == 0 {
			return
		}
		seconds = int(rand.Uint64N(maximum))
	}
	if seconds > 0 {
		time.Sleep(time.Duration(seconds) * time.Second)
	}
}
