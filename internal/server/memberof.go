package server

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type memberOfDanglingMode uint8

const (
	memberOfDanglingIgnore memberOfDanglingMode = iota
	memberOfDanglingDrop
	memberOfDanglingError
)

type memberOfRuntimeConfiguration struct {
	modifierDN        *directory.DN
	dangling          memberOfDanglingMode
	danglingError     ldapwire.ResultCode
	refint            bool
	addCheck          bool
	groupObjectClass  string
	memberAttribute   string
	memberOfAttribute string
}

func loadMemberOfRuntimeConfiguration(
	entry directory.Entry,
	database runtimeDatabase,
) (memberOfRuntimeConfiguration, error) {
	if databaseType(database.name) == "frontend" {
		return memberOfRuntimeConfiguration{}, fmt.Errorf(
			"%s memberof overlay cannot be global",
			entry.DN,
		)
	}
	if len(database.suffixes) == 0 {
		return memberOfRuntimeConfiguration{}, fmt.Errorf(
			"%s memberof overlay requires a database suffix",
			entry.DN,
		)
	}

	configuration := memberOfRuntimeConfiguration{
		dangling:          memberOfDanglingIgnore,
		danglingError:     ldapwire.ResultConstraintViolation,
		groupObjectClass:  "groupOfNames",
		memberAttribute:   "member",
		memberOfAttribute: "memberOf",
	}
	var err error
	configuration.groupObjectClass, err = memberOfSingleString(
		entry,
		"olcMemberOfGroupOC",
		configuration.groupObjectClass,
	)
	if err != nil {
		return memberOfRuntimeConfiguration{}, err
	}
	configuration.memberAttribute, err = memberOfSingleString(
		entry,
		"olcMemberOfMemberAD",
		configuration.memberAttribute,
	)
	if err != nil {
		return memberOfRuntimeConfiguration{}, err
	}
	configuration.memberOfAttribute, err = memberOfSingleString(
		entry,
		"olcMemberOfMemberOfAD",
		configuration.memberOfAttribute,
	)
	if err != nil {
		return memberOfRuntimeConfiguration{}, err
	}

	modifierValues := entry.Values("olcMemberOfDN")
	if len(modifierValues) > 1 {
		return memberOfRuntimeConfiguration{}, fmt.Errorf(
			"%s olcMemberOfDN must be single-valued",
			entry.DN,
		)
	}
	if len(modifierValues) == 1 {
		modifier, parseErr := directory.ParseDN(string(modifierValues[0]))
		if parseErr != nil {
			return memberOfRuntimeConfiguration{}, fmt.Errorf(
				"%s olcMemberOfDN: %w",
				entry.DN,
				parseErr,
			)
		}
		configuration.modifierDN = &modifier
	}

	dangling, err := memberOfSingleString(
		entry,
		"olcMemberOfDangling",
		"ignore",
	)
	if err != nil {
		return memberOfRuntimeConfiguration{}, err
	}
	switch strings.ToLower(dangling) {
	case "ignore":
		configuration.dangling = memberOfDanglingIgnore
	case "drop":
		configuration.dangling = memberOfDanglingDrop
	case "error":
		configuration.dangling = memberOfDanglingError
	default:
		return memberOfRuntimeConfiguration{}, fmt.Errorf(
			"%s olcMemberOfDangling has invalid value %q",
			entry.DN,
			dangling,
		)
	}
	danglingError, err := memberOfSingleString(
		entry,
		"olcMemberOfDanglingError",
		"constraintViolation",
	)
	if err != nil {
		return memberOfRuntimeConfiguration{}, err
	}
	configuration.danglingError, err = parseMemberOfResultCode(danglingError)
	if err != nil {
		return memberOfRuntimeConfiguration{}, fmt.Errorf(
			"%s olcMemberOfDanglingError: %w",
			entry.DN,
			err,
		)
	}
	configuration.refint, _, err = singleBoolean(entry, "olcMemberOfRefInt")
	if err != nil {
		return memberOfRuntimeConfiguration{}, err
	}
	configuration.addCheck, _, err = singleBoolean(entry, "olcMemberOfAddCheck")
	if err != nil {
		return memberOfRuntimeConfiguration{}, err
	}
	if len(entry.Values("olcMemberOfReverse")) > 0 {
		return memberOfRuntimeConfiguration{}, fmt.Errorf(
			"%s olcMemberOfReverse is not enabled by OpenLDAP 2.6",
			entry.DN,
		)
	}
	return configuration, nil
}

func memberOfSingleString(
	entry directory.Entry,
	description,
	fallback string,
) (string, error) {
	values := entry.Values(description)
	if len(values) == 0 {
		return fallback, nil
	}
	if len(values) != 1 {
		return "", fmt.Errorf(
			"%s %s must be single-valued",
			entry.DN,
			description,
		)
	}
	value := strings.TrimSpace(string(values[0]))
	if value == "" {
		return "", fmt.Errorf("%s %s must not be empty", entry.DN, description)
	}
	return value, nil
}

func parseMemberOfResultCode(value string) (ldapwire.ResultCode, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if code, found := memberOfResultCodes[normalized]; found {
		return code, nil
	}
	numeric, err := strconv.ParseInt(normalized, 0, 32)
	if err != nil || numeric < 0 {
		return 0, fmt.Errorf("invalid LDAP result code %q", value)
	}
	return ldapwire.ResultCode(numeric), nil
}

var memberOfResultCodes = map[string]ldapwire.ResultCode{
	"success":                      ldapwire.ResultSuccess,
	"operationserror":              ldapwire.ResultOperationsError,
	"protocolerror":                ldapwire.ResultProtocolError,
	"timelimitexceeded":            ldapwire.ResultTimeLimitExceeded,
	"sizelimitexceeded":            ldapwire.ResultSizeLimitExceeded,
	"comparefalse":                 ldapwire.ResultCompareFalse,
	"comparetrue":                  ldapwire.ResultCompareTrue,
	"authmethodnotsupported":       ldapwire.ResultAuthMethodNotSupported,
	"strongauthrequired":           ldapwire.ResultStrongerAuthRequired,
	"strongerauthrequired":         ldapwire.ResultStrongerAuthRequired,
	"referral":                     ldapwire.ResultReferral,
	"adminlimitexceeded":           ldapwire.ResultAdminLimitExceeded,
	"unavailablecriticalextension": ldapwire.ResultUnavailableCriticalExtension,
	"confidentialityrequired":      ldapwire.ResultConfidentialityRequired,
	"saslbindinprogress":           ldapwire.ResultSASLBindInProgress,
	"nosuchattribute":              ldapwire.ResultNoSuchAttribute,
	"undefinedtype":                ldapwire.ResultUndefinedAttributeType,
	"inappropriatematching":        ldapwire.ResultInappropriateMatching,
	"constraintviolation":          ldapwire.ResultConstraintViolation,
	"typeorvalueexists":            ldapwire.ResultAttributeOrValueExists,
	"invalidsyntax":                ldapwire.ResultInvalidAttributeSyntax,
	"nosuchobject":                 ldapwire.ResultNoSuchObject,
	"aliasproblem":                 ldapwire.ResultAliasProblem,
	"invaliddnsyntax":              ldapwire.ResultInvalidDNSyntax,
	"aliasderefproblem":            ldapwire.ResultAliasDereferencingProblem,
	"inappropriateauth":            ldapwire.ResultInappropriateAuthentication,
	"invalidcredentials":           ldapwire.ResultInvalidCredentials,
	"insufficientaccess":           ldapwire.ResultInsufficientAccessRights,
	"busy":                         ldapwire.ResultBusy,
	"unavailable":                  ldapwire.ResultUnavailable,
	"unwillingtoperform":           ldapwire.ResultUnwillingToPerform,
	"loopdetect":                   ldapwire.ResultLoopDetect,
	"namingviolation":              ldapwire.ResultNamingViolation,
	"objectclassviolation":         ldapwire.ResultObjectClassViolation,
	"notallowedonnonleaf":          ldapwire.ResultNotAllowedOnNonLeaf,
	"notallowedonrdn":              ldapwire.ResultNotAllowedOnRDN,
	"alreadyexists":                ldapwire.ResultEntryAlreadyExists,
	"noobjectclassmods":            ldapwire.ResultObjectClassModsProhibited,
	"affectsmultipledsas":          ldapwire.ResultAffectsMultipleDSAs,
	"other":                        ldapwire.ResultOther,
	"cancelled":                    ldapwire.ResultCanceled,
	"nosuchoperation":              ldapwire.ResultNoSuchOperation,
	"toolate":                      ldapwire.ResultTooLate,
	"cannotcancel":                 ldapwire.ResultCannotCancel,
	"assertionfailed":              ldapwire.ResultAssertionFailed,
	"proxiedauthorizationdenied":   ldapwire.ResultProxiedAuthorizationDenied,
	"syncrefreshrequired":          ldapwire.ResultSyncRefreshRequired,
}

func validateMemberOfSchema(
	registry *schema.Registry,
	configurations []memberOfRuntimeConfiguration,
) error {
	for _, configuration := range configurations {
		if _, found := registry.ObjectClass(configuration.groupObjectClass); !found {
			return fmt.Errorf(
				"undefined group objectClass %q",
				configuration.groupObjectClass,
			)
		}
		for _, attribute := range []string{
			configuration.memberAttribute,
			configuration.memberOfAttribute,
		} {
			if _, found := registry.AttributeType(attribute); !found {
				return fmt.Errorf("undefined attribute type %q", attribute)
			}
			if !registry.IsDNReferenceValued(attribute) {
				return fmt.Errorf(
					"attribute %q is not DN or nameAndOptionalUID-valued",
					attribute,
				)
			}
		}
	}
	return nil
}

func prepareMemberOfAdd(
	runtime *runtimeState,
	reader storage.Reader,
	database runtimeDatabase,
	dn directory.DN,
	entry *directory.Entry,
	relax bool,
) error {
	for _, configuration := range database.memberOf {
		if configuration.addCheck {
			if err := memberOfAddCheck(
				runtime,
				reader,
				database,
				dn,
				entry,
				configuration,
			); err != nil {
				return err
			}
		}
		if relax || configuration.dangling == memberOfDanglingIgnore ||
			!runtime.schema.EntryHasObjectClass(*entry, configuration.groupObjectClass) {
			continue
		}
		if err := filterMemberOfDanglingEntry(
			runtime.schema,
			reader,
			dn,
			entry,
			configuration,
		); err != nil {
			return err
		}
	}
	return nil
}

func prepareMemberOfModify(
	runtime *runtimeState,
	reader storage.Reader,
	database runtimeDatabase,
	dn directory.DN,
	before directory.Entry,
	changes []ldapwire.Modification,
	relax bool,
) ([]ldapwire.Modification, error) {
	prepared := cloneLDAPModifications(changes)
	if relax {
		return prepared, nil
	}
	for _, configuration := range database.memberOf {
		if configuration.dangling == memberOfDanglingIgnore ||
			!runtime.schema.EntryHasObjectClass(before, configuration.groupObjectClass) {
			continue
		}
		filtered := prepared[:0]
		for _, change := range prepared {
			if !runtime.schema.AttributeDescriptionSubtype(
				change.Attribute.Description,
				configuration.memberAttribute,
			) || (change.Operation != ldapwire.ModificationAdd &&
				change.Operation != ldapwire.ModificationReplace) ||
				len(change.Attribute.Values) == 0 {
				filtered = append(filtered, change)
				continue
			}
			values, err := filterMemberOfDanglingValues(
				reader,
				dn,
				change.Attribute.Values,
				configuration,
			)
			if err != nil {
				return nil, err
			}
			if len(values) == 0 && configuration.dangling == memberOfDanglingDrop {
				continue
			}
			change.Attribute.Values = values
			filtered = append(filtered, change)
		}
		prepared = filtered
	}
	return prepared, nil
}

func cloneLDAPModifications(changes []ldapwire.Modification) []ldapwire.Modification {
	cloned := make([]ldapwire.Modification, len(changes))
	for index, change := range changes {
		cloned[index] = ldapwire.Modification{
			Operation: change.Operation,
			Attribute: directory.Attribute{
				Description: change.Attribute.Description,
				Values:      make([][]byte, len(change.Attribute.Values)),
			},
		}
		for valueIndex, value := range change.Attribute.Values {
			cloned[index].Attribute.Values[valueIndex] = bytes.Clone(value)
		}
	}
	return cloned
}

func memberOfAddCheck(
	runtime *runtimeState,
	reader storage.Reader,
	database runtimeDatabase,
	dn directory.DN,
	entry *directory.Entry,
	configuration memberOfRuntimeConfiguration,
) error {
	base := database.suffixes[0]
	return reader.ForEach(func(candidate directory.Entry) error {
		candidateDN, err := directory.ParseDN(candidate.DN)
		if err != nil {
			return err
		}
		if !directory.InScope(base, candidateDN, directory.ScopeWholeSubtree) ||
			candidateDN.Equal(dn) ||
			!entryHasDNReference(
				runtime.schema,
				candidate,
				configuration.memberAttribute,
				dn,
			) {
			return nil
		}
		addDNReference(
			runtime.schema,
			entry,
			configuration.memberOfAttribute,
			candidateDN,
		)
		return nil
	})
}

func filterMemberOfDanglingEntry(
	registry *schema.Registry,
	reader storage.Reader,
	self directory.DN,
	entry *directory.Entry,
	configuration memberOfRuntimeConfiguration,
) error {
	attributes := entry.Attributes[:0]
	for _, attribute := range entry.Attributes {
		if !registry.AttributeDescriptionSubtype(
			attribute.Description,
			configuration.memberAttribute,
		) {
			attributes = append(attributes, attribute)
			continue
		}
		values, err := filterMemberOfDanglingValues(
			reader,
			self,
			attribute.Values,
			configuration,
		)
		if err != nil {
			return err
		}
		if len(values) == 0 && configuration.dangling == memberOfDanglingDrop {
			continue
		}
		attribute.Values = values
		attributes = append(attributes, attribute)
	}
	entry.Attributes = attributes
	return nil
}

func filterMemberOfDanglingValues(
	reader storage.Reader,
	self directory.DN,
	values [][]byte,
	configuration memberOfRuntimeConfiguration,
) ([][]byte, error) {
	filtered := make([][]byte, 0, len(values))
	for _, value := range values {
		target, err := directory.ParseDN(string(value))
		if err != nil {
			filtered = append(filtered, bytes.Clone(value))
			continue
		}
		if target.Equal(self) {
			filtered = append(filtered, bytes.Clone(value))
			continue
		}
		_, err = reader.Get(target)
		switch {
		case err == nil:
			filtered = append(filtered, bytes.Clone(value))
		case errors.Is(err, storage.ErrEntryNotFound):
			if configuration.dangling == memberOfDanglingError {
				return nil, operationFailed(
					configuration.danglingError,
					"adding non-existing object as group member",
				)
			}
		case err != nil:
			return nil, err
		}
	}
	return filtered, nil
}

func applyMemberOfAdd(
	runtime *runtimeState,
	writer storage.Writer,
	database runtimeDatabase,
	entry directory.Entry,
) error {
	groupDN, err := directory.ParseDN(entry.DN)
	if err != nil {
		return err
	}
	for _, configuration := range database.memberOf {
		if !runtime.schema.EntryHasObjectClass(entry, configuration.groupObjectClass) {
			continue
		}
		for _, memberDN := range memberOfDNValues(
			runtime.schema,
			entry,
			configuration.memberAttribute,
		) {
			if memberDN.Equal(groupDN) {
				continue
			}
			if err := updateMemberOfDNReference(
				runtime,
				writer,
				database,
				configuration,
				memberDN,
				configuration.memberOfAttribute,
				nil,
				&groupDN,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyMemberOfModify(
	runtime *runtimeState,
	writer storage.Writer,
	database runtimeDatabase,
	before,
	after directory.Entry,
) error {
	groupDN, err := directory.ParseDN(after.DN)
	if err != nil {
		return err
	}
	for _, configuration := range database.memberOf {
		oldMembers := memberOfGroupMembers(runtime.schema, before, configuration)
		newMembers := memberOfGroupMembers(runtime.schema, after, configuration)
		for key, memberDN := range oldMembers {
			if _, retained := newMembers[key]; retained || memberDN.Equal(groupDN) {
				continue
			}
			if err := updateMemberOfDNReference(
				runtime,
				writer,
				database,
				configuration,
				memberDN,
				configuration.memberOfAttribute,
				&groupDN,
				nil,
			); err != nil {
				return err
			}
		}
		for key, memberDN := range newMembers {
			if _, existed := oldMembers[key]; existed || memberDN.Equal(groupDN) {
				continue
			}
			if err := updateMemberOfDNReference(
				runtime,
				writer,
				database,
				configuration,
				memberDN,
				configuration.memberOfAttribute,
				nil,
				&groupDN,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyMemberOfDelete(
	runtime *runtimeState,
	writer storage.Writer,
	database runtimeDatabase,
	entry directory.Entry,
) error {
	entryDN, err := directory.ParseDN(entry.DN)
	if err != nil {
		return err
	}
	for _, configuration := range database.memberOf {
		for _, memberDN := range memberOfGroupMembers(runtime.schema, entry, configuration) {
			if memberDN.Equal(entryDN) {
				continue
			}
			if err := updateMemberOfDNReference(
				runtime,
				writer,
				database,
				configuration,
				memberDN,
				configuration.memberOfAttribute,
				&entryDN,
				nil,
			); err != nil {
				return err
			}
		}
		if !configuration.refint {
			continue
		}
		for _, groupDN := range memberOfDNValues(
			runtime.schema,
			entry,
			configuration.memberOfAttribute,
		) {
			if groupDN.Equal(entryDN) {
				continue
			}
			if err := updateMemberOfDNReference(
				runtime,
				writer,
				database,
				configuration,
				groupDN,
				configuration.memberAttribute,
				&entryDN,
				nil,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyMemberOfModifyDN(
	runtime *runtimeState,
	writer storage.Writer,
	database runtimeDatabase,
	oldDN,
	newDN directory.DN,
	after directory.Entry,
) error {
	for _, configuration := range database.memberOf {
		if runtime.schema.EntryHasObjectClass(after, configuration.groupObjectClass) {
			for _, memberDN := range memberOfDNValues(
				runtime.schema,
				after,
				configuration.memberAttribute,
			) {
				if memberDN.Equal(oldDN) || memberDN.Equal(newDN) {
					continue
				}
				if err := updateMemberOfDNReference(
					runtime,
					writer,
					database,
					configuration,
					memberDN,
					configuration.memberOfAttribute,
					&oldDN,
					&newDN,
				); err != nil {
					return err
				}
			}
		}
		if !configuration.refint ||
			!runtime.schema.HasAttributeDescription(after, configuration.memberOfAttribute) {
			continue
		}
		for _, groupDN := range memberOfDNValues(
			runtime.schema,
			after,
			configuration.memberOfAttribute,
		) {
			if groupDN.Equal(oldDN) || groupDN.Equal(newDN) {
				continue
			}
			if err := updateMemberOfDNReference(
				runtime,
				writer,
				database,
				configuration,
				groupDN,
				configuration.memberAttribute,
				&oldDN,
				&newDN,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func memberOfGroupMembers(
	registry *schema.Registry,
	entry directory.Entry,
	configuration memberOfRuntimeConfiguration,
) map[string]directory.DN {
	if !registry.EntryHasObjectClass(entry, configuration.groupObjectClass) {
		return nil
	}
	result := make(map[string]directory.DN)
	for _, dn := range memberOfDNValues(registry, entry, configuration.memberAttribute) {
		result[dn.Key()] = dn
	}
	return result
}

func memberOfDNValues(
	registry *schema.Registry,
	entry directory.Entry,
	description string,
) []directory.DN {
	values := registry.AttributeValues(entry, description)
	result := make([]directory.DN, 0, len(values))
	for _, value := range values {
		dn, err := directory.ParseDN(string(value))
		if err == nil {
			result = append(result, dn)
		}
	}
	return result
}

func entryHasDNReference(
	registry *schema.Registry,
	entry directory.Entry,
	description string,
	target directory.DN,
) bool {
	for _, candidate := range memberOfDNValues(registry, entry, description) {
		if candidate.Equal(target) {
			return true
		}
	}
	return false
}

func addDNReference(
	registry *schema.Registry,
	entry *directory.Entry,
	description string,
	value directory.DN,
) bool {
	return mutateDNReference(registry, entry, description, nil, &value)
}

func mutateDNReference(
	registry *schema.Registry,
	entry *directory.Entry,
	description string,
	oldDN,
	newDN *directory.DN,
) bool {
	if oldDN != nil && newDN != nil && oldDN.Equal(*newDN) {
		return false
	}
	changed := false
	hasNew := false
	attributes := entry.Attributes[:0]
	for _, attribute := range entry.Attributes {
		if !registry.AttributeDescriptionSubtype(attribute.Description, description) {
			attributes = append(attributes, attribute)
			continue
		}
		values := attribute.Values[:0]
		for _, value := range attribute.Values {
			parsed, err := directory.ParseDN(string(value))
			if err == nil && newDN != nil && parsed.Equal(*newDN) {
				hasNew = true
			}
			if err == nil && oldDN != nil && parsed.Equal(*oldDN) {
				changed = true
				continue
			}
			values = append(values, value)
		}
		attribute.Values = values
		if len(attribute.Values) > 0 {
			attributes = append(attributes, attribute)
		}
	}
	entry.Attributes = attributes
	if newDN != nil && !hasNew {
		_ = entry.AddValues(description, [][]byte{[]byte(newDN.String())})
		changed = true
	}
	return changed
}

func updateMemberOfDNReference(
	runtime *runtimeState,
	writer storage.Writer,
	database runtimeDatabase,
	configuration memberOfRuntimeConfiguration,
	targetDN directory.DN,
	description string,
	oldDN,
	newDN *directory.DN,
) error {
	entry, err := writer.Get(targetDN)
	if errors.Is(err, storage.ErrEntryNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !mutateDNReference(runtime.schema, &entry, description, oldDN, newDN) {
		return nil
	}
	modifier := configuration.modifierDN
	if modifier == nil {
		modifier = database.rootDN
	}
	if modifier != nil {
		entry.ReplaceValues("modifiersName", stringValues(modifier.String()))
	}
	if err := runtime.schema.ValidateEntry(entry); err != nil {
		return nil
	}
	return writer.Put(entry, true)
}
