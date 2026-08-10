package server

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
)

var sockManageableOperationalAttributes = map[string]struct{}{
	"1.3.6.1.1.16.4":             {}, // entryUUID
	"1.3.6.1.4.1.1466.101.119.3": {}, // entryTtl
	"2.5.18.1":                   {}, // createTimestamp
	"2.5.18.2":                   {}, // modifyTimestamp
	"2.5.18.3":                   {}, // creatorsName
	"2.5.18.4":                   {}, // modifiersName
}

func sockBackendControlSupport(request ldapwire.Request) requestControlSupport {
	switch request.(type) {
	case ldapwire.AddRequest,
		ldapwire.ModifyRequest,
		ldapwire.DeleteRequest,
		ldapwire.ModifyDNRequest:
		return supportsRelax
	case ldapwire.SearchRequest, ldapwire.CompareRequest:
		return supportsDontUseCopy
	default:
		return 0
	}
}

func validateSockBackendFrontend(
	runtime *runtimeState,
	database runtimeDatabase,
	request ldapwire.Request,
	controls requestControls,
) (ldapwire.Request, *ldapwire.Result) {
	switch request := request.(type) {
	case ldapwire.AddRequest:
		return request, validateSockAddRequest(
			runtime.schema,
			database,
			request,
			controls.relax,
		)
	case ldapwire.ModifyRequest:
		return request, validateSockModifyRequest(
			runtime.schema,
			database,
			request,
			controls.relax,
		)
	case ldapwire.CompareRequest:
		normalized, failure := validateSockCompareRequest(runtime.schema, request)
		if failure != nil {
			return normalized, failure
		}
		if controls.dontUseCopy && database.shadow {
			return normalized, sockFrontendResult(
				ldapwire.ResultUnwillingToPerform,
				"copy not used",
			)
		}
		return normalized, validateSockCompareTarget(runtime.schema, normalized)
	case ldapwire.ModifyDNRequest:
		return request, validateSockModifyDNRequest(runtime, database, request)
	case ldapwire.SearchRequest:
		if controls.dontUseCopy && database.shadow {
			target, err := directory.ParseDN(request.BaseDN)
			if err != nil {
				return request, sockFrontendResult(
					ldapwire.ResultInvalidDNSyntax,
					"invalid DN",
				)
			}
			result := shadowSearchResult(database, target, request.Scope)
			return request, &result
		}
		return request, nil
	default:
		return request, nil
	}
}

func validateSockAddRequest(
	registry *schema.Registry,
	database runtimeDatabase,
	request ldapwire.AddRequest,
	relax bool,
) *ldapwire.Result {
	if len(request.Entry.Attributes) == 0 {
		return sockFrontendResult(
			ldapwire.ResultProtocolError,
			"no attributes provided",
		)
	}

	types := make([]schema.AttributeType, len(request.Entry.Attributes))
	for index, attribute := range request.Entry.Attributes {
		attributeType, failure := validateSockModificationValues(
			registry,
			ldapwire.ModificationAdd,
			attribute,
		)
		if failure != nil {
			return failure
		}
		types[index] = attributeType
	}
	for index, attribute := range request.Entry.Attributes {
		if failure := validateSockObsoleteAttribute(
			types[index],
			attribute,
			ldapwire.ModificationAdd,
			relax,
		); failure != nil {
			return failure
		}
	}
	if database.updateDN == nil {
		for index, attribute := range request.Entry.Attributes {
			if failure := validateSockNoUserModification(
				registry,
				types[index],
				attribute.Description,
				relax,
			); failure != nil {
				return failure
			}
		}
	}

	seen := make(map[string]struct{}, len(request.Entry.Attributes))
	for _, attribute := range request.Entry.Attributes {
		key, err := sockCanonicalAttributeDescription(registry, attribute.Description)
		if err != nil {
			return sockFrontendResult(ldapwire.ResultOther, err.Error())
		}
		if _, duplicate := seen[key]; duplicate {
			return sockFrontendResult(
				ldapwire.ResultAttributeOrValueExists,
				fmt.Sprintf("attribute '%s' provided more than once", attribute.Description),
			)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateSockModifyRequest(
	registry *schema.Registry,
	database runtimeDatabase,
	request ldapwire.ModifyRequest,
	relax bool,
) *ldapwire.Result {
	for _, change := range request.Changes {
		switch change.Operation {
		case ldapwire.ModificationAdd:
			if len(change.Attribute.Values) == 0 {
				return sockFrontendResult(
					ldapwire.ResultProtocolError,
					"modify/add operation requires values",
				)
			}
		case ldapwire.ModificationIncrement:
			if len(change.Attribute.Values) == 0 {
				return sockFrontendResult(
					ldapwire.ResultProtocolError,
					"modify/increment operation requires value",
				)
			}
			if len(change.Attribute.Values) != 1 {
				return sockFrontendResult(
					ldapwire.ResultProtocolError,
					"modify/increment operation requires single value",
				)
			}
		case ldapwire.ModificationDelete, ldapwire.ModificationReplace:
		default:
			return sockFrontendResult(
				ldapwire.ResultProtocolError,
				"unrecognized modify operation",
			)
		}
	}

	types := make([]schema.AttributeType, len(request.Changes))
	for index, change := range request.Changes {
		attributeType, failure := validateSockModificationValues(
			registry,
			change.Operation,
			change.Attribute,
		)
		if failure != nil {
			return failure
		}
		types[index] = attributeType
	}
	for index, change := range request.Changes {
		if failure := validateSockObsoleteAttribute(
			types[index],
			change.Attribute,
			change.Operation,
			relax,
		); failure != nil {
			return failure
		}
	}
	for _, change := range request.Changes {
		if change.Operation == ldapwire.ModificationIncrement {
			return sockFrontendResult(
				ldapwire.ResultUnwillingToPerform,
				"modify/increment not supported in context",
			)
		}
	}
	if database.updateDN == nil {
		for index, change := range request.Changes {
			if failure := validateSockNoUserModification(
				registry,
				types[index],
				change.Attribute.Description,
				relax,
			); failure != nil {
				return failure
			}
		}
	}
	return nil
}

func validateSockModificationValues(
	registry *schema.Registry,
	operation ldapwire.ModificationOperation,
	attribute directory.Attribute,
) (schema.AttributeType, *ldapwire.Result) {
	attributeType, found, err := registry.EffectiveAttributeType(attribute.Description)
	if err != nil {
		return schema.AttributeType{}, sockFrontendResult(
			ldapwire.ResultOther,
			err.Error(),
		)
	}
	if !found {
		return schema.AttributeType{}, sockFrontendResult(
			ldapwire.ResultUndefinedAttributeType,
			attribute.Description+": attribute type undefined",
		)
	}
	if operation == ldapwire.ModificationIncrement &&
		attributeType.Syntax != schema.SyntaxInteger {
		return schema.AttributeType{}, sockFrontendResult(
			ldapwire.ResultConstraintViolation,
			attribute.Description+": attribute syntax inappropriate for increment",
		)
	}
	for index, value := range attribute.Values {
		if err := registry.ValidateAttributeValue(attribute.Description, value); err != nil {
			return schema.AttributeType{}, sockFrontendResult(
				ldapwire.ResultInvalidAttributeSyntax,
				fmt.Sprintf(
					"%s: value #%d invalid per syntax",
					attribute.Description,
					index,
				),
			)
		}
	}
	if (operation == ldapwire.ModificationAdd ||
		operation == ldapwire.ModificationReplace) &&
		attributeType.SingleValue && len(attribute.Values) > 1 {
		return schema.AttributeType{}, sockFrontendResult(
			ldapwire.ResultConstraintViolation,
			attribute.Description+": multiple values provided",
		)
	}
	if operation != ldapwire.ModificationDelete {
		if failure := validateSockDuplicateValues(registry, attribute); failure != nil {
			return schema.AttributeType{}, failure
		}
	}
	return attributeType, nil
}

func validateSockDuplicateValues(
	registry *schema.Registry,
	attribute directory.Attribute,
) *ldapwire.Result {
	normalized := make([][]byte, 0, len(attribute.Values))
	for index, value := range attribute.Values {
		candidate, err := registry.NormalizeEqualityValue(attribute.Description, value)
		if err != nil {
			return sockFrontendResult(
				ldapwire.ResultInvalidAttributeSyntax,
				fmt.Sprintf(
					"%s: value #%d normalization failed",
					attribute.Description,
					index,
				),
			)
		}
		for _, previous := range normalized {
			if bytes.Equal(previous, candidate) {
				return sockFrontendResult(
					ldapwire.ResultAttributeOrValueExists,
					fmt.Sprintf(
						"%s: value #%d provided more than once",
						attribute.Description,
						index,
					),
				)
			}
		}
		normalized = append(normalized, candidate)
	}
	return nil
}

func validateSockObsoleteAttribute(
	attributeType schema.AttributeType,
	attribute directory.Attribute,
	operation ldapwire.ModificationOperation,
	relax bool,
) *ldapwire.Result {
	if relax || !attributeType.Obsolete {
		return nil
	}
	removal := (operation == ldapwire.ModificationReplace ||
		operation == ldapwire.ModificationDelete) &&
		len(attribute.Values) == 0
	if removal {
		return nil
	}
	return sockFrontendResult(
		ldapwire.ResultConstraintViolation,
		attribute.Description+": attribute is obsolete",
	)
}

func validateSockNoUserModification(
	registry *schema.Registry,
	attributeType schema.AttributeType,
	description string,
	relax bool,
) *ldapwire.Result {
	if !attributeType.NoUserModification {
		return nil
	}
	if relax && sockAttributeIsManageable(registry, attributeType, description) {
		return nil
	}
	diagnostic := description + ": no user modification allowed"
	if relax {
		diagnostic = description + ": no-user-modification attribute not manageable"
	}
	return sockFrontendResult(ldapwire.ResultConstraintViolation, diagnostic)
}

func sockAttributeIsManageable(
	registry *schema.Registry,
	attributeType schema.AttributeType,
	description string,
) bool {
	if _, found := sockManageableOperationalAttributes[strings.ToLower(attributeType.OID)]; found {
		return true
	}
	return isManageablePasswordPolicyOperationalAttribute(registry, description)
}

func validateSockCompareRequest(
	registry *schema.Registry,
	request ldapwire.CompareRequest,
) (ldapwire.CompareRequest, *ldapwire.Result) {
	attributeType, found, err := registry.EffectiveAttributeType(request.Attribute)
	if err != nil {
		return request, sockFrontendResult(ldapwire.ResultOther, err.Error())
	}
	if !found {
		return request, sockFrontendResult(ldapwire.ResultUndefinedAttributeType, "")
	}
	if attributeType.Equality == "" {
		return request, sockFrontendResult(
			ldapwire.ResultInappropriateMatching,
			"inappropriate matching request",
		)
	}
	normalized, err := registry.NormalizeEqualityAssertion(
		request.Attribute,
		request.Assertion,
	)
	if err != nil {
		return request, sockFrontendResult(
			ldapwire.ResultInvalidAttributeSyntax,
			"value does not conform to assertion syntax",
		)
	}
	request.Assertion = normalized
	return request, nil
}

func validateSockCompareTarget(
	registry *schema.Registry,
	request ldapwire.CompareRequest,
) *ldapwire.Result {
	attributeType, found, err := registry.EffectiveAttributeType(request.Attribute)
	if err != nil {
		return sockFrontendResult(ldapwire.ResultOther, err.Error())
	}
	if !found {
		return sockFrontendResult(ldapwire.ResultUndefinedAttributeType, "")
	}
	switch strings.ToLower(attributeType.OID) {
	case "1.3.6.1.1.20":
		return sockFrontendResult(
			ldapwire.ResultUnwillingToPerform,
			"entryDN compare not supported",
		)
	case "2.5.18.10":
		return sockFrontendResult(
			ldapwire.ResultUnwillingToPerform,
			"subschemaSubentry compare not supported",
		)
	default:
		return nil
	}
}

func validateSockModifyDNRequest(
	runtime *runtimeState,
	database runtimeDatabase,
	request ldapwire.ModifyDNRequest,
) *ldapwire.Result {
	oldDN, err := directory.ParseDN(request.DN)
	if err != nil || oldDN.Depth() == 0 {
		return sockFrontendResult(ldapwire.ResultInvalidDNSyntax, "invalid DN")
	}

	var superior directory.DN
	if request.HasNewSuperior {
		superior, err = directory.ParseDN(request.NewSuperior)
		if err != nil {
			return sockFrontendResult(
				ldapwire.ResultInvalidDNSyntax,
				"invalid newSuperior",
			)
		}
	} else {
		var found bool
		superior, found = oldDN.Parent()
		if !found {
			return sockFrontendResult(
				ldapwire.ResultUnwillingToPerform,
				"cannot rename the root DSE",
			)
		}
	}
	newDN, err := directory.ComposeDN(request.NewRDN, superior)
	if err != nil {
		return sockFrontendResult(
			ldapwire.ResultInvalidDNSyntax,
			"invalid new RDN",
		)
	}
	if failure := validateSockNamingRDN(runtime.schema, newDN); failure != nil {
		return failure
	}
	if request.DeleteOldRDN {
		if failure := validateSockNamingRDN(runtime.schema, oldDN); failure != nil {
			return failure
		}
	}
	if oldDN.AncestorOf(newDN) {
		return sockFrontendResult(
			ldapwire.ResultUnwillingToPerform,
			"cannot place an entry below itself",
		)
	}
	if newDN.AncestorOf(oldDN) {
		return sockFrontendResult(
			ldapwire.ResultUnwillingToPerform,
			"cannot place an entry above itself",
		)
	}
	destination := databaseForDN(runtime, newDN)
	if destination == nil || destination.configDNKey != database.configDNKey {
		return sockFrontendResult(
			ldapwire.ResultAffectsMultipleDSAs,
			"cannot rename between DSAs",
		)
	}
	return nil
}

func validateSockNamingRDN(
	registry *schema.Registry,
	dn directory.DN,
) *ldapwire.Result {
	for _, value := range dn.RDNValues() {
		attributeType, found, err := registry.EffectiveAttributeType(value.Type)
		if err != nil {
			return sockFrontendResult(ldapwire.ResultOther, err.Error())
		}
		if !found {
			return sockFrontendResult(
				ldapwire.ResultUndefinedAttributeType,
				value.Type+": attribute type undefined",
			)
		}
		if attributeType.Equality == "" {
			return sockFrontendResult(
				ldapwire.ResultNamingViolation,
				"naming attribute has no equality matching rule",
			)
		}
		if err := registry.ValidateAttributeValue(value.Type, value.Value); err != nil {
			return sockFrontendResult(
				ldapwire.ResultInvalidAttributeSyntax,
				"value does not conform to assertion syntax",
			)
		}
		if _, err := registry.NormalizeEqualityValue(value.Type, value.Value); err != nil {
			return sockFrontendResult(
				ldapwire.ResultInvalidAttributeSyntax,
				"unable to normalize value for matching",
			)
		}
	}
	return nil
}

func sockCanonicalAttributeDescription(
	registry *schema.Registry,
	description string,
) (string, error) {
	parts := strings.Split(description, ";")
	attributeType, found, err := registry.EffectiveAttributeType(parts[0])
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("undefined attribute type %q", description)
	}
	options := make([]string, 0, len(parts)-1)
	for _, option := range parts[1:] {
		options = append(options, strings.ToLower(option))
	}
	sort.Strings(options)
	return strings.ToLower(attributeType.OID) + ";" + strings.Join(options, ";"), nil
}

func sockFrontendResult(
	code ldapwire.ResultCode,
	diagnostic string,
) *ldapwire.Result {
	result := ldapwire.ResultError(code, diagnostic)
	return &result
}
