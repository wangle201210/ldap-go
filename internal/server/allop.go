package server

import (
	"slices"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func applyAllOperationalAttributesOverlay(
	runtime *runtimeState,
	request ldapwire.SearchRequest,
) ldapwire.SearchRequest {
	if runtime == nil || request.Scope != directory.ScopeBase || request.BaseDN != "" ||
		!runtimeFrontendAllop(runtime.databases) ||
		slices.ContainsFunc(request.Attributes, func(value string) bool {
			return strings.EqualFold(value, "+")
		}) || !allopRequestsUserAttributes(runtime, request.Attributes) {
		return request
	}
	attributes := append([]string(nil), request.Attributes...)
	if len(attributes) == 0 {
		attributes = append(attributes, "*")
	}
	request.Attributes = append(attributes, "+")
	return request
}

func runtimeFrontendAllop(databases []runtimeDatabase) bool {
	for _, database := range databases {
		if databaseType(database.name) == "frontend" {
			return database.allOperationalAttrs
		}
	}
	return false
}

func allopRequestsUserAttributes(runtime *runtimeState, attributes []string) bool {
	if len(attributes) == 0 {
		return true
	}
	for _, attribute := range attributes {
		if attribute == "*" {
			return true
		}
		if attribute == "1.1" || attribute == "+" ||
			runtime.schema.IsOperational(attribute) {
			continue
		}
		return true
	}
	return false
}
