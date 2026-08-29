package webadmin

import (
	"net/http"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

var rootDSEAttributes = []string{
	"*", "+", "altServer", "namingContexts", "supportedControl",
	"supportedExtension", "supportedFeatures", "supportedLDAPVersion",
	"supportedSASLMechanisms", "subschemaSubentry", "vendorName", "vendorVersion",
}

var schemaAttributes = []string{
	"attributeTypes", "objectClasses", "ldapSyntaxes", "matchingRules",
	"matchingRuleUse", "nameForms", "dITContentRules", "dITStructureRules",
}

type schemaSummaryResponse struct {
	DN          string              `json:"dn"`
	Counts      map[string]int      `json:"counts"`
	Definitions map[string][]string `json:"definitions"`
}

type monitorSummaryResponse struct {
	BaseDN  string          `json:"base_dn"`
	Entries []entryResponse `json:"entries"`
}

func (application *Application) handleRootDSE(response http.ResponseWriter, request *http.Request) {
	if !methodAllowed(response, request, http.MethodGet) {
		return
	}
	current, ok := application.acquireSession(response, request)
	if !ok {
		return
	}
	defer application.releaseSession(current)
	result, release, err := application.search(current.client, ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
		application.config.MaxSearchSeconds, false, "(objectClass=*)", rootDSEAttributes, nil,
	))
	if err != nil {
		writeLDAPError(response, err)
		return
	}
	defer release()
	if len(result.Entries) == 0 {
		writeAPIError(response, http.StatusBadGateway, apiError{
			Code: "invalid_ldap_response", Message: "LDAP server returned no Root DSE",
		})
		return
	}
	writeJSON(response, http.StatusOK, convertEntry(result.Entries[0]))
}

func (application *Application) handleSchema(response http.ResponseWriter, request *http.Request) {
	if !methodAllowed(response, request, http.MethodGet) {
		return
	}
	current, ok := application.acquireSession(response, request)
	if !ok {
		return
	}
	defer application.releaseSession(current)
	root, releaseRoot, err := application.search(current.client, ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
		application.config.MaxSearchSeconds, false, "(objectClass=*)", []string{"subschemaSubentry"}, nil,
	))
	if err != nil {
		writeLDAPError(response, err)
		return
	}
	releaseRoot()
	if len(root.Entries) == 0 {
		writeAPIError(response, http.StatusBadGateway, apiError{Code: "invalid_ldap_response", Message: "LDAP server returned no Root DSE"})
		return
	}
	schemaDN := root.Entries[0].GetEqualFoldAttributeValue("subschemaSubentry")
	if schemaDN == "" {
		schemaDN = "cn=Subschema"
	}
	if err := validateDN(schemaDN, false); err != nil {
		writeAPIError(response, http.StatusBadGateway, apiError{Code: "invalid_ldap_response", Message: "LDAP server returned an invalid subschema DN"})
		return
	}
	schemaResult, releaseSchema, err := application.search(current.client, ldap.NewSearchRequest(
		schemaDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
		application.config.MaxSearchSeconds, false, "(objectClass=subschema)", schemaAttributes, nil,
	))
	if err != nil {
		writeLDAPError(response, err)
		return
	}
	defer releaseSchema()
	if len(schemaResult.Entries) == 0 {
		writeAPIError(response, http.StatusNotFound, apiError{Code: "schema_not_found", Message: "subschema entry was not found"})
		return
	}
	summary := schemaSummaryResponse{
		DN:          schemaResult.Entries[0].DN,
		Counts:      make(map[string]int, len(schemaAttributes)),
		Definitions: make(map[string][]string, len(schemaAttributes)),
	}
	for _, attribute := range schemaResult.Entries[0].Attributes {
		name := canonicalSummaryAttribute(attribute.Name, schemaAttributes)
		if name == "" {
			continue
		}
		values := append([]string(nil), attribute.Values...)
		summary.Definitions[name] = values
		summary.Counts[name] = len(values)
	}
	for _, attribute := range schemaAttributes {
		if _, exists := summary.Counts[attribute]; !exists {
			summary.Counts[attribute] = 0
			summary.Definitions[attribute] = []string{}
		}
	}
	writeJSON(response, http.StatusOK, summary)
}

func canonicalSummaryAttribute(value string, allowed []string) string {
	for _, candidate := range allowed {
		if strings.EqualFold(value, candidate) {
			return candidate
		}
	}
	return ""
}

func (application *Application) handleMonitor(response http.ResponseWriter, request *http.Request) {
	if !methodAllowed(response, request, http.MethodGet) {
		return
	}
	current, ok := application.acquireSession(response, request)
	if !ok {
		return
	}
	defer application.releaseSession(current)
	base := request.URL.Query().Get("base_dn")
	if base == "" {
		base = "cn=Monitor"
	}
	if err := validateDN(base, false); err != nil {
		writeAPIError(response, http.StatusBadRequest, apiError{Code: "invalid_dn", Message: err.Error()})
		return
	}
	attributes := []string{
		"cn", "description", "monitoredInfo", "monitorCounter",
		"monitorOpCompleted", "monitorOpInitiated", "monitorTimestamp", "objectClass",
	}
	ldapRequest := ldap.NewSearchRequest(
		base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		application.config.MaxMonitorEntries, application.config.MaxSearchSeconds,
		false, "(objectClass=*)", attributes, nil,
	)
	ldapRequest.EnforceSizeLimit = true
	result, release, err := application.search(current.client, ldapRequest)
	if err != nil {
		writeLDAPError(response, err)
		return
	}
	defer release()
	entries := make([]entryResponse, 0, len(result.Entries))
	for _, entry := range result.Entries {
		if entry != nil {
			entries = append(entries, convertEntry(entry))
		}
	}
	writeJSON(response, http.StatusOK, monitorSummaryResponse{BaseDN: base, Entries: entries})
}
