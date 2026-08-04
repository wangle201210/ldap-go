package server

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type accesslogReferenceObservation struct {
	requestType              string
	requestDN                string
	requestClass             string
	authorizationDN          string
	result                   string
	newRDN                   string
	deleteOldRDN             string
	newSuperior              string
	newDN                    string
	userModifications        []string
	userOldValues            []string
	hasStart                 bool
	hasEnd                   bool
	hasSession               bool
	hasRequestEntryUUID      bool
	hasValidEntryCSN         bool
	hasEntryUUIDModification bool
	hasEntryCSNModification  bool
	hasPasswordModification  bool
}

type accesslogOperationReferenceObservation struct {
	requestType       string
	requestClass      string
	requestDN         string
	result            string
	method            string
	version           string
	assertion         string
	scope             string
	derefAliases      string
	attributesOnly    string
	filter            string
	attributes        []string
	entries           string
	sizeLimit         string
	timeLimit         string
	modifications     []string
	requestID         string
	hasStart          bool
	hasEnd            bool
	hasSession        bool
	hasAuthorization  bool
	hasRequestMessage bool
	hasPagingRequest  bool
	hasPagingResponse bool
}

func TestOpenLDAPReferenceAccesslogOverlay(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	openLDAPURI, stopOpenLDAP := startOpenLDAPAccesslogProviderWithOptions(
		t,
		tools,
		"logold \"(objectClass=*)\"\nlogoldattr sn",
	)
	defer stopOpenLDAP()
	openLDAP, err := ldap.DialURL(openLDAPURI)
	if err != nil {
		t.Fatalf("dial OpenLDAP accesslog provider: %v", err)
	}
	if err := openLDAP.Bind(syncTestRootDN, syncTestRootPassword); err != nil {
		openLDAP.Close()
		t.Fatalf("bind OpenLDAP accesslog provider: %v", err)
	}
	seedOpenLDAPAccesslogData(t, openLDAP)
	openLDAP.Close()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoAccesslogProvider(t, store)
	configureLDAPGoAccesslogOld(
		t,
		store,
		"(objectClass=*)",
		[]string{"sn"},
	)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopLDAPGo()

	reference := observeAccesslogReferenceScenario(t, openLDAPURI)
	implementation := observeAccesslogReferenceScenario(
		t,
		"ldap://"+ldapGoAddress,
	)
	if reflect.DeepEqual(reference, implementation) {
		return
	}
	for index := range reference {
		if index < len(implementation) &&
			reflect.DeepEqual(reference[index], implementation[index]) {
			continue
		}
		var got any = "missing"
		if index < len(implementation) {
			got = implementation[index]
		}
		t.Errorf(
			"accesslog record %d mismatch\nOpenLDAP: %#v\nldap-go:  %#v",
			index,
			reference[index],
			got,
		)
	}
	if len(reference) != len(implementation) {
		t.Errorf(
			"accesslog record count mismatch: OpenLDAP=%d ldap-go=%d",
			len(reference),
			len(implementation),
		)
	}
}

func TestOpenLDAPReferenceAccesslogReadSessionAndFailureRecords(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	openLDAPURI, stopOpenLDAP := startOpenLDAPAccesslogProviderWithConfiguration(
		t,
		tools,
		"all",
		false,
		"",
	)
	defer stopOpenLDAP()
	openLDAP, err := ldap.DialURL(openLDAPURI)
	if err != nil {
		t.Fatalf("dial OpenLDAP accesslog provider: %v", err)
	}
	if err := openLDAP.Bind(syncTestRootDN, syncTestRootPassword); err != nil {
		openLDAP.Close()
		t.Fatalf("bind OpenLDAP accesslog provider: %v", err)
	}
	seedOpenLDAPAccesslogData(t, openLDAP)
	openLDAP.Close()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)
	seedAccesslogConfiguration(
		t,
		store,
		"cn=log",
		[]string{"all"},
		[]string{"FALSE"},
	)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopLDAPGo()

	reference := observeAccesslogOperationScenario(t, openLDAPURI)
	implementation := observeAccesslogOperationScenario(
		t,
		"ldap://"+ldapGoAddress,
	)
	if !reflect.DeepEqual(reference, implementation) {
		t.Fatalf(
			"read/session/failure accesslog mismatch\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			implementation,
		)
	}
}

func observeAccesslogOperationScenario(
	t *testing.T,
	uri string,
) []accesslogOperationReferenceObservation {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial accesslog provider %s: %v", uri, err)
	}
	defer client.Close()
	if err := client.Bind(syncTestRootDN, syncTestRootPassword); err != nil {
		t.Fatalf("bind accesslog provider %s: %v", uri, err)
	}
	clearAccesslogRecords(t, client, uri)

	searchRequest := ldap.NewSearchRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		3,
		2,
		true,
		"(&(objectClass=inetOrgPerson)(uid=alice))",
		[]string{"uid", "cn"},
		[]ldap.Control{ldap.NewControlPaging(1)},
	)
	result, err := client.Search(searchRequest)
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("accesslog provider %s search alice = %#v, %v", uri, result, err)
	}
	matched, err := client.Compare(
		"uid=alice,ou=people,dc=example,dc=com",
		"uid",
		"alice",
	)
	if err != nil || !matched {
		t.Fatalf("accesslog provider %s compare alice = %t, %v", uri, matched, err)
	}
	if _, err := client.WhoAmI(nil); err != nil {
		t.Fatalf("accesslog provider %s WhoAmI: %v", uri, err)
	}
	if err := client.Add(newPersonAddRequest("alice")); err == nil {
		t.Fatalf("accesslog provider %s duplicate add succeeded", uri)
	}
	modify := ldap.NewModifyRequest(
		"uid=missing,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Missing"})
	if err := client.Modify(modify); err == nil {
		t.Fatalf("accesslog provider %s missing modify succeeded", uri)
	}
	session, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial accesslog session %s: %v", uri, err)
	}
	if err := session.Bind(syncTestRootDN, syncTestRootPassword); err != nil {
		session.Close()
		t.Fatalf("bind accesslog session %s: %v", uri, err)
	}
	if err := session.Unbind(); err != nil {
		t.Fatalf("unbind accesslog session %s: %v", uri, err)
	}
	abandonConnection := dialAndBindRawLDAP(
		t,
		strings.TrimPrefix(uri, "ldap://"),
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer abandonConnection.Close()
	writeRawLDAPRequest(
		t,
		abandonConnection,
		2,
		rawSyncSearchRequest(t, ldap.NeverDerefAliases),
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshAndPersist,
		}, true),
	)
	for {
		message := readRawSyncMessage(t, abandonConnection, 2)
		if message.entry != nil {
			continue
		}
		if message.info != nil &&
			(message.info.Kind == ldapwire.SyncInfoRefreshPresent ||
				message.info.Kind == ldapwire.SyncInfoRefreshDelete) &&
			message.info.RefreshDone {
			break
		}
		t.Fatalf("unexpected accesslog abandon Sync response = %#v", message)
	}
	writeRawLDAPRequest(
		t,
		abandonConnection,
		3,
		rawAbandonRequest(2),
		nil,
	)

	deadline := time.Now().Add(3 * time.Second)
	for {
		result, err = client.Search(ldap.NewSearchRequest(
			"cn=log",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=auditObject)",
			[]string{"*", "+"},
			nil,
		))
		if err != nil {
			t.Fatalf("search accesslog operation records %s: %v", uri, err)
		}
		if accesslogEntriesContainTypes(
			result.Entries,
			"search", "compare", "add", "modify", "bind", "unbind", "abandon",
		) {
			break
		}
		if time.Now().After(deadline) {
			observed := make([]string, 0, len(result.Entries))
			for _, entry := range result.Entries {
				observed = append(observed, entry.GetAttributeValue("reqType"))
			}
			t.Fatalf(
				"accesslog operation records %s did not converge: %q",
				uri,
				observed,
			)
		}
		time.Sleep(20 * time.Millisecond)
	}

	observations := make([]accesslogOperationReferenceObservation, 0, 7)
	for _, entry := range result.Entries {
		requestType := entry.GetAttributeValue("reqType")
		if requestType == "search" &&
			entry.GetAttributeValue("reqDN") !=
				"uid=alice,ou=people,dc=example,dc=com" {
			continue
		}
		switch requestType {
		case "search", "compare", "add", "modify", "bind", "unbind", "abandon":
		default:
			continue
		}
		observations = append(observations, accesslogOperationReferenceObservation{
			requestType:    requestType,
			requestClass:   accesslogOperationReferenceClass(entry),
			requestDN:      entry.GetAttributeValue("reqDN"),
			result:         entry.GetAttributeValue("reqResult"),
			method:         entry.GetAttributeValue("reqMethod"),
			version:        entry.GetAttributeValue("reqVersion"),
			assertion:      entry.GetAttributeValue("reqAssertion"),
			scope:          entry.GetAttributeValue("reqScope"),
			derefAliases:   entry.GetAttributeValue("reqDerefAliases"),
			attributesOnly: entry.GetAttributeValue("reqAttrsOnly"),
			filter:         entry.GetAttributeValue("reqFilter"),
			attributes:     sortedAccesslogStrings(entry.GetAttributeValues("reqAttr")),
			entries:        entry.GetAttributeValue("reqEntries"),
			sizeLimit:      entry.GetAttributeValue("reqSizeLimit"),
			timeLimit:      entry.GetAttributeValue("reqTimeLimit"),
			modifications: normalizeAccesslogReferenceValues(
				entry.GetAttributeValues("reqMod"),
			),
			requestID:         entry.GetAttributeValue("reqId"),
			hasStart:          entry.GetAttributeValue("reqStart") != "",
			hasEnd:            entry.GetAttributeValue("reqEnd") != "",
			hasSession:        entry.GetAttributeValue("reqSession") != "",
			hasAuthorization:  entry.GetAttributeValue("reqAuthzID") != "",
			hasRequestMessage: entry.GetAttributeValue("reqMessage") != "",
			hasPagingRequest: accesslogReferenceContains(
				entry.GetAttributeValues("reqControls"),
				pagedResultsControlOID,
			),
			hasPagingResponse: accesslogReferenceContains(
				entry.GetAttributeValues("reqRespControls"),
				pagedResultsControlOID,
			),
		})
	}
	sort.Slice(observations, func(i, j int) bool {
		return observations[i].requestType < observations[j].requestType
	})
	return observations
}

func accesslogReferenceContains(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}

func clearAccesslogRecords(t *testing.T, client *ldap.Conn, uri string) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"cn=log",
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(reqStart=*)",
		[]string{"1.1"},
		nil,
	))
	if err != nil {
		t.Fatalf("list accesslog records for cleanup from %s: %v", uri, err)
	}
	for _, entry := range result.Entries {
		if err := client.Del(ldap.NewDelRequest(entry.DN, nil)); err != nil {
			t.Fatalf("delete accesslog record %s from %s: %v", entry.DN, uri, err)
		}
	}
}

func accesslogOperationReferenceClass(entry *ldap.Entry) string {
	for _, class := range []string{
		"auditSearch", "auditCompare", "auditExtended", "auditAdd",
		"auditModify", "auditBind", "auditAbandon", "auditObject",
	} {
		for _, value := range entry.GetAttributeValues("objectClass") {
			if strings.EqualFold(value, class) {
				return class
			}
		}
	}
	return ""
}

func sortedAccesslogStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func observeAccesslogReferenceScenario(
	t *testing.T,
	uri string,
) []accesslogReferenceObservation {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial accesslog provider %s: %v", uri, err)
	}
	defer client.Close()
	if err := client.Bind(syncTestRootDN, syncTestRootPassword); err != nil {
		t.Fatalf("bind accesslog provider %s: %v", uri, err)
	}

	if err := client.Add(newAccesslogPersonAddRequest("bob")); err != nil {
		t.Fatalf("accesslog provider %s add bob: %v", uri, err)
	}
	modify := ldap.NewModifyRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Bob Delta"})
	modify.Add("description", []string{"first", "second"})
	modify.Delete("description", []string{"first"})
	modify.Increment("uidNumber", "5")
	if err := client.Modify(modify); err != nil {
		t.Fatalf("accesslog provider %s modify bob: %v", uri, err)
	}
	if _, err := client.PasswordModify(ldap.NewPasswordModifyRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		"",
		"delta-secret",
	)); err != nil {
		t.Fatalf("accesslog provider %s password modify bob: %v", uri, err)
	}
	rename := ldap.NewModifyDNRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		"uid=renamed",
		true,
		"",
	)
	if err := client.ModifyDN(rename); err != nil {
		t.Fatalf("accesslog provider %s rename bob: %v", uri, err)
	}
	if err := client.Del(ldap.NewDelRequest(
		"uid=renamed,ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("accesslog provider %s delete renamed: %v", uri, err)
	}

	result, err := client.Search(ldap.NewSearchRequest(
		"cn=log",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(|(reqDN=uid=bob,ou=people,dc=example,dc=com)"+
			"(reqDN=uid=renamed,ou=people,dc=example,dc=com))",
		[]string{
			"objectClass",
			"reqStart",
			"reqEnd",
			"reqType",
			"reqSession",
			"reqAuthzID",
			"reqDN",
			"reqResult",
			"reqMod",
			"reqOld",
			"reqNewRDN",
			"reqDeleteOldRDN",
			"reqNewSuperior",
			"reqNewDN",
			"reqEntryUUID",
			"entryCSN",
		},
		nil,
	))
	if err != nil {
		t.Fatalf("search accesslog provider %s: %v", uri, err)
	}
	sort.Slice(result.Entries, func(i, j int) bool {
		return result.Entries[i].GetAttributeValue("reqStart") <
			result.Entries[j].GetAttributeValue("reqStart")
	})
	observations := make([]accesslogReferenceObservation, 0, len(result.Entries))
	for _, entry := range result.Entries {
		csn := entry.GetAttributeValue("entryCSN")
		_, csnErr := parseOpenLDAPCSN(csn)
		modifications := entry.GetAttributeValues("reqMod")
		observations = append(observations, accesslogReferenceObservation{
			requestType:              entry.GetAttributeValue("reqType"),
			requestDN:                entry.GetAttributeValue("reqDN"),
			requestClass:             accesslogReferenceClass(entry),
			authorizationDN:          entry.GetAttributeValue("reqAuthzID"),
			result:                   entry.GetAttributeValue("reqResult"),
			newRDN:                   entry.GetAttributeValue("reqNewRDN"),
			deleteOldRDN:             entry.GetAttributeValue("reqDeleteOldRDN"),
			newSuperior:              entry.GetAttributeValue("reqNewSuperior"),
			newDN:                    entry.GetAttributeValue("reqNewDN"),
			userModifications:        normalizeAccesslogReferenceValues(modifications),
			userOldValues:            normalizeAccesslogReferenceValues(entry.GetAttributeValues("reqOld")),
			hasStart:                 entry.GetAttributeValue("reqStart") != "",
			hasEnd:                   entry.GetAttributeValue("reqEnd") != "",
			hasSession:               entry.GetAttributeValue("reqSession") != "",
			hasRequestEntryUUID:      entry.GetAttributeValue("reqEntryUUID") != "",
			hasValidEntryCSN:         csn != "" && csnErr == nil,
			hasEntryUUIDModification: accesslogReferenceHasAttribute(modifications, "entryUUID"),
			hasEntryCSNModification:  accesslogReferenceHasAttribute(modifications, "entryCSN"),
			hasPasswordModification:  accesslogReferenceHasAttribute(modifications, "userPassword"),
		})
	}
	return observations
}

func accesslogReferenceClass(entry *ldap.Entry) string {
	for _, class := range []string{
		"auditAdd",
		"auditModify",
		"auditModRDN",
		"auditDelete",
	} {
		for _, value := range entry.GetAttributeValues("objectClass") {
			if strings.EqualFold(value, class) {
				return class
			}
		}
	}
	return ""
}

func normalizeAccesslogReferenceValues(values []string) []string {
	allowed := map[string]struct{}{
		"objectclass":   {},
		"uid":           {},
		"cn":            {},
		"sn":            {},
		"description":   {},
		"uidnumber":     {},
		"gidnumber":     {},
		"homedirectory": {},
	}
	var normalized []string
	for _, value := range values {
		colon := strings.IndexByte(value, ':')
		if colon <= 0 {
			continue
		}
		description := strings.ToLower(value[:colon])
		if _, keep := allowed[description]; !keep {
			continue
		}
		normalized = append(normalized, description+value[colon:])
	}
	sort.Strings(normalized)
	return normalized
}

func accesslogReferenceHasAttribute(values []string, want string) bool {
	for _, value := range values {
		colon := strings.IndexByte(value, ':')
		if colon > 0 && strings.EqualFold(value[:colon], want) {
			return true
		}
	}
	return false
}
