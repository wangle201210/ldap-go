package server

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type monitorReferenceResult struct {
	rootContext              string
	rootShape                []string
	containerShapes          []string
	operationShapes          []string
	statisticsShapes         []string
	timeShapes               []string
	connectionShapes         []string
	databaseShapes           []string
	logValues                []string
	searchOperationInFlight  bool
	connectionSearchInFlight bool
	connectionMetadata       bool
	statisticsNonZero        bool
	compareTrue              bool
	compareFalse             bool
	missingAttributeCode     uint16
	missingObjectCode        uint16
	missingObjectMatchedDN   string
	writeCodes               []uint16
}

type monitorManagementReferenceResult struct {
	logResultCodes        []uint16
	debugHistory          []string
	debugLevels           []string
	logLevels             []string
	databaseResultCodes   []uint16
	readOnly              string
	restricted            []string
	blockedAddCode        uint16
	writableAddCode       uint16
	restrictionCodes      []uint16
	restrictedSearch      uint16
	restoredSearch        uint16
	restrictedCompare     uint16
	operationRestrictions []uint16
}

func TestOpenLDAPReferenceMonitorBackend(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		"database monitor\nrootdn \"cn=admin,cn=Monitor\"\nrootpw monitor-secret\naccess to * by * read",
		"",
	)
	defer stopOpenLDAP()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedConfigDatabaseConfiguration(t, store)
	seedMonitorConfiguration(t, store)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	defer stopLDAPGo()

	reference := observeMonitorReference(t, openLDAPURI)
	implementation := observeMonitorReference(t, "ldap://"+ldapGoAddress)
	if !reflect.DeepEqual(reference, implementation) {
		t.Fatalf(
			"monitor behavior mismatch\nOpenLDAP: %#v\nldap-go:  %#v",
			reference,
			implementation,
		)
	}

	referenceManagement := observeMonitorManagement(t, openLDAPURI)
	implementationManagement := observeMonitorManagement(t, "ldap://"+ldapGoAddress)
	if !reflect.DeepEqual(referenceManagement, implementationManagement) {
		t.Fatalf(
			"monitor management behavior mismatch\nOpenLDAP: %#v\nldap-go:  %#v",
			referenceManagement,
			implementationManagement,
		)
	}
}

func observeMonitorReference(t *testing.T, uri string) monitorReferenceResult {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	if err := client.UnauthenticatedBind(""); err != nil {
		t.Fatalf("anonymous Bind(%s): %v", uri, err)
	}

	rootDSE := monitorSearch(t, client, "", ldap.ScopeBaseObject, "(objectClass=*)", []string{"monitorContext"})
	root := monitorSearch(
		t,
		client,
		"cn=Monitor",
		ldap.ScopeBaseObject,
		"(objectClass=*)",
		[]string{"objectClass", "structuralObjectClass", "entryDN", "hasSubordinates"},
	)
	containers := monitorSearch(
		t,
		client,
		"cn=Monitor",
		ldap.ScopeSingleLevel,
		"(objectClass=monitorContainer)",
		[]string{"cn", "structuralObjectClass", "entryDN"},
	)
	operations := monitorSearch(
		t,
		client,
		"cn=Operations,cn=Monitor",
		ldap.ScopeSingleLevel,
		"(objectClass=*)",
		[]string{"cn", "structuralObjectClass", "entryDN", "monitorOpInitiated", "monitorOpCompleted"},
	)
	statistics := monitorSearch(
		t,
		client,
		"cn=Statistics,cn=Monitor",
		ldap.ScopeSingleLevel,
		"(objectClass=*)",
		[]string{"cn", "structuralObjectClass", "entryDN", "monitorCounter"},
	)
	times := monitorSearch(
		t,
		client,
		"cn=Time,cn=Monitor",
		ldap.ScopeSingleLevel,
		"(objectClass=*)",
		[]string{"cn", "structuralObjectClass", "entryDN"},
	)
	connections := monitorSearch(
		t,
		client,
		"cn=Connections,cn=Monitor",
		ldap.ScopeSingleLevel,
		"(objectClass=*)",
		[]string{
			"cn", "structuralObjectClass", "entryDN", "monitorConnectionProtocol",
			"monitorConnectionOpsReceived", "monitorConnectionOpsExecuting",
			"monitorConnectionListener", "monitorConnectionLocalAddress",
		},
	)
	databases := monitorSearch(
		t,
		client,
		"cn=Databases,cn=Monitor",
		ldap.ScopeSingleLevel,
		"(objectClass=*)",
		[]string{
			"cn", "structuralObjectClass", "entryDN", "monitorIsShadow",
			"namingContexts", "monitorContext", "readOnly",
		},
	)
	logEntry := monitorSearch(
		t,
		client,
		"cn=Log,cn=Monitor",
		ldap.ScopeBaseObject,
		"(objectClass=*)",
		[]string{"monitorDebugLevel", "monitorLogLevel"},
	).Entries[0]

	searchOperation := ldapEntryByCN(operations.Entries, "Search")
	connection := ldapEntryByStructuralObjectClass(connections.Entries, "monitorConnection")
	searchInFlight := searchOperation != nil &&
		ldapEntryUint64(t, searchOperation, "monitorOpInitiated") >
			ldapEntryUint64(t, searchOperation, "monitorOpCompleted")
	connectionInFlight := connection != nil &&
		ldapEntryUint64(t, connection, "monitorConnectionOpsExecuting") > 0
	connectionMetadata := connection != nil &&
		connection.GetAttributeValue("monitorConnectionProtocol") == "3" &&
		ldapEntryUint64(t, connection, "monitorConnectionOpsReceived") > 0 &&
		connection.GetAttributeValue("monitorConnectionListener") != "" &&
		connection.GetAttributeValue("monitorConnectionLocalAddress") != ""
	statisticsNonZero := true
	for _, name := range []string{"Bytes", "PDU", "Entries"} {
		entry := ldapEntryByCN(statistics.Entries, name)
		if entry == nil || ldapEntryUint64(t, entry, "monitorCounter") == 0 {
			statisticsNonZero = false
		}
	}

	compareTrue, compareTrueErr := client.Compare(
		"cn=Search,cn=Operations,cn=Monitor",
		"cn",
		"search",
	)
	if compareTrueErr != nil {
		t.Fatalf("monitor Compare true (%s): %v", uri, compareTrueErr)
	}
	compareFalse, compareFalseErr := client.Compare(
		"cn=Search,cn=Operations,cn=Monitor",
		"cn",
		"other",
	)
	if compareFalseErr != nil {
		t.Fatalf("monitor Compare false (%s): %v", uri, compareFalseErr)
	}
	_, missingAttributeErr := client.Compare(
		"cn=Search,cn=Operations,cn=Monitor",
		"mail",
		"none@example.com",
	)
	_, missingObjectErr := client.Compare(
		"cn=Missing,cn=Time,cn=Monitor",
		"cn",
		"Missing",
	)

	add := ldap.NewAddRequest("cn=Blocked,cn=Monitor", nil)
	add.Attribute("objectClass", []string{"organizationalRole"})
	add.Attribute("cn", []string{"Blocked"})
	modify := ldap.NewModifyRequest("cn=Monitor", nil)
	modify.Replace("description", []string{"blocked"})
	writes := []error{
		client.Add(add),
		client.Modify(modify),
		client.Del(ldap.NewDelRequest("cn=Time,cn=Monitor", nil)),
		client.ModifyDN(ldap.NewModifyDNRequest(
			"cn=Time,cn=Monitor",
			"cn=Moved",
			true,
			"",
		)),
	}

	return monitorReferenceResult{
		rootContext:      rootDSE.Entries[0].GetAttributeValue("monitorContext"),
		rootShape:        monitorEntrySignatures(root.Entries, nil),
		containerShapes:  monitorEntrySignatures(containers.Entries, nil),
		operationShapes:  monitorEntrySignatures(operations.Entries, nil),
		statisticsShapes: monitorEntrySignatures(statistics.Entries, nil),
		timeShapes:       monitorEntrySignatures(times.Entries, nil),
		connectionShapes: monitorEntrySignatures(connections.Entries, map[string]bool{"connection": true}),
		databaseShapes:   monitorEntrySignatures(databases.Entries, map[string]bool{"database": true}),
		logValues: append(
			append([]string(nil), logEntry.GetAttributeValues("monitorDebugLevel")...),
			logEntry.GetAttributeValues("monitorLogLevel")...,
		),
		searchOperationInFlight:  searchInFlight,
		connectionSearchInFlight: connectionInFlight,
		connectionMetadata:       connectionMetadata,
		statisticsNonZero:        statisticsNonZero,
		compareTrue:              compareTrue,
		compareFalse:             compareFalse,
		missingAttributeCode:     monitorLDAPResultCode(missingAttributeErr),
		missingObjectCode:        monitorLDAPResultCode(missingObjectErr),
		missingObjectMatchedDN:   monitorLDAPMatchedDN(missingObjectErr),
		writeCodes: []uint16{
			monitorLDAPResultCode(writes[0]),
			monitorLDAPResultCode(writes[1]),
			monitorLDAPResultCode(writes[2]),
			monitorLDAPResultCode(writes[3]),
		},
	}
}

func monitorEntrySignatures(
	entries []*ldap.Entry,
	options map[string]bool,
) []string {
	signatures := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.GetAttributeValue("cn")
		structural := entry.GetAttributeValue("structuralObjectClass")
		signature := name + "|" + structural
		if options["connection"] && strings.EqualFold(structural, "monitorConnection") {
			signature = "Connection|monitorConnection"
		}
		if options["database"] {
			values := append([]string(nil), entry.GetAttributeValues("namingContexts")...)
			values = append(values, entry.GetAttributeValues("monitorContext")...)
			sort.Strings(values)
			signature += "|contexts=" + strings.Join(values, ",")
			signature += "|shadow=" + strings.ToUpper(entry.GetAttributeValue("monitorIsShadow"))
			signature += "|readOnly=" + strings.ToUpper(entry.GetAttributeValue("readOnly"))
		}
		signatures = append(signatures, signature)
	}
	sort.Strings(signatures)
	return signatures
}

func observeMonitorManagement(
	t *testing.T,
	uri string,
) monitorManagementReferenceResult {
	t.Helper()
	monitorClient, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL monitor management (%s): %v", uri, err)
	}
	defer monitorClient.Close()
	if err := monitorClient.Bind("cn=admin,cn=Monitor", "monitor-secret"); err != nil {
		t.Fatalf("monitor root Bind(%s): %v", uri, err)
	}

	replaceDebug := ldap.NewModifyRequest("cn=Log,cn=Monitor", nil)
	replaceDebug.Replace("monitorDebugLevel", []string{"Stats", "Sync"})
	duplicateDebug := ldap.NewModifyRequest("cn=Log,cn=Monitor", nil)
	duplicateDebug.Add("monitorDebugLevel", []string{"stats"})
	invalidDebug := ldap.NewModifyRequest("cn=Log,cn=Monitor", nil)
	invalidDebug.Replace("monitorDebugLevel", []string{"not-a-level"})
	deleteDebug := ldap.NewModifyRequest("cn=Log,cn=Monitor", nil)
	deleteDebug.Delete("monitorDebugLevel", []string{"Sync"})
	replaceLog := ldap.NewModifyRequest("cn=Log,cn=Monitor", nil)
	replaceLog.Replace("monitorLogLevel", []string{"ACL"})
	unmanagedLog := ldap.NewModifyRequest("cn=Log,cn=Monitor", nil)
	unmanagedLog.Replace("description", []string{"blocked"})
	var logResultCodes []uint16
	var debugHistory []string
	for _, request := range []*ldap.ModifyRequest{
		replaceDebug,
		duplicateDebug,
		invalidDebug,
		deleteDebug,
		replaceLog,
		unmanagedLog,
	} {
		logResultCodes = append(
			logResultCodes,
			monitorLDAPResultCode(monitorClient.Modify(request)),
		)
		current := monitorSearch(
			t,
			monitorClient,
			"cn=Log,cn=Monitor",
			ldap.ScopeBaseObject,
			"(objectClass=*)",
			[]string{"monitorDebugLevel"},
		).Entries[0]
		debugHistory = append(
			debugHistory,
			strings.Join(sortedStrings(current.GetAttributeValues("monitorDebugLevel")), ","),
		)
	}
	logEntry := monitorSearch(
		t,
		monitorClient,
		"cn=Log,cn=Monitor",
		ldap.ScopeBaseObject,
		"(objectClass=*)",
		[]string{"monitorDebugLevel", "monitorLogLevel"},
	).Entries[0]

	readOnly := ldap.NewModifyRequest("cn=Database 1,cn=Databases,cn=Monitor", nil)
	readOnly.Replace("readOnly", []string{"TRUE"})
	readOnlyCode := monitorLDAPResultCode(monitorClient.Modify(readOnly))
	databaseEntry := monitorSearch(
		t,
		monitorClient,
		"cn=Database 1,cn=Databases,cn=Monitor",
		ldap.ScopeBaseObject,
		"(objectClass=*)",
		[]string{"readOnly", "restrictedOperation"},
	).Entries[0]

	dataClient, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL data management (%s): %v", uri, err)
	}
	defer dataClient.Close()
	if err := dataClient.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("data root Bind(%s): %v", uri, err)
	}
	blockedAddCode := monitorLDAPResultCode(dataClient.Add(
		monitorReferencePersonAddRequest("monitor-read-only"),
	))

	writable := ldap.NewModifyRequest("cn=Database 1,cn=Databases,cn=Monitor", nil)
	writable.Replace("readOnly", []string{"FALSE"})
	writableCode := monitorLDAPResultCode(monitorClient.Modify(writable))
	writableAddCode := monitorLDAPResultCode(dataClient.Add(
		monitorReferencePersonAddRequest("monitor-writable"),
	))
	invalidReadOnly := ldap.NewModifyRequest("cn=Database 1,cn=Databases,cn=Monitor", nil)
	invalidReadOnly.Replace("readOnly", []string{"sometimes"})
	invalidReadOnlyCode := monitorLDAPResultCode(monitorClient.Modify(invalidReadOnly))
	deleteReadOnly := ldap.NewModifyRequest("cn=Database 1,cn=Databases,cn=Monitor", nil)
	deleteReadOnly.Delete("readOnly", nil)
	deleteReadOnlyCode := monitorLDAPResultCode(monitorClient.Modify(deleteReadOnly))
	monitorDatabase := ldap.NewModifyRequest("cn=Database 2,cn=Databases,cn=Monitor", nil)
	monitorDatabase.Replace("readOnly", []string{"TRUE"})
	monitorDatabaseCode := monitorLDAPResultCode(monitorClient.Modify(monitorDatabase))

	addSearchRestriction := ldap.NewModifyRequest(
		"cn=Database 1,cn=Databases,cn=Monitor",
		nil,
	)
	addSearchRestriction.Add("restrictedOperation", []string{"search"})
	addSearchRestrictionCode := monitorLDAPResultCode(
		monitorClient.Modify(addSearchRestriction),
	)
	duplicateSearchRestriction := ldap.NewModifyRequest(
		"cn=Database 1,cn=Databases,cn=Monitor",
		nil,
	)
	duplicateSearchRestriction.Add("restrictedOperation", []string{"search"})
	duplicateSearchRestrictionCode := monitorLDAPResultCode(
		monitorClient.Modify(duplicateSearchRestriction),
	)
	_, restrictedSearchErr := dataClient.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dc"},
		nil,
	))
	deleteSearchRestriction := ldap.NewModifyRequest(
		"cn=Database 1,cn=Databases,cn=Monitor",
		nil,
	)
	deleteSearchRestriction.Delete("restrictedOperation", []string{"search"})
	deleteSearchRestrictionCode := monitorLDAPResultCode(
		monitorClient.Modify(deleteSearchRestriction),
	)
	_, restoredSearchErr := dataClient.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dc"},
		nil,
	))
	replaceCompareRestriction := ldap.NewModifyRequest(
		"cn=Database 1,cn=Databases,cn=Monitor",
		nil,
	)
	replaceCompareRestriction.Replace("restrictedOperation", []string{"compare"})
	replaceCompareRestrictionCode := monitorLDAPResultCode(
		monitorClient.Modify(replaceCompareRestriction),
	)
	_, restrictedCompareErr := dataClient.Compare(
		"dc=example,dc=com",
		"dc",
		"example",
	)

	setRestriction := func(operation string) uint16 {
		request := ldap.NewModifyRequest(
			"cn=Database 1,cn=Databases,cn=Monitor",
			nil,
		)
		request.Replace("restrictedOperation", []string{operation})
		return monitorLDAPResultCode(monitorClient.Modify(request))
	}
	var operationRestrictions []uint16
	operationRestrictions = append(operationRestrictions, setRestriction("bind"))
	bindClient, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL restricted Bind (%s): %v", uri, err)
	}
	operationRestrictions = append(
		operationRestrictions,
		monitorLDAPResultCode(bindClient.Bind("cn=admin,dc=example,dc=com", "secret")),
	)
	bindClient.Close()

	operationRestrictions = append(operationRestrictions, setRestriction("add"))
	operationRestrictions = append(
		operationRestrictions,
		monitorLDAPResultCode(dataClient.Add(
			monitorReferencePersonAddRequest("monitor-restricted-add"),
		)),
	)
	operationRestrictions = append(operationRestrictions, setRestriction("modify"))
	restrictedModify := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	restrictedModify.Replace("cn", []string{"Restricted Alice"})
	operationRestrictions = append(
		operationRestrictions,
		monitorLDAPResultCode(dataClient.Modify(restrictedModify)),
	)
	operationRestrictions = append(operationRestrictions, setRestriction("delete"))
	operationRestrictions = append(
		operationRestrictions,
		monitorLDAPResultCode(dataClient.Del(ldap.NewDelRequest(
			"uid=monitor-writable,ou=people,dc=example,dc=com",
			nil,
		))),
	)
	operationRestrictions = append(operationRestrictions, setRestriction("rename"))
	operationRestrictions = append(
		operationRestrictions,
		monitorLDAPResultCode(dataClient.ModifyDN(ldap.NewModifyDNRequest(
			"uid=monitor-writable,ou=people,dc=example,dc=com",
			"uid=monitor-renamed",
			true,
			"",
		))),
	)

	return monitorManagementReferenceResult{
		logResultCodes: logResultCodes,
		debugHistory:   debugHistory,
		debugLevels:    sortedStrings(logEntry.GetAttributeValues("monitorDebugLevel")),
		logLevels:      sortedStrings(logEntry.GetAttributeValues("monitorLogLevel")),
		databaseResultCodes: []uint16{
			readOnlyCode,
			writableCode,
			invalidReadOnlyCode,
			deleteReadOnlyCode,
			monitorDatabaseCode,
		},
		readOnly:        strings.ToUpper(databaseEntry.GetAttributeValue("readOnly")),
		restricted:      sortedStrings(databaseEntry.GetAttributeValues("restrictedOperation")),
		blockedAddCode:  blockedAddCode,
		writableAddCode: writableAddCode,
		restrictionCodes: []uint16{
			addSearchRestrictionCode,
			duplicateSearchRestrictionCode,
			deleteSearchRestrictionCode,
			replaceCompareRestrictionCode,
		},
		restrictedSearch:      monitorLDAPResultCode(restrictedSearchErr),
		restoredSearch:        monitorLDAPResultCode(restoredSearchErr),
		restrictedCompare:     monitorLDAPResultCode(restrictedCompareErr),
		operationRestrictions: operationRestrictions,
	}
}

func monitorReferencePersonAddRequest(uid string) *ldap.AddRequest {
	request := ldap.NewAddRequest(
		"uid="+uid+",ou=people,dc=example,dc=com",
		nil,
	)
	request.Attribute("objectClass", []string{
		"top",
		"person",
		"organizationalPerson",
		"inetOrgPerson",
	})
	request.Attribute("uid", []string{uid})
	request.Attribute("cn", []string{"Monitor Managed User"})
	request.Attribute("sn", []string{"User"})
	return request
}

func ldapEntryByStructuralObjectClass(entries []*ldap.Entry, objectClass string) *ldap.Entry {
	for _, entry := range entries {
		if strings.EqualFold(entry.GetAttributeValue("structuralObjectClass"), objectClass) {
			return entry
		}
	}
	return nil
}

func monitorLDAPResultCode(err error) uint16 {
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return ldapErr.ResultCode
	}
	return ldap.ErrorNetwork
}

func monitorLDAPMatchedDN(err error) string {
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return strings.ToLower(ldapErr.MatchedDN)
	}
	return ""
}

func seedConfigDatabaseConfiguration(t *testing.T, store storage.Store) {
	t.Helper()
	entry := directory.Entry{
		DN: "olcDatabase={0}config,cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcConfig")},
			{Description: "olcDatabase", Values: stringValues("{0}config")},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed config database configuration: %v", err)
	}
}
