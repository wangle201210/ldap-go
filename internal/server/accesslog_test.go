package server

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestAccesslogOverlayRecordsSuccessfulWrites(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoAccesslogProvider(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()
	client := dialLDAPRoot(t, address)
	defer client.Close()

	container, err := client.Search(ldap.NewSearchRequest(
		"cn=log",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=auditContainer)",
		[]string{
			"objectClass",
			"entryUUID",
			"entryCSN",
			"contextCSN",
			"minCSN",
		},
		nil,
	))
	if err != nil {
		t.Fatalf("search accesslog container: %v", err)
	}
	if len(container.Entries) != 1 {
		t.Fatalf("accesslog container count = %d, want 1", len(container.Entries))
	}
	source, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"contextCSN", "auditContext"},
		nil,
	))
	if err != nil {
		t.Fatalf("search source contextCSN: %v", err)
	}
	if len(source.Entries) != 1 {
		t.Fatalf("source suffix count = %d, want 1", len(source.Entries))
	}
	wantContext := source.Entries[0].GetAttributeValues("contextCSN")
	if got := source.Entries[0].GetAttributeValue("auditContext"); got != "cn=log" {
		t.Fatalf("source auditContext = %q, want cn=log", got)
	}
	if got := container.Entries[0].GetAttributeValues("contextCSN"); !equalStringSets(got, wantContext) {
		t.Fatalf("accesslog contextCSN = %q, want %q", got, wantContext)
	}
	if got := container.Entries[0].GetAttributeValues("minCSN"); !equalStringSets(got, wantContext) {
		t.Fatalf("accesslog minCSN = %q, want %q", got, wantContext)
	}
	if got := container.Entries[0].GetAttributeValue("entryCSN"); len(wantContext) == 0 || got != wantContext[0] {
		t.Fatalf("accesslog entryCSN = %q, want first source contextCSN %q", got, wantContext)
	}
	if err := client.Add(newPersonAddRequest("alice")); err == nil {
		t.Fatal("duplicate add unexpectedly succeeded")
	}
	noOp := newPersonAddRequest("noop")
	noOp.Controls = []ldap.Control{
		ldap.NewControlString(noOpControlOID, true, ""),
	}
	if err := client.Add(noOp); err == nil {
		t.Fatal("No-Op add unexpectedly returned success")
	}

	if err := client.Add(newAccesslogPersonAddRequest("bob")); err != nil {
		t.Fatalf("add bob: %v", err)
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
		t.Fatalf("modify bob: %v", err)
	}
	if _, err := client.PasswordModify(ldap.NewPasswordModifyRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		"",
		"delta-secret",
	)); err != nil {
		t.Fatalf("password modify bob: %v", err)
	}
	rename := ldap.NewModifyDNRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		"uid=renamed",
		true,
		"",
	)
	if err := client.ModifyDN(rename); err != nil {
		t.Fatalf("rename bob: %v", err)
	}
	if err := client.Del(ldap.NewDelRequest(
		"uid=renamed,ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("delete renamed: %v", err)
	}

	result, err := client.Search(ldap.NewSearchRequest(
		"cn=log",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=auditWriteObject)",
		[]string{
			"objectClass",
			"reqStart",
			"reqEnd",
			"reqType",
			"reqDN",
			"reqMod",
			"reqOld",
			"reqNewRDN",
			"reqDeleteOldRDN",
			"reqNewDN",
			"reqEntryUUID",
			"reqResult",
			"entryCSN",
		},
		nil,
	))
	if err != nil {
		t.Fatalf("search accesslog records: %v", err)
	}
	if len(result.Entries) != 5 {
		t.Fatalf("accesslog record count = %d, want 5", len(result.Entries))
	}
	sort.Slice(result.Entries, func(i, j int) bool {
		return result.Entries[i].GetAttributeValue("reqStart") <
			result.Entries[j].GetAttributeValue("reqStart")
	})

	wantTypes := []string{"add", "modify", "modify", "modrdn", "delete"}
	seenCSNs := make(map[string]struct{}, len(result.Entries))
	var previousCSN string
	for index, entry := range result.Entries {
		if got := entry.GetAttributeValue("reqType"); got != wantTypes[index] {
			t.Fatalf("record %d reqType = %q, want %q", index, got, wantTypes[index])
		}
		if got := entry.GetAttributeValue("reqResult"); got != "0" {
			t.Fatalf("record %d reqResult = %q, want 0", index, got)
		}
		if entry.GetAttributeValue("reqStart") == "" ||
			entry.GetAttributeValue("reqEnd") == "" {
			t.Fatalf("record %d has empty request timestamps", index)
		}
		if entry.GetAttributeValue("reqEntryUUID") == "" {
			t.Fatalf("record %d has no reqEntryUUID", index)
		}
		csn := entry.GetAttributeValue("entryCSN")
		if _, err := parseOpenLDAPCSN(csn); err != nil {
			t.Fatalf("record %d entryCSN %q: %v", index, csn, err)
		}
		if _, duplicate := seenCSNs[csn]; duplicate {
			t.Fatalf("record %d reuses entryCSN %q", index, csn)
		}
		if previousCSN != "" && csn <= previousCSN {
			t.Fatalf("record %d entryCSN %q is not after %q", index, csn, previousCSN)
		}
		seenCSNs[csn] = struct{}{}
		previousCSN = csn
	}

	add := result.Entries[0]
	assertLDAPAttributeContains(t, add, "reqMod", "uid:+ bob")
	assertLDAPAttributeContains(t, add, "reqMod", "entryUUID:+ ")
	assertLDAPAttributeContains(t, add, "reqMod", "entryCSN:+ ")
	if got := add.GetAttributeValue("reqDN"); got != "uid=bob,ou=people,dc=example,dc=com" {
		t.Fatalf("add reqDN = %q", got)
	}

	modified := result.Entries[1]
	assertLDAPAttributeContains(t, modified, "reqMod", "cn:= Bob Delta")
	assertLDAPAttributeContains(t, modified, "reqMod", "description:+ first")
	assertLDAPAttributeContains(t, modified, "reqMod", "description:+ second")
	assertLDAPAttributeContains(t, modified, "reqMod", "description:- first")
	assertLDAPAttributeContains(t, modified, "reqMod", "uidNumber:# 5")
	assertLDAPAttributeContains(t, modified, "reqMod", "entryCSN:= ")

	password := result.Entries[2]
	assertLDAPAttributeContains(t, password, "reqMod", "userPassword:= {")
	for _, value := range password.GetAttributeValues("reqMod") {
		if strings.Contains(value, "delta-secret") {
			t.Fatalf("password accesslog contains cleartext: %q", value)
		}
	}

	renamed := result.Entries[3]
	if got := renamed.GetAttributeValue("reqNewRDN"); got != "uid=renamed" {
		t.Fatalf("modrdn reqNewRDN = %q", got)
	}
	if got := renamed.GetAttributeValue("reqDeleteOldRDN"); got != "TRUE" {
		t.Fatalf("modrdn reqDeleteOldRDN = %q, want TRUE", got)
	}
	if got := renamed.GetAttributeValue("reqNewDN"); got != "uid=renamed,ou=people,dc=example,dc=com" {
		t.Fatalf("modrdn reqNewDN = %q", got)
	}
	assertLDAPAttributeContains(t, renamed, "reqMod", "entryCSN:= ")

	deleted := result.Entries[4]
	if got := deleted.GetAttributeValue("reqDN"); got != "uid=renamed,ou=people,dc=example,dc=com" {
		t.Fatalf("delete reqDN = %q", got)
	}
	if values := deleted.GetAttributeValues("reqOld"); len(values) != 0 {
		t.Fatalf("delete reqOld = %q, want none without olcAccessLogOld", values)
	}
}

func TestAccesslogOverlayFollowsTransactionCommitAndAbort(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoAccesslogProvider(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()

	observer := dialLDAPRoot(t, address)
	defer observer.Close()
	connection := dialAndBindRawLDAP(
		t,
		address,
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer connection.Close()

	identifier := startRawLDAPTransaction(t, connection, 2)
	response := sendRawLDAPOperation(
		t,
		connection,
		3,
		rawAddRequest(accesslogTransactionEntry("committed")),
		rawTransactionSpecificationControl(identifier, true, true),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultSuccess))
	if got := accesslogRecordCount(t, observer); got != 0 {
		t.Fatalf("records visible before transaction commit = %d, want 0", got)
	}
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 4, true, identifier),
		int64(ldapwire.ResultSuccess),
	)
	if got := accesslogRecordCount(t, observer); got != 1 {
		t.Fatalf("records after transaction commit = %d, want 1", got)
	}

	identifier = startRawLDAPTransaction(t, connection, 5)
	response = sendRawLDAPOperation(
		t,
		connection,
		6,
		rawAddRequest(accesslogTransactionEntry("aborted")),
		rawTransactionSpecificationControl(identifier, true, true),
	)
	assertRawLDAPResult(t, response, int64(ldapwire.ResultSuccess))
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 7, false, identifier),
		int64(ldapwire.ResultSuccess),
	)
	if got := accesslogRecordCount(t, observer); got != 1 {
		t.Fatalf("records after transaction abort = %d, want 1", got)
	}
	if entryExists(
		t,
		store,
		"uid=aborted,ou=people,dc=example,dc=com",
	) {
		t.Fatal("aborted transaction persisted its data entry")
	}
}

func TestAccesslogClockContinuesAcrossRestartAndClockRollback(t *testing.T) {
	store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoAccesslogProvider(t, store)
	config := Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	}
	address, stop := startServer(t, store, config)
	client := dialLDAPRoot(t, address)
	if err := client.Add(newAccesslogPersonAddRequest("bob")); err != nil {
		t.Fatalf("add bob before restart: %v", err)
	}
	client.Close()
	stop()

	const futureStart = "20990101000000.000000Z"
	partition := configuredDatabasePartition("{2}mdb")
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		var record directory.Entry
		if err := writer.ForEachIn(
			partition,
			func(entry directory.Entry) error {
				if entry.HasValue("reqDN", []byte(
					"uid=bob,ou=people,dc=example,dc=com",
				)) {
					record = entry
				}
				return nil
			},
		); err != nil {
			return err
		}
		if record.DN == "" {
			return errors.New("bob accesslog record was not found")
		}
		oldDN, err := directory.ParseDN(record.DN)
		if err != nil {
			return err
		}
		if err := writer.DeleteIn(partition, oldDN); err != nil {
			return err
		}
		record.DN = "reqStart=" + futureStart + ",cn=log"
		record.ReplaceValues("reqStart", stringValues(futureStart))
		return writer.PutIn(partition, record, false)
	}); err != nil {
		t.Fatalf("move accesslog record into the future: %v", err)
	}

	address, stop = startServer(t, store, config)
	defer stop()
	client = dialLDAPRoot(t, address)
	defer client.Close()
	if err := client.Add(newAccesslogPersonAddRequest("carol")); err != nil {
		t.Fatalf("add carol after restart: %v", err)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		"cn=log",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(reqDN=uid=carol,ou=people,dc=example,dc=com)",
		[]string{"reqStart"},
		nil,
	))
	if err != nil {
		t.Fatalf("search carol accesslog record: %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("carol accesslog record count = %d, want 1", len(result.Entries))
	}
	if got := result.Entries[0].GetAttributeValue("reqStart"); got != "20990101000000.000001Z" {
		t.Fatalf("carol reqStart = %q, want future timestamp plus one microsecond", got)
	}
}

func TestAccesslogOverlayConfigurationValidation(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		operations []string
		success    []string
		bases      []string
		oldFilter  string
		oldAttrs   []string
		wantError  string
	}{
		{
			name:       "valid writes configuration",
			target:     "cn=log",
			operations: []string{"writes"},
			success:    []string{"TRUE"},
		},
		{
			name:    "valid branch writes configuration",
			target:  "cn=log",
			success: []string{"TRUE"},
			bases: []string{
				`add|modify "ou=people,dc=example,dc=com"`,
			},
		},
		{
			name:      "branch configuration requires two arguments",
			target:    "cn=log",
			success:   []string{"TRUE"},
			bases:     []string{"writes"},
			wantError: "requires operations and a base DN",
		},
		{
			name:    "branch configuration accepts read logging",
			target:  "cn=log",
			success: []string{"TRUE"},
			bases:   []string{`reads "ou=people,dc=example,dc=com"`},
		},
		{
			name:      "branch configuration rejects invalid DN",
			target:    "cn=log",
			success:   []string{"TRUE"},
			bases:     []string{`writes "ou=people,dc=example,dc=com,"`},
			wantError: "invalid base DN",
		},
		{
			name:       "missing target database",
			target:     "cn=missing",
			operations: []string{"writes"},
			success:    []string{"TRUE"},
			wantError:  "has no configured database",
		},
		{
			name:       "source database as target",
			target:     "dc=example,dc=com",
			operations: []string{"writes"},
			success:    []string{"TRUE"},
			wantError:  "points to the source database",
		},
		{
			name:       "valid read logging",
			target:     "cn=log",
			operations: []string{"reads"},
			success:    []string{"TRUE"},
		},
		{
			name:       "valid failed operation logging",
			target:     "cn=log",
			operations: []string{"writes"},
			success:    []string{"FALSE"},
		},
		{
			name:       "success setting defaults false",
			target:     "cn=log",
			operations: []string{"writes"},
		},
		{
			name:       "unsupported operation",
			target:     "cn=log",
			operations: []string{"unsupported"},
			success:    []string{"TRUE"},
			wantError:  "value \"unsupported\" is not supported",
		},
		{
			name:       "invalid old-value filter",
			target:     "cn=log",
			operations: []string{"writes"},
			success:    []string{"TRUE"},
			oldFilter:  "(uid=",
			wantError:  "olcAccessLogOld",
		},
		{
			name:       "unknown old-value filter attribute",
			target:     "cn=log",
			operations: []string{"writes"},
			success:    []string{"TRUE"},
			oldFilter:  "(undefinedAccesslogAttribute=*)",
			wantError:  "filter references unknown attribute",
		},
		{
			name:       "unknown always-logged old attribute",
			target:     "cn=log",
			operations: []string{"writes"},
			success:    []string{"TRUE"},
			oldFilter:  "(objectClass=*)",
			oldAttrs:   []string{"undefinedAccesslogAttribute"},
			wantError:  "olcAccessLogOldAttr references unknown attribute",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedSyncProviderDirectory(t, store)
			seedAccesslogConfiguration(
				t,
				store,
				test.target,
				test.operations,
				test.success,
			)
			if len(test.bases) != 0 {
				configureLDAPGoAccesslogAttribute(
					t,
					store,
					"olcAccessLogBase",
					test.bases,
				)
			}
			if test.oldFilter != "" || len(test.oldAttrs) != 0 {
				configureLDAPGoAccesslogOld(
					t,
					store,
					test.oldFilter,
					test.oldAttrs,
				)
			}
			_, err := New(Config{
				Store:        store,
				RootDN:       syncTestRootDN,
				RootPassword: []byte(syncTestRootPassword),
			})
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("New(): %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("New() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestAccesslogOverlayRecordsReadsSessionsAndFailures(t *testing.T) {
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
	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()
	client := dialLDAPRoot(t, address)
	defer client.Close()

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
	search, err := client.Search(searchRequest)
	if err != nil || len(search.Entries) != 1 {
		t.Fatalf("search alice = %#v, %v", search, err)
	}
	matched, err := client.Compare(
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice Example",
	)
	if err != nil || !matched {
		t.Fatalf("compare alice = %t, %v", matched, err)
	}
	if _, err := client.WhoAmI(nil); err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	if err := client.Add(newPersonAddRequest("alice")); err == nil {
		t.Fatal("duplicate add unexpectedly succeeded")
	}
	missingModify := ldap.NewModifyRequest(
		"uid=missing,ou=people,dc=example,dc=com",
		nil,
	)
	missingModify.Replace("cn", []string{"Missing"})
	if err := client.Modify(missingModify); err == nil {
		t.Fatal("missing-entry modify unexpectedly succeeded")
	}

	session := dialLDAPRoot(t, address)
	if err := session.Unbind(); err != nil {
		t.Fatalf("Unbind: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	var result *ldap.SearchResult
	for {
		result, err = client.Search(ldap.NewSearchRequest(
			"cn=log",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=auditObject)",
			[]string{
				"objectClass", "reqType", "reqDN", "reqResult",
				"reqMessage", "reqMethod", "reqVersion", "reqAssertion",
				"reqScope", "reqDerefAliases", "reqAttrsOnly", "reqFilter",
				"reqAttr", "reqEntries", "reqSizeLimit", "reqTimeLimit",
				"reqMod", "reqId", "reqControls", "reqRespControls",
			},
			nil,
		))
		if err != nil {
			t.Fatalf("search complete accesslog: %v", err)
		}
		if accesslogEntriesContainTypes(
			result.Entries,
			"bind", "search", "compare", "add", "modify", "unbind",
		) {
			break
		}
		if time.Now().After(deadline) {
			observed := make([]string, 0, len(result.Entries))
			for _, entry := range result.Entries {
				observed = append(
					observed,
					entry.GetAttributeValue("reqType")+":"+
						entry.GetAttributeValue("reqResult"),
				)
			}
			t.Fatalf("accesslog operations did not converge: %q", observed)
		}
		time.Sleep(20 * time.Millisecond)
	}

	find := func(requestType string) *ldap.Entry {
		t.Helper()
		for _, entry := range result.Entries {
			if entry.GetAttributeValue("reqType") == requestType {
				return entry
			}
		}
		t.Fatalf("accesslog has no reqType %q", requestType)
		return nil
	}
	bind := find("bind")
	if bind.GetAttributeValue("reqVersion") != "3" ||
		bind.GetAttributeValue("reqMethod") != "SIMPLE" {
		t.Fatalf("bind accesslog = %#v", bind)
	}
	loggedSearch := find("search")
	if loggedSearch.GetAttributeValue("reqScope") != "base" ||
		loggedSearch.GetAttributeValue("reqDerefAliases") != "never" ||
		loggedSearch.GetAttributeValue("reqAttrsOnly") != "TRUE" ||
		loggedSearch.GetAttributeValue("reqEntries") != "1" ||
		loggedSearch.GetAttributeValue("reqSizeLimit") != "3" ||
		loggedSearch.GetAttributeValue("reqTimeLimit") != "2" ||
		loggedSearch.GetAttributeValue("reqFilter") !=
			"(&(objectClass=inetOrgPerson)(uid=alice))" {
		t.Fatalf("search accesslog = %#v", loggedSearch)
	}
	assertLDAPAttributeContains(
		t,
		loggedSearch,
		"reqControls",
		pagedResultsControlOID,
	)
	assertLDAPAttributeContains(
		t,
		loggedSearch,
		"reqRespControls",
		pagedResultsControlOID,
	)
	compare := find("compare")
	if compare.GetAttributeValue("reqResult") !=
		strconv.Itoa(int(ldapwire.ResultCompareTrue)) ||
		compare.GetAttributeValue("reqAssertion") != "cn=Alice Example" {
		t.Fatalf("compare accesslog = %#v", compare)
	}
	failedAdd := find("add")
	if failedAdd.GetAttributeValue("reqResult") !=
		strconv.Itoa(int(ldapwire.ResultEntryAlreadyExists)) {
		t.Fatalf("failed add accesslog = %#v", failedAdd)
	}
	assertLDAPAttributeContains(t, failedAdd, "reqMod", "uid:+ alice")
	failedModify := find("modify")
	if failedModify.GetAttributeValue("reqResult") !=
		strconv.Itoa(int(ldapwire.ResultNoSuchObject)) {
		t.Fatalf("failed modify accesslog = %#v", failedModify)
	}
	assertLDAPAttributeContains(t, failedModify, "reqMod", "cn:= Missing")
	for _, entry := range result.Entries {
		if entry.GetAttributeValue("reqType") == "extended{"+whoAmIOID+"}" {
			t.Fatal("frontend Who Am I operation was written to database accesslog")
		}
	}
}

func accesslogEntriesContainTypes(entries []*ldap.Entry, want ...string) bool {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		seen[entry.GetAttributeValue("reqType")] = struct{}{}
	}
	for _, requestType := range want {
		if _, exists := seen[requestType]; !exists {
			return false
		}
	}
	return true
}

func TestAccesslogOverlayAppliesBranchOperationSelection(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)
	seedAccesslogConfiguration(
		t,
		store,
		"cn=log",
		nil,
		[]string{"TRUE"},
	)
	configureLDAPGoAccesslogAttribute(
		t,
		store,
		"olcAccessLogBase",
		[]string{`add|modify "ou=people,dc=example,dc=com"`},
	)
	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()
	client := dialLDAPRoot(t, address)
	defer client.Close()

	if err := client.Add(newAccesslogPersonAddRequest("branch")); err != nil {
		t.Fatalf("add branch entry: %v", err)
	}
	modifyBranch := ldap.NewModifyRequest(
		"uid=branch,ou=people,dc=example,dc=com",
		nil,
	)
	modifyBranch.Replace("cn", []string{"Branch Updated"})
	if err := client.Modify(modifyBranch); err != nil {
		t.Fatalf("modify branch entry: %v", err)
	}
	modifySuffix := ldap.NewModifyRequest("dc=example,dc=com", nil)
	modifySuffix.Replace("description", []string{"outside selected branch"})
	if err := client.Modify(modifySuffix); err != nil {
		t.Fatalf("modify source suffix: %v", err)
	}
	if err := client.Del(ldap.NewDelRequest(
		"uid=branch,ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("delete branch entry: %v", err)
	}

	result, err := client.Search(ldap.NewSearchRequest(
		"cn=log",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=auditWriteObject)",
		[]string{"reqType", "reqDN"},
		nil,
	))
	if err != nil {
		t.Fatalf("search branch accesslog records: %v", err)
	}
	if len(result.Entries) != 2 {
		t.Fatalf("branch accesslog record count = %d, want 2", len(result.Entries))
	}
	for _, entry := range result.Entries {
		if got := entry.GetAttributeValue("reqDN"); got != "uid=branch,ou=people,dc=example,dc=com" {
			t.Fatalf("branch reqDN = %q", got)
		}
		operation := entry.GetAttributeValue("reqType")
		if operation != "add" && operation != "modify" {
			t.Fatalf("branch reqType = %q", operation)
		}
	}
}

func TestParseAccesslogAge(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value string
		want  time.Duration
	}{
		{value: "00:01", want: time.Minute},
		{value: "01:02:03", want: time.Hour + 2*time.Minute + 3*time.Second},
		{value: "2+03:04", want: 51*time.Hour + 4*time.Minute},
		{value: "2+03:04:05", want: 51*time.Hour + 4*time.Minute + 5*time.Second},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			got, err := parseAccesslogAge(test.value)
			if err != nil {
				t.Fatalf("parseAccesslogAge(%q): %v", test.value, err)
			}
			if got != test.want {
				t.Fatalf("parseAccesslogAge(%q) = %s, want %s", test.value, got, test.want)
			}
		})
	}
	for _, value := range []string{
		"",
		"0:00",
		"00:00",
		"00:60",
		"00:00:60",
		"1+0:00",
		"25001+00:00",
		"00:00 extra",
	} {
		if _, err := parseAccesslogAge(value); err == nil {
			t.Errorf("parseAccesslogAge(%q) succeeded", value)
		}
	}
}

func TestAccesslogPurgeRemovesExpiredRecordsAndAdvancesMinCSN(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoAccesslogProvider(t, store)
	configureLDAPGoAccesslogAttribute(
		t,
		store,
		"olcAccessLogPurge",
		[]string{"00:00:01 00:00:01"},
	)
	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()
	client := dialLDAPRoot(t, address)
	defer client.Close()
	if err := client.Add(newPersonAddRequest("purged")); err != nil {
		t.Fatalf("add purge candidate: %v", err)
	}

	partition := configuredDatabasePartition("{2}mdb")
	const oldStart = "20000101000000.000000Z"
	var purgedCSN string
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		var record directory.Entry
		if err := writer.ForEachIn(
			partition,
			func(entry directory.Entry) error {
				if entry.HasValue("reqDN", []byte(
					"uid=purged,ou=people,dc=example,dc=com",
				)) {
					record = entry
				}
				return nil
			},
		); err != nil {
			return err
		}
		if record.DN == "" {
			return errors.New("purge candidate accesslog record was not found")
		}
		csns := record.Values("entryCSN")
		if len(csns) != 1 {
			return fmt.Errorf("purge candidate entryCSN = %q", csns)
		}
		purgedCSN = string(csns[0])
		oldDN, err := directory.ParseDN(record.DN)
		if err != nil {
			return err
		}
		if err := writer.DeleteIn(partition, oldDN); err != nil {
			return err
		}
		record.DN = "reqStart=" + oldStart + ",cn=log"
		record.ReplaceValues("reqStart", stringValues(oldStart))
		return writer.PutIn(partition, record, false)
	}); err != nil {
		t.Fatalf("age accesslog purge candidate: %v", err)
	}

	deadline := time.Now().Add(4 * time.Second)
	for {
		result, err := client.Search(ldap.NewSearchRequest(
			"cn=log",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(reqDN=uid=purged,ou=people,dc=example,dc=com)",
			[]string{"1.1"},
			nil,
		))
		if err != nil {
			t.Fatalf("search purge candidate: %v", err)
		}
		if len(result.Entries) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("accesslog purge did not remove the expired record")
		}
		time.Sleep(20 * time.Millisecond)
	}
	container, err := client.Search(ldap.NewSearchRequest(
		"cn=log",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=auditContainer)",
		[]string{"minCSN"},
		nil,
	))
	if err != nil {
		t.Fatalf("search accesslog minCSN: %v", err)
	}
	if len(container.Entries) != 1 ||
		!containsString(container.Entries[0].GetAttributeValues("minCSN"), purgedCSN) {
		t.Fatalf("accesslog minCSN = %#v, want %q", container.Entries, purgedCSN)
	}
}

func TestAccesslogSyncProviderRejectsCookieOlderThanMinCSN(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPGoAccesslogProvider(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stop()

	client := dialLDAPRoot(t, address)
	container, err := client.Search(ldap.NewSearchRequest(
		"cn=log",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=auditContainer)",
		[]string{"minCSN"},
		nil,
	))
	client.Close()
	if err != nil {
		t.Fatalf("search accesslog minCSN: %v", err)
	}
	if len(container.Entries) != 1 {
		t.Fatalf("accesslog container count = %d, want 1", len(container.Entries))
	}
	minimum, err := parseOpenLDAPCSN(
		container.Entries[0].GetAttributeValue("minCSN"),
	)
	if err != nil {
		t.Fatalf("parse accesslog minCSN: %v", err)
	}
	stale, err := parseOpenLDAPCSN(fmt.Sprintf(
		"20000101000000.000000Z#000000#%03x#000000",
		minimum.serverID,
	))
	if err != nil {
		t.Fatalf("construct stale CSN: %v", err)
	}
	connection := dialAndBindRawLDAP(
		t,
		address,
		syncTestRootDN,
		syncTestRootPassword,
	)
	defer connection.Close()
	search := rawSyncSearchRequestFor(
		t,
		"cn=log",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		"(objectClass=auditWriteObject)",
	)
	rejected := requestRawSyncRefresh(
		t,
		connection,
		2,
		search,
		ldapwire.SyncRequestValue{
			Mode:      ldapwire.SyncRefreshOnly,
			Cookie:    composeOpenLDAPSyncCookie(0, syncCSNState{stale.serverID: stale}),
			HasCookie: true,
		},
	)
	if rejected.resultCode != int64(ldapwire.ResultSyncRefreshRequired) ||
		rejected.done != nil || len(rejected.entries) != 0 {
		t.Fatalf("stale accesslog cookie response = %#v", rejected)
	}

	accepted := requestRawSyncRefresh(
		t,
		connection,
		3,
		search,
		ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshOnly,
			Cookie: composeOpenLDAPSyncCookie(
				0,
				syncCSNState{minimum.serverID: minimum},
			),
			HasCookie: true,
		},
	)
	if accepted.resultCode != int64(ldapwire.ResultSuccess) || accepted.done == nil {
		t.Fatalf("boundary accesslog cookie response = %#v", accepted)
	}
}

func TestAccesslogOverlayOnlineLifecycleAndRollback(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	config := Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	}
	address, stop := startServer(t, store, config)
	configClient := bindUniqueClient(t, address, "cn=config", "config-secret")
	dataClient := dialLDAPRoot(t, address)

	logDatabase := ldap.NewAddRequest(
		"olcDatabase={2}mdb,cn=config",
		nil,
	)
	logDatabase.Attribute("objectClass", []string{"olcDatabaseConfig"})
	logDatabase.Attribute("olcDatabase", []string{"{2}mdb"})
	logDatabase.Attribute("olcSuffix", []string{"cn=log"})
	logDatabase.Attribute(
		"olcAccess",
		[]string{"{0}to * by users read by * none"},
	)
	if err := configClient.Add(logDatabase); err != nil {
		t.Fatalf("add online accesslog database: %v", err)
	}

	const overlayDN = "olcOverlay={0}accesslog,olcDatabase={1}mdb,cn=config"
	overlay := ldap.NewAddRequest(overlayDN, nil)
	overlay.Attribute(
		"objectClass",
		[]string{"olcOverlayConfig", "olcAccessLogConfig"},
	)
	overlay.Attribute("olcOverlay", []string{"{0}accesslog"})
	overlay.Attribute("olcAccessLogDB", []string{"cn=log"})
	overlay.Attribute("olcAccessLogOps", []string{"writes"})
	overlay.Attribute("olcAccessLogSuccess", []string{"TRUE"})
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("add online accesslog overlay: %v", err)
	}
	if got := accesslogRecordCount(t, dataClient); got != 0 {
		t.Fatalf("initial online accesslog records = %d, want 0", got)
	}
	if err := dataClient.Add(newPersonAddRequest("online-one")); err != nil {
		t.Fatalf("add with online accesslog: %v", err)
	}
	if got := accesslogRecordCount(t, dataClient); got != 1 {
		t.Fatalf("online accesslog records after first add = %d, want 1", got)
	}

	invalid := ldap.NewModifyRequest(overlayDN, nil)
	invalid.Replace("olcAccessLogOps", []string{"unsupported"})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	configured := readStoredEntry(t, store, overlayDN).Values("olcAccessLogOps")
	if len(configured) != 1 || string(configured[0]) != "writes" {
		t.Fatalf("accesslog config after rollback = %q, want writes", configured)
	}
	if err := dataClient.Add(newPersonAddRequest("online-two")); err != nil {
		t.Fatalf("add after accesslog config rollback: %v", err)
	}
	if got := accesslogRecordCount(t, dataClient); got != 2 {
		t.Fatalf("online accesslog records after rollback = %d, want 2", got)
	}

	if err := configClient.Del(ldap.NewDelRequest(overlayDN, nil)); err != nil {
		t.Fatalf("delete online accesslog overlay: %v", err)
	}
	if err := dataClient.Add(newPersonAddRequest("online-three")); err != nil {
		t.Fatalf("add after disabling accesslog: %v", err)
	}
	if got := accesslogRecordCount(t, dataClient); got != 2 {
		t.Fatalf("records after disabling accesslog = %d, want 2", got)
	}
	configClient.Close()
	dataClient.Close()
	stop()

	address, stop = startServer(t, store, config)
	defer stop()
	dataClient = dialLDAPRoot(t, address)
	defer dataClient.Close()
	if err := dataClient.Add(newPersonAddRequest("online-four")); err != nil {
		t.Fatalf("add after disabled accesslog restart: %v", err)
	}
	if got := accesslogRecordCount(t, dataClient); got != 2 {
		t.Fatalf("records after disabled accesslog restart = %d, want 2", got)
	}
}

func TestLDAPGoAccesslogProviderFeedsDeltaSyncreplConsumer(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPGoAccesslogProvider(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopProvider()

	consumerStore := storage.NewMemory()
	t.Cleanup(func() { _ = consumerStore.Close() })
	seedOpenLDAPAccesslogConsumer(t, consumerStore, providerAddress)
	consumerAddress, stopConsumer := startServer(t, consumerStore, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopConsumer()
	consumer := dialLDAPRoot(t, consumerAddress)
	defer consumer.Close()
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice Example",
	)

	provider := dialLDAPRoot(t, providerAddress)
	defer provider.Close()
	modify := ldap.NewModifyRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Alice Delta"})
	if err := provider.Modify(modify); err != nil {
		t.Fatalf("provider modify alice: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=alice,ou=people,dc=example,dc=com",
		"cn",
		"Alice Delta",
	)

	if err := provider.Add(newAccesslogPersonAddRequest("bob")); err != nil {
		t.Fatalf("provider add bob: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=bob,ou=people,dc=example,dc=com",
		"uid",
		"bob",
	)
	modifyBob := ldap.NewModifyRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		nil,
	)
	modifyBob.Add("description", []string{"first", "second"})
	modifyBob.Delete("description", []string{"first"})
	modifyBob.Increment("uidNumber", "5")
	if err := provider.Modify(modifyBob); err != nil {
		t.Fatalf("provider modify bob deltas: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=bob,ou=people,dc=example,dc=com",
		"description",
		"second",
	)
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=bob,ou=people,dc=example,dc=com",
		"uidNumber",
		"15",
	)
	if _, err := provider.PasswordModify(ldap.NewPasswordModifyRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		"",
		"delta-secret",
	)); err != nil {
		t.Fatalf("provider password modify bob: %v", err)
	}
	waitForAccesslogConsumerBind(
		t,
		consumerAddress,
		"uid=bob,ou=people,dc=example,dc=com",
		"delta-secret",
	)
	rename := ldap.NewModifyDNRequest(
		"uid=bob,ou=people,dc=example,dc=com",
		"uid=renamed",
		true,
		"",
	)
	if err := provider.ModifyDN(rename); err != nil {
		t.Fatalf("provider rename bob: %v", err)
	}
	waitForSyncConsumerAttribute(
		t,
		consumer,
		"uid=renamed,ou=people,dc=example,dc=com",
		"uid",
		"renamed",
	)
	waitForSyncConsumerMissing(
		t,
		consumer,
		"uid=bob,ou=people,dc=example,dc=com",
	)
	if err := provider.Del(ldap.NewDelRequest(
		"uid=renamed,ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("provider delete renamed: %v", err)
	}
	waitForSyncConsumerMissing(
		t,
		consumer,
		"uid=renamed,ou=people,dc=example,dc=com",
	)
}

func seedLDAPGoAccesslogProvider(t *testing.T, store storage.Store) {
	t.Helper()
	seedSyncProviderDirectory(t, store)
	seedAccesslogConfiguration(
		t,
		store,
		"cn=log",
		[]string{"writes"},
		[]string{"TRUE"},
	)
}

func configureLDAPGoAccesslogOld(
	t *testing.T,
	store storage.Store,
	filter string,
	attributes []string,
) {
	t.Helper()
	dn, err := directory.ParseDN(
		"olcOverlay={1}accesslog,olcDatabase={1}mdb,cn=config",
	)
	if err != nil {
		t.Fatalf("parse accesslog overlay DN: %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccessLogOld", stringValues(filter))
		entry.ReplaceValues("olcAccessLogOldAttr", stringValues(attributes...))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure accesslog old values: %v", err)
	}
}

func configureLDAPGoAccesslogAttribute(
	t *testing.T,
	store storage.Store,
	description string,
	values []string,
) {
	t.Helper()
	dn, err := directory.ParseDN(
		"olcOverlay={1}accesslog,olcDatabase={1}mdb,cn=config",
	)
	if err != nil {
		t.Fatalf("parse accesslog overlay DN: %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues(description, stringValues(values...))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure accesslog %s: %v", description, err)
	}
}

func newAccesslogPersonAddRequest(uid string) *ldap.AddRequest {
	request := newPersonAddRequest(uid)
	for index := range request.Attributes {
		if strings.EqualFold(request.Attributes[index].Type, "objectClass") {
			request.Attributes[index].Vals = append(
				request.Attributes[index].Vals,
				"posixAccount",
			)
			break
		}
	}
	request.Attribute("uidNumber", []string{"10"})
	request.Attribute("gidNumber", []string{"10"})
	request.Attribute("homeDirectory", []string{"/home/" + uid})
	return request
}

func seedAccesslogConfiguration(
	t *testing.T,
	store storage.Store,
	target string,
	operations,
	success []string,
) {
	t.Helper()
	logDatabase := directory.Entry{
		DN: "olcDatabase={2}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{2}mdb")},
			{Description: "olcSuffix", Values: stringValues("cn=log")},
			{
				Description: "olcAccess",
				Values: stringValues(
					"{0}to * by dn.exact=\"" + syncTestRootDN + "\" manage by users read by * none",
				),
			},
		},
	}
	accesslogAttributes := []directory.Attribute{
		{Description: "olcOverlay", Values: stringValues("{1}accesslog")},
		{Description: "olcAccessLogDB", Values: stringValues(target)},
	}
	if len(operations) != 0 {
		accesslogAttributes = append(accesslogAttributes, directory.Attribute{
			Description: "olcAccessLogOps",
			Values:      stringValues(operations...),
		})
	}
	if len(success) != 0 {
		accesslogAttributes = append(accesslogAttributes, directory.Attribute{
			Description: "olcAccessLogSuccess",
			Values:      stringValues(success...),
		})
	}
	entries := []directory.Entry{
		logDatabase,
		{
			DN:         "olcOverlay={1}accesslog,olcDatabase={1}mdb,cn=config",
			Attributes: accesslogAttributes,
		},
		{
			DN: "olcOverlay={0}syncprov,olcDatabase={2}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("{0}syncprov")},
				{Description: "olcSpNoPresent", Values: stringValues("TRUE")},
				{Description: "olcSpReloadHint", Values: stringValues("TRUE")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed accesslog configuration: %v", err)
	}
}

func assertLDAPAttributeContains(
	t *testing.T,
	entry *ldap.Entry,
	description,
	want string,
) {
	t.Helper()
	for _, value := range entry.GetAttributeValues(description) {
		if strings.Contains(value, want) {
			return
		}
	}
	t.Fatalf("%s %s = %q, want value containing %q", entry.DN, description, entry.GetAttributeValues(description), want)
}

func equalStringSets(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, value := range left {
		counts[value]++
	}
	for _, value := range right {
		counts[value]--
		if counts[value] < 0 {
			return false
		}
	}
	return true
}

func accesslogTransactionEntry(uid string) directory.Entry {
	return directory.Entry{
		DN: "uid=" + uid + ",ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues(uid)},
			{Description: "cn", Values: stringValues(uid)},
			{Description: "sn", Values: stringValues(uid)},
		},
	}
}

func accesslogRecordCount(t *testing.T, client *ldap.Conn) int {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		"cn=log",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=auditWriteObject)",
		[]string{"1.1"},
		nil,
	))
	if err != nil {
		t.Fatalf("count accesslog records: %v", err)
	}
	return len(result.Entries)
}

func waitForAccesslogConsumerBind(
	t *testing.T,
	address,
	dn,
	password string,
) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		client, err := ldap.DialURL("ldap://" + address)
		if err == nil {
			err = client.Bind(dn, password)
			client.Close()
		}
		if err == nil {
			return
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("consumer bind %s did not converge: %v", dn, lastErr)
}
