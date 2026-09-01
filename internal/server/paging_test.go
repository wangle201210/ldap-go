package server

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientSearchWithPaging(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	expectedUIDs := seedPagedPeople(t, store, 7)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()

	request := newPagedPeopleSearch(0, nil)
	result, err := client.SearchWithPaging(request, 3)
	if err != nil {
		t.Fatalf("SearchWithPaging(): %v", err)
	}
	gotUIDs := pagedResultUIDs(t, result)
	slices.Sort(gotUIDs)
	if !slices.Equal(gotUIDs, expectedUIDs) {
		t.Fatalf("paged UIDs = %q, want %q", gotUIDs, expectedUIDs)
	}

	rootDSE, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedControl"},
		nil,
	))
	if err != nil || len(rootDSE.Entries) != 1 ||
		!containsString(
			rootDSE.Entries[0].GetAttributeValues("supportedControl"),
			pagedResultsControlOID,
		) {
		t.Fatalf("paged results Root DSE = %#v, %v", rootDSE, err)
	}
}

func TestLDAPClientPagedSearchCookieLifecycle(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedPagedPeople(t, store, 7)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	t.Run("page size may change", func(t *testing.T) {
		client := bindPagedRootClient(t, address)
		defer client.Close()
		control := ldap.NewControlPaging(2)
		request := newPagedPeopleSearch(0, control)
		first, err := client.Search(request)
		if err != nil || len(first.Entries) != 2 {
			t.Fatalf("first page = %#v, %v", first, err)
		}
		firstControl := pagedResponseControl(t, first)
		if firstControl.PagingSize != 0 || len(firstControl.Cookie) == 0 {
			t.Fatalf("first response control = %#v", firstControl)
		}

		control.SetCookie(bytes.Clone(firstControl.Cookie))
		control.PagingSize = 3
		second, err := client.Search(request)
		if err != nil || len(second.Entries) != 3 {
			t.Fatalf("second page = %#v, %v", second, err)
		}
		if len(pagedResponseControl(t, second).Cookie) == 0 {
			t.Fatal("second page unexpectedly completed the result set")
		}
	})

	t.Run("old cookie", func(t *testing.T) {
		client := bindPagedRootClient(t, address)
		defer client.Close()
		control := ldap.NewControlPaging(2)
		request := newPagedPeopleSearch(0, control)
		first, err := client.Search(request)
		if err != nil {
			t.Fatalf("first page: %v", err)
		}
		oldCookie := bytes.Clone(pagedResponseControl(t, first).Cookie)
		control.SetCookie(oldCookie)
		second, err := client.Search(request)
		if err != nil {
			t.Fatalf("second page: %v", err)
		}
		if len(pagedResponseControl(t, second).Cookie) == 0 {
			t.Fatal("second page unexpectedly completed the result set")
		}

		control.SetCookie(oldCookie)
		_, err = client.Search(request)
		assertLDAPResultCode(t, err, ldap.LDAPResultUnwillingToPerform)
	})

	t.Run("changed query", func(t *testing.T) {
		client := bindPagedRootClient(t, address)
		defer client.Close()
		control := ldap.NewControlPaging(2)
		request := newPagedPeopleSearch(0, control)
		first, err := client.Search(request)
		if err != nil {
			t.Fatalf("first page: %v", err)
		}
		control.SetCookie(bytes.Clone(pagedResponseControl(t, first).Cookie))
		request.Attributes = []string{"cn"}
		_, err = client.Search(request)
		assertLDAPResultCode(t, err, ldap.LDAPResultUnwillingToPerform)
	})

	t.Run("malformed cookie", func(t *testing.T) {
		client := bindPagedRootClient(t, address)
		defer client.Close()
		control := ldap.NewControlPaging(2)
		control.SetCookie([]byte("bad"))
		_, err := client.Search(newPagedPeopleSearch(0, control))
		assertLDAPResultCode(t, err, ldap.LDAPResultProtocolError)
	})

	t.Run("abandon", func(t *testing.T) {
		client := bindPagedRootClient(t, address)
		defer client.Close()
		control := ldap.NewControlPaging(2)
		request := newPagedPeopleSearch(0, control)
		first, err := client.Search(request)
		if err != nil {
			t.Fatalf("first page: %v", err)
		}
		cookie := bytes.Clone(pagedResponseControl(t, first).Cookie)
		control.SetCookie(cookie)
		control.PagingSize = 0
		abandoned, err := client.Search(request)
		if err != nil || len(abandoned.Entries) != 0 ||
			ldap.FindControl(
				abandoned.Controls,
				ldap.ControlTypePaging,
			) != nil {
			t.Fatalf("abandon response = %#v, %v", abandoned, err)
		}

		control.PagingSize = 2
		_, err = client.Search(request)
		assertLDAPResultCode(t, err, ldap.LDAPResultUnwillingToPerform)
	})

	t.Run("empty cookie with size zero", func(t *testing.T) {
		client := bindPagedRootClient(t, address)
		defer client.Close()
		control := ldap.NewControlPaging(0)
		result, err := client.Search(newPagedPeopleSearch(0, control))
		if err != nil || len(result.Entries) != 8 ||
			ldap.FindControl(
				result.Controls,
				ldap.ControlTypePaging,
			) != nil {
			t.Fatalf("unpaged size-zero response = %#v, %v", result, err)
		}
	})

	t.Run("bind resets cookie", func(t *testing.T) {
		client := bindPagedRootClient(t, address)
		defer client.Close()
		control := ldap.NewControlPaging(2)
		request := newPagedPeopleSearch(0, control)
		first, err := client.Search(request)
		if err != nil {
			t.Fatalf("first page: %v", err)
		}
		control.SetCookie(bytes.Clone(pagedResponseControl(t, first).Cookie))
		if err := client.Bind(
			"cn=admin,dc=example,dc=com",
			"admin-secret",
		); err != nil {
			t.Fatalf("rebind: %v", err)
		}
		_, err = client.Search(request)
		assertLDAPResultCode(t, err, ldap.LDAPResultUnwillingToPerform)
	})
}

func TestLDAPClientPagedSearchHonorsTotalSizeLimit(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedPagedPeople(t, store, 7)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()

	result, err := client.SearchWithPaging(newPagedPeopleSearch(5, nil), 2)
	assertLDAPResultCode(t, err, ldap.LDAPResultSizeLimitExceeded)
	if len(result.Entries) != 5 {
		t.Fatalf("entries before size limit = %d, want 5", len(result.Entries))
	}
}

func TestLDAPClientPagedSearchIgnoresPageAtRequestSizeLimit(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedPagedPeople(t, store, 2)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	matchCases := []struct {
		name       string
		filter     string
		matches    int
		resultCode uint16
	}{
		{
			name:       "fewer matches",
			filter:     "(uid=alice)",
			matches:    1,
			resultCode: ldap.LDAPResultSuccess,
		},
		{
			name:       "equal matches",
			filter:     "(|(uid=alice)(uid=page-00))",
			matches:    2,
			resultCode: ldap.LDAPResultSuccess,
		},
		{
			name:       "more matches",
			filter:     "(|(uid=alice)(uid=page-00)(uid=page-01))",
			matches:    2,
			resultCode: ldap.LDAPResultSizeLimitExceeded,
		},
	}
	for _, pageSize := range []uint32{2, 3} {
		pageName := "equal page size"
		if pageSize > 2 {
			pageName = "greater page size"
		}
		for _, critical := range []bool{false, true} {
			criticalName := "noncritical"
			if critical {
				criticalName = "critical"
			}
			for _, matchCase := range matchCases {
				t.Run(
					fmt.Sprintf("%s/%s/%s", pageName, criticalName, matchCase.name),
					func(t *testing.T) {
						client := bindPagedRootClient(t, address)
						defer client.Close()

						request := newPagedPeopleSearch(2, nil)
						request.Filter = matchCase.filter
						request.Controls = []ldap.Control{&ldap.ControlString{
							ControlType: pagedResultsControlOID,
							Criticality: critical,
							ControlValue: string(
								ldapwire.EncodePagedResultsValue(int(pageSize), nil),
							),
						}}

						result, err := client.Search(request)
						if matchCase.resultCode == ldap.LDAPResultSuccess {
							if err != nil {
								t.Fatalf("Search(): %v", err)
							}
						} else {
							assertLDAPResultCode(t, err, matchCase.resultCode)
						}
						entryCount := 0
						if result != nil {
							entryCount = len(result.Entries)
						}
						if entryCount != matchCase.matches {
							t.Fatalf(
								"Search() entries = %d, want %d",
								entryCount,
								matchCase.matches,
							)
						}
						if result == nil {
							t.Fatal("Search() returned a nil result")
						}
						if control := ldap.FindControl(
							result.Controls,
							ldap.ControlTypePaging,
						); control != nil {
							t.Fatalf("ignored paging response control = %#v", control)
						}
					},
				)
			}
		}
	}
}

func TestLDAPClientPagedSearchAcrossGlueDatabases(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedGlueConfiguration(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()

	request := ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	)
	unpaged, err := client.Search(request)
	if err != nil {
		t.Fatalf("unpaged glue Search(): %v", err)
	}
	paged, err := client.SearchWithPaging(ldap.NewSearchRequest(
		request.BaseDN,
		request.Scope,
		request.DerefAliases,
		request.SizeLimit,
		request.TimeLimit,
		request.TypesOnly,
		request.Filter,
		request.Attributes,
		nil,
	), 1)
	if err != nil {
		t.Fatalf("paged glue Search(): %v", err)
	}
	unpagedDNs := searchResultDNs(unpaged)
	pagedDNs := searchResultDNs(paged)
	slices.Sort(unpagedDNs)
	slices.Sort(pagedDNs)
	if !slices.Equal(pagedDNs, unpagedDNs) {
		t.Fatalf("paged glue DNs = %q, want %q", pagedDNs, unpagedDNs)
	}
}

func TestLDAPClientPagedSearchContinuesAcrossMutations(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	expectedUIDs := seedPagedPeople(t, store, 7)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()

	control := ldap.NewControlPaging(2)
	request := newPagedPeopleSearch(0, control)
	first, err := client.Search(request)
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	allUIDs := pagedResultUIDs(t, first)
	cookie := bytes.Clone(pagedResponseControl(t, first).Cookie)

	deletedUID := "page-04"
	addedUID := "zz-page-new"
	err = store.Update(context.Background(), func(writer storage.Writer) error {
		tx := storage.WriterInPartition(
			writer,
			configuredDatabasePartition("{1}mdb"),
		)
		deletedDN, err := directory.ParseDN(
			"uid=" + deletedUID + ",ou=people,dc=example,dc=com",
		)
		if err != nil {
			return err
		}
		if err := tx.Delete(deletedDN); err != nil {
			return err
		}
		return tx.Put(directory.Entry{
			DN: "uid=" + addedUID + ",ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{
					Description: "objectClass",
					Values:      stringValues("inetOrgPerson"),
				},
				{Description: "uid", Values: stringValues(addedUID)},
				{Description: "cn", Values: stringValues("Mutation User")},
				{Description: "sn", Values: stringValues("User")},
			},
		}, false)
	})
	if err != nil {
		t.Fatalf("mutate paged result set: %v", err)
	}

	for page := 0; len(cookie) > 0; page++ {
		if page > 10 {
			t.Fatal("paged search did not terminate")
		}
		control.SetCookie(cookie)
		result, err := client.Search(request)
		if err != nil {
			t.Fatalf("page %d after mutation: %v", page+2, err)
		}
		allUIDs = append(allUIDs, pagedResultUIDs(t, result)...)
		cookie = bytes.Clone(pagedResponseControl(t, result).Cookie)
	}

	expectedUIDs = slices.DeleteFunc(expectedUIDs, func(uid string) bool {
		return uid == deletedUID
	})
	expectedUIDs = append(expectedUIDs, addedUID)
	slices.Sort(expectedUIDs)
	slices.Sort(allUIDs)
	if !slices.Equal(allUIDs, expectedUIDs) {
		t.Fatalf("UIDs across mutation = %q, want %q", allUIDs, expectedUIDs)
	}
}

func TestBoltPagedSubstringSearchContinuesAcrossMutations(t *testing.T) {
	t.Parallel()

	store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	expectedUIDs := seedPagedPeople(t, store, 20)[1:]
	configDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(configDN)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcDbIndex", stringValues("uid eq"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure uid equality index: %v", err)
	}

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()

	control := ldap.NewControlPaging(3)
	request := ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=page-*)",
		[]string{"uid"},
		[]ldap.Control{control},
	)
	first, err := client.Search(request)
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	allUIDs := pagedResultUIDs(t, first)
	cookie := bytes.Clone(pagedResponseControl(t, first).Cookie)

	returned := make(map[string]struct{}, len(allUIDs))
	for _, uid := range allUIDs {
		returned[uid] = struct{}{}
	}
	deletedUID := ""
	for _, uid := range expectedUIDs {
		if _, found := returned[uid]; !found {
			deletedUID = uid
			break
		}
	}
	if deletedUID == "" {
		t.Fatal("first page unexpectedly returned every seeded entry")
	}
	addedUID := "page-99-new"
	if err := client.Del(ldap.NewDelRequest(
		"uid="+deletedUID+",ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("delete during paged search: %v", err)
	}
	deletedResult, err := client.Search(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid="+deletedUID+")",
		[]string{"1.1"},
		nil,
	))
	if err != nil || len(deletedResult.Entries) != 0 {
		t.Fatalf("deleted entry remains visible: %#v, %v", deletedResult, err)
	}
	if err := client.Add(newPersonAddRequest(addedUID)); err != nil {
		t.Fatalf("add during paged search: %v", err)
	}

	for page := 0; len(cookie) > 0; page++ {
		if page > 20 {
			t.Fatal("paged search did not terminate")
		}
		control.SetCookie(cookie)
		result, err := client.Search(request)
		if err != nil {
			t.Fatalf("page %d after mutation: %v", page+2, err)
		}
		allUIDs = append(allUIDs, pagedResultUIDs(t, result)...)
		cookie = bytes.Clone(pagedResponseControl(t, result).Cookie)
	}

	expectedUIDs = slices.DeleteFunc(expectedUIDs, func(uid string) bool {
		return uid == deletedUID
	})
	if slices.Contains(allUIDs, addedUID) {
		expectedUIDs = append(expectedUIDs, addedUID)
	}
	slices.Sort(expectedUIDs)
	slices.Sort(allUIDs)
	if !slices.Equal(allUIDs, expectedUIDs) {
		t.Fatalf(
			"Bolt keyset first/deleted/all = %q/%q/%q, want %q",
			returned,
			deletedUID,
			allUIDs,
			expectedUIDs,
		)
	}
}

func TestParsePagedResultsControl(t *testing.T) {
	t.Parallel()

	valid := ldapwire.Control{
		OID:      pagedResultsControlOID,
		Critical: true,
		Value:    ldapwire.EncodePagedResultsValue(25, []byte("cookie")),
		HasValue: true,
	}
	parsed, result := parseRequestControls(
		[]ldapwire.Control{valid},
		supportsPagedResults,
	)
	if result != nil || parsed.paging == nil ||
		parsed.paging.size != 25 ||
		!bytes.Equal(parsed.paging.cookie, []byte("cookie")) {
		t.Fatalf("valid paging control = %#v, %#v", parsed, result)
	}

	tests := []struct {
		name      string
		controls  []ldapwire.Control
		supported requestControlSupport
		wantCode  ldapwire.ResultCode
	}{
		{
			name:      "absent value",
			controls:  []ldapwire.Control{{OID: pagedResultsControlOID}},
			supported: supportsPagedResults,
			wantCode:  ldapwire.ResultProtocolError,
		},
		{
			name: "empty value",
			controls: []ldapwire.Control{{
				OID:      pagedResultsControlOID,
				HasValue: true,
			}},
			supported: supportsPagedResults,
			wantCode:  ldapwire.ResultProtocolError,
		},
		{
			name: "malformed value",
			controls: []ldapwire.Control{{
				OID:      pagedResultsControlOID,
				Value:    []byte{0x30, 0x00},
				HasValue: true,
			}},
			supported: supportsPagedResults,
			wantCode:  ldapwire.ResultProtocolError,
		},
		{
			name:      "duplicate",
			controls:  []ldapwire.Control{valid, valid},
			supported: supportsPagedResults,
			wantCode:  ldapwire.ResultProtocolError,
		},
		{
			name: "critical on non-search operation",
			controls: []ldapwire.Control{{
				OID:      pagedResultsControlOID,
				Critical: true,
				Value:    valid.Value,
				HasValue: true,
			}},
			supported: supportsAssertion,
			wantCode:  ldapwire.ResultUnavailableCriticalExtension,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, result := parseRequestControls(test.controls, test.supported)
			if result == nil || result.Code != test.wantCode {
				t.Fatalf("parseRequestControls() result = %#v", result)
			}
		})
	}
}

func TestPagedSearchFingerprint(t *testing.T) {
	t.Parallel()

	request := ldapwire.SearchRequest{
		BaseDN: "dc=example,dc=com",
		Scope:  directory.ScopeWholeSubtree,
		Filter: directory.Filter{
			Kind:      directory.FilterPresent,
			Attribute: "objectClass",
		},
		Attributes: []string{"uid"},
	}
	first := []ldapwire.Control{{
		OID:      pagedResultsControlOID,
		Value:    ldapwire.EncodePagedResultsValue(2, []byte("first")),
		HasValue: true,
	}}
	continued := []ldapwire.Control{{
		OID:      pagedResultsControlOID,
		Value:    ldapwire.EncodePagedResultsValue(3, []byte("second")),
		HasValue: true,
	}}
	if pagedSearchFingerprint("cn=admin", request, first) !=
		pagedSearchFingerprint("cn=admin", request, continued) {
		t.Fatal("page size and cookie changed the request fingerprint")
	}

	continued[0].Critical = true
	if pagedSearchFingerprint("cn=admin", request, first) ==
		pagedSearchFingerprint("cn=admin", request, continued) {
		t.Fatal("control criticality did not change the request fingerprint")
	}
}

func seedPagedPeople(
	t *testing.T,
	store storage.Store,
	count int,
) []string {
	t.Helper()

	expected := []string{"alice"}
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		for index := range count {
			uid := fmt.Sprintf("page-%02d", index)
			expected = append(expected, uid)
			if err := writer.Put(directory.Entry{
				DN: "uid=" + uid + ",ou=people,dc=example,dc=com",
				Attributes: []directory.Attribute{
					{
						Description: "objectClass",
						Values:      stringValues("inetOrgPerson"),
					},
					{Description: "uid", Values: stringValues(uid)},
					{Description: "cn", Values: stringValues("Paged " + uid)},
					{Description: "sn", Values: stringValues(uid)},
				},
			}, false); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed paged people: %v", err)
	}
	slices.Sort(expected)
	return expected
}

func bindPagedRootClient(t *testing.T, address string) *ldap.Conn {
	t.Helper()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	if err := client.Bind(
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	); err != nil {
		client.Close()
		t.Fatalf("Bind(): %v", err)
	}
	return client
}

func newPagedPeopleSearch(
	sizeLimit int,
	control *ldap.ControlPaging,
) *ldap.SearchRequest {
	var controls []ldap.Control
	if control != nil {
		controls = []ldap.Control{control}
	}
	return ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		sizeLimit,
		0,
		false,
		"(objectClass=inetOrgPerson)",
		[]string{"uid"},
		controls,
	)
}

func pagedResponseControl(
	t *testing.T,
	result *ldap.SearchResult,
) *ldap.ControlPaging {
	t.Helper()

	control := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
	paging, ok := control.(*ldap.ControlPaging)
	if !ok {
		t.Fatalf("paged response control = %T, want *ldap.ControlPaging", control)
	}
	return paging
}

func pagedResultUIDs(
	t *testing.T,
	result *ldap.SearchResult,
) []string {
	t.Helper()

	uids := make([]string, 0, len(result.Entries))
	seen := make(map[string]struct{}, len(result.Entries))
	for _, entry := range result.Entries {
		uid := entry.GetAttributeValue("uid")
		if uid == "" {
			t.Fatalf("entry has no uid: %#v", entry)
		}
		if _, duplicate := seen[uid]; duplicate {
			t.Fatalf("duplicate paged uid %q", uid)
		}
		seen[uid] = struct{}{}
		uids = append(uids, uid)
	}
	return uids
}

func searchResultDNs(result *ldap.SearchResult) []string {
	dns := make([]string, len(result.Entries))
	for index, entry := range result.Entries {
		dns[index] = entry.DN
	}
	return dns
}
