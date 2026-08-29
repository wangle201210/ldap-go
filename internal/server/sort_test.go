package server

import (
	"context"
	"slices"
	"strconv"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientServerSideSorting(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSortablePeople(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()

	t.Run("multiple keys and least value", func(t *testing.T) {
		request := newSortablePeopleSearch([]ldap.Control{
			newSortControl(
				ldap.SortKey{
					AttributeType: "sn",
					MatchingRule:  "2.5.13.3",
				},
				ldap.SortKey{
					AttributeType: "cn",
					MatchingRule:  "caseIgnoreOrderingMatch",
				},
			),
		})
		result, err := client.Search(request)
		if err != nil {
			t.Fatalf("Search(): %v", err)
		}
		assertSortedUIDs(t, result, []string{
			"sort-2",
			"sort-4",
			"sort-3",
			"sort-1",
		})
		assertSortResult(t, result, ldap.ControlServerSideSortingCodeSuccess)
	})

	t.Run("reverse places null first", func(t *testing.T) {
		request := newSortablePeopleSearch([]ldap.Control{
			newSortControl(ldap.SortKey{
				AttributeType: "mail",
				MatchingRule:  "caseIgnoreOrderingMatch",
				Reverse:       true,
			}),
		})
		result, err := client.Search(request)
		if err != nil {
			t.Fatalf("Search(): %v", err)
		}
		assertSortedUIDs(t, result, []string{
			"sort-2",
			"sort-1",
			"sort-4",
			"sort-3",
		})
		assertSortResult(t, result, ldap.ControlServerSideSortingCodeSuccess)
	})

	t.Run("sort key is independent of attribute selection", func(t *testing.T) {
		request := newSortablePeopleSearch([]ldap.Control{
			newSortControl(ldap.SortKey{
				AttributeType: "cn",
				MatchingRule:  "caseIgnoreOrderingMatch",
			}),
		})
		request.Attributes = []string{"uid"}
		result, err := client.Search(request)
		if err != nil {
			t.Fatalf("Search(): %v", err)
		}
		assertSortedUIDs(t, result, []string{
			"sort-2",
			"sort-4",
			"sort-3",
			"sort-1",
		})
	})

	t.Run("types only", func(t *testing.T) {
		request := newSortablePeopleSearch([]ldap.Control{
			newSortControl(ldap.SortKey{
				AttributeType: "cn",
				MatchingRule:  "caseIgnoreOrderingMatch",
			}),
		})
		request.Attributes = []string{"uid"}
		request.TypesOnly = true
		result, err := client.Search(request)
		if err != nil {
			t.Fatalf("Search(): %v", err)
		}
		wantDNs := []string{
			"uid=sort-2,ou=people,dc=example,dc=com",
			"uid=sort-4,ou=people,dc=example,dc=com",
			"uid=sort-3,ou=people,dc=example,dc=com",
			"uid=sort-1,ou=people,dc=example,dc=com",
		}
		if len(result.Entries) != len(wantDNs) {
			t.Fatalf("types-only entries = %d, want %d", len(result.Entries), len(wantDNs))
		}
		for index, entry := range result.Entries {
			if entry.DN != wantDNs[index] {
				t.Fatalf("types-only DN %d = %q, want %q", index, entry.DN, wantDNs[index])
			}
			if values := entry.GetAttributeValues("uid"); len(values) != 0 {
				t.Fatalf("types-only uid values = %q", values)
			}
		}
	})

	t.Run("unreadable sort values stay hidden", func(t *testing.T) {
		userClient, err := ldap.DialURL("ldap://" + address)
		if err != nil {
			t.Fatalf("DialURL(): %v", err)
		}
		defer userClient.Close()
		if err := userClient.Bind(aliceDN, "secret"); err != nil {
			t.Fatalf("user Bind(): %v", err)
		}
		request := newSortablePeopleSearch([]ldap.Control{
			newSortControl(ldap.SortKey{
				AttributeType: "userPassword",
				MatchingRule:  "octetStringOrderingMatch",
			}),
		})
		request.Attributes = []string{"uid"}
		result, err := userClient.Search(request)
		if err != nil {
			t.Fatalf("Search(): %v", err)
		}
		assertSortedUIDs(t, result, []string{
			"sort-1",
			"sort-2",
			"sort-3",
			"sort-4",
		})
	})

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
			sortRequestControlOID,
		) {
		t.Fatalf("server-side sort Root DSE = %#v, %v", rootDSE, err)
	}
}

func TestServerSideSortingHonorsGlobalCandidateBudgets(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		candidates int
		bytes      int64
	}{
		{name: "count", candidates: 2, bytes: 1 << 20},
		{name: "bytes", candidates: 100, bytes: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			seedSortablePeople(t, store)
			address, stop := startServer(t, store, Config{
				RootDN:                  "cn=admin,dc=example,dc=com",
				RootPassword:            []byte("admin-secret"),
				MaxSearchCandidates:     test.candidates,
				MaxSearchCandidateBytes: test.bytes,
			})
			defer stop()
			client := bindPagedRootClient(t, address)
			defer client.Close()
			request := newSortablePeopleSearch([]ldap.Control{
				newSortControl(ldap.SortKey{
					AttributeType: "cn",
					MatchingRule:  "caseIgnoreOrderingMatch",
				}),
			})
			_, err := client.Search(request)
			assertLDAPResultCode(t, err, ldap.LDAPResultAdminLimitExceeded)
		})
	}
}

func TestLDAPClientServerSideSortingFailures(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSortablePeople(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()

	tests := []struct {
		name     string
		keys     []ldap.SortKey
		wantCode uint16
	}{
		{
			name:     "unknown attribute",
			keys:     []ldap.SortKey{{AttributeType: "missingAttribute"}},
			wantCode: ldap.LDAPResultNoSuchAttribute,
		},
		{
			name:     "no default ordering rule",
			keys:     []ldap.SortKey{{AttributeType: "cn"}},
			wantCode: ldap.LDAPResultInappropriateMatching,
		},
		{
			name: "maximum keys",
			keys: []ldap.SortKey{
				{AttributeType: "uid", MatchingRule: "caseIgnoreOrderingMatch"},
				{AttributeType: "cn", MatchingRule: "caseIgnoreOrderingMatch"},
				{AttributeType: "sn", MatchingRule: "caseIgnoreOrderingMatch"},
				{AttributeType: "mail", MatchingRule: "caseIgnoreOrderingMatch"},
				{
					AttributeType: "userPassword",
					MatchingRule:  "octetStringOrderingMatch",
				},
				{
					AttributeType: "description",
					MatchingRule:  "caseIgnoreOrderingMatch",
				},
			},
			wantCode: ldap.LDAPResultUnwillingToPerform,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyPointers := make([]*ldap.SortKey, len(test.keys))
			for index := range test.keys {
				key := test.keys[index]
				keyPointers[index] = &key
			}
			result, err := client.Search(newSortablePeopleSearch([]ldap.Control{
				ldap.NewControlServerSideSortingWithSortKeys(keyPointers),
			}))
			assertLDAPResultCode(t, err, test.wantCode)
			if result != nil && len(result.Entries) != 0 {
				t.Fatalf("sort validation failure returned %d entries", len(result.Entries))
			}
		})
	}

	specialEntrySort := newSortControl(ldap.SortKey{
		AttributeType: "uid",
		MatchingRule:  "caseIgnoreOrderingMatch",
	})
	subSchemaRequest := func(controls []ldap.Control) *ldap.SearchRequest {
		return ldap.NewSearchRequest(
			"cn=Subschema",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"cn"},
			controls,
		)
	}
	ignored, err := client.Search(subSchemaRequest([]ldap.Control{
		specialEntrySort,
	}))
	if err != nil || len(ignored.Entries) != 1 {
		t.Fatalf("database-local sort on subschema = %#v, %v", ignored, err)
	}
	if ldap.FindControl(
		ignored.Controls,
		ldap.ControlTypeServerSideSortingResult,
	) != nil {
		t.Fatal("database-local sort affected subschema")
	}

	criticalSpecialEntrySort := &ldap.ControlString{
		ControlType: sortRequestControlOID,
		Criticality: true,
		ControlValue: string(ldapwire.EncodeSortRequestValue([]ldapwire.SortKey{{
			AttributeType: "uid",
			OrderingRule:  "caseIgnoreOrderingMatch",
		}})),
	}
	_, err = client.Search(subSchemaRequest([]ldap.Control{
		criticalSpecialEntrySort,
	}))
	assertLDAPResultCode(t, err, ldap.LDAPResultUnavailableCriticalExtension)

	duplicateResult, err := client.Search(newSortablePeopleSearch([]ldap.Control{
		newSortControl(
			ldap.SortKey{
				AttributeType: "uid",
				MatchingRule:  "caseIgnoreOrderingMatch",
			},
			ldap.SortKey{
				AttributeType: "userid",
				MatchingRule:  "caseIgnoreOrderingMatch",
			},
		),
	}))
	if err != nil {
		t.Fatalf("duplicate sort keys: %v", err)
	}
	assertSortedUIDs(t, duplicateResult, []string{
		"sort-1",
		"sort-2",
		"sort-3",
		"sort-4",
	})
	assertSortResult(
		t,
		duplicateResult,
		ldap.ControlServerSideSortingCodeSuccess,
	)

	critical := &ldap.ControlString{
		ControlType: sortRequestControlOID,
		Criticality: true,
		ControlValue: string(ldapwire.EncodeSortRequestValue([]ldapwire.SortKey{{
			AttributeType: "missingAttribute",
		}})),
	}
	result, err := client.Search(newSortablePeopleSearch([]ldap.Control{critical}))
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchAttribute)
	if result != nil && len(result.Entries) != 0 {
		t.Fatalf("critical sort failure returned %d entries", len(result.Entries))
	}
}

func TestLDAPClientServerSideSortingRequiresOverlay(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()

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
	if err != nil || len(rootDSE.Entries) != 1 {
		t.Fatalf("Root DSE = %#v, %v", rootDSE, err)
	}
	if containsString(
		rootDSE.Entries[0].GetAttributeValues("supportedControl"),
		sortRequestControlOID,
	) {
		t.Fatal("server-side sort was advertised without an sssvlv overlay")
	}

	noncritical, err := client.Search(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=alice)",
		[]string{"uid"},
		[]ldap.Control{newSortControl(ldap.SortKey{
			AttributeType: "cn",
			MatchingRule:  "caseIgnoreOrderingMatch",
		})},
	))
	if err != nil || len(noncritical.Entries) != 1 {
		t.Fatalf("noncritical unsupported sort = %#v, %v", noncritical, err)
	}
	if ldap.FindControl(
		noncritical.Controls,
		ldap.ControlTypeServerSideSortingResult,
	) != nil {
		t.Fatal("ignored noncritical sort returned a response control")
	}

	critical := &ldap.ControlString{
		ControlType: sortRequestControlOID,
		Criticality: true,
		ControlValue: string(ldapwire.EncodeSortRequestValue([]ldapwire.SortKey{{
			AttributeType: "cn",
			OrderingRule:  "caseIgnoreOrderingMatch",
		}})),
	}
	_, err = client.Search(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=alice)",
		[]string{"uid"},
		[]ldap.Control{critical},
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultUnavailableCriticalExtension)
}

func TestLDAPClientSpecialEntrySortingUsesFrontendOverlay(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedFrontendSortOverlay(t, store, 1)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()

	for _, baseDN := range []string{"", "cn=Subschema"} {
		result, err := client.Search(ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"cn"},
			[]ldap.Control{newSortControl(ldap.SortKey{
				AttributeType: "uid",
				MatchingRule:  "caseIgnoreOrderingMatch",
			})},
		))
		if err != nil || len(result.Entries) != 1 {
			t.Fatalf("frontend sort on %q = %#v, %v", baseDN, result, err)
		}
		assertSortResult(
			t,
			result,
			ldap.ControlServerSideSortingCodeSuccess,
		)
	}

	_, err := client.Search(ldap.NewSearchRequest(
		"cn=Subschema",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		[]ldap.Control{newSortControl(
			ldap.SortKey{
				AttributeType: "uid",
				MatchingRule:  "caseIgnoreOrderingMatch",
			},
			ldap.SortKey{
				AttributeType: "cn",
				MatchingRule:  "caseIgnoreOrderingMatch",
			},
		)},
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultUnwillingToPerform)
}

func TestLDAPClientServerSideSortingWithPaging(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSortablePeople(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()

	request := newSortablePeopleSearch([]ldap.Control{
		newSortControl(ldap.SortKey{
			AttributeType: "cn",
			MatchingRule:  "caseIgnoreOrderingMatch",
		}),
	})
	result, err := client.SearchWithPaging(request, 2)
	if err != nil {
		t.Fatalf("SearchWithPaging(): %v", err)
	}
	assertSortedUIDs(t, result, []string{
		"sort-2",
		"sort-4",
		"sort-3",
		"sort-1",
	})
	sortResponses := 0
	for _, control := range result.Controls {
		if response, ok := control.(*ldap.ControlServerSideSortingResult); ok {
			sortResponses++
			if response.Result != ldap.ControlServerSideSortingCodeSuccess {
				t.Fatalf("paged sort response = %#v", response)
			}
		}
	}
	if sortResponses != 2 {
		t.Fatalf("paged sort response controls = %d, want 2", sortResponses)
	}
}

func TestLDAPClientSortedPagingUsesInitialResultSet(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSortablePeople(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()

	pagingControl := ldap.NewControlPaging(2)
	request := newSortablePeopleSearch([]ldap.Control{
		newSortControl(ldap.SortKey{
			AttributeType: "cn",
			MatchingRule:  "caseIgnoreOrderingMatch",
		}),
		pagingControl,
	})
	first, err := client.Search(request)
	if err != nil {
		t.Fatalf("first sorted page: %v", err)
	}
	assertSortedUIDs(t, first, []string{"sort-2", "sort-4"})
	cookie := pagedResponseControl(t, first).Cookie

	err = store.Update(context.Background(), func(writer storage.Writer) error {
		tx := storage.WriterInPartition(
			writer,
			configuredDatabasePartition("{1}mdb"),
		)
		deleted, err := directory.ParseDN(
			"uid=sort-3,ou=people,dc=example,dc=com",
		)
		if err != nil {
			return err
		}
		if err := tx.Delete(deleted); err != nil {
			return err
		}
		return tx.Put(directory.Entry{
			DN: "uid=sort-0,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("sort-0")},
				{Description: "cn", Values: stringValues("Aardvark")},
				{Description: "sn", Values: stringValues("One")},
			},
		}, false)
	})
	if err != nil {
		t.Fatalf("mutate sorted result set: %v", err)
	}

	pagingControl.SetCookie(cookie)
	second, err := client.Search(request)
	if err != nil {
		t.Fatalf("second sorted page: %v", err)
	}
	assertSortedUIDs(t, second, []string{"sort-1"})
	if cookie := pagedResponseControl(t, second).Cookie; len(cookie) != 0 {
		t.Fatalf("final sorted paging cookie = %x, want empty", cookie)
	}
}

func TestLDAPClientPagedSortFailureContinuesUnsorted(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSortablePeople(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(
			"uid=sort-1,ou=people,dc=example,dc=com",
		)
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("uidNumber", stringValues("not-an-integer"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("seed malformed sort value: %v", err)
	}

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()

	pagingControl := ldap.NewControlPaging(2)
	request := newSortablePeopleSearch([]ldap.Control{
		newSortControl(ldap.SortKey{
			AttributeType: "uidNumber",
			MatchingRule:  "integerOrderingMatch",
		}),
		pagingControl,
	})
	first, err := client.Search(request)
	if err != nil {
		t.Fatalf("first unsorted fallback page: %v", err)
	}
	assertSortedUIDs(t, first, []string{"sort-1", "sort-2"})
	if ldap.FindControl(
		first.Controls,
		ldap.ControlTypeServerSideSortingResult,
	) == nil {
		t.Fatal("first unsorted fallback page omitted sort response")
	}

	pagingControl.SetCookie(pagedResponseControl(t, first).Cookie)
	second, err := client.Search(request)
	if err != nil {
		t.Fatalf("second unsorted fallback page: %v", err)
	}
	assertSortedUIDs(t, second, []string{"sort-3", "sort-4"})
	if ldap.FindControl(
		second.Controls,
		ldap.ControlTypeServerSideSortingResult,
	) == nil {
		t.Fatal("second unsorted fallback page omitted sort response")
	}
	if cookie := pagedResponseControl(t, second).Cookie; len(cookie) != 0 {
		t.Fatalf("final fallback paging cookie = %x, want empty", cookie)
	}
}

func TestLDAPClientSortedPagingHonorsTotalSizeLimit(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSortablePeople(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindPagedRootClient(t, address)
	defer client.Close()

	request := newSortablePeopleSearch([]ldap.Control{
		newSortControl(ldap.SortKey{
			AttributeType: "cn",
			MatchingRule:  "caseIgnoreOrderingMatch",
		}),
	})
	request.SizeLimit = 3
	result, err := client.SearchWithPaging(request, 2)
	assertLDAPResultCode(t, err, ldap.LDAPResultSizeLimitExceeded)
	assertSortedUIDs(t, result, []string{"sort-2", "sort-4", "sort-3"})
}

func TestPrepareServerSideSortFailures(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	tests := []struct {
		name     string
		keys     []ldapwire.SortKey
		maxKeys  int
		wantCode ldapwire.ResultCode
	}{
		{
			name:     "unknown attribute",
			keys:     []ldapwire.SortKey{{AttributeType: "missingAttribute"}},
			maxKeys:  defaultServerSideSortMaxKeys,
			wantCode: ldapwire.ResultNoSuchAttribute,
		},
		{
			name:     "no ordering rule",
			keys:     []ldapwire.SortKey{{AttributeType: "cn"}},
			maxKeys:  defaultServerSideSortMaxKeys,
			wantCode: ldapwire.ResultInappropriateMatching,
		},
		{
			name: "maximum keys",
			keys: []ldapwire.SortKey{
				{
					AttributeType: "uid",
					OrderingRule:  "caseIgnoreOrderingMatch",
				},
				{
					AttributeType: "cn",
					OrderingRule:  "caseIgnoreOrderingMatch",
				},
			},
			maxKeys:  1,
			wantCode: ldapwire.ResultUnwillingToPerform,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			context, result := prepareServerSideSort(
				registry,
				&serverSideSortRequest{keys: test.keys},
				test.maxKeys,
			)
			if context != nil ||
				result == nil ||
				result.Code != test.wantCode {
				t.Fatalf("sort preparation = %#v, %#v", context, result)
			}
		})
	}

	duplicate, result := prepareServerSideSort(
		registry,
		&serverSideSortRequest{keys: []ldapwire.SortKey{
			{
				AttributeType: "uid",
				OrderingRule:  "caseIgnoreOrderingMatch",
			},
			{
				AttributeType: "userid",
				OrderingRule:  "caseIgnoreOrderingMatch",
			},
		}},
		defaultServerSideSortMaxKeys,
	)
	if result != nil || duplicate == nil || len(duplicate.keys) != 2 {
		t.Fatalf("duplicate sort key preparation = %#v, %#v", duplicate, result)
	}

	duplicate.fail(ldapwire.ResultInappropriateMatching, "uid")
	controls := serverSideSortResponseControl(
		duplicate,
		ldapwire.Result{Code: ldapwire.ResultSuccess},
		1,
	)
	if len(controls) != 1 {
		t.Fatalf("runtime sort response controls = %#v", controls)
	}
	code, attributeType, err := ldapwire.DecodeSortResultValue(controls[0].Value)
	if err != nil {
		t.Fatalf("DecodeSortResultValue(): %v", err)
	}
	if code != ldapwire.ResultInappropriateMatching || attributeType != "uid" {
		t.Fatalf("runtime sort response = %d, %q", code, attributeType)
	}
}

func TestSortSearchCandidatesRejectsMalformedSingleValue(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	candidates := []searchCandidate{{
		dn: "uid=invalid,dc=example,dc=com",
		readable: directory.Entry{Attributes: []directory.Attribute{{
			Description: "uidNumber",
			Values:      stringValues("not-an-integer"),
		}}},
	}}
	err = sortSearchCandidates(
		registry,
		&serverSideSortContext{
			result: ldapwire.ResultSuccess,
			keys: []resolvedSortKey{{
				attribute:    "uidNumber",
				orderingRule: "integerOrderingMatch",
			}},
		},
		candidates,
	)
	if err == nil {
		t.Fatal("sortSearchCandidates() accepted a malformed single value")
	}
	if candidates[0].dn != "uid=invalid,dc=example,dc=com" {
		t.Fatalf(
			"sortSearchCandidates() changed candidates after failure: %#v",
			candidates,
		)
	}
}

func TestParseServerSideSortControl(t *testing.T) {
	t.Parallel()

	valid := ldapwire.Control{
		OID:      sortRequestControlOID,
		Critical: true,
		Value: ldapwire.EncodeSortRequestValue([]ldapwire.SortKey{{
			AttributeType: "cn",
			OrderingRule:  "caseIgnoreOrderingMatch",
			Reverse:       true,
		}}),
		HasValue: true,
	}
	parsed, result := parseRequestControls(
		[]ldapwire.Control{valid},
		supportsServerSideSort,
	)
	if result != nil || parsed.sorting == nil ||
		!parsed.sorting.critical ||
		len(parsed.sorting.keys) != 1 ||
		parsed.sorting.keys[0].AttributeType != "cn" ||
		!parsed.sorting.keys[0].Reverse {
		t.Fatalf("valid sort control = %#v, %#v", parsed, result)
	}

	tests := []struct {
		name      string
		controls  []ldapwire.Control
		supported requestControlSupport
		wantCode  ldapwire.ResultCode
	}{
		{
			name:      "absent value",
			controls:  []ldapwire.Control{{OID: sortRequestControlOID}},
			supported: supportsServerSideSort,
			wantCode:  ldapwire.ResultProtocolError,
		},
		{
			name: "empty value",
			controls: []ldapwire.Control{{
				OID:      sortRequestControlOID,
				HasValue: true,
			}},
			supported: supportsServerSideSort,
			wantCode:  ldapwire.ResultProtocolError,
		},
		{
			name: "malformed value",
			controls: []ldapwire.Control{{
				OID:      sortRequestControlOID,
				Value:    []byte{0x30, 0x00},
				HasValue: true,
			}},
			supported: supportsServerSideSort,
			wantCode:  ldapwire.ResultProtocolError,
		},
		{
			name:      "duplicate",
			controls:  []ldapwire.Control{valid, valid},
			supported: supportsServerSideSort,
			wantCode:  ldapwire.ResultProtocolError,
		},
		{
			name: "critical on non-search operation",
			controls: []ldapwire.Control{{
				OID:      sortRequestControlOID,
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

func seedSortablePeople(t *testing.T, store storage.Store) {
	t.Helper()

	entries := []directory.Entry{
		{
			DN: "olcOverlay={0}sssvlv,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("{0}sssvlv")},
				{
					Description: "olcSssVlvMaxKeys",
					Values:      stringValues("5"),
				},
			},
		},
		{
			DN: "uid=sort-1,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("sort-1")},
				{Description: "cn", Values: stringValues("Zulu", "Delta")},
				{Description: "sn", Values: stringValues("Two")},
				{Description: "mail", Values: stringValues("z@example.com")},
				{Description: "userPassword", Values: stringValues("delta-secret")},
			},
		},
		{
			DN: "uid=sort-2,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("sort-2")},
				{Description: "cn", Values: stringValues("Alpha")},
				{Description: "sn", Values: stringValues("One")},
				{Description: "userPassword", Values: stringValues("alpha-secret")},
			},
		},
		{
			DN: "uid=sort-3,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("sort-3")},
				{Description: "cn", Values: stringValues("Charlie")},
				{Description: "sn", Values: stringValues("One")},
				{Description: "mail", Values: stringValues("a@example.com")},
				{Description: "userPassword", Values: stringValues("charlie-secret")},
			},
		},
		{
			DN: "uid=sort-4,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("sort-4")},
				{Description: "cn", Values: stringValues("Bravo")},
				{Description: "sn", Values: stringValues("One")},
				{Description: "mail", Values: stringValues("m@example.com")},
				{Description: "userPassword", Values: stringValues("bravo-secret")},
			},
		},
	}
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed sortable people: %v", err)
	}
}

func seedFrontendSortOverlay(
	t *testing.T,
	store storage.Store,
	maxKeys int,
) {
	t.Helper()

	entries := []directory.Entry{
		{
			DN: "olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcDatabase",
				Values:      stringValues("{-1}frontend"),
			}},
		},
		{
			DN: "olcOverlay={0}sssvlv,olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("{0}sssvlv")},
				{
					Description: "olcSssVlvMaxKeys",
					Values:      stringValues(strconv.Itoa(maxKeys)),
				},
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
		t.Fatalf("seed frontend sort overlay: %v", err)
	}
}

func newSortControl(keys ...ldap.SortKey) ldap.Control {
	keyPointers := make([]*ldap.SortKey, len(keys))
	for index := range keys {
		key := keys[index]
		keyPointers[index] = &key
	}
	return ldap.NewControlServerSideSortingWithSortKeys(keyPointers)
}

func newSortablePeopleSearch(controls []ldap.Control) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=sort-*)",
		[]string{"uid", "cn", "sn", "mail"},
		controls,
	)
}

func assertSortedUIDs(
	t *testing.T,
	result *ldap.SearchResult,
	want []string,
) {
	t.Helper()

	got := make([]string, len(result.Entries))
	for index, entry := range result.Entries {
		got[index] = entry.GetAttributeValue("uid")
	}
	if !slices.Equal(got, want) {
		t.Fatalf("sorted UIDs = %q, want %q", got, want)
	}
}

func assertSortResult(
	t *testing.T,
	result *ldap.SearchResult,
	want ldap.ControlServerSideSortingCode,
) {
	t.Helper()

	control := ldap.FindControl(
		result.Controls,
		ldap.ControlTypeServerSideSortingResult,
	)
	response, ok := control.(*ldap.ControlServerSideSortingResult)
	if !ok || response.Result != want {
		t.Fatalf("sort response control = %#v, want result %d", control, want)
	}
}
