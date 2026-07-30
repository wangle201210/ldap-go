package server

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientVirtualListView(t *testing.T) {
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
	if err != nil ||
		len(rootDSE.Entries) != 1 ||
		!containsString(
			rootDSE.Entries[0].GetAttributeValues("supportedControl"),
			vlvRequestControlOID,
		) {
		t.Fatalf("VLV Root DSE = %#v, %v", rootDSE, err)
	}

	t.Run("offset", func(t *testing.T) {
		rebindVirtualListViewClient(t, client)
		result, err := client.Search(newSortablePeopleSearch([]ldap.Control{
			newSortControl(ldap.SortKey{
				AttributeType: "cn",
				MatchingRule:  "caseIgnoreOrderingMatch",
			}),
			newVirtualListViewControl(ldapwire.VirtualListViewRequest{
				BeforeCount:  1,
				AfterCount:   1,
				ByOffset:     true,
				Offset:       2,
				ContentCount: 4,
			}),
		}))
		if err != nil {
			t.Fatalf("offset VLV Search(): %v", err)
		}
		assertSortedUIDs(t, result, []string{"sort-2", "sort-4", "sort-3"})
		response := decodeVirtualListViewResponse(t, result)
		if response.TargetPosition != 2 ||
			response.ContentCount != 4 ||
			response.Result != ldapwire.ResultSuccess ||
			!response.HasContextID ||
			len(response.ContextID) != virtualListViewContextLength {
			t.Fatalf("offset VLV response = %#v", response)
		}
		assertSortResult(
			t,
			result,
			ldap.ControlServerSideSortingCodeSuccess,
		)
	})

	t.Run("proportional offset", func(t *testing.T) {
		rebindVirtualListViewClient(t, client)
		result, err := client.Search(newSortablePeopleSearch([]ldap.Control{
			newSortControl(ldap.SortKey{
				AttributeType: "cn",
				MatchingRule:  "caseIgnoreOrderingMatch",
			}),
			newVirtualListViewControl(ldapwire.VirtualListViewRequest{
				ByOffset:     true,
				Offset:       3,
				ContentCount: 8,
			}),
		}))
		if err != nil {
			t.Fatalf("proportional VLV Search(): %v", err)
		}
		assertSortedUIDs(t, result, []string{"sort-2"})
		if response := decodeVirtualListViewResponse(t, result); response.TargetPosition != 1 {
			t.Fatalf("proportional VLV response = %#v", response)
		}
	})

	t.Run("proportional offset rounds to zero", func(t *testing.T) {
		rebindVirtualListViewClient(t, client)
		result, err := client.Search(newSortablePeopleSearch([]ldap.Control{
			newSortControl(ldap.SortKey{
				AttributeType: "cn",
				MatchingRule:  "caseIgnoreOrderingMatch",
			}),
			newVirtualListViewControl(ldapwire.VirtualListViewRequest{
				ByOffset:     true,
				Offset:       2,
				ContentCount: 10,
			}),
		}))
		if err != nil {
			t.Fatalf("zero-position VLV Search(): %v", err)
		}
		assertSortedUIDs(t, result, []string{"sort-2"})
		if response := decodeVirtualListViewResponse(t, result); response.TargetPosition != 0 {
			t.Fatalf("zero-position VLV response = %#v", response)
		}
	})

	t.Run("empty result ignores offset range", func(t *testing.T) {
		rebindVirtualListViewClient(t, client)
		request := newSortablePeopleSearch([]ldap.Control{
			newSortControl(ldap.SortKey{
				AttributeType: "cn",
				MatchingRule:  "caseIgnoreOrderingMatch",
			}),
			newVirtualListViewControl(ldapwire.VirtualListViewRequest{
				ByOffset: true,
				Offset:   5,
			}),
		})
		request.Filter = "(uid=missing)"
		result, err := client.Search(request)
		if err != nil {
			t.Fatalf("empty VLV Search(): %v", err)
		}
		if len(result.Entries) != 0 {
			t.Fatalf("empty VLV entries = %d, want 0", len(result.Entries))
		}
		response := decodeVirtualListViewResponse(t, result)
		if response.TargetPosition != 0 ||
			response.ContentCount != 0 ||
			response.Result != ldapwire.ResultSuccess {
			t.Fatalf("empty VLV response = %#v", response)
		}
	})

	t.Run("typedown", func(t *testing.T) {
		rebindVirtualListViewClient(t, client)
		result, err := client.Search(newSortablePeopleSearch([]ldap.Control{
			newSortControl(ldap.SortKey{
				AttributeType: "cn",
				MatchingRule:  "caseIgnoreOrderingMatch",
			}),
			newVirtualListViewControl(ldapwire.VirtualListViewRequest{
				BeforeCount:    1,
				AfterCount:     1,
				AssertionValue: []byte("C"),
			}),
		}))
		if err != nil {
			t.Fatalf("typedown VLV Search(): %v", err)
		}
		assertSortedUIDs(t, result, []string{"sort-4", "sort-3", "sort-1"})
		if response := decodeVirtualListViewResponse(t, result); response.TargetPosition != 3 {
			t.Fatalf("typedown VLV response = %#v", response)
		}
	})

	t.Run("reverse typedown", func(t *testing.T) {
		rebindVirtualListViewClient(t, client)
		result, err := client.Search(newSortablePeopleSearch([]ldap.Control{
			newSortControl(ldap.SortKey{
				AttributeType: "mail",
				MatchingRule:  "caseIgnoreOrderingMatch",
				Reverse:       true,
			}),
			newVirtualListViewControl(ldapwire.VirtualListViewRequest{
				AfterCount:     1,
				AssertionValue: []byte("m@example.com"),
			}),
		}))
		if err != nil {
			t.Fatalf("reverse typedown VLV Search(): %v", err)
		}
		assertSortedUIDs(t, result, []string{"sort-4", "sort-3"})
		if response := decodeVirtualListViewResponse(t, result); response.TargetPosition != 3 {
			t.Fatalf("reverse typedown VLV response = %#v", response)
		}
	})
}

func TestLDAPClientVirtualListViewContextUsesInitialResultSet(t *testing.T) {
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

	sortControl := newSortControl(ldap.SortKey{
		AttributeType: "cn",
		MatchingRule:  "caseIgnoreOrderingMatch",
	})
	first, err := client.Search(newSortablePeopleSearch([]ldap.Control{
		sortControl,
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			ByOffset:     true,
			Offset:       2,
			ContentCount: 4,
		}),
	}))
	if err != nil {
		t.Fatalf("initial VLV Search(): %v", err)
	}
	assertSortedUIDs(t, first, []string{"sort-4"})
	firstResponse := decodeVirtualListViewResponse(t, first)

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
		t.Fatalf("mutate VLV result set: %v", err)
	}

	second, err := client.Search(newSortablePeopleSearch([]ldap.Control{
		sortControl,
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			BeforeCount:  1,
			ByOffset:     true,
			Offset:       4,
			ContentCount: 4,
			ContextID:    firstResponse.ContextID,
			HasContextID: true,
		}),
	}))
	if err != nil {
		t.Fatalf("continued VLV Search(): %v", err)
	}
	assertSortedUIDs(t, second, []string{"sort-1"})
	secondResponse := decodeVirtualListViewResponse(t, second)
	if secondResponse.TargetPosition != 4 ||
		secondResponse.ContentCount != 4 ||
		!bytes.Equal(secondResponse.ContextID, firstResponse.ContextID) {
		t.Fatalf("continued VLV response = %#v", secondResponse)
	}

	if err := client.Bind(
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	); err != nil {
		t.Fatalf("repeat Bind(): %v", err)
	}
	_, err = client.Search(newSortablePeopleSearch([]ldap.Control{
		sortControl,
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			ByOffset:     true,
			Offset:       4,
			ContentCount: 4,
			ContextID:    firstResponse.ContextID,
			HasContextID: true,
		}),
	}))
	assertLDAPResultCode(
		t,
		err,
		ldap.LDAPResultVirtualListViewErrorOrControlError,
	)
}

func TestLDAPClientVirtualListViewContinuationHonorsSizeLimit(t *testing.T) {
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

	sortControl := newSortControl(ldap.SortKey{
		AttributeType: "cn",
		MatchingRule:  "caseIgnoreOrderingMatch",
	})
	initialRequest := newSortablePeopleSearch([]ldap.Control{
		sortControl,
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			ByOffset:     true,
			Offset:       2,
			ContentCount: 4,
		}),
	})
	initialRequest.SizeLimit = 2
	initial, err := client.Search(initialRequest)
	if err != nil {
		t.Fatalf("initial size-limited VLV Search(): %v", err)
	}
	assertSortedUIDs(t, initial, []string{"sort-4"})
	contextID := decodeVirtualListViewResponse(t, initial).ContextID

	continuedRequest := newSortablePeopleSearch([]ldap.Control{
		sortControl,
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			BeforeCount:  2,
			AfterCount:   2,
			ByOffset:     true,
			Offset:       2,
			ContentCount: 4,
			ContextID:    contextID,
			HasContextID: true,
		}),
	})
	continuedRequest.SizeLimit = 2
	continued, err := client.Search(continuedRequest)
	assertLDAPResultCode(t, err, ldap.LDAPResultSizeLimitExceeded)
	assertSortedUIDs(t, continued, []string{"sort-2", "sort-4"})
}

func TestLDAPClientVirtualListViewContinuationRechecksACL(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSortablePeople(t, store)

	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		configDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		config, err := writer.Get(configDN)
		if err != nil {
			return err
		}
		config.ReplaceValues("olcAccess", stringValues(
			"{0}to attrs=userPassword by self =xw by anonymous auth by * none",
			"{1}to dn.exact=\"ou=people,dc=example,dc=com\" by users read by * none",
			"{2}to dn.subtree=\"ou=people,dc=example,dc=com\" by dnattr=owner read by * none",
			"{3}to * by users read by * none",
		))
		if err := writer.Put(config, true); err != nil {
			return err
		}

		for index := 1; index <= 4; index++ {
			dn, err := directory.ParseDN(
				fmt.Sprintf(
					"uid=sort-%d,ou=people,dc=example,dc=com",
					index,
				),
			)
			if err != nil {
				return err
			}
			entry, err := writer.Get(dn)
			if err != nil {
				return err
			}
			entry.ReplaceValues("owner", stringValues(aliceDN))
			if err := writer.Put(entry, true); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("configure VLV ACL fixture: %v", err)
	}

	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(aliceDN, "secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	sortControl := newSortControl(ldap.SortKey{
		AttributeType: "cn",
		MatchingRule:  "caseIgnoreOrderingMatch",
	})
	initial, err := client.Search(newSortablePeopleSearch([]ldap.Control{
		sortControl,
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			AfterCount:   3,
			ByOffset:     true,
			Offset:       1,
			ContentCount: 4,
		}),
	}))
	if err != nil {
		t.Fatalf("initial ACL VLV Search(): %v", err)
	}
	assertSortedUIDs(t, initial, []string{
		"sort-2",
		"sort-4",
		"sort-3",
		"sort-1",
	})
	initialResponse := decodeVirtualListViewResponse(t, initial)

	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		data := storage.WriterInPartition(
			writer,
			configuredDatabasePartition("{1}mdb"),
		)
		dn, err := directory.ParseDN(
			"uid=sort-3,ou=people,dc=example,dc=com",
		)
		if err != nil {
			return err
		}
		entry, err := data.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues(
			"owner",
			stringValues("uid=other,ou=people,dc=example,dc=com"),
		)
		return data.Put(entry, true)
	}); err != nil {
		t.Fatalf("revoke VLV entry ACL: %v", err)
	}

	continued, err := client.Search(newSortablePeopleSearch([]ldap.Control{
		sortControl,
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			AfterCount:   3,
			ByOffset:     true,
			Offset:       1,
			ContentCount: 4,
			ContextID:    initialResponse.ContextID,
			HasContextID: true,
		}),
	}))
	if err != nil {
		t.Fatalf("continued ACL VLV Search(): %v", err)
	}
	assertSortedUIDs(t, continued, []string{
		"sort-2",
		"sort-4",
		"sort-1",
	})
	if response := decodeVirtualListViewResponse(t, continued); response.ContentCount != 4 {
		t.Fatalf("continued ACL VLV response = %#v", response)
	}
}

func TestLDAPClientVirtualListViewFailures(t *testing.T) {
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

	t.Run("sort control missing", func(t *testing.T) {
		result := rawVirtualListViewSearch(t, address, []ldap.Control{
			newVirtualListViewControl(ldapwire.VirtualListViewRequest{
				ByOffset: true,
				Offset:   1,
			}),
		})
		assertRawLDAPResult(
			t,
			result,
			int64(ldap.LDAPResultVirtualListViewErrorOrControlError),
		)
		if response := decodeRawVirtualListViewResponse(t, result); response.Result !=
			openLDAPVLVSortControlMissing {
			t.Fatalf("missing-sort VLV response = %#v", response)
		}
	})

	t.Run("offset range", func(t *testing.T) {
		result := rawVirtualListViewSearch(t, address, []ldap.Control{
			newSortControl(ldap.SortKey{
				AttributeType: "cn",
				MatchingRule:  "caseIgnoreOrderingMatch",
			}),
			newVirtualListViewControl(ldapwire.VirtualListViewRequest{
				ByOffset:     true,
				Offset:       5,
				ContentCount: 4,
			}),
		})
		assertRawLDAPResult(
			t,
			result,
			int64(ldap.LDAPResultVirtualListViewErrorOrControlError),
		)
		response := decodeRawVirtualListViewResponse(t, result)
		if response.Result != openLDAPVLVOffsetRangeError ||
			response.ContentCount != 4 ||
			!response.HasContextID {
			t.Fatalf("range VLV response = %#v", response)
		}
	})

	t.Run("invalid context", func(t *testing.T) {
		result := rawVirtualListViewSearch(t, address, []ldap.Control{
			newSortControl(ldap.SortKey{
				AttributeType: "cn",
				MatchingRule:  "caseIgnoreOrderingMatch",
			}),
			newVirtualListViewControl(ldapwire.VirtualListViewRequest{
				ByOffset:     true,
				Offset:       1,
				ContextID:    []byte{0x01},
				HasContextID: true,
			}),
		})
		assertRawLDAPResult(
			t,
			result,
			int64(ldap.LDAPResultVirtualListViewErrorOrControlError),
		)
		if response := decodeRawVirtualListViewResponse(t, result); response.Result !=
			ldapwire.ResultProtocolError {
			t.Fatalf("invalid-context VLV response = %#v", response)
		}
	})

	t.Run("paged results conflict", func(t *testing.T) {
		result, err := client.Search(newSortablePeopleSearch([]ldap.Control{
			newSortControl(ldap.SortKey{
				AttributeType: "cn",
				MatchingRule:  "caseIgnoreOrderingMatch",
			}),
			newVirtualListViewControl(ldapwire.VirtualListViewRequest{
				ByOffset: true,
				Offset:   1,
			}),
			ldap.NewControlPaging(2),
		}))
		assertLDAPResultCode(t, err, ldap.LDAPResultUnwillingToPerform)
		if result != nil &&
			ldap.FindControl(result.Controls, ldap.ControlTypeVLVResponse) != nil {
			t.Fatal("paged-results conflict returned a VLV response control")
		}
	})
}

func TestLDAPClientVirtualListViewRequiresOverlay(t *testing.T) {
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
		vlvRequestControlOID,
	) {
		t.Fatal("VLV was advertised without an sssvlv overlay")
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
		[]ldap.Control{newVirtualListViewControlWithCriticality(
			ldapwire.VirtualListViewRequest{
				ByOffset: true,
				Offset:   1,
			},
			false,
		)},
	))
	if err != nil || len(noncritical.Entries) != 1 {
		t.Fatalf("noncritical unsupported VLV = %#v, %v", noncritical, err)
	}
	if ldap.FindControl(noncritical.Controls, vlvResponseControlOID) != nil {
		t.Fatal("ignored noncritical VLV returned a response control")
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
		[]ldap.Control{newVirtualListViewControl(
			ldapwire.VirtualListViewRequest{
				ByOffset: true,
				Offset:   1,
			},
		)},
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultUnavailableCriticalExtension)
}

func TestLDAPClientSpecialEntryVirtualListViewUsesFrontendOverlay(t *testing.T) {
	t.Parallel()

	t.Run("database overlay is not global", func(t *testing.T) {
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

		result, err := client.Search(ldap.NewSearchRequest(
			"",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"supportedControl"},
			[]ldap.Control{
				newSortControl(ldap.SortKey{
					AttributeType: "uid",
					MatchingRule:  "caseIgnoreOrderingMatch",
				}),
				newVirtualListViewControlWithCriticality(
					ldapwire.VirtualListViewRequest{
						ByOffset: true,
						Offset:   1,
					},
					false,
				),
			},
		))
		if err != nil || len(result.Entries) != 1 {
			t.Fatalf("noncritical local-overlay Root DSE VLV = %#v, %v", result, err)
		}
		if ldap.FindControl(result.Controls, vlvResponseControlOID) != nil {
			t.Fatal("local database overlay affected Root DSE VLV")
		}

		_, err = client.Search(ldap.NewSearchRequest(
			"",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"supportedControl"},
			[]ldap.Control{
				newSortControl(ldap.SortKey{
					AttributeType: "uid",
					MatchingRule:  "caseIgnoreOrderingMatch",
				}),
				newVirtualListViewControl(ldapwire.VirtualListViewRequest{
					ByOffset: true,
					Offset:   1,
				}),
			},
		))
		assertLDAPResultCode(t, err, ldap.LDAPResultUnavailableCriticalExtension)
	})

	t.Run("frontend overlay returns empty virtual view", func(t *testing.T) {
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
				[]ldap.Control{
					newSortControl(ldap.SortKey{
						AttributeType: "uid",
						MatchingRule:  "caseIgnoreOrderingMatch",
					}),
					newVirtualListViewControl(
						ldapwire.VirtualListViewRequest{
							ByOffset: true,
							Offset:   1,
						},
					),
				},
			))
			if err != nil || len(result.Entries) != 0 {
				t.Fatalf("frontend VLV on %q = %#v, %v", baseDN, result, err)
			}
			assertSortResult(
				t,
				result,
				ldap.ControlServerSideSortingCodeSuccess,
			)
			response := decodeVirtualListViewResponse(t, result)
			if response.TargetPosition != 0 ||
				response.ContentCount != 0 ||
				response.Result != ldapwire.ResultSuccess {
				t.Fatalf("frontend VLV response on %q = %#v", baseDN, response)
			}
		}
	})
}

func TestParseVirtualListViewControl(t *testing.T) {
	t.Parallel()

	value := ldapwire.EncodeVirtualListViewRequestValue(
		ldapwire.VirtualListViewRequest{
			BeforeCount: 1,
			AfterCount:  2,
			ByOffset:    true,
			Offset:      3,
		},
	)
	valid := ldapwire.Control{
		OID:      vlvRequestControlOID,
		Critical: true,
		Value:    value,
		HasValue: true,
	}
	parsed, result := parseRequestControls(
		[]ldapwire.Control{valid},
		supportsVirtualListView,
	)
	if result != nil ||
		parsed.vlv == nil ||
		!parsed.vlv.critical ||
		parsed.vlv.request.Offset != 3 {
		t.Fatalf("valid VLV control = %#v, %#v", parsed, result)
	}

	tests := []ldapwire.Control{
		{OID: vlvRequestControlOID},
		{OID: vlvRequestControlOID, HasValue: true},
		{
			OID:      vlvRequestControlOID,
			Value:    []byte{0x30, 0x00},
			HasValue: true,
		},
	}
	for _, control := range tests {
		if _, result := parseRequestControls(
			[]ldapwire.Control{control},
			supportsVirtualListView,
		); result == nil || result.Code != ldapwire.ResultProtocolError {
			t.Fatalf("invalid VLV control result = %#v", result)
		}
	}
	if _, result := parseRequestControls(
		[]ldapwire.Control{valid, valid},
		supportsVirtualListView,
	); result == nil || result.Code != ldapwire.ResultProtocolError {
		t.Fatalf("duplicate VLV controls result = %#v", result)
	}
}

func newVirtualListViewControl(
	request ldapwire.VirtualListViewRequest,
) ldap.Control {
	return newVirtualListViewControlWithCriticality(request, true)
}

func rebindVirtualListViewClient(t *testing.T, client *ldap.Conn) {
	t.Helper()
	if err := client.Bind(
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	); err != nil {
		t.Fatalf("reset VLV Bind(): %v", err)
	}
}

func newVirtualListViewControlWithCriticality(
	request ldapwire.VirtualListViewRequest,
	critical bool,
) ldap.Control {
	return &ldap.ControlString{
		ControlType: vlvRequestControlOID,
		Criticality: critical,
		ControlValue: string(
			ldapwire.EncodeVirtualListViewRequestValue(request),
		),
	}
}

func decodeVirtualListViewResponse(
	t *testing.T,
	result *ldap.SearchResult,
) ldapwire.VirtualListViewResponse {
	t.Helper()

	if result == nil {
		t.Fatal("VLV search result is nil")
	}
	control := ldap.FindControl(result.Controls, ldap.ControlTypeVLVResponse)
	value, ok := control.(*ldap.ControlString)
	if !ok {
		t.Fatalf("VLV response control = %#v", control)
	}
	response, err := ldapwire.DecodeVirtualListViewResponseValue(
		[]byte(value.ControlValue),
	)
	if err != nil {
		t.Fatalf("DecodeVirtualListViewResponseValue(): %v", err)
	}
	return response
}

func rawVirtualListViewSearch(
	t *testing.T,
	address string,
	controls []ldap.Control,
) *ber.Packet {
	t.Helper()

	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer connection.Close()

	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationSearchRequest,
		nil,
		"SearchRequest",
	)
	request.AppendChild(rawOctetString(
		[]byte("ou=people,dc=example,dc=com"),
	))
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(ldap.ScopeWholeSubtree),
		"scope",
	))
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagEnumerated,
		int64(ldap.NeverDerefAliases),
		"derefAliases",
	))
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(0),
		"sizeLimit",
	))
	request.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(0),
		"timeLimit",
	))
	request.AppendChild(ber.NewBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		false,
		"typesOnly",
	))
	filter, err := ldap.CompileFilter("(uid=sort-*)")
	if err != nil {
		t.Fatalf("CompileFilter(): %v", err)
	}
	request.AppendChild(filter)
	attributes := ber.NewSequence("attributes")
	for _, attribute := range []string{"uid", "cn", "sn", "mail"} {
		attributes.AppendChild(rawOctetString([]byte(attribute)))
	}
	request.AppendChild(attributes)

	rawControls := make([]*ber.Packet, len(controls))
	for index, control := range controls {
		rawControls[index] = control.Encode()
	}
	return sendRawLDAPOperation(t, connection, 2, request, rawControls...)
}

func decodeRawVirtualListViewResponse(
	t *testing.T,
	response *ber.Packet,
) ldapwire.VirtualListViewResponse {
	t.Helper()

	if response == nil || len(response.Children) != 3 {
		t.Fatalf("VLV response controls missing: %#v", response)
	}
	for _, control := range response.Children[2].Children {
		if len(control.Children) < 2 ||
			string(control.Children[0].Data.Bytes()) != vlvResponseControlOID {
			continue
		}
		decoded, err := ldapwire.DecodeVirtualListViewResponseValue(
			control.Children[len(control.Children)-1].Data.Bytes(),
		)
		if err != nil {
			t.Fatalf("DecodeVirtualListViewResponseValue(): %v", err)
		}
		return decoded
	}
	t.Fatalf("VLV response control not found: %#v", response)
	return ldapwire.VirtualListViewResponse{}
}
