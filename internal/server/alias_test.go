package server

import (
	"context"
	"errors"
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientAliasDereferenceModes(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedAliasDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindAliasRootClient(t, address)
	defer client.Close()

	aliasDN := "cn=direct,ou=aliases,dc=example,dc=com"
	targetDN := "uid=alice,ou=people,dc=example,dc=com"
	for _, test := range []struct {
		name string
		mode int
		want string
	}{
		{name: "never", mode: ldap.NeverDerefAliases, want: aliasDN},
		{name: "searching", mode: ldap.DerefInSearching, want: aliasDN},
		{name: "finding", mode: ldap.DerefFindingBaseObj, want: targetDN},
		{name: "always", mode: ldap.DerefAlways, want: targetDN},
	} {
		t.Run("base/"+test.name, func(t *testing.T) {
			result := aliasSearch(
				t,
				client,
				aliasDN,
				ldap.ScopeBaseObject,
				test.mode,
				"(objectClass=*)",
			)
			assertAliasDNs(t, result, []string{test.want})
		})
	}

	aliasesBase := "ou=aliases,dc=example,dc=com"
	never := aliasSearch(
		t,
		client,
		aliasesBase,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		"(objectClass=*)",
	)
	finding := aliasSearch(
		t,
		client,
		aliasesBase,
		ldap.ScopeSingleLevel,
		ldap.DerefFindingBaseObj,
		"(objectClass=*)",
	)
	neverDNs := sortedAliasDNs(never)
	findingDNs := sortedAliasDNs(finding)
	if !slices.Equal(neverDNs, findingDNs) ||
		!slices.Contains(neverDNs, aliasDN) ||
		slices.Contains(neverDNs, targetDN) {
		t.Fatalf(
			"never/finding one-level DNs = %q / %q",
			neverDNs,
			findingDNs,
		)
	}

	wantOneLevel := []string{
		"ou=people,dc=example,dc=com",
		targetDN,
		"uid=bob,ou=archive,dc=example,dc=com",
	}
	for _, mode := range []int{ldap.DerefInSearching, ldap.DerefAlways} {
		result := aliasSearch(
			t,
			client,
			aliasesBase,
			ldap.ScopeSingleLevel,
			mode,
			"(objectClass=*)",
		)
		assertAliasDNSet(t, result, wantOneLevel)
	}

	subtree := aliasSearch(
		t,
		client,
		aliasesBase,
		ldap.ScopeWholeSubtree,
		ldap.DerefInSearching,
		"(objectClass=*)",
	)
	counts := aliasDNCounts(subtree)
	for dn, want := range map[string]int{
		aliasesBase:                              1,
		"ou=people,dc=example,dc=com":            1,
		targetDN:                                 2,
		"cn=child," + targetDN:                   2,
		"uid=bob,ou=archive,dc=example,dc=com":   1,
		"uid=carol,ou=archive,dc=example,dc=com": 1,
	} {
		if counts[dn] != want {
			t.Fatalf(
				"subtree alias count for %q = %d, want %d; all=%v",
				dn,
				counts[dn],
				want,
				counts,
			)
		}
	}

	searchingBase := aliasSearch(
		t,
		client,
		aliasDN,
		ldap.ScopeWholeSubtree,
		ldap.DerefInSearching,
		"(objectClass=*)",
	)
	assertAliasDNs(t, searchingBase, []string{aliasDN})
	alwaysBase := aliasSearch(
		t,
		client,
		aliasDN,
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways,
		"(objectClass=*)",
	)
	assertAliasDNSet(t, alwaysBase, []string{
		targetDN,
		"cn=child," + targetDN,
	})

	throughAlias := aliasSearch(
		t,
		client,
		"uid=alice,ou=virtual,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.DerefFindingBaseObj,
		"(objectClass=*)",
	)
	assertAliasDNs(t, throughAlias, []string{targetDN})

	_, err := client.Search(ldap.NewSearchRequest(
		"cn=missing,ou=virtual,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.DerefFindingBaseObj,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"1.1"},
		nil,
	))
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) ||
		ldapErr.ResultCode != ldap.LDAPResultNoSuchObject ||
		ldapErr.MatchedDN != "ou=people,dc=example,dc=com" {
		t.Fatalf("search below alias error = %#v, %v", ldapErr, err)
	}
}

func TestLDAPClientAliasFailuresAndWriteRules(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedAliasDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindAliasRootClient(t, address)
	defer client.Close()

	for _, test := range []struct {
		name      string
		dn        string
		result    uint16
		matchedDN string
	}{
		{
			name:      "broken",
			dn:        "cn=broken,ou=aliases,dc=example,dc=com",
			result:    ldap.LDAPResultAliasProblem,
			matchedDN: "cn=broken,ou=aliases,dc=example,dc=com",
		},
		{
			name:      "loop",
			dn:        "cn=loop-a,ou=aliases,dc=example,dc=com",
			result:    ldap.LDAPResultAliasProblem,
			matchedDN: "cn=loop-a,ou=aliases,dc=example,dc=com",
		},
		{
			name:      "depth",
			dn:        "cn=depth-0,ou=aliases,dc=example,dc=com",
			result:    ldap.LDAPResultAliasDereferencingProblem,
			matchedDN: "cn=depth-3,ou=aliases,dc=example,dc=com",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := client.Search(ldap.NewSearchRequest(
				test.dn,
				ldap.ScopeBaseObject,
				ldap.DerefAlways,
				0,
				0,
				false,
				"(objectClass=*)",
				[]string{"1.1"},
				nil,
			))
			var ldapErr *ldap.Error
			if !errors.As(err, &ldapErr) ||
				ldapErr.ResultCode != test.result ||
				ldapErr.MatchedDN != test.matchedDN {
				t.Fatalf(
					"alias failure = %#v, %v; want code %d matchedDN %q",
					ldapErr,
					err,
					test.result,
					test.matchedDN,
				)
			}
		})
	}

	bad := ldap.NewAddRequest(
		"cn=bad-alias,dc=example,dc=com",
		nil,
	)
	bad.Attribute("objectClass", []string{"organizationalRole", "extensibleObject"})
	bad.Attribute("cn", []string{"bad-alias"})
	bad.Attribute(
		"aliasedObjectName",
		[]string{"uid=alice,ou=people,dc=example,dc=com"},
	)
	assertLDAPResultCode(
		t,
		client.Add(bad),
		ldap.LDAPResultObjectClassViolation,
	)

	addedDN := "cn=added-alias,ou=aliases,dc=example,dc=com"
	added := ldap.NewAddRequest(addedDN, nil)
	added.Attribute("objectClass", []string{"alias", "extensibleObject"})
	added.Attribute("cn", []string{"added-alias"})
	added.Attribute(
		"aliasedObjectName",
		[]string{"uid=alice,ou=people,dc=example,dc=com"},
	)
	if err := client.Add(added); err != nil {
		t.Fatalf("Add(alias): %v", err)
	}
	matches, err := client.Compare(
		addedDN,
		"aliasedObjectName",
		"uid=alice,ou=people,dc=example,dc=com",
	)
	if err != nil || !matches {
		t.Fatalf("Compare(alias) = %t, %v", matches, err)
	}

	modify := ldap.NewModifyRequest(addedDN, nil)
	modify.Replace(
		"aliasedObjectName",
		[]string{"uid=bob,ou=archive,dc=example,dc=com"},
	)
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify(alias): %v", err)
	}
	modified := aliasSearch(
		t,
		client,
		addedDN,
		ldap.ScopeBaseObject,
		ldap.DerefAlways,
		"(objectClass=*)",
	)
	assertAliasDNs(t, modified, []string{
		"uid=bob,ou=archive,dc=example,dc=com",
	})

	child := ldap.NewAddRequest("cn=child,"+addedDN, nil)
	child.Attribute("objectClass", []string{"organizationalRole"})
	child.Attribute("cn", []string{"child"})
	assertLDAPResultCode(
		t,
		client.Add(child),
		ldap.LDAPResultAliasProblem,
	)

	move := ldap.NewModifyDNRequest(
		"cn=move-me,dc=example,dc=com",
		"cn=move-me",
		true,
		addedDN,
	)
	assertLDAPResultCode(
		t,
		client.ModifyDN(move),
		ldap.LDAPResultAliasProblem,
	)

	aliasClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(alias bind): %v", err)
	}
	defer aliasClient.Close()
	assertLDAPResultCode(
		t,
		aliasClient.Bind(
			"cn=direct,ou=aliases,dc=example,dc=com",
			"alias-secret",
		),
		ldap.LDAPResultInvalidCredentials,
	)

	rename := ldap.NewModifyDNRequest(
		addedDN,
		"cn=renamed-alias",
		true,
		"",
	)
	if err := client.ModifyDN(rename); err != nil {
		t.Fatalf("ModifyDN(alias): %v", err)
	}
	renamedDN := "cn=renamed-alias,ou=aliases,dc=example,dc=com"
	if err := client.Del(ldap.NewDelRequest(renamedDN, nil)); err != nil {
		t.Fatalf("Delete(alias): %v", err)
	}
}

func TestLDAPClientAliasPagingAndSorting(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedAliasDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindAliasRootClient(t, address)
	defer client.Close()

	newRequest := func(controls []ldap.Control) *ldap.SearchRequest {
		return ldap.NewSearchRequest(
			"ou=aliases,dc=example,dc=com",
			ldap.ScopeSingleLevel,
			ldap.DerefInSearching,
			0,
			0,
			false,
			"(objectClass=inetOrgPerson)",
			[]string{"uid", "cn"},
			controls,
		)
	}

	paged, err := client.SearchWithPaging(newRequest(nil), 1)
	if err != nil {
		t.Fatalf("alias SearchWithPaging(): %v", err)
	}
	assertAliasUIDs(t, paged, []string{"alice", "bob"})

	sorted, err := client.SearchWithPaging(newRequest([]ldap.Control{
		newSortControl(ldap.SortKey{
			AttributeType: "cn",
			MatchingRule:  "caseIgnoreOrderingMatch",
		}),
	}), 1)
	if err != nil {
		t.Fatalf("sorted alias SearchWithPaging(): %v", err)
	}
	assertAliasUIDs(t, sorted, []string{"alice", "bob"})
	assertSortResult(
		t,
		sorted,
		ldap.ControlServerSideSortingCodeSuccess,
	)

	vlv, err := client.Search(newRequest([]ldap.Control{
		newSortControl(ldap.SortKey{
			AttributeType: "cn",
			MatchingRule:  "caseIgnoreOrderingMatch",
		}),
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			AfterCount:   1,
			ByOffset:     true,
			Offset:       1,
			ContentCount: 2,
		}),
	}))
	if err != nil {
		t.Fatalf("alias VLV Search(): %v", err)
	}
	assertAliasUIDs(t, vlv, []string{"alice", "bob"})
	if response := decodeVirtualListViewResponse(t, vlv); response.ContentCount != 2 ||
		response.TargetPosition != 1 ||
		response.Result != ldapwire.ResultSuccess {
		t.Fatalf("alias VLV response = %#v", response)
	}
}

func seedAliasDirectory(t *testing.T, store storage.Store) {
	t.Helper()
	seedDirectory(t, store)

	entries := []directory.Entry{
		{
			DN: "uid=bob,ou=archive,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("bob")},
				{Description: "cn", Values: stringValues("Bob Example")},
				{Description: "sn", Values: stringValues("Example")},
			},
		},
		{
			DN: "uid=carol,ou=archive,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("carol")},
				{Description: "cn", Values: stringValues("Carol Example")},
				{Description: "sn", Values: stringValues("Example")},
			},
		},
		{
			DN: "cn=child,uid=alice,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalRole")},
				{Description: "cn", Values: stringValues("child")},
			},
		},
		{
			DN: "cn=move-me,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalRole")},
				{Description: "cn", Values: stringValues("move-me")},
			},
		},
		{
			DN: "ou=aliases,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit")},
				{Description: "ou", Values: stringValues("aliases")},
			},
		},
		aliasTestEntry(
			"cn=direct,ou=aliases,dc=example,dc=com",
			"cn",
			"direct",
			"uid=alice,ou=people,dc=example,dc=com",
			"alias-secret",
		),
		aliasTestEntry(
			"cn=tree,ou=aliases,dc=example,dc=com",
			"cn",
			"tree",
			"ou=people,dc=example,dc=com",
			"",
		),
		aliasTestEntry(
			"cn=external,ou=aliases,dc=example,dc=com",
			"cn",
			"external",
			"uid=bob,ou=archive,dc=example,dc=com",
			"",
		),
		aliasTestEntry(
			"cn=nested,ou=people,dc=example,dc=com",
			"cn",
			"nested",
			"uid=carol,ou=archive,dc=example,dc=com",
			"",
		),
		aliasTestEntry(
			"cn=chain,ou=aliases,dc=example,dc=com",
			"cn",
			"chain",
			"cn=direct,ou=aliases,dc=example,dc=com",
			"",
		),
		aliasTestEntry(
			"cn=broken,ou=aliases,dc=example,dc=com",
			"cn",
			"broken",
			"cn=missing,dc=example,dc=com",
			"",
		),
		aliasTestEntry(
			"cn=loop-a,ou=aliases,dc=example,dc=com",
			"cn",
			"loop-a",
			"cn=loop-b,ou=aliases,dc=example,dc=com",
			"",
		),
		aliasTestEntry(
			"cn=loop-b,ou=aliases,dc=example,dc=com",
			"cn",
			"loop-b",
			"cn=loop-a,ou=aliases,dc=example,dc=com",
			"",
		),
		aliasTestEntry(
			"ou=virtual,dc=example,dc=com",
			"ou",
			"virtual",
			"ou=people,dc=example,dc=com",
			"",
		),
		aliasTestEntry(
			"cn=depth-0,ou=aliases,dc=example,dc=com",
			"cn",
			"depth-0",
			"cn=depth-1,ou=aliases,dc=example,dc=com",
			"",
		),
		aliasTestEntry(
			"cn=depth-1,ou=aliases,dc=example,dc=com",
			"cn",
			"depth-1",
			"cn=depth-2,ou=aliases,dc=example,dc=com",
			"",
		),
		aliasTestEntry(
			"cn=depth-2,ou=aliases,dc=example,dc=com",
			"cn",
			"depth-2",
			"cn=depth-3,ou=aliases,dc=example,dc=com",
			"",
		),
		aliasTestEntry(
			"cn=depth-3,ou=aliases,dc=example,dc=com",
			"cn",
			"depth-3",
			"uid=alice,ou=people,dc=example,dc=com",
			"",
		),
		{
			DN: "olcOverlay={0}sssvlv,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("{0}sssvlv")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		configDN, err := directory.ParseDN(
			"olcDatabase={1}mdb,cn=config",
		)
		if err != nil {
			return err
		}
		config, err := writer.Get(configDN)
		if err != nil {
			return err
		}
		config.ReplaceValues("olcMaxDerefDepth", stringValues("3"))
		if err := writer.Put(config, true); err != nil {
			return err
		}
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed alias directory: %v", err)
	}
}

func aliasTestEntry(
	dn, namingAttribute, namingValue, target, password string,
) directory.Entry {
	attributes := []directory.Attribute{
		{Description: "objectClass", Values: stringValues("alias", "extensibleObject")},
		{Description: namingAttribute, Values: stringValues(namingValue)},
		{Description: "aliasedObjectName", Values: stringValues(target)},
	}
	if password != "" {
		attributes = append(attributes, directory.Attribute{
			Description: "userPassword",
			Values:      stringValues(password),
		})
	}
	return directory.Entry{DN: dn, Attributes: attributes}
}

func bindAliasRootClient(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	if err := client.Bind(
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	); err != nil {
		_ = client.Close()
		t.Fatalf("Bind(): %v", err)
	}
	return client
}

func aliasSearch(
	t *testing.T,
	client *ldap.Conn,
	base string,
	scope, deref int,
	filter string,
) *ldap.SearchResult {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		base,
		scope,
		deref,
		0,
		0,
		false,
		filter,
		[]string{"*", "+"},
		nil,
	))
	if err != nil {
		t.Fatalf(
			"Search(base=%q scope=%d deref=%d): %v",
			base,
			scope,
			deref,
			err,
		)
	}
	return result
}

func assertAliasDNs(
	t *testing.T,
	result *ldap.SearchResult,
	want []string,
) {
	t.Helper()
	got := make([]string, len(result.Entries))
	for index := range result.Entries {
		got[index] = result.Entries[index].DN
	}
	if !slices.Equal(got, want) {
		t.Fatalf("alias result DNs = %q, want %q", got, want)
	}
}

func assertAliasDNSet(
	t *testing.T,
	result *ldap.SearchResult,
	want []string,
) {
	t.Helper()
	got := sortedAliasDNs(result)
	want = append([]string(nil), want...)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("alias result DNs = %q, want %q", got, want)
	}
}

func sortedAliasDNs(result *ldap.SearchResult) []string {
	dns := make([]string, len(result.Entries))
	for index := range result.Entries {
		dns[index] = result.Entries[index].DN
	}
	slices.Sort(dns)
	return dns
}

func aliasDNCounts(result *ldap.SearchResult) map[string]int {
	counts := make(map[string]int)
	for _, entry := range result.Entries {
		counts[entry.DN]++
	}
	return counts
}

func assertAliasUIDs(
	t *testing.T,
	result *ldap.SearchResult,
	want []string,
) {
	t.Helper()
	got := make([]string, len(result.Entries))
	for index := range result.Entries {
		got[index] = result.Entries[index].GetAttributeValue("uid")
	}
	if !slices.Equal(got, want) {
		t.Fatalf("alias result UIDs = %q, want %q", got, want)
	}
}
