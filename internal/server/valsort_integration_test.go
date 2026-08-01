package server

import (
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const testValueSortOverlayDN = "olcOverlay={0}valsort,olcDatabase={1}mdb,cn=config"

func TestValueSortOverlayOnlineLifecycleAndSearch(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	config := Config{
		Schema:       valueSortTestRegistry(t),
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	}
	address, stop := startServer(t, store, config)
	configClient := bindConstraintClient(t, address, "cn=config", "config-secret")
	dataClient := bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)

	valueSortOverlay := ldap.NewAddRequest(testValueSortOverlayDN, nil)
	valueSortOverlay.Attribute(
		"objectClass",
		[]string{"olcOverlayConfig", "olcValSortConfig"},
	)
	valueSortOverlay.Attribute("olcOverlay", []string{"{0}valsort"})
	valueSortOverlay.Attribute("olcValSortAttr", valueSortConfigurationValues(false))
	if err := configClient.Add(valueSortOverlay); err != nil {
		t.Fatalf("Add(valsort overlay): %v", err)
	}

	sssvlv := ldap.NewAddRequest(
		"olcOverlay={1}sssvlv,olcDatabase={1}mdb,cn=config",
		nil,
	)
	sssvlv.Attribute("objectClass", []string{"olcOverlayConfig"})
	sssvlv.Attribute("olcOverlay", []string{"{1}sssvlv"})
	if err := configClient.Add(sssvlv); err != nil {
		t.Fatalf("Add(sssvlv overlay): %v", err)
	}
	syncprov := ldap.NewAddRequest(
		"olcOverlay={2}syncprov,olcDatabase={1}mdb,cn=config",
		nil,
	)
	syncprov.Attribute("objectClass", []string{"olcOverlayConfig"})
	syncprov.Attribute("olcOverlay", []string{"{2}syncprov"})
	if err := configClient.Add(syncprov); err != nil {
		t.Fatalf("Add(syncprov overlay): %v", err)
	}

	for _, uid := range []string{"valsort-a", "valsort-b"} {
		if err := dataClient.Add(valueSortPersonAdd(uid, true)); err != nil {
			t.Fatalf("Add(%s): %v", uid, err)
		}
	}
	bad := valueSortPersonAdd("valsort-bad", false)
	assertLDAPResultCode(
		t,
		dataClient.Add(bad),
		ldap.LDAPResultConstraintViolation,
	)

	rootDSE, err := dataClient.Search(ldap.NewSearchRequest(
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
		t.Fatalf("Root DSE Search() = %#v, %v", rootDSE, err)
	}
	if containsString(
		rootDSE.Entries[0].GetAttributeValues("supportedControl"),
		valueSortControlOID,
	) {
		t.Fatal("hidden valSort control was advertised")
	}

	assertValueSortSearch(t, dataClient, nil, false, false)
	assertValueSortSearch(t, dataClient, []ldap.Control{valueSortControl(true)}, true, false)
	assertValueSortSearch(t, dataClient, []ldap.Control{valueSortControl(false)}, false, false)
	assertValueSortPagedSearch(t, dataClient, false)
	assertValueSortPagedSearch(t, dataClient, true)
	assertValueSortVLVSearch(t, dataClient, false)
	assertValueSortVLVSearch(t, dataClient, true)
	assertValueSortSyncSearchIsRaw(t, address)

	stored := readStoredEntry(
		t,
		store,
		"uid=valsort-a,ou=people,dc=example,dc=com",
	)
	assertByteValuesEqual(
		t,
		stored.Values("rankedLabel"),
		stringValues("{2}Beta", "{1}Zulu", "{1}alpha"),
	)
	assertByteValuesEqual(
		t,
		stored.Values("plainLabel"),
		stringValues("Zebra", "alpha", "Beta"),
	)

	badModify := ldap.NewModifyRequest(
		"uid=valsort-a,ou=people,dc=example,dc=com",
		nil,
	)
	badModify.Add("rankedLabel", []string{"missing"})
	assertLDAPResultCode(
		t,
		dataClient.Modify(badModify),
		ldap.LDAPResultConstraintViolation,
	)

	invalidConfig := ldap.NewModifyRequest(testValueSortOverlayDN, nil)
	invalidConfig.Replace(
		"olcValSortAttr",
		[]string{`plainLabel "ou=people,dc=example,dc=com" numeric-ascend`},
	)
	assertLDAPResultCode(
		t,
		configClient.Modify(invalidConfig),
		ldap.LDAPResultConstraintViolation,
	)
	assertValueSortSearch(t, dataClient, nil, false, false)

	descending := ldap.NewModifyRequest(testValueSortOverlayDN, nil)
	descending.Replace(
		"olcValSortAttr",
		valueSortConfigurationValues(true),
	)
	if err := configClient.Modify(descending); err != nil {
		t.Fatalf("Modify(valsort descending): %v", err)
	}
	assertValueSortSearch(t, dataClient, nil, false, true)

	configClient.Close()
	dataClient.Close()
	stop()

	address, stop = startServer(t, store, config)
	defer stop()
	dataClient = bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer dataClient.Close()
	assertValueSortSearch(t, dataClient, nil, false, true)
}

func assertValueSortSyncSearchIsRaw(t *testing.T, address string) {
	t.Helper()
	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer connection.Close()
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawSyncSearchRequestFor(
			t,
			"ou=people,dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			"(uid=valsort-a)",
		),
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshOnly,
		}, true),
	)
	refresh := readRawSyncRefresh(t, connection, 2)
	if refresh.resultCode != int64(ldapwire.ResultSuccess) ||
		len(refresh.entries) != 1 {
		t.Fatalf("valsort Sync refresh = %#v", refresh)
	}
	assertStringValuesEqual(
		t,
		refresh.entries[0].attributes["rankedLabel"],
		[]string{"{2}Beta", "{1}Zulu", "{1}alpha"},
	)
}

func valueSortConfigurationValues(descending bool) []string {
	plainMode := "alpha-ascend"
	if descending {
		plainMode = "alpha-descend"
	}
	return []string{
		`{0}plainLabel "ou=people,dc=example,dc=com" ` + plainMode,
		`{1}score "ou=people,dc=example,dc=com" numeric-descend`,
		`{2}rankedLabel "ou=people,dc=example,dc=com" weighted alpha-ascend`,
	}
}

func valueSortPersonAdd(uid string, weighted bool) *ldap.AddRequest {
	request := ldap.NewAddRequest(
		"uid="+uid+",ou=people,dc=example,dc=com",
		nil,
	)
	request.Attribute("objectClass", []string{"inetOrgPerson", "valueSortData"})
	request.Attribute("uid", []string{uid})
	request.Attribute("cn", []string{uid})
	request.Attribute("sn", []string{"User"})
	request.Attribute("plainLabel", []string{"Zebra", "alpha", "Beta"})
	request.Attribute("score", []string{"10", "-1", "2"})
	ranked := []string{"Beta", "Zulu", "alpha"}
	if weighted {
		ranked = []string{"{2}Beta", "{1}Zulu", "{1}alpha"}
	}
	request.Attribute("rankedLabel", ranked)
	return request
}

func valueSortControl(raw bool) ldap.Control {
	return &ldap.ControlString{
		ControlType:  valueSortControlOID,
		Criticality:  true,
		ControlValue: string(ldapwire.EncodeValueSortControlValue(raw)),
	}
}

func valueSortSearchRequest(controls []ldap.Control) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=valsort-a)",
		[]string{"plainLabel", "score", "rankedLabel"},
		controls,
	)
}

func assertValueSortSearch(
	t *testing.T,
	client *ldap.Conn,
	controls []ldap.Control,
	raw,
	descending bool,
) {
	t.Helper()
	result, err := client.Search(valueSortSearchRequest(controls))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("valsort Search() = %#v, %v", result, err)
	}
	entry := result.Entries[0]
	plain := []string{"alpha", "Beta", "Zebra"}
	ranked := []string{"alpha", "Zulu", "Beta"}
	scores := []string{"10", "2", "-1"}
	if raw {
		plain = []string{"Zebra", "alpha", "Beta"}
		ranked = []string{"{2}Beta", "{1}Zulu", "{1}alpha"}
		scores = []string{"10", "-1", "2"}
	} else if descending {
		plain = []string{"Zebra", "Beta", "alpha"}
	}
	assertStringValuesEqual(t, entry.GetAttributeValues("plainLabel"), plain)
	assertStringValuesEqual(t, entry.GetAttributeValues("rankedLabel"), ranked)
	assertStringValuesEqual(t, entry.GetAttributeValues("score"), scores)
}

func assertValueSortPagedSearch(t *testing.T, client *ldap.Conn, raw bool) {
	t.Helper()
	controls := []ldap.Control{newSortControl(ldap.SortKey{
		AttributeType: "uid",
		MatchingRule:  "caseIgnoreOrderingMatch",
	})}
	if raw {
		controls = append(controls, valueSortControl(true))
	}
	request := ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=valueSortData)",
		[]string{"uid", "plainLabel"},
		controls,
	)
	result, err := client.SearchWithPaging(request, 1)
	if err != nil || len(result.Entries) != 2 {
		t.Fatalf("valsort sorted paged Search() = %#v, %v", result, err)
	}
	want := []string{"alpha", "Beta", "Zebra"}
	if raw {
		want = []string{"Zebra", "alpha", "Beta"}
	}
	for _, entry := range result.Entries {
		assertStringValuesEqual(t, entry.GetAttributeValues("plainLabel"), want)
	}
}

func assertValueSortVLVSearch(t *testing.T, client *ldap.Conn, raw bool) {
	t.Helper()
	rebindVirtualListViewClient(t, client)
	sortControl := newSortControl(ldap.SortKey{
		AttributeType: "uid",
		MatchingRule:  "caseIgnoreOrderingMatch",
	})
	controls := func(request ldapwire.VirtualListViewRequest) []ldap.Control {
		result := []ldap.Control{
			sortControl,
			newVirtualListViewControl(request),
		}
		if raw {
			result = append(result, valueSortControl(true))
		}
		return result
	}
	search := func(request ldapwire.VirtualListViewRequest) *ldap.SearchResult {
		result, err := client.Search(ldap.NewSearchRequest(
			"ou=people,dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=valueSortData)",
			[]string{"uid", "plainLabel"},
			controls(request),
		))
		if err != nil || len(result.Entries) != 1 {
			t.Fatalf("valsort VLV Search(raw=%t) = %#v, %v", raw, result, err)
		}
		want := []string{"alpha", "Beta", "Zebra"}
		if raw {
			want = []string{"Zebra", "alpha", "Beta"}
		}
		assertStringValuesEqual(
			t,
			result.Entries[0].GetAttributeValues("plainLabel"),
			want,
		)
		return result
	}
	first := search(ldapwire.VirtualListViewRequest{
		ByOffset:     true,
		Offset:       1,
		ContentCount: 2,
	})
	contextID := decodeVirtualListViewResponse(t, first).ContextID
	second := search(ldapwire.VirtualListViewRequest{
		ByOffset:     true,
		Offset:       2,
		ContentCount: 2,
		ContextID:    contextID,
		HasContextID: true,
	})
	response := decodeVirtualListViewResponse(t, second)
	if response.TargetPosition != 2 || response.ContentCount != 2 {
		t.Fatalf("valsort VLV continuation response = %#v", response)
	}
}

func assertStringValuesEqual(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("values = %q, want %q", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("values = %q, want %q", got, want)
		}
	}
}
