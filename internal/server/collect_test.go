package server

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	collectDatabaseOverlayDN = "olcOverlay={0}collect,olcDatabase={1}mdb,cn=config"
	collectFrontendOverlayDN = "olcOverlay={0}collect,olcDatabase={-1}frontend,cn=config"
	collectPeopleDN          = "ou=people,dc=example,dc=com"
	collectTeamDN            = "ou=team,ou=people,dc=example,dc=com"
	collectBobDN             = "uid=bob,ou=team,ou=people,dc=example,dc=com"
	collectCarolDN           = "uid=carol,ou=team,ou=people,dc=example,dc=com"
)

func TestCollectRuntimeConfigurationParsing(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	entry := directory.Entry{
		DN: collectDatabaseOverlayDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcCollectConfig")},
			{Description: "olcOverlay", Values: stringValues("{0}collect")},
			{Description: "olcCollectInfo", Values: stringValues(
				`"ou=people,dc=example,dc=com" description,telephoneNumber`,
				`"ou=team,ou=people,dc=example,dc=com" description,description`,
				`ou=alpha,dc=example,dc=com mail`,
				`ou=bravo,dc=example,dc=com mail`,
			)},
		},
	}
	configuration, err := loadCollectRuntimeConfiguration(entry)
	if err != nil {
		t.Fatalf("loadCollectRuntimeConfiguration(): %v", err)
	}
	if err := validateCollectSchema(registry, &configuration); err != nil {
		t.Fatalf("validateCollectSchema(): %v", err)
	}
	gotBases := make([]string, len(configuration.rules))
	for index, rule := range configuration.rules {
		gotBases[index] = rule.base.Key()
	}
	wantBases := []string{
		"ou=team,ou=people,dc=example,dc=com",
		"ou=people,dc=example,dc=com",
		"ou=alpha,dc=example,dc=com",
		"ou=bravo,dc=example,dc=com",
	}
	if !reflect.DeepEqual(gotBases, wantBases) {
		t.Fatalf("ordered collect bases = %q, want %q", gotBases, wantBases)
	}
	if got := configuration.rules[0].attributes; len(got) != 2 ||
		got[0].description != "description" || got[1].description != "description" {
		t.Fatalf("repeated configured attributes = %#v", got)
	}

	tests := []struct {
		name string
		attr directory.Attribute
		code ldapwire.ResultCode
	}{
		{
			name: "normalized duplicate DN",
			attr: directory.Attribute{Description: "olcCollectInfo", Values: stringValues(
				`"OU=People,DC=Example,DC=Com" description`,
				`"ou=people,dc=example,dc=com" mail`,
			)},
			code: ldapwire.ResultOther,
		},
		{
			name: "empty item",
			attr: directory.Attribute{Description: "olcCollectInfo", Values: stringValues(
				`"ou=people,dc=example,dc=com" description,,mail`,
			)},
			code: ldapwire.ResultConstraintViolation,
		},
		{
			name: "whitespace item",
			attr: directory.Attribute{Description: "olcCollectInfo", Values: stringValues(
				`"ou=people,dc=example,dc=com" "description, mail"`,
			)},
			code: ldapwire.ResultConstraintViolation,
		},
		{
			name: "missing list",
			attr: directory.Attribute{Description: "olcCollectInfo", Values: stringValues(
				`"ou=people,dc=example,dc=com"`,
			)},
			code: ldapwire.ResultConstraintViolation,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := entry.Clone()
			candidate.ReplaceValues(test.attr.Description, test.attr.Values)
			_, err := loadCollectRuntimeConfiguration(candidate)
			result, ok := collectConfigurationResult(err)
			if !ok || result.Code != test.code {
				t.Fatalf("configuration error = %v, result %#v", err, result)
			}
		})
	}

	unknown := entry.Clone()
	unknown.ReplaceValues(
		"olcCollectInfo",
		stringValues(`"ou=people,dc=example,dc=com" collectUndefined`),
	)
	configuration, err = loadCollectRuntimeConfiguration(unknown)
	if err != nil {
		t.Fatalf("parse unknown schema attribute: %v", err)
	}
	err = validateCollectSchema(registry, &configuration)
	result, ok := collectConfigurationResult(err)
	if !ok || result.Code != ldapwire.ResultOther ||
		!strings.Contains(result.DiagnosticMessage, "attribute description unknown") {
		t.Fatalf("unknown schema attribute = %v, result %#v", err, result)
	}
}

func TestCollectSearchProjectionAndControls(t *testing.T) {
	store, _, configClient, dataClient, stop := startCollectTestServer(t)
	defer stop()
	defer configClient.Close()
	defer dataClient.Close()
	addCollectTestFixtures(t, dataClient)
	addCollectOverlays(t, configClient)

	entry := searchCollectEntry(
		t,
		dataClient,
		collectBobDN,
		[]string{"description", "telephoneNumber", "l"},
		false,
		nil,
	)
	wantDescriptions := []string{
		"Local-A",
		"SHARED",
		"specific-a",
		"shared",
		"specific-a",
		"shared",
		"broad-a",
		"shared",
	}
	if got := entry.GetAttributeValues("description"); !reflect.DeepEqual(got, wantDescriptions) {
		t.Fatalf("projected descriptions = %q, want %q", got, wantDescriptions)
	}
	if got := entry.GetAttributeValues("telephoneNumber"); !reflect.DeepEqual(
		got,
		[]string{"+15550200", "+15550100"},
	) {
		t.Fatalf("normalized telephoneNumber = %q", got)
	}
	if got := entry.GetAttributeValues("l"); !reflect.DeepEqual(
		got,
		[]string{"local", "global", "global"},
	) {
		t.Fatalf("frontend projected l = %q", got)
	}

	template := searchCollectEntry(
		t,
		dataClient,
		collectTeamDN,
		[]string{"description"},
		false,
		nil,
	)
	if got := template.GetAttributeValues("description"); !reflect.DeepEqual(
		got,
		[]string{"Specific-A", "shared", "broad-a", "shared"},
	) {
		t.Fatalf("nested template descriptions = %q", got)
	}
	people := searchCollectEntry(
		t,
		dataClient,
		collectPeopleDN,
		[]string{"description", "l"},
		false,
		nil,
	)
	if got := people.GetAttributeValues("description"); !reflect.DeepEqual(
		got,
		[]string{"Broad-A", "shared"},
	) {
		t.Fatalf("exact template descriptions = %q", got)
	}
	if got := people.GetAttributeValues("l"); !reflect.DeepEqual(got, []string{"Global"}) {
		t.Fatalf("exact frontend template l = %q", got)
	}

	cnOnly := searchCollectEntry(t, dataClient, collectCarolDN, []string{"cn"}, false, nil)
	if len(cnOnly.GetAttributeValues("description")) != 0 {
		t.Fatalf("cn-only search exposed projection: %#v", cnOnly.Attributes)
	}
	noAttributes := searchCollectEntry(t, dataClient, collectCarolDN, []string{"1.1"}, false, nil)
	if len(noAttributes.Attributes) != 0 {
		t.Fatalf("1.1 search attributes = %#v", noAttributes.Attributes)
	}
	operational := searchCollectEntry(t, dataClient, collectCarolDN, []string{"+"}, false, nil)
	if len(operational.GetAttributeValues("description")) != 0 {
		t.Fatalf("+ search exposed projected user attribute: %#v", operational.Attributes)
	}
	typesOnly := searchCollectEntry(
		t,
		dataClient,
		collectCarolDN,
		[]string{"description"},
		true,
		nil,
	)
	var typeOnlyDescription *ldap.EntryAttribute
	for _, candidate := range typesOnly.Attributes {
		if strings.EqualFold(candidate.Name, "description") {
			typeOnlyDescription = candidate
			break
		}
	}
	if typeOnlyDescription == nil || len(typeOnlyDescription.ByteValues) != 0 {
		t.Fatalf("typesOnly projected description = %#v", typeOnlyDescription)
	}

	filtered, err := dataClient.Search(ldap.NewSearchRequest(
		collectTeamDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(description=*)",
		[]string{"uid"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(projected filter): %v", err)
	}
	for _, candidate := range filtered.Entries {
		if strings.EqualFold(candidate.DN, collectCarolDN) {
			t.Fatalf("filter matched projected-only description: %#v", filtered.Entries)
		}
	}
	if code := collectCompareResultCode(
		t,
		dataClient,
		collectCarolDN,
		"description",
		"specific-a",
	); code != ldap.LDAPResultNoSuchAttribute {
		t.Fatalf("Compare(projected description) result = %d", code)
	}

	paging := ldap.NewControlPaging(1)
	seen := make(map[string]bool)
	for {
		request := ldap.NewSearchRequest(
			collectTeamDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=inetOrgPerson)",
			[]string{"description"},
			[]ldap.Control{paging},
		)
		result, err := dataClient.Search(request)
		if err != nil {
			t.Fatalf("paged collect Search(): %v", err)
		}
		for _, candidate := range result.Entries {
			seen[strings.ToLower(candidate.DN)] = true
			if len(candidate.GetAttributeValues("description")) == 0 {
				t.Fatalf("paged entry lacks projection: %#v", candidate)
			}
		}
		response := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		page, ok := response.(*ldap.ControlPaging)
		if !ok {
			t.Fatalf("paged response control = %#v", response)
		}
		if len(page.Cookie) == 0 {
			break
		}
		paging.SetCookie(page.Cookie)
	}
	if !seen[strings.ToLower(collectBobDN)] || !seen[strings.ToLower(collectCarolDN)] {
		t.Fatalf("paged collect entries = %v", seen)
	}

	managed := searchCollectEntry(
		t,
		dataClient,
		"ou=ref,"+collectTeamDN,
		[]string{"description"},
		false,
		[]ldap.Control{ldap.NewControlManageDsaIT(true)},
	)
	if got := managed.GetAttributeValues("description"); len(got) == 0 {
		t.Fatalf("ManageDsaIT referral projection = %#v", managed.Attributes)
	}
	withoutManage := ldap.NewSearchRequest(
		"ou=ref,"+collectTeamDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"description"},
		nil,
	)
	assertLDAPResultCode(t, func() error {
		_, err := dataClient.Search(withoutManage)
		return err
	}(), ldap.LDAPResultReferral)

	stored := readStoredEntry(t, store, collectCarolDN)
	if stored.HasAttribute("description") {
		t.Fatalf("projection persisted in target: %#v", stored.Attributes)
	}
}

func TestCollectModifyHardeningAndUnhookedWrites(t *testing.T) {
	store, _, configClient, dataClient, stop := startCollectTestServer(t)
	defer stop()
	defer configClient.Close()
	defer dataClient.Close()
	addCollectTestFixtures(t, dataClient)
	addCollectOverlays(t, configClient)

	direct := ldap.NewModifyRequest(collectCarolDN, nil)
	direct.Add("description", []string{"blocked"})
	assertCollectModifyDenied(t, dataClient.Modify(direct), "description")

	multiple := ldap.NewModifyRequest(collectCarolDN, nil)
	multiple.Add("givenName", []string{"must-rollback"})
	multiple.Add("description", []string{"must-not-persist"})
	assertCollectModifyDenied(t, dataClient.Modify(multiple), "description")
	stored := readStoredEntry(t, store, collectCarolDN)
	if stored.HasAttribute("givenName") || stored.HasAttribute("description") {
		t.Fatalf("multi-modification denial was not atomic: %#v", stored.Attributes)
	}

	optioned := ldap.NewModifyRequest(collectCarolDN, nil)
	optioned.Add("description;lang-en", []string{"must-not-bypass"})
	assertCollectModifyDenied(t, dataClient.Modify(optioned), "description")
	stored = readStoredEntry(t, store, collectCarolDN)
	if stored.HasAttribute("description;lang-en") {
		t.Fatalf("optioned collect attribute bypass persisted: %#v", stored.Attributes)
	}

	template := ldap.NewModifyRequest(collectPeopleDN, nil)
	template.Add("description", []string{"Template-Update"})
	if err := dataClient.Modify(template); err != nil {
		t.Fatalf("Modify(exact collect template): %v", err)
	}
	nestedTemplate := ldap.NewModifyRequest(collectTeamDN, nil)
	nestedTemplate.Add("description", []string{"blocked-by-broad-rule"})
	assertCollectModifyDenied(t, dataClient.Modify(nestedTemplate), "description")

	addedDN := "uid=collect-add," + collectTeamDN
	added := ldap.NewAddRequest(addedDN, nil)
	added.Attribute("objectClass", []string{"inetOrgPerson"})
	added.Attribute("uid", []string{"collect-add"})
	added.Attribute("cn", []string{"Collect Add"})
	added.Attribute("sn", []string{"Add"})
	added.Attribute("description", []string{"Local-Add"})
	if err := dataClient.Add(added); err != nil {
		t.Fatalf("Add(descendant with local collect attribute): %v", err)
	}
	projected := searchCollectEntry(
		t,
		dataClient,
		addedDN,
		[]string{"description"},
		false,
		nil,
	)
	if got := projected.GetAttributeValues("description"); len(got) < 2 || got[0] != "Local-Add" {
		t.Fatalf("Add local plus projected descriptions = %q", got)
	}

	movedDN := "uid=collect-add,ou=archive,dc=example,dc=com"
	move := ldap.NewModifyDNRequest(addedDN, "uid=collect-add", true, "ou=archive,dc=example,dc=com")
	if err := dataClient.ModifyDN(move); err != nil {
		t.Fatalf("ModifyDN(out of collect scope): %v", err)
	}
	moved := searchCollectEntry(t, dataClient, movedDN, []string{"description"}, false, nil)
	if got := moved.GetAttributeValues("description"); !reflect.DeepEqual(got, []string{"Local-Add"}) {
		t.Fatalf("moved entry descriptions = %q", got)
	}
	if err := dataClient.Del(ldap.NewDelRequest(movedDN, nil)); err != nil {
		t.Fatalf("Delete(collect target): %v", err)
	}
}

func TestCollectProjectionACLs(t *testing.T) {
	_, address, configClient, dataClient, stop := startCollectTestServer(t)
	defer stop()
	defer configClient.Close()
	defer dataClient.Close()
	addCollectTestFixtures(t, dataClient)
	addCollectOverlays(t, configClient)
	reader := bindConstraintClient(
		t,
		address,
		"uid=alice,ou=people,dc=example,dc=com",
		"secret",
	)
	defer reader.Close()

	replaceCollectDataACL(t, configClient,
		`{0}to dn.exact="`+collectTeamDN+`" attrs=description val.regex="^shared$" by dn.exact="uid=alice,ou=people,dc=example,dc=com" none by * read`,
		`{1}to * by * read`,
	)
	entry := searchCollectEntry(
		t,
		reader,
		collectBobDN,
		[]string{"description"},
		false,
		nil,
	)
	if got := entry.GetAttributeValues("description"); !reflect.DeepEqual(got, []string{
		"Local-A", "SHARED", "specific-a", "specific-a", "broad-a", "shared",
	}) {
		t.Fatalf("template value ACL descriptions = %q", got)
	}

	replaceCollectDataACL(t, configClient,
		`{0}to dn.exact="`+collectPeopleDN+`" attrs=description by dn.exact="uid=alice,ou=people,dc=example,dc=com" none by * read`,
		`{1}to * by * read`,
	)
	entry = searchCollectEntry(
		t,
		reader,
		collectBobDN,
		[]string{"description"},
		false,
		nil,
	)
	if got := entry.GetAttributeValues("description"); !reflect.DeepEqual(got, []string{
		"Local-A", "SHARED", "specific-a", "shared", "specific-a", "shared",
	}) {
		t.Fatalf("template attribute ACL descriptions = %q", got)
	}

	replaceCollectDataACL(t, configClient,
		`{0}to dn.exact="`+collectTeamDN+`" attrs=entry by dn.exact="uid=alice,ou=people,dc=example,dc=com" none by * read`,
		`{1}to * by * read`,
	)
	entry = searchCollectEntry(
		t,
		reader,
		collectBobDN,
		[]string{"description"},
		false,
		nil,
	)
	if got := entry.GetAttributeValues("description"); !reflect.DeepEqual(got, []string{
		"Local-A", "SHARED", "broad-a", "shared",
	}) {
		t.Fatalf("template entry ACL descriptions = %q", got)
	}

	replaceCollectDataACL(t, configClient,
		`{0}to dn.exact="`+collectBobDN+`" attrs=description val.regex="^shared$" by dn.exact="uid=alice,ou=people,dc=example,dc=com" none by * read`,
		`{1}to * by * read`,
	)
	entry = searchCollectEntry(
		t,
		reader,
		collectBobDN,
		[]string{"description"},
		false,
		nil,
	)
	if got := entry.GetAttributeValues("description"); !reflect.DeepEqual(got, []string{
		"Local-A", "specific-a", "specific-a", "broad-a",
	}) {
		t.Fatalf("target value ACL descriptions = %q", got)
	}

	replaceCollectDataACL(t, configClient,
		`{0}to dn.exact="`+collectBobDN+`" attrs=description by dn.exact="uid=alice,ou=people,dc=example,dc=com" none by * read`,
		`{1}to * by * read`,
	)
	entry = searchCollectEntry(
		t,
		reader,
		collectBobDN,
		[]string{"description"},
		false,
		nil,
	)
	if len(entry.GetAttributeValues("description")) != 0 {
		t.Fatalf("target attribute ACL exposed values: %#v", entry.Attributes)
	}

	replaceCollectDataACL(t, configClient,
		`{0}to dn.exact="`+collectBobDN+`" attrs=entry by dn.exact="uid=alice,ou=people,dc=example,dc=com" none by * read`,
		`{1}to * by * read`,
	)
	request := ldap.NewSearchRequest(
		collectBobDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"description"},
		nil,
	)
	result, err := reader.Search(request)
	if err == nil && len(result.Entries) != 0 {
		t.Fatalf("target entry ACL returned entry: %#v", result.Entries)
	}
	if err != nil {
		var ldapErr *ldap.Error
		if !errors.As(err, &ldapErr) ||
			(ldapErr.ResultCode != ldap.LDAPResultInsufficientAccessRights &&
				ldapErr.ResultCode != ldap.LDAPResultNoSuchObject) {
			t.Fatalf("target entry ACL Search() = %v", err)
		}
	}
}

func TestCollectProjectionIsInvisibleToSort(t *testing.T) {
	_, _, configClient, dataClient, stop := startCollectTestServer(t)
	defer stop()
	defer configClient.Close()
	defer dataClient.Close()

	schemaRequest := ldap.NewAddRequest("cn={9}collect,cn=schema,cn=config", nil)
	schemaRequest.Attribute("objectClass", []string{"olcSchemaConfig"})
	schemaRequest.Attribute("cn", []string{"{9}collect"})
	schemaRequest.Attribute("olcAttributeTypes", []string{
		"{0}( 1.3.6.1.4.1.99999.1901 NAME 'collectSort' " +
			"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
			"SYNTAX " + schema.SyntaxDirectoryString + " )",
	})
	if err := configClient.Add(schemaRequest); err != nil {
		t.Fatalf("Add(collect sort schema): %v", err)
	}
	addCollectTestFixtures(t, dataClient)
	people := ldap.NewModifyRequest(collectPeopleDN, nil)
	people.Add("collectSort", []string{"Zulu"})
	if err := dataClient.Modify(people); err != nil {
		t.Fatalf("Modify(people collectSort): %v", err)
	}
	team := ldap.NewModifyRequest(collectTeamDN, nil)
	team.Add("collectSort", []string{"Alpha"})
	if err := dataClient.Modify(team); err != nil {
		t.Fatalf("Modify(team collectSort): %v", err)
	}

	overlay := ldap.NewAddRequest(collectDatabaseOverlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcCollectConfig"})
	overlay.Attribute("olcOverlay", []string{"{0}collect"})
	overlay.Attribute("olcCollectInfo", []string{
		`"ou=people,dc=example,dc=com" collectSort`,
		`"ou=team,ou=people,dc=example,dc=com" collectSort`,
	})
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(sort collect overlay): %v", err)
	}
	sssVLV := ldap.NewAddRequest(
		"olcOverlay={1}sssvlv,olcDatabase={1}mdb,cn=config",
		nil,
	)
	sssVLV.Attribute("objectClass", []string{"olcOverlayConfig"})
	sssVLV.Attribute("olcOverlay", []string{"{1}sssvlv"})
	if err := configClient.Add(sssVLV); err != nil {
		t.Fatalf("Add(sssvlv overlay): %v", err)
	}

	newRequest := func(controls []ldap.Control) *ldap.SearchRequest {
		return ldap.NewSearchRequest(
			collectPeopleDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(|(uid=alice)(uid=bob))",
			[]string{"uid", "collectSort"},
			controls,
		)
	}
	natural, err := dataClient.Search(newRequest(nil))
	if err != nil {
		t.Fatalf("natural collectSort Search(): %v", err)
	}
	wantDNs := collectEntryDNs(natural.Entries)
	if len(wantDNs) != 2 {
		t.Fatalf("natural collectSort entries = %#v", natural.Entries)
	}
	sorted, err := dataClient.Search(newRequest([]ldap.Control{newSortControl(ldap.SortKey{
		AttributeType: "collectSort",
	})}))
	if err != nil {
		t.Fatalf("sorted collectSort Search(): %v", err)
	}
	assertSortResult(t, sorted, ldap.ControlServerSideSortingCodeSuccess)
	if got := collectEntryDNs(sorted.Entries); !reflect.DeepEqual(got, wantDNs) {
		t.Fatalf("projected sort changed order = %q, want backend order %q", got, wantDNs)
	}
	if got := sorted.Entries[0].GetAttributeValues("collectSort"); len(got) == 0 {
		t.Fatalf("sorted response lacks collect projection: %#v", sorted.Entries[0])
	}
	window, err := dataClient.Search(newRequest([]ldap.Control{
		newSortControl(ldap.SortKey{AttributeType: "collectSort"}),
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			ByOffset:     true,
			Offset:       2,
			ContentCount: 2,
		}),
	}))
	if err != nil {
		t.Fatalf("VLV collectSort Search(): %v", err)
	}
	if got := collectEntryDNs(window.Entries); !reflect.DeepEqual(got, wantDNs[1:]) {
		t.Fatalf("projected VLV DNs = %q, want %q", got, wantDNs[1:])
	}
	if len(window.Entries[0].GetAttributeValues("collectSort")) == 0 {
		t.Fatalf("VLV response lacks collect projection: %#v", window.Entries[0])
	}
	response := decodeVirtualListViewResponse(t, window)
	if response.TargetPosition != 2 || response.ContentCount != 2 {
		t.Fatalf("collect VLV response = %#v", response)
	}

	paging := ldap.NewControlPaging(1)
	var pagedDNs []string
	for {
		result, err := dataClient.Search(newRequest([]ldap.Control{
			newSortControl(ldap.SortKey{AttributeType: "collectSort"}),
			paging,
		}))
		if err != nil {
			t.Fatalf("sorted paged collect Search(): %v", err)
		}
		assertSortResult(t, result, ldap.ControlServerSideSortingCodeSuccess)
		for _, entry := range result.Entries {
			pagedDNs = append(pagedDNs, strings.ToLower(entry.DN))
			if len(entry.GetAttributeValues("collectSort")) == 0 {
				t.Fatalf("sorted paged response lacks projection: %#v", entry)
			}
		}
		control, ok := ldap.FindControl(
			result.Controls,
			ldap.ControlTypePaging,
		).(*ldap.ControlPaging)
		if !ok {
			t.Fatalf("sorted paging response = %#v", result.Controls)
		}
		if len(control.Cookie) == 0 {
			break
		}
		paging.SetCookie(control.Cookie)
	}
	if !reflect.DeepEqual(pagedDNs, wantDNs) {
		t.Fatalf("sorted paged DNs = %q, want %q", pagedDNs, wantDNs)
	}
}

func TestCollectOverlayRemainsSeparateFromRFC3671CollectiveAttributes(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
		Schema:       collectiveServerRegistry(t),
	})
	defer stop()
	configClient := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer configClient.Close()
	dataClient := bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer dataClient.Close()

	template := ldap.NewModifyRequest(collectPeopleDN, nil)
	template.Add("objectClass", []string{"extensibleObject"})
	template.Add("mail", []string{"Template@Example.COM"})
	if err := dataClient.Modify(template); err != nil {
		t.Fatalf("Modify(combined collect template): %v", err)
	}
	sourceDN := "cn=collective," + collectPeopleDN
	source := ldap.NewAddRequest(sourceDN, nil)
	source.Attribute("objectClass", []string{
		"subentry",
		"collectiveAttributeSubentry",
	})
	source.Attribute("cn", []string{"collective"})
	source.Attribute("subtreeSpecification", []string{"{}"})
	source.Attribute("c-description", []string{"RFC3671 Shared"})
	if err := dataClient.Add(source); err != nil {
		t.Fatalf("Add(RFC3671 collective source): %v", err)
	}
	targetDN := "uid=collect-combined," + collectPeopleDN
	if err := dataClient.Add(newPersonAddRequest("collect-combined")); err != nil {
		t.Fatalf("Add(combined collect target): %v", err)
	}
	overlay := ldap.NewAddRequest(collectDatabaseOverlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcCollectConfig"})
	overlay.Attribute("olcOverlay", []string{"{0}collect"})
	overlay.Attribute(
		"olcCollectInfo",
		[]string{`"ou=people,dc=example,dc=com" mail`},
	)
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(combined collect overlay): %v", err)
	}

	entry := searchCollectEntry(
		t,
		dataClient,
		targetDN,
		[]string{"mail", "c-description"},
		false,
		nil,
	)
	if got := entry.GetAttributeValues("mail"); !reflect.DeepEqual(
		got,
		[]string{"template@example.com"},
	) {
		t.Fatalf("collect mail projection = %q", got)
	}
	if got := entry.GetAttributeValues("c-description"); !reflect.DeepEqual(
		got,
		[]string{"RFC3671 Shared"},
	) {
		t.Fatalf("RFC3671 collective projection = %q", got)
	}

	mailFilter, err := dataClient.Search(ldap.NewSearchRequest(
		targetDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(mail=template@example.com)",
		[]string{"uid"},
		nil,
	))
	if err != nil || len(mailFilter.Entries) != 0 {
		t.Fatalf("collect mail filter = %#v, %v", mailFilter, err)
	}
	collectiveFilter, err := dataClient.Search(ldap.NewSearchRequest(
		targetDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(c-description=rfc3671 shared)",
		[]string{"uid"},
		nil,
	))
	if err != nil || len(collectiveFilter.Entries) != 1 {
		t.Fatalf("RFC3671 collective filter = %#v, %v", collectiveFilter, err)
	}
	if code := collectCompareResultCode(
		t,
		dataClient,
		targetDN,
		"mail",
		"template@example.com",
	); code != ldap.LDAPResultNoSuchAttribute {
		t.Fatalf("collect mail Compare result = %d", code)
	}
	matched, err := dataClient.Compare(targetDN, "c-description", "RFC3671 Shared")
	if err != nil || !matched {
		t.Fatalf("RFC3671 collective Compare = %t, %v", matched, err)
	}
}

func TestCollectDynamicConfigurationRollbackAndRestart(t *testing.T) {
	store, address, configClient, dataClient, stop := startCollectTestServer(t)
	addCollectTestFixtures(t, dataClient)
	addCollectDatabaseOverlay(t, configClient)

	if got := searchCollectEntry(
		t,
		dataClient,
		collectCarolDN,
		[]string{"description"},
		false,
		nil,
	).GetAttributeValues("description"); len(got) == 0 {
		t.Fatal("initial collect configuration was not live")
	}
	exactDuplicate := ldap.NewModifyRequest(collectDatabaseOverlayDN, nil)
	exactDuplicate.Add(
		"olcCollectInfo",
		[]string{`"ou=people,dc=example,dc=com" description,telephoneNumber,l`},
	)
	assertLDAPResultCode(
		t,
		configClient.Modify(exactDuplicate),
		ldap.LDAPResultAttributeOrValueExists,
	)
	distinctValue := `"ou=archive,dc=example,dc=com" mail`
	addDistinct := ldap.NewModifyRequest(collectDatabaseOverlayDN, nil)
	addDistinct.Add("olcCollectInfo", []string{distinctValue})
	if err := configClient.Modify(addDistinct); err != nil {
		t.Fatalf("add distinct olcCollectInfo: %v", err)
	}
	deleteDistinct := ldap.NewModifyRequest(collectDatabaseOverlayDN, nil)
	deleteDistinct.Delete("olcCollectInfo", []string{distinctValue})
	if err := configClient.Modify(deleteDistinct); err != nil {
		t.Fatalf("delete distinct olcCollectInfo: %v", err)
	}
	deleteDistinctAgain := ldap.NewModifyRequest(collectDatabaseOverlayDN, nil)
	deleteDistinctAgain.Delete("olcCollectInfo", []string{distinctValue})
	assertLDAPResultCode(
		t,
		configClient.Modify(deleteDistinctAgain),
		ldap.LDAPResultNoSuchAttribute,
	)

	duplicateDN := ldap.NewModifyRequest(collectDatabaseOverlayDN, nil)
	duplicateDN.Add(
		"olcCollectInfo",
		[]string{`"OU=PEOPLE,DC=EXAMPLE,DC=COM" mail`},
	)
	assertLDAPResultCode(t, configClient.Modify(duplicateDN), ldap.LDAPResultOther)

	unknownProjected := ldap.NewModifyRequest(collectDatabaseOverlayDN, nil)
	unknownProjected.Replace(
		"olcCollectInfo",
		[]string{`"ou=people,dc=example,dc=com" collectUndefined`},
	)
	assertLDAPResultCode(t, configClient.Modify(unknownProjected), ldap.LDAPResultOther)
	stored := readStoredEntry(t, store, collectDatabaseOverlayDN)
	if len(stored.Values("olcCollectInfo")) != 3 {
		t.Fatalf("invalid replace persisted: %q", stored.Values("olcCollectInfo"))
	}

	whitespace := ldap.NewModifyRequest(collectDatabaseOverlayDN, nil)
	whitespace.Add(
		"olcCollectInfo",
		[]string{`"ou=outside,dc=example,dc=com" "description, mail"`},
	)
	assertLDAPResultCode(t, configClient.Modify(whitespace), ldap.LDAPResultConstraintViolation)

	unknownConfig := ldap.NewModifyRequest(collectDatabaseOverlayDN, nil)
	unknownConfig.Add("olcCollectBogus", []string{"TRUE"})
	assertLDAPResultCode(t, configClient.Modify(unknownConfig), ldap.LDAPResultUndefinedAttributeType)

	validReplace := ldap.NewModifyRequest(collectDatabaseOverlayDN, nil)
	validReplace.Replace(
		"olcCollectInfo",
		[]string{`"ou=people,dc=example,dc=com" telephoneNumber`},
	)
	if err := configClient.Modify(validReplace); err != nil {
		t.Fatalf("valid collect replace: %v", err)
	}
	if got := searchCollectEntry(
		t,
		dataClient,
		collectCarolDN,
		[]string{"description", "telephoneNumber"},
		false,
		nil,
	); len(got.GetAttributeValues("description")) != 0 ||
		len(got.GetAttributeValues("telephoneNumber")) == 0 {
		t.Fatalf("valid replace response = %#v", got.Attributes)
	}

	deleteAll := ldap.NewModifyRequest(collectDatabaseOverlayDN, nil)
	deleteAll.Delete("olcCollectInfo", nil)
	if err := configClient.Modify(deleteAll); err != nil {
		t.Fatalf("delete all olcCollectInfo: %v", err)
	}
	if got := searchCollectEntry(
		t,
		dataClient,
		collectCarolDN,
		[]string{"telephoneNumber"},
		false,
		nil,
	).GetAttributeValues("telephoneNumber"); len(got) != 0 {
		t.Fatalf("projection survived delete-all: %q", got)
	}

	restore := ldap.NewModifyRequest(collectDatabaseOverlayDN, nil)
	restore.Add(
		"olcCollectInfo",
		[]string{`"ou=people,dc=example,dc=com" description`},
	)
	if err := configClient.Modify(restore); err != nil {
		t.Fatalf("restore olcCollectInfo: %v", err)
	}
	duplicateOverlay := ldap.NewAddRequest(
		"olcOverlay={1}collect,olcDatabase={1}mdb,cn=config",
		nil,
	)
	duplicateOverlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcCollectConfig"})
	duplicateOverlay.Attribute("olcOverlay", []string{"{1}collect"})
	assertLDAPResultCode(t, configClient.Add(duplicateOverlay), ldap.LDAPResultOther)

	configClient.Close()
	dataClient.Close()
	stop()
	address, stop = startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	dataClient = bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer dataClient.Close()
	if got := searchCollectEntry(
		t,
		dataClient,
		collectCarolDN,
		[]string{"description"},
		false,
		nil,
	).GetAttributeValues("description"); len(got) == 0 {
		t.Fatal("collect configuration did not survive restart")
	}
	configClient = bindConstraintClient(t, address, "cn=config", "config-secret")
	defer configClient.Close()
	if err := configClient.Del(ldap.NewDelRequest(collectDatabaseOverlayDN, nil)); err != nil {
		t.Fatalf("Delete(collect overlay): %v", err)
	}
	if got := searchCollectEntry(
		t,
		dataClient,
		collectCarolDN,
		[]string{"description"},
		false,
		nil,
	).GetAttributeValues("description"); len(got) != 0 {
		t.Fatalf("projection survived overlay delete: %q", got)
	}
}

func startCollectTestServer(
	t *testing.T,
) (storage.Store, string, *ldap.Conn, *ldap.Conn, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	configClient := bindConstraintClient(t, address, "cn=config", "config-secret")
	dataClient := bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	return store, address, configClient, dataClient, stop
}

func addCollectTestFixtures(t *testing.T, client *ldap.Conn) {
	t.Helper()
	people := ldap.NewModifyRequest(collectPeopleDN, nil)
	people.Add("objectClass", []string{"extensibleObject"})
	people.Add("description", []string{"Broad-A", "shared"})
	people.Add("telephoneNumber", []string{"+1 555 0100"})
	people.Add("l", []string{"Global"})
	if err := client.Modify(people); err != nil {
		t.Fatalf("Modify(collect people template): %v", err)
	}

	team := ldap.NewAddRequest(collectTeamDN, nil)
	team.Attribute("objectClass", []string{"organizationalUnit", "extensibleObject"})
	team.Attribute("ou", []string{"team"})
	team.Attribute("description", []string{"Specific-A", "shared"})
	team.Attribute("telephoneNumber", []string{"+1 555 0200"})
	team.Attribute("l", []string{"Local"})
	if err := client.Add(team); err != nil {
		t.Fatalf("Add(collect team template): %v", err)
	}

	bob := ldap.NewAddRequest(collectBobDN, nil)
	bob.Attribute("objectClass", []string{"inetOrgPerson"})
	bob.Attribute("uid", []string{"bob"})
	bob.Attribute("cn", []string{"Bob"})
	bob.Attribute("sn", []string{"Bob"})
	bob.Attribute("description", []string{"Local-A", "SHARED"})
	if err := client.Add(bob); err != nil {
		t.Fatalf("Add(collect Bob): %v", err)
	}
	carol := ldap.NewAddRequest(collectCarolDN, nil)
	carol.Attribute("objectClass", []string{"inetOrgPerson"})
	carol.Attribute("uid", []string{"carol"})
	carol.Attribute("cn", []string{"Carol"})
	carol.Attribute("sn", []string{"Carol"})
	if err := client.Add(carol); err != nil {
		t.Fatalf("Add(collect Carol): %v", err)
	}
	referral := ldap.NewAddRequest("ou=ref,"+collectTeamDN, nil)
	referral.Attribute("objectClass", []string{"referral", "extensibleObject"})
	referral.Attribute("ou", []string{"ref"})
	referral.Attribute("ref", []string{"ldap://127.0.0.1:9/dc=invalid"})
	if err := client.Add(referral); err != nil {
		t.Fatalf("Add(collect referral): %v", err)
	}
}

func addCollectOverlays(t *testing.T, configClient *ldap.Conn) {
	t.Helper()
	addCollectDatabaseOverlay(t, configClient)
	frontend := ldap.NewAddRequest("olcDatabase={-1}frontend,cn=config", nil)
	frontend.Attribute("objectClass", []string{"olcDatabaseConfig"})
	frontend.Attribute("olcDatabase", []string{"{-1}frontend"})
	if err := configClient.Add(frontend); err != nil {
		t.Fatalf("Add(frontend database): %v", err)
	}
	overlay := ldap.NewAddRequest(collectFrontendOverlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcCollectConfig"})
	overlay.Attribute("olcOverlay", []string{"{0}collect"})
	overlay.Attribute(
		"olcCollectInfo",
		[]string{`"ou=people,dc=example,dc=com" l`},
	)
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(frontend collect overlay): %v", err)
	}
}

func addCollectDatabaseOverlay(t *testing.T, configClient *ldap.Conn) {
	t.Helper()
	overlay := ldap.NewAddRequest(collectDatabaseOverlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcCollectConfig"})
	overlay.Attribute("olcOverlay", []string{"{0}collect"})
	overlay.Attribute("olcCollectInfo", []string{
		`"ou=people,dc=example,dc=com" description,telephoneNumber,l`,
		`"ou=team,ou=people,dc=example,dc=com" description,description,telephoneNumber,l`,
		`"ou=missing,dc=example,dc=com" mail`,
	})
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(database collect overlay): %v", err)
	}
}

func replaceCollectDataACL(t *testing.T, configClient *ldap.Conn, rules ...string) {
	t.Helper()
	request := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	request.Replace("olcAccess", rules)
	if err := configClient.Modify(request); err != nil {
		t.Fatalf("replace collect ACL: %v", err)
	}
}

func searchCollectEntry(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	attributes []string,
	typesOnly bool,
	controls []ldap.Control,
) *ldap.Entry {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		typesOnly,
		"(objectClass=*)",
		attributes,
		controls,
	))
	if err != nil {
		t.Fatalf("Search(%s): %v", dn, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search(%s) entries = %#v", dn, result.Entries)
	}
	return result.Entries[0]
}

func collectCompareResultCode(
	t *testing.T,
	client *ldap.Conn,
	dn,
	attribute,
	value string,
) uint16 {
	t.Helper()
	matched, err := client.Compare(dn, attribute, value)
	if err == nil {
		if matched {
			return ldap.LDAPResultCompareTrue
		}
		return ldap.LDAPResultCompareFalse
	}
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		t.Fatalf("Compare(%s): %v", dn, err)
	}
	return ldapErr.ResultCode
}

func collectEntryDNs(entries []*ldap.Entry) []string {
	result := make([]string, len(entries))
	for index, entry := range entries {
		result[index] = strings.ToLower(entry.DN)
	}
	return result
}

func assertCollectModifyDenied(t *testing.T, err error, attribute string) {
	t.Helper()
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) ||
		ldapErr.ResultCode != ldap.LDAPResultUnwillingToPerform ||
		!strings.Contains(ldapErr.Error(), "cannot change virtual attribute '"+attribute+"'") {
		t.Fatalf("collect Modify error = %v", err)
	}
}

func seedCollectOverlayDirect(
	t *testing.T,
	store storage.Store,
	values ...string,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: collectDatabaseOverlayDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcCollectConfig")},
				{Description: "olcOverlay", Values: stringValues("{0}collect")},
				{Description: "olcCollectInfo", Values: stringValues(values...)},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed collect overlay: %v", err)
	}
}
