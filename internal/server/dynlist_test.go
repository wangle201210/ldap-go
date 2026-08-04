package server

import (
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDynlistConfigurationParsingAndValidation(t *testing.T) {
	database := runtimeDatabase{name: "{1}mdb"}
	entry := directory.Entry{
		DN: "olcOverlay={0}dynlist,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{
				Description: "olcDlAttrSet",
				Values: stringValues(
					"{1}groupOfURLs ldap:///ou=second,dc=example,dc=com??sub?(cn=*) memberURL mail:mail",
					"{0}groupOfURLs ldap:///ou=first,dc=example,dc=com??one?(cn=Dynamic*) memberURL owner:seeAlso+dgMemberOf@groupOfNames*",
				),
			},
			{Description: "olcDynListSimple", Values: stringValues("TRUE")},
		},
	}
	configuration, err := loadDynlistRuntimeConfiguration(entry, database)
	if err != nil {
		t.Fatalf("loadDynlistRuntimeConfiguration(): %v", err)
	}
	if !configuration.simple || len(configuration.attributeSets) != 2 {
		t.Fatalf("dynlist configuration = %#v", configuration)
	}
	first := configuration.attributeSets[0]
	if first.restriction == nil ||
		first.restriction.base.String() != "ou=first,dc=example,dc=com" ||
		first.restriction.scope != directory.ScopeSingleLevel ||
		len(first.mappings) != 1 {
		t.Fatalf("ordered first dynlist attrset = %#v", first)
	}
	mapping := first.mappings[0]
	if mapping.mappedAttribute != "owner" ||
		mapping.memberAttribute != "seeAlso" ||
		mapping.memberOfAttribute != "dgMemberOf" ||
		mapping.staticObjectClass != "groupOfNames" ||
		!mapping.nested {
		t.Fatalf("dynlist mapping = %#v", mapping)
	}
	if second := configuration.attributeSets[1]; second.restriction == nil ||
		second.restriction.base.String() != "ou=second,dc=example,dc=com" {
		t.Fatalf("ordered second dynlist attrset = %#v", second)
	}

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if err := validateDynlistSchema(registry, &configuration); err != nil {
		t.Fatalf("validateDynlistSchema(): %v", err)
	}

	defaultConfiguration, err := loadDynlistRuntimeConfiguration(
		directory.Entry{DN: entry.DN},
		database,
	)
	if err != nil || len(defaultConfiguration.attributeSets) != 1 ||
		defaultConfiguration.attributeSets[0].objectClass != "groupOfURLs" ||
		defaultConfiguration.attributeSets[0].urlAttribute != "memberURL" {
		t.Fatalf("default dynlist configuration = %#v, %v", defaultConfiguration, err)
	}

	dynamicGroup, err := loadDynamicGroupRuntimeConfiguration(
		directory.Entry{
			DN: "olcOverlay={1}dyngroup,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{{
				Description: "olcDGAttrPair",
				Values:      stringValues("member memberURL", "uniqueMember memberURL"),
			}},
		},
		database,
	)
	if err != nil || len(dynamicGroup.pairs) != 2 {
		t.Fatalf("legacy dyngroup aliases = %#v, %v", dynamicGroup, err)
	}
	if err := validateDynamicGroupSchema(registry, &dynamicGroup); err != nil {
		t.Fatalf("validateDynamicGroupSchema(): %v", err)
	}

	for _, test := range []struct {
		name      string
		arguments []string
	}{
		{name: "missing URL attribute", arguments: []string{"groupOfURLs"}},
		{
			name: "restriction host",
			arguments: []string{
				"groupOfURLs",
				"ldap://directory.example/dc=example,dc=com??sub",
				"memberURL",
			},
		},
		{
			name: "restriction attributes",
			arguments: []string{
				"groupOfURLs",
				"ldap:///dc=example,dc=com?cn?sub",
				"memberURL",
			},
		},
		{
			name: "restriction extensions",
			arguments: []string{
				"groupOfURLs",
				"ldap:///dc=example,dc=com??sub??x-test=1",
				"memberURL",
			},
		},
		{
			name:      "empty memberOf",
			arguments: []string{"groupOfURLs", "memberURL", "member+"},
		},
		{
			name:      "empty static class",
			arguments: []string{"groupOfURLs", "memberURL", "member+dgMemberOf@"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseDynlistAttributeSet(test.arguments); err == nil {
				t.Fatalf("parseDynlistAttributeSet(%q) unexpectedly succeeded", test.arguments)
			}
		})
	}

	invalidSchema := configuration
	invalidSchema.attributeSets = append(
		[]dynlistAttributeSet(nil),
		configuration.attributeSets...,
	)
	invalidSchema.attributeSets[0].urlAttribute = "mail"
	if err := validateDynlistSchema(registry, &invalidSchema); err == nil {
		t.Fatal("non-labeledURI dynlist URL attribute unexpectedly validated")
	}
	if _, err := loadDynlistRuntimeConfiguration(
		entry,
		runtimeDatabase{name: "{-1}frontend"},
	); err == nil {
		t.Fatal("global dynlist overlay unexpectedly loaded")
	}

	for _, test := range []struct {
		scope string
		want  directory.Scope
	}{
		{scope: "one", want: directory.ScopeSingleLevel},
		{scope: "onelevel", want: directory.ScopeSingleLevel},
		{scope: "sub", want: directory.ScopeWholeSubtree},
		{scope: "subtree", want: directory.ScopeWholeSubtree},
		{scope: "children", want: directory.ScopeChildren},
		{scope: "subord", want: directory.ScopeChildren},
		{scope: "subordinate", want: directory.ScopeChildren},
	} {
		parsed, err := parseDynlistLDAPURL(
			"ldaps:///dc=example,dc=com??" + test.scope + "?(objectClass=*)",
		)
		if err != nil || parsed.scope != test.want {
			t.Errorf(
				"parseDynlistLDAPURL(scope=%s) = %#v, %v",
				test.scope,
				parsed,
				err,
			)
		}
	}
	if _, err := parseDynlistLDAPURL(
		"ldap:///dc=example,dc=com??sub?(objectClass=*)?",
	); err == nil {
		t.Fatal("LDAP URL with an empty extension unexpectedly parsed")
	}
}

func TestDynlistExpansionIdentityAndAuthorization(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	configClient := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer configClient.Close()
	root := bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer root.Close()
	addDynlistFixtures(t, root)
	bobPassword := ldap.NewModifyRequest(testDynlistBobDN, nil)
	bobPassword.Add("userPassword", []string{"bob-secret"})
	if err := root.Modify(bobPassword); err != nil {
		t.Fatalf("Modify(Bob password): %v", err)
	}
	memberURL := ldap.NewModifyRequest(testDynlistGroupDN, nil)
	memberURL.Replace(
		"memberURL",
		[]string{
			"ldap:///ou=people,dc=example,dc=com??sub?" +
				"(objectClass=inetOrgPerson)",
		},
	)
	if err := root.Modify(memberURL); err != nil {
		t.Fatalf("Modify(memberURL): %v", err)
	}

	overlay := ldap.NewAddRequest(testDynlistOverlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig"})
	overlay.Attribute("olcOverlay", []string{"{0}dynlist"})
	overlay.Attribute(
		"olcDynListAttrSet",
		[]string{"groupOfURLs memberURL member"},
	)
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(dynlist overlay): %v", err)
	}
	access := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	access.Replace("olcAccess", []string{
		"{0}to attrs=userPassword by self write by anonymous auth by * none",
		"{1}to dn.base=\"" + testDynlistGroupDN + "\" by * read",
		"{2}to * by users read by * search",
	})
	if err := configClient.Modify(access); err != nil {
		t.Fatalf("Modify(dynlist ACL): %v", err)
	}

	anonymous, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(anonymous): %v", err)
	}
	defer anonymous.Close()
	group := searchDynlistEntry(
		t,
		anonymous,
		testDynlistGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"member"},
		nil,
	)
	if values := group.GetAttributeValues("member"); len(values) != 0 {
		t.Fatalf("anonymous members without dgIdentity = %q", values)
	}

	identity := ldap.NewModifyRequest(testDynlistGroupDN, nil)
	identity.Add("objectClass", []string{"dgIdentityAux"})
	identity.Add("dgIdentity", []string{testDynlistAliceDN})
	if err := root.Modify(identity); err != nil {
		t.Fatalf("Modify(dgIdentity): %v", err)
	}
	group = searchDynlistEntry(
		t,
		anonymous,
		testDynlistGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"member"},
		nil,
	)
	assertDynlistValues(
		t,
		group.GetAttributeValues("member"),
		[]string{testDynlistAliceDN, testDynlistBobDN},
	)

	authorization := ldap.NewModifyRequest(testDynlistGroupDN, nil)
	authorization.Add("dgAuthz", []string{"dn:" + testDynlistBobDN})
	if err := root.Modify(authorization); err != nil {
		t.Fatalf("Modify(dgAuthz): %v", err)
	}
	group = searchDynlistEntry(
		t,
		anonymous,
		testDynlistGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"member"},
		nil,
	)
	if values := group.GetAttributeValues("member"); len(values) != 0 {
		t.Fatalf("unauthorized anonymous members = %q", values)
	}
	if code := overlayCompareResultCode(
		t,
		anonymous,
		testDynlistGroupDN,
		"member",
		testDynlistAliceDN,
	); code != ldap.LDAPResultInappropriateAuthentication {
		t.Fatalf("unauthorized anonymous Compare result = %d", code)
	}
	bob := bindConstraintClient(t, address, testDynlistBobDN, "bob-secret")
	defer bob.Close()
	group = searchDynlistEntry(
		t,
		bob,
		testDynlistGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"member"},
		nil,
	)
	assertDynlistValues(
		t,
		group.GetAttributeValues("member"),
		[]string{testDynlistAliceDN, testDynlistBobDN},
	)
	if code := overlayCompareResultCode(
		t,
		bob,
		testDynlistGroupDN,
		"member",
		testDynlistAliceDN,
	); code != ldap.LDAPResultCompareTrue {
		t.Fatalf("authorized Bob Compare result = %d", code)
	}
}

const (
	testDynlistOverlayDN = "olcOverlay={0}dynlist,olcDatabase={1}mdb,cn=config"
	testDynlistGroupDN   = "cn=Dynamic Group,ou=groups,dc=example,dc=com"
	testDynlistAliceDN   = "uid=alice,ou=people,dc=example,dc=com"
	testDynlistBobDN     = "uid=bob,ou=people,dc=example,dc=com"
)

func TestDynlistOverlayLifecycleAndSearchProjection(t *testing.T) {
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
	addDynlistFixtures(t, dataClient)

	overlay := ldap.NewAddRequest(testDynlistOverlayDN, nil)
	overlay.Attribute(
		"objectClass",
		[]string{"olcOverlayConfig", "olcDynListConfig"},
	)
	overlay.Attribute("olcOverlay", []string{"{0}dynlist"})
	overlay.Attribute(
		"olcDynListAttrSet",
		[]string{"{0}groupOfURLs memberURL mail:mail"},
	)
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(dynlist overlay): %v", err)
	}

	projected := searchDynlistEntry(
		t,
		dataClient,
		testDynlistGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"mail", "memberURL"},
		nil,
	)
	assertDynlistValues(
		t,
		projected.GetAttributeValues("mail"),
		[]string{"alice@example.com", "bob@example.com"},
	)

	filtered := searchDynlist(
		t,
		dataClient,
		"ou=groups,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(mail=alice@example.com)",
		[]string{"cn"},
		nil,
	)
	if len(filtered.Entries) != 1 ||
		filtered.Entries[0].DN != testDynlistGroupDN {
		t.Fatalf("dynamic-attribute filter entries = %#v", filtered.Entries)
	}

	matched, err := dataClient.Compare(
		testDynlistGroupDN,
		"mail",
		"alice@example.com",
	)
	if err != nil || !matched {
		t.Fatalf("Compare(dynamic mail) = %v, %v", matched, err)
	}
	matched, err = dataClient.Compare(
		testDynlistGroupDN,
		"mail",
		"nobody@example.com",
	)
	if err != nil || matched {
		t.Fatalf("Compare(missing dynamic mail) = %v, %v", matched, err)
	}

	managed := searchDynlistEntry(
		t,
		dataClient,
		testDynlistGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"mail", "memberURL"},
		[]ldap.Control{ldap.NewControlManageDsaIT(true)},
	)
	if values := managed.GetAttributeValues("mail"); len(values) != 0 {
		t.Fatalf("ManageDsaIT dynamic mail = %q", values)
	}
	if values := managed.GetAttributeValues("memberURL"); len(values) != 1 {
		t.Fatalf("ManageDsaIT memberURL = %q", values)
	}

	memberConfiguration := ldap.NewModifyRequest(testDynlistOverlayDN, nil)
	memberConfiguration.Replace(
		"olcDynListAttrSet",
		[]string{"{0}groupOfURLs memberURL member+dgMemberOf"},
	)
	if err := configClient.Modify(memberConfiguration); err != nil {
		t.Fatalf("Modify(dynlist member configuration): %v", err)
	}
	memberURL := ldap.NewModifyRequest(testDynlistGroupDN, nil)
	memberURL.Replace(
		"memberURL",
		[]string{
			"ldap:///ou=people,dc=example,dc=com??sub?" +
				"(objectClass=inetOrgPerson)",
		},
	)
	if err := dataClient.Modify(memberURL); err != nil {
		t.Fatalf("Modify(memberURL): %v", err)
	}

	members := searchDynlistEntry(
		t,
		dataClient,
		testDynlistGroupDN,
		ldap.ScopeBaseObject,
		"(member="+ldap.EscapeFilter(testDynlistAliceDN)+")",
		[]string{"member"},
		nil,
	)
	assertDynlistValues(
		t,
		members.GetAttributeValues("member"),
		[]string{testDynlistAliceDN, testDynlistBobDN},
	)
	alice := searchDynlistEntry(
		t,
		dataClient,
		testDynlistAliceDN,
		ldap.ScopeBaseObject,
		"(dgMemberOf="+ldap.EscapeFilter(testDynlistGroupDN)+")",
		[]string{"dgMemberOf"},
		nil,
	)
	assertDynlistValues(
		t,
		alice.GetAttributeValues("dgMemberOf"),
		[]string{testDynlistGroupDN},
	)

	invalid := ldap.NewModifyRequest(testDynlistOverlayDN, nil)
	invalid.Replace(
		"olcDynListAttrSet",
		[]string{"groupOfURLs memberURL undefinedDynlistAttribute:mail"},
	)
	assertLDAPResultCode(
		t,
		configClient.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	_ = searchDynlistEntry(
		t,
		dataClient,
		testDynlistAliceDN,
		ldap.ScopeBaseObject,
		"(dgMemberOf="+ldap.EscapeFilter(testDynlistGroupDN)+")",
		[]string{"dgMemberOf"},
		nil,
	)

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
	_ = searchDynlistEntry(
		t,
		dataClient,
		testDynlistAliceDN,
		ldap.ScopeBaseObject,
		"(dgMemberOf="+ldap.EscapeFilter(testDynlistGroupDN)+")",
		[]string{"dgMemberOf"},
		nil,
	)
}

func TestDynlistUnmappedAttributesAreOutputOnly(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
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
	addDynlistFixtures(t, dataClient)

	overlay := ldap.NewAddRequest(testDynlistOverlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcDynListConfig"})
	overlay.Attribute("olcOverlay", []string{"{0}dynlist"})
	overlay.Attribute("olcDynListAttrSet", []string{"groupOfURLs memberURL"})
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(unmapped dynlist overlay): %v", err)
	}

	projected := searchDynlistEntry(
		t,
		dataClient,
		testDynlistGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"mail"},
		nil,
	)
	assertDynlistValues(
		t,
		projected.GetAttributeValues("mail"),
		[]string{"alice@example.com", "bob@example.com"},
	)
	filtered := searchDynlist(
		t,
		dataClient,
		"ou=groups,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(mail=alice@example.com)",
		[]string{"cn"},
		nil,
	)
	if len(filtered.Entries) != 0 {
		t.Fatalf("unmapped dynamic-attribute filter entries = %#v", filtered.Entries)
	}
	matched, err := dataClient.Compare(
		testDynlistGroupDN,
		"mail",
		"alice@example.com",
	)
	if err != nil || !matched {
		t.Fatalf("Compare(unmapped dynamic mail) = %v, %v", matched, err)
	}

	mapped := ldap.NewModifyRequest(testDynlistOverlayDN, nil)
	mapped.Replace(
		"olcDynListAttrSet",
		[]string{"groupOfURLs memberURL mail:mail"},
	)
	if err := configClient.Modify(mapped); err != nil {
		t.Fatalf("Modify(self-mapped dynlist overlay): %v", err)
	}
	filtered = searchDynlist(
		t,
		dataClient,
		"ou=groups,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(mail=alice@example.com)",
		[]string{"cn"},
		nil,
	)
	if len(filtered.Entries) != 1 || filtered.Entries[0].DN != testDynlistGroupDN {
		t.Fatalf("self-mapped dynamic-attribute filter entries = %#v", filtered.Entries)
	}
	empty := ldap.NewModifyRequest(testDynlistGroupDN, nil)
	empty.Replace(
		"memberURL",
		[]string{
			"ldap:///ou=people,dc=example,dc=com?mail?sub?(uid=missing)",
		},
	)
	if err := dataClient.Modify(empty); err != nil {
		t.Fatalf("Modify(empty mapped memberURL): %v", err)
	}
	if code := overlayCompareResultCode(
		t,
		dataClient,
		testDynlistGroupDN,
		"mail",
		"missing@example.com",
	); code != ldap.LDAPResultNoSuchAttribute {
		t.Fatalf("empty mapped Compare result = %d, want noSuchAttribute", code)
	}
}

func TestDynlistURLMetadataMembershipSemantics(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
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
	addDynlistURLMetadataReferenceFixtures(t, dataClient)
	addDynlistReferenceOverlay(
		t,
		configClient,
		"groupOfURLs memberURL member+dgMemberOf*",
		false,
	)

	outcome := runDynlistURLMetadataReferenceScenario(t, dataClient)
	if len(outcome.values) != 0 ||
		!slices.Equal(outcome.managed, []string{testDynlistBobDN}) ||
		len(outcome.memberOf) != 0 ||
		!slices.Equal(outcome.compares, []bool{false, false}) {
		t.Fatalf("dynlist URL metadata outcome = %#v", outcome)
	}
}

func TestDynlistMappedDNFilterCompareAndMemberOfSemantics(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
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
	addMappedDNDynlistReferenceFixtures(t, dataClient)
	addDynlistReferenceOverlay(
		t,
		configClient,
		"groupOfURLs memberURL member:seeAlso+dgMemberOf",
		false,
	)

	outcome := runMappedDNDynlistReferenceScenario(t, dataClient)
	want := dynlistReferenceOutcome{
		values: []string{testDynlistBobDN},
		filtered: []string{
			"alice=",
			"bob=" + testDynlistGroupDN,
		},
		memberOf: []string{
			"alice=" + testDynlistGroupDN,
			"bob=",
		},
		compares: []bool{false, true},
	}
	if !slices.Equal(outcome.values, want.values) ||
		!slices.Equal(outcome.filtered, want.filtered) ||
		!slices.Equal(outcome.memberOf, want.memberOf) ||
		!slices.Equal(outcome.compares, want.compares) {
		t.Fatalf("mapped DN dynlist outcome = %#v, want %#v", outcome, want)
	}
}

func TestDynlistSortedPagingPreservesManageDsaIT(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
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
	addDynlistFixtures(t, dataClient)
	addDynlistReferenceOverlay(
		t,
		configClient,
		"groupOfURLs memberURL mail:mail",
		false,
	)
	sssVLV := ldap.NewAddRequest(
		"olcOverlay={1}sssvlv,olcDatabase={1}mdb,cn=config",
		nil,
	)
	sssVLV.Attribute("objectClass", []string{"olcOverlayConfig"})
	sssVLV.Attribute("olcOverlay", []string{"{1}sssvlv"})
	if err := configClient.Add(sssVLV); err != nil {
		t.Fatalf("Add(sssvlv overlay): %v", err)
	}

	paging := ldap.NewControlPaging(1)
	request := ldap.NewSearchRequest(
		"ou=groups,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn", "mail", "memberURL"},
		[]ldap.Control{
			newSortControl(ldap.SortKey{
				AttributeType: "cn",
				MatchingRule:  "caseIgnoreOrderingMatch",
			}),
			ldap.NewControlManageDsaIT(true),
			paging,
		},
	)
	var entries []*ldap.Entry
	for {
		page, err := dataClient.Search(request)
		if err != nil {
			t.Fatalf("Search(sorted paged ManageDsaIT): %v", err)
		}
		entries = append(entries, page.Entries...)
		response := pagedResponseControl(t, page)
		if len(response.Cookie) == 0 {
			break
		}
		paging.SetCookie(response.Cookie)
	}
	if len(entries) != 2 {
		t.Fatalf("sorted paged entries = %#v", entries)
	}
	for _, entry := range entries {
		if values := entry.GetAttributeValues("mail"); len(values) != 0 {
			t.Fatalf("ManageDsaIT %s dynamic mail = %q", entry.DN, values)
		}
	}
}

func TestDynlistPagedDynamicFilterMatchesOpenLDAP(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
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
	addDynlistFixtures(t, dataClient)
	addDynlistReferenceOverlay(
		t,
		configClient,
		"groupOfURLs memberURL mail:mail",
		false,
	)

	result := searchDynlist(
		t,
		dataClient,
		"ou=groups,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(mail=alice@example.com)",
		[]string{"cn"},
		[]ldap.Control{ldap.NewControlPaging(1)},
	)
	if len(result.Entries) != 0 {
		t.Fatalf("paged dynamic filter entries = %#v", result.Entries)
	}
	withoutPaging := searchDynlist(
		t,
		dataClient,
		"ou=groups,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(mail=alice@example.com)",
		[]string{"cn"},
		nil,
	)
	if len(withoutPaging.Entries) != 1 ||
		withoutPaging.Entries[0].DN != testDynlistGroupDN {
		t.Fatalf("non-paged dynamic filter entries = %#v", withoutPaging.Entries)
	}
}

func TestDynlistNestedStaticGroupsAndSimpleMode(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
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
	addDynlistFixtures(t, dataClient)

	childDN := "cn=Static Child,ou=groups,dc=example,dc=com"
	child := ldap.NewAddRequest(childDN, nil)
	child.Attribute("objectClass", []string{"groupOfNames"})
	child.Attribute("cn", []string{"Static Child"})
	child.Attribute("member", []string{testDynlistAliceDN})
	if err := dataClient.Add(child); err != nil {
		t.Fatalf("Add(static child): %v", err)
	}
	parentDN := "cn=Nested Parent,ou=groups,dc=example,dc=com"
	parent := ldap.NewAddRequest(parentDN, nil)
	parent.Attribute("objectClass", []string{"groupOfURLs"})
	parent.Attribute("cn", []string{"Nested Parent"})
	parent.Attribute(
		"memberURL",
		[]string{
			"ldap:///ou=groups,dc=example,dc=com??sub?" +
				"(cn=Static Child)",
		},
	)
	if err := dataClient.Add(parent); err != nil {
		t.Fatalf("Add(nested parent): %v", err)
	}

	overlay := ldap.NewAddRequest(testDynlistOverlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig"})
	overlay.Attribute("olcOverlay", []string{"{0}dynlist"})
	overlay.Attribute(
		"olcDynListAttrSet",
		[]string{
			"groupOfURLs memberURL member+dgMemberOf@groupOfNames*",
		},
	)
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(nested dynlist overlay): %v", err)
	}

	parentEntry := searchDynlistEntry(
		t,
		dataClient,
		parentDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"member", "dgMemberOf"},
		nil,
	)
	assertDynlistValues(
		t,
		parentEntry.GetAttributeValues("member"),
		[]string{childDN, testDynlistAliceDN},
	)
	filteredNested := searchDynlist(
		t,
		dataClient,
		"ou=groups,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(member="+ldap.EscapeFilter(testDynlistAliceDN)+")",
		[]string{"cn"},
		nil,
	)
	if len(filteredNested.Entries) != 1 || filteredNested.Entries[0].DN != childDN {
		t.Fatalf("nested member filter entries = %#v", filteredNested.Entries)
	}
	alice := searchDynlistEntry(
		t,
		dataClient,
		testDynlistAliceDN,
		ldap.ScopeBaseObject,
		"(objectClass=inetOrgPerson)",
		[]string{"dgMemberOf"},
		nil,
	)
	assertDynlistValues(
		t,
		alice.GetAttributeValues("dgMemberOf"),
		[]string{childDN, parentDN},
	)

	simple := ldap.NewModifyRequest(testDynlistOverlayDN, nil)
	simple.Replace("olcDynListSimple", []string{"TRUE"})
	if err := configClient.Modify(simple); err != nil {
		t.Fatalf("Modify(olcDynListSimple): %v", err)
	}
	filtered := searchDynlist(
		t,
		dataClient,
		"ou=groups,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(member="+ldap.EscapeFilter(testDynlistAliceDN)+")",
		[]string{"cn"},
		nil,
	)
	if len(filtered.Entries) != 1 || filtered.Entries[0].DN != childDN {
		t.Fatalf("simple dynamic-member filter entries = %#v", filtered.Entries)
	}
	parentEntry = searchDynlistEntry(
		t,
		dataClient,
		parentDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"member"},
		nil,
	)
	assertDynlistValues(
		t,
		parentEntry.GetAttributeValues("member"),
		[]string{childDN},
	)
}

func TestLegacyDynamicGroupOverlayCompareOnly(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
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
	addDynlistFixtures(t, dataClient)

	overlayDN := "olcOverlay={0}dyngroup,olcDatabase={1}mdb,cn=config"
	overlay := ldap.NewAddRequest(overlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcDynGroupConfig"})
	overlay.Attribute("olcOverlay", []string{"{0}dyngroup"})
	overlay.Attribute("olcDynGroupAttrPair", []string{"member memberURL"})
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(dyngroup overlay): %v", err)
	}
	memberURL := ldap.NewModifyRequest(testDynlistGroupDN, nil)
	memberURL.Replace(
		"memberURL",
		[]string{
			"ldap:///ou=people,dc=example,dc=com??sub?" +
				"(objectClass=inetOrgPerson)",
		},
	)
	if err := dataClient.Modify(memberURL); err != nil {
		t.Fatalf("Modify(dyngroup memberURL): %v", err)
	}

	matched, err := dataClient.Compare(
		testDynlistGroupDN,
		"member",
		testDynlistAliceDN,
	)
	if err != nil || !matched {
		t.Fatalf("dyngroup Compare(member) = %v, %v", matched, err)
	}
	entry := searchDynlistEntry(
		t,
		dataClient,
		testDynlistGroupDN,
		ldap.ScopeBaseObject,
		"(objectClass=groupOfURLs)",
		[]string{"member", "memberURL"},
		nil,
	)
	if values := entry.GetAttributeValues("member"); len(values) != 0 {
		t.Fatalf("dyngroup projected Search member = %q", values)
	}
}

func addDynlistFixtures(t *testing.T, client *ldap.Conn) {
	t.Helper()
	aliceMail := ldap.NewModifyRequest(testDynlistAliceDN, nil)
	aliceMail.Add("mail", []string{"alice@example.com"})
	if err := client.Modify(aliceMail); err != nil {
		t.Fatalf("Modify(Alice mail): %v", err)
	}
	bob := ldap.NewAddRequest(testDynlistBobDN, nil)
	bob.Attribute("objectClass", []string{"inetOrgPerson"})
	bob.Attribute("uid", []string{"bob"})
	bob.Attribute("cn", []string{"Bob Example"})
	bob.Attribute("sn", []string{"Example"})
	bob.Attribute("mail", []string{"bob@example.com"})
	if err := client.Add(bob); err != nil {
		t.Fatalf("Add(Bob): %v", err)
	}
	groups := ldap.NewAddRequest("ou=groups,dc=example,dc=com", nil)
	groups.Attribute("objectClass", []string{"organizationalUnit"})
	groups.Attribute("ou", []string{"groups"})
	if err := client.Add(groups); err != nil {
		t.Fatalf("Add(groups OU): %v", err)
	}
	group := ldap.NewAddRequest(testDynlistGroupDN, nil)
	group.Attribute("objectClass", []string{"groupOfURLs"})
	group.Attribute("cn", []string{"Dynamic Group"})
	group.Attribute(
		"memberURL",
		[]string{
			"ldap:///ou=people,dc=example,dc=com?mail?sub?" +
				"(objectClass=inetOrgPerson)",
		},
	)
	if err := client.Add(group); err != nil {
		t.Fatalf("Add(dynamic group): %v", err)
	}
}

func searchDynlistEntry(
	t *testing.T,
	client *ldap.Conn,
	base string,
	scope int,
	filter string,
	attributes []string,
	controls []ldap.Control,
) *ldap.Entry {
	t.Helper()
	result := searchDynlist(t, client, base, scope, filter, attributes, controls)
	if len(result.Entries) != 1 {
		t.Fatalf("Search(%s, %s) returned %d entries", base, filter, len(result.Entries))
	}
	return result.Entries[0]
}

func searchDynlist(
	t *testing.T,
	client *ldap.Conn,
	base string,
	scope int,
	filter string,
	attributes []string,
	controls []ldap.Control,
) *ldap.SearchResult {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		base,
		scope,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		controls,
	))
	if err != nil {
		t.Fatalf("Search(%s, %s): %v", base, filter, err)
	}
	return result
}

func assertDynlistValues(t *testing.T, got, want []string) {
	t.Helper()
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("dynlist values = %q, want %q", got, want)
	}
}
