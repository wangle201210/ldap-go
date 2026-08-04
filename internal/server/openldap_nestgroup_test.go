package server

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPNestGroupVersion = "2.6.13"
	openLDAPNestGroupCommit  = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

	nestGroupPeopleDN = "ou=people,dc=example,dc=com"
	nestGroupGroupsDN = "ou=groups,dc=example,dc=com"
	nestGroupCoreDN   = "ou=core," + nestGroupGroupsDN
	nestGroupEdgesDN  = "ou=edges," + nestGroupGroupsDN
	nestGroupACLDN    = "ou=acl," + nestGroupGroupsDN

	nestGroupAliceDN  = "uid=alice," + nestGroupPeopleDN
	nestGroupBobDN    = "uid=bob," + nestGroupPeopleDN
	nestGroupCarolDN  = "uid=carol," + nestGroupPeopleDN
	nestGroupDeltaDN  = "uid=delta," + nestGroupPeopleDN
	nestGroupHiddenDN = "uid=hidden," + nestGroupPeopleDN
	nestGroupViewerDN = "uid=viewer," + nestGroupPeopleDN
	nestGroupLimitDN  = "uid=limited," + nestGroupPeopleDN

	nestGroupLeafADN = "cn=leaf-a," + nestGroupCoreDN
	nestGroupLeafBDN = "cn=leaf-b," + nestGroupCoreDN
	nestGroupMidDN   = "cn=mid," + nestGroupCoreDN
	nestGroupTopDN   = "cn=top," + nestGroupCoreDN
)

type nestGroupCoreOutcome struct {
	topMembers             []string
	aliceMemberOf          []string
	memberFilter           []string
	memberOfFilter         []string
	requested              []string
	filterCases            []string
	compareCodes           []uint16
	edges                  []string
	acl                    []string
	paged                  []string
	pagedPages             int
	sorted                 []string
	sortedPages            int
	limitedResultCodes     []uint16
	limitedResultCounts    []int
	manageDSAITMembers     []string
	manageDSAITFilterCount int
}

type nestGroupLDAPGoConfigurationOutcome struct {
	nestGroup uint16
	access    uint16
	limits    uint16
}

func TestOpenLDAPReferenceNestGroupFixture(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	assertPinnedOpenLDAPNestGroupReference(t)

	t.Run("defaults graph filters ACL and controls", func(t *testing.T) {
		uri, stop := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{
				nestGroupMemberOfOverlay("member", "memberOf", "groupOfNames"),
				"sssvlv\nsssvlv-max 8\nsssvlv-maxperconn 8",
				nestGroupStaticOverlay(
					"",
					"",
					[]string{nestGroupGroupsDN},
					nestGroupAllFlags(),
				),
			},
			"",
			nestGroupReferenceDatabaseConfig(),
			"",
		)
		defer stop()

		root := bindOverlayReferenceClient(t, uri, "secret")
		defer root.Close()
		addNestGroupReferenceEntries(t, root)
		outcome := observeNestGroupCore(t, root, uri)
		assertOpenLDAPNestGroupCore(t, outcome)
	})

	t.Run("custom attributes and reverse overlay order", func(t *testing.T) {
		schemaPath := writeNestGroupCustomSchema(t)
		uri, stop := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{
				nestGroupStaticOverlay(
					"xMember",
					"xMemberOf",
					[]string{nestGroupGroupsDN},
					nestGroupAllFlags(),
				),
				nestGroupMemberOfOverlay("xMember", "xMemberOf", "xGroup"),
				"sssvlv\nsssvlv-max 8\nsssvlv-maxperconn 8",
			},
			"include "+schemaPath,
			"",
			"",
		)
		defer stop()
		client := bindOverlayReferenceClient(t, uri, "secret")
		defer client.Close()
		addOpenLDAPNestGroupCustomEntries(t, client)
		assertOpenLDAPNestGroupCustom(t, client)
	})

	t.Run("frontend database and multiple instances", func(t *testing.T) {
		assertOpenLDAPNestGroupPlacements(t, tools)
	})

	t.Run("online lifecycle and restart", func(t *testing.T) {
		assertOpenLDAPNestGroupOnlineLifecycle(t, tools)
	})

	t.Run("slapd.conf conversion drops custom attributes", func(t *testing.T) {
		assertOpenLDAPNestGroupConversionBug(t, tools)
	})
}

func TestOpenLDAPReferenceNestGroupDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	assertPinnedOpenLDAPNestGroupReference(t)

	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{
			nestGroupMemberOfOverlay("member", "memberOf", "groupOfNames"),
			"sssvlv\nsssvlv-max 8\nsssvlv-maxperconn 8",
			nestGroupStaticOverlay(
				"",
				"",
				[]string{nestGroupGroupsDN},
				nestGroupAllFlags(),
			),
		},
		"",
		nestGroupReferenceDatabaseConfig(),
		"",
	)
	defer stopOpenLDAP()
	openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
	defer openLDAP.Close()
	addNestGroupReferenceEntries(t, openLDAP)
	openLDAPOutcome := observeNestGroupCore(t, openLDAP, openLDAPURI)
	assertOpenLDAPNestGroupCore(t, openLDAPOutcome)

	ldapGo, ldapGoConfig, ldapGoURI, stopLDAPGo := startNestGroupReferenceLDAPGo(t)
	defer stopLDAPGo()
	defer ldapGo.Close()
	defer ldapGoConfig.Close()
	configurationOutcome := addLDAPGoNestGroupOverlay(t, ldapGoConfig)
	addNestGroupReferenceEntries(t, ldapGo)
	ldapGoOutcome := observeNestGroupCore(t, ldapGo, ldapGoURI)
	wantConfiguration := nestGroupLDAPGoConfigurationOutcome{}
	if configurationOutcome != wantConfiguration ||
		!reflect.DeepEqual(openLDAPOutcome, ldapGoOutcome) {
		t.Fatalf(
			"nestgroup mismatch (ldap-go configuration=%#v, want=%#v)\nOpenLDAP: %#v\nldap-go:  %#v",
			configurationOutcome,
			wantConfiguration,
			openLDAPOutcome,
			ldapGoOutcome,
		)
	}
}

func assertPinnedOpenLDAPNestGroupReference(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" {
		t.Fatal("nestgroup differential test requires a verified OpenLDAP reference build")
	}
	if got := os.Getenv("OPENLDAP_ACTUAL_VERSION"); got != openLDAPNestGroupVersion {
		t.Fatalf("OpenLDAP reference version = %q, want %q", got, openLDAPNestGroupVersion)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPNestGroupCommit {
		t.Fatalf("OpenLDAP reference commit = %q, want %q", got, openLDAPNestGroupCommit)
	}
	source := filepath.Join(
		os.Getenv("OPENLDAP_SOURCE"),
		"servers",
		"slapd",
		"overlays",
		"nestgroup.c",
	)
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read pinned nestgroup.c: %v", err)
	}
	for _, expected := range []string{
		"nestgroup_searchresp",
		"nestgroup_memberFilter",
		"nestgroup_memberOfFilter",
		"overlay_entry_get_ov",
		"member-values",
		"memberof-filter",
		"/*\tnestgroup.on_bi.bi_op_compare = nestgroup_op_compare; */",
	} {
		if !bytes.Contains(contents, []byte(expected)) {
			t.Fatalf("pinned nestgroup.c lacks %q", expected)
		}
	}
}

func nestGroupAllFlags() []string {
	return []string{
		"member-values",
		"member-filter",
		"memberof-values",
		"memberof-filter",
	}
}

func nestGroupStaticOverlay(
	member,
	memberOf string,
	bases,
	flags []string,
) string {
	lines := []string{"nestgroup"}
	if member != "" {
		lines = append(lines, "nestgroup-member "+member)
	}
	if memberOf != "" {
		lines = append(lines, "nestgroup-memberof "+memberOf)
	}
	for _, base := range bases {
		lines = append(lines, `nestgroup-base "`+base+`"`)
	}
	for _, flag := range flags {
		lines = append(lines, "nestgroup-flags "+flag)
	}
	return strings.Join(lines, "\n")
}

func nestGroupMemberOfOverlay(member, memberOf, groupClass string) string {
	return "memberof\n" +
		"memberof-group-oc " + groupClass + "\n" +
		"memberof-member-ad " + member + "\n" +
		"memberof-memberof-ad " + memberOf + "\n" +
		"memberof-addcheck TRUE"
}

func nestGroupReferenceDatabaseConfig() string {
	return strings.Join([]string{
		`limits dn.exact="` + nestGroupLimitDN + `" size.soft=2 size.hard=2`,
		`access to dn.exact="cn=secret-leaf,` + nestGroupACLDN + `" attrs=member`,
		`  by dn.exact="` + nestGroupViewerDN + `" none`,
		`  by * read`,
		`access to dn.exact="cn=acl-top,` + nestGroupACLDN + `" attrs=member`,
		`  by dn.exact="` + nestGroupViewerDN + `" none`,
		`  by * read`,
		`access to attrs=userPassword by self write by anonymous auth by * none`,
		`access to * by * read`,
	}, "\n")
}

func observeNestGroupCore(
	t *testing.T,
	root *ldap.Conn,
	uri string,
) nestGroupCoreOutcome {
	t.Helper()
	var outcome nestGroupCoreOutcome
	outcome.topMembers = nestGroupEntryValues(
		t,
		root,
		nestGroupTopDN,
		"(objectClass=*)",
		[]string{"member"},
		false,
		nil,
		"member",
	)
	outcome.aliceMemberOf = nestGroupEntryValues(
		t,
		root,
		nestGroupAliceDN,
		"(objectClass=*)",
		[]string{"memberOf"},
		false,
		nil,
		"memberOf",
	)
	outcome.memberFilter = nestGroupSearchDNs(
		t,
		root,
		nestGroupCoreDN,
		ldap.ScopeWholeSubtree,
		"(member="+ldap.EscapeFilter(nestGroupAliceDN)+")",
		[]string{"cn"},
		false,
		0,
		nil,
	)
	outcome.memberOfFilter = nestGroupSearchDNs(
		t,
		root,
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(memberOf="+ldap.EscapeFilter(nestGroupTopDN)+")",
		[]string{"cn"},
		false,
		0,
		nil,
	)
	outcome.requested = observeNestGroupRequestedAttributes(t, root)
	outcome.filterCases = observeNestGroupFilterCases(t, root)
	outcome.compareCodes = []uint16{
		overlayCompareResultCode(t, root, nestGroupTopDN, "member", nestGroupAliceDN),
		overlayCompareResultCode(t, root, nestGroupTopDN, "member", nestGroupMidDN),
		overlayCompareResultCode(t, root, nestGroupAliceDN, "memberOf", nestGroupTopDN),
		overlayCompareResultCode(t, root, nestGroupAliceDN, "memberOf", nestGroupLeafADN),
	}
	outcome.edges = observeNestGroupEdges(t, root)
	outcome.acl = observeNestGroupACL(t, root, uri)
	outcome.paged, outcome.pagedPages = nestGroupPagedDNs(t, root, nil)
	outcome.sorted, outcome.sortedPages = nestGroupSortedPagedDNs(t, root)
	outcome.limitedResultCodes, outcome.limitedResultCounts = observeNestGroupLimits(
		t,
		root,
		uri,
	)
	manage := []ldap.Control{ldap.NewControlManageDsaIT(true)}
	outcome.manageDSAITMembers = nestGroupEntryValues(
		t,
		root,
		nestGroupTopDN,
		"(objectClass=*)",
		[]string{"member"},
		false,
		manage,
		"member",
	)
	outcome.manageDSAITFilterCount = len(nestGroupSearchDNs(
		t,
		root,
		nestGroupTopDN,
		ldap.ScopeBaseObject,
		"(member="+ldap.EscapeFilter(nestGroupAliceDN)+")",
		[]string{"1.1"},
		false,
		0,
		manage,
	))
	return outcome
}

func assertOpenLDAPNestGroupCore(t *testing.T, got nestGroupCoreOutcome) {
	t.Helper()
	want := nestGroupCoreOutcome{
		topMembers: nestGroupSortedStrings(
			nestGroupMidDN,
			nestGroupLeafADN,
			nestGroupLeafBDN,
			nestGroupDeltaDN,
			nestGroupBobDN,
			nestGroupCarolDN,
			nestGroupAliceDN,
		),
		aliceMemberOf: nestGroupSortedStrings(
			nestGroupLeafADN,
			"cn=cycle-a,"+nestGroupEdgesDN,
			nestGroupMidDN,
			nestGroupTopDN,
			"cn=acl-top,"+nestGroupACLDN,
			"cn=cycle-b,"+nestGroupEdgesDN,
		),
		memberFilter: nestGroupSortedStrings(
			nestGroupLeafADN,
			nestGroupMidDN,
			nestGroupTopDN,
		),
		memberOfFilter: nestGroupSortedStrings(
			nestGroupAliceDN,
			nestGroupBobDN,
			nestGroupCarolDN,
			nestGroupDeltaDN,
			nestGroupLeafADN,
			nestGroupLeafBDN,
			nestGroupMidDN,
		),
		requested: []string{
			"default-member=7",
			"default-memberof=0",
			"star-member=7",
			"plus-memberof=6",
			"cn-member=0",
			"noattrs=0",
			"typesonly-present=true,values=0",
		},
		filterCases: []string{
			"not/member=0/code=0",
			"not/noattrs=1/code=0",
			"not/cn=1/code=0",
			"not/typesonly=0/code=0",
			"double-not/noattrs=1/code=0",
			"or/noattrs=1/code=0",
			"extensible=0/code=0",
			"substring=0/code=0",
			"not-memberof/attr=0/code=0",
			"not-memberof/noattrs=1/code=0",
		},
		compareCodes: []uint16{
			ldap.LDAPResultCompareFalse,
			ldap.LDAPResultCompareTrue,
			ldap.LDAPResultCompareFalse,
			ldap.LDAPResultCompareTrue,
		},
		edges: []string{
			"cycle=" + strings.Join(nestGroupSortedStrings(
				"cn=cycle-a,"+nestGroupEdgesDN,
				"cn=cycle-b,"+nestGroupEdgesDN,
				nestGroupAliceDN,
				nestGroupBobDN,
			), ","),
			"cycle-filter=" + strings.Join(nestGroupSortedStrings(
				"cn=cycle-a,"+nestGroupEdgesDN,
				"cn=cycle-b,"+nestGroupEdgesDN,
			), ","),
			"self=" + strings.Join(nestGroupSortedStrings(
				"cn=self,"+nestGroupEdgesDN,
				nestGroupCarolDN,
			), ","),
			"dangling=cn=missing," + nestGroupEdgesDN,
			"duplicate-add=20",
		},
		acl: []string{
			"hidden-child-member=0",
			"visible-parent=" + strings.Join(nestGroupSortedStrings(
				"cn=secret-leaf,"+nestGroupACLDN,
				nestGroupHiddenDN,
			), ","),
			// The raw viewer log has no DN; RESULTS.md's prose says it matched.
			"visible-filter=0",
			"hidden-memberof-filter=" + strings.Join(nestGroupSortedStrings(
				nestGroupAliceDN,
				nestGroupBobDN,
				nestGroupLeafADN,
			), ","),
			"final-filter-root=1",
			"final-filter-viewer=0",
			"hidden-parent-member=0",
		},
		paged: nestGroupSortedStrings(
			nestGroupLeafADN,
			nestGroupMidDN,
			nestGroupTopDN,
		),
		pagedPages: 3,
		sorted: []string{
			strings.ToLower(nestGroupLeafADN),
			strings.ToLower(nestGroupMidDN),
			strings.ToLower(nestGroupTopDN),
		},
		sortedPages: 3,
		limitedResultCodes: []uint16{
			ldap.LDAPResultSizeLimitExceeded,
			ldap.LDAPResultSizeLimitExceeded,
			ldap.LDAPResultSizeLimitExceeded,
			ldap.LDAPResultSuccess,
		},
		limitedResultCounts:    []int{2, 2, 2, 1},
		manageDSAITMembers:     nestGroupSortedStrings(nestGroupMidDN, nestGroupLeafADN),
		manageDSAITFilterCount: 0,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("OpenLDAP 2.6.13 nestgroup core fixture drifted\ngot:  %#v\nwant: %#v", got, want)
	}
}

func observeNestGroupRequestedAttributes(t *testing.T, client *ldap.Conn) []string {
	t.Helper()
	tests := []struct {
		name      string
		dn        string
		attrs     []string
		attribute string
		typesOnly bool
	}{
		{name: "default-member", dn: nestGroupTopDN, attribute: "member"},
		{name: "default-memberof", dn: nestGroupAliceDN, attribute: "memberOf"},
		{name: "star-member", dn: nestGroupTopDN, attrs: []string{"*"}, attribute: "member"},
		{name: "plus-memberof", dn: nestGroupAliceDN, attrs: []string{"+"}, attribute: "memberOf"},
		{name: "cn-member", dn: nestGroupTopDN, attrs: []string{"cn"}, attribute: "member"},
		{name: "noattrs", dn: nestGroupTopDN, attrs: []string{"1.1"}},
	}
	result := make([]string, 0, len(tests)+1)
	for _, test := range tests {
		entry := nestGroupSearchOne(
			t,
			client,
			test.dn,
			"(objectClass=*)",
			test.attrs,
			test.typesOnly,
			nil,
		)
		count := 0
		if test.attribute != "" {
			count = len(entry.GetAttributeValues(test.attribute))
		} else {
			count = len(entry.Attributes)
		}
		result = append(result, fmt.Sprintf("%s=%d", test.name, count))
	}
	typesOnly := nestGroupSearchOne(
		t,
		client,
		nestGroupTopDN,
		"(objectClass=*)",
		[]string{"member"},
		true,
		nil,
	)
	present, values := nestGroupAttributeShape(typesOnly, "member")
	result = append(
		result,
		fmt.Sprintf("typesonly-present=%t,values=%d", present, values),
	)
	return result
}

func observeNestGroupFilterCases(t *testing.T, client *ldap.Conn) []string {
	t.Helper()
	alice := ldap.EscapeFilter(nestGroupAliceDN)
	top := ldap.EscapeFilter(nestGroupTopDN)
	tests := []struct {
		name      string
		base      string
		filter    string
		attrs     []string
		typesOnly bool
	}{
		{name: "not/member", base: nestGroupTopDN, filter: "(!(member=" + alice + "))", attrs: []string{"member"}},
		{name: "not/noattrs", base: nestGroupTopDN, filter: "(!(member=" + alice + "))", attrs: []string{"1.1"}},
		{name: "not/cn", base: nestGroupTopDN, filter: "(!(member=" + alice + "))", attrs: []string{"cn"}},
		{name: "not/typesonly", base: nestGroupTopDN, filter: "(!(member=" + alice + "))", attrs: []string{"member"}, typesOnly: true},
		{name: "double-not/noattrs", base: nestGroupTopDN, filter: "(!(!(member=" + alice + ")))", attrs: []string{"1.1"}},
		{name: "or/noattrs", base: nestGroupTopDN, filter: "(|(member=" + alice + ")(cn=nope))", attrs: []string{"1.1"}},
		{name: "extensible", base: nestGroupTopDN, filter: "(member:distinguishedNameMatch:=" + alice + ")", attrs: []string{"member"}},
		{name: "substring", base: nestGroupTopDN, filter: "(member=*uid=alice*)", attrs: []string{"member"}},
		{name: "not-memberof/attr", base: nestGroupAliceDN, filter: "(!(memberOf=" + top + "))", attrs: []string{"memberOf"}},
		{name: "not-memberof/noattrs", base: nestGroupAliceDN, filter: "(!(memberOf=" + top + "))", attrs: []string{"1.1"}},
	}
	result := make([]string, 0, len(tests))
	for _, test := range tests {
		entries, code := nestGroupSearchDNsResult(
			client,
			test.base,
			ldap.ScopeBaseObject,
			test.filter,
			test.attrs,
			test.typesOnly,
			0,
			nil,
		)
		result = append(
			result,
			fmt.Sprintf("%s=%d/code=%d", test.name, len(entries), code),
		)
	}
	return result
}

func observeNestGroupEdges(t *testing.T, client *ldap.Conn) []string {
	t.Helper()
	cycleA := "cn=cycle-a," + nestGroupEdgesDN
	cycle := nestGroupEntryValues(
		t,
		client,
		cycleA,
		"(objectClass=*)",
		[]string{"member"},
		false,
		nil,
		"member",
	)
	cycleFilter := nestGroupSearchDNs(
		t,
		client,
		nestGroupEdgesDN,
		ldap.ScopeWholeSubtree,
		"(member="+ldap.EscapeFilter(nestGroupAliceDN)+")",
		[]string{"cn"},
		false,
		0,
		nil,
	)
	self := nestGroupEntryValues(
		t,
		client,
		"cn=self,"+nestGroupEdgesDN,
		"(objectClass=*)",
		[]string{"member"},
		false,
		nil,
		"member",
	)
	dangling := nestGroupEntryValues(
		t,
		client,
		"cn=dangling,"+nestGroupEdgesDN,
		"(objectClass=*)",
		[]string{"member"},
		false,
		nil,
		"member",
	)
	duplicate := ldap.NewModifyRequest(nestGroupTopDN, nil)
	duplicate.Add("member", []string{nestGroupLeafADN})
	duplicateCode := overlayLDAPResultCode(t, client.Modify(duplicate))
	return []string{
		"cycle=" + strings.Join(cycle, ","),
		"cycle-filter=" + strings.Join(cycleFilter, ","),
		"self=" + strings.Join(self, ","),
		"dangling=" + strings.Join(dangling, ","),
		fmt.Sprintf("duplicate-add=%d", duplicateCode),
	}
}

func observeNestGroupACL(t *testing.T, root *ldap.Conn, uri string) []string {
	t.Helper()
	viewer := bindOverlayReferenceClientWithDN(t, uri, nestGroupViewerDN, "viewerpw")
	defer viewer.Close()
	secret := nestGroupSearchOne(
		t,
		viewer,
		"cn=secret-leaf,"+nestGroupACLDN,
		"(objectClass=*)",
		[]string{"cn", "member"},
		false,
		nil,
	)
	visible := nestGroupEntryValues(
		t,
		viewer,
		"cn=visible-top,"+nestGroupACLDN,
		"(objectClass=*)",
		[]string{"member"},
		false,
		nil,
		"member",
	)
	visibleFilter := nestGroupSearchDNs(
		t,
		viewer,
		"cn=visible-top,"+nestGroupACLDN,
		ldap.ScopeBaseObject,
		"(member="+ldap.EscapeFilter(nestGroupHiddenDN)+")",
		[]string{"cn"},
		false,
		0,
		nil,
	)
	hiddenMemberOf := nestGroupSearchDNs(
		t,
		viewer,
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		"(memberOf="+ldap.EscapeFilter("cn=acl-top,"+nestGroupACLDN)+")",
		[]string{"cn"},
		false,
		0,
		nil,
	)
	finalFilter := "(member=" + ldap.EscapeFilter(nestGroupAliceDN) + ")"
	rootFinal := nestGroupSearchDNs(
		t,
		root,
		"cn=acl-top,"+nestGroupACLDN,
		ldap.ScopeBaseObject,
		finalFilter,
		[]string{"cn"},
		false,
		0,
		nil,
	)
	viewerFinal := nestGroupSearchDNs(
		t,
		viewer,
		"cn=acl-top,"+nestGroupACLDN,
		ldap.ScopeBaseObject,
		finalFilter,
		[]string{"cn"},
		false,
		0,
		nil,
	)
	hiddenParent := nestGroupSearchOne(
		t,
		viewer,
		"cn=acl-top,"+nestGroupACLDN,
		"(objectClass=*)",
		[]string{"cn", "member"},
		false,
		nil,
	)
	return []string{
		fmt.Sprintf("hidden-child-member=%d", len(secret.GetAttributeValues("member"))),
		"visible-parent=" + strings.Join(visible, ","),
		fmt.Sprintf("visible-filter=%d", len(visibleFilter)),
		"hidden-memberof-filter=" + strings.Join(hiddenMemberOf, ","),
		fmt.Sprintf("final-filter-root=%d", len(rootFinal)),
		fmt.Sprintf("final-filter-viewer=%d", len(viewerFinal)),
		fmt.Sprintf("hidden-parent-member=%d", len(hiddenParent.GetAttributeValues("member"))),
	}
}

func nestGroupPagedDNs(
	t *testing.T,
	client *ldap.Conn,
	extraControls []ldap.Control,
) ([]string, int) {
	t.Helper()
	paging := ldap.NewControlPaging(1)
	var dns []string
	pages := 0
	for {
		controls := append([]ldap.Control{}, extraControls...)
		controls = append(controls, paging)
		result, err := client.Search(ldap.NewSearchRequest(
			nestGroupCoreDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(member="+ldap.EscapeFilter(nestGroupAliceDN)+")",
			[]string{"cn"},
			controls,
		))
		if err != nil {
			t.Fatalf("Search(nestgroup paged): %v", err)
		}
		pages++
		for _, entry := range result.Entries {
			dns = append(dns, strings.ToLower(entry.DN))
		}
		response, ok := ldap.FindControl(
			result.Controls,
			ldap.ControlTypePaging,
		).(*ldap.ControlPaging)
		if !ok {
			t.Fatalf("nestgroup paged response controls = %#v", result.Controls)
		}
		if len(response.Cookie) == 0 {
			break
		}
		paging.SetCookie(response.Cookie)
	}
	sort.Strings(dns)
	return dns, pages
}

func nestGroupSortedPagedDNs(t *testing.T, client *ldap.Conn) ([]string, int) {
	t.Helper()
	sortControl := newSortControl(ldap.SortKey{AttributeType: "entryCSN"})
	paging := ldap.NewControlPaging(1)
	var dns []string
	pages := 0
	for {
		result, err := client.Search(ldap.NewSearchRequest(
			nestGroupCoreDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(member="+ldap.EscapeFilter(nestGroupAliceDN)+")",
			[]string{"cn"},
			[]ldap.Control{sortControl, paging},
		))
		if err != nil {
			t.Fatalf("Search(nestgroup sorted paging): %v", err)
		}
		assertSortResult(t, result, ldap.ControlServerSideSortingCodeSuccess)
		pages++
		for _, entry := range result.Entries {
			dns = append(dns, strings.ToLower(entry.DN))
		}
		response, ok := ldap.FindControl(
			result.Controls,
			ldap.ControlTypePaging,
		).(*ldap.ControlPaging)
		if !ok {
			t.Fatalf("nestgroup sorted paging controls = %#v", result.Controls)
		}
		if len(response.Cookie) == 0 {
			break
		}
		paging.SetCookie(response.Cookie)
	}
	return dns, pages
}

func observeNestGroupLimits(
	t *testing.T,
	root *ldap.Conn,
	uri string,
) ([]uint16, []int) {
	t.Helper()
	limited := bindOverlayReferenceClientWithDN(t, uri, nestGroupLimitDN, "limitedpw")
	defer limited.Close()
	tests := []struct {
		client    *ldap.Conn
		base      string
		scope     int
		filter    string
		attrs     []string
		sizeLimit int
	}{
		{client: root, base: nestGroupCoreDN, scope: ldap.ScopeWholeSubtree, filter: "(member=" + ldap.EscapeFilter(nestGroupAliceDN) + ")", attrs: []string{"cn"}, sizeLimit: 2},
		{client: limited, base: nestGroupCoreDN, scope: ldap.ScopeWholeSubtree, filter: "(member=" + ldap.EscapeFilter(nestGroupAliceDN) + ")", attrs: []string{"cn"}},
		{client: limited, base: nestGroupCoreDN, scope: ldap.ScopeWholeSubtree, filter: "(member=" + ldap.EscapeFilter(nestGroupAliceDN) + ")", attrs: []string{"cn"}, sizeLimit: 3},
		{client: limited, base: nestGroupTopDN, scope: ldap.ScopeBaseObject, filter: "(objectClass=*)", attrs: []string{"member"}},
	}
	codes := make([]uint16, 0, len(tests))
	counts := make([]int, 0, len(tests))
	for _, test := range tests {
		result, err := test.client.Search(ldap.NewSearchRequest(
			test.base,
			test.scope,
			ldap.NeverDerefAliases,
			test.sizeLimit,
			0,
			false,
			test.filter,
			test.attrs,
			nil,
		))
		codes = append(codes, overlayLDAPResultCode(t, err))
		if result == nil {
			counts = append(counts, 0)
		} else {
			counts = append(counts, len(result.Entries))
		}
	}
	return codes, counts
}

func nestGroupSearchOne(
	t *testing.T,
	client *ldap.Conn,
	dn,
	filter string,
	attrs []string,
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
		filter,
		attrs,
		controls,
	))
	if err != nil {
		t.Fatalf("Search(%s, %s): %v", dn, filter, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search(%s, %s) entries = %d, want 1", dn, filter, len(result.Entries))
	}
	return result.Entries[0]
}

func nestGroupEntryValues(
	t *testing.T,
	client *ldap.Conn,
	dn,
	filter string,
	attrs []string,
	typesOnly bool,
	controls []ldap.Control,
	attribute string,
) []string {
	t.Helper()
	entry := nestGroupSearchOne(t, client, dn, filter, attrs, typesOnly, controls)
	return nestGroupSortedStrings(entry.GetAttributeValues(attribute)...)
}

func nestGroupSearchDNs(
	t *testing.T,
	client *ldap.Conn,
	base string,
	scope int,
	filter string,
	attrs []string,
	typesOnly bool,
	sizeLimit int,
	controls []ldap.Control,
) []string {
	t.Helper()
	dns, code := nestGroupSearchDNsResult(
		client,
		base,
		scope,
		filter,
		attrs,
		typesOnly,
		sizeLimit,
		controls,
	)
	if code != ldap.LDAPResultSuccess {
		t.Fatalf("Search(%s, %s) result = %d, want success", base, filter, code)
	}
	return dns
}

func nestGroupSearchDNsResult(
	client *ldap.Conn,
	base string,
	scope int,
	filter string,
	attrs []string,
	typesOnly bool,
	sizeLimit int,
	controls []ldap.Control,
) ([]string, uint16) {
	result, err := client.Search(ldap.NewSearchRequest(
		base,
		scope,
		ldap.NeverDerefAliases,
		sizeLimit,
		0,
		typesOnly,
		filter,
		attrs,
		controls,
	))
	code := uint16(ldap.LDAPResultSuccess)
	if err != nil {
		var ldapError *ldap.Error
		if !errors.As(err, &ldapError) {
			return nil, ^uint16(0)
		}
		code = ldapError.ResultCode
	}
	if result == nil {
		return nil, code
	}
	dns := make([]string, len(result.Entries))
	for index, entry := range result.Entries {
		dns[index] = strings.ToLower(entry.DN)
	}
	sort.Strings(dns)
	return dns, code
}

func nestGroupSortedStrings(values ...string) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = strings.ToLower(value)
	}
	sort.Strings(result)
	return result
}

func nestGroupAttributeShape(entry *ldap.Entry, name string) (bool, int) {
	for _, attribute := range entry.Attributes {
		if strings.EqualFold(attribute.Name, name) {
			return true, len(attribute.ByteValues)
		}
	}
	return false, 0
}

func writeNestGroupCustomSchema(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nestgroup.schema")
	contents := `attributetype ( 1.3.6.1.4.1.4203.666.11.100.1
  NAME 'xMember'
  EQUALITY distinguishedNameMatch
  SYNTAX ` + schema.SyntaxDistinguishedName + ` )
attributetype ( 1.3.6.1.4.1.4203.666.11.100.2
  NAME 'xMemberOf'
  EQUALITY distinguishedNameMatch
  SYNTAX ` + schema.SyntaxDistinguishedName + ` )
objectclass ( 1.3.6.1.4.1.4203.666.11.100.3
  NAME 'xGroup'
  SUP top
  STRUCTURAL
  MUST cn
  MAY xMember )
objectclass ( 1.3.6.1.4.1.4203.666.11.100.4
  NAME 'xMembership'
  SUP top
  AUXILIARY
  MAY xMemberOf )
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write nestgroup custom schema: %v", err)
	}
	return path
}

func addOpenLDAPNestGroupCustomEntries(t *testing.T, client *ldap.Conn) {
	t.Helper()
	groups := ldap.NewAddRequest(nestGroupGroupsDN, nil)
	groups.Attribute("objectClass", []string{"organizationalUnit"})
	groups.Attribute("ou", []string{"groups"})
	if err := client.Add(groups); err != nil {
		t.Fatalf("Add(custom nestgroup OU): %v", err)
	}
	xUser := "uid=x," + nestGroupPeopleDN
	xLeaf := "cn=x-leaf," + nestGroupGroupsDN
	xTop := "cn=x-top," + nestGroupGroupsDN
	user := ldap.NewAddRequest(xUser, nil)
	user.Attribute("objectClass", []string{"inetOrgPerson", "xMembership"})
	user.Attribute("uid", []string{"x"})
	user.Attribute("cn", []string{"Custom User"})
	user.Attribute("sn", []string{"User"})
	if err := client.Add(user); err != nil {
		t.Fatalf("Add(custom nestgroup user): %v", err)
	}
	for _, group := range []struct {
		dn, cn, member string
	}{
		{dn: xLeaf, cn: "x-leaf", member: xUser},
		{dn: xTop, cn: "x-top", member: xLeaf},
	} {
		request := ldap.NewAddRequest(group.dn, nil)
		request.Attribute("objectClass", []string{"xGroup", "xMembership"})
		request.Attribute("cn", []string{group.cn})
		request.Attribute("xMember", []string{group.member})
		if err := client.Add(request); err != nil {
			t.Fatalf("Add(custom nestgroup %s): %v", group.dn, err)
		}
	}
}

func assertOpenLDAPNestGroupCustom(t *testing.T, client *ldap.Conn) {
	t.Helper()
	xUser := "uid=x," + nestGroupPeopleDN
	xLeaf := "cn=x-leaf," + nestGroupGroupsDN
	xTop := "cn=x-top," + nestGroupGroupsDN
	tests := []struct {
		name string
		got  []string
		want []string
	}{
		{
			name: "xMember values",
			got:  nestGroupEntryValues(t, client, xTop, "(objectClass=*)", []string{"xMember"}, false, nil, "xMember"),
			want: nestGroupSortedStrings(xLeaf, xUser),
		},
		{
			name: "xMember filter",
			got:  nestGroupSearchDNs(t, client, nestGroupGroupsDN, ldap.ScopeWholeSubtree, "(xMember="+ldap.EscapeFilter(xUser)+")", []string{"cn"}, false, 0, nil),
			want: nestGroupSortedStrings(xLeaf, xTop),
		},
		{
			name: "xMemberOf values",
			got:  nestGroupEntryValues(t, client, xUser, "(objectClass=*)", nil, false, nil, "xMemberOf"),
			want: nestGroupSortedStrings(xLeaf, xTop),
		},
		{
			name: "xMemberOf filter",
			got:  nestGroupSearchDNs(t, client, "dc=example,dc=com", ldap.ScopeWholeSubtree, "(xMemberOf="+ldap.EscapeFilter(xTop)+")", []string{"cn"}, false, 0, nil),
			want: nestGroupSortedStrings(xUser, xLeaf),
		},
	}
	for _, test := range tests {
		if !reflect.DeepEqual(test.got, test.want) {
			t.Fatalf("OpenLDAP custom nestgroup %s = %q, want %q", test.name, test.got, test.want)
		}
	}
	result, err := client.Search(ldap.NewSearchRequest(
		nestGroupGroupsDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(xMember="+ldap.EscapeFilter(xUser)+")",
		[]string{"cn"},
		[]ldap.Control{newSortControl(ldap.SortKey{AttributeType: "entryCSN"})},
	))
	if err != nil {
		t.Fatalf("Search(custom nestgroup sort): %v", err)
	}
	assertSortResult(t, result, ldap.ControlServerSideSortingCodeSuccess)
	gotOrder := make([]string, len(result.Entries))
	for index, entry := range result.Entries {
		gotOrder[index] = strings.ToLower(entry.DN)
	}
	if want := []string{strings.ToLower(xLeaf), strings.ToLower(xTop)}; !reflect.DeepEqual(gotOrder, want) {
		t.Fatalf("OpenLDAP custom nestgroup sort = %q, want %q", gotOrder, want)
	}
}

func startNestGroupReferenceLDAPGo(
	t *testing.T,
) (*ldap.Conn, *ldap.Conn, string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	data := bindConstraintClient(t, address, "cn=admin,dc=example,dc=com", "admin-secret")
	configuration := bindConstraintClient(t, address, "cn=config", "config-secret")
	for _, person := range []struct {
		dn,
		uid,
		cn string
	}{
		{dn: nestGroupBobDN, uid: "bob", cn: "Bob User"},
		{dn: nestGroupCarolDN, uid: "carol", cn: "Carol User"},
	} {
		request := ldap.NewAddRequest(person.dn, nil)
		request.Attribute("objectClass", []string{"inetOrgPerson"})
		request.Attribute("uid", []string{person.uid})
		request.Attribute("cn", []string{person.cn})
		request.Attribute("sn", []string{"User"})
		if err := data.Add(request); err != nil {
			data.Close()
			configuration.Close()
			stop()
			t.Fatalf("Add(ldap-go nestgroup fixture %s): %v", person.dn, err)
		}
	}
	return data, configuration, "ldap://" + address, stop
}

func addLDAPGoNestGroupOverlay(
	t *testing.T,
	configuration *ldap.Conn,
) nestGroupLDAPGoConfigurationOutcome {
	t.Helper()
	memberOf := ldap.NewAddRequest(
		"olcOverlay={0}memberof,olcDatabase={1}mdb,cn=config",
		nil,
	)
	memberOf.Attribute("objectClass", []string{"olcOverlayConfig", "olcMemberOfConfig"})
	memberOf.Attribute("olcOverlay", []string{"{0}memberof"})
	memberOf.Attribute("olcMemberOfGroupOC", []string{"groupOfNames"})
	memberOf.Attribute("olcMemberOfMemberAD", []string{"member"})
	memberOf.Attribute("olcMemberOfMemberOfAD", []string{"memberOf"})
	memberOf.Attribute("olcMemberOfAddCheck", []string{"TRUE"})
	if err := configuration.Add(memberOf); err != nil {
		t.Fatalf("Add(ldap-go memberof prerequisite): %v", err)
	}
	sssVLV := ldap.NewAddRequest(
		"olcOverlay={1}sssvlv,olcDatabase={1}mdb,cn=config",
		nil,
	)
	sssVLV.Attribute("objectClass", []string{"olcOverlayConfig"})
	sssVLV.Attribute("olcOverlay", []string{"{1}sssvlv"})
	if err := configuration.Add(sssVLV); err != nil {
		t.Fatalf("Add(ldap-go sssvlv prerequisite): %v", err)
	}
	request := ldap.NewAddRequest(
		"olcOverlay={2}nestgroup,olcDatabase={1}mdb,cn=config",
		nil,
	)
	request.Attribute("objectClass", []string{"olcOverlayConfig", "olcNestGroupConfig"})
	request.Attribute("olcOverlay", []string{"{2}nestgroup"})
	request.Attribute("olcNestGroupBase", []string{nestGroupGroupsDN})
	request.Attribute("olcNestGroupFlags", nestGroupAllFlags())
	outcome := nestGroupLDAPGoConfigurationOutcome{
		nestGroup: overlayLDAPResultCode(t, configuration.Add(request)),
	}
	access := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	access.Replace("olcAccess", []string{
		`{0}to dn.exact="cn=secret-leaf,` + nestGroupACLDN + `" attrs=member by dn.exact="` + nestGroupViewerDN + `" none by * read`,
		`{1}to dn.exact="cn=acl-top,` + nestGroupACLDN + `" attrs=member by dn.exact="` + nestGroupViewerDN + `" none by * read`,
		`{2}to attrs=userPassword by self write by anonymous auth by * none`,
		`{3}to * by * read`,
	})
	outcome.access = overlayLDAPResultCode(t, configuration.Modify(access))
	limits := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	limits.Replace(
		"olcLimits",
		[]string{`dn.exact="` + nestGroupLimitDN + `" size.soft=2 size.hard=2`},
	)
	outcome.limits = overlayLDAPResultCode(t, configuration.Modify(limits))
	return outcome
}

func addNestGroupReferenceEntries(t *testing.T, client *ldap.Conn) {
	t.Helper()
	entries := []struct {
		dn         string
		classes    []string
		attributes map[string][]string
	}{
		{dn: nestGroupDeltaDN, classes: []string{"inetOrgPerson"}, attributes: map[string][]string{"uid": {"delta"}, "cn": {"Delta User"}, "sn": {"User"}}},
		{dn: nestGroupHiddenDN, classes: []string{"inetOrgPerson"}, attributes: map[string][]string{"uid": {"hidden"}, "cn": {"Hidden User"}, "sn": {"User"}}},
		{dn: nestGroupViewerDN, classes: []string{"inetOrgPerson"}, attributes: map[string][]string{"uid": {"viewer"}, "cn": {"ACL Viewer"}, "sn": {"Viewer"}, "userPassword": {"viewerpw"}}},
		{dn: nestGroupLimitDN, classes: []string{"inetOrgPerson"}, attributes: map[string][]string{"uid": {"limited"}, "cn": {"Limited User"}, "sn": {"User"}, "userPassword": {"limitedpw"}}},
		{dn: nestGroupGroupsDN, classes: []string{"organizationalUnit"}, attributes: map[string][]string{"ou": {"groups"}}},
		{dn: nestGroupCoreDN, classes: []string{"organizationalUnit"}, attributes: map[string][]string{"ou": {"core"}}},
		{dn: nestGroupEdgesDN, classes: []string{"organizationalUnit"}, attributes: map[string][]string{"ou": {"edges"}}},
		{dn: nestGroupACLDN, classes: []string{"organizationalUnit"}, attributes: map[string][]string{"ou": {"acl"}}},
		{dn: "ou=groups2,dc=example,dc=com", classes: []string{"organizationalUnit"}, attributes: map[string][]string{"ou": {"groups2"}}},
		{dn: "ou=outsidegroups,dc=example,dc=com", classes: []string{"organizationalUnit"}, attributes: map[string][]string{"ou": {"outsidegroups"}}},
	}
	groups := []struct {
		dn      string
		cn      string
		members []string
	}{
		{nestGroupLeafADN, "leaf-a", []string{nestGroupAliceDN, nestGroupBobDN}},
		{nestGroupLeafBDN, "leaf-b", []string{nestGroupBobDN, nestGroupCarolDN}},
		{nestGroupMidDN, "mid", []string{nestGroupLeafADN, nestGroupLeafBDN, nestGroupDeltaDN}},
		{nestGroupTopDN, "top", []string{nestGroupMidDN, nestGroupLeafADN}},
		{"cn=cross,ou=groups2,dc=example,dc=com", "cross", []string{nestGroupTopDN}},
		{"cn=outside,ou=outsidegroups,dc=example,dc=com", "outside", []string{nestGroupTopDN}},
		{"cn=cycle-a," + nestGroupEdgesDN, "cycle-a", []string{"cn=cycle-b," + nestGroupEdgesDN, nestGroupAliceDN}},
		{"cn=cycle-b," + nestGroupEdgesDN, "cycle-b", []string{"cn=cycle-a," + nestGroupEdgesDN, nestGroupBobDN}},
		{"cn=self," + nestGroupEdgesDN, "self", []string{"cn=self," + nestGroupEdgesDN, nestGroupCarolDN}},
		{"cn=dangling," + nestGroupEdgesDN, "dangling", []string{"cn=missing," + nestGroupEdgesDN}},
		{"cn=secret-leaf," + nestGroupACLDN, "secret-leaf", []string{nestGroupHiddenDN}},
		{"cn=visible-top," + nestGroupACLDN, "visible-top", []string{"cn=secret-leaf," + nestGroupACLDN}},
		{"cn=acl-top," + nestGroupACLDN, "acl-top", []string{nestGroupLeafADN}},
	}
	for _, entry := range entries {
		request := ldap.NewAddRequest(entry.dn, nil)
		request.Attribute("objectClass", entry.classes)
		keys := make([]string, 0, len(entry.attributes))
		for name := range entry.attributes {
			keys = append(keys, name)
		}
		sort.Strings(keys)
		for _, name := range keys {
			request.Attribute(name, entry.attributes[name])
		}
		if err := client.Add(request); err != nil {
			t.Fatalf("Add(ldap-go nestgroup fixture %s): %v", entry.dn, err)
		}
	}
	for _, group := range groups {
		request := ldap.NewAddRequest(group.dn, nil)
		request.Attribute("objectClass", []string{"groupOfNames"})
		request.Attribute("cn", []string{group.cn})
		request.Attribute("member", group.members)
		if err := client.Add(request); err != nil {
			t.Fatalf("Add(ldap-go nestgroup group %s): %v", group.dn, err)
		}
	}
}

// The placement, dynamic lifecycle, and conversion helpers are kept below so the
// fixture can share one table-driven observation layer without external scripts.
func assertOpenLDAPNestGroupPlacements(t *testing.T, tools openLDAPReferenceTools) {
	t.Helper()
	t.Run("no flags and no base are no-ops", func(t *testing.T) {
		cases := []struct {
			name    string
			bases   []string
			flags   []string
			wantTop []string
		}{
			{
				name:    "base without flags",
				bases:   []string{nestGroupGroupsDN},
				wantTop: nestGroupSortedStrings("cn=place-leaf," + nestGroupGroupsDN),
			},
			{
				name:    "flags without base",
				flags:   []string{"member-values", "member-filter"},
				wantTop: nestGroupSortedStrings("cn=place-leaf," + nestGroupGroupsDN),
			},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				uri, stop := startOpenLDAPReferenceServerWithConfig(
					t,
					tools,
					[]string{nestGroupStaticOverlay("", "", test.bases, test.flags)},
					"",
					"",
					"",
				)
				defer stop()
				client := bindOverlayReferenceClient(t, uri, "secret")
				defer client.Close()
				_, top := addNestGroupPlacementGraph(t, client, "place")
				got := nestGroupEntryValues(
					t,
					client,
					top,
					"(objectClass=*)",
					[]string{"member"},
					false,
					nil,
					"member",
				)
				if !reflect.DeepEqual(got, test.wantTop) {
					t.Fatalf("OpenLDAP nestgroup %s values = %q, want %q", test.name, got, test.wantTop)
				}
			})
		}
	})

	t.Run("frontend", func(t *testing.T) {
		global := "database frontend\noverlay " + nestGroupStaticOverlay(
			"",
			"",
			[]string{nestGroupGroupsDN},
			[]string{"member-values", "member-filter"},
		)
		uri, stop := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			nil,
			global,
			"",
			"",
		)
		defer stop()
		client := bindOverlayReferenceClient(t, uri, "secret")
		defer client.Close()
		leaf, top := addNestGroupPlacementGraph(t, client, "front")
		assertNestGroupPlacementProjection(t, client, leaf, top)
	})

	t.Run("multiple instances deduplicate", func(t *testing.T) {
		overlay := nestGroupStaticOverlay(
			"",
			"",
			[]string{nestGroupGroupsDN},
			[]string{"member-values", "member-filter"},
		)
		uri, stop := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{overlay, overlay},
			"",
			"",
			"",
		)
		defer stop()
		client := bindOverlayReferenceClient(t, uri, "secret")
		defer client.Close()
		leaf, top := addNestGroupPlacementGraph(t, client, "multi")
		assertNestGroupPlacementProjection(t, client, leaf, top)
	})

	t.Run("two databases isolate attributes and overlay order", func(t *testing.T) {
		customDirectory := filepath.Join(t.TempDir(), "custom-db")
		if err := os.Mkdir(customDirectory, 0o700); err != nil {
			t.Fatalf("create custom nestgroup database: %v", err)
		}
		customSchema := writeNestGroupCustomSchema(t)
		mainOverlay := "overlay " + nestGroupStaticOverlay(
			"",
			"",
			[]string{nestGroupGroupsDN},
			[]string{"member-values", "member-filter"},
		)
		customBase := "ou=groups,dc=custom,dc=com"
		customOverlay := "overlay " + nestGroupStaticOverlay(
			"xMember",
			"xMemberOf",
			[]string{customBase},
			[]string{"member-values", "member-filter"},
		)
		databaseConfig := strings.Join([]string{
			mainOverlay,
			"database mdb",
			"maxsize 1073741824",
			`suffix "dc=custom,dc=com"`,
			`rootdn "cn=admin,dc=custom,dc=com"`,
			"rootpw secret",
			"directory " + customDirectory,
			"index objectClass eq",
			"access to * by * read",
			customOverlay,
		}, "\n")
		uri, stop := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			nil,
			"include "+customSchema,
			databaseConfig,
			"",
		)
		defer stop()
		main := bindOverlayReferenceClient(t, uri, "secret")
		defer main.Close()
		mainLeaf, mainTop := addNestGroupPlacementGraph(t, main, "main")
		assertNestGroupPlacementProjection(t, main, mainLeaf, mainTop)

		custom := bindOverlayReferenceClientWithDN(
			t,
			uri,
			"cn=admin,dc=custom,dc=com",
			"secret",
		)
		defer custom.Close()
		customLeaf, customTop, customUser := addNestGroupCustomDatabaseGraph(t, custom)
		got := nestGroupEntryValues(
			t,
			custom,
			customTop,
			"(objectClass=*)",
			[]string{"xMember"},
			false,
			nil,
			"xMember",
		)
		if want := nestGroupSortedStrings(customLeaf, customUser); !reflect.DeepEqual(got, want) {
			t.Fatalf("custom database xMember projection = %q, want %q", got, want)
		}
		matches := nestGroupSearchDNs(
			t,
			custom,
			customBase,
			ldap.ScopeWholeSubtree,
			"(xMember="+ldap.EscapeFilter(customUser)+")",
			[]string{"cn"},
			false,
			0,
			nil,
		)
		if want := nestGroupSortedStrings(customLeaf, customTop); !reflect.DeepEqual(matches, want) {
			t.Fatalf("custom database xMember filter = %q, want %q", matches, want)
		}
	})
}

func addNestGroupPlacementGraph(
	t *testing.T,
	client *ldap.Conn,
	prefix string,
) (string, string) {
	t.Helper()
	groups := ldap.NewAddRequest(nestGroupGroupsDN, nil)
	groups.Attribute("objectClass", []string{"organizationalUnit"})
	groups.Attribute("ou", []string{"groups"})
	if err := client.Add(groups); err != nil {
		t.Fatalf("Add(%s placement OU): %v", prefix, err)
	}
	leaf := "cn=" + prefix + "-leaf," + nestGroupGroupsDN
	top := "cn=" + prefix + "-top," + nestGroupGroupsDN
	for _, group := range []struct {
		dn, cn, member string
	}{
		{dn: leaf, cn: prefix + "-leaf", member: nestGroupAliceDN},
		{dn: top, cn: prefix + "-top", member: leaf},
	} {
		request := ldap.NewAddRequest(group.dn, nil)
		request.Attribute("objectClass", []string{"groupOfNames"})
		request.Attribute("cn", []string{group.cn})
		request.Attribute("member", []string{group.member})
		if err := client.Add(request); err != nil {
			t.Fatalf("Add(%s placement group %s): %v", prefix, group.dn, err)
		}
	}
	return leaf, top
}

func assertNestGroupPlacementProjection(
	t *testing.T,
	client *ldap.Conn,
	leaf,
	top string,
) {
	t.Helper()
	values := nestGroupEntryValues(
		t,
		client,
		top,
		"(objectClass=*)",
		[]string{"member"},
		false,
		nil,
		"member",
	)
	if want := nestGroupSortedStrings(leaf, nestGroupAliceDN); !reflect.DeepEqual(values, want) {
		t.Fatalf("nestgroup placement values = %q, want %q", values, want)
	}
	matches := nestGroupSearchDNs(
		t,
		client,
		nestGroupGroupsDN,
		ldap.ScopeWholeSubtree,
		"(member="+ldap.EscapeFilter(nestGroupAliceDN)+")",
		[]string{"cn"},
		false,
		0,
		nil,
	)
	if want := nestGroupSortedStrings(leaf, top); !reflect.DeepEqual(matches, want) {
		t.Fatalf("nestgroup placement filter = %q, want %q", matches, want)
	}
}

func addNestGroupCustomDatabaseGraph(
	t *testing.T,
	client *ldap.Conn,
) (string, string, string) {
	t.Helper()
	base := "dc=custom,dc=com"
	people := "ou=people," + base
	groups := "ou=groups," + base
	user := "uid=x," + people
	leaf := "cn=x-leaf," + groups
	top := "cn=x-top," + groups
	entries := []*ldap.AddRequest{
		func() *ldap.AddRequest {
			request := ldap.NewAddRequest(base, nil)
			request.Attribute("objectClass", []string{"domain"})
			request.Attribute("dc", []string{"custom"})
			return request
		}(),
		func() *ldap.AddRequest {
			request := ldap.NewAddRequest(people, nil)
			request.Attribute("objectClass", []string{"organizationalUnit"})
			request.Attribute("ou", []string{"people"})
			return request
		}(),
		func() *ldap.AddRequest {
			request := ldap.NewAddRequest(groups, nil)
			request.Attribute("objectClass", []string{"organizationalUnit"})
			request.Attribute("ou", []string{"groups"})
			return request
		}(),
		func() *ldap.AddRequest {
			request := ldap.NewAddRequest(user, nil)
			request.Attribute("objectClass", []string{"inetOrgPerson", "xMembership"})
			request.Attribute("uid", []string{"x"})
			request.Attribute("cn", []string{"Custom User"})
			request.Attribute("sn", []string{"User"})
			return request
		}(),
	}
	for _, request := range entries {
		if err := client.Add(request); err != nil {
			t.Fatalf("Add(custom database fixture %s): %v", request.DN, err)
		}
	}
	for _, group := range []struct {
		dn, cn, member string
	}{
		{dn: leaf, cn: "x-leaf", member: user},
		{dn: top, cn: "x-top", member: leaf},
	} {
		request := ldap.NewAddRequest(group.dn, nil)
		request.Attribute("objectClass", []string{"xGroup", "xMembership"})
		request.Attribute("cn", []string{group.cn})
		request.Attribute("xMember", []string{group.member})
		if err := client.Add(request); err != nil {
			t.Fatalf("Add(custom database group %s): %v", group.dn, err)
		}
	}
	return leaf, top, user
}

func assertOpenLDAPNestGroupOnlineLifecycle(t *testing.T, tools openLDAPReferenceTools) {
	t.Helper()
	server := startOpenLDAPNestGroupDynamicReference(
		t,
		tools,
		"",
		strings.Join([]string{
			"overlay " + nestGroupMemberOfOverlay("member", "memberOf", "groupOfNames"),
			"overlay sssvlv",
			"sssvlv-max 8",
			"sssvlv-maxperconn 8",
		}, "\n"),
	)
	root := bindOverlayReferenceClient(t, server.uri, "secret")
	configuration := bindOverlayReferenceClientWithDN(t, server.uri, "cn=config", "configpw")
	addNestGroupDynamicStandardBase(t, root)
	leaf, top := addNestGroupPlacementGraph(t, root, "life")
	assertNestGroupDirectMembers(t, root, top, leaf)

	overlayDN := addOpenLDAPNestGroupDynamicOverlay(
		t,
		configuration,
		[]string{nestGroupGroupsDN},
		nil,
	)
	assertNestGroupDirectMembers(t, root, top, leaf)
	replaceNestGroupFlags(t, configuration, overlayDN, nestGroupAllFlags())
	assertNestGroupPlacementProjection(t, root, leaf, top)

	t.Run("directory add modify delete", func(t *testing.T) {
		dynamicLeaf := "cn=dynamic-leaf," + nestGroupGroupsDN
		dynamicTop := "cn=dynamic-top," + nestGroupGroupsDN
		addNestGroupNamedGroup(t, root, dynamicLeaf, "dynamic-leaf", nestGroupAliceDN)
		addNestGroupNamedGroup(t, root, dynamicTop, "dynamic-top", dynamicLeaf)
		if got := nestGroupEntryValues(t, root, dynamicTop, "(objectClass=*)", []string{"member"}, false, nil, "member"); !reflect.DeepEqual(got, nestGroupSortedStrings(dynamicLeaf, nestGroupAliceDN)) {
			t.Fatalf("online Add projection = %q", got)
		}
		modify := ldap.NewModifyRequest(dynamicLeaf, nil)
		modify.Replace("member", []string{nestGroupCarolDN})
		if err := root.Modify(modify); err != nil {
			t.Fatalf("Modify(dynamic nestgroup leaf): %v", err)
		}
		if got := nestGroupEntryValues(t, root, dynamicTop, "(objectClass=*)", []string{"member"}, false, nil, "member"); !reflect.DeepEqual(got, nestGroupSortedStrings(dynamicLeaf, nestGroupCarolDN)) {
			t.Fatalf("online Modify projection = %q", got)
		}
		carolMemberOf := nestGroupEntryValues(
			t,
			root,
			nestGroupCarolDN,
			"(objectClass=*)",
			[]string{"memberOf"},
			false,
			nil,
			"memberOf",
		)
		if want := nestGroupSortedStrings(dynamicLeaf, dynamicTop); !reflect.DeepEqual(carolMemberOf, want) {
			t.Fatalf("online Modify memberOf = %q, want %q", carolMemberOf, want)
		}
		if err := root.Del(ldap.NewDelRequest(dynamicLeaf, nil)); err != nil {
			t.Fatalf("Delete(dynamic nestgroup leaf): %v", err)
		}
		assertNestGroupDirectMembers(t, root, dynamicTop, dynamicLeaf)
		if got := nestGroupSearchDNs(
			t,
			root,
			dynamicTop,
			ldap.ScopeBaseObject,
			"(member="+ldap.EscapeFilter(nestGroupCarolDN)+")",
			[]string{"1.1"},
			false,
			0,
			nil,
		); len(got) != 0 {
			t.Fatalf("deleted subgroup remained in filter projection: %q", got)
		}
		if err := root.Del(ldap.NewDelRequest(dynamicTop, nil)); err != nil {
			t.Fatalf("Delete(dynamic nestgroup parent): %v", err)
		}
	})

	t.Run("flags bases instances and overlay re-add", func(t *testing.T) {
		replaceNestGroupFlags(t, configuration, overlayDN, []string{"member-values"})
		assertNestGroupPlacementValues(t, root, leaf, top)
		matches := nestGroupSearchDNs(
			t,
			root,
			nestGroupGroupsDN,
			ldap.ScopeWholeSubtree,
			"(member="+ldap.EscapeFilter(nestGroupAliceDN)+")",
			[]string{"cn"},
			false,
			0,
			nil,
		)
		if want := nestGroupSortedStrings(leaf); !reflect.DeepEqual(matches, want) {
			t.Fatalf("member-values-only filter = %q, want %q", matches, want)
		}
		deleteNestGroupConfigAttribute(t, configuration, overlayDN, "olcNestGroupFlags")
		assertNestGroupDirectMembers(t, root, top, leaf)
		replaceNestGroupFlags(t, configuration, overlayDN, nestGroupAllFlags())

		groups2 := "ou=groups2,dc=example,dc=com"
		groups2Request := ldap.NewAddRequest(groups2, nil)
		groups2Request.Attribute("objectClass", []string{"organizationalUnit"})
		groups2Request.Attribute("ou", []string{"groups2"})
		if err := root.Add(groups2Request); err != nil {
			t.Fatalf("Add(second nestgroup base): %v", err)
		}
		cross := "cn=cross," + groups2
		addNestGroupNamedGroup(t, root, cross, "cross", top)
		assertNestGroupFilterCount(t, root, cross, nestGroupAliceDN, 0)
		baseAdd := ldap.NewModifyRequest(overlayDN, nil)
		baseAdd.Add("olcNestGroupBase", []string{groups2})
		if err := configuration.Modify(baseAdd); err != nil {
			t.Fatalf("Add(olcNestGroupBase): %v", err)
		}
		assertNestGroupFilterCount(t, root, cross, nestGroupAliceDN, 1)
		duplicate := ldap.NewModifyRequest(overlayDN, nil)
		duplicate.Add("olcNestGroupBase", []string{groups2})
		if code := overlayLDAPResultCode(t, configuration.Modify(duplicate)); code != ldap.LDAPResultAttributeOrValueExists {
			t.Fatalf("duplicate olcNestGroupBase result = %d, want %d", code, ldap.LDAPResultAttributeOrValueExists)
		}
		deleteNestGroupConfigAttribute(t, configuration, overlayDN, "olcNestGroupBase")
		assertNestGroupDirectMembers(t, root, top, leaf)
		baseRestore := ldap.NewModifyRequest(overlayDN, nil)
		baseRestore.Add("olcNestGroupBase", []string{nestGroupGroupsDN})
		if err := configuration.Modify(baseRestore); err != nil {
			t.Fatalf("restore olcNestGroupBase: %v", err)
		}
		assertNestGroupPlacementProjection(t, root, leaf, top)

		secondDN := addOpenLDAPNestGroupDynamicOverlay(
			t,
			configuration,
			[]string{nestGroupGroupsDN},
			nestGroupAllFlags(),
		)
		dns := nestGroupConfigurationDNs(t, configuration)
		if len(dns) != 2 {
			t.Fatalf("online nestgroup instance count = %d, want 2: %q", len(dns), dns)
		}
		deleteNestGroupConfigAttribute(t, configuration, overlayDN, "olcNestGroupFlags")
		assertNestGroupPlacementProjection(t, root, leaf, top)
		if err := configuration.Del(ldap.NewDelRequest(secondDN, nil)); err != nil {
			t.Fatalf("Delete(second nestgroup instance): %v", err)
		}
		assertNestGroupDirectMembers(t, root, top, leaf)
		replaceNestGroupFlags(t, configuration, overlayDN, nestGroupAllFlags())
		assertNestGroupPlacementProjection(t, root, leaf, top)

		if err := configuration.Del(ldap.NewDelRequest(overlayDN, nil)); err != nil {
			t.Fatalf("Delete(nestgroup overlay): %v", err)
		}
		assertNestGroupDirectMembers(t, root, top, leaf)
		overlayDN = addOpenLDAPNestGroupDynamicOverlay(
			t,
			configuration,
			[]string{nestGroupGroupsDN},
			nestGroupAllFlags(),
		)
		assertNestGroupPlacementProjection(t, root, leaf, top)
	})

	root.Close()
	configuration.Close()
	server.restart(t)
	root = bindOverlayReferenceClient(t, server.uri, "secret")
	defer root.Close()
	configuration = bindOverlayReferenceClientWithDN(t, server.uri, "cn=config", "configpw")
	defer configuration.Close()
	assertNestGroupPlacementProjection(t, root, leaf, top)
	entries := nestGroupConfigurationEntries(t, configuration)
	if len(entries) != 1 {
		t.Fatalf("restarted nestgroup configuration entries = %d, want 1", len(entries))
	}
	if got := nestGroupSortedStrings(entries[0].GetAttributeValues("olcNestGroupFlags")...); !reflect.DeepEqual(got, nestGroupSortedStrings(nestGroupAllFlags()...)) {
		t.Fatalf("restarted olcNestGroupFlags = %q", got)
	}
	if got := nestGroupSortedStrings(entries[0].GetAttributeValues("olcNestGroupBase")...); !reflect.DeepEqual(got, nestGroupSortedStrings(nestGroupGroupsDN)) {
		t.Fatalf("restarted olcNestGroupBase = %q", got)
	}
}

func assertOpenLDAPNestGroupConversionBug(t *testing.T, tools openLDAPReferenceTools) {
	t.Helper()
	customSchema := writeNestGroupCustomSchema(t)
	server := startOpenLDAPNestGroupDynamicReference(
		t,
		tools,
		customSchema,
		strings.Join([]string{
			"overlay " + nestGroupStaticOverlay(
				"xMember",
				"xMemberOf",
				[]string{nestGroupGroupsDN},
				nestGroupAllFlags(),
			),
			"overlay " + nestGroupMemberOfOverlay("xMember", "xMemberOf", "xGroup"),
			"overlay sssvlv",
			"sssvlv-max 8",
			"sssvlv-maxperconn 8",
		}, "\n"),
	)
	converted := nestGroupConvertedOverlayContents(t, server.configDir)
	for _, missing := range []string{"olcNestGroupMember:", "olcNestGroupMemberOf:"} {
		if strings.Contains(converted, missing) {
			t.Fatalf("OpenLDAP 2.6.13 conversion unexpectedly preserved %s\n%s", missing, converted)
		}
	}
	for _, retained := range []string{
		"olcNestGroupBase: " + nestGroupGroupsDN,
		"olcNestGroupFlags: member-values",
		"olcNestGroupFlags: member-filter",
		"olcNestGroupFlags: memberof-values",
		"olcNestGroupFlags: memberof-filter",
	} {
		if !strings.Contains(converted, retained) {
			t.Fatalf("converted nestgroup config lacks %q\n%s", retained, converted)
		}
	}

	root := bindOverlayReferenceClient(t, server.uri, "secret")
	configuration := bindOverlayReferenceClientWithDN(t, server.uri, "cn=config", "configpw")
	addNestGroupDynamicStandardBase(t, root)
	addOpenLDAPNestGroupCustomEntries(t, root)
	xUser := "uid=x," + nestGroupPeopleDN
	xLeaf := "cn=x-leaf," + nestGroupGroupsDN
	xTop := "cn=x-top," + nestGroupGroupsDN
	if got := nestGroupEntryValues(t, root, xTop, "(objectClass=*)", []string{"xMember"}, false, nil, "xMember"); !reflect.DeepEqual(got, nestGroupSortedStrings(xLeaf)) {
		t.Fatalf("converted custom xMember values = %q, want direct value", got)
	}
	if got := nestGroupSearchDNs(
		t,
		root,
		nestGroupGroupsDN,
		ldap.ScopeWholeSubtree,
		"(xMember="+ldap.EscapeFilter(xUser)+")",
		[]string{"cn"},
		false,
		0,
		nil,
	); !reflect.DeepEqual(got, nestGroupSortedStrings(xLeaf)) {
		t.Fatalf("converted custom xMember filter = %q, want direct group", got)
	}
	entries := nestGroupConfigurationEntries(t, configuration)
	if len(entries) != 1 ||
		len(entries[0].GetAttributeValues("olcNestGroupMember")) != 0 ||
		len(entries[0].GetAttributeValues("olcNestGroupMemberOf")) != 0 {
		t.Fatalf("converted custom attribute state = %#v", entries)
	}
	overlayDN := entries[0].DN
	repair := ldap.NewModifyRequest(overlayDN, nil)
	repair.Add("olcNestGroupMember", []string{"xMember"})
	repair.Add("olcNestGroupMemberOf", []string{"xMemberOf"})
	if err := configuration.Modify(repair); err != nil {
		t.Fatalf("repair converted nestgroup custom attributes: %v", err)
	}
	assertOpenLDAPNestGroupCustom(t, root)

	root.Close()
	configuration.Close()
	server.restart(t)
	root = bindOverlayReferenceClient(t, server.uri, "secret")
	defer root.Close()
	configuration = bindOverlayReferenceClientWithDN(t, server.uri, "cn=config", "configpw")
	defer configuration.Close()
	assertOpenLDAPNestGroupCustom(t, root)
	entries = nestGroupConfigurationEntries(t, configuration)
	if len(entries) != 1 ||
		!reflect.DeepEqual(entries[0].GetAttributeValues("olcNestGroupMember"), []string{"xMember"}) ||
		!reflect.DeepEqual(entries[0].GetAttributeValues("olcNestGroupMemberOf"), []string{"xMemberOf"}) {
		t.Fatalf("restarted repaired custom attribute state = %#v", entries)
	}
}

type openLDAPNestGroupDynamicReference struct {
	tools     openLDAPReferenceTools
	configDir string
	uri       string
	address   string
	logs      bytes.Buffer
	command   *exec.Cmd
	wait      chan error
}

func startOpenLDAPNestGroupDynamicReference(
	t *testing.T,
	tools openLDAPReferenceTools,
	customSchema,
	overlays string,
) *openLDAPNestGroupDynamicReference {
	t.Helper()
	root := t.TempDir()
	configDir := filepath.Join(root, "slapd.d")
	databaseDir := filepath.Join(root, "db")
	for _, path := range []string{configDir, databaseDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("create OpenLDAP nestgroup path %s: %v", path, err)
		}
	}
	customInclude := ""
	if customSchema != "" {
		customInclude = "include " + customSchema
	}
	configPath := filepath.Join(root, "slapd.conf")
	config := fmt.Sprintf(
		`include %s
include %s
include %s
%s
pidfile %s
argsfile %s

database config
rootdn "cn=config"
rootpw configpw
access to * by dn.exact="cn=config" manage by * none

database mdb
maxsize 1073741824
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
directory %s
index objectClass eq
index entryUUID,entryCSN eq
access to attrs=userPassword by self write by anonymous auth by * none
access to * by * read
%s
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		customInclude,
		filepath.Join(root, "slapd.pid"),
		filepath.Join(root, "slapd.args"),
		databaseDir,
		overlays,
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write dynamic nestgroup slapd.conf: %v", err)
	}
	emptyLDIF := filepath.Join(root, "empty.ldif")
	if err := os.WriteFile(emptyLDIF, nil, 0o600); err != nil {
		t.Fatalf("write dynamic nestgroup empty LDIF: %v", err)
	}
	command := exec.Command(
		tools.slapadd,
		"-q",
		"-f",
		configPath,
		"-n",
		"1",
		"-l",
		emptyLDIF,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("initialize dynamic nestgroup database: %v\n%s", err, output)
	}
	command = exec.Command(
		tools.slapd,
		"-Ttest",
		"-f",
		configPath,
		"-F",
		configDir,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("convert dynamic nestgroup configuration: %v\n%s", err, output)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve dynamic nestgroup port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release dynamic nestgroup port: %v", err)
	}
	server := &openLDAPNestGroupDynamicReference{
		tools:     tools,
		configDir: configDir,
		uri:       "ldap://" + address,
		address:   address,
	}
	server.start(t)
	t.Cleanup(func() { server.stop(t) })
	return server
}

func (server *openLDAPNestGroupDynamicReference) start(t *testing.T) {
	t.Helper()
	if server.command != nil {
		t.Fatal("dynamic OpenLDAP nestgroup server is already running")
	}
	server.command = exec.Command(
		server.tools.slapd,
		"-F",
		server.configDir,
		"-h",
		server.uri,
		"-d",
		"0",
	)
	server.command.Stdout = &server.logs
	server.command.Stderr = &server.logs
	if err := server.command.Start(); err != nil {
		server.command = nil
		t.Fatalf("start dynamic OpenLDAP nestgroup server: %v", err)
	}
	server.wait = make(chan error, 1)
	go func(command *exec.Cmd, wait chan<- error) {
		wait <- command.Wait()
	}(server.command, server.wait)
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-server.wait:
			server.command = nil
			server.wait = nil
			t.Fatalf("dynamic OpenLDAP nestgroup server exited: %v\n%s", err, openLDAPReferenceLogTail(server.logs.Bytes()))
		default:
		}
		connection, err := net.DialTimeout("tcp", server.address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		if time.Now().After(deadline) {
			server.stop(t)
			t.Fatalf("dynamic OpenLDAP nestgroup server did not start: %v\n%s", err, openLDAPReferenceLogTail(server.logs.Bytes()))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (server *openLDAPNestGroupDynamicReference) stop(t *testing.T) {
	t.Helper()
	if server.command == nil {
		return
	}
	command := server.command
	wait := server.wait
	server.command = nil
	server.wait = nil
	if command.Process != nil {
		_ = command.Process.Signal(os.Interrupt)
	}
	select {
	case <-wait:
		return
	case <-time.After(5 * time.Second):
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		<-wait
		t.Errorf("dynamic OpenLDAP nestgroup server required forced shutdown")
	}
}

func (server *openLDAPNestGroupDynamicReference) restart(t *testing.T) {
	t.Helper()
	server.stop(t)
	server.logs.WriteString("\n--- restart ---\n")
	server.start(t)
}

func addNestGroupDynamicStandardBase(t *testing.T, client *ldap.Conn) {
	t.Helper()
	entries := []*ldap.AddRequest{
		func() *ldap.AddRequest {
			request := ldap.NewAddRequest("dc=example,dc=com", nil)
			request.Attribute("objectClass", []string{"domain"})
			request.Attribute("dc", []string{"example"})
			return request
		}(),
		func() *ldap.AddRequest {
			request := ldap.NewAddRequest(nestGroupPeopleDN, nil)
			request.Attribute("objectClass", []string{"organizationalUnit"})
			request.Attribute("ou", []string{"people"})
			return request
		}(),
	}
	for _, request := range entries {
		if err := client.Add(request); err != nil {
			t.Fatalf("Add(dynamic nestgroup fixture %s): %v", request.DN, err)
		}
	}
	for _, person := range []struct {
		dn, uid, cn string
	}{
		{dn: nestGroupAliceDN, uid: "alice", cn: "Alice"},
		{dn: nestGroupBobDN, uid: "bob", cn: "Bob"},
		{dn: nestGroupCarolDN, uid: "carol", cn: "Carol"},
	} {
		request := ldap.NewAddRequest(person.dn, nil)
		request.Attribute("objectClass", []string{"inetOrgPerson"})
		request.Attribute("uid", []string{person.uid})
		request.Attribute("cn", []string{person.cn})
		request.Attribute("sn", []string{person.cn})
		if err := client.Add(request); err != nil {
			t.Fatalf("Add(dynamic nestgroup person %s): %v", person.dn, err)
		}
	}
}

func addNestGroupNamedGroup(
	t *testing.T,
	client *ldap.Conn,
	dn,
	cn,
	member string,
) {
	t.Helper()
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"groupOfNames"})
	request.Attribute("cn", []string{cn})
	request.Attribute("member", []string{member})
	if err := client.Add(request); err != nil {
		t.Fatalf("Add(nestgroup %s): %v", dn, err)
	}
}

func addOpenLDAPNestGroupDynamicOverlay(
	t *testing.T,
	configuration *ldap.Conn,
	bases,
	flags []string,
) string {
	t.Helper()
	request := ldap.NewAddRequest(
		"olcOverlay=nestgroup,olcDatabase={1}mdb,cn=config",
		nil,
	)
	request.Attribute("objectClass", []string{"olcOverlayConfig", "olcNestGroupConfig"})
	request.Attribute("olcOverlay", []string{"nestgroup"})
	if len(bases) > 0 {
		request.Attribute("olcNestGroupBase", bases)
	}
	if len(flags) > 0 {
		request.Attribute("olcNestGroupFlags", flags)
	}
	if err := configuration.Add(request); err != nil {
		t.Fatalf("Add(dynamic nestgroup overlay): %v", err)
	}
	dns := nestGroupConfigurationDNs(t, configuration)
	if len(dns) == 0 {
		t.Fatal("dynamic nestgroup overlay was not visible in cn=config")
	}
	return dns[len(dns)-1]
}

func nestGroupConfigurationDNs(t *testing.T, configuration *ldap.Conn) []string {
	t.Helper()
	entries := nestGroupConfigurationEntries(t, configuration)
	dns := make([]string, len(entries))
	for index, entry := range entries {
		dns[index] = entry.DN
	}
	sort.Strings(dns)
	return dns
}

func nestGroupConfigurationEntries(
	t *testing.T,
	configuration *ldap.Conn,
) []*ldap.Entry {
	t.Helper()
	result, err := configuration.Search(ldap.NewSearchRequest(
		"olcDatabase={1}mdb,cn=config",
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=olcNestGroupConfig)",
		[]string{
			"olcOverlay",
			"olcNestGroupMember",
			"olcNestGroupMemberOf",
			"olcNestGroupBase",
			"olcNestGroupFlags",
		},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(nestgroup cn=config): %v", err)
	}
	sort.Slice(result.Entries, func(left, right int) bool {
		return result.Entries[left].DN < result.Entries[right].DN
	})
	return result.Entries
}

func replaceNestGroupFlags(
	t *testing.T,
	configuration *ldap.Conn,
	overlayDN string,
	flags []string,
) {
	t.Helper()
	request := ldap.NewModifyRequest(overlayDN, nil)
	request.Replace("olcNestGroupFlags", flags)
	if err := configuration.Modify(request); err != nil {
		t.Fatalf("Replace(olcNestGroupFlags=%q): %v", flags, err)
	}
}

func deleteNestGroupConfigAttribute(
	t *testing.T,
	configuration *ldap.Conn,
	overlayDN,
	attribute string,
) {
	t.Helper()
	request := ldap.NewModifyRequest(overlayDN, nil)
	request.Delete(attribute, nil)
	if err := configuration.Modify(request); err != nil {
		t.Fatalf("Delete(%s from %s): %v", attribute, overlayDN, err)
	}
}

func assertNestGroupDirectMembers(
	t *testing.T,
	client *ldap.Conn,
	top,
	leaf string,
) {
	t.Helper()
	got := nestGroupEntryValues(
		t,
		client,
		top,
		"(objectClass=*)",
		[]string{"member"},
		false,
		nil,
		"member",
	)
	if want := nestGroupSortedStrings(leaf); !reflect.DeepEqual(got, want) {
		t.Fatalf("direct nestgroup members = %q, want %q", got, want)
	}
}

func assertNestGroupPlacementValues(
	t *testing.T,
	client *ldap.Conn,
	leaf,
	top string,
) {
	t.Helper()
	got := nestGroupEntryValues(
		t,
		client,
		top,
		"(objectClass=*)",
		[]string{"member"},
		false,
		nil,
		"member",
	)
	if want := nestGroupSortedStrings(leaf, nestGroupAliceDN); !reflect.DeepEqual(got, want) {
		t.Fatalf("nestgroup projected values = %q, want %q", got, want)
	}
}

func assertNestGroupFilterCount(
	t *testing.T,
	client *ldap.Conn,
	base,
	member string,
	want int,
) {
	t.Helper()
	got := nestGroupSearchDNs(
		t,
		client,
		base,
		ldap.ScopeBaseObject,
		"(member="+ldap.EscapeFilter(member)+")",
		[]string{"1.1"},
		false,
		0,
		nil,
	)
	if len(got) != want {
		t.Fatalf("nestgroup filter %s under %s returned %q, want %d entries", member, base, got, want)
	}
}

func nestGroupConvertedOverlayContents(t *testing.T, configDir string) string {
	t.Helper()
	var contents string
	err := filepath.WalkDir(configDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".ldif") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		unfolded := strings.ReplaceAll(string(data), "\n ", "")
		if strings.Contains(unfolded, "olcNestGroupConfig") {
			contents += unfolded
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk converted nestgroup configuration: %v", err)
	}
	if contents == "" {
		t.Fatal("converted slapd.d has no olcNestGroupConfig entry")
	}
	return contents
}
