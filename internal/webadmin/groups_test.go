package webadmin

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestHandleGroupsListsSupportedGroupKinds(t *testing.T) {
	t.Parallel()
	client := &fakeClient{searchFunc: func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if request.BaseDN != "ou=groups,dc=example,dc=com" || request.Scope != ldap.ScopeWholeSubtree ||
			request.Filter != groupObjectFilter || request.SizeLimit != 7 || !request.EnforceSizeLimit ||
			request.TimeLimit != 15 || strings.Join(request.Attributes, ",") != strings.Join(groupSearchAttributes, ",") {
			t.Fatalf("group search request = %#v", request)
		}
		return &ldap.SearchResult{Entries: []*ldap.Entry{
			ldap.NewEntry("cn=staff,ou=groups,dc=example,dc=com", map[string][]string{
				"objectClass": {"top", "groupOfNames"},
				"member":      {"uid=Alice,ou=people,dc=example,dc=com"},
			}),
			ldap.NewEntry("cn=owners,ou=groups,dc=example,dc=com", map[string][]string{
				"OBJECTCLASS":  {"groupOfUniqueNames"},
				"UNIQUEMEMBER": {"uid=bob,ou=people,dc=example,dc=com#'101'B"},
			}),
			ldap.NewEntry("cn=ops,ou=groups,dc=example,dc=com", map[string][]string{
				"objectClass": {"posixGroup"}, "memberUid": {"alice", "Bob"},
			}),
		}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxSearchSize = 7
	})
	authenticated := loginTestSession(t, application, "dn")

	response := performGroupsRequest(t, application, http.MethodGet,
		"/api/groups?base_dn="+url.QueryEscape("ou=groups,dc=example,dc=com"),
		nil, authenticated.cookie, "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET groups status = %d, body = %s", response.Code, response.Body.String())
	}
	var body groupsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode groups response: %v", err)
	}
	if len(body.Groups) != 3 || body.Groups[0].Type != "groupOfNames" ||
		len(body.Groups[0].Member) != 1 || body.Groups[0].Member[0] != "uid=Alice,ou=people,dc=example,dc=com" ||
		body.Groups[1].Type != "groupOfUniqueNames" || body.Groups[1].UniqueMember[0] != "uid=bob,ou=people,dc=example,dc=com#'101'B" ||
		body.Groups[2].Type != "posixGroup" || strings.Join(body.Groups[2].MemberUID, ",") != "alice,Bob" {
		t.Fatalf("groups response = %#v", body)
	}
}

func TestHandleGroupsExpandsNestedMembersWithCyclesAndDeduplication(t *testing.T) {
	t.Parallel()
	rootDN := "cn=Root,ou=groups,dc=example,dc=com"
	childDN := "cn=Child,ou=groups,dc=example,dc=com"
	sharedDN := "cn=Shared,ou=groups,dc=example,dc=com"
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{
			ldap.NewEntry(rootDN, map[string][]string{
				"objectClass": {"groupOfNames", "posixGroup"},
				"member": {
					childDN,
					sharedDN,
					"UID=Alice,ou=people,dc=example,dc=com",
					"uid=Alice,OU=people,DC=example,DC=com",
				},
				"memberUid": {"LocalUser", "localuser", "LocalUser"},
			}),
			ldap.NewEntry(childDN, map[string][]string{
				"objectClass": {"groupOfUniqueNames"},
				"uniqueMember": {
					rootDN,
					sharedDN + "#'01'B",
					"uid=Bob,ou=people,dc=example,dc=com#'101'B",
					"uid=Bob,ou=people,dc=example,dc=com#'111'B",
				},
			}),
			ldap.NewEntry(sharedDN, map[string][]string{
				"objectClass": {"posixGroup"}, "memberUid": {"service"},
			}),
		}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	path := "/api/groups?base_dn=" + url.QueryEscape("ou=groups,dc=example,dc=com") +
		"&dn=" + url.QueryEscape("CN=Root,OU=groups,DC=example,DC=com") + "&nested=true"

	response := performGroupsRequest(t, application, http.MethodGet, path, nil, authenticated.cookie, "")
	if response.Code != http.StatusOK {
		t.Fatalf("nested GET status = %d, body = %s", response.Code, response.Body.String())
	}
	var body groupsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode nested response: %v", err)
	}
	if len(body.Groups) != 1 || body.Nested == nil {
		t.Fatalf("nested response = %#v", body)
	}
	nested := body.Nested
	if nested.RootDN != rootDN || strings.Join(nested.Groups, "|") != strings.Join([]string{rootDN, childDN, sharedDN}, "|") {
		t.Fatalf("nested groups = %#v", nested)
	}
	if len(nested.Member) != 1 || nested.Member[0] != "UID=Alice,ou=people,dc=example,dc=com" {
		t.Fatalf("nested member values = %#v", nested.Member)
	}
	if strings.Join(nested.UniqueMember, "|") != strings.Join([]string{
		"uid=Bob,ou=people,dc=example,dc=com#'101'B",
		"uid=Bob,ou=people,dc=example,dc=com#'111'B",
	}, "|") {
		t.Fatalf("nested uniqueMember values = %#v", nested.UniqueMember)
	}
	if strings.Join(nested.MemberUID, ",") != "service,LocalUser,localuser" {
		t.Fatalf("nested memberUid values = %#v", nested.MemberUID)
	}
	if len(nested.Cycles) != 1 || nested.Cycles[0] != rootDN {
		t.Fatalf("nested cycles = %#v", nested.Cycles)
	}
}

func TestHandleGroupsFindsDirectDNAndUIDMemberships(t *testing.T) {
	t.Parallel()
	targetDN := "uid=Alice,ou=people,dc=example,dc=com"
	typedTargetDN := "UID=Alice,OU=people,DC=example,DC=com"
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{
			ldap.NewEntry("cn=unique,ou=groups,dc=example,dc=com", map[string][]string{
				"objectClass":  {"groupOfUniqueNames"},
				"uniqueMember": {targetDN + "#'101'B"},
			}),
			ldap.NewEntry("cn=none,ou=groups,dc=example,dc=com", map[string][]string{
				"objectClass": {"groupOfNames"},
				"member":      {"uid=bob,ou=people,dc=example,dc=com"},
			}),
			ldap.NewEntry("cn=posix,ou=groups,dc=example,dc=com", map[string][]string{
				"objectClass": {"posixGroup"}, "memberUid": {"Alice"},
			}),
			ldap.NewEntry("cn=names,ou=groups,dc=example,dc=com", map[string][]string{
				"objectClass": {"groupOfNames"}, "member": {targetDN},
			}),
			ldap.NewEntry("cn=hybrid,ou=groups,dc=example,dc=com", map[string][]string{
				"objectClass": {"groupOfNames", "posixGroup"},
				"member":      {typedTargetDN},
				"memberUid":   {"Alice"},
			}),
		}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	requestedDN := typedTargetDN
	path := "/api/groups?base_dn=" + url.QueryEscape("ou=groups,dc=example,dc=com") +
		"&member_dn=" + url.QueryEscape(requestedDN) + "&member_uid=Alice"

	response := performGroupsRequest(t, application, http.MethodGet, path, nil, authenticated.cookie, "")
	if response.Code != http.StatusOK {
		t.Fatalf("membership GET status = %d, body = %s", response.Code, response.Body.String())
	}
	var body groupsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode membership response: %v", err)
	}
	if body.Memberships == nil || body.Nested != nil {
		t.Fatalf("membership response = %#v", body)
	}
	memberships := body.Memberships
	if memberships.MemberDN != requestedDN || memberships.MemberUID != "Alice" || memberships.Cycles == nil || len(memberships.Cycles) != 0 {
		t.Fatalf("membership selector or cycles = %#v", memberships)
	}
	wantDNs := []string{
		"cn=hybrid,ou=groups,dc=example,dc=com",
		"cn=names,ou=groups,dc=example,dc=com",
		"cn=posix,ou=groups,dc=example,dc=com",
		"cn=unique,ou=groups,dc=example,dc=com",
	}
	if len(memberships.Groups) != len(wantDNs) || len(body.Groups) != len(wantDNs) {
		t.Fatalf("matched groups = %#v, outer = %#v", memberships.Groups, body.Groups)
	}
	for index, wantDN := range wantDNs {
		if memberships.Groups[index].DN != wantDN || body.Groups[index].DN != wantDN ||
			!memberships.Groups[index].Direct || memberships.Groups[index].Depth != 0 ||
			memberships.Groups[index].ViaDN != "" {
			t.Fatalf("membership group %d = %#v, outer = %#v", index, memberships.Groups[index], body.Groups[index])
		}
	}
	assertGroupMembershipReferences(t, memberships.Groups[0], []groupMembershipReference{
		{Attribute: "member", Value: typedTargetDN},
		{Attribute: "memberUid", Value: "Alice"},
	})
	assertGroupMembershipReferences(t, memberships.Groups[1], []groupMembershipReference{{Attribute: "member", Value: targetDN}})
	assertGroupMembershipReferences(t, memberships.Groups[2], []groupMembershipReference{{Attribute: "memberUid", Value: "Alice"}})
	assertGroupMembershipReferences(t, memberships.Groups[3], []groupMembershipReference{{Attribute: "uniqueMember", Value: targetDN + "#'101'B"}})
}

func TestHandleGroupsMembershipPreservesCaseExactDNValues(t *testing.T) {
	t.Parallel()
	requestedDN := "CASEEXACTNAME=alice+UID=100,OU=people,DC=example,DC=com"
	storedMatch := "uid=100+caseExactName=alice,ou=people,dc=example,dc=com"
	storedDifferent := "uid=100+caseExactName=Alice,ou=people,dc=example,dc=com"
	matchingGroupDN := "cn=matching,ou=groups,dc=example,dc=com"
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{
			ldap.NewEntry("cn=different,ou=groups,dc=example,dc=com", map[string][]string{
				"objectClass": {"groupOfNames"}, "member": {storedDifferent},
			}),
			ldap.NewEntry(matchingGroupDN, map[string][]string{
				"objectClass": {"groupOfNames"}, "member": {storedMatch},
			}),
		}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	response := performGroupsRequest(t, application, http.MethodGet,
		"/api/groups?base_dn="+url.QueryEscape("ou=groups,dc=example,dc=com")+
			"&member_dn="+url.QueryEscape(requestedDN), nil, authenticated.cookie, "")
	if response.Code != http.StatusOK {
		t.Fatalf("case-exact membership GET status = %d, body = %s", response.Code, response.Body.String())
	}
	var body groupsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode case-exact membership response: %v", err)
	}
	if body.Memberships == nil || len(body.Memberships.Groups) != 1 || len(body.Groups) != 1 ||
		body.Memberships.Groups[0].DN != matchingGroupDN || body.Groups[0].DN != matchingGroupDN {
		t.Fatalf("case-exact membership response = %#v", body)
	}
	assertGroupMembershipReferences(t, body.Memberships.Groups[0], []groupMembershipReference{{
		Attribute: "member", Value: storedMatch,
	}})
}

func TestHandleGroupsMembershipTreatsInvalidUniqueMemberBitSuffixAsDN(t *testing.T) {
	t.Parallel()
	storedDN := "uid=alice,dc=example,dc=com#'102'B"
	groupDN := "cn=fallback,dc=example,dc=com"
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(groupDN, map[string][]string{
			"objectClass": {"groupOfUniqueNames"}, "uniqueMember": {storedDN},
		})}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	response := performGroupsRequest(t, application, http.MethodGet,
		"/api/groups?base_dn="+url.QueryEscape("dc=example,dc=com")+
			"&member_dn="+url.QueryEscape(storedDN), nil, authenticated.cookie, "")
	if response.Code != http.StatusOK {
		t.Fatalf("uniqueMember fallback GET status = %d, body = %s", response.Code, response.Body.String())
	}
	var body groupsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode uniqueMember fallback response: %v", err)
	}
	if body.Memberships == nil || len(body.Memberships.Groups) != 1 || body.Memberships.Groups[0].DN != groupDN {
		t.Fatalf("uniqueMember fallback response = %#v", body)
	}
	assertGroupMembershipReferences(t, body.Memberships.Groups[0], []groupMembershipReference{{
		Attribute: "uniqueMember", Value: storedDN,
	}})
}

func TestHandleGroupsMembershipAcceptsUniqueMemberEmptyDNWithUID(t *testing.T) {
	t.Parallel()
	parsed, identity, err := parseGroupMember("#'1'B", true)
	if err != nil {
		t.Fatalf("parse empty-DN uniqueMember: %v", err)
	}
	if parsed == nil || len(parsed.RDNs) != 0 || identity != "#'1'B" || groupDNKey(parsed) != "" ||
		groupDNKey(parsed) != groupDNKey(&ldap.DN{}) {
		t.Fatalf("empty-DN uniqueMember = %#v, identity = %q, key = %q", parsed, identity, groupDNKey(parsed))
	}

	targetDN := "uid=alice,dc=example,dc=com"
	directGroupDN := "cn=direct,dc=example,dc=com"
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{
			ldap.NewEntry("cn=empty-dn,dc=example,dc=com", map[string][]string{
				"objectClass": {"groupOfUniqueNames"}, "uniqueMember": {"#'1'B"},
			}),
			ldap.NewEntry(directGroupDN, map[string][]string{
				"objectClass": {"groupOfNames"}, "member": {targetDN},
			}),
		}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	response := performGroupsRequest(t, application, http.MethodGet,
		"/api/groups?base_dn="+url.QueryEscape("dc=example,dc=com")+
			"&member_dn="+url.QueryEscape(targetDN)+"&nested=true", nil, authenticated.cookie, "")
	if response.Code != http.StatusOK {
		t.Fatalf("empty-DN uniqueMember GET status = %d, body = %s", response.Code, response.Body.String())
	}
	var body groupsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode empty-DN uniqueMember response: %v", err)
	}
	if body.Memberships == nil || len(body.Memberships.Groups) != 1 ||
		body.Memberships.Groups[0].DN != directGroupDN {
		t.Fatalf("empty-DN uniqueMember response = %#v", body)
	}
}

func TestHandleGroupsFindsNestedParentMembershipsByShortestPath(t *testing.T) {
	t.Parallel()
	targetDN := "uid=alice,ou=people,dc=example,dc=com"
	alphaDN := "cn=alpha,ou=groups,dc=example,dc=com"
	bravoDN := "cn=bravo,ou=groups,dc=example,dc=com"
	charlieDN := "cn=charlie,ou=groups,dc=example,dc=com"
	deltaDN := "cn=delta,ou=groups,dc=example,dc=com"
	echoDN := "cn=echo,ou=groups,dc=example,dc=com"
	typedTargetDN := "UID=alice,OU=people,DC=example,DC=com"
	typedAlphaDN := "CN=alpha,OU=groups,DC=example,DC=com"
	bravoReference := "CN=bravo,OU=groups,DC=example,DC=com"
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{
			ldap.NewEntry(echoDN, map[string][]string{
				"objectClass": {"groupOfNames"}, "member": {deltaDN},
			}),
			ldap.NewEntry(deltaDN, map[string][]string{
				"objectClass":  {"groupOfNames", "groupOfUniqueNames"},
				"member":       {bravoReference, charlieDN},
				"uniqueMember": {bravoDN + "#'01'B"},
			}),
			ldap.NewEntry(charlieDN, map[string][]string{
				"objectClass":  {"groupOfUniqueNames"},
				"uniqueMember": {typedAlphaDN + "#'11'B"},
			}),
			ldap.NewEntry(alphaDN, map[string][]string{
				"objectClass": {"groupOfNames"}, "member": {targetDN, echoDN},
			}),
			ldap.NewEntry(bravoDN, map[string][]string{
				"objectClass": {"groupOfNames"}, "member": {typedAlphaDN},
			}),
			ldap.NewEntry("cn=unrelated,ou=groups,dc=example,dc=com", map[string][]string{
				"objectClass": {"posixGroup"}, "memberUid": {"other"},
			}),
		}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	path := "/api/groups?base_dn=" + url.QueryEscape("ou=groups,dc=example,dc=com") +
		"&member_dn=" + url.QueryEscape(typedTargetDN) + "&nested=true"

	response := performGroupsRequest(t, application, http.MethodGet, path, nil, authenticated.cookie, "")
	if response.Code != http.StatusOK {
		t.Fatalf("nested membership GET status = %d, body = %s", response.Code, response.Body.String())
	}
	var body groupsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode nested membership response: %v", err)
	}
	if body.Memberships == nil {
		t.Fatalf("nested memberships missing: %#v", body)
	}
	want := []struct {
		dn, via string
		depth   int
		direct  bool
	}{
		{dn: alphaDN, depth: 0, direct: true},
		{dn: bravoDN, via: alphaDN, depth: 1},
		{dn: charlieDN, via: alphaDN, depth: 1},
		{dn: deltaDN, via: bravoDN, depth: 2},
		{dn: echoDN, via: deltaDN, depth: 3},
	}
	if len(body.Memberships.Groups) != len(want) || len(body.Groups) != len(want) {
		t.Fatalf("nested memberships = %#v, outer = %#v", body.Memberships.Groups, body.Groups)
	}
	for index, expected := range want {
		actual := body.Memberships.Groups[index]
		if actual.DN != expected.dn || actual.ViaDN != expected.via || actual.Depth != expected.depth ||
			actual.Direct != expected.direct || body.Groups[index].DN != expected.dn {
			t.Fatalf("nested membership %d = %#v, want %#v", index, actual, expected)
		}
	}
	assertGroupMembershipReferences(t, body.Memberships.Groups[0], []groupMembershipReference{{Attribute: "member", Value: targetDN}})
	assertGroupMembershipReferences(t, body.Memberships.Groups[1], []groupMembershipReference{{Attribute: "member", Value: typedAlphaDN}})
	assertGroupMembershipReferences(t, body.Memberships.Groups[2], []groupMembershipReference{{Attribute: "uniqueMember", Value: typedAlphaDN + "#'11'B"}})
	assertGroupMembershipReferences(t, body.Memberships.Groups[3], []groupMembershipReference{
		{Attribute: "member", Value: bravoReference},
		{Attribute: "uniqueMember", Value: bravoDN + "#'01'B"},
	})
	assertGroupMembershipReferences(t, body.Memberships.Groups[4], []groupMembershipReference{{Attribute: "member", Value: deltaDN}})
	if strings.Join(body.Memberships.Cycles, "|") != alphaDN {
		t.Fatalf("membership cycles = %#v", body.Memberships.Cycles)
	}
}

func TestHandleGroupsMemberUIDMatchingIsExactAndReturnsEmptyArrays(t *testing.T) {
	t.Parallel()
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(
			"cn=posix,dc=example,dc=com",
			map[string][]string{"objectClass": {"posixGroup"}, "memberUid": {"Alice"}},
		)}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	response := performGroupsRequest(t, application, http.MethodGet,
		"/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&member_uid=alice&nested=true",
		nil, authenticated.cookie, "")
	if response.Code != http.StatusOK {
		t.Fatalf("memberUid GET status = %d, body = %s", response.Code, response.Body.String())
	}
	var body groupsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode memberUid response: %v", err)
	}
	if body.Memberships == nil || body.Memberships.MemberDN != "" || body.Memberships.MemberUID != "alice" ||
		body.Groups == nil || len(body.Groups) != 0 || body.Memberships.Groups == nil || len(body.Memberships.Groups) != 0 ||
		body.Memberships.Cycles == nil || len(body.Memberships.Cycles) != 0 {
		t.Fatalf("empty memberships response = %#v", body)
	}
}

func TestHandleGroupsPatchUsesOneAtomicLDAPModify(t *testing.T) {
	t.Parallel()
	groupDN := "cn=staff,ou=groups,dc=example,dc=com"
	client := &fakeClient{
		searchFunc: func(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if request.BaseDN != groupDN || request.Scope != ldap.ScopeBaseObject || request.SizeLimit != 1 ||
				request.Filter != groupObjectFilter || !request.EnforceSizeLimit {
				t.Fatalf("group lookup = %#v", request)
			}
			return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(groupDN, map[string][]string{
				"objectClass": {"groupOfNames"},
			})}}, nil
		},
		modifyFunc: func(request *ldap.ModifyRequest) error {
			if request.DN != groupDN || len(request.Changes) != 3 {
				t.Fatalf("modify request = %#v", request)
			}
			assertLDAPChange(t, request.Changes[0], ldap.AddAttribute, "member", []string{"uid=alice,dc=example,dc=com"})
			assertLDAPChange(t, request.Changes[1], ldap.DeleteAttribute, "uniqueMember", []string{
				"uid=old,dc=example,dc=com#'1'B", "uid=old,dc=example,dc=com#'0'B",
			})
			assertLDAPChange(t, request.Changes[2], ldap.AddAttribute, "memberUid", []string{"local-user"})
			return nil
		},
	}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
	authenticated := loginTestSession(t, application, "dn")
	response := performGroupsRequest(t, application, http.MethodPatch, "/api/groups", map[string]any{
		"dn": groupDN,
		"changes": []map[string]any{
			{"operation": "ADD", "attribute": "MEMBER", "values": []string{"uid=alice,dc=example,dc=com"}},
			{"operation": "remove", "attribute": "uniqueMember", "values": []string{
				"uid=old,dc=example,dc=com#'1'B", "uid=old,dc=example,dc=com#'0'B",
			}},
			{"operation": "add", "attribute": "memberUid", "values": []string{"local-user"}},
		},
	}, authenticated.cookie, authenticated.csrf)
	if response.Code != http.StatusOK {
		t.Fatalf("PATCH groups status = %d, body = %s", response.Code, response.Body.String())
	}
	var body groupPatchResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode patch response: %v", err)
	}
	if body.DN != groupDN || !body.Atomic || len(body.Results) != 3 {
		t.Fatalf("patch response = %#v", body)
	}
	for _, result := range body.Results {
		if result.Status != "applied" {
			t.Fatalf("patch result = %#v", result)
		}
	}
	client.mu.Lock()
	modifyCount := len(client.modifies)
	client.mu.Unlock()
	if modifyCount != 1 {
		t.Fatalf("LDAP modify count = %d", modifyCount)
	}
}

func TestHandleGroupsSecurityAndValidationErrorsAvoidModify(t *testing.T) {
	t.Parallel()
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(
			"cn=staff,dc=example,dc=com", map[string][]string{"objectClass": {"groupOfNames"}},
		)}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxAttributes = 2
	})
	authenticated := loginTestSession(t, application, "dn")

	tests := []struct {
		name   string
		method string
		path   string
		body   any
		cookie *http.Cookie
		csrf   string
		origin string
		status int
	}{
		{name: "unauthenticated", method: http.MethodGet, path: "/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom", status: http.StatusUnauthorized},
		{name: "method", method: http.MethodPost, path: "/api/groups", cookie: authenticated.cookie, status: http.StatusMethodNotAllowed},
		{name: "unknown query", method: http.MethodGet, path: "/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&limit=1", cookie: authenticated.cookie, status: http.StatusBadRequest},
		{name: "duplicate query", method: http.MethodGet, path: "/api/groups?base_dn=a&base_dn=b", cookie: authenticated.cookie, status: http.StatusBadRequest},
		{name: "nested without selector", method: http.MethodGet, path: "/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&nested=true", cookie: authenticated.cookie, status: http.StatusBadRequest},
		{name: "empty nested", method: http.MethodGet, path: "/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&nested=", cookie: authenticated.cookie, status: http.StatusBadRequest},
		{name: "empty member DN", method: http.MethodGet, path: "/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&member_dn=", cookie: authenticated.cookie, status: http.StatusBadRequest},
		{name: "empty member UID", method: http.MethodGet, path: "/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&member_uid=", cookie: authenticated.cookie, status: http.StatusBadRequest},
		{name: "invalid member DN", method: http.MethodGet, path: "/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&member_dn=not-a-dn", cookie: authenticated.cookie, status: http.StatusBadRequest},
		{name: "invalid member UID", method: http.MethodGet, path: "/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&member_uid=%20", cookie: authenticated.cookie, status: http.StatusBadRequest},
		{name: "dn and member DN", method: http.MethodGet, path: "/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&dn=cn%3Dx%2Cdc%3Dexample%2Cdc%3Dcom&member_dn=uid%3Da%2Cdc%3Dexample%2Cdc%3Dcom", cookie: authenticated.cookie, status: http.StatusBadRequest},
		{name: "dn and member UID", method: http.MethodGet, path: "/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&dn=cn%3Dx%2Cdc%3Dexample%2Cdc%3Dcom&member_uid=alice", cookie: authenticated.cookie, status: http.StatusBadRequest},
		{name: "dn outside base", method: http.MethodGet, path: "/api/groups?base_dn=ou%3Dgroups%2Cdc%3Dexample%2Cdc%3Dcom&dn=cn%3Dx%2Cou%3Dother%2Cdc%3Dexample%2Cdc%3Dcom", cookie: authenticated.cookie, status: http.StatusBadRequest},
		{name: "missing csrf", method: http.MethodPatch, path: "/api/groups", body: validGroupPatchBody(), cookie: authenticated.cookie, status: http.StatusForbidden},
		{name: "bad origin", method: http.MethodPatch, path: "/api/groups", body: validGroupPatchBody(), cookie: authenticated.cookie, csrf: authenticated.csrf, origin: "https://evil.example", status: http.StatusForbidden},
		{name: "unknown JSON", method: http.MethodPatch, path: "/api/groups", body: map[string]any{"dn": "cn=staff,dc=example,dc=com", "changes": []any{}, "extra": true}, cookie: authenticated.cookie, csrf: authenticated.csrf, status: http.StatusBadRequest},
		{name: "too many changes", method: http.MethodPatch, path: "/api/groups", body: map[string]any{"dn": "cn=staff,dc=example,dc=com", "changes": []map[string]any{{"operation": "add", "attribute": "memberUid", "values": []string{"a"}}, {"operation": "add", "attribute": "memberUid", "values": []string{"b"}}, {"operation": "add", "attribute": "memberUid", "values": []string{"c"}}}}, cookie: authenticated.cookie, csrf: authenticated.csrf, status: http.StatusBadRequest},
		{name: "invalid operation", method: http.MethodPatch, path: "/api/groups", body: patchBody("replace", "memberUid", "alice"), cookie: authenticated.cookie, csrf: authenticated.csrf, status: http.StatusBadRequest},
		{name: "invalid attribute", method: http.MethodPatch, path: "/api/groups", body: patchBody("add", "owner", "uid=alice,dc=example,dc=com"), cookie: authenticated.cookie, csrf: authenticated.csrf, status: http.StatusBadRequest},
		{name: "invalid member DN", method: http.MethodPatch, path: "/api/groups", body: patchBody("add", "member", "not-a-dn"), cookie: authenticated.cookie, csrf: authenticated.csrf, status: http.StatusBadRequest},
		{name: "invalid uid", method: http.MethodPatch, path: "/api/groups", body: patchBody("add", "memberUid", "bad\nuid"), cookie: authenticated.cookie, csrf: authenticated.csrf, status: http.StatusBadRequest},
		{
			name: "duplicate value", method: http.MethodPatch, path: "/api/groups",
			body: map[string]any{
				"dn": "cn=staff,dc=example,dc=com",
				"changes": []map[string]any{{
					"operation": "add", "attribute": "member",
					"values": []string{"UID=Alice,dc=example,dc=com", "uid=Alice,DC=example,dc=com"},
				}},
			},
			cookie: authenticated.cookie, csrf: authenticated.csrf, status: http.StatusBadRequest,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := performGroupsRequestWithOrigin(t, application, test.method, test.path, test.body, test.cookie, test.csrf, test.origin)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d, body = %s", response.Code, test.status, response.Body.String())
			}
		})
	}
	client.mu.Lock()
	modifyCount := len(client.modifies)
	client.mu.Unlock()
	if modifyCount != 0 {
		t.Fatalf("invalid requests sent %d LDAP modifies", modifyCount)
	}
}

func TestHandleGroupsLDAPAndResourceErrors(t *testing.T) {
	t.Parallel()
	t.Run("search LDAP error", func(t *testing.T) {
		client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, &ldap.Error{ResultCode: ldap.LDAPResultInsufficientAccessRights, Err: errors.New("denied")}
		}}
		application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
		authenticated := loginTestSession(t, application, "dn")
		response := performGroupsRequest(t, application, http.MethodGet,
			"/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom", nil, authenticated.cookie, "")
		if response.Code != http.StatusForbidden {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	})

	t.Run("response budget", func(t *testing.T) {
		client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(
				"cn=large,dc=example,dc=com", map[string][]string{
					"objectClass": {"groupOfNames"}, "member": {"uid=" + strings.Repeat("x", 2048) + ",dc=example,dc=com"},
				},
			)}}, nil
		}}
		application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
			config.MaxLDAPResponseBytes = 1024
			config.MaxProcessResponseBytes = 2048
		})
		authenticated := loginTestSession(t, application, "dn")
		response := performGroupsRequest(t, application, http.MethodGet,
			"/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom", nil, authenticated.cookie, "")
		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	})

	t.Run("modify LDAP error is atomic failure", func(t *testing.T) {
		client := &fakeClient{
			searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(
					"cn=staff,dc=example,dc=com", map[string][]string{"objectClass": {"groupOfNames"}},
				)}}, nil
			},
			modifyFunc: func(*ldap.ModifyRequest) error {
				return &ldap.Error{ResultCode: ldap.LDAPResultConstraintViolation, Err: errors.New("constraint")}
			},
		}
		application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
		authenticated := loginTestSession(t, application, "dn")
		response := performGroupsRequest(t, application, http.MethodPatch, "/api/groups",
			validGroupPatchBody(), authenticated.cookie, authenticated.csrf)
		if response.Code != http.StatusUnprocessableEntity || strings.Contains(response.Body.String(), "applied") {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	})
}

func TestHandleGroupsRejectsInvalidLDAPGroupResults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		entries    []*ldap.Entry
		resultNil  bool
		selectedDN string
		limit      int
		status     int
		code       string
	}{
		{name: "nil result", resultNil: true, status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "nil entry", entries: []*ldap.Entry{nil}, status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "invalid entry DN", entries: []*ldap.Entry{ldap.NewEntry("not-a-dn", map[string][]string{"objectClass": {"groupOfNames"}})}, status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "non-group entry", entries: []*ldap.Entry{ldap.NewEntry("cn=user,dc=example,dc=com", map[string][]string{"objectClass": {"person"}})}, status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "duplicate group DN", entries: []*ldap.Entry{
			ldap.NewEntry("cn=staff,dc=example,dc=com", map[string][]string{"objectClass": {"groupOfNames"}}),
			ldap.NewEntry("CN=staff,DC=example,DC=com", map[string][]string{"objectClass": {"groupOfNames"}}),
		}, limit: 3, status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "result entry limit", entries: []*ldap.Entry{
			ldap.NewEntry("cn=one,dc=example,dc=com", map[string][]string{"objectClass": {"groupOfNames"}}),
			ldap.NewEntry("cn=two,dc=example,dc=com", map[string][]string{"objectClass": {"groupOfNames"}}),
		}, limit: 1, status: http.StatusRequestEntityTooLarge, code: "group_limit_exceeded"},
		{name: "selected group missing", entries: []*ldap.Entry{}, selectedDN: "cn=missing,dc=example,dc=com", status: http.StatusNotFound, code: "group_not_found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				if test.resultNil {
					return nil, nil
				}
				return &ldap.SearchResult{Entries: test.entries}, nil
			}}
			application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
				if test.limit != 0 {
					config.MaxSearchSize = test.limit
				}
			})
			authenticated := loginTestSession(t, application, "dn")
			path := "/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom"
			if test.selectedDN != "" {
				path += "&dn=" + url.QueryEscape(test.selectedDN)
			}
			response := performGroupsRequest(t, application, http.MethodGet, path, nil, authenticated.cookie, "")
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestHandleGroupsPatchLookupAndRequestErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		path        string
		contentType string
		entries     []*ldap.Entry
		searchErr   error
		status      int
		code        string
	}{
		{name: "query rejected", path: "/api/groups?dn=cn%3Dstaff", status: http.StatusBadRequest, code: "invalid_groups_query"},
		{name: "content type required", contentType: "text/plain", status: http.StatusBadRequest, code: "invalid_request"},
		{name: "group missing", entries: []*ldap.Entry{}, status: http.StatusNotFound, code: "group_not_found"},
		{name: "nil lookup result", status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "nil lookup entry", entries: []*ldap.Entry{nil}, status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "multiple lookup entries", entries: []*ldap.Entry{
			ldap.NewEntry("cn=staff,dc=example,dc=com", map[string][]string{"objectClass": {"groupOfNames"}}),
			ldap.NewEntry("cn=other,dc=example,dc=com", map[string][]string{"objectClass": {"groupOfNames"}}),
		}, status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "lookup entry is not group", entries: []*ldap.Entry{ldap.NewEntry(
			"cn=staff,dc=example,dc=com", map[string][]string{"objectClass": {"person"}},
		)}, status: http.StatusBadGateway, code: "invalid_ldap_response"},
		{name: "lookup ACL error", searchErr: &ldap.Error{
			ResultCode: ldap.LDAPResultInsufficientAccessRights, Err: errors.New("denied"),
		}, status: http.StatusForbidden, code: "ldap_error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				if test.searchErr != nil {
					return nil, test.searchErr
				}
				if test.entries == nil {
					return nil, nil
				}
				return &ldap.SearchResult{Entries: test.entries}, nil
			}}
			application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
			authenticated := loginTestSession(t, application, "dn")
			path := test.path
			if path == "" {
				path = "/api/groups"
			}
			response := performGroupsRequestWithContentType(
				t, application, path, validGroupPatchBody(), authenticated, test.contentType,
			)
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			client.mu.Lock()
			modifyCount := len(client.modifies)
			client.mu.Unlock()
			if modifyCount != 0 {
				t.Fatalf("invalid PATCH sent %d LDAP modifies", modifyCount)
			}
		})
	}
}

func TestNestedGroupLimitAndMalformedLDAPMembership(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		entries []*ldap.Entry
		limit   int
		code    string
	}{
		{
			name: "member limit",
			entries: []*ldap.Entry{ldap.NewEntry("cn=root,dc=example,dc=com", map[string][]string{
				"objectClass": {"groupOfNames"},
				"member":      {"uid=a,dc=example,dc=com", "uid=b,dc=example,dc=com"},
			})},
			limit: 1, code: "nested_group_limit_exceeded",
		},
		{
			name: "invalid LDAP member",
			entries: []*ldap.Entry{ldap.NewEntry("cn=root,dc=example,dc=com", map[string][]string{
				"objectClass": {"groupOfNames"}, "member": {"not-a-dn"},
			})},
			limit: 2, code: "invalid_ldap_response",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: test.entries}, nil
			}}
			application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
				config.MaxSearchSize = test.limit
			})
			authenticated := loginTestSession(t, application, "dn")
			response := performGroupsRequest(t, application, http.MethodGet,
				"/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&dn=cn%3Droot%2Cdc%3Dexample%2Cdc%3Dcom&nested=true",
				nil, authenticated.cookie, "")
			expectedStatus := http.StatusRequestEntityTooLarge
			if test.code == "invalid_ldap_response" {
				expectedStatus = http.StatusBadGateway
			}
			if response.Code != expectedStatus || !strings.Contains(response.Body.String(), test.code) {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestHandleGroupsMembershipRejectsMalformedLDAPValues(t *testing.T) {
	t.Parallel()
	targetDN := "uid=alice,dc=example,dc=com"
	tests := []struct {
		name       string
		attributes map[string][]string
	}{
		{
			name: "invalid member DN",
			attributes: map[string][]string{
				"objectClass": {"groupOfNames"}, "member": {"not-a-dn"},
			},
		},
		{
			name: "valid optional UID with invalid DN",
			attributes: map[string][]string{
				"objectClass": {"groupOfUniqueNames"}, "uniqueMember": {"not-a-dn#'101'B"},
			},
		},
		{
			name: "invalid memberUid",
			attributes: map[string][]string{
				"objectClass": {"posixGroup"}, "memberUid": {"bad\nuid"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(
					"cn=broken,dc=example,dc=com", test.attributes,
				)}}, nil
			}}
			application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, nil)
			authenticated := loginTestSession(t, application, "dn")
			response := performGroupsRequest(t, application, http.MethodGet,
				"/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&member_dn="+url.QueryEscape(targetDN),
				nil, authenticated.cookie, "")
			if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "invalid_ldap_response") {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestHandleGroupsMembershipEnforcesMembershipValueLimit(t *testing.T) {
	t.Parallel()
	targetDN := "uid=alice,dc=example,dc=com"
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(
			"cn=staff,dc=example,dc=com", map[string][]string{
				"objectClass": {"groupOfNames"},
				"member":      {targetDN, "uid=bob,dc=example,dc=com"},
			},
		)}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxSearchSize = 1
	})
	authenticated := loginTestSession(t, application, "dn")
	response := performGroupsRequest(t, application, http.MethodGet,
		"/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&member_dn="+url.QueryEscape(targetDN)+"&nested=true",
		nil, authenticated.cookie, "")
	if response.Code != http.StatusRequestEntityTooLarge ||
		!strings.Contains(response.Body.String(), "group_membership_limit_exceeded") {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestHandleGroupsMembershipAllowsExactMembershipValueLimit(t *testing.T) {
	t.Parallel()
	targetDN := "uid=alice,dc=example,dc=com"
	client := &fakeClient{searchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry(
			"cn=staff,dc=example,dc=com", map[string][]string{
				"objectClass": {"groupOfNames"},
				"member":      {targetDN, "uid=bob,dc=example,dc=com"},
			},
		)}}, nil
	}}
	application, _ := newTestApplication(t, &fakeConnector{clients: []Client{client}}, func(config *Config) {
		config.MaxSearchSize = 2
	})
	authenticated := loginTestSession(t, application, "dn")
	response := performGroupsRequest(t, application, http.MethodGet,
		"/api/groups?base_dn=dc%3Dexample%2Cdc%3Dcom&member_dn="+url.QueryEscape(targetDN),
		nil, authenticated.cookie, "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var body groupsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode exact-limit response: %v", err)
	}
	if body.Memberships == nil || len(body.Memberships.Groups) != 1 {
		t.Fatalf("exact-limit response = %#v", body)
	}
}

func validGroupPatchBody() map[string]any {
	return patchBody("add", "memberUid", "alice")
}

func patchBody(operation, attribute, value string) map[string]any {
	return map[string]any{
		"dn": "cn=staff,dc=example,dc=com",
		"changes": []map[string]any{{
			"operation": operation, "attribute": attribute, "values": []string{value},
		}},
	}
}

func assertLDAPChange(t *testing.T, change ldap.Change, operation uint, attribute string, values []string) {
	t.Helper()
	if change.Operation != operation || change.Modification.Type != attribute ||
		strings.Join(change.Modification.Vals, "\x00") != strings.Join(values, "\x00") {
		t.Fatalf("LDAP change = %#v, want operation=%d attribute=%q values=%q", change, operation, attribute, values)
	}
}

func assertGroupMembershipReferences(
	t *testing.T,
	membership groupMembershipResponse,
	want []groupMembershipReference,
) {
	t.Helper()
	if len(membership.References) != len(want) {
		t.Fatalf("membership %q references = %#v, want %#v", membership.DN, membership.References, want)
	}
	for index := range want {
		if membership.References[index] != want[index] {
			t.Fatalf("membership %q reference %d = %#v, want %#v", membership.DN, index, membership.References[index], want[index])
		}
	}
}

func performGroupsRequest(
	t *testing.T,
	application *Application,
	method, path string,
	body any,
	cookie *http.Cookie,
	csrf string,
) *httptest.ResponseRecorder {
	t.Helper()
	return performGroupsRequestWithOrigin(t, application, method, path, body, cookie, csrf, "https://admin.example")
}

func performGroupsRequestWithOrigin(
	t *testing.T,
	application *Application,
	method, path string,
	body any,
	cookie *http.Cookie,
	csrf, origin string,
) *httptest.ResponseRecorder {
	t.Helper()
	if origin == "" {
		origin = "https://admin.example"
	}
	var encoded bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&encoded).Encode(body); err != nil {
			t.Fatalf("encode request: %v", err)
		}
	}
	request := httptest.NewRequest(method, "https://admin.example"+path, &encoded)
	request.TLS = &tls.ConnectionState{}
	request.RemoteAddr = "192.0.2.10:12345"
	request.Header.Set("Origin", origin)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response := httptest.NewRecorder()
	application.handleGroups(response, request)
	return response
}

func performGroupsRequestWithContentType(
	t *testing.T,
	application *Application,
	path string,
	body any,
	authenticated authenticatedSession,
	contentType string,
) *httptest.ResponseRecorder {
	t.Helper()
	var encoded bytes.Buffer
	if err := json.NewEncoder(&encoded).Encode(body); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPatch, "https://admin.example"+path, &encoded)
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Origin", "https://admin.example")
	request.Header.Set("X-CSRF-Token", authenticated.csrf)
	if contentType == "" {
		contentType = "application/json"
	}
	request.Header.Set("Content-Type", contentType)
	request.AddCookie(authenticated.cookie)
	response := httptest.NewRecorder()
	application.handleGroups(response, request)
	return response
}
