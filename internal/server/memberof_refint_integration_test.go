package server

import (
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	testMemberOfOverlayDN       = "olcOverlay={0}memberof,olcDatabase={1}mdb,cn=config"
	testCustomMemberOfOverlayDN = "olcOverlay={1}memberof,olcDatabase={1}mdb,cn=config"
	testRefintOverlayDN         = "olcOverlay={2}refint,olcDatabase={1}mdb,cn=config"
)

func TestMemberOfOverlayOnlineLifecycleAndWrites(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	registry := memberOfTestRegistry(t)
	config := Config{
		Schema:       registry,
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

	if err := dataClient.Add(memberOfOUAdd("ou=groups,dc=example,dc=com", "groups")); err != nil {
		t.Fatalf("Add(groups OU): %v", err)
	}
	for _, uid := range []string{"bob", "carol"} {
		if err := dataClient.Add(memberOfPersonAdd(uid)); err != nil {
			t.Fatalf("Add(%s): %v", uid, err)
		}
	}

	standardOverlay := ldap.NewAddRequest(testMemberOfOverlayDN, nil)
	standardOverlay.Attribute(
		"objectClass",
		[]string{"olcOverlayConfig", "olcMemberOfConfig"},
	)
	standardOverlay.Attribute("olcOverlay", []string{"{0}memberof"})
	standardOverlay.Attribute("olcMemberOfDangling", []string{"error"})
	standardOverlay.Attribute("olcMemberOfDanglingError", []string{"noSuchObject"})
	standardOverlay.Attribute("olcMemberOfRefInt", []string{"TRUE"})
	standardOverlay.Attribute("olcMemberOfAddCheck", []string{"TRUE"})
	if err := configClient.Add(standardOverlay); err != nil {
		t.Fatalf("Add(standard memberof overlay): %v", err)
	}

	customOverlay := ldap.NewAddRequest(testCustomMemberOfOverlayDN, nil)
	customOverlay.Attribute(
		"objectClass",
		[]string{"olcOverlayConfig", "olcMemberOfConfig"},
	)
	customOverlay.Attribute("olcOverlay", []string{"{1}memberof"})
	customOverlay.Attribute("olcMemberOfGroupOC", []string{"groupA"})
	customOverlay.Attribute("olcMemberOfMemberAD", []string{"memberA"})
	customOverlay.Attribute("olcMemberOfMemberOfAD", []string{"memberOfA"})
	customOverlay.Attribute("olcMemberOfRefInt", []string{"TRUE"})
	if err := configClient.Add(customOverlay); err != nil {
		t.Fatalf("Add(custom memberof overlay): %v", err)
	}

	aliceDN := "uid=alice,ou=people,dc=example,dc=com"
	bobDN := "uid=bob,ou=people,dc=example,dc=com"
	carolDN := "uid=carol,ou=people,dc=example,dc=com"
	groupDN := "cn=staff,ou=groups,dc=example,dc=com"
	group := memberOfGroupAdd(groupDN, "groupOfNames", "member", aliceDN, bobDN)
	if err := dataClient.Add(group); err != nil {
		t.Fatalf("Add(groupOfNames): %v", err)
	}
	assertStoredDNAttribute(t, store, aliceDN, "memberOf", groupDN)
	assertStoredDNAttribute(t, store, bobDN, "memberOf", groupDN)

	changeMembers := ldap.NewModifyRequest(groupDN, nil)
	changeMembers.Delete("member", []string{bobDN})
	changeMembers.Add("member", []string{carolDN})
	if err := dataClient.Modify(changeMembers); err != nil {
		t.Fatalf("Modify(group members): %v", err)
	}
	assertStoredDNAttribute(t, store, bobDN, "memberOf")
	assertStoredDNAttribute(t, store, carolDN, "memberOf", groupDN)

	renamedGroupDN := "cn=engineering,ou=groups,dc=example,dc=com"
	if err := dataClient.ModifyDN(
		ldap.NewModifyDNRequest(groupDN, "cn=engineering", true, ""),
	); err != nil {
		t.Fatalf("ModifyDN(group): %v", err)
	}
	assertStoredDNAttribute(t, store, aliceDN, "memberOf", renamedGroupDN)
	assertStoredDNAttribute(t, store, carolDN, "memberOf", renamedGroupDN)

	renamedAliceDN := "uid=alice-renamed,ou=people,dc=example,dc=com"
	if err := dataClient.ModifyDN(
		ldap.NewModifyDNRequest(aliceDN, "uid=alice-renamed", true, ""),
	); err != nil {
		t.Fatalf("ModifyDN(member): %v", err)
	}
	assertStoredDNAttribute(
		t,
		store,
		renamedGroupDN,
		"member",
		renamedAliceDN,
		carolDN,
	)

	if err := dataClient.Del(ldap.NewDelRequest(carolDN, nil)); err != nil {
		t.Fatalf("Delete(member): %v", err)
	}
	assertStoredDNAttribute(t, store, renamedGroupDN, "member", renamedAliceDN)
	if err := dataClient.Del(ldap.NewDelRequest(renamedGroupDN, nil)); err != nil {
		t.Fatalf("Delete(group): %v", err)
	}
	assertStoredDNAttribute(t, store, renamedAliceDN, "memberOf")

	missingDN := "uid=missing,ou=people,dc=example,dc=com"
	badGroupDN := "cn=bad,ou=groups,dc=example,dc=com"
	assertLDAPResultCode(
		t,
		dataClient.Add(memberOfGroupAdd(
			badGroupDN,
			"groupOfNames",
			"member",
			missingDN,
		)),
		ldap.LDAPResultNoSuchObject,
	)

	dropDangling := ldap.NewModifyRequest(testMemberOfOverlayDN, nil)
	dropDangling.Replace("olcMemberOfDangling", []string{"drop"})
	if err := configClient.Modify(dropDangling); err != nil {
		t.Fatalf("Modify(memberof dangling=drop): %v", err)
	}
	dropGroupDN := "cn=drop,ou=groups,dc=example,dc=com"
	if err := dataClient.Add(memberOfGroupAdd(
		dropGroupDN,
		"groupOfNames",
		"member",
		renamedAliceDN,
		missingDN,
	)); err != nil {
		t.Fatalf("Add(group with dropped dangling member): %v", err)
	}
	assertStoredDNAttribute(t, store, dropGroupDN, "member", renamedAliceDN)

	ignoreDangling := ldap.NewModifyRequest(testMemberOfOverlayDN, nil)
	ignoreDangling.Replace("olcMemberOfDangling", []string{"ignore"})
	if err := configClient.Modify(ignoreDangling); err != nil {
		t.Fatalf("Modify(memberof dangling=ignore): %v", err)
	}
	futureDN := "uid=future,ou=people,dc=example,dc=com"
	futureGroupDN := "cn=future,ou=groups,dc=example,dc=com"
	if err := dataClient.Add(memberOfGroupAdd(
		futureGroupDN,
		"groupOfNames",
		"member",
		futureDN,
	)); err != nil {
		t.Fatalf("Add(group with future member): %v", err)
	}
	if err := dataClient.Add(memberOfPersonAdd("future")); err != nil {
		t.Fatalf("Add(future member): %v", err)
	}
	assertStoredDNAttribute(t, store, futureDN, "memberOf", futureGroupDN)

	customGroupDN := "cn=custom,ou=groups,dc=example,dc=com"
	if err := dataClient.Add(memberOfGroupAdd(
		customGroupDN,
		"groupA",
		"memberA",
		renamedAliceDN,
	)); err != nil {
		t.Fatalf("Add(custom group): %v", err)
	}
	assertStoredDNAttribute(t, store, renamedAliceDN, "memberOfA", customGroupDN)

	writeMemberOf := ldap.NewModifyRequest(renamedAliceDN, nil)
	writeMemberOf.Add("memberOf", []string{futureGroupDN})
	assertLDAPResultCode(
		t,
		dataClient.Modify(writeMemberOf),
		ldap.LDAPResultConstraintViolation,
	)

	invalidConfig := ldap.NewModifyRequest(testMemberOfOverlayDN, nil)
	invalidConfig.Replace("olcMemberOfMemberAD", []string{"mail"})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalidConfig),
		ldap.LDAPResultConstraintViolation,
	)
	if values := readStoredEntry(t, store, testMemberOfOverlayDN).
		Values("olcMemberOfMemberAD"); len(values) != 0 {
		t.Fatalf("invalid memberof configuration was stored: %q", values)
	}

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
	restartAdd := ldap.NewModifyRequest(dropGroupDN, nil)
	restartAdd.Add("member", []string{bobDN})
	if err := dataClient.Modify(restartAdd); err != nil {
		t.Fatalf("Modify(group after restart): %v", err)
	}
	assertStoredDNAttribute(t, store, bobDN, "memberOf", dropGroupDN)
	customRestartAdd := ldap.NewModifyRequest(customGroupDN, nil)
	customRestartAdd.Add("memberA", []string{bobDN})
	if err := dataClient.Modify(customRestartAdd); err != nil {
		t.Fatalf("Modify(custom group after restart): %v", err)
	}
	assertStoredDNAttribute(t, store, bobDN, "memberOfA", customGroupDN)
}

func TestRefintOverlayOnlineSubtreeAndNothing(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	registry := memberOfTestRegistry(t)
	config := Config{
		Schema:       registry,
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

	if err := dataClient.Add(memberOfOUAdd("ou=groups,dc=example,dc=com", "groups")); err != nil {
		t.Fatalf("Add(groups OU): %v", err)
	}
	placeholderDN := "cn=placeholder,dc=example,dc=com"
	refint := ldap.NewAddRequest(testRefintOverlayDN, nil)
	refint.Attribute("objectClass", []string{"olcOverlayConfig", "olcRefintConfig"})
	refint.Attribute("olcOverlay", []string{"{2}refint"})
	refint.Attribute("olcRefintAttribute", []string{"managerRef memberA"})
	refint.Attribute("olcRefintNothing", []string{placeholderDN})
	refint.Attribute(
		"olcRefintModifiersName",
		[]string{"cn=refint-repair,dc=example,dc=com"},
	)
	if err := configClient.Add(refint); err != nil {
		t.Fatalf("Add(refint overlay): %v", err)
	}

	targetDN := "uid=target,ou=people,dc=example,dc=com"
	if err := dataClient.Add(memberOfPersonAdd("target")); err != nil {
		t.Fatalf("Add(refint target): %v", err)
	}
	holderDN := "uid=holder,ou=people,dc=example,dc=com"
	holder := memberOfPersonAdd("holder")
	holder.Attributes[0].Vals = append(holder.Attributes[0].Vals, "refHolder")
	holder.Attribute("managerRef", []string{targetDN})
	if err := dataClient.Add(holder); err != nil {
		t.Fatalf("Add(refint holder): %v", err)
	}
	groupDN := "cn=refint,ou=groups,dc=example,dc=com"
	if err := dataClient.Add(memberOfGroupAdd(
		groupDN,
		"groupA",
		"memberA",
		targetDN,
	)); err != nil {
		t.Fatalf("Add(refint group): %v", err)
	}

	renamedTargetDN := "uid=target-renamed,ou=people,dc=example,dc=com"
	if err := dataClient.ModifyDN(
		ldap.NewModifyDNRequest(targetDN, "uid=target-renamed", true, ""),
	); err != nil {
		t.Fatalf("ModifyDN(refint target): %v", err)
	}
	assertStoredDNAttribute(t, store, holderDN, "managerRef", renamedTargetDN)
	assertStoredDNAttribute(t, store, groupDN, "memberA", renamedTargetDN)
	assertStoredStringAttribute(
		t,
		store,
		holderDN,
		"modifiersName",
		"cn=refint-repair,dc=example,dc=com",
	)

	if err := dataClient.Del(ldap.NewDelRequest(renamedTargetDN, nil)); err != nil {
		t.Fatalf("Delete(refint target): %v", err)
	}
	assertStoredDNAttribute(t, store, holderDN, "managerRef", placeholderDN)
	assertStoredDNAttribute(t, store, groupDN, "memberA", placeholderDN)

	teamDN := "ou=team,ou=people,dc=example,dc=com"
	if err := dataClient.Add(memberOfOUAdd(teamDN, "team")); err != nil {
		t.Fatalf("Add(team OU): %v", err)
	}
	leadDN := "uid=lead," + teamDN
	lead := ldap.NewAddRequest(leadDN, nil)
	lead.Attribute("objectClass", []string{"inetOrgPerson"})
	lead.Attribute("uid", []string{"lead"})
	lead.Attribute("cn", []string{"Lead"})
	lead.Attribute("sn", []string{"User"})
	if err := dataClient.Add(lead); err != nil {
		t.Fatalf("Add(team lead): %v", err)
	}
	subtreeHolderDN := "uid=subtree-holder,ou=people,dc=example,dc=com"
	subtreeHolder := memberOfPersonAdd("subtree-holder")
	subtreeHolder.Attributes[0].Vals = append(
		subtreeHolder.Attributes[0].Vals,
		"refHolder",
	)
	subtreeHolder.Attribute("managerRef", []string{leadDN})
	if err := dataClient.Add(subtreeHolder); err != nil {
		t.Fatalf("Add(subtree holder): %v", err)
	}

	divisionDN := "ou=division,ou=people,dc=example,dc=com"
	if err := dataClient.ModifyDN(
		ldap.NewModifyDNRequest(teamDN, "ou=division", true, ""),
	); err != nil {
		t.Fatalf("ModifyDN(refint subtree): %v", err)
	}
	renamedLeadDN := "uid=lead," + divisionDN
	assertStoredDNAttribute(
		t,
		store,
		subtreeHolderDN,
		"managerRef",
		renamedLeadDN,
	)

	invalidConfig := ldap.NewModifyRequest(testRefintOverlayDN, nil)
	invalidConfig.Replace("olcRefintAttribute", []string{"undefinedRefintAttribute"})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalidConfig),
		ldap.LDAPResultConstraintViolation,
	)
	configured := readStoredEntry(t, store, testRefintOverlayDN).
		Values("olcRefintAttribute")
	if len(configured) != 1 || string(configured[0]) != "managerRef memberA" {
		t.Fatalf("refint configuration rollback values = %q", configured)
	}

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
	finalLeadDN := "uid=lead-final," + divisionDN
	if err := dataClient.ModifyDN(
		ldap.NewModifyDNRequest(renamedLeadDN, "uid=lead-final", true, ""),
	); err != nil {
		t.Fatalf("ModifyDN(refint target after restart): %v", err)
	}
	assertStoredDNAttribute(
		t,
		store,
		subtreeHolderDN,
		"managerRef",
		finalLeadDN,
	)
}

func memberOfPersonAdd(uid string) *ldap.AddRequest {
	request := ldap.NewAddRequest(
		"uid="+uid+",ou=people,dc=example,dc=com",
		nil,
	)
	request.Attribute("objectClass", []string{"inetOrgPerson"})
	request.Attribute("uid", []string{uid})
	request.Attribute("cn", []string{uid})
	request.Attribute("sn", []string{"User"})
	return request
}

func memberOfOUAdd(dn, name string) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"organizationalUnit"})
	request.Attribute("ou", []string{name})
	return request
}

func memberOfGroupAdd(
	dn,
	objectClass,
	memberAttribute string,
	members ...string,
) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{objectClass})
	parsed, err := directory.ParseDN(dn)
	if err == nil {
		for _, rdnValue := range parsed.RDNValues() {
			request.Attribute(rdnValue.Type, []string{string(rdnValue.Value)})
		}
	}
	request.Attribute(memberAttribute, members)
	return request
}

func assertStoredDNAttribute(
	t *testing.T,
	store storage.Store,
	dn,
	attribute string,
	want ...string,
) {
	t.Helper()
	values := readStoredEntry(t, store, dn).Values(attribute)
	if len(values) != len(want) {
		t.Fatalf("%s %s = %q, want %q", dn, attribute, values, want)
	}
	remaining := make(map[string]struct{}, len(want))
	for _, raw := range want {
		parsed, err := directory.ParseDN(raw)
		if err != nil {
			t.Fatalf("ParseDN(%q): %v", raw, err)
		}
		remaining[parsed.Key()] = struct{}{}
	}
	for _, value := range values {
		parsed, err := directory.ParseDN(string(value))
		if err != nil {
			t.Fatalf("stored %s %s value %q is not a DN: %v", dn, attribute, value, err)
		}
		if _, found := remaining[parsed.Key()]; !found {
			t.Fatalf("%s %s contains unexpected DN %q", dn, attribute, value)
		}
		delete(remaining, parsed.Key())
	}
	if len(remaining) != 0 {
		t.Fatalf("%s %s is missing DNs: %v", dn, attribute, remaining)
	}
}

func assertStoredStringAttribute(
	t *testing.T,
	store storage.Store,
	dn,
	attribute,
	want string,
) {
	t.Helper()
	values := readStoredEntry(t, store, dn).Values(attribute)
	if len(values) != 1 || string(values[0]) != want {
		t.Fatalf("%s %s = %q, want %q", dn, attribute, values, want)
	}
}
