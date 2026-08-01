package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type overlayReferenceOutcome struct {
	codes  []uint16
	states []string
}

func TestOpenLDAPReferenceMemberOfOverlay(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{memberOfReferenceOverlayConfiguration()},
		"",
		"",
		"",
	)
	defer stopOpenLDAP()
	openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
	defer openLDAP.Close()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	registry := memberOfTestRegistry(t)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{
		Schema:       registry,
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stopLDAPGo()
	ldapGo := bindConstraintClient(
		t,
		ldapGoAddress,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer ldapGo.Close()
	for _, uid := range []string{"bob", "carol"} {
		if err := ldapGo.Add(memberOfPersonAdd(uid)); err != nil {
			t.Fatalf("Add(ldap-go memberof seed %s): %v", uid, err)
		}
	}
	configClient := bindConstraintClient(t, ldapGoAddress, "cn=config", "config-secret")
	defer configClient.Close()
	overlay := ldap.NewAddRequest(testMemberOfOverlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcMemberOfConfig"})
	overlay.Attribute("olcOverlay", []string{"{0}memberof"})
	overlay.Attribute("olcMemberOfDangling", []string{"error"})
	overlay.Attribute("olcMemberOfDanglingError", []string{"noSuchObject"})
	overlay.Attribute("olcMemberOfRefInt", []string{"TRUE"})
	overlay.Attribute("olcMemberOfAddCheck", []string{"TRUE"})
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(ldap-go memberof overlay): %v", err)
	}

	openLDAPOutcome := runMemberOfReferenceScenario(t, openLDAP)
	ldapGoOutcome := runMemberOfReferenceScenario(t, ldapGo)
	assertOverlayReferenceOutcome(
		t,
		"memberof",
		openLDAPOutcome,
		ldapGoOutcome,
		[]uint16{
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultNoSuchObject,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultConstraintViolation,
		},
	)
}

func TestOpenLDAPReferenceMemberOfUniqueNames(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{memberOfUniqueNamesReferenceOverlayConfiguration()},
		"",
		"",
		"",
	)
	defer stopOpenLDAP()
	openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
	defer openLDAP.Close()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{
		Schema:       memberOfTestRegistry(t),
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stopLDAPGo()
	ldapGo := bindConstraintClient(
		t,
		ldapGoAddress,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer ldapGo.Close()
	if err := ldapGo.Add(memberOfPersonAdd("bob")); err != nil {
		t.Fatalf("Add(ldap-go uniqueMember seed bob): %v", err)
	}
	configClient := bindConstraintClient(t, ldapGoAddress, "cn=config", "config-secret")
	defer configClient.Close()
	overlay := ldap.NewAddRequest(testMemberOfOverlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcMemberOfConfig"})
	overlay.Attribute("olcOverlay", []string{"{0}memberof"})
	overlay.Attribute("olcMemberOfGroupOC", []string{"groupOfUniqueNames"})
	overlay.Attribute("olcMemberOfMemberAD", []string{"uniqueMember"})
	overlay.Attribute("olcMemberOfRefInt", []string{"TRUE"})
	overlay.Attribute("olcMemberOfAddCheck", []string{"TRUE"})
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(ldap-go uniqueMember memberof overlay): %v", err)
	}

	openLDAPOutcome := runMemberOfUniqueNamesReferenceScenario(t, openLDAP)
	ldapGoOutcome := runMemberOfUniqueNamesReferenceScenario(t, ldapGo)
	assertOverlayReferenceOutcome(
		t,
		"memberof uniqueMember",
		openLDAPOutcome,
		ldapGoOutcome,
		[]uint16{
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultCompareTrue,
			ldap.LDAPResultCompareFalse,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
		},
	)
}

func TestOpenLDAPReferenceRefintOverlay(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		[]string{refintReferenceOverlayConfiguration()},
		"",
		"",
		"",
	)
	defer stopOpenLDAP()
	openLDAP := bindOverlayReferenceClient(t, openLDAPURI, "secret")
	defer openLDAP.Close()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	registry := memberOfTestRegistry(t)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{
		Schema:       registry,
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stopLDAPGo()
	ldapGo := bindConstraintClient(
		t,
		ldapGoAddress,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer ldapGo.Close()
	configClient := bindConstraintClient(t, ldapGoAddress, "cn=config", "config-secret")
	defer configClient.Close()
	overlay := ldap.NewAddRequest(testRefintOverlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcRefintConfig"})
	overlay.Attribute("olcOverlay", []string{"{2}refint"})
	overlay.Attribute("olcRefintAttribute", []string{"member"})
	overlay.Attribute("olcRefintNothing", []string{refintReferencePlaceholderDN})
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(ldap-go refint overlay): %v", err)
	}

	openLDAPOutcome := runRefintReferenceScenario(t, openLDAP)
	ldapGoOutcome := runRefintReferenceScenario(t, ldapGo)
	assertOverlayReferenceOutcome(
		t,
		"refint",
		openLDAPOutcome,
		ldapGoOutcome,
		[]uint16{
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
			ldap.LDAPResultSuccess,
		},
	)
}

func TestOpenLDAPSlapcatMemberOfAndRefintConfigImport(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	slaptest := findOpenLDAPSchemaTool(
		t,
		"slaptest",
		"/opt/homebrew/opt/openldap/sbin/slaptest",
		"/usr/sbin/slaptest",
	)
	slapcat := findOpenLDAPSchemaTool(
		t,
		"slapcat",
		"/opt/homebrew/opt/openldap/sbin/slapcat",
		"/usr/sbin/slapcat",
	)

	root := t.TempDir()
	configDir := filepath.Join(root, "slapd.d")
	databaseDir := filepath.Join(root, "db")
	for _, path := range []string{configDir, databaseDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("Mkdir(%s): %v", path, err)
		}
	}
	configPath := filepath.Join(root, "slapd.conf")
	config := fmt.Sprintf(
		`include %s
include %s
include %s
pidfile %s
argsfile %s

database mdb
maxsize 1073741824
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
directory %s
overlay memberof
memberof-dangling error
memberof-dangling-error noSuchObject
memberof-refint TRUE
memberof-addcheck TRUE
overlay refint
refint_attributes member
refint_nothing "cn=placeholder,dc=example,dc=com"
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		filepath.Join(root, "slapd.pid"),
		filepath.Join(root, "slapd.args"),
		databaseDir,
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write slapd.conf: %v", err)
	}
	dataPath := filepath.Join(root, "data.ldif")
	data := `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

`
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		t.Fatalf("write OpenLDAP seed data: %v", err)
	}
	command := exec.Command(
		tools.slapadd,
		"-q",
		"-f",
		configPath,
		"-l",
		dataPath,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("slapadd failed: %v\n%s", err, output)
	}
	command = exec.Command(slaptest, "-f", configPath, "-F", configDir)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("slaptest failed: %v\n%s", err, output)
	}

	var stderr bytes.Buffer
	command = exec.Command(
		slapcat,
		"-F",
		configDir,
		"-n",
		"0",
		"-a",
		"(olcOverlay=*)",
	)
	command.Stderr = &stderr
	exported, err := command.Output()
	if err != nil {
		t.Fatalf("slapcat -n 0 failed: %v\n%s", err, stderr.Bytes())
	}
	for _, expected := range [][]byte{
		[]byte("olcMemberOfConfig"),
		[]byte("olcMemberOfRefInt:"),
		[]byte("olcRefintConfig"),
		[]byte("olcRefintAttribute:"),
	} {
		if !bytes.Contains(exported, expected) {
			t.Fatalf("slapcat output is missing %q:\n%s", expected, exported)
		}
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if _, err := migration.ImportLDIF(
		context.Background(),
		store,
		bytes.NewReader(exported),
		migration.ImportOptions{},
	); err != nil {
		t.Fatalf("ImportLDIF(real slapcat overlay config): %v\n%s", err, exported)
	}
	address, stop := startServer(t, store, Config{
		Schema:       memberOfTestRegistry(t),
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindConstraintClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer client.Close()
	if err := client.Add(memberOfOUAdd("ou=groups,dc=example,dc=com", "groups")); err != nil {
		t.Fatalf("Add(groups OU after slapcat import): %v", err)
	}
	groupDN := "cn=slapcat,ou=groups,dc=example,dc=com"
	aliceDN := "uid=alice,ou=people,dc=example,dc=com"
	if err := client.Add(memberOfGroupAdd(
		groupDN,
		"groupOfNames",
		"member",
		aliceDN,
	)); err != nil {
		t.Fatalf("Add(group after slapcat import): %v", err)
	}
	assertStoredDNAttribute(t, store, aliceDN, "memberOf", groupDN)
	renamedAliceDN := "uid=slapcat-alice,ou=people,dc=example,dc=com"
	if err := client.ModifyDN(
		ldap.NewModifyDNRequest(aliceDN, "uid=slapcat-alice", true, ""),
	); err != nil {
		t.Fatalf("ModifyDN(member after slapcat import): %v", err)
	}
	assertStoredDNAttribute(t, store, groupDN, "member", renamedAliceDN)
}

func runMemberOfReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
) overlayReferenceOutcome {
	t.Helper()

	var outcome overlayReferenceOutcome
	groupsDN := "ou=groups,dc=example,dc=com"
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Add(memberOfOUAdd(groupsDN, "groups"))),
	)
	aliceDN := "uid=alice,ou=people,dc=example,dc=com"
	bobDN := "uid=bob,ou=people,dc=example,dc=com"
	carolDN := "uid=carol,ou=people,dc=example,dc=com"
	groupDN := "cn=staff," + groupsDN
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Add(memberOfGroupAdd(
			groupDN,
			"groupOfNames",
			"member",
			aliceDN,
			bobDN,
		))),
	)
	outcome.states = append(
		outcome.states,
		ldapDNAttributeSignature(t, client, aliceDN, "memberOf"),
		ldapDNAttributeSignature(t, client, bobDN, "memberOf"),
	)

	modify := ldap.NewModifyRequest(groupDN, nil)
	modify.Delete("member", []string{bobDN})
	modify.Add("member", []string{carolDN})
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Modify(modify)),
	)
	outcome.states = append(
		outcome.states,
		ldapDNAttributeSignature(t, client, groupDN, "member"),
		ldapDNAttributeSignature(t, client, bobDN, "memberOf"),
	)

	renamedGroupDN := "cn=engineering," + groupsDN
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.ModifyDN(
			ldap.NewModifyDNRequest(groupDN, "cn=engineering", true, ""),
		)),
	)
	outcome.states = append(
		outcome.states,
		ldapDNAttributeSignature(t, client, aliceDN, "memberOf"),
	)

	renamedAliceDN := "uid=alice-renamed,ou=people,dc=example,dc=com"
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.ModifyDN(
			ldap.NewModifyDNRequest(aliceDN, "uid=alice-renamed", true, ""),
		)),
	)
	outcome.states = append(
		outcome.states,
		ldapDNAttributeSignature(t, client, renamedGroupDN, "member"),
	)

	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Del(ldap.NewDelRequest(carolDN, nil))),
	)
	outcome.states = append(
		outcome.states,
		ldapDNAttributeSignature(t, client, renamedGroupDN, "member"),
	)
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Del(ldap.NewDelRequest(renamedGroupDN, nil))),
	)
	outcome.states = append(
		outcome.states,
		ldapDNAttributeSignature(t, client, renamedAliceDN, "memberOf"),
	)

	missingDN := "uid=missing,ou=people,dc=example,dc=com"
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Add(memberOfGroupAdd(
			"cn=bad,"+groupsDN,
			"groupOfNames",
			"member",
			missingDN,
		))),
	)
	futureDN := "uid=future,ou=people,dc=example,dc=com"
	futureGroupDN := "cn=future," + groupsDN
	futureGroup := memberOfGroupAdd(
		futureGroupDN,
		"groupOfNames",
		"member",
		futureDN,
	)
	futureGroup.Controls = []ldap.Control{relaxLDAPControl()}
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Add(futureGroup)),
	)
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Add(memberOfPersonAdd("future"))),
	)
	outcome.states = append(
		outcome.states,
		ldapDNAttributeSignature(t, client, futureDN, "memberOf"),
	)
	direct := ldap.NewModifyRequest(renamedAliceDN, nil)
	direct.Add("memberOf", []string{futureGroupDN})
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Modify(direct)),
	)
	return outcome
}

func runMemberOfUniqueNamesReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
) overlayReferenceOutcome {
	t.Helper()

	var outcome overlayReferenceOutcome
	groupsDN := "ou=groups,dc=example,dc=com"
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Add(memberOfOUAdd(groupsDN, "groups"))),
	)
	aliceDN := "uid=alice,ou=people,dc=example,dc=com"
	bobDN := "uid=bob,ou=people,dc=example,dc=com"
	bobWithUID := bobDN + "#'1'B"
	groupDN := "cn=unique," + groupsDN
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Add(memberOfGroupAdd(
			groupDN,
			"groupOfUniqueNames",
			"uniqueMember",
			aliceDN,
			bobWithUID,
		))),
	)
	outcome.states = append(
		outcome.states,
		ldapDNAttributeSignature(t, client, aliceDN, "memberOf"),
		ldapDNAttributeSignature(t, client, bobDN, "memberOf"),
		ldapStringAttributeSignature(t, client, groupDN, "uniqueMember"),
	)
	outcome.codes = append(
		outcome.codes,
		overlayCompareResultCode(
			t,
			client,
			groupDN,
			"uniqueMember",
			"UID=BOB,OU=people,DC=example,DC=com#'1'B",
		),
		overlayCompareResultCode(t, client, groupDN, "uniqueMember", bobDN),
	)

	renamedAliceDN := "uid=alice-unique,ou=people,dc=example,dc=com"
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.ModifyDN(
			ldap.NewModifyDNRequest(aliceDN, "uid=alice-unique", true, ""),
		)),
	)
	outcome.states = append(
		outcome.states,
		ldapStringAttributeSignature(t, client, groupDN, "uniqueMember"),
		ldapDNAttributeSignature(t, client, renamedAliceDN, "memberOf"),
	)

	renamedBobDN := "uid=bob-unique,ou=people,dc=example,dc=com"
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.ModifyDN(
			ldap.NewModifyDNRequest(bobDN, "uid=bob-unique", true, ""),
		)),
	)
	outcome.states = append(
		outcome.states,
		ldapStringAttributeSignature(t, client, groupDN, "uniqueMember"),
		ldapDNAttributeSignature(t, client, renamedBobDN, "memberOf"),
	)

	futureDN := "uid=unique-future,ou=people,dc=example,dc=com"
	addFuture := ldap.NewModifyRequest(groupDN, nil)
	addFuture.Add("uniqueMember", []string{futureDN})
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Modify(addFuture)),
		overlayLDAPResultCode(t, client.Add(memberOfPersonAdd("unique-future"))),
	)
	outcome.states = append(
		outcome.states,
		ldapDNAttributeSignature(t, client, futureDN, "memberOf"),
	)
	return outcome
}

const refintReferencePlaceholderDN = "cn=placeholder,dc=example,dc=com"

func runRefintReferenceScenario(
	t *testing.T,
	client *ldap.Conn,
) overlayReferenceOutcome {
	t.Helper()

	var outcome overlayReferenceOutcome
	groupsDN := "ou=groups,dc=example,dc=com"
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Add(memberOfOUAdd(groupsDN, "groups"))),
	)
	aliceDN := "uid=alice,ou=people,dc=example,dc=com"
	exactGroupDN := "cn=exact," + groupsDN
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Add(memberOfGroupAdd(
			exactGroupDN,
			"groupOfNames",
			"member",
			aliceDN,
		))),
	)
	renamedAliceDN := "uid=alice-refint,ou=people,dc=example,dc=com"
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.ModifyDN(
			ldap.NewModifyDNRequest(aliceDN, "uid=alice-refint", true, ""),
		)),
	)
	waitLDAPDNAttribute(
		t,
		client,
		exactGroupDN,
		"member",
		renamedAliceDN,
	)
	outcome.states = append(
		outcome.states,
		ldapDNAttributeSignature(t, client, exactGroupDN, "member"),
	)
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Del(ldap.NewDelRequest(renamedAliceDN, nil))),
	)
	waitLDAPDNAttribute(
		t,
		client,
		exactGroupDN,
		"member",
		refintReferencePlaceholderDN,
	)
	outcome.states = append(
		outcome.states,
		ldapDNAttributeSignature(t, client, exactGroupDN, "member"),
	)

	teamDN := "ou=team,ou=people,dc=example,dc=com"
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Add(memberOfOUAdd(teamDN, "team"))),
	)
	leadDN := "uid=lead," + teamDN
	lead := ldap.NewAddRequest(leadDN, nil)
	lead.Attribute("objectClass", []string{"inetOrgPerson"})
	lead.Attribute("uid", []string{"lead"})
	lead.Attribute("cn", []string{"Lead"})
	lead.Attribute("sn", []string{"User"})
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Add(lead)),
	)
	subtreeGroupDN := "cn=subtree," + groupsDN
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.Add(memberOfGroupAdd(
			subtreeGroupDN,
			"groupOfNames",
			"member",
			leadDN,
		))),
	)
	divisionDN := "ou=division,ou=people,dc=example,dc=com"
	renamedLeadDN := "uid=lead," + divisionDN
	outcome.codes = append(
		outcome.codes,
		overlayLDAPResultCode(t, client.ModifyDN(
			ldap.NewModifyDNRequest(teamDN, "ou=division", true, ""),
		)),
	)
	waitLDAPDNAttribute(
		t,
		client,
		subtreeGroupDN,
		"member",
		renamedLeadDN,
	)
	outcome.states = append(
		outcome.states,
		ldapDNAttributeSignature(t, client, subtreeGroupDN, "member"),
	)
	return outcome
}

func memberOfReferenceOverlayConfiguration() string {
	return "memberof\n" +
		"memberof-dangling error\n" +
		"memberof-dangling-error noSuchObject\n" +
		"memberof-refint TRUE\n" +
		"memberof-addcheck TRUE"
}

func memberOfUniqueNamesReferenceOverlayConfiguration() string {
	return "memberof\n" +
		"memberof-group-oc groupOfUniqueNames\n" +
		"memberof-member-ad uniqueMember\n" +
		"memberof-refint TRUE\n" +
		"memberof-addcheck TRUE"
}

func refintReferenceOverlayConfiguration() string {
	return "refint\n" +
		"refint_attributes member\n" +
		"refint_nothing \"" + refintReferencePlaceholderDN + "\""
}

func bindOverlayReferenceClient(
	t *testing.T,
	uri,
	password string,
) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	if err := client.Bind("cn=admin,dc=example,dc=com", password); err != nil {
		client.Close()
		t.Fatalf("Bind(%s): %v", uri, err)
	}
	return client
}

func overlayLDAPResultCode(t *testing.T, err error) uint16 {
	t.Helper()
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		t.Fatalf("LDAP operation returned non-LDAP error: %v", err)
	}
	return ldapErr.ResultCode
}

func overlayCompareResultCode(
	t *testing.T,
	client *ldap.Conn,
	dn,
	attribute,
	value string,
) uint16 {
	t.Helper()
	matched, err := client.Compare(dn, attribute, value)
	if err != nil {
		return overlayLDAPResultCode(t, err)
	}
	if matched {
		return ldap.LDAPResultCompareTrue
	}
	return ldap.LDAPResultCompareFalse
}

func assertOverlayReferenceOutcome(
	t *testing.T,
	name string,
	openLDAP,
	ldapGo overlayReferenceOutcome,
	wantCodes []uint16,
) {
	t.Helper()
	if len(openLDAP.codes) != len(wantCodes) || len(ldapGo.codes) != len(wantCodes) {
		t.Fatalf(
			"%s result lengths: OpenLDAP=%d ldap-go=%d want=%d",
			name,
			len(openLDAP.codes),
			len(ldapGo.codes),
			len(wantCodes),
		)
	}
	for index, want := range wantCodes {
		if openLDAP.codes[index] != want || ldapGo.codes[index] != openLDAP.codes[index] {
			t.Fatalf(
				"%s operation %d: OpenLDAP=%d ldap-go=%d want=%d",
				name,
				index,
				openLDAP.codes[index],
				ldapGo.codes[index],
				want,
			)
		}
	}
	if len(openLDAP.states) != len(ldapGo.states) {
		t.Fatalf(
			"%s state lengths: OpenLDAP=%d ldap-go=%d",
			name,
			len(openLDAP.states),
			len(ldapGo.states),
		)
	}
	for index := range openLDAP.states {
		if openLDAP.states[index] != ldapGo.states[index] {
			t.Fatalf(
				"%s state %d: OpenLDAP=%q ldap-go=%q",
				name,
				index,
				openLDAP.states[index],
				ldapGo.states[index],
			)
		}
	}
}

func ldapDNAttributeSignature(
	t *testing.T,
	client *ldap.Conn,
	dn,
	attribute string,
) string {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{attribute},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(%s, %s): %v", dn, attribute, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search(%s, %s) returned %d entries", dn, attribute, len(result.Entries))
	}
	values := result.Entries[0].GetAttributeValues(attribute)
	keys := make([]string, 0, len(values))
	for _, value := range values {
		parsed, err := directory.ParseDN(value)
		if err != nil {
			t.Fatalf("Search(%s, %s) returned invalid DN %q: %v", dn, attribute, value, err)
		}
		keys = append(keys, parsed.Key())
	}
	sort.Strings(keys)
	return strings.Join(keys, "|")
}

func ldapStringAttributeSignature(
	t *testing.T,
	client *ldap.Conn,
	dn,
	attribute string,
) string {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{attribute},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(%s, %s): %v", dn, attribute, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search(%s, %s) returned %d entries", dn, attribute, len(result.Entries))
	}
	values := result.Entries[0].GetAttributeValues(attribute)
	sort.Strings(values)
	return strings.Join(values, "|")
}

func waitLDAPDNAttribute(
	t *testing.T,
	client *ldap.Conn,
	dn,
	attribute string,
	want ...string,
) {
	t.Helper()
	keys := make([]string, 0, len(want))
	for _, value := range want {
		parsed, err := directory.ParseDN(value)
		if err != nil {
			t.Fatalf("ParseDN(%q): %v", value, err)
		}
		keys = append(keys, parsed.Key())
	}
	sort.Strings(keys)
	wantSignature := strings.Join(keys, "|")
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := ldapDNAttributeSignature(t, client, dn, attribute)
		if got == wantSignature {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf(
				"%s %s = %q after refint wait, want %q",
				dn,
				attribute,
				got,
				wantSignature,
			)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
