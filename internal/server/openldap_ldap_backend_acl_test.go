package server

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/audit"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type openLDAPBackendACLOutcome struct {
	visibleEntries      int
	visibleAttributes   []string
	descriptionValues   []string
	hiddenEntries       int
	filterEntries       int
	compareClassified   bool
	compareClassifiedRC uint16
	compareHidden       bool
	compareHiddenRC     uint16
	modifyRC            uint16
	addRC               uint16
	modifyDNRC          uint16
	deleteRC            uint16
	createdAfterDelete  int
	providerDescription string
}

const openLDAPLDAPBackendACLCommit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

func TestOpenLDAPReferenceLDAPBackendLocalACL(t *testing.T) {
	tools := requireOpenLDAPLDAPBackendReferenceTools(t)
	assertOpenLDAPLDAPBackendACLReference(t, tools)

	var reference openLDAPBackendACLOutcome
	t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
		providerURI, stopProvider := startLDAPBackendACLProvider(t)
		defer stopProvider()
		proxyURI, stopProxy := startOpenLDAPBackendACLProxy(t, tools, providerURI)
		defer stopProxy()

		reference = observeLDAPBackendLocalACL(t, proxyURI, providerURI)
		assertOpenLDAPBackendACLFixture(t, reference)
	})
	if t.Failed() {
		return
	}

	t.Run("ldap-go differential", func(t *testing.T) {
		providerURI, stopProvider := startLDAPBackendACLProvider(t)
		defer stopProvider()
		proxyURI, stopProxy := startLDAPGoBackendACLProxy(t, providerURI)
		defer stopProxy()

		got := observeLDAPBackendLocalACL(t, proxyURI, providerURI)
		if !reflect.DeepEqual(got, reference) {
			t.Fatalf(
				"ldap-go back-ldap local olcAccess differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
				reference,
				got,
			)
		}
	})
}

func ldapBackendACLRules() []string {
	return []string{
		`to dn.exact="uid=bob,` + ldapBackendTestPeopleDN + `" by * none`,
		`to attrs=description val.regex="^classified$" by * none`,
		`to * by * read`,
	}
}

func assertOpenLDAPLDAPBackendACLReference(
	t *testing.T,
	tools openLDAPReferenceTools,
) {
	t.Helper()
	output, err := exec.Command(tools.slapd, "-VV").CombinedOutput()
	if err != nil && len(output) == 0 {
		t.Fatalf("inspect OpenLDAP back-ldap version: %v", err)
	}
	if !strings.Contains(string(output), "OpenLDAP: slapd 2.6.13 ") {
		t.Fatalf("back-ldap ACL differential requires OpenLDAP 2.6.13, got:\n%s", output)
	}
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Fatal("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	read := func(relativePath string) string {
		t.Helper()
		contents, err := exec.Command(
			"git",
			"-C",
			source,
			"show",
			openLDAPLDAPBackendACLCommit+":"+relativePath,
		).Output()
		if err != nil {
			t.Fatalf("read pinned OpenLDAP %s: %v", relativePath, err)
		}
		return string(contents)
	}
	search := read("servers/slapd/back-ldap/search.c")
	build := strings.Index(search, "ldap_build_entry( op, e, &ent")
	send := strings.Index(search, "send_search_entry( op, rs )")
	if build < 0 || send < 0 || send < build {
		t.Fatal("pinned back-ldap Search no longer decodes entries before send_search_entry ACL processing")
	}
	for _, relativePath := range []string{
		"servers/slapd/back-ldap/compare.c",
		"servers/slapd/back-ldap/add.c",
		"servers/slapd/back-ldap/modify.c",
		"servers/slapd/back-ldap/delete.c",
		"servers/slapd/back-ldap/modrdn.c",
	} {
		if strings.Contains(read(relativePath), "access_allowed(") {
			t.Fatalf("pinned %s unexpectedly performs local ACL authorization", relativePath)
		}
	}
}

func startLDAPBackendACLProvider(t *testing.T) (string, func()) {
	return startLDAPBackendACLProviderWithAudit(t, nil)
}

func startLDAPBackendACLProviderWithAudit(
	t *testing.T,
	sink audit.Sink,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPBackendProvider(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(ldapBackendTestUserDN)
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("description", stringValues("public", "classified"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("seed back-ldap ACL provider values: %v", err)
	}
	address, stop := startServer(t, store, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
		AuditSink:    sink,
	})
	return "ldap://" + address, stop
}

func startOpenLDAPBackendACLProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerURI string,
) (string, func()) {
	t.Helper()
	rules := ldapBackendACLRules()
	return startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		fmt.Sprintf(
			`access to * by * read

database ldap
suffix "%s"
rootdn "%s"
rootpw %s
uri %s
network-timeout 1
chase-referrals FALSE
idassert-bind bindmethod=simple binddn="%s" credentials="%s" mode=none
access %s
access %s
access %s`,
			ldapBackendTestSuffix,
			ldapBackendTestLocalRootDN,
			ldapBackendTestLocalRootPW,
			providerURI,
			ldapBackendTestAdminDN,
			ldapBackendTestAdminSecret,
			rules[0],
			rules[1],
			rules[2],
		),
		"",
	)
}

func startLDAPGoBackendACLProxy(
	t *testing.T,
	providerURI string,
) (string, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPBackendProxyURI(t, store, providerURI)
	dn, err := directory.ParseDN(ldapBackendTestDatabaseDN)
	if err != nil {
		t.Fatalf("parse back-ldap configuration DN: %v", err)
	}
	rules := ldapBackendACLRules()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccess", stringValues(
			"{0}"+rules[0],
			"{1}"+rules[1],
			"{2}"+rules[2],
		))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("seed ldap-go back-ldap olcAccess: %v", err)
	}
	address, stop := startServer(t, store, Config{})
	return "ldap://" + address, stop
}

func observeLDAPBackendLocalACL(
	t *testing.T,
	proxyURI,
	providerURI string,
) openLDAPBackendACLOutcome {
	t.Helper()
	client, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Fatalf("dial back-ldap ACL proxy %s: %v", proxyURI, err)
	}
	defer client.Close()
	if err := client.Bind(ldapBackendTestUserDN, ldapBackendTestUserPassword); err != nil {
		t.Fatalf("bind back-ldap ACL proxy %s: %v", proxyURI, err)
	}

	visible, err := client.Search(ldap.NewSearchRequest(
		ldapBackendTestUserDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid", "cn", "sn", "description"},
		nil,
	))
	if err != nil {
		t.Fatalf("visible back-ldap ACL Search: %v", err)
	}
	outcome := openLDAPBackendACLOutcome{visibleEntries: len(visible.Entries)}
	if len(visible.Entries) == 1 {
		for _, attribute := range visible.Entries[0].Attributes {
			outcome.visibleAttributes = append(
				outcome.visibleAttributes,
				strings.ToLower(attribute.Name),
			)
		}
		sort.Strings(outcome.visibleAttributes)
		outcome.descriptionValues = append(
			[]string(nil),
			visible.Entries[0].GetAttributeValues("description")...,
		)
		sort.Strings(outcome.descriptionValues)
	}

	hidden, err := client.Search(ldap.NewSearchRequest(
		"uid=bob,"+ldapBackendTestPeopleDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid", "cn"},
		nil,
	))
	if err != nil {
		t.Fatalf("hidden back-ldap ACL Search: %v", err)
	}
	outcome.hiddenEntries = len(hidden.Entries)

	filtered, err := client.Search(ldap.NewSearchRequest(
		ldapBackendTestUserDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(description=classified)",
		[]string{"uid"},
		nil,
	))
	if err != nil {
		t.Fatalf("filter back-ldap ACL Search: %v", err)
	}
	outcome.filterEntries = len(filtered.Entries)
	outcome.compareClassified, err = client.Compare(
		ldapBackendTestUserDN,
		"description",
		"classified",
	)
	outcome.compareClassifiedRC = monitorLDAPResultCode(err)
	outcome.compareHidden, err = client.Compare(
		"uid=bob,"+ldapBackendTestPeopleDN,
		"cn",
		"Bob Proxy",
	)
	outcome.compareHiddenRC = monitorLDAPResultCode(err)

	modify := ldap.NewModifyRequest(ldapBackendTestUserDN, nil)
	modify.Replace("description", []string{"modified-through-proxy"})
	outcome.modifyRC = monitorLDAPResultCode(client.Modify(modify))
	createdDN := "uid=acl-write," + ldapBackendTestPeopleDN
	add := ldap.NewAddRequest(createdDN, nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"acl-write"})
	add.Attribute("cn", []string{"ACL Write"})
	add.Attribute("sn", []string{"Write"})
	outcome.addRC = monitorLDAPResultCode(client.Add(add))
	renamedDN := "uid=acl-renamed," + ldapBackendTestPeopleDN
	outcome.modifyDNRC = monitorLDAPResultCode(client.ModifyDN(
		ldap.NewModifyDNRequest(createdDN, "uid=acl-renamed", true, ""),
	))
	outcome.deleteRC = monitorLDAPResultCode(client.Del(
		ldap.NewDelRequest(renamedDN, nil),
	))
	provider := dialLDAPBackendClient(t, strings.TrimPrefix(providerURI, "ldap://"))
	defer provider.Close()
	if err := provider.Bind(ldapBackendTestAdminDN, ldapBackendTestAdminSecret); err != nil {
		t.Fatalf("bind back-ldap ACL provider: %v", err)
	}
	result, err := provider.Search(ldap.NewSearchRequest(
		ldapBackendTestUserDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"description"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("read back-ldap ACL provider after Modify: %#v, %v", result, err)
	}
	outcome.providerDescription = result.Entries[0].GetAttributeValue("description")
	created, err := provider.Search(ldap.NewSearchRequest(
		renamedDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	))
	if err == nil {
		outcome.createdAfterDelete = len(created.Entries)
	} else if code := monitorLDAPResultCode(err); code != ldap.LDAPResultNoSuchObject {
		t.Fatalf("read deleted back-ldap ACL provider entry: %v", err)
	}
	return outcome
}

func assertOpenLDAPBackendACLFixture(
	t *testing.T,
	got openLDAPBackendACLOutcome,
) {
	t.Helper()
	want := openLDAPBackendACLOutcome{
		visibleEntries:      1,
		visibleAttributes:   []string{"cn", "description", "sn", "uid"},
		descriptionValues:   []string{"public"},
		hiddenEntries:       0,
		filterEntries:       1,
		compareClassified:   true,
		compareClassifiedRC: ldap.LDAPResultSuccess,
		compareHidden:       true,
		compareHiddenRC:     ldap.LDAPResultSuccess,
		modifyRC:            ldap.LDAPResultSuccess,
		addRC:               ldap.LDAPResultSuccess,
		modifyDNRC:          ldap.LDAPResultSuccess,
		deleteRC:            ldap.LDAPResultSuccess,
		providerDescription: "modified-through-proxy",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"OpenLDAP 2.6.13 back-ldap local ACL fixture drifted:\n got: %#v\nwant: %#v",
			got,
			want,
		)
	}
}
