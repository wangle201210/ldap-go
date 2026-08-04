package server

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type translucentPhaseTwoDifferentialOutcome struct {
	addOverride       uint16
	localFilterDNs    []string
	remoteFilterDNs   []string
	combinedFilterDNs []string
	remoteBind        uint16
	localBind         uint16
	modifyRemoteOnly  uint16
	strictDelete      uint16
	renameLocal       uint16
	oldDescription    string
	newDescription    string
	deleteLocal       uint16
	revealedRemote    string
	passwordModify    uint16
	changedLocalBind  uint16
	nonRootAdd        uint16
}

func TestOpenLDAPReferenceTranslucentPhaseTwoSourceContract(t *testing.T) {
	requireOpenLDAPTranslucentReferenceTools(t)
	assertPinnedOpenLDAPTranslucentReference(t)
	source := os.Getenv("OPENLDAP_SOURCE")
	tests := []struct {
		path    string
		hash    string
		anchors []string
	}{
		{
			path: filepath.Join(source, "servers", "slapd", "overlays", "translucent.c"),
			hash: "9920a3de864d229907252477db5cf81a498ecccefb0ce5685dc8407ebed592cd",
			anchors: []string{
				"NAME 'olcTranslucentStrict'",
				"NAME 'olcTranslucentNoGlue'",
				"NAME 'olcTranslucentLocal'",
				"NAME 'olcTranslucentRemote'",
				"NAME 'olcTranslucentBindLocal'",
				"NAME 'olcTranslucentPwModLocal'",
				"if(!ov->no_glue) glue_parent(op);",
				"if(ov->strict)",
				"fr = ov->remote ? trans_filter_dup",
				"fl = ov->local ? trans_filter_dup",
				"if (ov->bind_local)",
				"if (!ov->pwmod_local)",
			},
		},
		{
			path: filepath.Join(source, "tests", "scripts", "test034-translucent"),
			hash: "91294588a146c8bb5b24d800961e1bf92fee158148649e43934ba07be33ee528",
			anchors: []string{
				"Testing add: valid local record, no_glue...",
				"Testing strict mode delete: nonexistent local attribute...",
				"Testing search: configured local filter...",
				"Testing search: configured remote filter...",
			},
		},
		{
			path: filepath.Join(source, "doc", "man", "man5", "slapo-translucent.5"),
			hash: "439ed5f35b83430cd4f810241e1c35279abee36e31a016d54a541c12fba8c1ec",
			anchors: []string{
				"translucent_strict",
				"translucent_no_glue",
				"translucent_bind_local",
				"translucent_pwmod_local",
			},
		},
	}
	for _, test := range tests {
		contents, err := os.ReadFile(test.path)
		if err != nil {
			t.Fatalf("read pinned OpenLDAP source %s: %v", test.path, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != test.hash {
			t.Fatalf("pinned OpenLDAP source hash %s = %s, want %s", test.path, got, test.hash)
		}
		assertTranslucentSourceAnchors(t, test.path, test.anchors)
	}
}

func TestOpenLDAPReferenceTranslucentPhaseTwoDifferential(t *testing.T) {
	tools := requireOpenLDAPTranslucentReferenceTools(t)
	assertPinnedOpenLDAPTranslucentReference(t)

	var reference translucentPhaseTwoDifferentialOutcome
	t.Run("OpenLDAP fixture", func(t *testing.T) {
		remoteURI, stopRemote := startOpenLDAPReferenceServer(t, tools, nil)
		defer stopRemote()
		remote := bindOverlayReferenceClient(t, remoteURI, "secret")
		defer remote.Close()
		addTranslucentPhaseTwoRemoteFixture(t, remote)

		localURI, stopLocal := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{translucentPhaseTwoStaticOverlay(remoteURI, false)},
			"",
			"",
			"",
		)
		defer stopLocal()
		local := bindOverlayReferenceClient(t, localURI, "secret")
		defer local.Close()
		reference = observeTranslucentPhaseTwo(t, local, localURI)
	})
	if t.Failed() {
		return
	}
	wantReference := translucentPhaseTwoDifferentialOutcome{
		addOverride:       ldap.LDAPResultSuccess,
		localFilterDNs:    []string{strings.ToLower(translucentPhase2UserDN)},
		remoteFilterDNs:   []string{strings.ToLower(translucentPhase2UserDN)},
		combinedFilterDNs: []string{strings.ToLower(translucentPhase2UserDN)},
		remoteBind:        ldap.LDAPResultSuccess,
		localBind:         ldap.LDAPResultSuccess,
		modifyRemoteOnly:  ldap.LDAPResultSuccess,
		strictDelete:      ldap.LDAPResultConstraintViolation,
		renameLocal:       ldap.LDAPResultNoSuchAttribute,
		oldDescription:    "local-old-override",
		newDescription:    "remote-new",
		deleteLocal:       ldap.LDAPResultNoSuchObject,
		revealedRemote:    "remote-new",
		passwordModify:    ldap.LDAPResultSuccess,
		changedLocalBind:  ldap.LDAPResultSuccess,
		nonRootAdd:        ldap.LDAPResultInsufficientAccessRights,
	}
	if !reflect.DeepEqual(reference, wantReference) {
		t.Fatalf(
			"OpenLDAP translucent Phase 2 fixture did not exercise the pinned contract:\n got: %#v\nwant: %#v",
			reference,
			wantReference,
		)
	}

	t.Run("ldap-go differential", func(t *testing.T) {
		remoteURI, stopRemote := startOpenLDAPReferenceServer(t, tools, nil)
		defer stopRemote()
		remote := bindOverlayReferenceClient(t, remoteURI, "secret")
		defer remote.Close()
		addTranslucentPhaseTwoRemoteFixture(t, remote)

		local, localURI, stopLocal := startTranslucentPhaseTwoLDAPGo(
			t,
			remoteURI,
			false,
		)
		defer stopLocal()
		defer local.Close()
		got := observeTranslucentPhaseTwo(t, local, localURI)
		if !reflect.DeepEqual(got, reference) {
			t.Fatalf(
				"ldap-go translucent Phase 2 differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
				reference,
				got,
			)
		}
	})
}

func TestOpenLDAPReferenceTranslucentNoGlueDifferential(t *testing.T) {
	tools := requireOpenLDAPTranslucentReferenceTools(t)
	assertPinnedOpenLDAPTranslucentReference(t)

	run := func(t *testing.T, ldapGo bool) uint16 {
		remoteURI, stopRemote := startOpenLDAPReferenceServer(t, tools, nil)
		defer stopRemote()
		remote := bindOverlayReferenceClient(t, remoteURI, "secret")
		defer remote.Close()
		addTranslucentPhaseTwoRemoteFixture(t, remote)

		var local *ldap.Conn
		var stopLocal func()
		if ldapGo {
			local, _, stopLocal = startTranslucentPhaseTwoLDAPGo(t, remoteURI, true)
		} else {
			localURI, stop := startOpenLDAPReferenceServerWithConfig(
				t,
				tools,
				[]string{translucentPhaseTwoStaticOverlay(remoteURI, true)},
				"",
				"",
				"",
			)
			stopLocal = stop
			local = bindOverlayReferenceClient(t, localURI, "secret")
		}
		defer stopLocal()
		defer local.Close()
		return translucentPhaseOneResultCode(t, local.Add(
			translucentPhaseTwoLocalOverrideRequest(),
		))
	}

	reference := run(t, false)
	if reference != ldap.LDAPResultNoSuchObject {
		t.Fatalf("OpenLDAP noGlue Add = %d, want noSuchObject", reference)
	}
	if got := run(t, true); got != reference {
		t.Fatalf("ldap-go noGlue Add = %d, OpenLDAP = %d", got, reference)
	}
}

func translucentPhaseTwoStaticOverlay(remoteURI string, noGlue bool) string {
	lines := []string{
		"translucent",
		"translucent_strict",
		"translucent_local description",
		"translucent_remote telephoneNumber",
		"translucent_bind_local",
		"translucent_pwmod_local",
	}
	if noGlue {
		lines = append(lines, "translucent_no_glue")
	}
	lines = append(lines,
		"uri "+remoteURI,
		"network-timeout 1",
		"chase-referrals FALSE",
	)
	return strings.Join(lines, "\n")
}

func addTranslucentPhaseTwoRemoteFixture(t *testing.T, client *ldap.Conn) {
	t.Helper()
	base := ldap.NewAddRequest(translucentTestBaseDN, nil)
	base.Attribute("objectClass", []string{"organizationalUnit"})
	base.Attribute("ou", []string{"translucent"})
	if err := client.Add(base); err != nil {
		t.Fatalf("Add(translucent Phase 2 remote base): %v", err)
	}
	entries := []struct {
		dn          string
		uid         string
		description string
		telephone   string
		password    string
	}{
		{translucentPhase2UserDN, "phase2", "remote-phase2", "100", "remote-phase2-secret"},
		{translucentPhase2OldDN, "phase2-old", "remote-old", "101", ""},
		{translucentPhase2NewDN, "phase2-new", "remote-new", "102", ""},
	}
	for _, fixture := range entries {
		entry := ldap.NewAddRequest(fixture.dn, nil)
		entry.Attribute("objectClass", []string{"inetOrgPerson"})
		entry.Attribute("uid", []string{fixture.uid})
		entry.Attribute("cn", []string{fixture.uid})
		entry.Attribute("sn", []string{fixture.uid})
		entry.Attribute("description", []string{fixture.description})
		entry.Attribute("telephoneNumber", []string{fixture.telephone})
		if fixture.password != "" {
			entry.Attribute("userPassword", []string{fixture.password})
		}
		if err := client.Add(entry); err != nil {
			t.Fatalf("Add(translucent Phase 2 remote %s): %v", fixture.dn, err)
		}
	}
}

func observeTranslucentPhaseTwo(
	t *testing.T,
	root *ldap.Conn,
	uri string,
) translucentPhaseTwoDifferentialOutcome {
	t.Helper()
	outcome := translucentPhaseTwoDifferentialOutcome{}
	outcome.addOverride = translucentPhaseOneResultCode(
		t,
		root.Add(translucentPhaseTwoLocalOverrideRequest()),
	)
	outcome.localFilterDNs = translucentPhaseTwoSearchDNs(
		t,
		root,
		"(description=local-phase2)",
	)
	outcome.remoteFilterDNs = translucentPhaseTwoSearchDNs(
		t,
		root,
		"(telephoneNumber=100)",
	)
	outcome.combinedFilterDNs = translucentPhaseTwoSearchDNs(
		t,
		root,
		"(&(description=local-phase2)(telephoneNumber=100))",
	)
	outcome.remoteBind = translucentPhaseTwoBindCode(
		t,
		uri,
		translucentPhase2UserDN,
		"remote-phase2-secret",
	)
	outcome.localBind = translucentPhaseTwoBindCode(
		t,
		uri,
		translucentPhase2UserDN,
		"local-phase2-secret",
	)

	modify := ldap.NewModifyRequest(translucentPhase2OldDN, nil)
	modify.Replace("description", []string{"local-old-override"})
	outcome.modifyRemoteOnly = translucentPhaseOneResultCode(t, root.Modify(modify))
	strictDelete := ldap.NewModifyRequest(translucentPhase2UserDN, nil)
	strictDelete.Delete("telephoneNumber", nil)
	outcome.strictDelete = translucentPhaseOneResultCode(t, root.Modify(strictDelete))
	outcome.renameLocal = translucentPhaseOneResultCode(t, root.ModifyDN(
		ldap.NewModifyDNRequest(
			translucentPhase2OldDN,
			"uid=phase2-new",
			true,
			"",
		),
	))
	outcome.oldDescription = translucentPhaseTwoReadAttribute(
		t,
		root,
		translucentPhase2OldDN,
		"description",
	)
	outcome.newDescription = translucentPhaseTwoReadAttribute(
		t,
		root,
		translucentPhase2NewDN,
		"description",
	)
	outcome.deleteLocal = translucentPhaseOneResultCode(
		t,
		root.Del(ldap.NewDelRequest(translucentPhase2NewDN, nil)),
	)
	outcome.revealedRemote = translucentPhaseTwoReadAttribute(
		t,
		root,
		translucentPhase2NewDN,
		"description",
	)
	_, passwordErr := root.PasswordModify(ldap.NewPasswordModifyRequest(
		translucentPhase2UserDN,
		"",
		"changed-local-secret",
	))
	outcome.passwordModify = translucentPhaseOneResultCode(t, passwordErr)
	outcome.changedLocalBind = translucentPhaseTwoBindCode(
		t,
		uri,
		translucentPhase2UserDN,
		"changed-local-secret",
	)

	nonRoot, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(non-root %s): %v", uri, err)
	}
	defer nonRoot.Close()
	if err := nonRoot.Bind(translucentPhase2UserDN, "remote-phase2-secret"); err != nil {
		t.Fatalf("Bind(non-root %s): %v", uri, err)
	}
	denied := ldap.NewAddRequest("uid=denied,"+translucentTestBaseDN, nil)
	denied.Attribute("objectClass", []string{"inetOrgPerson"})
	denied.Attribute("uid", []string{"denied"})
	denied.Attribute("cn", []string{"denied"})
	denied.Attribute("sn", []string{"denied"})
	outcome.nonRootAdd = translucentPhaseOneResultCode(t, nonRoot.Add(denied))
	return outcome
}

func translucentPhaseTwoLocalOverrideRequest() *ldap.AddRequest {
	entry := ldap.NewAddRequest(translucentPhase2UserDN, nil)
	entry.Attribute("objectClass", []string{"inetOrgPerson"})
	entry.Attribute("uid", []string{"phase2"})
	entry.Attribute("cn", []string{"phase2"})
	entry.Attribute("sn", []string{"phase2"})
	entry.Attribute("description", []string{"local-phase2"})
	entry.Attribute("userPassword", []string{"local-phase2-secret"})
	return entry
}

func translucentPhaseTwoSearchDNs(
	t *testing.T,
	client *ldap.Conn,
	filter string,
) []string {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		translucentTestBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"uid"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(%s): %v", filter, err)
	}
	dns := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		dns = append(dns, strings.ToLower(entry.DN))
	}
	sort.Strings(dns)
	return dns
}

func translucentPhaseTwoReadAttribute(
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
		t.Fatalf("Search(%s): %v", dn, err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("Search(%s) entries = %d, want 1", dn, len(result.Entries))
	}
	return result.Entries[0].GetAttributeValue(attribute)
}

func translucentPhaseTwoBindCode(
	t *testing.T,
	uri,
	dn,
	password string,
) uint16 {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	return translucentPhaseOneResultCode(t, client.Bind(dn, password))
}

func startTranslucentPhaseTwoLDAPGo(
	t *testing.T,
	remoteURI string,
	noGlue bool,
) (*ldap.Conn, string, func()) {
	t.Helper()
	store := storage.NewMemory()
	seedOnlineConfiguration(t, store)
	overlay := translucentTestOverlayEntry(translucentTestOverlayDN, false)
	overlay.Attributes = append(overlay.Attributes,
		directory.Attribute{Description: "olcTranslucentStrict", Values: stringValues("TRUE")},
		directory.Attribute{Description: "olcTranslucentLocal", Values: stringValues("description")},
		directory.Attribute{Description: "olcTranslucentRemote", Values: stringValues("telephoneNumber")},
		directory.Attribute{Description: "olcTranslucentBindLocal", Values: stringValues("TRUE")},
		directory.Attribute{Description: "olcTranslucentPwModLocal", Values: stringValues("TRUE")},
	)
	if noGlue {
		overlay.Attributes = append(overlay.Attributes, directory.Attribute{
			Description: "olcTranslucentNoGlue",
			Values:      stringValues("TRUE"),
		})
	}
	putTranslucentTestEntries(t, store,
		overlay,
		translucentTestBackendEntry(
			translucentTestBackendDN,
			"{0}ldap",
			remoteURI,
		),
	)
	address, stopServer := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	client := dialTranslucentPhase2(t, address)
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		client.Close()
		stopServer()
		_ = store.Close()
		t.Fatalf("Bind(ldap-go translucent root): %v", err)
	}
	stop := func() {
		stopServer()
		_ = store.Close()
	}
	return client, "ldap://" + address, stop
}
