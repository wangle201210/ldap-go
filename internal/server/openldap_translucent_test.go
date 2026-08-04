package server

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPTranslucentVersion = "2.6.13"
	openLDAPTranslucentCommit  = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

	translucentPhaseOneBaseDN   = "ou=translucent,dc=example,dc=com"
	translucentPhaseOneMergedDN = "uid=merged," + translucentPhaseOneBaseDN
)

type translucentPhaseOneAttribute struct {
	name   string
	values []string
}

type translucentPhaseOneEntry struct {
	dn         string
	attributes []translucentPhaseOneAttribute
}

type translucentPhaseOneSearch struct {
	code    uint16
	entries []translucentPhaseOneEntry
}

type translucentPhaseOneOutcome struct {
	search                translucentPhaseOneSearch
	compareLocal          uint16
	compareShadowedRemote uint16
	compareRemoteFallback uint16
	manageDSAIT           translucentPhaseOneSearch
}

func TestOpenLDAPReferenceTranslucentPhaseOne(t *testing.T) {
	tools := requireOpenLDAPTranslucentReferenceTools(t)
	assertPinnedOpenLDAPTranslucentReference(t)

	var reference translucentPhaseOneOutcome
	t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
		remoteURI, stopRemote := startOpenLDAPReferenceServer(t, tools, nil)
		defer stopRemote()
		remote := bindOverlayReferenceClient(t, remoteURI, "secret")
		defer remote.Close()
		addTranslucentPhaseOneRemoteFixture(t, remote)

		localURI, stopLocal := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			[]string{translucentPhaseOneStaticOverlay(remoteURI)},
			"",
			"",
			"",
		)
		defer stopLocal()
		local := bindOverlayReferenceClient(t, localURI, "secret")
		defer local.Close()
		addTranslucentPhaseOneLocalOverride(t, local)

		reference = observeTranslucentPhaseOne(t, local)
		assertOpenLDAPTranslucentPhaseOne(t, reference)
	})
	if t.Failed() {
		return
	}

	t.Run("ldap-go differential", func(t *testing.T) {
		remoteURI, stopRemote := startOpenLDAPReferenceServer(t, tools, nil)
		defer stopRemote()
		remote := bindOverlayReferenceClient(t, remoteURI, "secret")
		defer remote.Close()
		addTranslucentPhaseOneRemoteFixture(t, remote)

		local, stopLocal := startTranslucentPhaseOneLDAPGo(t, remoteURI)
		defer stopLocal()
		defer local.Close()
		got := observeTranslucentPhaseOne(t, local)
		if !reflect.DeepEqual(got, reference) {
			t.Fatalf(
				"ldap-go translucent Phase 1 is not implemented or differs from OpenLDAP 2.6.13:\nOpenLDAP: %#v\nldap-go:  %#v",
				reference,
				got,
			)
		}
	})
}

func requireOpenLDAPTranslucentReferenceTools(
	t *testing.T,
) openLDAPReferenceTools {
	t.Helper()
	tools := requireOpenLDAPLDAPBackendReferenceTools(t)
	output, err := exec.Command(tools.slapd, "-VVV").CombinedOutput()
	if err != nil && len(output) == 0 {
		t.Skipf("inspect OpenLDAP overlays: %v", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.EqualFold(strings.TrimSpace(line), "translucent") {
			return tools
		}
	}
	t.Skip("the selected OpenLDAP slapd was not built with the translucent overlay")
	return openLDAPReferenceTools{}
}

func assertPinnedOpenLDAPTranslucentReference(t *testing.T) {
	t.Helper()
	if os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" {
		t.Fatal("translucent differential requires a verified OpenLDAP reference build")
	}
	if got := os.Getenv("OPENLDAP_ACTUAL_VERSION"); got != openLDAPTranslucentVersion {
		t.Fatalf("OpenLDAP reference version = %q, want %q", got, openLDAPTranslucentVersion)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPTranslucentCommit {
		t.Fatalf("OpenLDAP reference commit = %q, want %q", got, openLDAPTranslucentCommit)
	}

	source := os.Getenv("OPENLDAP_SOURCE")
	revision, err := exec.Command("git", "-C", source, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("inspect pinned OpenLDAP checkout: %v", err)
	}
	if got := strings.TrimSpace(string(revision)); got != openLDAPTranslucentCommit {
		t.Fatalf("OpenLDAP source checkout = %q, want %q", got, openLDAPTranslucentCommit)
	}
	assertTranslucentSourceAnchors(t, filepath.Join(
		source,
		"servers",
		"slapd",
		"overlays",
		"translucent.c",
	), []string{
		"static int translucent_compare(Operation *op, SlapReply *rs)",
		"static int translucent_search(Operation *op, SlapReply *rs)",
		"if ( op->o_managedsait > SLAP_CONTROL_IGNORED )",
		"ber_bvarray_dup_x( &a->a_vals, ax->a_vals, NULL );",
		"ov->db.bd_info->bi_op_compare(op, rs)",
	})
	assertTranslucentSourceAnchors(t, filepath.Join(
		source,
		"tests",
		"scripts",
		"test034-translucent",
	), []string{
		"Testing search: data merging...",
		"Testing compare: valid local...",
	})
	assertTranslucentSourceAnchors(t, filepath.Join(
		source,
		"tests",
		"data",
		"regressions",
		"its10248",
		"its10248",
	), []string{"Searching a translucent overlay with subordinate backend."})
}

func assertTranslucentSourceAnchors(
	t *testing.T,
	path string,
	anchors []string,
) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pinned OpenLDAP source %s: %v", path, err)
	}
	for _, anchor := range anchors {
		if !bytes.Contains(contents, []byte(anchor)) {
			t.Fatalf("pinned OpenLDAP source %s lacks %q", path, anchor)
		}
	}
}

func translucentPhaseOneStaticOverlay(remoteURI string) string {
	return strings.Join([]string{
		"translucent",
		"uri " + remoteURI,
		"network-timeout 1",
		"chase-referrals FALSE",
	}, "\n")
}

func addTranslucentPhaseOneRemoteFixture(t *testing.T, client *ldap.Conn) {
	t.Helper()
	base := ldap.NewAddRequest(translucentPhaseOneBaseDN, nil)
	base.Attribute("objectClass", []string{"organizationalUnit"})
	base.Attribute("ou", []string{"translucent"})
	if err := client.Add(base); err != nil {
		t.Fatalf("Add(translucent remote base): %v", err)
	}

	entry := ldap.NewAddRequest(translucentPhaseOneMergedDN, nil)
	entry.Attribute("objectClass", []string{"inetOrgPerson"})
	entry.Attribute("uid", []string{"merged"})
	entry.Attribute("cn", []string{"Remote Merged"})
	entry.Attribute("sn", []string{"Merged"})
	entry.Attribute("description", []string{"remote-one", "remote-two"})
	entry.Attribute("telephoneNumber", []string{"100"})
	if err := client.Add(entry); err != nil {
		t.Fatalf("Add(translucent remote entry): %v", err)
	}
}

func addTranslucentPhaseOneLocalOverride(t *testing.T, client *ldap.Conn) {
	t.Helper()
	entry := ldap.NewAddRequest(translucentPhaseOneMergedDN, nil)
	entry.Attribute("description", []string{"local-only"})
	if err := client.Add(entry); err != nil {
		t.Fatalf("Add(translucent local override): %v", err)
	}
}

func observeTranslucentPhaseOne(
	t *testing.T,
	client *ldap.Conn,
) translucentPhaseOneOutcome {
	t.Helper()
	return translucentPhaseOneOutcome{
		search: translucentPhaseOneSearchEntry(
			t,
			client,
			nil,
		),
		compareLocal: translucentPhaseOneCompareCode(
			t,
			client,
			"description",
			"local-only",
		),
		compareShadowedRemote: translucentPhaseOneCompareCode(
			t,
			client,
			"description",
			"remote-one",
		),
		compareRemoteFallback: translucentPhaseOneCompareCode(
			t,
			client,
			"telephoneNumber",
			"100",
		),
		manageDSAIT: translucentPhaseOneSearchEntry(
			t,
			client,
			[]ldap.Control{ldap.NewControlManageDsaIT(true)},
		),
	}
}

func translucentPhaseOneSearchEntry(
	t *testing.T,
	client *ldap.Conn,
	controls []ldap.Control,
) translucentPhaseOneSearch {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		translucentPhaseOneMergedDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(description=*)",
		[]string{"cn", "description", "telephoneNumber"},
		controls,
	))
	outcome := translucentPhaseOneSearch{code: translucentPhaseOneResultCode(t, err)}
	if result == nil {
		return outcome
	}
	for _, entry := range result.Entries {
		observed := translucentPhaseOneEntry{dn: strings.ToLower(entry.DN)}
		for _, attribute := range entry.Attributes {
			values := append([]string(nil), attribute.Values...)
			sort.Strings(values)
			observed.attributes = append(observed.attributes, translucentPhaseOneAttribute{
				name:   strings.ToLower(attribute.Name),
				values: values,
			})
		}
		sort.Slice(observed.attributes, func(left, right int) bool {
			return observed.attributes[left].name < observed.attributes[right].name
		})
		outcome.entries = append(outcome.entries, observed)
	}
	sort.Slice(outcome.entries, func(left, right int) bool {
		return outcome.entries[left].dn < outcome.entries[right].dn
	})
	return outcome
}

func translucentPhaseOneCompareCode(
	t *testing.T,
	client *ldap.Conn,
	attribute,
	value string,
) uint16 {
	t.Helper()
	matched, err := client.Compare(
		translucentPhaseOneMergedDN,
		attribute,
		value,
	)
	if err != nil {
		return translucentPhaseOneResultCode(t, err)
	}
	if matched {
		return ldap.LDAPResultCompareTrue
	}
	return ldap.LDAPResultCompareFalse
}

func translucentPhaseOneResultCode(t *testing.T, err error) uint16 {
	t.Helper()
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) {
		t.Fatalf("translucent operation returned a non-LDAP error: %v", err)
	}
	return ldapErr.ResultCode
}

func assertOpenLDAPTranslucentPhaseOne(
	t *testing.T,
	got translucentPhaseOneOutcome,
) {
	t.Helper()
	want := translucentPhaseOneOutcome{
		search: translucentPhaseOneSearch{
			code: ldap.LDAPResultSuccess,
			entries: []translucentPhaseOneEntry{{
				dn: translucentPhaseOneMergedDN,
				attributes: []translucentPhaseOneAttribute{
					{name: "cn", values: []string{"Remote Merged"}},
					{name: "description", values: []string{"local-only"}},
					{name: "telephonenumber", values: []string{"100"}},
				},
			}},
		},
		compareLocal:          ldap.LDAPResultCompareTrue,
		compareShadowedRemote: ldap.LDAPResultCompareFalse,
		compareRemoteFallback: ldap.LDAPResultCompareTrue,
		manageDSAIT: translucentPhaseOneSearch{
			code: ldap.LDAPResultSuccess,
			entries: []translucentPhaseOneEntry{{
				dn: translucentPhaseOneMergedDN,
				attributes: []translucentPhaseOneAttribute{
					{name: "description", values: []string{"local-only"}},
				},
			}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("OpenLDAP translucent fixture drifted:\n got: %#v\nwant: %#v", got, want)
	}
}

func startTranslucentPhaseOneLDAPGo(
	t *testing.T,
	remoteURI string,
) (*ldap.Conn, func()) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	entries := []directory.Entry{
		{
			DN: "olcOverlay={0}translucent,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcTranslucentConfig")},
				{Description: "olcOverlay", Values: stringValues("{0}translucent")},
			},
		},
		{
			DN: "olcDatabase={0}ldap,olcOverlay={0}translucent,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcTranslucentDatabase")},
				{Description: "olcDatabase", Values: stringValues("{0}ldap")},
				{Description: "olcDbURI", Values: stringValues(remoteURI)},
			},
		},
		{
			DN: translucentPhaseOneBaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit")},
				{Description: "ou", Values: stringValues("translucent")},
			},
		},
		{
			DN: translucentPhaseOneMergedDN,
			Attributes: []directory.Attribute{
				{Description: "description", Values: stringValues("local-only")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed ldap-go translucent fixture: %v", err)
	}
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	client := bindOverlayReferenceClient(t, "ldap://"+address, "secret")
	return client, stop
}
