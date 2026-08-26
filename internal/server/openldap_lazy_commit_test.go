package server

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceLazyCommitControl(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	referenceURI, stopReference := startOpenLDAPReferenceServer(t, tools, nil)
	t.Cleanup(stopReference)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	localAddress, stopLocal := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	t.Cleanup(stopLocal)

	control := func(critical, hasValue bool, value []byte) ldap.Control {
		return &domainScopeWireControl{
			oid: lazyCommitControlOID, critical: critical,
			hasValue: hasValue, value: value,
		}
	}
	valid := control(false, false, nil)
	for _, test := range []struct {
		name     string
		controls []ldap.Control
		want     uint16
	}{
		{name: "noncritical", controls: []ldap.Control{valid}, want: ldap.LDAPResultSuccess},
		{name: "critical", controls: []ldap.Control{control(true, false, nil)}, want: ldap.LDAPResultSuccess},
		{name: "empty value", controls: []ldap.Control{control(false, true, nil)}, want: ldap.LDAPResultProtocolError},
		{name: "nonempty value", controls: []ldap.Control{control(true, true, []byte{0})}, want: ldap.LDAPResultProtocolError},
		{name: "duplicate", controls: []ldap.Control{valid, control(true, false, nil)}, want: ldap.LDAPResultProtocolError},
		{name: "duplicate before value", controls: []ldap.Control{valid, control(true, true, []byte{0})}, want: ldap.LDAPResultProtocolError},
	} {
		t.Run(test.name, func(t *testing.T) {
			reference := observeLazyCommitSearch(t, trimLDAPURI(referenceURI), test.controls)
			local := observeLazyCommitSearch(t, localAddress, test.controls)
			if reference != test.want || local != test.want {
				t.Fatalf("Lazy Commit Search: OpenLDAP=%d ldap-go=%d want=%d", reference, local, test.want)
			}
		})
	}

	for _, test := range []struct {
		name     string
		control  ldap.Control
		extended bool
		want     uint16
	}{
		{name: "Bind noncritical invalid ignored", control: control(false, true, []byte("ignored")), want: ldap.LDAPResultSuccess},
		{name: "Bind critical unsupported", control: control(true, false, nil), want: ldap.LDAPResultUnavailableCriticalExtension},
		{name: "Extended noncritical invalid ignored", control: control(false, true, []byte("ignored")), extended: true, want: ldap.LDAPResultSuccess},
		{name: "Extended critical unsupported", control: control(true, false, nil), extended: true, want: ldap.LDAPResultUnavailableCriticalExtension},
	} {
		t.Run(test.name, func(t *testing.T) {
			var reference, local uint16
			if test.extended {
				reference = observeLazyCommitWhoAmI(t, trimLDAPURI(referenceURI), test.control)
				local = observeLazyCommitWhoAmI(t, localAddress, test.control)
			} else {
				reference = observeLazyCommitBind(t, trimLDAPURI(referenceURI), test.control)
				local = observeLazyCommitBind(t, localAddress, test.control)
			}
			if reference != test.want || local != test.want {
				t.Fatalf("unsupported operation: OpenLDAP=%d ldap-go=%d want=%d", reference, local, test.want)
			}
		})
	}

	referenceLifecycle := observeLazyCommitWriteLifecycle(
		t,
		trimLDAPURI(referenceURI),
		control(true, false, nil),
		"reference",
	)
	localLifecycle := observeLazyCommitWriteLifecycle(
		t,
		localAddress,
		control(true, false, nil),
		"local",
	)
	for index, code := range referenceLifecycle {
		if code != ldap.LDAPResultSuccess {
			t.Fatalf("OpenLDAP Lazy Commit lifecycle operation %d = %d", index, code)
		}
	}
	if !reflect.DeepEqual(referenceLifecycle, localLifecycle) {
		t.Fatalf("Lazy Commit write lifecycle: OpenLDAP=%v ldap-go=%v", referenceLifecycle, localLifecycle)
	}

	for name, address := range map[string]string{
		"OpenLDAP": trimLDAPURI(referenceURI),
		"ldap-go":  localAddress,
	} {
		if lazyCommitRootDSEAdvertises(t, address) {
			t.Errorf("%s publishes hidden Lazy Commit control", name)
		}
	}
}

func observeLazyCommitSearch(t *testing.T, address string, controls []ldap.Control) uint16 {
	t.Helper()
	client := dialLazyCommitClient(t, address)
	defer client.Close()
	_, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"1.1"}, controls,
	))
	return monitorLDAPResultCode(err)
}

func observeLazyCommitBind(t *testing.T, address string, control ldap.Control) uint16 {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", address, err)
	}
	defer client.Close()
	_, err = client.SimpleBind(ldap.NewSimpleBindRequest(
		"cn=admin,dc=example,dc=com", "secret", []ldap.Control{control},
	))
	return monitorLDAPResultCode(err)
}

func observeLazyCommitWhoAmI(t *testing.T, address string, control ldap.Control) uint16 {
	t.Helper()
	client := dialLazyCommitClient(t, address)
	defer client.Close()
	request := ldap.NewExtendedRequest(whoAmIOID, nil)
	request.Controls = []ldap.Control{control}
	_, err := client.Extended(request)
	return monitorLDAPResultCode(err)
}

func observeLazyCommitWriteLifecycle(
	t *testing.T,
	address string,
	control ldap.Control,
	identifier string,
) []uint16 {
	t.Helper()
	client := dialLazyCommitClient(t, address)
	defer client.Close()
	dn := "uid=lazy-" + identifier + ",ou=people,dc=example,dc=com"
	add := ldap.NewAddRequest(dn, []ldap.Control{control})
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"lazy-" + identifier})
	add.Attribute("cn", []string{"Lazy Commit"})
	add.Attribute("sn", []string{"Commit"})
	codes := []uint16{monitorLDAPResultCode(client.Add(add))}
	modify := ldap.NewModifyRequest(dn, []ldap.Control{control})
	modify.Replace("cn", []string{"Lazy Commit Updated"})
	codes = append(codes, monitorLDAPResultCode(client.Modify(modify)))
	renamedDN := "uid=lazy-renamed-" + identifier + ",ou=people,dc=example,dc=com"
	rename := ldap.NewModifyDNRequest(dn, "uid=lazy-renamed-"+identifier, true, "")
	rename.Controls = []ldap.Control{control}
	codes = append(codes, monitorLDAPResultCode(client.ModifyDN(rename)))
	codes = append(codes, monitorLDAPResultCode(client.Del(ldap.NewDelRequest(
		renamedDN,
		[]ldap.Control{control},
	))))
	return codes
}

func dialLazyCommitClient(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", address, err)
	}
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		_ = client.Close()
		t.Fatalf("Bind(%s): %v", address, err)
	}
	return client
}

func lazyCommitRootDSEAdvertises(t *testing.T, address string) bool {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", address, err)
	}
	defer client.Close()
	result, err := client.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"supportedControl"}, nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("Root DSE(%s) = %#v, %v", address, result, err)
	}
	return slices.Contains(
		result.Entries[0].GetAttributeValues("supportedControl"),
		lazyCommitControlOID,
	)
}

func TestOpenLDAP2613LazyCommitSourceContract(t *testing.T) {
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	if sourceRoot == "" {
		t.Skip("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	command := exec.Command("git", "-C", sourceRoot, "rev-parse", "HEAD")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("read pinned OpenLDAP commit: %v", err)
	}
	if commit := strings.TrimSpace(string(output)); commit != "d172686d3d270bc961b78f3ff00d7019c8dfb094" {
		t.Fatalf("OpenLDAP source commit = %s", commit)
	}
	for _, file := range []struct {
		path    string
		hash    string
		anchors []string
	}{
		{
			path: "servers/slapd/controls.c",
			hash: "dac19d7202fd319e7d79487a0d3263e5f773750f1459457ae88f5179bb9e61d6",
			anchors: []string{
				"SLAP_CTRL_GLOBAL|SLAP_CTRL_ACCESS|SLAP_CTRL_HIDE",
				"parseLazyCommit",
				`\"Lazy Commit?\" control value not absent`,
			},
		},
		{
			path:    "servers/slapd/back-mdb/id2entry.c",
			hash:    "c3960e2ca8ad670a65da2cc3f9a12b4ac06b32f1fc98f59991ca5540c87830f6",
			anchors: []string{"get_lazyCommit( op )", "flag |= MDB_NOMETASYNC"},
		},
		{
			path: "libraries/liblmdb/mdb.c",
			hash: "eb8b0fdde8f13bed1139ae899bcc7767e44490f6316ccede59b62392d1c0d717",
			anchors: []string{
				"#define MDB_TXN_BEGIN_FLAGS\tMDB_RDONLY",
				"flags &= MDB_TXN_BEGIN_FLAGS",
				"flags = env->me_flags",
			},
		},
	} {
		contents, err := os.ReadFile(filepath.Join(sourceRoot, file.path))
		if err != nil {
			t.Fatalf("read %s: %v", file.path, err)
		}
		if hash := fmt.Sprintf("%x", sha256.Sum256(contents)); hash != file.hash {
			t.Fatalf("%s SHA-256 = %s, want %s", file.path, hash, file.hash)
		}
		for _, anchor := range file.anchors {
			if !bytes.Contains(contents, []byte(anchor)) {
				t.Fatalf("%s lacks %q", file.path, anchor)
			}
		}
	}
}
