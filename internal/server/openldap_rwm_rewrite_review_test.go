package server

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceRWMRelayRestrictionSource(t *testing.T) {
	_ = requireOpenLDAPRelayReferenceTools(t)
	if os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" ||
		os.Getenv("OPENLDAP_COMMIT") != openLDAPMetaCommit {
		t.Fatal("RWM relay restriction source test requires the pinned OpenLDAP 2.6.13 build")
	}
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Fatal("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	files := []struct {
		path string
		hash string
	}{
		{path: "servers/slapd/backend.c", hash: "3857ce86f0b38d765a6c83a81ac8216726fed735fb1cef805e8bfa69215c00cf"},
		{path: "servers/slapd/delete.c", hash: "017fd68d0e7707cc791f354cab00d5cab87f126f1951753528aad660d75aaa05"},
		{path: "servers/slapd/overlays/rwm.c", hash: "cd444a95b514b95958c35b86c35828270cf58f2615c2227015d50520523e91c5"},
	}
	contents := make(map[string]string, len(files))
	for _, file := range files {
		value, err := exec.Command(
			"git",
			"-C",
			source,
			"show",
			openLDAPMetaCommit+":"+file.path,
		).Output()
		if err != nil {
			t.Fatalf("read pinned %s: %v", file.path, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(value)); got != file.hash {
			t.Fatalf("%s SHA-256 = %s, want %s", file.path, got, file.hash)
		}
		contents[file.path] = string(value)
	}

	backend := contents["servers/slapd/backend.c"]
	controls := strings.Index(backend, "backend_check_controls( op, rs )")
	restrictions := strings.Index(backend, "restrictops |= op->o_bd->be_restrictops")
	decision := strings.Index(backend, "if( ( restrictops & opflag )")
	if controls < 0 || restrictions <= controls || decision <= restrictions {
		t.Fatal("OpenLDAP backend no longer validates controls before database restrictions")
	}
	deleteSource := contents["servers/slapd/delete.c"]
	check := strings.Index(deleteSource, "backend_check_restrictions( op, rs, NULL )")
	delegate := strings.Index(deleteSource, "op->o_bd->be_delete( op, rs )")
	if check < 0 || delegate <= check {
		t.Fatal("OpenLDAP delete no longer checks restrictions before backend/overlay delegation")
	}
	rwm := contents["servers/slapd/overlays/rwm.c"]
	deleteHook := openLDAPSourceSection(t, rwm, "static int\nrwm_op_delete(", "static int\nrwm_op_modify(")
	if !strings.Contains(deleteHook, `rwm_op_dn_massage( op, rs, "deleteDN"`) {
		t.Fatal("OpenLDAP RWM delete hook no longer invokes deleteDN")
	}
}

func TestOpenLDAPReferenceRWMRelayRestrictionOrdering(t *testing.T) {
	tools := requireOpenLDAPRelayReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)
	for _, mode := range []struct {
		name     string
		readOnly bool
		restrict bool
	}{
		{name: "rewrite result"},
		{name: "read only", readOnly: true},
		{name: "restricted writes", restrict: true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			configuration := `database relay
suffix "dc=virtual,dc=test"
relay "dc=example,dc=com"
`
			if mode.readOnly {
				configuration += "readonly on\n"
			}
			if mode.restrict {
				configuration += "restrict add modify delete rename\n"
			}
			configuration += `overlay rwm
rwm-suffixmassage "dc=virtual,dc=test" "dc=example,dc=com"
rwm-rewriteEngine on
rwm-rewriteContext addDN
rwm-rewriteRule ".*" "$0" ":U{51}"
rwm-rewriteContext modifyDN
rwm-rewriteRule ".*" "$0" ":U{51}"
rwm-rewriteContext deleteDN
rwm-rewriteRule ".*" "$0" ":U{51}"
rwm-rewriteContext renameDN
rwm-rewriteRule ".*" "$0" ":U{51}"
`
			referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
				t,
				tools,
				nil,
				"",
				configuration,
				"",
			)
			defer stopReference()

			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedRWMRelayConfiguration(t, store)
			configureRWMReviewRelay(t, store, mode.readOnly, mode.restrict)
			replaceRWMRewriteConfiguration(
				t,
				store,
				rwmOverlayConfigDN,
				"olcRwmRewrite",
				rwmReviewTerminalWriteDirectives()...,
			)
			address, stopGo := startServer(t, store, Config{})
			defer stopGo()

			want := observeRWMRelayWriteOrdering(t, referenceURI)
			got := observeRWMRelayWriteOrdering(t, "ldap://"+address)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("relay ordering differs: ldap-go=%#v OpenLDAP=%#v", got, want)
			}
		})
	}
}
