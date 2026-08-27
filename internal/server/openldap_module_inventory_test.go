package server

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

func TestOpenLDAP2613OfficialModuleInventorySourceContract(t *testing.T) {
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Skip("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	backendEntries, err := os.ReadDir(filepath.Join(source, "servers", "slapd"))
	if err != nil {
		t.Fatal(err)
	}
	var backends []string
	for _, entry := range backendEntries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "back-") {
			backends = append(backends, strings.TrimPrefix(entry.Name(), "back-"))
		}
	}
	sort.Strings(backends)
	wantBackends := []string{
		"asyncmeta", "dnssrv", "ldap", "ldif", "mdb", "meta", "monitor",
		"null", "passwd", "perl", "relay", "sock", "sql", "wt",
	}
	if !slices.Equal(backends, wantBackends) {
		t.Fatalf("OpenLDAP backend source inventory = %q, want %q", backends, wantBackends)
	}
	for _, backend := range backends {
		_, supported := supportedRuntimeDatabaseTypes[backend]
		if backend == "perl" {
			if supported {
				t.Fatal("back-perl must remain explicit until a Perl execution contract exists")
			}
			continue
		}
		if !supported {
			t.Errorf("official backend %q is absent from the runtime inventory", backend)
		}
	}

	contribEntries, err := os.ReadDir(filepath.Join(source, "contrib", "slapd-modules"))
	if err != nil {
		t.Fatal(err)
	}
	var contrib []string
	for _, entry := range contribEntries {
		if entry.IsDir() {
			contrib = append(contrib, entry.Name())
		}
	}
	sort.Strings(contrib)
	wantContrib := []string{
		"acl", "addpartial", "adremap", "alias", "allop", "allowed", "authzid",
		"autogroup", "ciboolean", "cloak", "comp_match", "datamorph", "denyop",
		"dsaschema", "dupent", "emptyds", "kinit", "lastbind", "lastmod",
		"noopsrch", "nops", "nssov", "passwd", "ppm", "proxyOld", "rbac",
		"samba4", "smbk5pwd", "trace", "usn", "variant", "vc",
	}
	if !slices.Equal(contrib, wantContrib) {
		t.Fatalf("OpenLDAP contrib module inventory = %q, want %q", contrib, wantContrib)
	}
}

func TestOpenLDAP2613StandardOverlayInventory(t *testing.T) {
	overlays := []string{
		"accesslog", "auditlog", "autoca", "collect", "constraint", "dds", "deref",
		"dyngroup", "dynlist", "homedir", "memberof", "nestgroup", "otp", "ppolicy",
		"proxycache", "refint", "remoteauth", "retcode", "rwm", "seqmod", "sssvlv",
		"syncprov", "translucent", "unique", "valsort",
	}
	for _, overlay := range overlays {
		if _, supported := supportedRuntimeOverlayType(overlay); !supported {
			t.Errorf("official standard overlay %q is absent from the runtime inventory", overlay)
		}
	}
	for _, extra := range []string{"chain", "glue", "pbind", "sock", "totp"} {
		if _, supported := supportedRuntimeOverlayType(extra); !supported {
			t.Errorf("implemented extra overlay %q is absent from the runtime inventory", extra)
		}
	}
}
