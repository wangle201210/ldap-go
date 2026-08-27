package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPAllopDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	module := buildOpenLDAPSingleSourceContribModule(t, "allop", "allop.c", "allop.la")
	referenceURI, stopReference := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"moduleload "+module+"\noverlay allop",
		"",
		"",
	)
	t.Cleanup(stopReference)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		for _, entry := range []directory.Entry{
			{
				DN: "olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcDatabase",
					Values:      stringValues("{-1}frontend"),
				}},
			},
			{
				DN: "olcOverlay={0}allop,olcDatabase={-1}frontend,cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcOverlay",
					Values:      stringValues("{0}allop"),
				}},
			},
		} {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	localAddress, stopLocal := startServer(t, store, Config{})
	t.Cleanup(stopLocal)

	for _, attributes := range [][]string{nil, {"1.1"}, {"supportedLDAPVersion"}} {
		reference := searchAllopProjection(t, referenceURI, attributes)
		local := searchAllopProjection(t, "ldap://"+localAddress, attributes)
		for _, name := range []string{"objectClass", "supportedControl", "supportedLDAPVersion"} {
			if (reference.GetAttributeValue(name) != "") != (local.GetAttributeValue(name) != "") {
				t.Fatalf(
					"attributes %q projection %s differs: OpenLDAP=%q ldap-go=%q",
					attributes,
					name,
					reference.GetAttributeValues(name),
					local.GetAttributeValues(name),
				)
			}
		}
	}
}

func searchAllopProjection(t *testing.T, uri string, attributes []string) *ldap.Entry {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		attributes,
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("Root DSE Search(%s, %q) = %#v, %v", uri, attributes, result, err)
	}
	return result.Entries[0]
}

func buildOpenLDAPSingleSourceContribModule(
	t *testing.T,
	directoryName,
	sourceName,
	moduleName string,
) string {
	t.Helper()
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	buildRoot := os.Getenv("OPENLDAP_BUILD_WORK")
	if sourceRoot == "" || buildRoot == "" {
		t.Fatal("OPENLDAP_SOURCE and OPENLDAP_BUILD_WORK are required")
	}
	moduleRoot := filepath.Join(t.TempDir(), directoryName)
	if err := os.Mkdir(moduleRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	sourceDir := filepath.Join(sourceRoot, "contrib", "slapd-modules", directoryName)
	for _, name := range []string{"Makefile", sourceName} {
		contents, err := os.ReadFile(filepath.Join(sourceDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(moduleRoot, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ldflags := os.Getenv("OPENLDAP_LDFLAGS")
	command := exec.Command(
		"make",
		"-C", moduleRoot,
		"LDAP_SRC="+sourceRoot,
		"LDAP_BUILD="+buildRoot,
		"CPPFLAGS="+os.Getenv("OPENLDAP_CPPFLAGS"),
		"LDFLAGS="+ldflags,
		"UNIX_LIB="+ldflags,
		"CC=cc",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build OpenLDAP %s module: %v\n%s", directoryName, err, output)
	}
	module := filepath.Join(moduleRoot, moduleName)
	if info, err := os.Stat(module); err != nil || info.IsDir() {
		t.Fatalf("module was not built at %s", module)
	}
	return module
}
