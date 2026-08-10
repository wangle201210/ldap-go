package server

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const openLDAPNetscapePasswordCommit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

func TestNetscapePasswordHashSelectionMatchesOpenLDAPFailure(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{
					Description: "olcDatabase",
					Values:      stringValues("{-1}frontend"),
				},
				{
					Description: "olcPasswordHash",
					Values:      stringValues(auth.OpenLDAPNetscapeMTAHashScheme),
				},
			},
		}, false)
	}); err != nil {
		t.Fatalf("configure Netscape password hash: %v", err)
	}
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial ldap-go: %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=example,dc=com", "admin-secret"); err != nil {
		t.Fatalf("admin Bind: %v", err)
	}
	_, err = client.PasswordModify(ldap.NewPasswordModifyRequest(
		aliceDN,
		"",
		"replacement-secret",
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultOther)
	assertBindPassword(t, address, aliceDN, "secret", true)
	assertBindPassword(t, address, aliceDN, "replacement-secret", false)
}

func TestOpenLDAPReferenceNetscapePasswordModule(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	module := buildOpenLDAPNetscapePasswordModule(t)
	assertOpenLDAPNetscapePasswordSourceContract(t)

	const password = "netscape-import-secret"
	stored := netscapePasswordReferenceValue(password)
	binarySalt := make([]byte, 32)
	for index := range binarySalt {
		binarySalt[index] = byte(index)
	}
	binaryPassword := []byte{'p', 0x00, 'w', 0xff}
	binaryStored := netscapePasswordReferenceValueBytes(binaryPassword, binarySalt)
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"moduleload "+module,
		"",
		"userPassword: "+stored+"\n",
	)
	defer stopOpenLDAP()
	assertReferencePasswordBind(
		t,
		openLDAPURI,
		"uid=bob,ou=people,dc=example,dc=com",
		password,
	)
	binaryOpenLDAPURI, stopBinaryOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"moduleload "+module,
		"",
		"userPassword:: "+base64.StdEncoding.EncodeToString(binaryStored)+"\n",
	)
	defer stopBinaryOpenLDAP()
	assertReferencePasswordBind(
		t,
		binaryOpenLDAPURI,
		"uid=bob,ou=people,dc=example,dc=com",
		string(binaryPassword),
	)

	ldapGoStore := storage.NewMemory()
	t.Cleanup(func() { _ = ldapGoStore.Close() })
	ldifInput := "dn: dc=example,dc=com\n" +
		"objectClass: domain\n" +
		"dc: example\n\n" +
		"dn: ou=people,dc=example,dc=com\n" +
		"objectClass: organizationalUnit\n" +
		"ou: people\n\n" +
		"dn: " + aliceDN + "\n" +
		"objectClass: inetOrgPerson\n" +
		"uid: alice\n" +
		"cn: Alice Example\n" +
		"sn: Example\n" +
		"userPassword:: " + base64.StdEncoding.EncodeToString([]byte(stored)) + "\n" +
		"userPassword:: " + base64.StdEncoding.EncodeToString(binaryStored) + "\n\n"
	result, err := migration.ImportLDIF(
		t.Context(),
		ldapGoStore,
		bytes.NewBufferString(ldifInput),
		migration.ImportOptions{},
	)
	if err != nil {
		t.Fatalf("import Netscape password LDIF: %v", err)
	}
	if result.Entries != 3 {
		t.Fatalf("imported Netscape LDIF entries = %d, want 3", result.Entries)
	}
	ldapGoAddress, stopLDAPGo := startServer(t, ldapGoStore, Config{})
	defer stopLDAPGo()
	assertReferencePasswordBind(
		t,
		"ldap://"+ldapGoAddress,
		aliceDN,
		password,
	)
	assertReferencePasswordBind(
		t,
		"ldap://"+ldapGoAddress,
		aliceDN,
		string(binaryPassword),
	)

	t.Run("verify-only hash selection", func(t *testing.T) {
		uri, stop := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			nil,
			"moduleload "+module+"\npassword-hash "+auth.OpenLDAPNetscapeMTAHashScheme,
			"",
			"userPassword: "+stored+"\n",
		)
		defer stop()
		client := dialAndBindReferencePassword(
			t,
			uri,
			"cn=admin,dc=example,dc=com",
			"secret",
		)
		defer client.Close()
		_, err := client.PasswordModify(ldap.NewPasswordModifyRequest(
			"uid=bob,ou=people,dc=example,dc=com",
			"",
			"replacement-secret",
		))
		assertLDAPResultCode(t, err, ldap.LDAPResultOther)
	})
}

func netscapePasswordReferenceValue(password string) string {
	const salt = "0123456789abcdef0123456789abcdef"
	return string(netscapePasswordReferenceValueBytes([]byte(password), []byte(salt)))
}

func netscapePasswordReferenceValueBytes(password, salt []byte) []byte {
	input := make([]byte, 0, len(salt)*2+len(password)+2)
	input = append(input, salt...)
	input = append(input, 0x59)
	input = append(input, password...)
	input = append(input, 0xf7)
	input = append(input, salt...)
	digest := md5.Sum(input)
	stored := make([]byte, 0, len(auth.OpenLDAPNetscapeMTAHashScheme)+32+len(salt))
	stored = append(stored, auth.OpenLDAPNetscapeMTAHashScheme...)
	stored = append(stored, hex.EncodeToString(digest[:])...)
	stored = append(stored, salt...)
	return stored
}

func buildOpenLDAPNetscapePasswordModule(t *testing.T) string {
	t.Helper()
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	buildRoot := os.Getenv("OPENLDAP_BUILD_WORK")
	if sourceRoot == "" || buildRoot == "" {
		t.Fatal("OPENLDAP_SOURCE and OPENLDAP_BUILD_WORK are required")
	}
	portable, err := os.ReadFile(filepath.Join(buildRoot, "include", "portable.h"))
	if err != nil {
		t.Fatalf("read OpenLDAP portable.h: %v", err)
	}
	if !bytes.Contains(portable, []byte("#define SLAPD_MODULES 1")) {
		t.Fatal("OpenLDAP reference must be rebuilt with --enable-modules=yes")
	}

	moduleRoot := filepath.Join(t.TempDir(), "netscape")
	if err := os.Mkdir(moduleRoot, 0o700); err != nil {
		t.Fatalf("create pw-netscape build directory: %v", err)
	}
	sourceDir := filepath.Join(
		sourceRoot,
		"contrib",
		"slapd-modules",
		"passwd",
	)
	for _, name := range []string{"Makefile", "netscape.c"} {
		contents, err := os.ReadFile(filepath.Join(sourceDir, name))
		if err != nil {
			t.Fatalf("read pw-netscape %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(moduleRoot, name), contents, 0o600); err != nil {
			t.Fatalf("write pw-netscape %s: %v", name, err)
		}
	}
	command := exec.Command(
		"make",
		"-C",
		moduleRoot,
		"pw-netscape.la",
		"LDAP_SRC="+sourceRoot,
		"LDAP_BUILD="+buildRoot,
		"CPPFLAGS="+os.Getenv("OPENLDAP_CPPFLAGS"),
		"LDFLAGS="+os.Getenv("OPENLDAP_LDFLAGS"),
		"UNIX_LIB="+os.Getenv("OPENLDAP_LDFLAGS"),
		"CC=cc",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build OpenLDAP pw-netscape module: %v\n%s", err, output)
	}
	module := filepath.Join(moduleRoot, "pw-netscape.la")
	if info, err := os.Stat(module); err != nil || info.IsDir() {
		t.Fatalf("pw-netscape module was not built at %s", module)
	}
	return module
}

func assertOpenLDAPNetscapePasswordSourceContract(t *testing.T) {
	t.Helper()
	source := filepath.Join(
		os.Getenv("OPENLDAP_SOURCE"),
		"contrib",
		"slapd-modules",
		"passwd",
		"netscape.c",
	)
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read pinned pw-netscape source: %v", err)
	}
	for _, fragment := range []string{
		`BER_BVC("{NS-MTA-MD5}")`,
		`#define NS_MTA_MD5_PASSLEN`,
		`c = 0x59`,
		`c = 0xF7`,
		`chk_ns_mta_md5, NULL`,
	} {
		if !bytes.Contains(contents, []byte(fragment)) {
			t.Fatalf("pinned pw-netscape source is missing %q", fragment)
		}
	}
	if revision := os.Getenv("OPENLDAP_COMMIT"); revision != openLDAPNetscapePasswordCommit {
		t.Fatalf(
			"pw-netscape reference commit = %q, want %q",
			revision,
			openLDAPNetscapePasswordCommit,
		)
	}
}
