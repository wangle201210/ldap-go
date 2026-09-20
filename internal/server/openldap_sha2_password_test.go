package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const openLDAPSHA2PasswordCommit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

func TestOpenLDAPReferenceSHA2PasswordModule(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	module := buildOpenLDAPSHA2PasswordModule(t)
	assertOpenLDAPSHA2PasswordSourceContract(t)

	for _, scheme := range []string{
		"{SHA256}",
		"{SSHA256}",
		"{SHA384}",
		"{SSHA384}",
		"{SHA512}",
		"{SSHA512}",
	} {
		t.Run(scheme, func(t *testing.T) {
			const originalPassword = "sha2-original-secret"
			stored := generateLDAPGoPasswordModifyHash(
				t,
				scheme,
				originalPassword,
			)

			openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
				t,
				tools,
				nil,
				"moduleload "+module+"\npassword-hash "+scheme,
				"",
				"userPassword: "+string(stored)+"\n",
			)
			defer stopOpenLDAP()
			assertReferencePasswordBind(
				t,
				openLDAPURI,
				"uid=bob,ou=people,dc=example,dc=com",
				originalPassword,
			)

			const modifiedPassword = "sha2-modified-secret"
			openLDAP := dialAndBindReferencePassword(
				t,
				openLDAPURI,
				"cn=admin,dc=example,dc=com",
				"secret",
			)
			if _, err := openLDAP.PasswordModify(ldap.NewPasswordModifyRequest(
				"uid=bob,ou=people,dc=example,dc=com",
				"",
				modifiedPassword,
			)); err != nil {
				openLDAP.Close()
				t.Fatalf("OpenLDAP PasswordModify(%s): %v", scheme, err)
			}
			generated := readReferenceAttribute(
				t,
				openLDAP,
				"uid=bob,ou=people,dc=example,dc=com",
				"userPassword",
			)
			openLDAP.Close()
			if len(generated) != 1 || !strings.HasPrefix(generated[0], scheme) {
				t.Fatalf("OpenLDAP generated password = %q, want %s prefix", generated, scheme)
			}
			if !auth.VerifyPassword([]byte(generated[0]), []byte(modifiedPassword)) {
				t.Fatalf("ldap-go rejected OpenLDAP-generated %s password", scheme)
			}
			assertReferencePasswordBind(
				t,
				openLDAPURI,
				"uid=bob,ou=people,dc=example,dc=com",
				modifiedPassword,
			)

			ldapGoStore := storage.NewMemory()
			t.Cleanup(func() { _ = ldapGoStore.Close() })
			seedDirectory(t, ldapGoStore)
			if err := ldapGoStore.Update(t.Context(), func(writer storage.Writer) error {
				dn, err := directory.ParseDN(aliceDN)
				if err != nil {
					return err
				}
				entry, err := writer.Get(dn)
				if err != nil {
					return err
				}
				entry.ReplaceValues("userPassword", stringValues(generated[0]))
				return writer.Put(entry, true)
			}); err != nil {
				t.Fatalf("import OpenLDAP-generated %s password: %v", scheme, err)
			}
			ldapGoAddress, stopLDAPGo := startServer(t, ldapGoStore, Config{})
			defer stopLDAPGo()
			assertReferencePasswordBind(
				t,
				"ldap://"+ldapGoAddress,
				aliceDN,
				modifiedPassword,
			)
		})
	}

	t.Run("Base64 boundaries", func(t *testing.T) {
		for _, test := range []struct {
			name     string
			stored   string
			wantBind bool
		}{
			{
				name:     "whitespace",
				stored:   "{SHA256}K7gN U3sdo+OL0wNh\tqoVWhr3g6s1xYv72ol/pe/Unols=",
				wantBind: true,
			},
			{
				name:   "nonzero padding bits",
				stored: "{SHA256}K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unolt=",
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
					t,
					tools,
					nil,
					"moduleload "+module,
					"",
					"userPassword: "+test.stored+"\n",
				)
				defer stopOpenLDAP()
				openLDAP := dialReferencePassword(t, openLDAPURI)
				openLDAPCode := otpLDAPResultCode(openLDAP.Bind(
					"uid=bob,ou=people,dc=example,dc=com",
					"secret",
				))
				openLDAP.Close()
				ldapGoAccepted := auth.VerifyPassword(
					[]byte(test.stored),
					[]byte("secret"),
				)
				wantCode := uint16(ldap.LDAPResultInvalidCredentials)
				if test.wantBind {
					wantCode = ldap.LDAPResultSuccess
				}
				if openLDAPCode != wantCode || ldapGoAccepted != test.wantBind {
					t.Fatalf(
						"Base64 result: OpenLDAP=%d ldap-go=%t want code=%d accepted=%t",
						openLDAPCode,
						ldapGoAccepted,
						wantCode,
						test.wantBind,
					)
				}
			})
		}
	})
}

func generateLDAPGoPasswordModifyHash(
	t *testing.T,
	scheme,
	password string,
) []byte {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
				{Description: "olcPasswordHash", Values: stringValues(scheme)},
			},
		}, false)
	}); err != nil {
		t.Fatalf("configure ldap-go password hash %s: %v", scheme, err)
	}
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	admin := dialAndBindReferencePassword(
		t,
		"ldap://"+address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	if _, err := admin.PasswordModify(ldap.NewPasswordModifyRequest(
		aliceDN,
		"",
		password,
	)); err != nil {
		admin.Close()
		stop()
		t.Fatalf("ldap-go PasswordModify(%s): %v", scheme, err)
	}
	admin.Close()
	stored := readStoredEntry(t, store, aliceDN).Values("userPassword")
	stop()
	if len(stored) != 1 || !bytes.HasPrefix(stored[0], []byte(scheme)) {
		t.Fatalf("ldap-go generated password = %q, want %s prefix", stored, scheme)
	}
	return bytes.Clone(stored[0])
}

func assertReferencePasswordBind(t *testing.T, uri, dn, password string) {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	if err := client.Bind(dn, password); err != nil {
		t.Fatalf("Bind(%s, correct password): %v", uri, err)
	}
	assertLDAPResultCode(t, client.Bind(dn, "wrong-password"), ldap.LDAPResultInvalidCredentials)
}

func dialAndBindReferencePassword(
	t *testing.T,
	uri,
	dn,
	password string,
) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	if err := client.Bind(dn, password); err != nil {
		client.Close()
		t.Fatalf("Bind(%s): %v", uri, err)
	}
	return client
}

func dialReferencePassword(t *testing.T, uri string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	return client
}

func buildOpenLDAPSHA2PasswordModule(t *testing.T) string {
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

	moduleRoot := filepath.Join(t.TempDir(), "sha2")
	if err := os.Mkdir(moduleRoot, 0o700); err != nil {
		t.Fatalf("create pw-sha2 build directory: %v", err)
	}
	sourceDir := filepath.Join(
		sourceRoot,
		"contrib",
		"slapd-modules",
		"passwd",
		"sha2",
	)
	for _, name := range []string{"Makefile", "slapd-sha2.c", "sha2.c", "sha2.h"} {
		contents, err := os.ReadFile(filepath.Join(sourceDir, name))
		if err != nil {
			t.Fatalf("read pw-sha2 %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(moduleRoot, name), contents, 0o600); err != nil {
			t.Fatalf("write pw-sha2 %s: %v", name, err)
		}
	}
	cppflags := os.Getenv("OPENLDAP_CPPFLAGS")
	ldflags := os.Getenv("OPENLDAP_LDFLAGS")
	command := exec.Command(
		"make",
		"-C",
		moduleRoot,
		"LDAP_SRC="+sourceRoot,
		"LDAP_BUILD="+buildRoot,
		"CPPFLAGS="+cppflags,
		"LDFLAGS="+ldflags,
		"UNIX_LIB="+ldflags,
		"CC=cc",
		// sha2.c aliases its byte buffer through word pointers. GCC -O2 can
		// otherwise generate incorrect SHA256 digests on Linux arm64.
		"OPT=-g -O2 -fno-strict-aliasing",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build OpenLDAP pw-sha2 module: %v\n%s", err, output)
	}
	module := filepath.Join(moduleRoot, "pw-sha2.la")
	if info, err := os.Stat(module); err != nil || info.IsDir() {
		t.Fatalf("pw-sha2 module was not built at %s", module)
	}
	assertOpenLDAPSHA2PasswordModuleDigests(t, module)
	return module
}

func assertOpenLDAPSHA2PasswordModuleDigests(t *testing.T, module string) {
	t.Helper()
	slappasswd := os.Getenv("OPENLDAP_SLAPPASSWD")
	if slappasswd == "" {
		var err error
		slappasswd, err = exec.LookPath("slappasswd")
		if err != nil {
			t.Fatalf("find OpenLDAP slappasswd for SHA2 oracle self-check: %v", err)
		}
	}
	for _, password := range []string{"secret", strings.Repeat("a", 56), strings.Repeat("a", 112)} {
		sha256Digest := sha256.Sum256([]byte(password))
		sha384Digest := sha512.Sum384([]byte(password))
		sha512Digest := sha512.Sum512([]byte(password))
		for _, test := range []struct {
			scheme string
			digest []byte
		}{
			{"{SHA256}", sha256Digest[:]},
			{"{SHA384}", sha384Digest[:]},
			{"{SHA512}", sha512Digest[:]},
		} {
			command := exec.Command(slappasswd, "-o", "module-load="+module, "-h", test.scheme, "-s", password)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("OpenLDAP SHA2 oracle self-check failed for %s: %v\n%s", test.scheme, err, output)
			}
			want := test.scheme + base64.StdEncoding.EncodeToString(test.digest)
			if got := strings.TrimSpace(string(output)); got != want {
				t.Fatalf("OpenLDAP SHA2 oracle is unusable: %s with %d-byte input = %q, want standard digest %q", test.scheme, len(password), got, want)
			}
		}
	}
}

func assertOpenLDAPSHA2PasswordSourceContract(t *testing.T) {
	t.Helper()
	source := filepath.Join(
		os.Getenv("OPENLDAP_SOURCE"),
		"contrib",
		"slapd-modules",
		"passwd",
		"sha2",
		"slapd-sha2.c",
	)
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read pinned pw-sha2 source: %v", err)
	}
	for _, fragment := range []string{
		`#define SHA2_SALT_SIZE 8`,
		`BER_BVC("{SHA256}")`,
		`BER_BVC("{SSHA256}")`,
		`BER_BVC("{SHA384}")`,
		`BER_BVC("{SSHA384}")`,
		`BER_BVC("{SHA512}")`,
		`BER_BVC("{SSHA512}")`,
	} {
		if !bytes.Contains(contents, []byte(fragment)) {
			t.Fatalf("pinned pw-sha2 source is missing %q", fragment)
		}
	}
	if revision := os.Getenv("OPENLDAP_COMMIT"); revision != openLDAPSHA2PasswordCommit {
		t.Fatalf(
			"pw-sha2 reference commit = %q, want %q",
			revision,
			openLDAPSHA2PasswordCommit,
		)
	}
}
