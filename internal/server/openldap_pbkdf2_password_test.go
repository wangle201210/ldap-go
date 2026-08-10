package server

import (
	"bytes"
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

const openLDAPPBKDF2PasswordCommit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

func TestOpenLDAPReferencePBKDF2PasswordModule(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	module := buildOpenLDAPPBKDF2PasswordModule(t)
	assertOpenLDAPPBKDF2PasswordSourceContract(t)

	for _, scheme := range []string{
		auth.OpenLDAPPBKDF2HashScheme,
		auth.OpenLDAPPBKDF2SHA1HashScheme,
		auth.OpenLDAPPBKDF2SHA256HashScheme,
		auth.OpenLDAPPBKDF2SHA512HashScheme,
	} {
		t.Run(scheme, func(t *testing.T) {
			const originalPassword = "pbkdf2-original-secret"
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

			const modifiedPassword = "pbkdf2-modified-secret"
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

	t.Run("adapted Base64 whitespace", func(t *testing.T) {
		const prefix = auth.OpenLDAPPBKDF2SHA256HashScheme + "10000$"
		const salt = "jq40ImWtmpTE.aYDYV1GfQ"
		const derived = "mpiL4ui02ACmYOAnCjp/MI1gQk50xLbZ54RZneU0fCg"
		for _, test := range []struct {
			name     string
			stored   string
			wantBind bool
		}{
			{
				name:     "four whitespace bytes preserve padding",
				stored:   prefix + salt + "$" + derived[:10] + "    " + derived[10:],
				wantBind: true,
			},
			{
				name:   "two whitespace bytes change padding",
				stored: prefix + salt + "$" + derived[:10] + "  " + derived[10:],
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

func buildOpenLDAPPBKDF2PasswordModule(t *testing.T) string {
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

	moduleRoot := filepath.Join(t.TempDir(), "pbkdf2")
	if err := os.Mkdir(moduleRoot, 0o700); err != nil {
		t.Fatalf("create pw-pbkdf2 build directory: %v", err)
	}
	sourceDir := filepath.Join(
		sourceRoot,
		"contrib",
		"slapd-modules",
		"passwd",
		"pbkdf2",
	)
	for _, name := range []string{"Makefile", "pw-pbkdf2.c"} {
		contents, err := os.ReadFile(filepath.Join(sourceDir, name))
		if err != nil {
			t.Fatalf("read pw-pbkdf2 %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(moduleRoot, name), contents, 0o600); err != nil {
			t.Fatalf("write pw-pbkdf2 %s: %v", name, err)
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
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build OpenLDAP pw-pbkdf2 module: %v\n%s", err, output)
	}
	module := filepath.Join(moduleRoot, "pw-pbkdf2.la")
	if info, err := os.Stat(module); err != nil || info.IsDir() {
		t.Fatalf("pw-pbkdf2 module was not built at %s", module)
	}
	return module
}

func assertOpenLDAPPBKDF2PasswordSourceContract(t *testing.T) {
	t.Helper()
	source := filepath.Join(
		os.Getenv("OPENLDAP_SOURCE"),
		"contrib",
		"slapd-modules",
		"passwd",
		"pbkdf2",
		"pw-pbkdf2.c",
	)
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read pinned pw-pbkdf2 source: %v", err)
	}
	for _, fragment := range []string{
		`#define PBKDF2_ITERATION 10000`,
		`#define PBKDF2_SALT_SIZE 16`,
		`#define PBKDF2_SHA1_DK_SIZE 20`,
		`#define PBKDF2_SHA256_DK_SIZE 32`,
		`#define PBKDF2_SHA512_DK_SIZE 64`,
		`BER_BVC("{PBKDF2}")`,
		`BER_BVC("{PBKDF2-SHA1}")`,
		`BER_BVC("{PBKDF2-SHA256}")`,
		`BER_BVC("{PBKDF2-SHA512}")`,
	} {
		if !bytes.Contains(contents, []byte(fragment)) {
			t.Fatalf("pinned pw-pbkdf2 source is missing %q", fragment)
		}
	}
	if revision := os.Getenv("OPENLDAP_COMMIT"); revision != openLDAPPBKDF2PasswordCommit {
		t.Fatalf(
			"pw-pbkdf2 reference commit = %q, want %q",
			revision,
			openLDAPPBKDF2PasswordCommit,
		)
	}
}
