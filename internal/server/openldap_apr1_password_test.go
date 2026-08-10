package server

import (
	"bytes"
	"errors"
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

const (
	openLDAPAPR1PasswordCommit          = "d172686d3d270bc961b78f3ff00d7019c8dfb094"
	openLDAPAPR1OversizedPasswordVector = "{APR1}Xj/5SbTs7ESKfXw3JRHGzi4uLi4uLi4u"
	openLDAPAPR1OversizedSaltVector     = "{APR1}jTd0aY48xIlzq0z2dL0YDHNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nz"
)

func TestOpenLDAPPHKOversizedSimpleBindFailsClosed(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(aliceDN)
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues(
			"userPassword",
			stringValues(openLDAPAPR1OversizedPasswordVector),
		)
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("store APR1 password: %v", err)
	}
	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial ldap-go: %v", err)
	}
	defer client.Close()
	err = client.Bind(aliceDN, strings.Repeat("x", 4097))
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) || ldapError.ResultCode != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("oversized APR1 Bind = %v, want invalid credentials", err)
	}
}

func TestOpenLDAPReferenceAPR1PasswordModule(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	module := buildOpenLDAPAPR1PasswordModule(t)
	assertOpenLDAPAPR1PasswordSourceContract(t)
	t.Run("documented hardening boundaries", func(t *testing.T) {
		openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			nil,
			"moduleload "+module+"\npassword-hash "+auth.OpenLDAPAPR1HashScheme,
			"",
			"userPassword: "+openLDAPAPR1OversizedPasswordVector+"\n"+
				"userPassword: "+openLDAPAPR1OversizedSaltVector+"\n",
		)
		defer stopOpenLDAP()
		assertReferencePasswordBind(
			t,
			openLDAPURI,
			"uid=bob,ou=people,dc=example,dc=com",
			strings.Repeat("x", 4097),
		)
		assertReferencePasswordBind(
			t,
			openLDAPURI,
			"uid=bob,ou=people,dc=example,dc=com",
			"secret",
		)
	})

	for _, scheme := range []string{
		auth.OpenLDAPAPR1HashScheme,
		auth.OpenLDAPBSDMD5HashScheme,
	} {
		t.Run(scheme, func(t *testing.T) {
			const originalPassword = "apr1-original-secret"
			stored := generateLDAPGoPasswordModifyHash(
				t,
				scheme,
				originalPassword,
			)
			stored = []byte(
				scheme + strings.Repeat(" ", 4097) + strings.TrimPrefix(string(stored), scheme),
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

			const modifiedPassword = "apr1-modified-secret"
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
}

func buildOpenLDAPAPR1PasswordModule(t *testing.T) string {
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

	moduleRoot := filepath.Join(t.TempDir(), "apr1")
	if err := os.Mkdir(moduleRoot, 0o700); err != nil {
		t.Fatalf("create pw-apr1 build directory: %v", err)
	}
	sourceDir := filepath.Join(
		sourceRoot,
		"contrib",
		"slapd-modules",
		"passwd",
	)
	for _, name := range []string{"Makefile", "apr1.c"} {
		contents, err := os.ReadFile(filepath.Join(sourceDir, name))
		if err != nil {
			t.Fatalf("read pw-apr1 %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(moduleRoot, name), contents, 0o600); err != nil {
			t.Fatalf("write pw-apr1 %s: %v", name, err)
		}
	}
	cppflags := os.Getenv("OPENLDAP_CPPFLAGS")
	ldflags := os.Getenv("OPENLDAP_LDFLAGS")
	command := exec.Command(
		"make",
		"-C",
		moduleRoot,
		"pw-apr1.la",
		"LDAP_SRC="+sourceRoot,
		"LDAP_BUILD="+buildRoot,
		"CPPFLAGS="+cppflags,
		"LDFLAGS="+ldflags,
		"UNIX_LIB="+ldflags,
		"CC=cc",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build OpenLDAP pw-apr1 module: %v\n%s", err, output)
	}
	module := filepath.Join(moduleRoot, "pw-apr1.la")
	if info, err := os.Stat(module); err != nil || info.IsDir() {
		t.Fatalf("pw-apr1 module was not built at %s", module)
	}
	return module
}

func assertOpenLDAPAPR1PasswordSourceContract(t *testing.T) {
	t.Helper()
	source := filepath.Join(
		os.Getenv("OPENLDAP_SOURCE"),
		"contrib",
		"slapd-modules",
		"passwd",
		"apr1.c",
	)
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read pinned pw-apr1 source: %v", err)
	}
	for _, fragment := range []string{
		`BER_BVC("{APR1}")`,
		`BER_BVC("$apr1$")`,
		`BER_BVC("{BSDMD5}")`,
		`BER_BVC("$1$")`,
		`#define APR_SALT_SIZE`,
		`n < 1000`,
	} {
		if !bytes.Contains(contents, []byte(fragment)) {
			t.Fatalf("pinned pw-apr1 source is missing %q", fragment)
		}
	}
	if revision := os.Getenv("OPENLDAP_COMMIT"); revision != openLDAPAPR1PasswordCommit {
		t.Fatalf(
			"pw-apr1 reference commit = %q, want %q",
			revision,
			openLDAPAPR1PasswordCommit,
		)
	}
}
