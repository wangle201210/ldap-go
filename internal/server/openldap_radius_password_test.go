package server

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
)

const openLDAPRADIUSPasswordCommit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

func TestOpenLDAPReferenceRADIUSPasswordModule(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	module := buildOpenLDAPRADIUSPasswordModule(t)
	assertOpenLDAPRADIUSPasswordSourceContract(t)
	configuration := filepath.Join(t.TempDir(), "radius.conf")
	if err := os.WriteFile(
		configuration,
		[]byte("auth 127.0.0.1 radius-reference-secret 1 1\n"),
		0o600,
	); err != nil {
		t.Fatalf("write reference radius.conf: %v", err)
	}
	global := "moduleload " + module + " config=\"" + configuration + "\""
	uri, stop := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		global,
		"",
		"userPassword: "+auth.OpenLDAPRADIUSHashScheme+"radius-user\n",
	)
	defer stop()
	assertReferencePasswordBind(
		t,
		uri,
		"uid=bob,ou=people,dc=example,dc=com",
		"radius-secret",
	)
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial OpenLDAP reference: %v", err)
	}
	defer client.Close()
	assertLDAPResultCode(
		t,
		client.Bind("uid=bob,ou=people,dc=example,dc=com", "wrong"),
		ldap.LDAPResultInvalidCredentials,
	)

	t.Run("verify-only hash selection", func(t *testing.T) {
		selectionURI, selectionStop := startOpenLDAPReferenceServerWithConfig(
			t,
			tools,
			nil,
			global+"\npassword-hash "+auth.OpenLDAPRADIUSHashScheme,
			"",
			"userPassword: "+auth.OpenLDAPRADIUSHashScheme+"radius-user\n",
		)
		defer selectionStop()
		selectionClient := dialAndBindReferencePassword(
			t,
			selectionURI,
			"cn=admin,dc=example,dc=com",
			"secret",
		)
		defer selectionClient.Close()
		_, err := selectionClient.PasswordModify(ldap.NewPasswordModifyRequest(
			"uid=bob,ou=people,dc=example,dc=com",
			"",
			"replacement-secret",
		))
		assertLDAPResultCode(t, err, ldap.LDAPResultOther)
	})
}

func buildOpenLDAPRADIUSPasswordModule(t *testing.T) string {
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

	moduleRoot := filepath.Join(t.TempDir(), "radius")
	if err := os.Mkdir(moduleRoot, 0o700); err != nil {
		t.Fatalf("create pw-radius build directory: %v", err)
	}
	sourceDir := filepath.Join(sourceRoot, "contrib", "slapd-modules", "passwd")
	for _, name := range []string{"Makefile", "radius.c"} {
		contents, err := os.ReadFile(filepath.Join(sourceDir, name))
		if err != nil {
			t.Fatalf("read pw-radius %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(moduleRoot, name), contents, 0o600); err != nil {
			t.Fatalf("write pw-radius %s: %v", name, err)
		}
	}
	if err := os.WriteFile(
		filepath.Join(moduleRoot, "radlib.h"),
		[]byte(openLDAPRADIUSStubHeader),
		0o600,
	); err != nil {
		t.Fatalf("write radlib stub header: %v", err)
	}
	stubSource := filepath.Join(moduleRoot, "radlib_stub.c")
	if err := os.WriteFile(stubSource, []byte(openLDAPRADIUSStubSource), 0o600); err != nil {
		t.Fatalf("write radlib stub source: %v", err)
	}
	stubObject := filepath.Join(moduleRoot, "radlib_stub.o")
	compile := exec.Command("cc", "-fPIC", "-I"+moduleRoot, "-c", stubSource, "-o", stubObject)
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("compile radlib stub: %v\n%s", err, output)
	}
	command := exec.Command(
		"make",
		"-C",
		moduleRoot,
		"pw-radius.la",
		"LDAP_SRC="+sourceRoot,
		"LDAP_BUILD="+buildRoot,
		"CPPFLAGS=-I"+moduleRoot+" "+os.Getenv("OPENLDAP_CPPFLAGS"),
		"LDFLAGS="+os.Getenv("OPENLDAP_LDFLAGS"),
		"UNIX_LIB="+stubObject+" "+os.Getenv("OPENLDAP_LDFLAGS"),
		"CC=cc",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build OpenLDAP pw-radius module: %v\n%s", err, output)
	}
	module := filepath.Join(moduleRoot, "pw-radius.la")
	if info, err := os.Stat(module); err != nil || info.IsDir() {
		t.Fatalf("pw-radius module was not built at %s", module)
	}
	return module
}

func assertOpenLDAPRADIUSPasswordSourceContract(t *testing.T) {
	t.Helper()
	source := filepath.Join(
		os.Getenv("OPENLDAP_SOURCE"),
		"contrib",
		"slapd-modules",
		"passwd",
		"radius.c",
	)
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read pinned pw-radius source: %v", err)
	}
	for _, fragment := range []string{
		`BER_BVC("{RADIUS}")`,
		`rad_put_string( h, RAD_USER_NAME, passwd->bv_val )`,
		`rad_put_string( h, RAD_USER_PASSWORD, cred->bv_val )`,
		`rad_put_string( h, RAD_NAS_IDENTIFIER, global_host )`,
		`case RAD_ACCESS_ACCEPT:`,
		`lutil_passwd_add( (struct berval *)&scheme, chk_radius, NULL )`,
	} {
		if !bytes.Contains(contents, []byte(fragment)) {
			t.Fatalf("pinned pw-radius source is missing %q", fragment)
		}
	}
	if revision := os.Getenv("OPENLDAP_COMMIT"); revision != openLDAPRADIUSPasswordCommit {
		t.Fatalf(
			"pw-radius reference commit = %q, want %q",
			revision,
			openLDAPRADIUSPasswordCommit,
		)
	}
}

const openLDAPRADIUSStubHeader = `
#ifndef LDAP_GO_RADLIB_H
#define LDAP_GO_RADLIB_H
struct rad_handle;
#define RAD_ACCESS_REQUEST 1
#define RAD_ACCESS_ACCEPT 2
#define RAD_ACCESS_REJECT 3
#define RAD_ACCESS_CHALLENGE 11
#define RAD_USER_NAME 1
#define RAD_USER_PASSWORD 2
#define RAD_NAS_IDENTIFIER 32
struct rad_handle *rad_auth_open(void);
int rad_config(struct rad_handle *, const char *);
int rad_create_request(struct rad_handle *, int);
int rad_put_string(struct rad_handle *, int, const char *);
int rad_send_request(struct rad_handle *);
void rad_close(struct rad_handle *);
#endif
`

const openLDAPRADIUSStubSource = `
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "radlib.h"

struct rad_handle {
    char *username;
    char *password;
    char *nas;
};

struct rad_handle *rad_auth_open(void) {
    return calloc(1, sizeof(struct rad_handle));
}

int rad_config(struct rad_handle *handle, const char *path) {
    char line[16];
    FILE *file;
    (void)handle;
    if (path == NULL || (file = fopen(path, "r")) == NULL) return -1;
    if (fgets(line, sizeof(line), file) == NULL) {
        fclose(file);
        return -1;
    }
    fclose(file);
    return strncmp(line, "auth ", 5) == 0 ? 0 : -1;
}

int rad_create_request(struct rad_handle *handle, int code) {
    return handle != NULL && code == RAD_ACCESS_REQUEST ? 0 : -1;
}

int rad_put_string(struct rad_handle *handle, int attribute, const char *value) {
    char **target = NULL;
    if (handle == NULL || value == NULL) return -1;
    if (attribute == RAD_USER_NAME) target = &handle->username;
    if (attribute == RAD_USER_PASSWORD) target = &handle->password;
    if (attribute == RAD_NAS_IDENTIFIER) target = &handle->nas;
    if (target == NULL) return -1;
    free(*target);
    *target = strdup(value);
    return *target == NULL ? -1 : 0;
}

int rad_send_request(struct rad_handle *handle) {
    if (handle == NULL || handle->username == NULL ||
        handle->password == NULL || handle->nas == NULL || handle->nas[0] == '\0') {
        return -1;
    }
    if (strcmp(handle->username, "radius-user") == 0 &&
        strcmp(handle->password, "radius-secret") == 0) {
        return RAD_ACCESS_ACCEPT;
    }
    if (strcmp(handle->username, "radius-challenge") == 0) {
        return RAD_ACCESS_CHALLENGE;
    }
    return RAD_ACCESS_REJECT;
}

void rad_close(struct rad_handle *handle) {
    if (handle == NULL) return;
    free(handle->username);
    free(handle->password);
    free(handle->nas);
    free(handle);
}
`
