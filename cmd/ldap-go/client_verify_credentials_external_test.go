package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

// Opt in to a native binary separately from the pure Go protocol fixtures.
// Its version is checked; source inspection uses the exact commit in ldapVCUsage.
func TestLDAPVCOpenLDAPNativeDifferential(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") == "" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 for native ldapvc differential fixtures")
	}
	tool := os.Getenv("OPENLDAP_LDAPVC")
	if tool == "" {
		var err error
		tool, err = exec.LookPath("ldapvc")
		if err != nil {
			t.Fatal(err)
		}
	}
	versionOutput, err := exec.Command(tool, "-VV").CombinedOutput()
	if err != nil || !bytes.Contains(versionOutput, []byte("ldapvc 2.6.13")) {
		t.Fatalf("native tool is not OpenLDAP 2.6.13: %v", err)
	}
	innerControls := ldapVCTestTLV(0xa2,
		ldapVCTestTLV(0x30, ldapVCTestTLV(4, []byte(ldapVCAuthzIDOID)), ldapVCTestTLV(4, []byte("dn:cn=user"))),
		ldapVCTestTLV(0x30, ldapVCTestTLV(4, []byte(ldap.ControlTypeBeheraPasswordPolicy)), ldapVCTestTLV(4, []byte{0x30, 5, 0xa0, 3, 0x80, 1, 60})),
	)
	for _, test := range []struct {
		name               string
		args               []string
		outer              ldapwire.Result
		value              []byte
		goCode, nativeCode int
	}{
		{name: "simple", args: []string{"-x", "cn=user", "pw"}, value: ldapVCTestValue(0, "")},
		{name: "anonymous", args: []string{"-x"}, value: ldapVCTestValue(0, "")},
		{name: "explicit anonymous", args: []string{"-x", "", ""}, value: ldapVCTestValue(0, "")},
		{name: "verbose", args: []string{"-xv", "cn=user", "pw"}, value: ldapVCTestValue(0, "")},
		{name: "nested controls", args: []string{"-xab", "-o", "ldif_wrap=no", "cn=user", "pw"}, value: ldapVCTestValue(0, "", innerControls)},
		{name: "general controls", args: []string{"-x", "-e", "ppolicy", "-e", "!1.2.3", "-D", "cn=operator", "-w", "bind-secret", "cn=user", "pw"}, value: ldapVCTestValue(0, "")},
		{name: "inner rejection", args: []string{"-xv", "cn=user", "pw"}, value: ldapVCTestValue(49, "denied")},
		{name: "outer rejection", args: []string{"-x", "cn=user", "pw"}, outer: ldapwire.Result{Code: 53, DiagnosticMessage: "disabled"}, goCode: 1, nativeCode: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := make(chan ldapwire.Message, 4)
			fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
				if _, ok := message.Request.(ldapwire.UnbindRequest); ok {
					return nil, nil
				}
				requests <- message
				if _, ok := message.Request.(ldapwire.BindRequest); ok {
					return nil, nil
				}
				return [][]byte{ldapVCTestResponse(message.ID, test.outer, test.value)}, nil
			})
			arguments := append([]string{"-H", fixture.uri}, test.args...)
			stdout, stderr, goCode := runLDAPClientCommand(append([]string{"ldapvc"}, arguments...), "")
			if goCode != test.goCode || stderr != "" {
				t.Fatalf("Go exit=%d stdout=%q stderr=%q", goCode, stdout, stderr)
			}
			goBind := awaitLDAPClientWireMessage(t, requests)
			goVC := awaitLDAPClientWireMessage(t, requests)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, tool, arguments...)
			var nativeOut, nativeErr bytes.Buffer
			command.Stdout, command.Stderr = &nativeOut, &nativeErr
			err := command.Run()
			nativeCode := 0
			if err != nil {
				var exitError *exec.ExitError
				if !errors.As(err, &exitError) {
					t.Fatal(err)
				}
				nativeCode = exitError.ExitCode()
			}
			if nativeCode != test.nativeCode || goCode != nativeCode || stdout != nativeOut.String() {
				t.Fatalf("Go exit=%d stdout=%q; native exit=%d stdout=%q stderr=%q", goCode, stdout, nativeCode, nativeOut.String(), nativeErr.String())
			}
			nativeBind := awaitLDAPClientWireMessage(t, requests)
			nativeVC := awaitLDAPClientWireMessage(t, requests)
			pairs := [][2]ldapwire.Message{{goBind, nativeBind}, {goVC, nativeVC}}
			for _, pair := range pairs {
				if !reflect.DeepEqual(pair[0].Request, pair[1].Request) || !reflect.DeepEqual(pair[0].Controls, pair[1].Controls) {
					t.Fatal("Go and native requests differ (credential-bearing packets omitted)")
				}
			}
		})
	}
}

// Use a supplied disposable server or automatically start a built VC module.
// The independent endpoint gate is an explicit skip when no artifacts exist.
func TestLDAPVCExternalOpenLDAPModule(t *testing.T) {
	uri := os.Getenv("LDAP_GO_OPENLDAP_VC_URI")
	dn := os.Getenv("LDAP_GO_OPENLDAP_VC_DN")
	passwordFile := os.Getenv("LDAP_GO_OPENLDAP_VC_PASSWORD_FILE")
	if uri == "" {
		uri, dn, passwordFile = startLDAPVCExternalModule(t)
		if uri == "" {
			t.Skip("requires an external OpenLDAP vc module: LDAP_GO_OPENLDAP_VC_URI, LDAP_GO_OPENLDAP_VC_DN, LDAP_GO_OPENLDAP_VC_PASSWORD_FILE, or OPENLDAP_BUILD with built vc/authzid modules")
		}
	}
	if dn == "" || passwordFile == "" {
		t.Fatal("external VC DN and password file are required")
	}
	password, err := readLDAPPasswordFile(passwordFile, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(password)
	args := []string{"ldapvc", "-x", "-H", uri, "-a", "-b", dn, string(password)}
	stdout, stderr, code := runLDAPClientCommand(args, "")
	if code != 0 || !strings.Contains(stdout, "authzid:") {
		t.Fatalf("external vc verification failed with exit %d (output omitted to protect credentials)", code)
	}
	if len(password) != 0 && strings.Contains(stdout+stderr, string(password)) {
		t.Fatal("password appeared in output")
	}
	args[len(args)-1] += "-invalid"
	stdout, _, code = runLDAPClientCommand(args, "")
	if code != 1 || (!strings.Contains(stdout, "(49)") && !strings.Contains(stdout, "Failed:")) {
		t.Fatal("external vc did not reject incorrect credentials")
	}
	t.Log("real OpenLDAP VC module: correct password exit=0; incorrect password exit=1; authzid response decoded")
}

func startLDAPVCExternalModule(t *testing.T) (string, string, string) {
	t.Helper()
	build := os.Getenv("OPENLDAP_BUILD")
	if build == "" {
		return "", "", ""
	}
	vc := filepath.Join(build, "contrib/slapd-modules/vc/vc.la")
	if _, err := os.Stat(vc); os.IsNotExist(err) {
		return "", "", ""
	}
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		source = build
	}
	slapd := filepath.Join(build, "servers/slapd/slapd")
	authzid := filepath.Join(build, "contrib/slapd-modules/authzid/authzid.la")
	for _, path := range []string{slapd, vc, authzid} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("external VC artifact: %v", err)
		}
	}
	directory := t.TempDir()
	database := filepath.Join(directory, "db")
	if err := os.Mkdir(database, 0o700); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`include %q
include %q
moduleload %q
moduleload %q
pidfile %q
argsfile %q
overlay authzid
database mdb
suffix "dc=example"
rootdn "cn=admin,dc=example"
rootpw "vc-fixture-admin-password"
directory %q
access to attrs=userPassword by anonymous auth by * none
access to * by * read
overlay ppolicy
ppolicy_default "cn=policy,dc=example"
`, filepath.Join(source, "servers/slapd/schema/core.schema"), filepath.Join(source, "servers/slapd/schema/cosine.schema"),
		vc, authzid, filepath.Join(directory, "slapd.pid"), filepath.Join(directory, "slapd.args"), database)
	configPath := filepath.Join(directory, "slapd.conf")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	uri := "ldap://" + listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, slapd, "-f", configPath, "-h", uri, "-d", "0")
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("temporary VC slapd did not stop")
		}
	})
	var connection *ldap.Conn
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			done <- err
			t.Fatalf("temporary VC slapd exited: %v: %s", err, output.String())
		default:
		}
		connection, err = ldap.DialURL(uri, ldap.DialWithDialer(&net.Dialer{Timeout: 100 * time.Millisecond}))
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("temporary VC slapd did not become ready")
	}
	defer connection.Close()
	connection.SetTimeout(3 * time.Second)
	if err := connection.Bind("cn=admin,dc=example", "vc-fixture-admin-password"); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		dn    string
		attrs map[string][]string
	}{
		{"dc=example", map[string][]string{"objectClass": {"domain"}, "dc": {"example"}}},
		{"cn=policy,dc=example", map[string][]string{"objectClass": {"organizationalRole", "pwdPolicy"}, "cn": {"policy"}, "pwdAttribute": {"userPassword"}, "pwdMaxAge": {"3600"}}},
		{"cn=user,dc=example", map[string][]string{"objectClass": {"person"}, "cn": {"user"}, "sn": {"User"}, "userPassword": {"vc-fixture-user-password"}}},
	} {
		request := ldap.NewAddRequest(entry.dn, nil)
		for name, values := range entry.attrs {
			request.Attribute(name, values)
		}
		if err := connection.Add(request); err != nil {
			t.Fatalf("seed VC fixture: %v", err)
		}
	}
	passwordPath := filepath.Join(directory, "password")
	if err := os.WriteFile(passwordPath, []byte("vc-fixture-user-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	return uri, "cn=user,dc=example", passwordPath
}
