package lloadd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// This tests Go lloadd against a real slapd/Cyrus endpoint provider. Native
// lloadd's automatic raw tls-unique binding is a separate source contract.
func TestServiceSASLSCRAMPlusOpenLDAP2613NativeProvider(t *testing.T) {
	const gate = "LDAP_GO_LLOADD_SCRAM_PLUS_NATIVE_TESTS"
	if os.Getenv(gate) != "1" {
		t.Skip("set " + gate + "=1 with the pinned OpenLDAP build environment")
	}
	if os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" || os.Getenv("OPENLDAP_COMMIT") != openLDAPLloaddCommit {
		t.Fatal("native provider requires the verified OpenLDAP 2.6.13 build pin")
	}
	source, binary := os.Getenv("OPENLDAP_SOURCE"), os.Getenv("OPENLDAP_SLAPD")
	if source == "" || binary == "" {
		t.Fatal("OPENLDAP_SOURCE and OPENLDAP_SLAPD are required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	head, err := exec.CommandContext(ctx, "git", "-C", source, "rev-parse", "HEAD").Output()
	cancel()
	if err != nil || strings.TrimSpace(string(head)) != openLDAPLloaddCommit {
		t.Fatalf("native provider source pin: %q, %v", head, err)
	}
	ctx, cancel = context.WithTimeout(t.Context(), 5*time.Second)
	version, err := exec.CommandContext(ctx, binary, "-VV").CombinedOutput()
	cancel()
	if err != nil || !strings.Contains(string(version), "slapd 2.6.13 (") {
		t.Fatalf("native provider version: %s, %v", version, err)
	}
	t.Logf("Go lloadd -> slapd/Cyrus: %s/%s %s; pin=%s; sasl-cbinding=tls-endpoint; SASL_PATH=%s",
		runtime.GOOS, runtime.GOARCH, runtime.Version(), openLDAPLloaddCommit, os.Getenv("SASL_PATH"))
	t.Logf("OPENLDAP_SLAPD=%s\n%s", binary, strings.TrimSpace(string(version)))
	pki := newExternalTestPKI(t)
	ldapURI, ldapsURI := startServiceSCRAMPlusNativeProvider(t, pki, source, binary)
	for _, transport := range []struct {
		name, uri string
		startTLS  bool
	}{{"StartTLS", ldapURI, true}, {"LDAPS", ldapsURI, false}} {
		for _, mechanism := range serviceSCRAMPlusTestMechanisms {
			t.Run(transport.name+"/"+mechanism, func(t *testing.T) {
				config := serviceSCRAMPlusTestConfig(t, pki, transport.uri, mechanism, transport.startTLS)
				config.Bind.AuthorizationID, config.PrivilegedIdentity = "", ""
				config.Tiers[0].Backends[0].StartTLSCritical = transport.startTLS
				proxy, err := NewProxy(config)
				if err != nil {
					t.Fatal(err)
				}
				defer proxy.Close()
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				upstream, err := proxy.tiers[0].backends[0].connect(ctx, "native-plus-provider", false)
				cancel()
				if err != nil {
					t.Fatalf("Go service bind against native provider: %v", err)
				}
				client := ldap.NewConn(upstream.conn, true)
				client.Start()
				defer client.Close()
				client.SetTimeout(2 * time.Second)
				identity, err := client.WhoAmI(nil)
				if err != nil || identity == nil || identity.AuthzID != "dn:"+serviceSASLTestDN {
					t.Fatalf("native WhoAmI: %+v, %v", identity, err)
				}
				result, err := client.Search(ldap.NewSearchRequest(serviceSASLTestBaseDN, ldap.ScopeBaseObject,
					ldap.NeverDerefAliases, 1, 1, false, "(objectClass=*)", []string{"dc"}, nil))
				if err != nil || result == nil || len(result.Entries) != 1 || result.Entries[0].GetAttributeValue("dc") != "example" {
					t.Fatalf("native authenticated Search: %+v, %v", result, err)
				}
				t.Logf("verified server proof; WhoAmI=%s; authenticated Search succeeded", identity.AuthzID)
			})
		}
	}
}

func startServiceSCRAMPlusNativeProvider(t *testing.T, pki externalTestPKI, source, binary string) (string, string) {
	t.Helper()
	reserve := func() string {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().String()
	}
	ldapURI, ldapsURI := "ldap://"+reserve(), "ldaps://"+reserve()
	databaseDir := filepath.Join(pki.dir, "db")
	if err := os.Mkdir(databaseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(pki.dir, "slapd.conf")
	config := fmt.Sprintf(`include %s
include %s
pidfile %s
argsfile %s
TLSCACertificateFile %s
TLSCertificateFile %s
TLSCertificateKeyFile %s
TLSVerifyClient never
sasl-host localhost
sasl-secprops none
sasl-cbinding tls-endpoint
authz-regexp "^uid=service,.*cn=auth$" "%s"
database mdb
maxsize 10485760
suffix "%s"
rootdn "cn=Manager,dc=example,dc=com"
rootpw secret
directory %s
access to * by dn.exact="%s" read by anonymous auth by * none
`, filepath.Join(source, "servers/slapd/schema/core.schema"), filepath.Join(source, "servers/slapd/schema/cosine.schema"),
		filepath.Join(pki.dir, "slapd.pid"), filepath.Join(pki.dir, "slapd.args"),
		pki.caFile, pki.serverCert, pki.serverKey, serviceSASLTestDN, serviceSASLTestBaseDN, databaseDir, serviceSASLTestDN)
	externalTestWrite(t, configPath, []byte(config))
	process := &openLDAPLloaddProcess{done: make(chan struct{})}
	// T.Context is canceled before Cleanup, which would kill the process before
	// the shared helper can stop it gracefully. Keep an independent time cap.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	process.command = exec.CommandContext(ctx, binary, "-f", configPath, "-h", ldapURI+" "+ldapsURI, "-d", "0")
	process.command.Stdout, process.command.Stderr = &process.logs, &process.logs
	if err := process.start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer cancel()
		forced, exited, err := process.stop(3*time.Second, 3*time.Second)
		if forced || !exited || err != nil {
			t.Errorf("native provider cleanup: forced=%t exited=%t err=%v", forced, exited, err)
		}
		if exited && t.Failed() {
			t.Logf("native provider output:\n%s", process.logs.String())
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	var client *ldap.Conn
	for {
		var err error
		client, err = ldap.DialURL(ldapURI, ldap.DialWithDialer(&net.Dialer{Timeout: 100 * time.Millisecond}))
		if err == nil {
			break
		}
		if exited, err := process.wait(0); exited {
			t.Fatalf("native provider exited: %v\n%s", err, process.logs.String())
		}
		if time.Now().After(deadline) {
			t.Fatal("native provider did not listen within 5 seconds")
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer client.Close()
	client.SetTimeout(time.Second)
	if err := client.Bind("cn=Manager,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	base := ldap.NewAddRequest(serviceSASLTestBaseDN, nil)
	base.Attribute("objectClass", []string{"domain"})
	base.Attribute("dc", []string{"example"})
	if err := client.Add(base); err != nil {
		t.Fatal(err)
	}
	service := ldap.NewAddRequest(serviceSASLTestDN, nil)
	service.Attribute("objectClass", []string{"organizationalRole", "simpleSecurityObject"})
	service.Attribute("cn", []string{"service"})
	service.Attribute("userPassword", []string{serviceSASLTestPassword})
	if err := client.Add(service); err != nil {
		t.Fatal(err)
	}
	return ldapURI, ldapsURI
}
