package lloadd

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestOpenLDAPReferenceLloaddServiceExternal(t *testing.T) {
	source := requirePinnedOpenLDAPLloaddSource(t)
	upstream, err := os.ReadFile(filepath.Join(source, "servers", "lloadd", "upstream.c"))
	if err != nil {
		t.Fatal(err)
	}
	if hash := fmt.Sprintf("%x", sha256.Sum256(upstream)); hash != "db9d0725ad5cc3e41be6dd6132e68f28a55138f5544042f658db70a5d138b282" {
		t.Fatalf("pinned upstream.c hash = %s", hash)
	}
	for _, anchor := range []string{
		"sasl_setprop( ctx, SASL_AUTH_EXTERNAL, authid.bv_val );",
		"if ( b->b_proto == LDAP_PROTO_IPC )",
		"sasl_setprop( ctx, SASL_AUTH_EXTERNAL, authid );",
		"bindconf.sb_cred.bv_val, bindconf.sb_authzId.bv_val",
		"&c->c_sasl_bind_mech, BER_BV_OPTIONAL( &cred )",
	} {
		if !strings.Contains(string(upstream), anchor) {
			t.Fatalf("pinned upstream.c lacks %q", anchor)
		}
	}
	for _, variable := range []string{"OPENLDAP_SLAPD", "OPENLDAP_LLOADD"} {
		binary := os.Getenv(variable)
		if binary == "" {
			t.Fatalf("%s must name the pinned executable", variable)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		output, err := exec.CommandContext(ctx, binary, "-VV").CombinedOutput()
		cancel()
		// Pinned standalone lloadd exits 1 from its version-only stop path.
		var exitError *exec.ExitError
		versionExit := variable == "OPENLDAP_LLOADD" && errors.As(err, &exitError) && exitError.ExitCode() == 1
		if !strings.Contains(string(output), " 2.6.13 (") ||
			(err != nil && !versionExit) {
			t.Fatalf("%s version: %v\n%s", variable, err, output)
		}
	}
	pki := newExternalTestPKI(t)
	ldapURI, ldapsURI, ldapiURI := startExternalTestOpenLDAP(t, pki, source)
	for _, test := range []struct {
		name       string
		uri        string
		startTLS   bool
		authzid    string
		omitCert   bool
		wantDenied bool
	}{
		{name: "StartTLS transport identity", uri: ldapURI, startTLS: true},
		{name: "LDAPS transport identity", uri: ldapsURI},
		{name: "LDAPS requested identity", uri: ldapsURI, authzid: "dn:" + externalTestReaderDN},
		{name: "StartTLS denied identity", uri: ldapURI, startTLS: true, authzid: "dn:cn=denied,dc=example,dc=com", wantDenied: true},
		{name: "TLS without client certificate", uri: ldapsURI, omitCert: true, wantDenied: true},
		{name: "cleartext rejected", uri: ldapURI, wantDenied: true},
		{name: "LDAPI transport identity", uri: ldapiURI},
		{name: "LDAPI requested identity", uri: ldapiURI, authzid: "dn:" + externalTestReaderDN},
		{name: "LDAPI denied identity", uri: ldapiURI, authzid: "dn:cn=denied,dc=example,dc=com", wantDenied: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.uri == "" {
				t.Skip("LDAPI requires Unix sockets")
			}
			bindTLS := ""
			if test.startTLS || strings.HasPrefix(test.uri, "ldaps:") {
				bindTLS = fmt.Sprintf(" tls_cacert=%s tls_reqcert=demand", pki.caFile)
				if !test.omitCert {
					bindTLS += fmt.Sprintf(" tls_cert=%s tls_key=%s", pki.clientCert, pki.clientKey)
				}
			}
			authzid := ""
			if test.authzid != "" {
				authzid = " authzid=" + test.authzid
			}
			startTLS := ""
			if test.startTLS {
				startTLS = " starttls=critical"
			}
			configText := fmt.Sprintf(`
feature proxyauthz
bindconf bindmethod=sasl saslmech=EXTERNAL secprops=none timeout=2%s%s
tier roundrobin
backend-server uri=%s numconns=1 bindconns=1 retry=50%s
`, authzid, bindTLS, test.uri, startTLS)
			config, err := Parse(strings.NewReader(configText))
			if err != nil {
				t.Fatal(err)
			}
			runtime, err := config.RuntimeConfig()
			if err != nil {
				t.Fatal(err)
			}
			// Verify the authenticated identity on new physical connections before
			// the proxy attaches any per-client authorization controls.
			direct, err := NewProxy(runtime)
			if err != nil {
				t.Fatal(err)
			}
			defer direct.Close()
			for generation := 0; generation < 2; generation++ {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				upstream, err := direct.tiers[0].backends[0].connect(ctx, "external-probe", false)
				cancel()
				if test.wantDenied {
					if err == nil {
						upstream.conn.Close()
						t.Fatal("unauthenticated EXTERNAL connection became usable")
					}
					break
				}
				if err != nil {
					t.Fatalf("connect generation %d: %v", generation, err)
				}
				connection := ldap.NewConn(upstream.conn, false)
				connection.Start()
				connection.SetTimeout(time.Second)
				identity, err := connection.WhoAmI(nil)
				connection.Close()
				want := "dn:" + serviceSASLTestDN
				if test.authzid != "" {
					want = test.authzid
				}
				if err != nil || identity == nil || identity.AuthzID != want {
					t.Fatalf("EXTERNAL generation %d WhoAmI = %#v, %v; want %q", generation, identity, err, want)
				}
			}
			proxy, goAddress := startRuntimeProxy(t, runtime)
			referenceAddress := startOpenLDAPReferenceLloadd(t, configText)
			if !test.wantDenied {
				waitForReadyConnections(t, proxy, PoolRegular, 1)
			}
			for _, target := range []struct{ name, address string }{{"ldap-go", goAddress}, {"OpenLDAP", referenceAddress}} {
				deadline := time.Now().Add(5 * time.Second)
				if test.wantDenied {
					deadline = time.Now().Add(500 * time.Millisecond)
				}
				for {
					err := externalTestSearch(target.address)
					if test.wantDenied {
						if !ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailable) {
							t.Fatalf("%s rejected EXTERNAL search = %v; want unavailable", target.name, err)
						}
						if time.Now().After(deadline) {
							break
						}
					} else if err == nil {
						break
					} else if time.Now().After(deadline) {
						t.Fatalf("%s EXTERNAL Bind/Search: %v", target.name, err)
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			if test.wantDenied && readyServiceSASLConnections(proxy, PoolRegular) != 0 {
				t.Fatal("rejected EXTERNAL backend entered regular pool")
			}
		})
	}
}

func startExternalTestOpenLDAP(t *testing.T, pki externalTestPKI, source string) (string, string, string) {
	t.Helper()
	reserve := func() string {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().String()
	}
	address, tlsAddress := reserve(), reserve()
	ldapURI, ldapsURI := "ldap://"+address, "ldaps://"+tlsAddress
	ldapiURI := ""
	if runtime.GOOS != "windows" {
		dir, err := os.MkdirTemp("/tmp", "ldap-go-external-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		ldapiURI = "ldapi://" + url.PathEscape(filepath.Join(dir, "ldap.sock"))
	}
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
TLSVerifyClient try
sasl-secprops none
authz-policy to
authz-regexp "^cn=lloadd-service$" "%s"
authz-regexp "^gidNumber=%d[+]uidNumber=%d,cn=peercred,cn=external,cn=auth$" "%s"
database mdb
maxsize 10485760
suffix "%s"
rootdn "cn=Manager,dc=example,dc=com"
rootpw secret
directory %s
access to * by * read
`, filepath.Join(source, "servers/slapd/schema/core.schema"),
		filepath.Join(source, "servers/slapd/schema/cosine.schema"),
		filepath.Join(pki.dir, "slapd.pid"), filepath.Join(pki.dir, "slapd.args"),
		pki.caFile, pki.serverCert, pki.serverKey, serviceSASLTestDN, os.Getegid(), os.Geteuid(),
		serviceSASLTestDN, serviceSASLTestBaseDN, databaseDir)
	externalTestWrite(t, configPath, []byte(config))
	process := &openLDAPLloaddProcess{done: make(chan struct{})}
	process.command = exec.Command(os.Getenv("OPENLDAP_SLAPD"), "-f", configPath,
		"-h", strings.TrimSpace(ldapURI+" "+ldapsURI+" "+ldapiURI), "-d", "0")
	process.command.Stdout, process.command.Stderr = &process.logs, &process.logs
	if err := process.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		forced, exited, err := process.stop(3*time.Second, 3*time.Second)
		if forced || !exited {
			t.Errorf("slapd shutdown: forced=%t exited=%t error=%v", forced, exited, err)
		}
		if exited && t.Failed() {
			t.Logf("slapd output:\n%s", process.logs.String())
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	var connection *ldap.Conn
	for {
		var err error
		connection, err = ldap.DialURL(ldapURI, ldap.DialWithDialer(&net.Dialer{Timeout: 100 * time.Millisecond}))
		if err == nil {
			break
		}
		if exited, err := process.wait(0); exited {
			t.Fatalf("slapd exited: %v\n%s", err, process.logs.String())
		}
		if time.Now().After(deadline) {
			t.Fatal("slapd did not listen")
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer connection.Close()
	connection.SetTimeout(time.Second)
	if err := connection.Bind("cn=Manager,dc=example,dc=com", "secret"); err != nil {
		t.Fatal(err)
	}
	base := ldap.NewAddRequest(serviceSASLTestBaseDN, nil)
	base.Attribute("objectClass", []string{"domain"})
	base.Attribute("dc", []string{"example"})
	if err := connection.Add(base); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"service", "reader", "denied"} {
		entry := ldap.NewAddRequest("cn="+name+","+serviceSASLTestBaseDN, nil)
		entry.Attribute("objectClass", []string{"organizationalRole", "simpleSecurityObject"})
		entry.Attribute("cn", []string{name})
		entry.Attribute("userPassword", []string{name + "-secret"})
		if name == "service" {
			entry.Attribute("authzTo", []string{"dn.exact:" + externalTestReaderDN})
		}
		if err := connection.Add(entry); err != nil {
			t.Fatal(err)
		}
	}
	return ldapURI, ldapsURI, ldapiURI
}
