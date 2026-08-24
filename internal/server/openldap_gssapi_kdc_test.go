package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const openLDAPGSSAPITestRealm = "LDAPGO.TEST"

type openLDAPGSSAPITestTools struct {
	krb5kdc    string
	kdb5Util   string
	kadmin     string
	kinit      string
	ldapwhoami string
}

type openLDAPGSSAPITestKDC struct {
	realm         string
	configuration string
	serviceKeytab string
	clientKeytab  string
	credential    string
}

func TestOpenLDAPReferenceGSSAPIDifferential(t *testing.T) {
	tools := requireOpenLDAPGSSAPITestTools(t)
	kdc := startOpenLDAPGSSAPITestKDC(t, tools)
	t.Setenv("KRB5_CONFIG", kdc.configuration)
	t.Setenv("KRB5CCNAME", "FILE:"+kdc.credential)
	t.Setenv("KRB5_CLIENT_KTNAME", "")
	t.Setenv("KRB5_KTNAME", "")

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
				{Description: "olcSaslHost", Values: stringValues("localhost")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("configure SASL host: %v", err)
	}

	address, stop := startServer(t, store, Config{
		GSSAPIKeytabPath: "FILE:" + kdc.serviceKeytab,
	})
	t.Cleanup(stop)
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("split LDAP listener address: %v", err)
	}

	want := "dn:uid=alice,cn=" + kdc.realm + ",cn=gssapi,cn=auth"
	for _, test := range []struct {
		name       string
		minimumSSF uint32
		maximumSSF uint32
		wantSSF    uint32
	}{
		{name: "no layer", maximumSSF: 0, wantSSF: 0},
		{name: "integrity", minimumSSF: 1, maximumSSF: 1, wantSSF: 1},
		{name: "confidentiality", minimumSSF: 2, maximumSSF: 256, wantSSF: 256},
	} {
		t.Run("pure Go ccache "+test.name, func(t *testing.T) {
			properties := defaultSyncConsumerSASLSecurityProperties()
			properties.minSSF = test.minimumSSF
			properties.maxSSF = test.maximumSSF
			configuration := syncConsumerConfig{
				bindMethod:         "sasl",
				saslMechanism:      "GSSAPI",
				securityProperties: properties,
			}
			runOpenLDAPGSSAPIPureGo(
				t,
				port,
				configuration,
				want,
				test.wantSSF,
			)
		})
	}

	properties := defaultSyncConsumerSASLSecurityProperties()
	properties.minSSF = 2
	properties.maxSSF = 256
	t.Run("pure Go password", func(t *testing.T) {
		runOpenLDAPGSSAPIPureGo(
			t,
			port,
			syncConsumerConfig{
				bindMethod:         "sasl",
				saslMechanism:      "GSSAPI",
				authenticationID:   "password-user",
				realm:              kdc.realm,
				credentials:        []byte("password-secret"),
				credentialsSet:     true,
				securityProperties: properties,
			},
			"dn:uid=password-user,cn="+kdc.realm+",cn=gssapi,cn=auth",
			256,
		)
	})

	t.Setenv("KRB5_CLIENT_KTNAME", "FILE:"+kdc.clientKeytab)
	properties.minSSF = 1
	properties.maxSSF = 1
	t.Run("pure Go keytab", func(t *testing.T) {
		runOpenLDAPGSSAPIPureGo(
			t,
			port,
			syncConsumerConfig{
				bindMethod:         "sasl",
				saslMechanism:      "GSSAPI",
				authenticationID:   "keytab-user",
				realm:              kdc.realm,
				securityProperties: properties,
			},
			"dn:uid=keytab-user,cn="+kdc.realm+",cn=gssapi,cn=auth",
			1,
		)
	})
	t.Setenv("KRB5_CLIENT_KTNAME", "")

	for _, test := range []struct {
		name       string
		properties string
	}{
		{name: "no layer", properties: "minssf=0,maxssf=0"},
		{name: "integrity", properties: "minssf=1,maxssf=1"},
		{name: "confidentiality", properties: "minssf=2,maxssf=256"},
	} {
		t.Run("native OpenLDAP "+test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(
				ctx,
				tools.ldapwhoami,
				"-H", "ldap://localhost:"+port,
				"-Y", "GSSAPI",
				"-Q",
				"-N",
				"-O", test.properties,
			)
			command.Env = append(os.Environ(),
				"KRB5_CONFIG="+kdc.configuration,
				"KRB5CCNAME=FILE:"+kdc.credential,
				"LDAPNOINIT=1",
			)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("native ldapwhoami GSSAPI %s: %v\n%s", test.name, err, output)
			}
			if got := strings.TrimSpace(string(output)); got != want {
				t.Fatalf("native ldapwhoami GSSAPI %s = %q, want %q", test.name, got, want)
			}
		})
	}
}

func runOpenLDAPGSSAPIPureGo(
	t *testing.T,
	port string,
	configuration syncConsumerConfig,
	wantIdentity string,
	wantSSF uint32,
) {
	t.Helper()
	defer clear(configuration.credentials)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(
		ctx,
		"tcp",
		net.JoinHostPort("localhost", port),
	)
	if err != nil {
		t.Fatalf("dial ldap-go GSSAPI provider: %v", err)
	}
	transport := &syncConsumerTransport{
		connection:       connection,
		context:          ctx,
		operationTimeout: 10 * time.Second,
	}
	defer transport.close()
	provider := "ldap://" + net.JoinHostPort("localhost", port)
	if err := bindLDAPBackendGSSAPI(ctx, transport, configuration, provider); err != nil {
		t.Fatalf("pure-Go GSSAPI Bind: %v", err)
	}
	if transport.ssf != wantSSF {
		t.Fatalf("pure-Go GSSAPI SSF = %d, want %d", transport.ssf, wantSSF)
	}

	messageID := transport.nextMessageID()
	encoded, err := ldapwire.EncodeRequestMessage(ldapwire.Message{
		ID: messageID,
		Request: ldapwire.ExtendedRequest{
			Name: whoAmIOID,
		},
	})
	if err != nil {
		t.Fatalf("encode protected Who Am I: %v", err)
	}
	request, err := ber.DecodePacketErr(encoded)
	if err != nil {
		t.Fatalf("decode protected Who Am I request: %v", err)
	}
	result, err := transport.exchangeLDAPResult(
		messageID,
		request,
		ldap.ApplicationExtendedResponse,
	)
	if err != nil {
		t.Fatalf("pure-Go GSSAPI Who Am I: %v", err)
	}
	defer clear(result.responseValue)
	if result.code != ldap.LDAPResultSuccess || string(result.responseValue) != wantIdentity {
		t.Fatalf(
			"pure-Go GSSAPI Who Am I = code %d, %q; want 0, %q",
			result.code,
			result.responseValue,
			wantIdentity,
		)
	}
}

func requireOpenLDAPGSSAPITestTools(t *testing.T) openLDAPGSSAPITestTools {
	t.Helper()
	if os.Getenv("LDAP_GO_OPENLDAP_GSSAPI_TESTS") != "1" {
		t.Skip("set LDAP_GO_OPENLDAP_GSSAPI_TESTS=1 through scripts/test-openldap.sh")
	}
	lookup := func(environment, name string) string {
		if value := strings.TrimSpace(os.Getenv(environment)); value != "" {
			if info, err := os.Stat(value); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
				return value
			}
		}
		value, err := exec.LookPath(name)
		if err != nil {
			t.Fatalf("GSSAPI topology requires %s: %v", name, err)
		}
		return value
	}
	return openLDAPGSSAPITestTools{
		krb5kdc:    lookup("LDAP_GO_KRB5KDC", "krb5kdc"),
		kdb5Util:   lookup("LDAP_GO_KDB5_UTIL", "kdb5_util"),
		kadmin:     lookup("LDAP_GO_KADMIN_LOCAL", "kadmin.local"),
		kinit:      lookup("LDAP_GO_KINIT", "kinit"),
		ldapwhoami: lookup("OPENLDAP_LDAPWHOAMI", "ldapwhoami"),
	}
}

func startOpenLDAPGSSAPITestKDC(
	t *testing.T,
	tools openLDAPGSSAPITestTools,
) openLDAPGSSAPITestKDC {
	t.Helper()
	root := t.TempDir()
	port := reserveOpenLDAPGSSAPITestPort(t)
	realm := openLDAPGSSAPITestRealm
	configuration := filepath.Join(root, "krb5.conf")
	kdcConfiguration := filepath.Join(root, "kdc.conf")
	database := filepath.Join(root, "principal")
	stash := filepath.Join(root, ".k5."+realm)
	acl := filepath.Join(root, "kadm5.acl")
	serviceKeytab := filepath.Join(root, "ldap.keytab")
	clientKeytab := filepath.Join(root, "alice.keytab")
	nativeClientKeytab := filepath.Join(root, "keytab-user.keytab")
	credential := filepath.Join(root, "krb5cc_alice")
	logPath := filepath.Join(root, "krb5kdc.log")

	writeOpenLDAPGSSAPITestFile(t, configuration, fmt.Sprintf(`[libdefaults]
 default_realm = %[1]s
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 udp_preference_limit = 1

[realms]
 %[1]s = {
  kdc = 127.0.0.1:%[2]d
 }

[domain_realm]
 localhost = %[1]s
 .localhost = %[1]s
`, realm, port))
	writeOpenLDAPGSSAPITestFile(t, kdcConfiguration, fmt.Sprintf(`[kdcdefaults]
 kdc_ports = %[1]d
 kdc_tcp_ports = %[1]d

[realms]
 %[2]s = {
  database_name = %[3]s
  key_stash_file = %[4]s
  acl_file = %[5]s
  max_life = 1h
  max_renewable_life = 2h
  master_key_type = aes256-cts-hmac-sha1-96
  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
 }
`, port, realm, database, stash, acl))
	writeOpenLDAPGSSAPITestFile(t, acl, "*/admin@"+realm+" *\n")

	environment := append(os.Environ(),
		"KRB5_CONFIG="+configuration,
		"KRB5_KDC_PROFILE="+kdcConfiguration,
	)
	runOpenLDAPGSSAPITestCommand(
		t, environment, tools.kdb5Util,
		"-r", realm, "-d", database, "-sf", stash,
		"-P", "ldap-go-test-master-password", "create", "-s",
	)
	for _, command := range []string{
		"addprinc -randkey alice@" + realm,
		"ktadd -k " + clientKeytab + " alice@" + realm,
		"addprinc -pw password-secret password-user@" + realm,
		"addprinc -randkey keytab-user@" + realm,
		"ktadd -k " + nativeClientKeytab + " keytab-user@" + realm,
		"addprinc -randkey ldap/localhost@" + realm,
		"ktadd -k " + serviceKeytab + " ldap/localhost@" + realm,
	} {
		runOpenLDAPGSSAPITestCommand(
			t, environment, tools.kadmin,
			"-r", realm, "-d", database, "-q", command,
		)
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open KDC log: %v", err)
	}
	kdcCommand := exec.Command(tools.krb5kdc, "-n", "-r", realm, "-d", database)
	kdcCommand.Env = environment
	kdcCommand.Stdout = logFile
	kdcCommand.Stderr = logFile
	if err := kdcCommand.Start(); err != nil {
		_ = logFile.Close()
		t.Fatalf("start MIT KDC: %v", err)
	}
	kdcDone := make(chan error, 1)
	go func() { kdcDone <- kdcCommand.Wait() }()
	kdcWaited := false
	t.Cleanup(func() {
		if kdcWaited {
			_ = logFile.Close()
			return
		}
		if kdcCommand.Process != nil {
			_ = kdcCommand.Process.Signal(os.Interrupt)
		}
		select {
		case <-kdcDone:
			kdcWaited = true
		case <-time.After(2 * time.Second):
			if kdcCommand.Process != nil {
				_ = kdcCommand.Process.Kill()
			}
			<-kdcDone
			kdcWaited = true
		}
		_ = logFile.Close()
	})

	var lastOutput []byte
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		command := exec.Command(
			tools.kinit,
			"-k", "-t", clientKeytab,
			"-c", "FILE:"+credential,
			"alice@"+realm,
		)
		command.Env = environment
		lastOutput, err = command.CombinedOutput()
		if err == nil {
			return openLDAPGSSAPITestKDC{
				realm:         realm,
				configuration: configuration,
				serviceKeytab: serviceKeytab,
				clientKeytab:  nativeClientKeytab,
				credential:    credential,
			}
		}
		select {
		case kdcErr := <-kdcDone:
			kdcWaited = true
			log, _ := os.ReadFile(logPath)
			t.Fatalf("MIT KDC exited before readiness: %v\n%s", kdcErr, log)
		case <-time.After(50 * time.Millisecond):
		}
	}
	log, _ := os.ReadFile(logPath)
	t.Fatalf("initialize MIT KDC client credential: %v\n%s\n%s", err, lastOutput, log)
	return openLDAPGSSAPITestKDC{}
}

func reserveOpenLDAPGSSAPITestPort(t *testing.T) int {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve KDC TCP port: %v", err)
	}
	port := tcp.Addr().(*net.TCPAddr).Port
	udp, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		_ = tcp.Close()
		t.Fatalf("reserve KDC UDP port: %v", err)
	}
	_ = udp.Close()
	_ = tcp.Close()
	return port
}

func writeOpenLDAPGSSAPITestFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatalf("write %s: %v", filepath.Base(path), err)
	}
}

func runOpenLDAPGSSAPITestCommand(
	t *testing.T,
	environment []string,
	name string,
	arguments ...string,
) {
	t.Helper()
	command := exec.Command(name, arguments...)
	command.Env = environment
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run %s %s: %v\n%s", filepath.Base(name), strings.Join(arguments, " "), err, bytes.TrimSpace(output))
	}
}
