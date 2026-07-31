package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
	"github.com/xdg-go/scram"
)

func TestLDAPClientSASLSCRAMBind(t *testing.T) {
	for _, mechanism := range []string{
		"SCRAM-SHA-1",
		"SCRAM-SHA-256",
		"SCRAM-SHA-512",
	} {
		mechanism := mechanism
		t.Run(mechanism, func(t *testing.T) {
			t.Parallel()

			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedDirectory(t, store)
			seedSASLSCRAMConfiguration(t, store, mechanism)

			address, stop := startServer(t, store, Config{})
			defer stop()
			probe, err := ldap.DialURL("ldap://" + address)
			if err != nil {
				t.Fatalf("dial Root DSE probe: %v", err)
			}
			rootDSE, err := probe.Search(ldap.NewSearchRequest(
				"",
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				0,
				0,
				false,
				"(objectClass=*)",
				[]string{"supportedSASLMechanisms"},
				nil,
			))
			_ = probe.Close()
			if err != nil ||
				len(rootDSE.Entries) != 1 ||
				!containsString(
					rootDSE.Entries[0].GetAttributeValues(
						"supportedSASLMechanisms",
					),
					mechanism,
				) {
				t.Fatalf("SCRAM Root DSE = %#v, %v", rootDSE, err)
			}

			connection, err := dialAndBindSASLSCRAM(
				address,
				mechanism,
				"u:alice",
				"alice",
				"secret",
			)
			if err != nil {
				t.Fatalf("%s Bind: %v", mechanism, err)
			}
			client := ldap.NewConn(connection, false)
			client.Start()
			identity, err := client.WhoAmI(nil)
			_ = client.Close()
			if err != nil ||
				identity.AuthzID !=
					"dn:uid=alice,ou=people,dc=example,dc=com" {
				t.Fatalf("%s WhoAmI = %#v, %v", mechanism, identity, err)
			}

			connection, err = dialAndBindSASLSCRAM(
				address,
				mechanism,
				"",
				"alice",
				"wrong-password",
			)
			if connection != nil {
				_ = connection.Close()
			}
			assertWrappedLDAPResultCode(
				t,
				err,
				ldap.LDAPResultInvalidCredentials,
			)
		})
	}
}

func TestLDAPClientSASLSCRAMRejectsProxyAuthorization(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSASLSCRAMConfiguration(t, store, "SCRAM-SHA-256")

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection, err := dialAndBindSASLSCRAM(
		address,
		"SCRAM-SHA-256",
		"dn:uid=someone,ou=people,dc=example,dc=com",
		"alice",
		"secret",
	)
	if connection != nil {
		_ = connection.Close()
	}
	assertWrappedLDAPResultCode(
		t,
		err,
		ldap.LDAPResultInappropriateAuthentication,
	)
}

func TestLDAPClientSASLSCRAMBindWithCyrusAuthPassword(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedCyrusSCRAMAuthPassword(t, store, true)

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection, err := dialAndBindSASLSCRAM(
		address,
		"SCRAM-SHA-256",
		"",
		"alice",
		"secret",
	)
	if err != nil {
		t.Fatalf("authPassword SCRAM Bind: %v", err)
	}
	_ = connection.Close()
}

func TestSASLSCRAMCyrusAuthPasswordRequiresAuthAccess(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedCyrusSCRAMAuthPassword(t, store, false)

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection, err := dialAndBindSASLSCRAM(
		address,
		"SCRAM-SHA-256",
		"",
		"alice",
		"secret",
	)
	if connection != nil {
		_ = connection.Close()
	}
	assertWrappedLDAPResultCode(
		t,
		err,
		ldap.LDAPResultInvalidCredentials,
	)
}

func TestSASLSCRAMBindWithoutInitialResponse(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSASLSCRAMConfiguration(t, store, "SCRAM-SHA-256")

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial SCRAM server: %v", err)
	}
	defer connection.Close()
	transport := &syncConsumerTransport{
		connection:       connection,
		context:          context.Background(),
		operationTimeout: 2 * time.Second,
	}

	first, err := sendSyncConsumerSASLBind(
		transport,
		"SCRAM-SHA-256",
		nil,
		false,
	)
	if err != nil ||
		first.code != ldap.LDAPResultSaslBindInProgress ||
		!first.hasSASLCredentials ||
		len(first.saslCredentials) != 0 {
		t.Fatalf("empty SCRAM initial result = %#v, %v", first, err)
	}

	client, err := scram.SHA256.NewClient("alice", "secret", "")
	if err != nil {
		t.Fatalf("create SCRAM client: %v", err)
	}
	conversation := client.NewConversation()
	clientFirst, err := conversation.Step("")
	if err != nil {
		t.Fatalf("create SCRAM client-first: %v", err)
	}
	second, err := sendSyncConsumerSASLBind(
		transport,
		"SCRAM-SHA-256",
		[]byte(clientFirst),
		true,
	)
	if err != nil ||
		second.code != ldap.LDAPResultSaslBindInProgress ||
		!second.hasSASLCredentials {
		t.Fatalf("SCRAM server-first result = %#v, %v", second, err)
	}
	clientFinal, err := conversation.Step(
		string(second.saslCredentials),
	)
	if err != nil {
		t.Fatalf("create SCRAM client-final: %v", err)
	}
	final, err := sendSyncConsumerSASLBind(
		transport,
		"SCRAM-SHA-256",
		[]byte(clientFinal),
		true,
	)
	if err != nil ||
		final.code != ldap.LDAPResultSuccess ||
		!final.hasSASLCredentials {
		t.Fatalf("SCRAM server-final result = %#v, %v", final, err)
	}
	if _, err := conversation.Step(
		string(final.saslCredentials),
	); err != nil || !conversation.Valid() {
		t.Fatalf("verify SCRAM server-final: valid=%t, error=%v",
			conversation.Valid(),
			err,
		)
	}
}

func TestSASLBindInProgressRejectsSearch(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSASLSCRAMConfiguration(t, store, "SCRAM-SHA-256")

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial SCRAM server: %v", err)
	}
	transport := &syncConsumerTransport{
		connection:       connection,
		context:          context.Background(),
		operationTimeout: 2 * time.Second,
	}
	result, err := sendSyncConsumerSASLBind(
		transport,
		"SCRAM-SHA-256",
		nil,
		false,
	)
	if err != nil || result.code != ldap.LDAPResultSaslBindInProgress {
		_ = connection.Close()
		t.Fatalf("start SCRAM Bind = %#v, %v", result, err)
	}

	client := ldap.NewConn(connection, false)
	client.Start()
	defer client.Close()
	_, err = client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedLDAPVersion"},
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultOperationsError)
}

func TestParseCyrusSASLSCRAMSecret(t *testing.T) {
	t.Parallel()

	client, err := scram.SHA256.NewClient("alice", "secret", "")
	if err != nil {
		t.Fatalf("create SCRAM client: %v", err)
	}
	want, err := client.GetStoredCredentialsWithError(scram.KeyFactors{
		Salt:  "salt",
		Iters: 4096,
	})
	if err != nil {
		t.Fatalf("derive SCRAM credentials: %v", err)
	}
	encoded := formatCyrusSASLSCRAMSecret("SCRAM-SHA-256", want)
	got, ok := parseCyrusSASLSCRAMSecret(
		encoded,
		"SCRAM-SHA-256",
		scram.SHA256().Size(),
	)
	if !ok ||
		got.Salt != want.Salt ||
		got.Iters != want.Iters ||
		!bytes.Equal(got.StoredKey, want.StoredKey) ||
		!bytes.Equal(got.ServerKey, want.ServerKey) {
		t.Fatalf("parsed SCRAM credentials = %#v, %t", got, ok)
	}
	for _, malformed := range [][]byte{
		[]byte("SCRAM-SHA-1$4096:c2FsdA==$bad:bad"),
		[]byte("SCRAM-SHA-256$0:c2FsdA==$bad:bad"),
		[]byte("SCRAM-SHA-256$10000001:c2FsdA==$bad:bad"),
		[]byte("SCRAM-SHA-256$4096:not-base64$bad:bad"),
	} {
		if _, ok := parseCyrusSASLSCRAMSecret(
			malformed,
			"SCRAM-SHA-256",
			scram.SHA256().Size(),
		); ok {
			t.Fatalf("accepted malformed SCRAM secret %q", malformed)
		}
	}
}

func TestOpenLDAPClientSASLSCRAMSHA256Bind(t *testing.T) {
	if os.Getenv(openLDAPReferenceTestsEnv) == "" {
		t.Skipf(
			"set %s=1 to run the OpenLDAP SCRAM interoperability test",
			openLDAPReferenceTestsEnv,
		)
	}
	ldapWhoAmI := ""
	if path, err := exec.LookPath("ldapwhoami"); err == nil {
		ldapWhoAmI = path
	}
	if ldapWhoAmI == "" {
		const homebrewLDAPWhoAmI = "/opt/homebrew/opt/openldap/bin/ldapwhoami"
		if info, err := os.Stat(homebrewLDAPWhoAmI); err == nil &&
			!info.IsDir() {
			ldapWhoAmI = homebrewLDAPWhoAmI
		}
	}
	if ldapWhoAmI == "" {
		t.Skip("OpenLDAP ldapwhoami is not installed")
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSASLSCRAMConfiguration(t, store, "SCRAM-SHA-256")
	address, stop := startServer(t, store, Config{})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		ldapWhoAmI,
		"-Y",
		"SCRAM-SHA-256",
		"-U",
		"alice",
		"-w",
		"secret",
		"-O",
		"none",
		"-H",
		"ldap://"+address,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		lower := strings.ToLower(string(output))
		if strings.Contains(lower, "no worthy mechs") ||
			strings.Contains(lower, "mechanism not supported") {
			t.Skip("OpenLDAP Cyrus SASL installation has no SCRAM-SHA-256 plugin")
		}
		t.Fatalf("ldapwhoami SCRAM-SHA-256: %v\n%s", err, output)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 ||
		lines[len(lines)-1] !=
			"dn:uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("ldapwhoami SCRAM-SHA-256 output = %q", output)
	}
}

func seedSASLSCRAMConfiguration(
	t *testing.T,
	store storage.Store,
	mechanism string,
) {
	t.Helper()
	seedSASLConfiguration(
		t,
		store,
		"noplain,noanonymous",
		fmt.Sprintf(
			`{0}^uid=([^,]+),cn=%s,cn=auth$ `+
				`uid=$1,ou=people,dc=example,dc=com`,
			strings.ToLower(mechanism),
		),
	)
}

func seedCyrusSCRAMAuthPassword(
	t *testing.T,
	store storage.Store,
	grantAuthAccess bool,
) {
	t.Helper()

	credentialClient, err := scram.SHA256.NewClient(
		"alice",
		"secret",
		"",
	)
	if err != nil {
		t.Fatalf("create SCRAM credential client: %v", err)
	}
	credentials, err := credentialClient.GetStoredCredentialsWithError(
		scram.KeyFactors{
			Salt:  "fixed SCRAM salt",
			Iters: defaultSASLSCRAMIterations,
		},
	)
	if err != nil {
		t.Fatalf("derive SCRAM credentials: %v", err)
	}
	secret := formatCyrusSASLSCRAMSecret(
		"SCRAM-SHA-256",
		credentials,
	)

	seedDirectory(t, store)
	userDN, err := directory.ParseDN(
		"uid=alice,ou=people,dc=example,dc=com",
	)
	if err != nil {
		t.Fatalf("parse user DN: %v", err)
	}
	configDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
	if err != nil {
		t.Fatalf("parse config DN: %v", err)
	}
	if err := store.Update(context.Background(), func(
		writer storage.Writer,
	) error {
		user, err := writer.Get(userDN)
		if err != nil {
			return err
		}
		user.ReplaceValues(
			"objectClass",
			stringValues("inetOrgPerson", "extensibleObject"),
		)
		user.ReplaceValues("userPassword", nil)
		user.ReplaceValues("authPassword", [][]byte{secret})
		if err := writer.Put(user, true); err != nil {
			return err
		}
		if !grantAuthAccess {
			return nil
		}
		config, err := writer.Get(configDN)
		if err != nil {
			return err
		}
		config.ReplaceValues("olcAccess", stringValues(
			"{0}to attrs=userPassword,authPassword by anonymous auth by * none",
			"{1}to * by self write by users read by * none",
		))
		return writer.Put(config, true)
	}); err != nil {
		t.Fatalf("seed Cyrus authPassword credentials: %v", err)
	}
	seedSASLSCRAMConfiguration(t, store, "SCRAM-SHA-256")
}

func dialAndBindSASLSCRAM(
	address string,
	mechanism string,
	authorizationID string,
	authenticationID string,
	password string,
) (net.Conn, error) {
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return nil, err
	}
	properties, err := parseSASLSecurityProperties("none")
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	transport := &syncConsumerTransport{
		connection:       connection,
		context:          context.Background(),
		operationTimeout: 2 * time.Second,
	}
	err = bindSyncConsumerSASL(transport, syncConsumerConfig{
		saslMechanism:      mechanism,
		authenticationID:   authenticationID,
		authorizationID:    authorizationID,
		credentials:        []byte(password),
		securityProperties: properties,
	})
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	if err := transport.clearDeadline(); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return connection, nil
}

func formatCyrusSASLSCRAMSecret(
	mechanism string,
	credentials scram.StoredCredentials,
) []byte {
	return []byte(fmt.Sprintf(
		"%s$%d:%s$%s:%s",
		mechanism,
		credentials.Iters,
		base64.StdEncoding.EncodeToString([]byte(credentials.Salt)),
		base64.StdEncoding.EncodeToString(credentials.StoredKey),
		base64.StdEncoding.EncodeToString(credentials.ServerKey),
	))
}
