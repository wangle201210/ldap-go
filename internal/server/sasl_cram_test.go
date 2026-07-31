package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientSASLCRAMMD5Bind(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSASLCRAMMD5Configuration(t, store)

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
			"CRAM-MD5",
		) {
		t.Fatalf("CRAM-MD5 Root DSE = %#v, %v", rootDSE, err)
	}

	connection, err := dialAndBindSASLCRAMMD5(
		address,
		"alice",
		"secret",
	)
	if err != nil {
		t.Fatalf("CRAM-MD5 Bind: %v", err)
	}
	client := ldap.NewConn(connection, false)
	client.Start()
	identity, err := client.WhoAmI(nil)
	_ = client.Close()
	if err != nil ||
		identity.AuthzID !=
			"dn:uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("CRAM-MD5 WhoAmI = %#v, %v", identity, err)
	}

	connection, err = dialAndBindSASLCRAMMD5(
		address,
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
}

func TestSASLCRAMMD5ChallengeAndInitialResponse(t *testing.T) {
	t.Parallel()

	challenge, err := newSASLCRAMMD5Challenge(
		"ldap.example.test",
		time.Unix(0xFFFFFF+7, 0),
		bytes.NewReader([]byte{1, 2, 3, 4}),
	)
	if err != nil ||
		string(challenge) != "<16909060.7@ldap.example.test>" {
		t.Fatalf("deterministic CRAM-MD5 challenge = %q, %v", challenge, err)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSASLCRAMMD5Configuration(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial CRAM-MD5 server: %v", err)
	}
	defer connection.Close()
	transport := &syncConsumerTransport{
		connection:       connection,
		context:          context.Background(),
		operationTimeout: 2 * time.Second,
	}

	rejected, err := sendSyncConsumerSASLBind(
		transport,
		"CRAM-MD5",
		[]byte("unexpected initial response"),
		true,
	)
	if err != nil ||
		rejected.code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("CRAM-MD5 initial response = %#v, %v", rejected, err)
	}

	first, err := sendSyncConsumerSASLBind(
		transport,
		"CRAM-MD5",
		nil,
		false,
	)
	if err != nil ||
		first.code != ldap.LDAPResultSaslBindInProgress ||
		!first.hasSASLCredentials ||
		!strings.HasPrefix(string(first.saslCredentials), "<") ||
		!strings.HasSuffix(
			string(first.saslCredentials),
			"@ldap.example.test>",
		) {
		t.Fatalf("CRAM-MD5 challenge = %#v, %v", first, err)
	}

	final, err := sendSyncConsumerSASLBind(
		transport,
		"CRAM-MD5",
		saslCRAMMD5Response(
			"alice",
			[]byte("secret"),
			first.saslCredentials,
		),
		true,
	)
	if err != nil || final.code != ldap.LDAPResultSuccess {
		t.Fatalf("CRAM-MD5 response = %#v, %v", final, err)
	}
}

func TestSASLCRAMMD5RequiresCleartextPassword(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	hashed, err := auth.HashPassword(
		[]byte("secret"),
		"{SSHA}",
		bytes.NewReader([]byte{1, 2, 3, 4}),
	)
	if err != nil {
		t.Fatalf("hash CRAM-MD5 user password: %v", err)
	}
	replaceSASLCRAMMD5UserPassword(t, store, hashed)
	seedSASLCRAMMD5Configuration(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection, err := dialAndBindSASLCRAMMD5(
		address,
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

func TestSASLCRAMMD5RequiresAuthAccess(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	databaseDN, err := directory.ParseDN(
		"olcDatabase={1}mdb,cn=config",
	)
	if err != nil {
		t.Fatalf("parse database DN: %v", err)
	}
	if err := store.Update(context.Background(), func(
		writer storage.Writer,
	) error {
		entry, err := writer.Get(databaseDN)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccess", stringValues(
			"{0}to attrs=userPassword by * none",
			"{1}to * by self write by users read by * none",
		))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("deny anonymous auth access: %v", err)
	}
	seedSASLCRAMMD5Configuration(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection, err := dialAndBindSASLCRAMMD5(
		address,
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

func TestOpenLDAPClientSASLCRAMMD5Bind(t *testing.T) {
	if os.Getenv(openLDAPReferenceTestsEnv) == "" {
		t.Skipf(
			"set %s=1 to run the OpenLDAP CRAM-MD5 interoperability test",
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
	seedSASLCRAMMD5Configuration(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		ldapWhoAmI,
		"-Y",
		"CRAM-MD5",
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
			t.Skip("OpenLDAP Cyrus SASL installation has no CRAM-MD5 plugin")
		}
		t.Fatalf("ldapwhoami CRAM-MD5: %v\n%s", err, output)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 ||
		lines[len(lines)-1] !=
			"dn:uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("ldapwhoami CRAM-MD5 output = %q", output)
	}
}

func seedSASLCRAMMD5Configuration(
	t *testing.T,
	store storage.Store,
) {
	t.Helper()
	seedSASLConfiguration(
		t,
		store,
		"noplain,noanonymous",
		`{0}^uid=([^,]+),cn=cram-md5,cn=auth$ `+
			`uid=$1,ou=people,dc=example,dc=com`,
	)
	configDN, err := directory.ParseDN("cn=config")
	if err != nil {
		t.Fatalf("parse global configuration DN: %v", err)
	}
	if err := store.Update(context.Background(), func(
		writer storage.Writer,
	) error {
		entry, err := writer.Get(configDN)
		if err != nil {
			return err
		}
		entry.ReplaceValues(
			"olcSaslHost",
			stringValues("ldap.example.test"),
		)
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("seed CRAM-MD5 SASL host: %v", err)
	}
}

func replaceSASLCRAMMD5UserPassword(
	t *testing.T,
	store storage.Store,
	password []byte,
) {
	t.Helper()
	userDN, err := directory.ParseDN(
		"uid=alice,ou=people,dc=example,dc=com",
	)
	if err != nil {
		t.Fatalf("parse user DN: %v", err)
	}
	if err := store.Update(context.Background(), func(
		writer storage.Writer,
	) error {
		entry, err := writer.Get(userDN)
		if err != nil {
			return err
		}
		entry.ReplaceValues("userPassword", [][]byte{password})
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("replace CRAM-MD5 user password: %v", err)
	}
}

func dialAndBindSASLCRAMMD5(
	address string,
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
		saslMechanism:      "CRAM-MD5",
		authenticationID:   authenticationID,
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

func saslCRAMMD5Response(
	authenticationID string,
	password []byte,
	challenge []byte,
) []byte {
	mac := hmac.New(md5.New, password)
	_, _ = mac.Write(challenge)
	digest := make([]byte, hex.EncodedLen(md5.Size))
	hex.Encode(digest, mac.Sum(nil))
	response := make([]byte, 0, len(authenticationID)+1+len(digest))
	response = append(response, authenticationID...)
	response = append(response, ' ')
	return append(response, digest...)
}
