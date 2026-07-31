package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientSASLDigestMD5Bind(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSASLDigestMD5Configuration(t, store)

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
			"DIGEST-MD5",
		) {
		t.Fatalf("DIGEST-MD5 Root DSE = %#v, %v", rootDSE, err)
	}

	client, err := dialAndBindSASLDigestMD5(
		address,
		"alice",
		"secret",
	)
	if err != nil {
		t.Fatalf("DIGEST-MD5 Bind: %v", err)
	}
	identity, err := client.WhoAmI(nil)
	_ = client.Close()
	if err != nil ||
		identity.AuthzID !=
			"dn:uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("DIGEST-MD5 WhoAmI = %#v, %v", identity, err)
	}

	client, err = dialAndBindSASLDigestMD5(
		address,
		"alice",
		"wrong-password",
	)
	if client != nil {
		client.Close()
	}
	assertLDAPResultCode(t, err, ldap.LDAPResultInvalidCredentials)
}

func TestSASLDigestMD5RFC2831Vector(t *testing.T) {
	t.Parallel()

	response := saslDigestMD5Response{
		username:   "chris",
		realm:      "elwood.innosoft.com",
		nonce:      "OA6MG9tEQGm2hh",
		cnonce:     "OA6MHXh6VqTrRk",
		nonceCount: 1,
		qop:        "auth",
		digestURI:  "imap/elwood.innosoft.com",
	}
	secret := calculateSASLDigestMD5Secret(
		response.username,
		response.realm,
		[]byte("secret"),
		false,
	)
	defer clear(secret)
	got, rspauth := calculateSASLDigestMD5Exchange(secret, response)
	if got != "d388dad90d4bbd760a152321f2143af7" {
		t.Fatalf("RFC 2831 response = %q", got)
	}
	if rspauth != "ea40f60335c427b5527b84dbabcdfffd" {
		t.Fatalf("RFC 2831 rspauth = %q", rspauth)
	}
}

func TestSASLDigestMD5ChallengeAndSuccessData(t *testing.T) {
	t.Parallel()

	runtime := &runtimeState{sasl: saslRuntimeConfiguration{
		host:  "ldap.example.test",
		realm: "example.com",
		securityProperties: saslSecurityProperties{
			maxBufferSize: 65536,
		},
	}}
	deterministic, err := newSASLDigestMD5Session(
		runtime,
		bytes.NewReader(make([]byte, saslDigestMD5NonceSize)),
	)
	if err != nil {
		t.Fatalf("create deterministic DIGEST-MD5 session: %v", err)
	}
	challenge, err := parseSASLDigestMD5Directives(
		deterministic.challenge,
	)
	if err != nil ||
		challenge["nonce"] !=
			"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ||
		challenge["realm"] != "example.com" ||
		challenge["qop"] != "auth" ||
		challenge["maxbuf"] != "65536" ||
		challenge["charset"] != "utf-8" ||
		challenge["algorithm"] != "md5-sess" {
		t.Fatalf("DIGEST-MD5 challenge = %#v, %v", challenge, err)
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSASLDigestMD5Configuration(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial DIGEST-MD5 server: %v", err)
	}
	defer connection.Close()
	transport := &syncConsumerTransport{
		connection:       connection,
		context:          context.Background(),
		operationTimeout: 2 * time.Second,
	}
	first, err := sendSyncConsumerSASLBind(
		transport,
		"DIGEST-MD5",
		[]byte("ignored fast-reauth attempt"),
		true,
	)
	if err != nil ||
		first.code != ldap.LDAPResultSaslBindInProgress ||
		!first.hasSASLCredentials {
		t.Fatalf("DIGEST-MD5 first result = %#v, %v", first, err)
	}
	directives, err := parseSASLDigestMD5Directives(
		first.saslCredentials,
	)
	if err != nil {
		t.Fatalf("parse DIGEST-MD5 challenge: %v", err)
	}
	response := saslDigestMD5Response{
		username:   "alice",
		realm:      directives["realm"],
		nonce:      directives["nonce"],
		cnonce:     "fixed-client-nonce",
		nonceCount: 1,
		qop:        "auth",
		digestURI:  "ldap/ldap.example.test",
	}
	secret := calculateSASLDigestMD5Secret(
		response.username,
		response.realm,
		[]byte("secret"),
		true,
	)
	digest, rspauth := calculateSASLDigestMD5Exchange(
		secret,
		response,
	)
	clear(secret)
	final, err := sendSyncConsumerSASLBind(
		transport,
		"DIGEST-MD5",
		formatSASLDigestMD5Response(response, digest),
		true,
	)
	if err != nil ||
		final.code != ldap.LDAPResultSuccess ||
		!final.hasSASLCredentials ||
		string(final.saslCredentials) != "rspauth="+rspauth {
		t.Fatalf("DIGEST-MD5 final result = %#v, %v", final, err)
	}
	if err := transport.clearDeadline(); err != nil {
		t.Fatalf("clear DIGEST-MD5 deadline: %v", err)
	}
	client := ldap.NewConn(connection, false)
	client.Start()
	identity, err := client.WhoAmI(nil)
	if err != nil ||
		identity.AuthzID !=
			"dn:uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("DIGEST-MD5 raw WhoAmI = %#v, %v", identity, err)
	}
}

func TestSASLDigestMD5CredentialForms(t *testing.T) {
	t.Run("CLEARTEXT", func(t *testing.T) {
		t.Parallel()

		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedDirectory(t, store)
		replaceSASLDigestMD5UserPassword(
			t,
			store,
			[]byte("{CLEARTEXT}secret"),
		)
		seedSASLDigestMD5Configuration(t, store)
		address, stop := startServer(t, store, Config{})
		defer stop()

		client, err := dialAndBindSASLDigestMD5(
			address,
			"alice",
			"secret",
		)
		if err != nil {
			t.Fatalf("{CLEARTEXT} DIGEST-MD5 Bind: %v", err)
		}
		client.Close()
	})

	t.Run("SSHA", func(t *testing.T) {
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
			t.Fatalf("hash DIGEST-MD5 user password: %v", err)
		}
		replaceSASLDigestMD5UserPassword(t, store, hashed)
		seedSASLDigestMD5Configuration(t, store)
		address, stop := startServer(t, store, Config{})
		defer stop()

		client, err := dialAndBindSASLDigestMD5(
			address,
			"alice",
			"secret",
		)
		if client != nil {
			client.Close()
		}
		assertLDAPResultCode(
			t,
			err,
			ldap.LDAPResultInvalidCredentials,
		)
	})

	t.Run("cmusaslsecret", func(t *testing.T) {
		t.Parallel()

		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		seedDirectory(t, store)
		secret := calculateSASLDigestMD5Secret(
			"alice",
			"example.com",
			[]byte("secret"),
			true,
		)
		seedSASLDigestMD5PrecomputedSecret(t, store, secret)
		clear(secret)
		seedSASLDigestMD5Configuration(t, store)
		address, stop := startServer(t, store, Config{})
		defer stop()

		client, err := dialAndBindSASLDigestMD5(
			address,
			"alice",
			"secret",
		)
		if err != nil {
			t.Fatalf("precomputed DIGEST-MD5 Bind: %v", err)
		}
		client.Close()
	})
}

func TestSASLDigestMD5RequiresAuthAccess(t *testing.T) {
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
		t.Fatalf("deny DIGEST-MD5 auth access: %v", err)
	}
	seedSASLDigestMD5Configuration(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	client, err := dialAndBindSASLDigestMD5(
		address,
		"alice",
		"secret",
	)
	if client != nil {
		client.Close()
	}
	assertLDAPResultCode(t, err, ldap.LDAPResultInvalidCredentials)
}

func TestSASLDigestMD5RejectsProxyAuthorization(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSASLDigestMD5Configuration(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial DIGEST-MD5 proxy test: %v", err)
	}
	defer connection.Close()
	transport := &syncConsumerTransport{
		connection:       connection,
		context:          context.Background(),
		operationTimeout: 2 * time.Second,
	}
	first, err := sendSyncConsumerSASLBind(
		transport,
		"DIGEST-MD5",
		nil,
		false,
	)
	if err != nil ||
		first.code != ldap.LDAPResultSaslBindInProgress {
		t.Fatalf("DIGEST-MD5 proxy challenge = %#v, %v", first, err)
	}
	directives, err := parseSASLDigestMD5Directives(
		first.saslCredentials,
	)
	if err != nil {
		t.Fatalf("parse DIGEST-MD5 proxy challenge: %v", err)
	}
	response := saslDigestMD5Response{
		username:         "alice",
		realm:            directives["realm"],
		nonce:            directives["nonce"],
		cnonce:           "proxy-client-nonce",
		nonceCount:       1,
		qop:              "auth",
		digestURI:        "ldap/ldap.example.test",
		authorization:    "dn:uid=someone,ou=people,dc=example,dc=com",
		hasAuthorization: true,
	}
	secret := calculateSASLDigestMD5Secret(
		response.username,
		response.realm,
		[]byte("secret"),
		true,
	)
	digest, _ := calculateSASLDigestMD5Exchange(secret, response)
	clear(secret)
	final, err := sendSyncConsumerSASLBind(
		transport,
		"DIGEST-MD5",
		formatSASLDigestMD5Response(response, digest),
		true,
	)
	if err != nil ||
		final.code != ldap.LDAPResultInappropriateAuthentication {
		t.Fatalf("DIGEST-MD5 proxy result = %#v, %v", final, err)
	}
}

func TestParseSASLDigestMD5Directives(t *testing.T) {
	t.Parallel()

	directives, err := parseSASLDigestMD5Directives([]byte(
		" username=\"a\\\"b\" ,\r\n realm=\"c\\\\d\",qop=auth ",
	))
	if err != nil ||
		directives["username"] != `a"b` ||
		directives["realm"] != `c\d` ||
		directives["qop"] != "auth" {
		t.Fatalf("DIGEST-MD5 directives = %#v, %v", directives, err)
	}

	malformed := [][]byte{
		nil,
		[]byte(`username="alice",username="bob"`),
		[]byte(`username="alice`),
		[]byte(`username=`),
		[]byte(`username="alice"x`),
		[]byte(`username="alice",`),
		[]byte("username=\"alice\"\x00,qop=auth"),
	}
	for _, value := range malformed {
		if _, err := parseSASLDigestMD5Directives(value); err == nil {
			t.Fatalf("accepted malformed DIGEST-MD5 directives %q", value)
		}
	}

	session := &serverSASLDigestMD5Session{nonce: "server-nonce"}
	invalidQOP := []byte(
		`username="alice",nonce="server-nonce",cnonce="client",` +
			`nc=00000001,qop=auth-int,digest-uri="ldap/host",` +
			`response=00000000000000000000000000000000`,
	)
	if _, err := parseSASLDigestMD5Response(
		invalidQOP,
		session,
	); err == nil {
		t.Fatal("accepted unsupported DIGEST-MD5 auth-int qop")
	}
}

func TestSASLDigestMD5SecurityPolicy(t *testing.T) {
	t.Parallel()

	properties := defaultSASLSecurityProperties()
	if failure := saslMechanismPolicyFailure(
		properties,
		"DIGEST-MD5",
		0,
	); failure != nil {
		t.Fatalf("default DIGEST-MD5 policy = %#v", failure)
	}
	properties.noActive = true
	failure := saslMechanismPolicyFailure(
		properties,
		"DIGEST-MD5",
		0,
	)
	if failure == nil ||
		failure.Code != ldapwire.ResultAuthMethodNotSupported {
		t.Fatalf("noactive DIGEST-MD5 policy = %#v", failure)
	}
}

func TestOpenLDAPClientSASLDigestMD5Bind(t *testing.T) {
	if os.Getenv(openLDAPReferenceTestsEnv) == "" {
		t.Skipf(
			"set %s=1 to run the OpenLDAP DIGEST-MD5 interoperability test",
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
	seedSASLDigestMD5Configuration(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		ldapWhoAmI,
		"-Y",
		"DIGEST-MD5",
		"-U",
		"alice",
		"-R",
		"example.com",
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
			t.Skip("OpenLDAP Cyrus SASL installation has no DIGEST-MD5 plugin")
		}
		t.Fatalf("ldapwhoami DIGEST-MD5: %v\n%s", err, output)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 ||
		lines[len(lines)-1] !=
			"dn:uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("ldapwhoami DIGEST-MD5 output = %q", output)
	}
}

func seedSASLDigestMD5Configuration(
	t *testing.T,
	store storage.Store,
) {
	t.Helper()
	seedSASLConfiguration(
		t,
		store,
		"noplain,noanonymous",
		`{0}^uid=([^,]+),cn=example\.com,cn=digest-md5,cn=auth$ `+
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
		entry.ReplaceValues(
			"olcSaslRealm",
			stringValues("example.com"),
		)
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("seed DIGEST-MD5 SASL configuration: %v", err)
	}
}

func replaceSASLDigestMD5UserPassword(
	t *testing.T,
	store storage.Store,
	password []byte,
) {
	t.Helper()
	userDN, err := directory.ParseDN(
		"uid=alice,ou=people,dc=example,dc=com",
	)
	if err != nil {
		t.Fatalf("parse DIGEST-MD5 user DN: %v", err)
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
		t.Fatalf("replace DIGEST-MD5 user password: %v", err)
	}
}

func seedSASLDigestMD5PrecomputedSecret(
	t *testing.T,
	store storage.Store,
	secret []byte,
) {
	t.Helper()
	userDN, err := directory.ParseDN(
		"uid=alice,ou=people,dc=example,dc=com",
	)
	if err != nil {
		t.Fatalf("parse DIGEST-MD5 user DN: %v", err)
	}
	databaseDN, err := directory.ParseDN(
		"olcDatabase={1}mdb,cn=config",
	)
	if err != nil {
		t.Fatalf("parse DIGEST-MD5 database DN: %v", err)
	}
	if err := store.Update(context.Background(), func(
		writer storage.Writer,
	) error {
		user, err := writer.Get(userDN)
		if err != nil {
			return err
		}
		user.ReplaceValues("userPassword", nil)
		user.ReplaceValues(
			saslDigestMD5SecretAttribute,
			[][]byte{bytes.Clone(secret)},
		)
		if err := writer.Put(user, true); err != nil {
			return err
		}
		database, err := writer.Get(databaseDN)
		if err != nil {
			return err
		}
		database.ReplaceValues("olcAccess", stringValues(
			fmt.Sprintf(
				"{0}to attrs=userPassword,%s by anonymous auth by * none",
				saslDigestMD5SecretAttribute,
			),
			"{1}to * by self write by users read by * none",
		))
		return writer.Put(database, true)
	}); err != nil {
		t.Fatalf("seed precomputed DIGEST-MD5 secret: %v", err)
	}
}

func dialAndBindSASLDigestMD5(
	address string,
	username string,
	password string,
) (*ldap.Conn, error) {
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		return nil, err
	}
	_, err = client.DigestMD5Bind(&ldap.DigestMD5BindRequest{
		Host:     "ldap.example.test",
		Username: username,
		Password: password,
	})
	if err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

func formatSASLDigestMD5Response(
	response saslDigestMD5Response,
	digest string,
) []byte {
	var value strings.Builder
	fmt.Fprintf(
		&value,
		`username="%s",realm="%s",nonce="%s",cnonce="%s",`+
			`nc=%08x,qop=%s,digest-uri="%s",response=%s`,
		quoteSASLDigestMD5Value(response.username),
		quoteSASLDigestMD5Value(response.realm),
		quoteSASLDigestMD5Value(response.nonce),
		quoteSASLDigestMD5Value(response.cnonce),
		response.nonceCount,
		response.qop,
		quoteSASLDigestMD5Value(response.digestURI),
		digest,
	)
	if response.hasAuthorization {
		fmt.Fprintf(
			&value,
			`,authzid="%s"`,
			quoteSASLDigestMD5Value(response.authorization),
		)
	}
	value.WriteString(",charset=utf-8")
	return []byte(value.String())
}
