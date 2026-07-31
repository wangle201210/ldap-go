package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientSASLPlainBind(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSASLPlainConfiguration(t, store, "none")

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
	if err != nil || len(rootDSE.Entries) != 1 ||
		!containsString(
			rootDSE.Entries[0].GetAttributeValues(
				"supportedSASLMechanisms",
			),
			"PLAIN",
		) {
		t.Fatalf("PLAIN Root DSE = %#v, %v", rootDSE, err)
	}

	raw, err := dialAndBindSASLPlain(
		address,
		"u:alice",
		"alice",
		"secret",
	)
	if err != nil {
		t.Fatalf("PLAIN Bind: %v", err)
	}
	client := ldap.NewConn(raw, false)
	client.Start()
	defer client.Close()
	identity, err := client.WhoAmI(nil)
	if err != nil ||
		identity.AuthzID !=
			"dn:uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("PLAIN WhoAmI = %#v, %v", identity, err)
	}

	raw, err = dialAndBindSASLPlain(
		address,
		"",
		"alice",
		"wrong-password",
	)
	if raw != nil {
		_ = raw.Close()
	}
	assertWrappedLDAPResultCode(
		t,
		err,
		ldap.LDAPResultInvalidCredentials,
	)

	raw, err = dialAndBindSASLPlain(
		address,
		"dn:uid=someone,ou=people,dc=example,dc=com",
		"alice",
		"secret",
	)
	if raw != nil {
		_ = raw.Close()
	}
	assertWrappedLDAPResultCode(
		t,
		err,
		ldap.LDAPResultInappropriateAuthentication,
	)
}

func TestOpenLDAPClientSASLPlainBind(t *testing.T) {
	if os.Getenv(openLDAPReferenceTestsEnv) == "" {
		t.Skipf(
			"set %s=1 to run the OpenLDAP PLAIN interoperability test",
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
	seedSASLPlainConfiguration(t, store, "none")
	address, stop := startServer(t, store, Config{})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		ldapWhoAmI,
		"-Y",
		"PLAIN",
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
		if strings.Contains(
			strings.ToLower(string(output)),
			"no worthy mechs",
		) {
			t.Skip("OpenLDAP Cyrus SASL installation has no PLAIN plugin")
		}
		t.Fatalf("ldapwhoami PLAIN: %v\n%s", err, output)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 ||
		lines[len(lines)-1] !=
			"dn:uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("ldapwhoami PLAIN output = %q", output)
	}
}

func TestSASLPlainDefaultPolicyRequiresProtectedTransport(t *testing.T) {
	t.Parallel()

	properties := defaultSASLSecurityProperties()
	failure := saslMechanismPolicyFailure(properties, "PLAIN", 0)
	if failure == nil ||
		failure.Code != ldapwire.ResultConfidentialityRequired {
		t.Fatalf("plaintext PLAIN policy = %#v", failure)
	}
	if failure := saslMechanismPolicyFailure(
		properties,
		"PLAIN",
		128,
	); failure != nil {
		t.Fatalf("TLS PLAIN policy = %#v", failure)
	}
}

func TestSASLPlainBindWithoutInitialResponse(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSASLPlainConfiguration(t, store, "none")

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial PLAIN server: %v", err)
	}
	defer connection.Close()
	transport := &syncConsumerTransport{
		connection:       connection,
		context:          context.Background(),
		operationTimeout: 2 * time.Second,
	}
	first, err := sendSyncConsumerSASLBind(
		transport,
		"PLAIN",
		nil,
		false,
	)
	if err != nil ||
		first.code != ldap.LDAPResultSaslBindInProgress ||
		!first.hasSASLCredentials ||
		len(first.saslCredentials) != 0 {
		t.Fatalf("empty PLAIN initial result = %#v, %v", first, err)
	}
	final, err := sendSyncConsumerSASLBind(
		transport,
		"PLAIN",
		[]byte("\x00alice\x00secret"),
		true,
	)
	if err != nil || final.code != ldap.LDAPResultSuccess {
		t.Fatalf("continued PLAIN result = %#v, %v", final, err)
	}
}

func TestLDAPClientSASLPlainBindOverTLSWithDefaultPolicy(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	seedSASLPlainConfiguration(t, store, "noplain,noanonymous")

	address, stop := startServer(t, store, Config{
		TLSConfig:   testServerTLSConfig(t),
		ImplicitTLS: true,
	})
	defer stop()
	connection, err := tls.Dial(
		"tcp",
		address,
		&tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	)
	if err != nil {
		t.Fatalf("dial TLS: %v", err)
	}
	if err := bindSASLPlainConnection(
		connection,
		"",
		"alice",
		"secret",
	); err != nil {
		_ = connection.Close()
		t.Fatalf("TLS PLAIN Bind: %v", err)
	}
	client := ldap.NewConn(connection, true)
	client.Start()
	defer client.Close()
	identity, err := client.WhoAmI(nil)
	if err != nil ||
		identity.AuthzID !=
			"dn:uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("TLS PLAIN WhoAmI = %#v, %v", identity, err)
	}
}

func TestLDAPClientSASLPlainRootProxyAuthorization(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	dataConfigDN, err := directory.ParseDN(
		"olcDatabase={1}mdb,cn=config",
	)
	if err != nil {
		t.Fatalf("parse database configuration DN: %v", err)
	}
	if err := store.Update(context.Background(), func(
		writer storage.Writer,
	) error {
		entry, err := writer.Get(dataConfigDN)
		if err != nil {
			return err
		}
		entry.ReplaceValues(
			"olcRootDN",
			stringValues("cn=admin,dc=example,dc=com"),
		)
		entry.ReplaceValues(
			"olcRootPW",
			stringValues("root-secret"),
		)
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure database root: %v", err)
	}
	seedSASLConfiguration(t, store, "none",
		`{0}^uid=admin,cn=plain,cn=auth$ `+
			`cn=admin,dc=example,dc=com`,
	)

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection, err := dialAndBindSASLPlain(
		address,
		"dn:uid=alice,ou=people,dc=example,dc=com",
		"admin",
		"root-secret",
	)
	if err != nil {
		t.Fatalf("root proxy PLAIN Bind: %v", err)
	}
	client := ldap.NewConn(connection, false)
	client.Start()
	defer client.Close()
	identity, err := client.WhoAmI(nil)
	if err != nil ||
		identity.AuthzID !=
			"dn:uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("root proxy PLAIN WhoAmI = %#v, %v", identity, err)
	}
}

func TestLDAPClientSASLPlainBindWithURLMapping(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	dataConfigDN, err := directory.ParseDN(
		"olcDatabase={1}mdb,cn=config",
	)
	if err != nil {
		t.Fatalf("parse database configuration DN: %v", err)
	}
	if err := store.Update(context.Background(), func(
		writer storage.Writer,
	) error {
		entry, err := writer.Get(dataConfigDN)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccess", stringValues(
			"{0}to attrs=entry,uid by anonymous auth by * none",
			"{1}to attrs=userPassword by anonymous auth by self =xw by * none",
			"{2}to * by self write by users read by * none",
		))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure URL mapping ACL: %v", err)
	}
	seedSASLConfiguration(t, store, "none",
		`{0}^uid=([^,]+),cn=plain,cn=auth$ `+
			`ldap:///ou=people,dc=example,dc=com??one?(uid=$1)`,
	)

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection, err := dialAndBindSASLPlain(
		address,
		"",
		"alice",
		"secret",
	)
	if err != nil {
		t.Fatalf("PLAIN Bind with LDAP URL mapping: %v", err)
	}
	client := ldap.NewConn(connection, false)
	client.Start()
	defer client.Close()
	identity, err := client.WhoAmI(nil)
	if err != nil ||
		identity.AuthzID !=
			"dn:uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("URL-mapped PLAIN WhoAmI = %#v, %v", identity, err)
	}
}

func TestSASLPlainURLMappingRequiresAuthAccessToSearchBase(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	dataConfigDN, err := directory.ParseDN(
		"olcDatabase={1}mdb,cn=config",
	)
	if err != nil {
		t.Fatalf("parse database configuration DN: %v", err)
	}
	if err := store.Update(context.Background(), func(
		writer storage.Writer,
	) error {
		entry, err := writer.Get(dataConfigDN)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcAccess", stringValues(
			`{0}to dn.exact="uid=alice,ou=people,dc=example,dc=com" `+
				`attrs=entry,uid by anonymous auth by * none`,
			"{1}to attrs=userPassword by anonymous auth by self =xw by * none",
			"{2}to * by self write by users read by * none",
		))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure URL mapping ACL: %v", err)
	}
	seedSASLConfiguration(t, store, "none",
		`{0}^uid=([^,]+),cn=plain,cn=auth$ `+
			`ldap:///ou=people,dc=example,dc=com??one?(uid=$1)`,
	)

	address, stop := startServer(t, store, Config{})
	defer stop()
	connection, err := dialAndBindSASLPlain(
		address,
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

func TestLoadSASLRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entry := directory.Entry{
		DN: "cn=config",
		Attributes: []directory.Attribute{
			{
				Description: "olcSaslHost",
				Values:      stringValues("ldap.example.com"),
			},
			{
				Description: "olcSaslRealm",
				Values:      stringValues("example.com"),
			},
			{
				Description: "olcSaslSecProps",
				Values: stringValues(
					"none,noanonymous,minssf=64,maxssf=128",
				),
			},
			{
				Description: "olcAuthzRegexp",
				Values: stringValues(
					`{1}^uid=([^,]+),cn=plain,cn=auth$ `+
						`uid=$1,ou=fallback,dc=example,dc=com`,
					`{0}^UID=([^,]+),CN=EXAMPLE.COM,CN=PLAIN,CN=AUTH$ `+
						`uid=$1,ou=people,dc=example,dc=com`,
				),
			},
		},
	}
	if err := store.Update(context.Background(), func(
		writer storage.Writer,
	) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed SASL configuration: %v", err)
	}

	var configuration saslRuntimeConfiguration
	if err := store.View(context.Background(), func(
		reader storage.Reader,
	) error {
		var err error
		configuration, err = loadSASLRuntimeConfiguration(reader)
		return err
	}); err != nil {
		t.Fatalf("load SASL configuration: %v", err)
	}
	if configuration.host != "ldap.example.com" ||
		configuration.realm != "example.com" ||
		configuration.securityProperties.noPlain ||
		!configuration.securityProperties.noAnonymous ||
		configuration.securityProperties.minSSF != 64 ||
		configuration.securityProperties.maxSSF != 128 ||
		len(configuration.authzRegexps) != 2 ||
		configuration.authzRegexps[0].order != 0 {
		t.Fatalf("SASL configuration = %#v", configuration)
	}
	instance := &Server{config: Config{Store: store}}
	mapped, err := instance.saslAuthenticationDN(
		context.Background(),
		&runtimeState{sasl: configuration},
		"PLAIN",
		"Alice",
	)
	if err != nil ||
		mapped.String() != "uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("mapped SASL DN = %q, %v", mapped.String(), err)
	}
}

func TestLoadSASLRuntimeConfigurationRejectsMixedOrderValues(
	t *testing.T,
) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entry := directory.Entry{
		DN: "cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcAuthzRegexp",
			Values: stringValues(
				`{0}^uid=one,cn=plain,cn=auth$ uid=one,dc=example`,
				`^uid=two,cn=plain,cn=auth$ uid=two,dc=example`,
			),
		}},
	}
	if err := store.Update(context.Background(), func(
		writer storage.Writer,
	) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed SASL configuration: %v", err)
	}

	err := store.View(context.Background(), func(
		reader storage.Reader,
	) error {
		_, err := loadSASLRuntimeConfiguration(reader)
		return err
	})
	if err == nil ||
		!strings.Contains(err.Error(), "mixes indexed and unindexed") {
		t.Fatalf("mixed olcAuthzRegexp error = %v", err)
	}
}

func TestParseSASLPlainCredentials(t *testing.T) {
	t.Parallel()

	authzID, authcID, password, ok := parseSASLPlainCredentials(
		[]byte("u:alice\x00alice\x00secret"),
	)
	if !ok ||
		authzID != "u:alice" ||
		authcID != "alice" ||
		password != "secret" {
		t.Fatalf(
			"PLAIN credentials = %q/%q/%q/%t",
			authzID,
			authcID,
			password,
			ok,
		)
	}
	for _, malformed := range [][]byte{
		[]byte("alice\x00secret"),
		[]byte("\x00alice\x00secret\x00extra"),
		{0, 0xff, 0},
	} {
		if _, _, _, valid := parseSASLPlainCredentials(malformed); valid {
			t.Fatalf("accepted malformed PLAIN credentials %q", malformed)
		}
	}
}

func seedSASLPlainConfiguration(
	t *testing.T,
	store storage.Store,
	securityProperties string,
) {
	t.Helper()
	seedSASLConfiguration(
		t,
		store,
		securityProperties,
		`{0}^uid=([^,]+),cn=plain,cn=auth$ `+
			`uid=$1,ou=people,dc=example,dc=com`,
	)
}

func seedSASLConfiguration(
	t *testing.T,
	store storage.Store,
	securityProperties string,
	authzRegexp string,
) {
	t.Helper()
	entry := directory.Entry{
		DN: "cn=config",
		Attributes: []directory.Attribute{
			{
				Description: "olcSaslSecProps",
				Values:      stringValues(securityProperties),
			},
			{
				Description: "olcAuthzRegexp",
				Values:      stringValues(authzRegexp),
			},
		},
	}
	if err := store.Update(context.Background(), func(
		writer storage.Writer,
	) error {
		return writer.Put(entry, false)
	}); err != nil {
		t.Fatalf("seed PLAIN SASL configuration: %v", err)
	}
}

func dialAndBindSASLPlain(
	address string,
	authorizationID string,
	authenticationID string,
	password string,
) (net.Conn, error) {
	connection, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return nil, err
	}
	err = bindSASLPlainConnection(
		connection,
		authorizationID,
		authenticationID,
		password,
	)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	return connection, nil
}

func bindSASLPlainConnection(
	connection net.Conn,
	authorizationID string,
	authenticationID string,
	password string,
) error {
	properties, err := parseSASLSecurityProperties("none")
	if err != nil {
		return err
	}
	transport := &syncConsumerTransport{
		connection:       connection,
		context:          context.Background(),
		operationTimeout: 2 * time.Second,
	}
	err = bindSyncConsumerSASL(transport, syncConsumerConfig{
		saslMechanism:      "PLAIN",
		authenticationID:   authenticationID,
		authorizationID:    authorizationID,
		credentials:        []byte(password),
		securityProperties: properties,
	})
	if err != nil {
		return err
	}
	if err := transport.clearDeadline(); err != nil {
		return err
	}
	return nil
}

func assertWrappedLDAPResultCode(
	t *testing.T,
	err error,
	want uint16,
) {
	t.Helper()
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) ||
		ldapError.ResultCode != want {
		t.Fatalf("LDAP error = %v, want result code %d", err, want)
	}
}
