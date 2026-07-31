package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestResolveSyncConsumerGSSAPISettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      syncConsumerConfig
		environment map[string]string
		wantSource  syncConsumerGSSAPICredentialSource
		wantUser    string
		wantRealm   string
		wantSecret  string
		wantPath    string
		wantError   string
	}{
		{
			name: "password including empty value",
			config: syncConsumerConfig{
				credentialsSet:   true,
				authenticationID: "replicator@EXAMPLE.COM",
				authorizationID:  "dn:cn=sync,dc=example,dc=com",
			},
			environment: map[string]string{
				"KRB5_CONFIG":        "/run/krb5.conf",
				"KRB5_CLIENT_KTNAME": "FILE:/run/ignored.keytab",
			},
			wantSource: syncConsumerGSSAPIPassword,
			wantUser:   "replicator",
			wantRealm:  "EXAMPLE.COM",
		},
		{
			name: "client keytab",
			config: syncConsumerConfig{
				authenticationID: "replicator",
				realm:            "EXAMPLE.COM",
			},
			environment: map[string]string{
				"KRB5_CONFIG":        "/run/krb5.conf",
				"KRB5_CLIENT_KTNAME": "FILE:/run/client.keytab",
				"KRB5_KTNAME":        "FILE:/run/fallback.keytab",
			},
			wantSource: syncConsumerGSSAPIKeytab,
			wantUser:   "replicator",
			wantRealm:  "EXAMPLE.COM",
			wantPath:   "/run/client.keytab",
		},
		{
			name: "credential cache",
			config: syncConsumerConfig{
				authenticationID: "cache-principal-is-authoritative",
			},
			environment: map[string]string{
				"KRB5_CONFIG": "/run/krb5.conf",
				"KRB5CCNAME":  "FILE:/run/krb5cc_replication",
			},
			wantSource: syncConsumerGSSAPICCache,
			wantPath:   "/run/krb5cc_replication",
		},
		{
			name: "unsupported cache implementation",
			environment: map[string]string{
				"KRB5_CONFIG": "/run/krb5.conf",
				"KRB5CCNAME":  "KCM:1000",
			},
			wantError: "KCM",
		},
		{
			name: "keytab needs authcid",
			environment: map[string]string{
				"KRB5_CONFIG":        "/run/krb5.conf",
				"KRB5_CLIENT_KTNAME": "FILE:/run/client.keytab",
			},
			wantError: "require authcid",
		},
		{
			name: "conflicting realm",
			config: syncConsumerConfig{
				credentialsSet:   true,
				authenticationID: "replicator@ONE.EXAMPLE",
				realm:            "TWO.EXAMPLE",
			},
			environment: map[string]string{
				"KRB5_CONFIG": "/run/krb5.conf",
			},
			wantError: "conflicts",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			settings, err := resolveSyncConsumerGSSAPISettings(
				test.config,
				"ldaps://ldap.example.com:636",
				syncConsumerEnvironment(test.environment),
			)
			if test.wantError != "" {
				if err == nil ||
					!strings.Contains(err.Error(), test.wantError) {
					t.Fatalf(
						"resolve settings error = %v, want %q",
						err,
						test.wantError,
					)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve settings: %v", err)
			}
			if settings.source != test.wantSource ||
				settings.username != test.wantUser ||
				settings.realm != test.wantRealm ||
				settings.password != test.wantSecret ||
				settings.credentialPath != test.wantPath {
				t.Fatalf("GSSAPI settings = %#v", settings)
			}
			if settings.configuration != "/run/krb5.conf" ||
				settings.servicePrincipal != "ldap/ldap.example.com" ||
				settings.authorizationID != test.config.authorizationID {
				t.Fatalf("GSSAPI target settings = %#v", settings)
			}
		})
	}
}

func TestParseSyncConsumerKerberosFileCredential(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value         string
		allowWritable bool
		want          string
		wantError     string
	}{
		{value: "/tmp/krb5cc_1000", want: "/tmp/krb5cc_1000"},
		{value: "FILE:/tmp/krb5cc_1000", want: "/tmp/krb5cc_1000"},
		{
			value:         "WRFILE:/tmp/client.keytab",
			allowWritable: true,
			want:          "/tmp/client.keytab",
		},
		{value: `C:\krb5\cache`, want: `C:\krb5\cache`},
		{value: "DIR:/tmp/cache", wantError: "unsupported"},
		{value: "FILE:", wantError: "empty"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.value, func(t *testing.T) {
			t.Parallel()
			got, err := parseSyncConsumerKerberosFileCredential(
				test.value,
				"KRB5_TEST",
				test.allowWritable,
			)
			if test.wantError != "" {
				if err == nil ||
					!strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("credential path error = %v", err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("credential path = %q, %v", got, err)
			}
		})
	}
}

func TestExecuteSyncConsumerGSSAPIBind(t *testing.T) {
	t.Parallel()

	settings := syncConsumerGSSAPISettings{
		servicePrincipal: "ldap/provider.example",
		authorizationID:  "dn:cn=sync,dc=example,dc=com",
	}
	client := &testSyncConsumerGSSAPIClient{}
	binder := &testSyncConsumerGSSAPIBinder{}
	err := executeSyncConsumerGSSAPIBind(
		binder,
		settings,
		func(got syncConsumerGSSAPISettings) (
			syncConsumerGSSAPIClient,
			error,
		) {
			if got != settings {
				t.Fatalf("factory settings = %#v", got)
			}
			return client, nil
		},
	)
	if err != nil {
		t.Fatalf("execute GSSAPI bind: %v", err)
	}
	if binder.client != client ||
		binder.servicePrincipal != settings.servicePrincipal ||
		binder.authorizationID != settings.authorizationID ||
		!client.closed {
		t.Fatalf("GSSAPI bind state = %#v / %#v", binder, client)
	}

	bindFailure := errors.New("bind failed")
	failedClient := &testSyncConsumerGSSAPIClient{}
	err = executeSyncConsumerGSSAPIBind(
		&testSyncConsumerGSSAPIBinder{err: bindFailure},
		settings,
		func(syncConsumerGSSAPISettings) (
			syncConsumerGSSAPIClient,
			error,
		) {
			return failedClient, nil
		},
	)
	if !errors.Is(err, bindFailure) || !failedClient.closed {
		t.Fatalf("failed GSSAPI bind = %v, client %#v", err, failedClient)
	}
}

func syncConsumerEnvironment(
	values map[string]string,
) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

type testSyncConsumerGSSAPIClient struct {
	closed bool
}

func (*testSyncConsumerGSSAPIClient) InitSecContext(
	string,
	[]byte,
) ([]byte, bool, error) {
	return nil, false, nil
}

func (*testSyncConsumerGSSAPIClient) InitSecContextWithOptions(
	string,
	[]byte,
	[]int,
) ([]byte, bool, error) {
	return nil, false, nil
}

func (*testSyncConsumerGSSAPIClient) NegotiateSaslAuth(
	[]byte,
	string,
) ([]byte, error) {
	return nil, nil
}

func (*testSyncConsumerGSSAPIClient) DeleteSecContext() error {
	return nil
}

func (client *testSyncConsumerGSSAPIClient) Close() error {
	client.closed = true
	return nil
}

type testSyncConsumerGSSAPIBinder struct {
	client           ldap.GSSAPIClient
	servicePrincipal string
	authorizationID  string
	err              error
}

func (binder *testSyncConsumerGSSAPIBinder) GSSAPIBind(
	client ldap.GSSAPIClient,
	servicePrincipal string,
	authorizationID string,
) error {
	binder.client = client
	binder.servicePrincipal = servicePrincipal
	binder.authorizationID = authorizationID
	return binder.err
}
