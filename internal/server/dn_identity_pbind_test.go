package server

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDNIdentityPBindOverlay(t *testing.T) {
	providerTLS := testServerTLSConfig(t)
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	dnIdentityBindEntryImport(t, providerStore, "0", dnIdentityBindEntryConfigLDIF, true)
	dnIdentityBindEntryImport(t, providerStore, "1", dnIdentityBindEntryUpperContentLDIF, false)
	dnIdentityBindEntryImport(t, providerStore, "2", dnIdentityBindEntryLowerContentLDIF, false)
	providerAddress, stopProvider := startServer(
		t,
		providerStore,
		Config{TLSConfig: providerTLS},
	)
	t.Cleanup(stopProvider)

	_, providerPort, err := net.SplitHostPort(providerAddress)
	if err != nil {
		t.Fatalf("SplitHostPort(provider): %v", err)
	}
	deadProvider := dnIdentityPBindClosedAddress(t)
	certificatePath := writePBindTestCertificate(
		t,
		providerTLS.Certificates[0].Certificate[0],
	)
	providers := "ldap://" + deadProvider + " ldap://localhost:" + providerPort
	startTLS := "start tls_cacert=" + certificatePath +
		" tls_reqcert=demand tls_reqsan=demand"

	for _, backend := range []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{name: "memory", open: func(*testing.T) storage.Store { return storage.NewMemory() }},
		{name: "bolt", open: func(t *testing.T) storage.Store {
			store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	} {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			consumerStore := backend.open(t)
			t.Cleanup(func() { _ = consumerStore.Close() })
			dnIdentityBindEntryImport(
				t,
				consumerStore,
				"0",
				dnIdentityBindEntryConfigLDIF,
				true,
			)
			seedDNIdentityPBindOverlay(
				t,
				consumerStore,
				providers,
				startTLS,
			)

			consumerAddress, instance, stopConsumer :=
				startDNIdentityBindEntryServer(t, consumerStore)
			t.Cleanup(stopConsumer)
			runtime := instance.runtime.Load()

			const equivalentUpperUser = "1.3.6.1.4.1.99999.950.2=PRIMARY TEAM+" +
				"bindExactAlias=Alice,OU=PEOPLE,bindExactAlias=Tenant," +
				"DC=EXAMPLE,DC=COM"
			canonical, err := runtime.schema.NormalizeDN(equivalentUpperUser)
			if err != nil {
				t.Fatalf("NormalizeDN(equivalent user): %v", err)
			}
			database := databaseForDN(runtime, canonical)
			if database == nil || database.pbind == nil {
				t.Fatal("schema-equivalent Bind did not route to the pbind database")
			}
			wireRequest, failure := preparePBindRequest(
				runtime,
				*database.pbind,
				ldapwire.BindRequest{Name: equivalentUpperUser},
			)
			if failure != nil {
				t.Fatalf("preparePBindRequest() = %#v", *failure)
			}
			if wireRequest.Name != canonical.String() ||
				strings.Contains(wireRequest.Name, "1.3.6.1.4.1.99999.950") ||
				strings.Contains(strings.ToLower(wireRequest.Name), "alias") {
				t.Fatalf(
					"provider wire DN = %q, want canonical %q",
					wireRequest.Name,
					canonical.String(),
				)
			}
			if len(database.pbind.providerKeys) != 2 ||
				database.pbind.providerKeys[0] == database.pbind.providerKeys[1] {
				t.Fatalf("pbind endpoint keys = %#v", database.pbind.providerKeys)
			}

			lowerSuffixTarget := strings.Replace(
				dnIdentityBindEntryLowerUser,
				dnIdentityBindEntryUpperBase,
				dnIdentityBindEntryLowerBase,
				1,
			)
			_, failure = preparePBindRequest(
				runtime,
				*database.pbind,
				ldapwire.BindRequest{Name: lowerSuffixTarget},
			)
			if failure == nil || failure.Code != ldapwire.ResultUnavailable {
				t.Fatalf("caseExact sibling database pbind result = %#v", failure)
			}

			failureClient, err := ldap.DialURL("ldap://" + consumerAddress)
			if err != nil {
				t.Fatalf("DialURL(failure client): %v", err)
			}
			err = failureClient.Bind(
				dnIdentityBindEntryLowerUser,
				"upper-user-secret",
			)
			_ = failureClient.Close()
			if err == nil {
				t.Fatal("pbind collapsed caseExact sibling credentials")
			}
			assertLDAPResultCode(t, err, ldap.LDAPResultInvalidCredentials)

			client, err := ldap.DialURL("ldap://" + consumerAddress)
			if err != nil {
				t.Fatalf("DialURL(success client): %v", err)
			}
			defer client.Close()
			if err := client.Bind(equivalentUpperUser, "upper-user-secret"); err != nil {
				t.Fatalf("schema-equivalent pbind over StartTLS with failover: %v", err)
			}
			identity, err := client.WhoAmI(nil)
			if err != nil {
				t.Fatalf("WhoAmI(): %v", err)
			}
			if !strings.HasPrefix(identity.AuthzID, "dn:") ||
				strings.Contains(identity.AuthzID, "1.3.6.1.4.1.99999.950") ||
				strings.Contains(strings.ToLower(identity.AuthzID), "alias") {
				t.Fatalf("successful pbind identity = %q", identity.AuthzID)
			}
			stateDN, err := runtime.schema.NormalizeDN(
				strings.TrimPrefix(identity.AuthzID, "dn:"),
			)
			if err != nil || !stateDN.Equal(canonical) {
				t.Fatalf(
					"successful pbind state DN = %q, %v; want %q",
					identity.AuthzID,
					err,
					canonical.String(),
				)
			}
			if database.pbind.health == nil || database.pbind.health.quarantined {
				t.Fatalf("successful failover quarantine state = %#v", database.pbind.health)
			}
		})
	}
}

func seedDNIdentityPBindOverlay(
	t *testing.T,
	store storage.Store,
	providers,
	startTLS string,
) {
	t.Helper()
	entry := directory.Entry{
		DN: "olcOverlay={0}pbind,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "olcOverlay", Values: stringValues("{0}pbind")},
			{Description: "olcDbURI", Values: stringValues(providers)},
			{Description: "olcDbStartTLS", Values: stringValues(startTLS)},
			{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
			{Description: "olcDbQuarantine", Values: stringValues("1s,1 2s,+")},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.PutIn(configurationStoragePartition, entry, false)
	}); err != nil {
		t.Fatalf("seed pbind overlay: %v", err)
	}
}

func dnIdentityPBindClosedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve unavailable pbind address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close unavailable pbind address: %v", err)
	}
	return address
}
