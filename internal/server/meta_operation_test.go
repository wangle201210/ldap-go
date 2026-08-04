package server

import (
	"context"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	metaOperationLocalSuffix   = "dc=meta,dc=test"
	metaOperationLocalPeople   = "ou=people," + metaOperationLocalSuffix
	metaOperationLocalUser     = "uid=alice," + metaOperationLocalPeople
	metaOperationDatabaseDN    = "olcDatabase={1}meta,cn=config"
	metaOperationLocalRootDN   = "cn=admin," + metaOperationLocalSuffix
	metaOperationLocalRootPass = "meta-root-secret"
)

func TestMetaBackendRealTopologyUserBindAndWrite(t *testing.T) {
	providerStore := storage.NewMemory()
	t.Cleanup(func() { _ = providerStore.Close() })
	seedLDAPBackendProvider(t, providerStore)
	providerAddress, stopProvider := startServer(t, providerStore, Config{
		RootDN:       ldapBackendTestAdminDN,
		RootPassword: []byte(ldapBackendTestAdminSecret),
	})
	defer stopProvider()

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedMetaOperationProxy(t, proxyStore, providerAddress)
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{})
	defer stopProxy()

	client := dialLDAPBackendClient(t, proxyAddress)
	defer client.Close()
	if err := client.Bind(metaOperationLocalUser, ldapBackendTestUserPassword); err != nil {
		t.Fatalf("Bind(back-meta mapped user): %v", err)
	}
	search, err := client.Search(ldap.NewSearchRequest(
		metaOperationLocalUser,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=alice)",
		[]string{"uid", "description"},
		nil,
	))
	if err != nil || len(search.Entries) != 1 ||
		search.Entries[0].DN != metaOperationLocalUser {
		t.Fatalf("Search(back-meta mapped user) = %#v, %v", search, err)
	}
	modify := ldap.NewModifyRequest(metaOperationLocalUser, nil)
	modify.Replace("description", []string{"written-through-meta"})
	modify.Replace("seeAlso", []string{"uid=bob," + metaOperationLocalPeople})
	if err := client.Modify(modify); err != nil {
		t.Fatalf("Modify(back-meta mapped user): %v", err)
	}
	mapped, err := client.Search(ldap.NewSearchRequest(
		metaOperationLocalUser,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(seeAlso=uid=bob,"+metaOperationLocalPeople+")",
		[]string{"seeAlso"},
		nil,
	))
	if err != nil || len(mapped.Entries) != 1 ||
		mapped.Entries[0].GetAttributeValue("seeAlso") != "uid=bob,"+metaOperationLocalPeople {
		t.Fatalf("mapped DN-valued Search = %#v, %v", mapped, err)
	}

	provider := dialLDAPBackendClient(t, providerAddress)
	defer provider.Close()
	if err := provider.Bind(ldapBackendTestAdminDN, ldapBackendTestAdminSecret); err != nil {
		t.Fatalf("Bind(provider root): %v", err)
	}
	remote, err := provider.Search(ldap.NewSearchRequest(
		ldapBackendTestUserDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"description", "seeAlso"},
		nil,
	))
	if err != nil || len(remote.Entries) != 1 ||
		remote.Entries[0].GetAttributeValue("description") != "written-through-meta" ||
		remote.Entries[0].GetAttributeValue("seeAlso") != "uid=bob,"+ldapBackendTestPeopleDN {
		t.Fatalf("provider state after back-meta Modify = %#v, %v", remote, err)
	}
}

func TestMetaModifyDNUsesSingleTarget(t *testing.T) {
	configuration := &metaBackendRuntimeConfiguration{
		targets: []metaBackendTargetRuntimeConfiguration{
			{
				configDNKey: "olcmetasub={0}uri," + metaOperationDatabaseDN,
				suffix:      mustMetaBackendDN(t, metaOperationLocalSuffix),
			},
			{
				configDNKey: "olcmetasub={1}uri," + metaOperationDatabaseDN,
				suffix:      mustMetaBackendDN(t, "ou=team,"+metaOperationLocalSuffix),
			},
		},
		defaultTarget: metaBackendNoDefaultTarget,
	}
	broad, ok := configuration.targetForDN(mustMetaBackendDN(
		t,
		"uid=user,ou=people,"+metaOperationLocalSuffix,
	))
	if !ok {
		t.Fatal("broad back-meta target was not selected")
	}
	if !metaModifyDNUsesTarget(configuration, *broad, ldapwire.ModifyDNRequest{
		DN:           "uid=user,ou=people," + metaOperationLocalSuffix,
		NewRDN:       "uid=renamed",
		DeleteOldRDN: true,
	}) {
		t.Fatal("same-target ModifyDN was rejected")
	}
	if metaModifyDNUsesTarget(configuration, *broad, ldapwire.ModifyDNRequest{
		DN:             "uid=user,ou=people," + metaOperationLocalSuffix,
		NewRDN:         "uid=user",
		DeleteOldRDN:   true,
		NewSuperior:    "ou=team," + metaOperationLocalSuffix,
		HasNewSuperior: true,
	}) {
		t.Fatal("cross-target ModifyDN was accepted")
	}
}

func TestMetaBackendRemotePreference(t *testing.T) {
	target := metaBackendTargetRuntimeConfiguration{preferred: &proxyPreferredRemoteState{}}
	if got := metaBackendRemoteOrder(target, 3); !equalInts(got, []int{0, 1, 2}) {
		t.Fatalf("initial order = %v", got)
	}
	rememberMetaBackendRemote(target, 2)
	if got := metaBackendRemoteOrder(target, 3); !equalInts(got, []int{2, 0, 1}) {
		t.Fatalf("promoted order = %v", got)
	}
	other := metaBackendTargetRuntimeConfiguration{preferred: &proxyPreferredRemoteState{}}
	if got := metaBackendRemoteOrder(other, 2); !equalInts(got, []int{0, 1}) {
		t.Fatalf("independent target order = %v", got)
	}
	if got := metaBackendRemoteOrder(target, 2); !equalInts(got, []int{0, 1}) {
		t.Fatalf("stale preferred index was not ignored: %v", got)
	}
}

func TestMetaBackendRemoteRetryBudget(t *testing.T) {
	tests := []struct {
		name       string
		attempt    chainAttempt
		bind       bool
		preReplay  bool
		wantRetry  bool
		wantReplay bool
	}{
		{
			name:      "connection failure traverses URI list",
			attempt:   chainAttempt{transportErr: context.DeadlineExceeded},
			wantRetry: true,
		},
		{
			name:       "sent operation replays once",
			attempt:    chainAttempt{requestSent: true, transportErr: context.DeadlineExceeded},
			wantRetry:  true,
			wantReplay: true,
		},
		{
			name:      "sent bind is not replayed",
			attempt:   chainAttempt{requestSent: true, transportErr: context.DeadlineExceeded},
			bind:      true,
			wantRetry: false,
		},
		{
			name: "remote unavailable replays once",
			attempt: chainAttempt{
				hasResult: true,
				result:    ldapwire.Result{Code: ldapwire.ResultUnavailable},
			},
			wantRetry:  true,
			wantReplay: true,
		},
		{
			name:      "replay budget exhausted",
			attempt:   chainAttempt{requestSent: true, transportErr: context.DeadlineExceeded},
			preReplay: true,
		},
		{
			name: "partial search is not replayed",
			attempt: chainAttempt{
				requestSent:  true,
				transportErr: context.DeadlineExceeded,
				packets:      []*ber.Packet{ber.NewSequence("entry")},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			replayed := test.preReplay
			retry, replay := metaBackendShouldRetryRemote(
				context.Background(),
				test.attempt,
				test.bind,
				&replayed,
			)
			if retry != test.wantRetry || replay != test.wantReplay {
				t.Fatalf("decision = retry=%t replay=%t", retry, replay)
			}
		})
	}
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func seedMetaOperationProxy(t *testing.T, store storage.Store, providerAddress string) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
			},
		},
		{
			DN: "olcDatabase={0}config,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{0}config")},
				{Description: "olcRootDN", Values: stringValues("cn=config")},
				{Description: "olcRootPW", Values: stringValues("config-secret")},
			},
		},
		{
			DN: metaOperationDatabaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcMetaConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}meta")},
				{Description: "olcSuffix", Values: stringValues(metaOperationLocalSuffix)},
				{Description: "olcRootDN", Values: stringValues(metaOperationLocalRootDN)},
				{Description: "olcRootPW", Values: stringValues(metaOperationLocalRootPass)},
				{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
			},
		},
		{
			DN: "olcMetaSub={0}uri," + metaOperationDatabaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcMetaTargetConfig")},
				{Description: "olcMetaSub", Values: stringValues("{0}uri")},
				{Description: "olcDbURI", Values: stringValues(
					"ldap://" + providerAddress + "/" + metaOperationLocalSuffix,
				)},
				{Description: "olcDbRewrite", Values: stringValues(
					`suffixmassage "` + metaOperationLocalSuffix + `" "` + ldapBackendTestSuffix + `"`,
				)},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{metaOperationLocalSuffix, "cn=config"})
	}); err != nil {
		t.Fatalf("seed back-meta operation proxy: %v", err)
	}
}
