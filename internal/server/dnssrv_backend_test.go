package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type fakeDNSSRVResolver struct {
	mu      sync.Mutex
	calls   int
	service string
	proto   string
	name    string
	records []*net.SRV
	err     error
}

func (resolver *fakeDNSSRVResolver) LookupSRV(
	_ context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.calls++
	resolver.service = service
	resolver.proto = proto
	resolver.name = name
	records := make([]*net.SRV, len(resolver.records))
	for index, record := range resolver.records {
		if record != nil {
			copy := *record
			records[index] = &copy
		}
	}
	return "_ldap._tcp." + name + ".", records, resolver.err
}

func (resolver *fakeDNSSRVResolver) callCount() int {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.calls
}

func TestDNSSRVBackendDomainCacheTTLAndFailureCodes(t *testing.T) {
	dn, err := directory.ParseDN("uid=alice,ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if domain, ok := dnssrvDomain(dn); !ok || domain != "example.com" {
		t.Fatalf("dnssrvDomain() = %q, %t", domain, ok)
	}
	resolver := &fakeDNSSRVResolver{records: []*net.SRV{
		{Target: "second.example.", Port: 2389, Priority: 20},
		{Target: "first.example.", Port: 1389, Priority: 10},
	}}
	now := time.Unix(1700000000, 0)
	configuration := &dnssrvBackendRuntimeConfiguration{
		common:          defaultChainRemoteConfiguration(),
		positiveTTL:     time.Minute,
		negativeTTL:     10 * time.Second,
		resolver:        resolver,
		now:             func() time.Time { return now },
		maxCacheEntries: 4,
	}
	first, failure := configuration.resolve(context.Background(), dn)
	if failure != nil || len(first.remotes) != 2 ||
		first.remotes[0].uri != "ldap://first.example:1389" ||
		resolver.service != "ldap" || resolver.proto != "tcp" || resolver.name != "example.com" {
		t.Fatalf("first resolve = %#v, failure %#v, resolver %#v", first, failure, resolver)
	}
	if _, failure := configuration.resolve(context.Background(), dn); failure != nil || resolver.callCount() != 1 {
		t.Fatalf("positive cache failure = %#v, calls = %d", failure, resolver.callCount())
	}
	now = now.Add(time.Minute)
	if _, failure := configuration.resolve(context.Background(), dn); failure != nil || resolver.callCount() != 2 {
		t.Fatalf("expired positive cache failure = %#v, calls = %d", failure, resolver.callCount())
	}

	resolver.records = nil
	resolver.err = &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true}
	now = now.Add(time.Minute)
	_, failure = configuration.resolve(context.Background(), dn)
	if failure == nil || failure.Code != ldapwire.ResultNoSuchObject {
		t.Fatalf("NXDOMAIN failure = %#v", failure)
	}
	if _, cached := configuration.resolve(context.Background(), dn); cached == nil ||
		cached.Code != ldapwire.ResultNoSuchObject || resolver.callCount() != 3 {
		t.Fatalf("negative cache = %#v, calls = %d", cached, resolver.callCount())
	}
	now = now.Add(10 * time.Second)
	resolver.err = &net.DNSError{Err: "timeout", Name: "example.com", IsTimeout: true}
	_, failure = configuration.resolve(context.Background(), dn)
	if failure == nil || failure.Code != ldapwire.ResultUnavailable {
		t.Fatalf("temporary DNS failure = %#v", failure)
	}
}

func TestDNSSRVBackendConcurrentCacheAccess(t *testing.T) {
	dn, _ := directory.ParseDN("dc=example,dc=com")
	resolver := &fakeDNSSRVResolver{records: []*net.SRV{{Target: "ldap.example.", Port: 389}}}
	configuration := &dnssrvBackendRuntimeConfiguration{
		common:          defaultChainRemoteConfiguration(),
		positiveTTL:     time.Hour,
		negativeTTL:     time.Minute,
		resolver:        resolver,
		now:             func() time.Time { return time.Unix(1700000000, 0) },
		maxCacheEntries: 4,
	}
	var wait sync.WaitGroup
	errorsSeen := make(chan string, 32)
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			resolved, failure := configuration.resolve(context.Background(), dn)
			if failure != nil || resolved == nil || len(resolved.remotes) != 1 {
				errorsSeen <- "resolve failed"
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for failure := range errorsSeen {
		t.Error(failure)
	}
	if calls := resolver.callCount(); calls != 1 {
		t.Fatalf("concurrent resolver calls = %d, want 1", calls)
	}
}

func TestDNSSRVBackendReturnsReferralWithoutForwardingCredentialsOrWrites(t *testing.T) {
	resolver := &fakeDNSSRVResolver{records: []*net.SRV{{
		Target: "untrusted.example.",
		Port:   1389,
	}}}

	proxyStore := storage.NewMemory()
	t.Cleanup(func() { _ = proxyStore.Close() })
	seedDNSSRVBackendConfiguration(t, proxyStore, "1m", "10s")
	proxyAddress, stopProxy := startServer(t, proxyStore, Config{DNSSRVResolver: resolver})
	defer stopProxy()
	client, err := ldap.DialURL("ldap://" + proxyAddress)
	if err != nil {
		t.Fatalf("DialURL(proxy): %v", err)
	}
	defer client.Close()
	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err == nil {
		t.Fatal("DNSSRV Bind unexpectedly accepted credentials")
	} else {
		assertLDAPResultCode(t, err, ldap.LDAPResultUnwillingToPerform)
	}
	if resolver.callCount() != 0 {
		t.Fatalf("credential Bind performed %d DNS lookups", resolver.callCount())
	}
	_, err = client.Search(ldap.NewSearchRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(uid=alice)",
		[]string{"cn"},
		nil,
	))
	assertLDAPReferral(t, err, "", "ldap://untrusted.example:1389")

	add := ldap.NewAddRequest("uid=write,dc=example,dc=com", nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"write"})
	add.Attribute("cn", []string{"Write"})
	add.Attribute("sn", []string{"Write"})
	assertLDAPReferral(t, client.Add(add), "", "ldap://untrusted.example:1389")
	if resolver.callCount() != 1 {
		t.Fatalf("resolver calls = %d, want one cached lookup", resolver.callCount())
	}
}

func TestDNSSRVBackendCacheIsBoundedLRU(t *testing.T) {
	resolver := &fakeDNSSRVResolver{records: []*net.SRV{{Target: "ldap.example.", Port: 389}}}
	configuration := &dnssrvBackendRuntimeConfiguration{
		common: defaultChainRemoteConfiguration(), positiveTTL: time.Hour,
		negativeTTL: time.Minute, resolver: resolver,
		now:             func() time.Time { return time.Unix(1700000000, 0) },
		maxCacheEntries: 2,
	}
	for _, raw := range []string{
		"dc=one,dc=test", "dc=two,dc=test", "dc=three,dc=test", "dc=one,dc=test",
	} {
		dn, err := directory.ParseDN(raw)
		if err != nil {
			t.Fatalf("ParseDN(%q): %v", raw, err)
		}
		if _, failure := configuration.resolve(context.Background(), dn); failure != nil {
			t.Fatalf("resolve(%q): %#v", raw, failure)
		}
	}
	configuration.mu.Lock()
	cacheSize := len(configuration.cache)
	configuration.mu.Unlock()
	if cacheSize != 2 || resolver.callCount() != 4 {
		t.Fatalf("cache size/calls = %d/%d, want 2/4", cacheSize, resolver.callCount())
	}
}

func TestDNSSRVBackendMissingRecordsResult(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDNSSRVBackendConfiguration(t, store, "1m", "10s")
	resolver := &fakeDNSSRVResolver{err: &net.DNSError{
		Err: "no such host", Name: "example.com", IsNotFound: true,
	}}
	address, stop := startServer(t, store, Config{DNSSRVResolver: resolver})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	_, err = client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		nil,
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
}

func seedDNSSRVBackendConfiguration(
	t *testing.T,
	store storage.Store,
	positiveTTL, negativeTTL string,
) {
	t.Helper()
	entry := directory.Entry{
		DN: "olcDatabase={1}dnssrv,cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcDNSSRVConfig")},
			{Description: "olcDatabase", Values: stringValues("{1}dnssrv")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			{Description: "olcDNSSRVCacheTTL", Values: stringValues(positiveTTL)},
			{Description: "olcDNSSRVNegativeTTL", Values: stringValues(negativeTTL)},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.PutIn(configurationStoragePartition, entry, false); err != nil {
			return err
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed dnssrv backend: %v", err)
	}
}
