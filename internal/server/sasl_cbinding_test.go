package server

import (
	"context"
	"crypto/tls"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestSASLCBindingStartup(t *testing.T) {
	for _, value := range []string{"", "none", "NONE", "tls-unique", "TLS-ENDPOINT",
		"tls-server-end-point", "tls-exporter", "require", "auto", " none", "none ",
		"none\x00tls-unique", "{0}none", `"none"`, "tls-unique tls-endpoint", "tls-un\u0130que"} {
		t.Run(value, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedOnlineConfiguration(t, store)
			setUnsupportedRuntimeConfigurationAttribute(t, store, "cn=config", saslCBindingAttribute, value)
			_, wantErr := parseSASLCBindingPolicy(value)
			_, err := ValidateConfiguration(t.Context(), Config{Store: store})
			if (err != nil) != (wantErr != nil) {
				t.Fatalf("ValidateConfiguration(%q): %v", value, err)
			}
			instance, err := New(Config{Store: store})
			if (err != nil) != (wantErr != nil) {
				t.Fatalf("New(%q): %v", value, err)
			}
			if instance != nil {
				instance.closeSQLBackends()
				want, _ := parseSASLCBindingPolicy(value)
				if instance.runtime.Load().sasl.channelBinding != want {
					t.Fatal("startup did not activate policy")
				}
			}
		})
	}
	for _, test := range []struct {
		dn, description string
		values          []string
	}{
		{"cn=config", saslCBindingAttribute, []string{"none", "tls-unique"}},
		{"cn=config", saslCBindingAttribute + ";lang-en", []string{"none"}},
		{"cn=config", saslCBindingOID + ";binary", []string{"none"}},
		{"olcDatabase={1}mdb,cn=config", saslCBindingOID, []string{"none"}},
	} {
		t.Run(test.description+test.dn, func(t *testing.T) {
			store := storage.NewMemory()
			defer store.Close()
			seedOnlineConfiguration(t, store)
			if err := store.Update(t.Context(), func(writer storage.Writer) error {
				dn, _ := directory.ParseDN(test.dn)
				entry, err := writer.Get(dn)
				if err != nil {
					return err
				}
				entry.ReplaceValues(test.description, stringValues(test.values...))
				return writer.Put(entry, true)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateConfiguration(t.Context(), Config{Store: store}); err == nil {
				t.Fatal("invalid policy form accepted")
			}
		})
	}
}

func TestSASLCBindingOnlineAtomicity(t *testing.T) {
	store := storage.NewMemory()
	defer store.Close()
	seedOnlineConfiguration(t, store)
	instance, address, stop := startConfigurationCapabilityServer(t, store)
	defer stop()
	client := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer client.Close()
	if instance.runtime.Load().sasl.channelBinding != saslCBindingNone {
		t.Fatal("absent policy must disable binding")
	}
	if got := readSASLCBindingConfig(t, client); len(got) != 0 {
		t.Fatalf("default was materialized: %q", got)
	}
	for _, value := range []string{"TLS-UNIQUE", "NoNe", "tls-ENDPOINT"} {
		request := ldap.NewModifyRequest("cn=config", nil)
		request.Replace(saslCBindingOID, []string{value})
		if err := client.Modify(request); err != nil {
			t.Fatal(err)
		}
		if got := readSASLCBindingConfig(t, client); !reflect.DeepEqual(got, []string{value}) {
			t.Fatalf("case-preserving read = %q, want %q", got, value)
		}
		want, _ := parseSASLCBindingPolicy(value)
		if instance.runtime.Load().sasl.channelBinding != want {
			t.Fatal("runtime policy not updated")
		}
	}
	for _, test := range []struct {
		name   string
		code   uint16
		modify func(*ldap.ModifyRequest)
	}{
		{"duplicate", ldap.LDAPResultAttributeOrValueExists, func(r *ldap.ModifyRequest) { r.Add(saslCBindingAttribute, []string{"TLS-ENDPOINT"}) }},
		{"second", ldap.LDAPResultConstraintViolation, func(r *ldap.ModifyRequest) { r.Add(saslCBindingAttribute, []string{"none"}) }},
		{"multiple", ldap.LDAPResultConstraintViolation, func(r *ldap.ModifyRequest) { r.Replace(saslCBindingAttribute, []string{"none", "tls-unique"}) }},
		{"unknown", ldap.LDAPResultConstraintViolation, func(r *ldap.ModifyRequest) { r.Replace(saslCBindingAttribute, []string{"required"}) }},
		{"transient invalid", ldap.LDAPResultConstraintViolation, func(r *ldap.ModifyRequest) {
			r.Replace(saslCBindingAttribute, []string{"unknown"})
			r.Replace(saslCBindingAttribute, []string{"none"})
		}},
		{"options", ldap.LDAPResultConstraintViolation, func(r *ldap.ModifyRequest) { r.Replace(saslCBindingAttribute+";lang-en", []string{"none"}) }},
		{"other runtime error", ldap.LDAPResultConstraintViolation, func(r *ldap.ModifyRequest) {
			r.Replace(saslCBindingAttribute, []string{"none"})
			r.Replace("olcSaslSecProps", []string{"unknown"})
		}},
		{"wrong delete", ldap.LDAPResultNoSuchAttribute, func(r *ldap.ModifyRequest) { r.Delete(saslCBindingAttribute, []string{"none"}) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := instance.runtime.Load()
			stored := readStoredEntry(t, store, "cn=config")
			request := ldap.NewModifyRequest("cn=config", nil)
			test.modify(request)
			assertLDAPResultCode(t, client.Modify(request), test.code)
			if instance.runtime.Load() != before || !reflect.DeepEqual(stored, readStoredEntry(t, store, "cn=config")) {
				t.Fatal("failed modification changed storage or runtime")
			}
		})
	}
	request := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	request.Replace(saslCBindingAttribute, []string{"none"})
	assertLDAPResultCode(t, client.Modify(request), ldap.LDAPResultObjectClassViolation)
	request = ldap.NewModifyRequest("cn=config", nil)
	request.Delete(saslCBindingAttribute, []string{"TLS-ENDPOINT"})
	if err := client.Modify(request); err != nil {
		t.Fatal(err)
	}
	if instance.runtime.Load().sasl.channelBinding != saslCBindingNone || len(readSASLCBindingConfig(t, client)) != 0 {
		t.Fatal("delete did not restore absent default")
	}
}

func readSASLCBindingConfig(t *testing.T, client *ldap.Conn) []string {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest("cn=config", ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{saslCBindingAttribute}, nil))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("read cn=config: %v, %v", result, err)
	}
	return result.Entries[0].GetAttributeValues(saslCBindingAttribute)
}

func TestSASLCBindingTLSUniqueConstraints(t *testing.T) {
	valid := tls.ConnectionState{Version: tls.VersionTLS12, HandshakeComplete: true, TLSUnique: []byte("123456789012")}
	if got := string(saslTLSUniqueApplicationData(valid)); got != "tls-unique:123456789012" {
		t.Fatal(got)
	}
	for _, mutate := range []func(*tls.ConnectionState){
		func(s *tls.ConnectionState) { s.Version = tls.VersionTLS13 },
		func(s *tls.ConnectionState) { s.Version = tls.VersionTLS11 },
		func(s *tls.ConnectionState) { s.DidResume = true },
		func(s *tls.ConnectionState) { s.HandshakeComplete = false },
		func(s *tls.ConnectionState) { s.TLSUnique = nil },
		func(s *tls.ConnectionState) { s.TLSUnique = []byte("short") },
	} {
		state := valid
		mutate(&state)
		if got := saslTLSUniqueApplicationData(state); len(got) != 0 {
			t.Fatalf("unsafe binding: %q", got)
		}
	}
	for _, value := range []string{"none", "tls-unique", "tls-endpoint"} {
		policy, err := parseSASLCBindingPolicy(strings.ToUpper(value))
		if err != nil || policy.applicationData(saslSCRAMTLCPStyleConnection{}) != nil {
			t.Fatal("TLCP supplied TLS binding")
		}
	}
}

func TestSASLCBindingPersistentRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.db")
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	seedOnlineConfiguration(t, store)
	_, address, stop := startConfigurationCapabilityServer(t, store)
	client := bindConstraintClient(t, address, "cn=config", "config-secret")
	request := ldap.NewModifyRequest("cn=config", nil)
	request.Replace(saslCBindingAttribute, []string{"TLS-UNIQUE"})
	if err := client.Modify(request); err != nil {
		t.Fatal(err)
	}
	request = ldap.NewModifyRequest("cn=config", nil)
	request.Replace(saslCBindingAttribute, []string{"none"})
	request.Replace("olcSaslSecProps", []string{"unknown"})
	assertLDAPResultCode(t, client.Modify(request), ldap.LDAPResultConstraintViolation)
	client.Close()
	stop()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = storage.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	instance, address, stop := startConfigurationCapabilityServer(t, store)
	defer stop()
	if instance.runtime.Load().sasl.channelBinding != saslCBindingUnique {
		t.Fatal("restart did not restore committed policy")
	}
	client = bindConstraintClient(t, address, "cn=config", "config-secret")
	defer client.Close()
	if got := readSASLCBindingConfig(t, client); !reflect.DeepEqual(got, []string{"TLS-UNIQUE"}) {
		t.Fatalf("restart value: %q", got)
	}
}

type saslCBindingCommitFailureStore struct {
	storage.Store
	fail atomic.Bool
}

func (store *saslCBindingCommitFailureStore) Update(ctx context.Context, fn func(storage.Writer) error) error {
	return store.Store.Update(ctx, func(writer storage.Writer) error {
		if err := fn(writer); err != nil {
			return err
		}
		if store.fail.Load() {
			return errors.New("injected commit failure")
		}
		return nil
	})
}

func TestSASLCBindingCommitFailure(t *testing.T) {
	store := &saslCBindingCommitFailureStore{Store: storage.NewMemory()}
	defer store.Close()
	seedOnlineConfiguration(t, store)
	instance, address, stop := startConfigurationCapabilityServer(t, store)
	defer stop()
	client := bindConstraintClient(t, address, "cn=config", "config-secret")
	defer client.Close()
	before := instance.runtime.Load()
	stored := readStoredEntry(t, store, "cn=config")
	request := ldap.NewModifyRequest("cn=config", nil)
	request.Replace(saslCBindingAttribute, []string{"tls-endpoint"})
	store.fail.Store(true)
	if err := client.Modify(request); err == nil {
		t.Fatal("commit unexpectedly succeeded")
	}
	store.fail.Store(false)
	if instance.runtime.Load() != before || !reflect.DeepEqual(stored, readStoredEntry(t, store, "cn=config")) {
		t.Fatal("failed commit published a policy or persisted the candidate")
	}
	if err := client.Modify(request); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if instance.runtime.Load().sasl.channelBinding != saslCBindingEndpoint {
		t.Fatal("retry did not activate policy")
	}
}
