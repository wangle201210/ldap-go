package server

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

// BenchmarkNetworkCommon matches ldapcommonbench's fixed -people/-uid searches.
// b.Loop excludes setup and validation from benchmark timing, but -cpuprofile
// includes them and SDK work. Use pprof -focus=runConnectionOperation to inspect
// handler stacks; this is not an isolated server CPU or OpenLDAP comparison.
func BenchmarkNetworkCommon(b *testing.B) {
	seed := os.Getenv("LDAP_GO_NETWORK_BENCH_FIXTURE")
	if seed == "" {
		b.Skip("set LDAP_GO_NETWORK_BENCH_FIXTURE to a quiescent 100k CLI seed database")
	}
	const peopleDN = "ou=people,dc=scale,dc=qualification"
	const uid = "scale-001001"
	const targetDN = "uid=" + uid + "," + peopleDN
	for _, test := range []struct {
		name, base, filter string
		scope              int
	}{
		{"nonrootBase", targetDN, "(objectClass=*)", ldap.ScopeBaseObject},
		{"nonrootEquality", peopleDN, "(uid=" + ldap.EscapeFilter(uid) + ")", ldap.ScopeWholeSubtree},
	} {
		b.Run(test.name+"/hot", func(b *testing.B) {
			conn := newNetworkCommonClient(b, seed)
			request := ldap.NewSearchRequest(test.base, test.scope, ldap.NeverDerefAliases,
				2, 0, false, test.filter, []string{"uid"}, nil)
			wantDN, err := ldap.ParseDN(targetDN)
			if err != nil {
				b.Fatal(err)
			}
			wantUID := []string{uid}
			validate := func(result *ldap.SearchResult) {
				b.Helper()
				if result == nil || len(result.Referrals) != 0 || len(result.Entries) != 1 || result.Entries[0] == nil {
					b.Fatal("search must return exactly one entry and no referrals")
				}
				entry := result.Entries[0]
				gotDN, err := ldap.ParseDN(entry.DN)
				if err != nil || !gotDN.EqualFold(wantDN) {
					b.Fatal("search returned an unexpected DN")
				}
				if len(entry.Attributes) != 1 || entry.Attributes[0] == nil ||
					!strings.EqualFold(entry.Attributes[0].Name, "uid") || !slices.Equal(entry.Attributes[0].Values, wantUID) {
					b.Fatal("search must return only the expected single uid value")
				}
			}
			result, err := conn.Search(request)
			if err != nil {
				b.Fatalf("warm-up search: %v", err)
			}
			validate(result)
			b.ReportAllocs()
			for b.Loop() {
				result, err = conn.Search(request)
				if err != nil {
					b.Fatalf("search: %v", err)
				}
			}
			validate(result)
		})
	}
}

func newNetworkCommonClient(t testing.TB, seed string) *ldap.Conn {
	t.Helper()
	// New can migrate a database. Only the private copy is ever opened by Bolt.
	source, err := os.Open(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	path := filepath.Join(t.TempDir(), "network-common.db")
	destination, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	if err := errors.Join(copyErr, destination.Close()); err != nil {
		t.Fatal(err)
	}
	store, err := storage.OpenBoltForServer(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close listener: %v", err)
		}
	})
	const rootDN = "cn=admin,dc=scale,dc=qualification"
	const rootPassword = "network-profile-root"
	instance, err := New(Config{
		Store:            store,
		ListenerURLs:     []string{"ldap://" + listener.Addr().String()},
		RootDN:           rootDN,
		RootPassword:     []byte(rootPassword),
		MaxSearchEntries: 100100, MaxSearchCandidates: 100100,
		MaxSearchCandidateBytes: 819200000, MaxSearchMemoryBytes: 1638400000,
		// Match qualification limits; Schema and AccessPolicy use CLI defaults.
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- instance.Serve(ctx, listener)
	}()
	t.Cleanup(func() {
		cancel()
		// Serve closes its listener and drains connections/background workers.
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	dialer := net.Dialer{Timeout: 10 * time.Second}
	transport, err := dialer.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn := ldap.NewConn(transport, false)
	conn.Start()
	conn.SetTimeout(30 * time.Second) // Match the qualification scripts.
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close client: %v", err)
		}
	})
	if err := conn.Bind(rootDN, rootPassword); err != nil {
		t.Fatalf("root bind: %v", err)
	}
	const readerUID = "network-profile-reader"
	const readerDN = "uid=" + readerUID + ",ou=people,dc=scale,dc=qualification"
	add := ldap.NewAddRequest(readerDN, nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{readerUID})
	add.Attribute("cn", []string{"Network Profile Reader"})
	add.Attribute("sn", []string{"Reader"})
	add.Attribute("userPassword", []string{string(bindRouteSSHA(t))})
	if err := conn.Add(add); err != nil {
		t.Fatalf("add profile reader to copy: %v", err)
	}
	if err := conn.Bind(readerDN, "secret"); err != nil {
		t.Fatalf("reader bind: %v", err)
	}
	identity, err := conn.WhoAmI(nil)
	if err != nil {
		t.Fatalf("reader WhoAmI: %v", err)
	}
	if identity == nil || identity.AuthzID != "dn:"+readerDN {
		t.Fatal("connection is not bound as the profile reader")
	}
	return conn
}
