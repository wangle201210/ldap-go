package server

import (
	"context"
	"errors"
	"testing"

	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLocalPasswordBindAfterExternalPreverify(t *testing.T) {
	t.Parallel()

	first, err := auth.HashPassword([]byte("first-secret"), auth.SMPBKDF2HashScheme, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := auth.HashPassword([]byte("second-secret"), auth.SMPBKDF2HashScheme, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		passwords [][]byte
		access    []string
		accepted  []string
	}{
		{name: "single", passwords: [][]byte{first}, accepted: []string{"first-secret"}},
		{name: "multiple", passwords: [][]byte{first, second}, accepted: []string{"first-secret", "second-secret"}},
		{
			name: "ACL excludes matching local value", passwords: [][]byte{first, second},
			access: []string{
				`{0}to attrs=userPassword val.exact="` + string(first) + `" by * none`,
				`{1}to attrs=userPassword by anonymous auth by * none`,
			},
			accepted: []string{"second-secret"},
		},
		{name: "no passwords"},
		{name: "invalid local hash", passwords: stringValues("{PBKDF2-SM3}invalid")},
	} {
		t.Run(test.name, func(t *testing.T) {
			instance, database, dn := newLocalPasswordPreverifyFixture(t, test.passwords, test.access)
			runtime := instance.runtime.Load()
			for _, supplied := range []string{"first-secret", "second-secret", "wrong"} {
				matches, err := instance.preverifyExternalPasswordBind(
					t.Context(), runtime, database, dn, []byte(supplied), instance.clock(),
				)
				if err != nil || matches.values != nil || matches.collector != nil {
					t.Fatalf("local preverify = %#v, %v; want empty result", matches, err)
				}
				result, err := instance.authenticatePasswordBind(
					t.Context(), runtime, dn.String(), []byte(supplied), false,
				)
				want := false
				for _, accepted := range test.accepted {
					want = want || supplied == accepted
				}
				if err != nil || result.authenticated != want {
					t.Fatalf("Bind(%q) = %#v, %v; want authenticated=%v", supplied, result, err, want)
				}
			}
		})
	}
}

func TestLocalPasswordPreverifyPreservesStorageErrors(t *testing.T) {
	t.Parallel()

	for _, afterRead := range []bool{false, true} {
		name := "before candidates"
		if afterRead {
			name = "after candidates"
		}
		t.Run(name, func(t *testing.T) {
			instance, database, dn := newLocalPasswordPreverifyFixture(t, stringValues("secret"), nil)
			want := errors.New("preverify storage failure")
			instance.config.Store = localPasswordPreverifyErrorStore{
				Store: instance.config.Store, err: want, afterRead: afterRead,
			}
			matches, err := instance.preverifyExternalPasswordBind(
				t.Context(), instance.runtime.Load(), database, dn, []byte("secret"), instance.clock(),
			)
			if !errors.Is(err, want) || matches.values != nil || matches.collector != nil {
				t.Fatalf("preverify = %#v, %v; want empty result and original storage error", matches, err)
			}
		})
	}
}

type localPasswordPreverifyErrorStore struct {
	storage.Store
	err       error
	afterRead bool
}

func (store localPasswordPreverifyErrorStore) View(ctx context.Context, fn func(storage.Reader) error) error {
	if store.afterRead {
		if err := store.Store.View(ctx, fn); err != nil {
			return err
		}
	}
	return store.err
}

func newLocalPasswordPreverifyFixture(
	t testing.TB,
	passwords [][]byte,
	access []string,
) (*Server, runtimeDatabase, directory.DN) {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if access == nil {
		access = []string{"to attrs=userPassword by anonymous auth by * none"}
	}
	entries := []directory.Entry{
		{DN: "dc=example,dc=com", Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("domain")},
			{Description: "dc", Values: stringValues("example")},
		}},
		{DN: aliceDN, Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues("alice")},
			{Description: "cn", Values: stringValues("Alice")},
			{Description: "sn", Values: stringValues("Example")},
			{Description: "userPassword", Values: passwords},
		}},
		{DN: "olcDatabase={1}mdb,cn=config", Attributes: []directory.Attribute{
			{Description: "olcDatabase", Values: stringValues("{1}mdb")},
			{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
			{Description: "olcAccess", Values: stringValues(access...)},
		}},
	}
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatal(err)
	}
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	runtime := instance.runtime.Load()
	dn, err := parseRuntimeConnectionDN(runtime, aliceDN)
	if err != nil {
		t.Fatal(err)
	}
	database := databaseForDN(runtime, dn)
	if database == nil {
		t.Fatal("missing password database")
	}
	return instance, *database, dn
}

func BenchmarkLocalPasswordBindPreverify(b *testing.B) {
	stored, err := auth.HashPassword([]byte("secret"), auth.SMPBKDF2HashScheme, nil)
	if err != nil {
		b.Fatal(err)
	}
	for _, supplied := range []string{"secret", "wrong"} {
		b.Run(supplied, func(b *testing.B) {
			instance, database, dn := newLocalPasswordPreverifyFixture(b, [][]byte{stored}, nil)
			runtime := instance.runtime.Load()
			password := []byte(supplied)
			now := instance.clock()
			b.ReportAllocs()
			for b.Loop() {
				matches, err := instance.preverifyExternalPasswordBind(b.Context(), runtime, database, dn, password, now)
				if err != nil || !matches.empty() {
					b.Fatalf("preverify = %#v, %v", matches, err)
				}
			}
		})
	}
}

func BenchmarkLocalPasswordBind(b *testing.B) {
	stored, err := auth.HashPassword([]byte("secret"), auth.SMPBKDF2HashScheme, nil)
	if err != nil {
		b.Fatal(err)
	}
	for _, test := range []struct {
		name          string
		password      string
		authenticated bool
	}{
		{name: "success", password: "secret", authenticated: true},
		{name: "failure", password: "wrong"},
	} {
		b.Run(test.name, func(b *testing.B) {
			instance, _, dn := newLocalPasswordPreverifyFixture(b, [][]byte{stored}, nil)
			runtime := instance.runtime.Load()
			rawDN := dn.String()
			password := []byte(test.password)
			b.ReportAllocs()
			for b.Loop() {
				result, err := instance.authenticatePasswordBind(b.Context(), runtime, rawDN, password, false)
				if err != nil || result.authenticated != test.authenticated {
					b.Fatalf("Bind = %#v, %v; want authenticated=%v", result, err, test.authenticated)
				}
			}
		})
	}
}
