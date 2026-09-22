package server

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDeleteMetadataPreflightServerWriterEligibility(t *testing.T) {
	server, database, _ := newModifySnapshotFixture(t, "bolt", 4096)
	for _, limit := range []uint64{0, 1 << 20} {
		t.Run(fmt.Sprintf("entry-limit-%d", limit), func(t *testing.T) {
			database.entryLimit.bytes = limit
			if err := server.updateStorage(t.Context(), func(writer storage.Writer) error {
				tracker, ok := writer.(*homedirTrackingWriter)
				if !ok {
					t.Fatalf("ordinary update writer = %T, want homedir tracker", writer)
				}
				if _, ok := tracker.Writer.(accessContextWriter); !ok {
					t.Fatalf("inner ordinary writer = %T, want access context", tracker.Writer)
				}
				tx := writerForDatabase(writer, database)
				var want, got []string
				if err := tx.ForEach(func(entry directory.Entry) error {
					want = append(want, entry.DN)
					return nil
				}); err != nil {
					return err
				}
				handled, err := storage.ForEachDeleteCandidateDN(tx, func(entry directory.Entry) error {
					got = append(got, entry.DN)
					return nil
				})
				if err != nil {
					return err
				}
				if !handled || len(got) != 2 || !reflect.DeepEqual(got, want) {
					t.Fatalf("server preflight writer=%T handled=%v rows=%q, want %q", tx, handled, got, want)
				}
				t.Logf("ordinary server writer=%T, database writer=%T, metadata handled=%v", writer, tx, handled)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDeleteMetadataPreflightLDAP(t *testing.T) {
	for _, backend := range dnIdentityCoreWriteBackends() {
		t.Run(backend.name, func(t *testing.T) {
			var store storage.Store
			client := startDNMultiAVALocalServer(t, func(t *testing.T) storage.Store {
				store = backend.open(t)
				return store
			})
			const (
				upper       = "exactName=Alice+foldName=Engineering,dc=example,dc=com"
				lower       = "exactName=alice+foldName=engineering,dc=example,dc=com"
				middle      = "cn=middle," + upper
				grandchild  = "cn=grandchild," + middle
				upperLookup = "foldAlias=ENGINEERING+" + dnMultiAVAExactOID + "=Alice,DC=EXAMPLE,DC=COM"
				lowerLookup = "foldAlias=ENGINEERING+" + dnMultiAVAExactOID + "=alice,DC=EXAMPLE,DC=COM"
			)
			addDNIdentityCoreWriteEntry(t, client, middle, "middle")
			addDNIdentityCoreWriteEntry(t, client, grandchild, "grandchild")
			registry := newDNMultiAVARegistry(t)
			middleDN, err := registry.NormalizeDN(middle)
			if err != nil {
				t.Fatal(err)
			}
			// Remove only the intermediate row through storage to create an orphan
			// grandchild. The LDAP nonleaf check must still protect its ancestor.
			if err := store.Update(t.Context(), func(writer storage.Writer) error {
				var partition string
				if err := writer.ForEachPartition(func(candidatePartition string, entry directory.Entry) error {
					if entry.DN == middle {
						partition = candidatePartition
					}
					return nil
				}); err != nil {
					return err
				}
				if partition == "" {
					return errors.New("intermediate entry partition not found")
				}
				return writer.DeleteIn(partition, middleDN)
			}); err != nil {
				t.Fatal(err)
			}

			type row struct {
				partition string
				entry     directory.Entry
			}
			snapshot := func() ([]row, []string) {
				t.Helper()
				var rows []row
				var contexts []string
				if err := store.View(t.Context(), func(reader storage.Reader) error {
					if err := reader.ForEachPartition(func(partition string, entry directory.Entry) error {
						rows = append(rows, row{partition: partition, entry: entry})
						return nil
					}); err != nil {
						return err
					}
					var err error
					contexts, err = reader.NamingContexts()
					return err
				}); err != nil {
					t.Fatal(err)
				}
				return rows, contexts
			}
			before, beforeContexts := snapshot()
			assertLDAPResultCode(t, client.Del(ldap.NewDelRequest(upperLookup, nil)), ldap.LDAPResultNotAllowedOnNonLeaf)
			assertLDAPResultCode(t, client.Del(ldap.NewDelRequest(upperLookup, []ldap.Control{
				ldap.NewControlString(noOpControlOID, true, ""),
			})), ldap.LDAPResultNotAllowedOnNonLeaf)
			assertLDAPResultCode(t, client.Del(ldap.NewDelRequest(lowerLookup, []ldap.Control{
				ldap.NewControlString(noOpControlOID, true, ""),
			})), uint16(ldapwire.ResultNoOperation))
			after, afterContexts := snapshot()
			if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(beforeContexts, afterContexts) {
				t.Fatal("failed/no-op Delete changed entries or naming contexts")
			}
			searchDNIdentityCoreWriteBase(t, client, grandchild)
			if err := client.Del(ldap.NewDelRequest(lowerLookup, nil)); err != nil {
				t.Fatalf("caseExact sibling leaf Delete: %v", err)
			}
			assertLDAPResultCode(t, dnMultiAVABaseSearchError(client, lower), ldap.LDAPResultNoSuchObject)
			searchDNIdentityCoreWriteBase(t, client, upper)
			searchDNIdentityCoreWriteBase(t, client, grandchild)
		})
	}
}

type deletePreflightNormalizer struct {
	directory.DNAttributeNormalizer
	calls  []string
	failAt int
	err    error
}

func (normalizer *deletePreflightNormalizer) NormalizeDNAttribute(attribute string, value []byte) (string, []byte, error) {
	normalizer.calls = append(normalizer.calls, attribute+"="+string(value))
	if len(normalizer.calls) == normalizer.failAt {
		return "", nil, normalizer.err
	}
	return normalizer.DNAttributeNormalizer.NormalizeDNAttribute(attribute, value)
}

func TestDeleteMetadataPreflightNormalizationParity(t *testing.T) {
	store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "normalization.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	registry := newDNMultiAVARegistry(t)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		for _, raw := range []string{
			"exactName=Alice+foldName=Engineering,dc=example,dc=com",
			"exactName=alice+foldName=engineering,dc=example,dc=com",
			"CN=child,cn=missing,exactAlias=Alice+foldAlias=ENGINEERING,DC=EXAMPLE,DC=COM",
			"CN=unrelated,DC=EXAMPLE,DC=COM",
		} {
			dn, err := registry.NormalizeDN(raw)
			if err != nil {
				return err
			}
			if err := storage.PutInWithDN(writer, "db", directory.Entry{DN: raw}, dn, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	type observation struct {
		rows        []string
		identities  []string
		calls       []string
		hasChildren bool
		err         error
	}
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		// Inner maintenance decorators are used by ordinary server writes too.
		wrapped := &homedirTrackingWriter{Writer: accessContextWriter{Writer: &entryLimitWriter{Writer: writer}}}
		injected := errors.New("normalization failure")
		for _, target := range []struct {
			base        string
			hasChildren bool
		}{
			{"foldAlias=engineering+" + dnMultiAVAExactOID + "=Alice,dc=example,dc=com", true},
			{"foldAlias=ENGINEERING+" + dnMultiAVAExactOID + "=alice,dc=example,dc=com", false},
		} {
			base := target.base
			for failAt := 0; failAt <= 30; failAt++ {
				var want observation
				for _, metadata := range []bool{false, true} {
					normalizer := &deletePreflightNormalizer{DNAttributeNormalizer: registry, failAt: failAt, err: injected}
					scoped := storage.WriterInPartitionWithNormalizerLegacy(wrapped, "db", normalizer)
					var got observation
					comparison, err := directory.ParseDN(base)
					if err != nil {
						return err
					}
					comparison, got.err = storage.NormalizeReaderDN(scoped, comparison)
					if got.err == nil {
						visit := func(entry directory.Entry) error {
							got.rows = append(got.rows, entry.DN)
							candidate, err := normalizedWriteCandidateDN(scoped, entry)
							if err != nil {
								return err
							}
							got.identities = append(got.identities, candidate.Key())
							got.hasChildren = got.hasChildren || comparison.AncestorOf(candidate)
							return nil
						}
						if metadata {
							var handled bool
							handled, got.err = storage.ForEachDeleteCandidateDN(scoped, visit)
							if !handled {
								t.Fatal("decorated Bolt writer was not handled")
							}
						} else {
							got.err = scoped.ForEach(visit)
						}
					}
					got.calls = normalizer.calls
					if !metadata {
						want = got
					} else if !reflect.DeepEqual(got.rows, want.rows) || !reflect.DeepEqual(got.identities, want.identities) ||
						!reflect.DeepEqual(got.calls, want.calls) || got.hasChildren != want.hasChildren ||
						fmt.Sprint(got.err) != fmt.Sprint(want.err) || reflect.TypeOf(got.err) != reflect.TypeOf(want.err) ||
						errors.Is(got.err, injected) != errors.Is(want.err, injected) {
						t.Fatalf("base=%s failAt=%d: normalization/order/result differ: %#v vs %#v", base, failAt, got, want)
					}
					if failAt == 0 {
						if got.err != nil || len(got.calls) <= 4 || got.hasChildren != target.hasChildren {
							// Both bases have four AVAs. Additional calls prove that
							// noncanonical stored DNs exercised normalization fallback.
							t.Fatalf("fixture did not exercise expected ancestry and normalization fallback: %#v", got)
						}
					}
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
