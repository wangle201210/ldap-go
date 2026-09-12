package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDeltaIncrementIncomingRejectionIsAtomic(t *testing.T) {
	for _, backend := range []string{"memory", "bbolt"} {
		for _, older := range []bool{false, true} {
			for _, test := range []struct {
				name string
				mods []string
			}{
				{"positive", []string{"uidNumber:# 2"}},
				{"negative", []string{"uidNumber:# -2"}},
				{"zero", []string{"uidNumber:# 0"}},
				{"missing_operand", []string{"uidNumber:#"}},
				{"empty_operand", []string{"uidNumber:# "}},
				{"multiple_operands", []string{"uidNumber:# 1", "uidNumber:# 2"}},
				{"invalid_integer", []string{"uidNumber:# 1.5"}},
				{"out_of_range", []string{"uidNumber:# 9223372036854775808"}},
				{"non_integer_syntax", []string{"description:# 2"}},
				{"oid", []string{"1.3.6.1.1.1.1.0:# 2"}},
				{"options", []string{"uidNumber;lang-en:# 2"}},
				{"replace_increment", []string{"uidNumber:= 20", "uidNumber:# 2"}},
				{"increment_replace", []string{"uidNumber:# 2", "uidNumber:= 20"}},
				{"delete_increment", []string{"uidNumber:-", "uidNumber:# 2"}},
				{"increment_delete", []string{"uidNumber:# 2", "uidNumber:- 10"}},
				{"add_increment", []string{"uidNumber:+ 30", "uidNumber:# 2"}},
				{"increment_add", []string{"uidNumber:# 2", "uidNumber:+ 30"}},
				{"two_increments", []string{"uidNumber:# 2", ":", "uidNumber:# 3"}},
			} {
				t.Run(fmt.Sprintf("%s/older=%v/%s", backend, older, test.name), func(t *testing.T) {
					instance, _ := newDeltaMPRServer(t, backend, 10)
					deltaMPRApply(t, instance, 1, deltaMPRChange(t, 1, 0, "mail:= committed@example.com"))
					deltaMPRApply(t, instance, 2, deltaMPRChange(t, 2, 2, "uidNumber:= 10", "description:= 10"))
					config, _ := deltaCascadeUnitConfig(t, instance, 1)
					// Neither schema-checking mode may bypass the ordering boundary.
					config.schemaChecking = older
					tick := 3
					if older {
						tick = 1
					}
					mods := append([]string{"mail:= must-not-commit@example.com"}, test.mods...)
					source := deltaMPRChange(t, 1, tick, mods...)
					before := deltaIncrementSnapshot(t, instance, config)
					for retry := 0; retry < 2; retry++ {
						err := instance.applySyncConsumerAccesslogEntry(context.Background(), config, source, []byte("rid=001,csn="+source.GetAttributeValue("entryCSN")))
						assertDeltaIncrementRejected(t, err)
						assertDeltaIncrementRejected(t, instance.syncConsumerAccesslogFailure(context.Background(), config, err))
						if after := deltaIncrementSnapshot(t, instance, config); !reflect.DeepEqual(before, after) {
							t.Fatal("rejected increment changed entries, original accesslogs, contextCSNs, or cookie")
						}
					}
					// On another RID the same rejected CSN must still be rejected.
					other, _ := deltaCascadeUnitConfig(t, instance, 3)
					before = deltaIncrementSnapshot(t, instance, config, other)
					assertDeltaIncrementRejected(t, instance.applySyncConsumerAccesslogEntry(context.Background(), other, source, nil))
					if after := deltaIncrementSnapshot(t, instance, config, other); !reflect.DeepEqual(before, after) {
						t.Fatal("cross-RID retry marked a rejected increment as applied")
					}
				})
			}
		}
	}
}

func TestDeltaIncrementHistoryRejectionIsAtomic(t *testing.T) {
	for _, backend := range []string{"memory", "bbolt"} {
		for _, mods := range [][]string{
			{"uidNumber:= 20"}, {"uidNumber:-"}, {"uidNumber:- 10"},
			{"uidNumber:+ 30"}, {"mail:= unrelated@example.com"},
		} {
			t.Run(backend+"/"+mods[0], func(t *testing.T) {
				instance, store := newDeltaMPRServer(t, backend, 10)
				newer := deltaMPRChange(t, 2, 2, "uidNumber:= 12")
				deltaMPRApply(t, instance, 2, newer)
				config, database := deltaCascadeUnitConfig(t, instance, 1)
				logDB := instance.runtime.Load().databases[database.accesslog.targetDatabaseIndex]
				row := deltaMPRLog(t, instance)[0]
				// Model a local increment already committed through the write path.
				// TCP coverage below also creates this history with real LDAP writes.
				if err := store.Update(context.Background(), func(writer storage.Writer) error {
					tx := writerForDatabase(writer, logDB)
					entry, err := tx.Get(mustSyncConsumerDN(t, row.DN))
					if err != nil {
						return err
					}
					entry.ReplaceValues("reqMod", stringValues("uidNumber:# 2", "entryCSN:= "+newer.GetAttributeValue("entryCSN")))
					return tx.Put(entry, true)
				}); err != nil {
					t.Fatal(err)
				}
				before := deltaIncrementSnapshot(t, instance, config)
				err := instance.applySyncConsumerAccesslogEntry(context.Background(), config, deltaMPRChange(t, 1, 1, mods...), nil)
				assertDeltaIncrementRejected(t, err)
				if after := deltaIncrementSnapshot(t, instance, config); !reflect.DeepEqual(before, after) {
					t.Fatal("unsafe increment history changed committed state")
				}
			})
		}
	}
}

func assertDeltaIncrementRejected(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, errSyncConsumerAccesslogGap) || !strings.Contains(err.Error(), "increment") {
		t.Fatalf("error = %v, want unsafe increment gap", err)
	}
}

type deltaIncrementState struct {
	entries  map[string]directory.Entry
	contexts map[string]syncCSNState
	metadata map[string]string
}

func deltaIncrementSnapshot(t *testing.T, instance *Server, configs ...syncConsumerConfig) deltaIncrementState {
	t.Helper()
	state := deltaIncrementState{map[string]directory.Entry{}, map[string]syncCSNState{}, map[string]string{}}
	if err := instance.config.Store.View(context.Background(), func(reader storage.Reader) error {
		if err := reader.ForEachPartition(func(partition string, entry directory.Entry) error {
			state.entries[partition+"\x00"+entry.DN] = entry.Clone()
			return nil
		}); err != nil {
			return err
		}
		for _, database := range instance.runtime.Load().databases {
			csns, err := syncContextCSNs(reader, database.partition)
			if err != nil {
				return err
			}
			state.contexts[database.partition] = csns
		}
		for _, config := range configs {
			for _, key := range []string{syncConsumerCookieMetadataKey(config), syncConsumerAccesslogBootstrapMetadataKey(config)} {
				value, err := reader.Metadata(key)
				if errors.Is(err, storage.ErrMetadataNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				state.metadata[key] = string(value)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestDeltaIncrementTCPTopologiesStopAndDeduplicate(t *testing.T) {
	for _, backend := range []string{"memory", "bbolt"} {
		for _, topology := range []string{"ring", "mesh"} {
			t.Run(backend+"/"+topology, func(t *testing.T) {
				const count = 3
				instances := make([]*Server, count)
				nodes := make([]*multiProviderTestNode, count)
				logs := make([]*ldap.Entry, count)
				paths := make([]string, count)
				for i := range nodes {
					var store storage.Store = storage.NewMemory()
					if backend == "bbolt" {
						paths[i] = filepath.Join(t.TempDir(), "directory.db")
						var err error
						store, err = storage.OpenBolt(paths[i])
						if err != nil {
							t.Fatal(err)
						}
					}
					instance := newDeltaMPRServerWithStore(t, store, uint16(i+1))
					instances[i] = instance
					_, database := deltaCascadeUnitConfig(t, instance, 100)
					if err := store.Update(context.Background(), func(writer storage.Writer) error {
						content := writerForDatabase(writer, database)
						entry, err := content.Get(mustSyncConsumerDN(t, deltaMPRTarget))
						if err != nil {
							return err
						}
						entry.ReplaceValues("objectClass", stringValues("inetOrgPerson", "extensibleObject"))
						entry.ReplaceValues("uidNumber", stringValues("10"))
						return content.Put(entry, true)
					}); err != nil {
						t.Fatal(err)
					}
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					node := &multiProviderTestNode{id: uint16(i + 1), store: store, address: listener.Addr().String(), listener: listener}
					nodes[i] = node
					t.Cleanup(func() { _ = node.store.Close() })
					startMultiProviderTestNode(node, instance)
					t.Cleanup(func() { stopMultiProviderTestNode(t, node) })
					client := dialLDAPRoot(t, node.address)
					request := ldap.NewModifyRequest(deltaMPRTarget, nil)
					request.Increment("uidNumber", fmt.Sprint(i+1))
					if err := client.Modify(request); err != nil {
						t.Fatal(err)
					}
					_ = client.Close()
					rows := deltaMPRLog(t, instance)
					if len(rows) != 1 || !strings.Contains(strings.Join(rows[0].GetAttributeValues("reqMod"), "\n"), fmt.Sprintf("uidNumber:# %d", i+1)) {
						t.Fatalf("local increment did not preserve original accesslog: %v", rows)
					}
					logs[i] = rows[0]
				}
				for pass := 0; pass < 2; pass++ {
					for target, instance := range instances {
						for source := range nodes {
							if source == target || topology == "ring" && source != (target+1)%count {
								continue
							}
							config, _ := deltaCascadeUnitConfig(t, instance, source+1)
							config.mode = syncConsumerRefreshOnly
							config.bindDN, config.credentials, config.credentialsSet = syncTestRootDN, []byte(syncTestRootPassword), true
							config.operationTimeout = 3 * time.Second
							if complete, err := instance.prepareSyncConsumerAccesslogBootstrap(context.Background(), config); err != nil || !complete {
								t.Fatalf("adopt local state: complete=%v err=%v", complete, err)
							}
							before := deltaIncrementSnapshot(t, instance, config)
							ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
							err := instance.runSyncConsumerCycle(ctx, config, "ldap://"+nodes[source].address)
							cancel()
							assertDeltaIncrementRejected(t, err)
							if after := deltaIncrementSnapshot(t, instance, config); !reflect.DeepEqual(before, after) {
								t.Fatal("failed TCP replay advanced cookie or changed content/history")
							}
						}
						// A looped-back local CSN must be deduplicated before the guard.
						for _, rid := range []int{100, 101} {
							deltaMPRApply(t, instance, rid, logs[target])
						}
						if rows := deltaMPRLog(t, instance); len(rows) != 1 || !reflect.DeepEqual(rows[0], logs[target]) {
							t.Fatal("dedup changed the original increment log")
						}
						_, database := deltaCascadeUnitConfig(t, instance, 100)
						assertSyncConsumerEntryValues(t, nodes[target].store, database.partition, deltaMPRTarget, "uidNumber", []string{fmt.Sprint(11 + target)})
					}
					if pass == 0 {
						for i, node := range nodes {
							stopMultiProviderTestNode(t, node)
							var err error
							if backend == "bbolt" {
								// Reopen the actual file, not just the Server runtime.
								if err := node.store.Close(); err != nil {
									t.Fatal(err)
								}
								node.store, err = storage.OpenBolt(paths[i])
								if err != nil {
									t.Fatal(err)
								}
							}
							instances[i], err = New(Config{Store: node.store, RootDN: syncTestRootDN, RootPassword: []byte(syncTestRootPassword)})
							if err != nil {
								t.Fatal(err)
							}
							node.listener, err = net.Listen("tcp", node.address)
							if err != nil {
								t.Fatal(err)
							}
							startMultiProviderTestNode(node, instances[i])
						}
					}
				}
			})
		}
	}
}
