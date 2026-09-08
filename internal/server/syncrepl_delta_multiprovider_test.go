package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const deltaMPRTarget = "uid=alice,ou=people,dc=example,dc=com"

func newDeltaMPRServer(t *testing.T, backend string, sid uint16) (*Server, storage.Store) {
	t.Helper()
	store := newDeltaMultiProviderGuardStore(t, backend)
	return newDeltaMPRServerWithStore(t, store, sid), store
}

func newDeltaMPRServerWithStore(t *testing.T, store storage.Store, sid uint16) *Server {
	t.Helper()
	seedLDAPGoAccesslogProvider(t, store)
	seedMultiProviderTestConfiguration(t, &multiProviderTestNode{id: sid, store: store}, []multiProviderTestPeer{{rid: 999, address: "127.0.0.1:1"}})
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, _ := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcSyncrepl", stringValues(deltaMultiProviderGuardSyncreplValue(0, 999, "dc=example,dc=com", true)))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateConfiguration(context.Background(), Config{Store: store}); err != nil {
		t.Fatalf("validate supported writable delta configuration: %v", err)
	}
	instance, err := New(Config{Store: store, RootDN: syncTestRootDN, RootPassword: []byte(syncTestRootPassword)})
	if err != nil {
		t.Fatal(err)
	}
	return instance
}

func deltaMPRChange(t *testing.T, sid uint16, tick int, mods ...string) *ldap.Entry {
	t.Helper()
	csn := fmt.Sprintf("202609080101%02d.000001Z#000000#%03x#000000", tick, sid)
	mods = append(mods, "entryCSN:= "+csn, fmt.Sprintf("modifyTimestamp:= 202609080101%02dZ", tick), fmt.Sprintf("modifiersName:= cn=provider-%d,dc=example,dc=com", sid))
	return syncConsumerAccesslogTestEntry("reqStart="+csn[:22]+",cn=log", deltaMPRTarget, "modify", csn, mods, nil)
}

func deltaMPRApply(t *testing.T, instance *Server, rid int, source *ldap.Entry) {
	t.Helper()
	config, _ := deltaCascadeUnitConfig(t, instance, rid)
	if err := instance.applySyncConsumerAccesslogEntry(context.Background(), config, source, nil); err != nil {
		t.Fatalf("apply %s: %v", source.GetAttributeValue("entryCSN"), err)
	}
}

func TestDeltaMultiProviderReplayOrderAndOriginalLog(t *testing.T) {
	for _, backend := range []string{"memory", "bbolt"} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reverse=%v", backend, reverse), func(t *testing.T) {
				instance, store := newDeltaMPRServer(t, backend, 10)
				older := deltaMPRChange(t, 1, 1, "description:= older", "mail:= alice@example.com")
				newer := deltaMPRChange(t, 2, 2, "description:= newer", "sn:= Changed")
				if reverse {
					deltaMPRApply(t, instance, 2, newer)
					deltaMPRApply(t, instance, 1, older)
				} else {
					deltaMPRApply(t, instance, 1, older)
					deltaMPRApply(t, instance, 2, newer)
				}
				_, database := deltaCascadeUnitConfig(t, instance, 1)
				for attribute, want := range map[string][]string{
					"description": {"newer"}, "mail": {"alice@example.com"}, "sn": {"Changed"},
					"entryCSN":        {newer.GetAttributeValue("entryCSN")},
					"modifyTimestamp": {"20260908010102Z"}, "modifiersName": {"cn=provider-2,dc=example,dc=com"},
				} {
					assertSyncConsumerEntryValues(t, store, database.partition, deltaMPRTarget, attribute, want)
				}
				log := deltaMPRLog(t, instance)
				if len(log) != 2 {
					t.Fatalf("log count = %d, want 2", len(log))
				}
				for _, entry := range log {
					if entry.GetAttributeValue("entryCSN") == older.GetAttributeValue("entryCSN") {
						config, _ := deltaCascadeUnitConfig(t, instance, 1)
						got, err := parseSyncConsumerAccesslogOperation(instance.runtime.Load(), config, entry)
						if err != nil {
							t.Fatal(err)
						}
						want, err := parseSyncConsumerAccesslogOperation(instance.runtime.Load(), config, older)
						if err != nil {
							t.Fatal(err)
						}
						assertDeltaMPRModifications(t, got.modifications, want.modifications)
					}
				}
				// Relay the actual local accesslog to a fresh peer.
				relay, relayStore := newDeltaMPRServer(t, backend, 11)
				for _, entry := range log {
					deltaMPRApply(t, relay, 3, entry)
				}
				assertSyncConsumerEntryValues(t, relayStore, database.partition, deltaMPRTarget, "mail", []string{"alice@example.com"})
				assertSyncConsumerEntryValues(t, relayStore, database.partition, deltaMPRTarget, "description", []string{"newer"})
			})
		}
	}
}

func deltaMPRLog(t *testing.T, instance *Server) []*ldap.Entry {
	t.Helper()
	_, database := deltaCascadeUnitConfig(t, instance, 1)
	runtime := instance.runtime.Load()
	var entries []*ldap.Entry
	if err := instance.config.Store.View(context.Background(), func(reader storage.Reader) error {
		return readerForDatabase(reader, runtime.databases[database.accesslog.targetDatabaseIndex]).ForEach(func(entry directory.Entry) error {
			if len(entry.Values("reqType")) == 0 {
				return nil
			}
			attributes := make(map[string][]string)
			for _, attribute := range entry.Attributes {
				attributes[attribute.Description] = byteValuesToStrings(attribute.Values)
			}
			entries = append(entries, ldap.NewEntry(entry.DN, attributes))
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestDeltaMultiProviderConcurrentReplay(t *testing.T) {
	for _, backend := range []string{"memory", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			instance, store := newDeltaMPRServer(t, backend, 10)
			const peers = 12
			start := make(chan struct{})
			failures := make(chan error, peers*2)
			var workers sync.WaitGroup
			for peer := 1; peer <= peers; peer++ {
				change := deltaMPRChange(t, uint16(peer), peer, fmt.Sprintf("description:+ peer-%d", peer))
				for replay := 0; replay < 2; replay++ {
					config, _ := deltaCascadeUnitConfig(t, instance, peer+replay*peers)
					workers.Go(func() {
						<-start
						failures <- instance.applySyncConsumerAccesslogEntry(context.Background(), config, change, nil)
					})
				}
			}
			close(start)
			workers.Wait()
			close(failures)
			for err := range failures {
				if err != nil {
					t.Fatal(err)
				}
			}
			var want []string
			for peer := 1; peer <= peers; peer++ {
				want = append(want, fmt.Sprintf("peer-%d", peer))
			}
			entry := readStoredEntry(t, store, deltaMPRTarget)
			if got := byteValuesToStrings(entry.Values("description")); !equalStringSets(got, want) {
				t.Fatalf("concurrent values = %q, want %q", got, want)
			}
			if log := deltaMPRLog(t, instance); len(log) != peers {
				t.Fatalf("log count = %d, want %d", len(log), peers)
			}
		})
	}
}

func TestDeltaMultiProviderSoftDeleteUsesSchema(t *testing.T) {
	instance, store := newDeltaMPRServer(t, "memory", 10)
	deltaMPRApply(t, instance, 1, deltaMPRChange(t, 1, 1, "description:= Keep", "description:= REMOVE"))
	deltaMPRApply(t, instance, 2, deltaMPRChange(t, 2, 2, "description:- remove", "description:- absent"))
	_, database := deltaCascadeUnitConfig(t, instance, 1)
	assertSyncConsumerEntryValues(t, store, database.partition, deltaMPRTarget, "description", []string{"Keep"})
}

func TestDeltaMultiProviderPurgeFloorAndCookieSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delta.db")
	store, err := storage.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	instance := newDeltaMPRServerWithStore(t, store, 10)
	// The first row for SID 2 remains its minCSN. An older row from that
	// SID can arrive through another peer and be purged independently.
	newer := deltaMPRChange(t, 2, 4, "description:= newest")
	deltaMPRApply(t, instance, 2, newer)
	_, db := deltaCascadeUnitConfig(t, instance, 1)
	runtime := instance.runtime.Load()
	logDB := runtime.databases[db.accesslog.targetDatabaseIndex]
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		tx := writerForDatabase(writer, logDB)
		log := deltaMPRChange(t, 2, 3, "mail:= purged@example.com")
		entry := directory.Entry{DN: "reqStart=20000101000000.000000Z,cn=log"}
		entry.ReplaceValues("objectClass", stringValues("auditModify"))
		entry.ReplaceValues("reqStart", stringValues("20000101000000.000000Z"))
		entry.ReplaceValues("reqDN", stringValues(deltaMPRTarget))
		entry.ReplaceValues("reqType", stringValues("modify"))
		entry.ReplaceValues("reqResult", stringValues("0"))
		entry.ReplaceValues("entryCSN", stringValues(log.GetAttributeValue("entryCSN")))
		entry.ReplaceValues("reqMod", log.GetRawAttributeValues("reqMod"))
		return tx.Put(entry, false)
	}); err != nil {
		t.Fatal(err)
	}
	configuration := *db.accesslog
	configuration.purgeAge = time.Hour
	db.accesslog = &configuration
	if err := instance.purgeAccesslogDatabase(context.Background(), runtime, db, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(deltaMPRLog(t, instance)) != 1 {
		t.Fatal("purge did not retain exactly the newer row")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = storage.OpenBolt(path)
	if err != nil {
		t.Fatal(err)
	}
	instance, err = New(Config{Store: store, RootDN: syncTestRootDN, RootPassword: []byte(syncTestRootPassword)})
	if err != nil {
		t.Fatal(err)
	}
	config, _ := deltaCascadeUnitConfig(t, instance, 1)
	older := deltaMPRChange(t, 1, 2, "mail:= must-not-return@example.com")
	if err := instance.applySyncConsumerAccesslogEntry(context.Background(), config, older, nil); !errors.Is(err, errSyncConsumerAccesslogGap) {
		t.Fatalf("purged conflict error = %v", err)
	}
	committed, _ := deltaCascadeUnitConfig(t, instance, 2)
	cookie, err := instance.loadSyncConsumerCookie(context.Background(), committed)
	if err != nil || len(cookie) == 0 {
		t.Fatalf("committed cookie: %q %v", cookie, err)
	}
	_ = instance.syncConsumerAccesslogFailure(context.Background(), committed, errSyncConsumerAccesslogGap)
	assertSyncConsumerCookie(t, store, committed, cookie)
	deltaMPRApply(t, instance, 3, newer)
	if len(deltaMPRLog(t, instance)) != 1 {
		t.Fatal("restart replay logged a duplicate")
	}
}

func TestDeltaMultiProviderAddUUIDConflicts(t *testing.T) {
	instance, store := newDeltaMPRServer(t, "memory", 10)
	const dn = "uid=new,ou=people,dc=example,dc=com"
	add := deltaCascadeAddEntry(dn, "New", "20260908010201.000001Z#000000#001#000000")
	deltaMPRApply(t, instance, 1, add)
	deltaMPRApply(t, instance, 3, add)
	conflict := deltaCascadeAddEntry("uid=other,ou=people,dc=example,dc=com", "Other", "20260908010202.000001Z#000000#002#000000")
	config, db := deltaCascadeUnitConfig(t, instance, 2)
	if err := instance.applySyncConsumerAccesslogEntry(context.Background(), config, conflict, nil); !errors.Is(err, errSyncConsumerAccesslogGap) {
		t.Fatalf("existing UUID error = %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		target, _ := directory.ParseDN(dn)
		if err := writer.DeleteIn(db.partition, target); err != nil {
			return err
		}
		return advanceSyncTombstone(writer, db.partition, "10000000-0000-4000-8000-000000000001", mustOpenLDAPCSN(t, "20260908010203.000001Z#000000#00a#000000"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := instance.applySyncConsumerAccesslogEntry(context.Background(), config, conflict, nil); !errors.Is(err, errSyncConsumerAccesslogGap) {
		t.Fatalf("deleted UUID error = %v", err)
	}
	if len(deltaMPRLog(t, instance)) != 1 {
		t.Fatal("rejected UUID conflict created accesslog records")
	}
}

func TestDeltaMultiProviderFailureIsAtomic(t *testing.T) {
	for _, backend := range []string{"memory", "bbolt"} {
		for _, failure := range []string{"missing history", "purged history", "increment history", "increment", "rename", "delete", "missing CSN", "wrong CSN", "wrong UUID", "controls"} {
			t.Run(backend+"/"+failure, func(t *testing.T) {
				instance, store := newDeltaMPRServer(t, backend, 10)
				newer := deltaMPRChange(t, 2, 2, "description:= newer")
				deltaMPRApply(t, instance, 2, newer)
				older := deltaMPRChange(t, 1, 1, "mail:= must-not-commit@example.com")
				switch failure {
				case "increment":
					older = deltaMPRChange(t, 1, 1, "uidNumber:# 1")
				case "rename":
					older = syncConsumerAccesslogTestEntry("reqStart=20260908010101.000001Z,cn=log", deltaMPRTarget, "modrdn", older.GetAttributeValue("entryCSN"), nil, map[string][]string{"reqNewRDN": {"uid=renamed"}})
				case "delete":
					older = syncConsumerAccesslogTestEntry("reqStart=20260908010101.000001Z,cn=log", deltaMPRTarget, "delete", older.GetAttributeValue("entryCSN"), nil, nil)
				case "missing CSN":
					older = syncConsumerAccesslogTestEntry(older.DN, deltaMPRTarget, "modify", older.GetAttributeValue("entryCSN"), []string{"mail:= bad"}, nil)
				case "wrong CSN":
					older = syncConsumerAccesslogTestEntry(older.DN, deltaMPRTarget, "modify", older.GetAttributeValue("entryCSN"), []string{"entryCSN:= " + newer.GetAttributeValue("entryCSN")}, nil)
				case "wrong UUID":
					older.Attributes = append(older.Attributes, ldap.NewEntryAttribute("reqEntryUUID", []string{"00000000-0000-4000-8000-ffffffffffff"}))
				case "controls":
					older.Attributes = append(older.Attributes, ldap.NewEntryAttribute("reqControls", []string{"1.2.3 true"}))
				default:
					_, db := deltaCascadeUnitConfig(t, instance, 1)
					logDB := instance.runtime.Load().databases[db.accesslog.targetDatabaseIndex]
					log := deltaMPRLog(t, instance)[0]
					if err := store.Update(context.Background(), func(writer storage.Writer) error {
						tx := writerForDatabase(writer, logDB)
						dn, _ := directory.ParseDN(log.DN)
						if failure == "increment history" {
							entry, err := tx.Get(dn)
							if err != nil {
								return err
							}
							entry.ReplaceValues("reqMod", stringValues("uidNumber:# 1"))
							return tx.Put(entry, true)
						}
						if failure == "purged history" {
							container, err := tx.Get(db.accesslog.targetSuffix)
							if err != nil {
								return err
							}
							container.ReplaceValues("minCSN", stringValues(newer.GetAttributeValue("entryCSN")))
							if err := tx.Put(container, true); err != nil {
								return err
							}
						}
						return tx.Delete(dn)
					}); err != nil {
						t.Fatal(err)
					}
				}
				config, db := deltaCascadeUnitConfig(t, instance, 1)
				before := readStoredEntry(t, store, deltaMPRTarget)
				logBefore := deltaMPRLog(t, instance)
				err := instance.applySyncConsumerAccesslogEntry(context.Background(), config, older, nil)
				if !errors.Is(err, errSyncConsumerAccesslogGap) {
					t.Fatalf("error = %v, want fail-closed gap", err)
				}
				if after := readStoredEntry(t, store, deltaMPRTarget); !reflect.DeepEqual(before, after) {
					t.Fatal("failed replay changed entry")
				}
				if !reflect.DeepEqual(logBefore, deltaMPRLog(t, instance)) {
					t.Fatal("failed replay changed accesslog")
				}
				if err := store.View(context.Background(), func(reader storage.Reader) error {
					if _, err := reader.Metadata(syncConsumerCookieMetadataKey(config)); !errors.Is(err, storage.ErrMetadataNotFound) {
						return fmt.Errorf("cookie after failure: %v", err)
					}
					state, err := syncContextCSNs(reader, db.partition)
					if _, found := state[1]; found {
						return fmt.Errorf("failed CSN committed")
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestDeltaMultiProviderConflictMatrix(t *testing.T) {
	server, _ := newDeltaCascadeUnitServer(t)
	runtime := server.runtime.Load()
	current := directory.Entry{Attributes: []directory.Attribute{
		{Description: "description", Values: stringValues("X", "Y", "Z")},
	}}
	tests := []struct {
		name  string
		older syncConsumerAccesslogModification
		newer syncConsumerAccesslogModification
		want  []syncConsumerAccesslogModification
	}{
		{
			name:  "delete all then delete all",
			older: deltaMPRMod('-', "description"),
			newer: deltaMPRMod('-', "description"),
		},
		{
			name:  "delete all then delete X",
			older: deltaMPRMod('-', "description"),
			newer: deltaMPRMod('-', "description", "X"),
			want:  []syncConsumerAccesslogModification{deltaMPRMod('-', "description")},
		},
		{
			name:  "delete X then delete all",
			older: deltaMPRMod('-', "description", "X"),
			newer: deltaMPRMod('-', "description"),
		},
		{
			name:  "delete X then delete X",
			older: deltaMPRMod('-', "description", "X"),
			newer: deltaMPRMod('-', "description", "X"),
		},
		{
			name:  "delete X then delete Y",
			older: deltaMPRMod('-', "description", "X"),
			newer: deltaMPRMod('-', "description", "Y"),
			want:  []syncConsumerAccesslogModification{deltaMPRMod('-', "description", "X")},
		},
		{
			name:  "delete all then add X",
			older: deltaMPRMod('-', "description"),
			newer: deltaMPRMod('+', "description", "X"),
			want:  []syncConsumerAccesslogModification{deltaMPRMod('-', "description", "Y", "Z")},
		},
		{
			name:  "delete X then add X",
			older: deltaMPRMod('-', "description", "X"),
			newer: deltaMPRMod('+', "description", "X"),
		},
		{
			name:  "delete X then add Y",
			older: deltaMPRMod('-', "description", "X"),
			newer: deltaMPRMod('+', "description", "Y"),
			want:  []syncConsumerAccesslogModification{deltaMPRMod('-', "description", "X")},
		},
		{
			name:  "add X then delete all",
			older: deltaMPRMod('+', "description", "X"),
			newer: deltaMPRMod('-', "description"),
		},
		{
			name:  "add X then delete X",
			older: deltaMPRMod('+', "description", "X"),
			newer: deltaMPRMod('-', "description", "X"),
		},
		{
			name:  "add X then add X",
			older: deltaMPRMod('+', "description", "X"),
			newer: deltaMPRMod('+', "description", "X"),
		},
		{
			name:  "add X then add Y multi-valued",
			older: deltaMPRMod('+', "description", "X"),
			newer: deltaMPRMod('+', "description", "Y"),
			want:  []syncConsumerAccesslogModification{deltaMPRMod('+', "description", "X")},
		},
		{
			name:  "add X then add Y single-valued",
			older: deltaMPRMod('+', "uidNumber", "32"),
			newer: deltaMPRMod('+', "uidNumber", "64"),
		},
		{
			name:  "newer replace drops older attribute modification",
			older: deltaMPRMod('+', "description", "X"),
			newer: deltaMPRMod('=', "description", "Y"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveSyncConsumerDeltaMultiProviderMods(
				runtime,
				current,
				[]syncConsumerAccesslogModification{test.older},
				[]syncConsumerAccesslogModification{test.newer},
			)
			if err != nil {
				t.Fatalf("resolve conflict: %v", err)
			}
			assertDeltaMPRModifications(t, got, test.want)
		})
	}
}

func TestDeltaMultiProviderReplaceSplitAndOperationalAttributes(t *testing.T) {
	server, _ := newDeltaCascadeUnitServer(t)
	runtime := server.runtime.Load()
	const csn = "20260908010101.000001Z#000000#001#000000"
	got := duplicateOlderSyncConsumerAccesslogModifications(
		runtime,
		[]syncConsumerAccesslogModification{
			deltaMPRMod('=', "description", "one", "two"),
			deltaMPRMod('=', "mail"),
			deltaMPRMod('=', "entryCSN", csn),
			deltaMPRMod('=', "modifiersName", syncTestRootDN),
			deltaMPRMod('=', "modifyTimestamp", "20260908010101Z"),
		},
	)
	want := []syncConsumerAccesslogModification{
		deltaMPRMod('-', "description"),
		deltaMPRMod('+', "description", "one", "two"),
		deltaMPRMod('-', "mail"),
	}
	assertDeltaMPRModifications(t, got, want)
}

func TestDeltaMultiProviderConflictUsesSchemaEquality(t *testing.T) {
	server, _ := newDeltaCascadeUnitServer(t)
	runtime := server.runtime.Load()
	tests := []struct {
		name        string
		description string
		older       string
		newer       string
	}{
		{name: "case ignore", description: "description", older: "OutStanding", newer: "outstanding"},
		{name: "attribute OID", description: "2.5.4.3", older: " Alice  Smith ", newer: "alice smith"},
		{name: "language option", description: "description;lang-en", older: "English", newer: "english"},
		{name: "DN", description: "member", older: "CN=Alice,OU=People,DC=example,DC=com", newer: "cn=alice,ou=people,dc=example,dc=com"},
		{name: "integer", description: "uidNumber", older: "00042", newer: "42"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveSyncConsumerDeltaMultiProviderMods(
				runtime,
				directory.Entry{},
				[]syncConsumerAccesslogModification{
					deltaMPRMod('+', test.description, test.older),
				},
				[]syncConsumerAccesslogModification{
					deltaMPRMod('+', test.description, test.newer),
				},
			)
			if err != nil {
				t.Fatalf("resolve conflict: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("schema-equal values were not removed: %#v", got)
			}
		})
	}

	got, err := resolveSyncConsumerDeltaMultiProviderMods(
		runtime,
		directory.Entry{},
		[]syncConsumerAccesslogModification{deltaMPRRawMod('+', "jpegPhoto", []byte{0x00, 0xff})},
		[]syncConsumerAccesslogModification{deltaMPRRawMod('+', "jpegPhoto", []byte{0x00, 0xfe})},
	)
	if err != nil {
		t.Fatalf("resolve binary conflict: %v", err)
	}
	if len(got) != 1 || !bytes.Equal(got[0].values[0], []byte{0x00, 0xff}) {
		t.Fatalf("distinct binary value was removed: %#v", got)
	}
}

func deltaMPRMod(
	operation byte,
	description string,
	values ...string,
) syncConsumerAccesslogModification {
	return syncConsumerAccesslogModification{
		description: description,
		operation:   operation,
		values:      stringValues(values...),
	}
}

func deltaMPRRawMod(
	operation byte,
	description string,
	values ...[]byte,
) syncConsumerAccesslogModification {
	return syncConsumerAccesslogModification{
		description: description,
		operation:   operation,
		values:      cloneSyncConsumerAccesslogValues(values),
	}
}

func assertDeltaMPRModifications(
	t *testing.T,
	got,
	want []syncConsumerAccesslogModification,
) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("modification count = %d, want %d: %#v", len(got), len(want), got)
	}
	for index := range want {
		if got[index].operation != want[index].operation ||
			got[index].description != want[index].description ||
			len(got[index].values) != len(want[index].values) {
			t.Fatalf("modification[%d] = %#v, want %#v", index, got[index], want[index])
		}
		for valueIndex := range want[index].values {
			if !bytes.Equal(got[index].values[valueIndex], want[index].values[valueIndex]) {
				t.Fatalf(
					"modification[%d].values[%d] = %q, want %q",
					index,
					valueIndex,
					got[index].values[valueIndex],
					want[index].values[valueIndex],
				)
			}
		}
	}
}
