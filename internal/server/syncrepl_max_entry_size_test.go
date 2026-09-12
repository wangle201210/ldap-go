package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	syncEntryLimitFirstCSN = "20260912010101.000001Z#000000#001#000000"
	syncEntryLimitLargeCSN = "20260912010102.000001Z#000000#001#000000"
	syncEntryLimitLaterCSN = "20260912010103.000001Z#000000#001#000000"
)

func TestSyncreplMaxEntrySizeTCP(t *testing.T) {
	for _, backend := range []string{"memory", "bbolt"} {
		for _, mode := range []string{"default", "accesslog"} {
			for _, operation := range []string{"add", "modify", "rename"} {
				t.Run(backend+"/"+mode+"/"+operation, func(t *testing.T) {
					store, restart := syncEntryLimitStore(t, backend)
					seedSyncEntryLimitConsumer(t, store, mode)
					if operation == "rename" {
						setUnsupportedRuntimeConfigurationAttribute(t, store, entryLimitConfigDN, "olcDbMaxEntrySize", "16384")
					}
					instance, config := loadSyncEntryLimitConsumer(t, store)
					firstCookie := syncConsumerAccesslogTestCookie(syncEntryLimitFirstCSN)
					largeCookie := syncConsumerAccesslogTestCookie(syncEntryLimitLargeCSN)
					laterCookie := syncConsumerAccesslogTestCookie(syncEntryLimitLaterCSN)
					accepted := syncEntryLimitEntry("accepted", syncEntryLimitFirstCSN, "small")
					if operation == "rename" {
						accepted.ReplaceValues("description", stringValues(strings.Repeat("x", 4096)))
					}
					bootstrap := []syncEntryLimitSearch{{
						base:    config.searchBase.String(),
						entries: []syncEntryLimitResponse{{accepted, ldapwire.SyncStateAdd, firstCookie}},
						done:    firstCookie,
					}}
					if mode == "accesslog" {
						bootstrap = append(bootstrap, syncEntryLimitSearch{base: "cn=log", cookie: firstCookie, done: firstCookie})
					}
					if err := runSyncEntryLimitTCP(t, instance, config, bootstrap...); err != nil {
						t.Fatalf("initial refresh: %v", err)
					}
					assertSyncEntryLimitState(t, store, config, firstCookie, accepted)
					if operation == "rename" {
						setSyncEntryLimit(t, store, "1024")
						instance, config = loadSyncEntryLimitConsumer(t, store)
					}

					large := syncEntryLimitEntry("large", syncEntryLimitLargeCSN, strings.Repeat("x", 4096))
					state := ldapwire.SyncStateAdd
					if operation != "add" {
						large = accepted.Clone()
						large.ReplaceValues("description", stringValues(strings.Repeat("x", 4096)))
						large.ReplaceValues("entryCSN", stringValues(syncEntryLimitLargeCSN))
						state = ldapwire.SyncStateModify
						if operation == "rename" {
							large.DN = "uid=renamed,ou=people,dc=example,dc=com"
							large.ReplaceValues("uid", stringValues("renamed"))
						}
					}
					later := syncEntryLimitEntry("later", syncEntryLimitLaterCSN, "must wait")
					search := syncEntryLimitSearch{
						base: config.searchBase.String(), cookie: firstCookie,
						entries: []syncEntryLimitResponse{{large, state, largeCookie}, {later, ldapwire.SyncStateAdd, laterCookie}},
						done:    laterCookie,
					}
					if mode == "accesslog" {
						search.base = "cn=log"
						search.entries[0].entry = syncEntryLimitLog(large, operation, accepted.DN)
						search.entries[1].entry = syncEntryLimitLog(later, "add", "")
					}
					for attempt := 0; attempt < 2; attempt++ {
						err := runSyncEntryLimitTCP(t, instance, config, search)
						if failure := asOperationFailure(err); failure == nil || failure.result.Code != ldapwire.ResultAdminLimitExceeded {
							t.Errorf("oversized %s: %v, want adminLimitExceeded", operation, err)
						}
						assertSyncEntryLimitState(t, store, config, firstCookie, accepted)
						assertSyncConsumerMissingEntry(t, store, config.partition, later.DN)
						if operation != "modify" {
							assertSyncConsumerMissingEntry(t, store, config.partition, large.DN)
						}
						if mode == "accesslog" {
							complete, err := instance.syncConsumerAccesslogBootstrapComplete(context.Background(), config)
							if err != nil || !complete {
								t.Fatalf("size rejection invalidated bootstrap: complete=%v, err=%v", complete, err)
							}
						}
						store = restart()
						instance, config = loadSyncEntryLimitConsumer(t, store)
						assertSyncEntryLimitState(t, store, config, firstCookie, accepted)
					}

					setSyncEntryLimit(t, store, "16384")
					store = restart()
					instance, config = loadSyncEntryLimitConsumer(t, store)
					if config.entryLimit.bytes != 16384 {
						t.Fatalf("restarted consumer limit = %d", config.entryLimit.bytes)
					}
					if err := runSyncEntryLimitTCP(t, instance, config, search); err != nil {
						t.Fatalf("retry after limit increase: %v", err)
					}
					assertSyncEntryLimitState(t, store, config, laterCookie, large, later)
					if operation == "rename" {
						assertSyncConsumerMissingEntry(t, store, config.partition, accepted.DN)
					}
					store = restart()
					_, config = loadSyncEntryLimitConsumer(t, store)
					assertSyncEntryLimitState(t, store, config, laterCookie, large, later)
				})
			}
		}
	}
}

func TestSyncreplMaxEntrySizeBootstrapTCP(t *testing.T) {
	for _, backend := range []string{"memory", "bbolt"} {
		for _, mode := range []string{"default", "accesslog"} {
			t.Run(backend+"/"+mode, func(t *testing.T) {
				store, restart := syncEntryLimitStore(t, backend)
				seedSyncEntryLimitConsumer(t, store, mode)
				instance, config := loadSyncEntryLimitConsumer(t, store)
				accepted := syncEntryLimitEntry("accepted", syncEntryLimitFirstCSN, "small")
				large := syncEntryLimitEntry("large", syncEntryLimitLargeCSN, strings.Repeat("x", 4096))
				firstCookie := syncConsumerAccesslogTestCookie(syncEntryLimitFirstCSN)
				largeCookie := syncConsumerAccesslogTestCookie(syncEntryLimitLargeCSN)
				search := syncEntryLimitSearch{
					base:    config.searchBase.String(),
					entries: []syncEntryLimitResponse{{accepted, ldapwire.SyncStateAdd, firstCookie}, {large, ldapwire.SyncStateAdd, largeCookie}},
					done:    largeCookie,
				}
				err := runSyncEntryLimitTCP(t, instance, config, search)
				if failure := asOperationFailure(err); failure == nil || failure.result.Code != ldapwire.ResultAdminLimitExceeded {
					t.Fatalf("oversized bootstrap entry: %v", err)
				}
				assertSyncEntryLimitState(t, store, config, firstCookie, accepted)
				assertSyncConsumerMissingEntry(t, store, config.partition, large.DN)
				if mode == "accesslog" {
					complete, err := instance.syncConsumerAccesslogBootstrapComplete(context.Background(), config)
					if err != nil || complete {
						t.Fatalf("failed bootstrap complete=%v, err=%v", complete, err)
					}
				}
				setSyncEntryLimit(t, store, "16384")
				store = restart()
				instance, config = loadSyncEntryLimitConsumer(t, store)
				assertSyncEntryLimitState(t, store, config, firstCookie, accepted)
				searches := []syncEntryLimitSearch{search}
				if mode == "accesslog" {
					// An incomplete bootstrap must restart the full refresh with no cookie.
					searches = append(searches, syncEntryLimitSearch{base: "cn=log", cookie: largeCookie, done: largeCookie})
				} else {
					searches[0].cookie = firstCookie
				}
				if err := runSyncEntryLimitTCP(t, instance, config, searches...); err != nil {
					t.Fatalf("retry bootstrap: %v", err)
				}
				assertSyncEntryLimitState(t, store, config, largeCookie, accepted, large)
			})
		}
	}
}

func syncEntryLimitStore(t *testing.T, backend string) (storage.Store, func() storage.Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "syncrepl-entry-limit.db")
	var store storage.Store
	open := func() {
		if backend == "memory" {
			store = storage.NewMemory()
			return
		}
		var err error
		store, err = storage.OpenBolt(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	open()
	t.Cleanup(func() { _ = store.Close() })
	return store, func() storage.Store {
		if backend == "bbolt" {
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			open()
		}
		return store
	}
}

func seedSyncEntryLimitConsumer(t *testing.T, store storage.Store, mode string) {
	t.Helper()
	seedEntryLimit(t, store, "1024", true)
	value := `rid=001 provider=ldap://127.0.0.1:1 bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret searchbase="dc=example,dc=com" type=refreshOnly schemachecking=on`
	if mode == "accesslog" {
		value += ` syncdata=accesslog logbase="cn=log" logfilter="(&(objectClass=auditWriteObject)(reqResult=0))"`
	}
	setUnsupportedRuntimeConfigurationAttribute(t, store, entryLimitConfigDN, "olcSyncrepl", value)
}

func loadSyncEntryLimitConsumer(t *testing.T, store storage.Store) (*Server, syncConsumerConfig) {
	t.Helper()
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	configs := activeSyncConsumerConfigs(instance.runtime.Load())
	if len(configs) != 1 || configs[0].entryLimit.bytes == 0 || configs[0].entryLimit.schema == nil {
		t.Fatalf("consumer did not load database entry limit: %+v", configs)
	}
	return instance, configs[0]
}

func setSyncEntryLimit(t *testing.T, store storage.Store, limit string) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		config := storage.WriterInPartition(writer, storage.OpenLDAPConfigPartition)
		dn, err := directory.ParseDN(entryLimitConfigDN)
		if err != nil {
			return err
		}
		entry, err := config.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcDbMaxEntrySize", stringValues(limit))
		return config.Put(entry, true)
	}); err != nil {
		t.Fatal(err)
	}
}

func syncEntryLimitEntry(uid, csn, description string) directory.Entry {
	entry := deltaBootstrapEntry(uid, csn)
	entry.ReplaceValues("entryUUID", stringValues(uuid.NewSHA1(uuid.NameSpaceOID, []byte(entry.DN)).String()))
	entry.ReplaceValues("description", stringValues(description))
	return entry
}

func syncEntryLimitLog(entry directory.Entry, operation, oldDN string) directory.Entry {
	csn := string(entry.Values("entryCSN")[0])
	log := directory.Entry{DN: "reqStart=" + strings.Split(csn, "#")[0] + ",cn=log"}
	log.ReplaceValues("objectClass", stringValues("auditWriteObject"))
	log.ReplaceValues("entryCSN", stringValues(csn))
	log.ReplaceValues("entryUUID", stringValues(uuid.NewSHA1(uuid.NameSpaceOID, []byte(log.DN)).String()))
	log.ReplaceValues("reqDN", stringValues(entry.DN))
	log.ReplaceValues("reqType", stringValues(operation))
	log.ReplaceValues("reqResult", stringValues("0"))
	var mods []string
	switch operation {
	case "add":
		for _, attr := range entry.Attributes {
			for _, value := range attr.Values {
				mods = append(mods, attr.Description+":+ "+string(value))
			}
		}
	case "modify":
		mods = []string{"description:= " + string(entry.Values("description")[0]), "entryCSN:= " + csn}
	case "rename":
		log.ReplaceValues("reqType", stringValues("modrdn"))
		log.ReplaceValues("reqDN", stringValues(oldDN))
		log.ReplaceValues("reqNewRDN", stringValues("uid=renamed"))
		log.ReplaceValues("reqDeleteOldRDN", stringValues("TRUE"))
		mods = []string{"entryCSN:= " + csn}
	}
	log.ReplaceValues("reqMod", stringValues(mods...))
	return log
}

// Check entry contents, operational attributes, and the checkpoint in one read transaction.
func assertSyncEntryLimitState(t *testing.T, store storage.Store, config syncConsumerConfig, cookie []byte, entries ...directory.Entry) {
	t.Helper()
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		gotCookie, err := reader.Metadata(syncConsumerCookieMetadataKey(config))
		if err != nil || !bytes.Equal(gotCookie, cookie) {
			return fmt.Errorf("cookie = %q, want %q: %v", gotCookie, cookie, err)
		}
		contextCSNs, err := syncContextCSNs(reader, config.partition)
		if err != nil {
			return err
		}
		if got := contextCSNs[1].raw; got != parseOpenLDAPSyncCookie(cookie).csns[1].raw {
			return fmt.Errorf("contextCSN = %q, inconsistent with cookie %q", got, cookie)
		}
		content := syncConsumerReader(reader, nil, config)
		for _, want := range entries {
			dn, err := syncConsumerParseDN(content, want.DN)
			if err != nil {
				return err
			}
			got, err := content.Get(dn)
			want = want.Clone()
			byDescription := func(a, b directory.Attribute) int { return strings.Compare(a.Description, b.Description) }
			slices.SortFunc(got.Attributes, byDescription)
			slices.SortFunc(want.Attributes, byDescription)
			if err != nil || !got.Equal(want) {
				return fmt.Errorf("entry %s differs from expected contents (entryCSN=%q, description bytes=%d): %v", want.DN, got.Values("entryCSN"), len(bytes.Join(got.Values("description"), nil)), err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type syncEntryLimitResponse struct {
	entry  directory.Entry
	state  ldapwire.SyncState
	cookie []byte
}

type syncEntryLimitSearch struct {
	base    string
	cookie  []byte
	entries []syncEntryLimitResponse
	done    []byte
}

func runSyncEntryLimitTCP(t *testing.T, instance *Server, config syncConsumerConfig, searches ...syncEntryLimitSearch) error {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	providerDone := make(chan error, 1)
	go func() {
		providerDone <- serveSyncEntryLimitTCP(listener, searches)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = instance.runSyncConsumerCycle(ctx, config, "ldap://"+listener.Addr().String())
	_ = listener.Close()
	if providerErr := <-providerDone; providerErr != nil {
		t.Fatalf("TCP provider: %v (consumer: %v)", providerErr, err)
	}
	return err
}

func serveSyncEntryLimitTCP(listener net.Listener, searches []syncEntryLimitSearch) error {
	connection, err := listener.Accept()
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	bind, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
	if err != nil {
		return err
	}
	if _, ok := bind.Request.(ldapwire.BindRequest); !ok {
		return fmt.Errorf("request = %T, want Bind", bind.Request)
	}
	if err := ldapwire.Write(connection, ldapwire.EncodeBindResponse(bind.ID, ldapwire.Result{Code: ldapwire.ResultSuccess}, nil)); err != nil {
		return err
	}
	for _, search := range searches {
		message, err := ldapwire.ReadMessage(connection, ldapwire.DefaultMaxMessageSize)
		if err != nil {
			return err
		}
		request, ok := message.Request.(ldapwire.SearchRequest)
		if !ok || request.BaseDN != search.base {
			return fmt.Errorf("search = %#v, want base %s", message.Request, search.base)
		}
		control, err := deltaBootstrapSyncRequest(message.Controls)
		if err != nil || !bytes.Equal(control.Cookie, search.cookie) {
			return fmt.Errorf("request cookie = %q, want %q: %v", control.Cookie, search.cookie, err)
		}
		var batch bytes.Buffer
		for _, response := range search.entries {
			identifier := uuid.MustParse(string(response.entry.Values("entryUUID")[0]))
			batch.Write(ldapwire.EncodeSearchResultEntry(message.ID, response.entry, []ldapwire.Control{{
				OID: syncStateControlOID, HasValue: true,
				Value: ldapwire.EncodeSyncStateValue(ldapwire.SyncStateValue{
					State: response.state, EntryUUID: ldapwire.SyncUUID(identifier),
					Cookie: response.cookie, HasCookie: len(response.cookie) != 0,
				}),
			}}))
		}
		batch.Write(ldapwire.EncodeSearchResultDone(message.ID, ldapwire.Result{Code: ldapwire.ResultSuccess}, []ldapwire.Control{{
			OID: syncDoneControlOID, HasValue: true,
			Value: ldapwire.EncodeSyncDoneValue(ldapwire.SyncDoneValue{
				Cookie: search.done, HasCookie: len(search.done) != 0, RefreshDeletes: true,
			}),
		}}))
		if _, err := batch.WriteTo(connection); err != nil {
			return err
		}
	}
	_, _ = io.Copy(io.Discard, connection)
	return nil
}
