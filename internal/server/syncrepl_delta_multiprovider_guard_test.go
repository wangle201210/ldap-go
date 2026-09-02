package server

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const deltaMultiProviderUnsupportedDiagnostic = "cannot combine delta-syncrepl syncdata=accesslog with writable " +
	"olcMultiProvider/olcMirrorMode: attribute-level conflict merging is not supported"

func TestDeltaMultiProviderGuardRejectsStartupAndOfflineValidation(t *testing.T) {
	for _, backend := range []string{"memory", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			for _, mode := range []string{"olcMultiProvider", "olcMirrorMode"} {
				t.Run(mode, func(t *testing.T) {
					store := newDeltaMultiProviderGuardStore(t, backend)
					syncValue := deltaMultiProviderGuardSyncreplValue(
						0, 1, "dc=example,dc=com", true,
					)
					seedDeltaMultiProviderGuardConfiguration(
						t, store, mode, []string{syncValue},
					)

					_, err := ValidateConfiguration(
						context.Background(),
						Config{Store: store},
					)
					assertDeltaMultiProviderConfigurationError(t, err)

					instance, err := New(Config{Store: store})
					if instance != nil {
						instance.closeSQLBackends()
					}
					assertDeltaMultiProviderConfigurationError(t, err)

					entry := readStoredEntry(
						t, store, "olcDatabase={1}mdb,cn=config",
					)
					if got := byteValuesToStrings(entry.Values(mode)); !slices.Equal(got, []string{"TRUE"}) {
						t.Fatalf("persisted %s = %q, want TRUE", mode, got)
					}
					if got := byteValuesToStrings(entry.Values("olcSyncrepl")); !slices.Equal(got, []string{syncValue}) {
						t.Fatalf("persisted olcSyncrepl = %q, want %q", got, syncValue)
					}
				})
			}
		})
	}
}

func TestDeltaMultiProviderGuardAllowsSupportedCombinations(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		syncValues []string
	}{
		{
			name: "single-provider delta",
			syncValues: []string{deltaMultiProviderGuardSyncreplValue(
				0, 1, "dc=example,dc=com", true,
			)},
		},
		{
			name: "single-provider standard",
			syncValues: []string{deltaMultiProviderGuardSyncreplValue(
				0, 1, "dc=example,dc=com", false,
			)},
		},
		{
			name: "multi-provider standard",
			mode: "olcMultiProvider",
			syncValues: []string{deltaMultiProviderGuardSyncreplValue(
				0, 1, "dc=example,dc=com", false,
			)},
		},
		{
			name: "mirror-mode standard",
			mode: "olcMirrorMode",
			syncValues: []string{deltaMultiProviderGuardSyncreplValue(
				0, 1, "dc=example,dc=com", false,
			)},
		},
	}

	for _, backend := range []string{"memory", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					store := newDeltaMultiProviderGuardStore(t, backend)
					seedDeltaMultiProviderGuardConfiguration(
						t, store, test.mode, test.syncValues,
					)
					if _, err := ValidateConfiguration(
						context.Background(), Config{Store: store},
					); err != nil {
						t.Fatalf("ValidateConfiguration(): %v", err)
					}
					instance, err := New(Config{Store: store})
					if err != nil {
						t.Fatalf("New(): %v", err)
					}
					instance.closeSQLBackends()
				})
			}
		})
	}
}

func TestDeltaMultiProviderGuardOnlineDatabaseAddRollsBack(t *testing.T) {
	for _, backend := range []string{"memory", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			for _, mode := range []string{"olcMultiProvider", "olcMirrorMode"} {
				t.Run(mode, func(t *testing.T) {
					store := newDeltaMultiProviderGuardStore(t, backend)
					seedDeltaMultiProviderGuardConfiguration(t, store, "", nil)
					instance, address, stop := startDeltaMultiProviderGuardServer(t, store)
					defer stop()
					client := bindDeltaMultiProviderGuardConfigClient(t, address)
					defer client.Close()
					activeRuntime := instance.runtime.Load()

					const databaseDN = "olcDatabase={2}mdb,cn=config"
					request := ldap.NewAddRequest(databaseDN, nil)
					request.Attribute("objectClass", []string{"olcDatabaseConfig"})
					request.Attribute("olcDatabase", []string{"{2}mdb"})
					request.Attribute("olcSuffix", []string{"dc=blocked,dc=test"})
					request.Attribute("olcSyncrepl", []string{
						deltaMultiProviderGuardSyncreplValue(
							0, 2, "dc=blocked,dc=test", true,
						),
					})
					request.Attribute(mode, []string{"TRUE"})
					err := client.Add(request)
					assertDeltaMultiProviderLDAPError(t, err)
					if instance.runtime.Load() != activeRuntime {
						t.Fatal("failed database Add activated a new runtime snapshot")
					}
					assertStoredEntryMissing(t, store, databaseDN)
				})
			}
		})
	}
}

func TestDeltaMultiProviderGuardOnlineDatabaseModifyRollsBack(t *testing.T) {
	tests := []struct {
		name        string
		initialMode string
		initialSync []string
		modify      func(*ldap.ModifyRequest)
		wantMode    string
	}{
		{
			name: "enable multi-provider on delta",
			initialSync: []string{deltaMultiProviderGuardSyncreplValue(
				0, 1, "dc=example,dc=com", true,
			)},
			modify: func(request *ldap.ModifyRequest) {
				request.Add("olcMultiProvider", []string{"TRUE"})
			},
			wantMode: "olcMultiProvider",
		},
		{
			name: "enable mirror mode on delta",
			initialSync: []string{deltaMultiProviderGuardSyncreplValue(
				0, 1, "dc=example,dc=com", true,
			)},
			modify: func(request *ldap.ModifyRequest) {
				request.Add("olcMirrorMode", []string{"TRUE"})
			},
			wantMode: "olcMirrorMode",
		},
		{
			name:        "add delta consumer to multi-provider",
			initialMode: "olcMultiProvider",
			initialSync: []string{deltaMultiProviderGuardSyncreplValue(
				0, 1, "dc=example,dc=com", false,
			)},
			modify: func(request *ldap.ModifyRequest) {
				request.Add("olcSyncrepl", []string{
					deltaMultiProviderGuardSyncreplValue(
						1, 2, "dc=example,dc=com", true,
					),
				})
			},
			wantMode: "olcMultiProvider",
		},
		{
			name:        "replace standard consumer with delta",
			initialMode: "olcMirrorMode",
			initialSync: []string{deltaMultiProviderGuardSyncreplValue(
				0, 1, "dc=example,dc=com", false,
			)},
			modify: func(request *ldap.ModifyRequest) {
				request.Replace("olcSyncrepl", []string{
					deltaMultiProviderGuardSyncreplValue(
						0, 1, "dc=example,dc=com", true,
					),
				})
			},
			wantMode: "olcMirrorMode",
		},
	}

	for _, backend := range []string{"memory", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					store := newDeltaMultiProviderGuardStore(t, backend)
					seedDeltaMultiProviderGuardConfiguration(
						t, store, test.initialMode, test.initialSync,
					)
					instance, address, stop := startDeltaMultiProviderGuardServer(t, store)
					defer stop()
					client := bindDeltaMultiProviderGuardConfigClient(t, address)
					defer client.Close()
					activeRuntime := instance.runtime.Load()

					const databaseDN = "olcDatabase={1}mdb,cn=config"
					request := ldap.NewModifyRequest(databaseDN, nil)
					test.modify(request)
					err := client.Modify(request)
					assertDeltaMultiProviderLDAPError(t, err)
					if instance.runtime.Load() != activeRuntime {
						t.Fatal("failed database Modify activated a new runtime snapshot")
					}

					entry := readStoredEntry(t, store, databaseDN)
					if got := byteValuesToStrings(entry.Values("olcSyncrepl")); !slices.Equal(got, test.initialSync) {
						t.Fatalf("persisted olcSyncrepl after rollback = %q, want %q", got, test.initialSync)
					}
					if test.initialMode == "" {
						if got := entry.Values(test.wantMode); len(got) != 0 {
							t.Fatalf("persisted %s after rollback = %q, want absent", test.wantMode, got)
						}
					} else if got := byteValuesToStrings(entry.Values(test.initialMode)); !slices.Equal(got, []string{"TRUE"}) {
						t.Fatalf("persisted %s after rollback = %q, want TRUE", test.initialMode, got)
					}
				})
			}
		})
	}
}

func TestOpenLDAP2613DeltaMultiProviderConflictSourceContract(t *testing.T) {
	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Skip("OPENLDAP_SOURCE must name the pinned OpenLDAP 2.6.13 checkout")
	}
	scriptPath := filepath.Join(
		source, "tests", "scripts", "test063-delta-multiprovider",
	)
	script, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read pinned OpenLDAP test063: %v", err)
	}
	const wantScriptHash = "14f9ec183ae25387f4c51b517151f95ba26a6e98f6899b3ad1442b089e10ff38"
	if got := fmt.Sprintf("%x", sha256.Sum256(script)); got != wantScriptHash {
		t.Fatalf("pinned OpenLDAP test063 SHA-256 = %s, want %s", got, wantScriptHash)
	}

	syncreplPath := filepath.Join(source, "servers", "slapd", "syncrepl.c")
	syncrepl, err := os.ReadFile(syncreplPath)
	if err != nil {
		t.Fatalf("read pinned OpenLDAP syncrepl.c: %v", err)
	}
	text := string(syncrepl)
	for _, anchor := range []string{
		"/* delta-mpr overlay handler */",
		"syncrepl_op_modify",
		"Find all mods to this reqDN newer than the mod stamp.",
		"(&(entryCSN>=%s)(reqDN=%s)%s)",
		"SLAP_MULTIPROVIDER( op->o_bd )",
	} {
		if !strings.Contains(text, anchor) {
			t.Fatalf("pinned OpenLDAP syncrepl.c lacks %q", anchor)
		}
	}
}

func newDeltaMultiProviderGuardStore(t *testing.T, backend string) storage.Store {
	t.Helper()
	switch backend {
	case "memory":
		store := storage.NewMemory()
		t.Cleanup(func() { _ = store.Close() })
		return store
	case "bbolt":
	default:
		t.Fatalf("unknown storage backend %q", backend)
	}
	store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "directory.db"))
	if err != nil {
		t.Fatalf("OpenBolt(): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func seedDeltaMultiProviderGuardConfiguration(
	t *testing.T,
	store storage.Store,
	mode string,
	syncValues []string,
) {
	t.Helper()
	seedOnlineConfiguration(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		globalDN, err := directory.ParseDN("cn=config")
		if err != nil {
			return err
		}
		global, err := writer.Get(globalDN)
		if err != nil {
			return err
		}
		global.ReplaceValues("olcServerID", stringValues("1"))
		if err := writer.Put(global, true); err != nil {
			return err
		}

		databaseDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		database, err := writer.Get(databaseDN)
		if err != nil {
			return err
		}
		database.ReplaceValues("olcSyncrepl", stringValues(syncValues...))
		if mode != "" {
			database.ReplaceValues(mode, stringValues("TRUE"))
		}
		return writer.Put(database, true)
	}); err != nil {
		t.Fatalf("seed delta multi-provider guard configuration: %v", err)
	}
}

func deltaMultiProviderGuardSyncreplValue(
	order,
	rid int,
	base string,
	delta bool,
) string {
	value := fmt.Sprintf(
		`{%d}rid=%03d provider=ldap://127.0.0.1:1 searchbase=%q type=refreshOnly`,
		order,
		rid,
		base,
	)
	if delta {
		value += ` logbase="cn=log" ` +
			`logfilter="(&(objectClass=auditWriteObject)(reqResult=0))" ` +
			`syncdata=accesslog`
	}
	return value
}

func startDeltaMultiProviderGuardServer(
	t *testing.T,
	store storage.Store,
) (*Server, string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	instance, err := New(Config{Store: store})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- instance.Serve(ctx, listener)
	}()
	stop := func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve(): %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	}
	return instance, fmt.Sprint(listener.Addr()), stop
}

func bindDeltaMultiProviderGuardConfigClient(
	t *testing.T,
	address string,
) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		_ = client.Close()
		t.Fatalf("Bind(config): %v", err)
	}
	return client
}

func assertDeltaMultiProviderConfigurationError(t *testing.T, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), deltaMultiProviderUnsupportedDiagnostic) {
		t.Fatalf(
			"configuration error = %v, want %q",
			err,
			deltaMultiProviderUnsupportedDiagnostic,
		)
	}
}

func assertDeltaMultiProviderLDAPError(t *testing.T, err error) {
	t.Helper()
	assertLDAPResultCode(t, err, ldap.LDAPResultConstraintViolation)
	assertDeltaMultiProviderConfigurationError(t, err)
}
