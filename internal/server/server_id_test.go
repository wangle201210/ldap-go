package server

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestParseServerIDValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw       string
		wantID    uint16
		wantURI   string
		wantError bool
	}{
		{raw: "0", wantID: 0},
		{raw: "4095", wantID: 0xfff},
		{raw: "0xA5", wantID: 0x0a5},
		{
			raw:     "{3}12 ldap://ldap.example.com:1389/",
			wantID:  12,
			wantURI: "ldap://ldap.example.com:1389/",
		},
		{raw: "-1", wantError: true},
		{raw: "4096", wantError: true},
		{raw: "0x1000", wantError: true},
		{raw: "1 ldap://host/dc=example,dc=com", wantError: true},
		{raw: "1 ldap://one ldap://two", wantError: true},
		{raw: "{x}1", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			t.Parallel()
			got, err := parseServerIDValue(test.raw)
			if test.wantError {
				if err == nil {
					t.Fatalf("parseServerIDValue(%q) = %#v, want error", test.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseServerIDValue(%q): %v", test.raw, err)
			}
			if got.id != test.wantID || got.uri != test.wantURI {
				t.Fatalf(
					"parseServerIDValue(%q) = %#v, want ID %03x URI %q",
					test.raw,
					got,
					test.wantID,
					test.wantURI,
				)
			}
		})
	}
}

func TestLoadServerIDSelectsListenerURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		values        []string
		listenerURLs  []string
		want          uint16
		errorContains string
	}{
		{
			name:   "unqualified",
			values: []string{"0x12"},
			want:   0x12,
		},
		{
			name: "qualified exact",
			values: []string{
				"{0}1 ldap://ldap1.example.com:1389/",
				"{1}2 ldap://ldap2.example.com:1389/",
			},
			listenerURLs: []string{"ldap://ldap2.example.com:1389"},
			want:         2,
		},
		{
			name: "default port",
			values: []string{
				"1 ldap:///",
				"2 ldaps:///",
			},
			listenerURLs: []string{"ldap://:389"},
			want:         1,
		},
		{
			name: "equivalent listeners count once",
			values: []string{
				"1 ldap:///",
				"2 ldaps:///",
			},
			listenerURLs: []string{"ldap://:389", "ldap://0.0.0.0:389/"},
			want:         1,
		},
		{
			name:          "no URL match",
			values:        []string{"1 ldap://ldap1.example.com"},
			listenerURLs:  []string{"ldap://ldap2.example.com"},
			errorContains: "no URL matching",
		},
		{
			name: "multiple matches",
			values: []string{
				"1 ldap:///",
				"2 ldap://localhost/",
			},
			listenerURLs:  []string{"ldap:///"},
			errorContains: "multiple URLs matching",
		},
		{
			name:          "mixed forms",
			values:        []string{"1 ldap:///", "2"},
			listenerURLs:  []string{"ldap:///"},
			errorContains: "cannot mix",
		},
		{
			name:          "duplicate ID",
			values:        []string{"1 ldap://one/", "1 ldap://two/"},
			listenerURLs:  []string{"ldap://one/"},
			errorContains: "duplicate server ID",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Update(
				context.Background(),
				func(writer storage.Writer) error {
					return writer.Put(directory.Entry{
						DN: "cn=config",
						Attributes: []directory.Attribute{{
							Description: "olcServerID",
							Values:      stringValues(test.values...),
						}},
					}, false)
				},
			); err != nil {
				t.Fatalf("seed olcServerID: %v", err)
			}

			var got uint16
			err := store.View(
				context.Background(),
				func(reader storage.Reader) error {
					var err error
					got, err = loadServerID(reader, test.listenerURLs)
					return err
				},
			)
			if test.errorContains != "" {
				if err == nil || !strings.Contains(err.Error(), test.errorContains) {
					t.Fatalf("loadServerID() error = %v, want %q", err, test.errorContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadServerID(): %v", err)
			}
			if got != test.want {
				t.Fatalf("loadServerID() = %03x, want %03x", got, test.want)
			}
		})
	}
}

func TestStoredSyncContextCSNsPreserveMultipleServerIDs(t *testing.T) {
	t.Parallel()

	first, err := parseOpenLDAPCSN(
		"20260731010101.000001Z#000000#001#000000",
	)
	if err != nil {
		t.Fatalf("parse first CSN: %v", err)
	}
	second, err := parseOpenLDAPCSN(
		"20260731010101.000002Z#000000#002#000000",
	)
	if err != nil {
		t.Fatalf("parse second CSN: %v", err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	key := syncContextCSNMetadataKey("data")
	if err := store.Update(
		context.Background(),
		func(writer storage.Writer) error {
			if err := writer.SetMetadata(key, []byte(first.raw)); err != nil {
				return err
			}
			return advanceSyncContextCSN(writer, "data", second)
		},
	); err != nil {
		t.Fatalf("advanceSyncContextCSN(): %v", err)
	}

	var (
		state syncCSNState
		raw   []byte
	)
	if err := store.View(
		context.Background(),
		func(reader storage.Reader) error {
			var err error
			raw, err = reader.Metadata(key)
			if err != nil {
				return err
			}
			state, err = syncContextCSNs(reader, "data")
			return err
		},
	); err != nil {
		t.Fatalf("read context CSNs: %v", err)
	}
	if !strings.HasPrefix(string(raw), "[") {
		t.Fatalf("multi-SID metadata = %q, want encoded vector", raw)
	}
	if got := orderedSyncCSNs(state); !reflect.DeepEqual(
		got,
		[]string{first.raw, second.raw},
	) {
		t.Fatalf("context CSNs = %q", got)
	}
}

func TestNextCSNUsesConfiguredServerID(t *testing.T) {
	t.Parallel()

	server := &Server{}
	csn, err := parseOpenLDAPCSN(server.nextCSN(0x0a5))
	if err != nil {
		t.Fatalf("parse generated CSN: %v", err)
	}
	if csn.serverID != 0x0a5 {
		t.Fatalf("generated CSN server ID = %03x, want 0a5", csn.serverID)
	}
}

func TestConfiguredServerIDPersistsMultiSIDContextAcrossRestart(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)
	if err := store.Update(
		context.Background(),
		func(writer storage.Writer) error {
			return writer.Put(directory.Entry{
				DN: "cn=config",
				Attributes: []directory.Attribute{{
					Description: "olcServerID",
					Values:      stringValues("0xa5"),
				}},
			}, false)
		},
	); err != nil {
		t.Fatalf("seed olcServerID: %v", err)
	}

	start := func() (string, func()) {
		return startServer(t, store, Config{
			RootDN:       syncTestRootDN,
			RootPassword: []byte(syncTestRootPassword),
		})
	}
	address, stop := start()
	client := dialLDAPRoot(t, address)
	if err := client.Add(newPersonAddRequest("sid-one")); err != nil {
		t.Fatalf("Add(sid-one): %v", err)
	}
	client.Close()
	stop()

	first := readStoredEntry(
		t,
		store,
		"uid=sid-one,ou=people,dc=example,dc=com",
	)
	firstValues := first.Values("entryCSN")
	if len(firstValues) != 1 {
		t.Fatalf("first entryCSN = %q", firstValues)
	}
	firstCSN, err := parseOpenLDAPCSN(string(firstValues[0]))
	if err != nil {
		t.Fatalf("parse first entryCSN: %v", err)
	}
	if firstCSN.serverID != 0x0a5 {
		t.Fatalf("first entryCSN SID = %03x, want 0a5", firstCSN.serverID)
	}

	address, stop = start()
	defer stop()
	client = dialLDAPRoot(t, address)
	defer client.Close()
	if err := client.Add(newPersonAddRequest("sid-two")); err != nil {
		t.Fatalf("Add(sid-two): %v", err)
	}

	var state syncCSNState
	if err := store.View(
		context.Background(),
		func(reader storage.Reader) error {
			var err error
			state, err = syncContextCSNs(
				reader,
				configuredDatabasePartition("{1}mdb"),
			)
			return err
		},
	); err != nil {
		t.Fatalf("read context CSNs: %v", err)
	}
	if _, found := state[0]; !found {
		t.Fatalf("context CSNs = %q, missing imported SID 000", orderedSyncCSNs(state))
	}
	if local, found := state[0x0a5]; !found ||
		compareOpenLDAPCSN(local, firstCSN) <= 0 {
		t.Fatalf(
			"context CSNs = %q, missing newer local SID 0a5",
			orderedSyncCSNs(state),
		)
	}

	result, err := client.Search(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"contextCSN"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(contextCSN): %v", err)
	}
	values := result.Entries[0].GetAttributeValues("contextCSN")
	if len(values) != 2 {
		t.Fatalf("published contextCSN = %q, want two SIDs", values)
	}
}
