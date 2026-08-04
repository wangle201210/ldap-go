package server

import (
	"context"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	translucentTestBaseDN       = "ou=translucent,dc=example,dc=com"
	translucentTestMergedDN     = "uid=merged," + translucentTestBaseDN
	translucentTestRemoteOnlyDN = "uid=remote-only," + translucentTestBaseDN
	translucentTestStaleDN      = "uid=stale," + translucentTestBaseDN
	translucentTestFilterDN     = "uid=filter," + translucentTestBaseDN
	translucentTestOverlayDN    = "olcOverlay={0}translucent,olcDatabase={1}mdb,cn=config"
	translucentTestBackendDN    = "olcDatabase={0}ldap," + translucentTestOverlayDN
)

func TestMergeTranslucentEntryReplacesWholeAttribute(t *testing.T) {
	remote := directory.Entry{
		DN: translucentTestMergedDN,
		Attributes: []directory.Attribute{
			{Description: "cn", Values: stringValues("Remote")},
			{Description: "description", Values: stringValues("remote-one", "remote-two")},
		},
	}
	local := directory.Entry{
		DN: translucentTestMergedDN,
		Attributes: []directory.Attribute{
			{Description: "DESCRIPTION", Values: stringValues("local")},
			{Description: "telephoneNumber", Values: stringValues("200")},
		},
	}
	merged := mergeTranslucentEntry(remote, local)
	if got := stringsFromBytes(merged.Values("description")); len(got) != 1 || got[0] != "local" {
		t.Fatalf("merged description = %q", got)
	}
	if got := stringsFromBytes(merged.Values("cn")); len(got) != 1 || got[0] != "Remote" {
		t.Fatalf("merged cn = %q", got)
	}
	if got := stringsFromBytes(merged.Values("telephoneNumber")); len(got) != 1 || got[0] != "200" {
		t.Fatalf("merged telephoneNumber = %q", got)
	}
	if got := stringsFromBytes(remote.Values("description")); len(got) != 2 {
		t.Fatalf("remote entry was mutated: %q", got)
	}
}

func TestTranslucentRuntimeConfigurationValidation(t *testing.T) {
	tests := []struct {
		name    string
		entries []directory.Entry
	}{
		{
			name: "missing child backend",
			entries: []directory.Entry{
				translucentTestOverlayEntry(translucentTestOverlayDN, false),
			},
		},
		{
			name: "overlay lacks translucent object class",
			entries: []directory.Entry{
				{
					DN: translucentTestOverlayDN,
					Attributes: []directory.Attribute{
						{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
						{Description: "olcOverlay", Values: stringValues("{0}translucent")},
					},
				},
				translucentTestBackendEntry(
					translucentTestBackendDN,
					"{0}ldap",
					"ldap://127.0.0.1:389",
				),
			},
		},
		{
			name: "child lacks translucent object class",
			entries: []directory.Entry{
				translucentTestOverlayEntry(translucentTestOverlayDN, false),
				{
					DN: translucentTestBackendDN,
					Attributes: []directory.Attribute{
						{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
						{Description: "olcDatabase", Values: stringValues("{0}ldap")},
						{Description: "olcDbURI", Values: stringValues("ldap://127.0.0.1:389")},
					},
				},
			},
		},
		{
			name: "child lacks URI",
			entries: []directory.Entry{
				translucentTestOverlayEntry(translucentTestOverlayDN, false),
				{
					DN: translucentTestBackendDN,
					Attributes: []directory.Attribute{
						{
							Description: "objectClass",
							Values: stringValues(
								"olcDatabaseConfig",
								"olcTranslucentDatabase",
							),
						},
						{Description: "olcDatabase", Values: stringValues("{0}ldap")},
					},
				},
			},
		},
		{
			name: "child uses non ldap backend",
			entries: []directory.Entry{
				translucentTestOverlayEntry(translucentTestOverlayDN, false),
				translucentTestBackendEntry(
					translucentTestBackendDN,
					"{0}mdb",
					"ldap://127.0.0.1:389",
				),
			},
		},
		{
			name: "duplicate overlay",
			entries: []directory.Entry{
				translucentTestOverlayEntry(translucentTestOverlayDN, false),
				translucentTestBackendEntry(
					translucentTestBackendDN,
					"{0}ldap",
					"ldap://127.0.0.1:389",
				),
				translucentTestOverlayEntry(
					"olcOverlay={1}translucent,olcDatabase={1}mdb,cn=config",
					false,
				),
				translucentTestBackendEntry(
					"olcDatabase={0}ldap,olcOverlay={1}translucent,olcDatabase={1}mdb,cn=config",
					"{0}ldap",
					"ldap://127.0.0.1:390",
				),
			},
		},
		{
			name: "frontend placement",
			entries: []directory.Entry{
				{
					DN: "olcDatabase={-1}frontend,cn=config",
					Attributes: []directory.Attribute{
						{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
						{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
					},
				},
				translucentTestOverlayEntry(
					"olcOverlay={0}translucent,olcDatabase={-1}frontend,cn=config",
					false,
				),
				translucentTestBackendEntry(
					"olcDatabase={0}ldap,olcOverlay={0}translucent,olcDatabase={-1}frontend,cn=config",
					"{0}ldap",
					"ldap://127.0.0.1:389",
				),
			},
		},
		{
			name: "proxy backend placement",
			entries: []directory.Entry{
				{
					DN: "olcDatabase={2}ldap,cn=config",
					Attributes: []directory.Attribute{
						{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
						{Description: "olcDatabase", Values: stringValues("{2}ldap")},
						{Description: "olcSuffix", Values: stringValues("dc=proxy,dc=example")},
						{Description: "olcDbURI", Values: stringValues("ldap://127.0.0.1:389")},
					},
				},
				translucentTestOverlayEntry(
					"olcOverlay={0}translucent,olcDatabase={2}ldap,cn=config",
					false,
				),
				translucentTestBackendEntry(
					"olcDatabase={0}ldap,olcOverlay={0}translucent,olcDatabase={2}ldap,cn=config",
					"{0}ldap",
					"ldap://127.0.0.1:390",
				),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			t.Cleanup(func() { _ = store.Close() })
			seedOnlineConfiguration(t, store)
			putTranslucentTestEntries(t, store, test.entries...)
			if _, err := loadRuntimeDatabases(context.Background(), store); err == nil {
				t.Fatal("invalid translucent configuration was accepted")
			}
		})
	}
}

func TestTranslucentPhaseOneSearchCompareAndManageDsaIT(t *testing.T) {
	client, _, stop := startTranslucentTestPair(t)
	defer stop()
	defer client.Close()

	result, err := client.Search(ldap.NewSearchRequest(
		translucentTestBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid", "cn", "description", "telephoneNumber"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(translucent subtree): %v", err)
	}
	entries := make(map[string]*ldap.Entry, len(result.Entries))
	for _, entry := range result.Entries {
		entries[strings.ToLower(entry.DN)] = entry
	}
	if entries[strings.ToLower(translucentTestStaleDN)] != nil {
		t.Fatal("stale local-only entry was visible")
	}
	if entries[strings.ToLower(translucentTestRemoteOnlyDN)] == nil {
		t.Fatal("remote-only entry was not visible")
	}
	merged := entries[strings.ToLower(translucentTestMergedDN)]
	if merged == nil {
		t.Fatal("merged entry was not visible")
	}
	if got := merged.GetAttributeValues("description"); len(got) != 1 || got[0] != "local-only" {
		t.Fatalf("merged description = %q", got)
	}
	if got := merged.GetAttributeValue("cn"); got != "Remote Merged" {
		t.Fatalf("merged cn = %q", got)
	}

	filtered, err := client.Search(ldap.NewSearchRequest(
		translucentTestBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(description=remote-match)",
		[]string{"uid"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(filter recheck): %v", err)
	}
	if len(filtered.Entries) != 0 {
		t.Fatalf("filter recheck returned %d entries", len(filtered.Entries))
	}

	matched, err := client.Compare(translucentTestMergedDN, "description", "local-only")
	if err != nil || !matched {
		t.Fatalf("Compare(local override) = %t, %v", matched, err)
	}
	matched, err = client.Compare(translucentTestMergedDN, "description", "remote-one")
	if err != nil || matched {
		t.Fatalf("Compare(shadowed remote value) = %t, %v", matched, err)
	}
	matched, err = client.Compare(translucentTestMergedDN, "telephoneNumber", "100")
	if err != nil || !matched {
		t.Fatalf("Compare(remote fallback) = %t, %v", matched, err)
	}

	managed, err := client.Search(ldap.NewSearchRequest(
		translucentTestMergedDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(description=*)",
		[]string{"cn", "description", "telephoneNumber"},
		[]ldap.Control{ldap.NewControlManageDsaIT(true)},
	))
	if err != nil {
		t.Fatalf("Search(ManageDsaIT): %v", err)
	}
	if len(managed.Entries) != 1 ||
		managed.Entries[0].GetAttributeValue("description") != "local-only" ||
		managed.Entries[0].GetAttributeValue("cn") != "" ||
		managed.Entries[0].GetAttributeValue("telephoneNumber") != "" {
		t.Fatalf("ManageDsaIT local entry = %#v", managed.Entries)
	}
}

func TestTranslucentOnlineDisableReloadAndRollback(t *testing.T) {
	client, localAddress, stop := startTranslucentTestPair(t)
	defer stop()
	defer client.Close()

	config, err := ldap.DialURL("ldap://" + localAddress)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer config.Close()
	if err := config.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(config): %v", err)
	}

	disable := ldap.NewModifyRequest(translucentTestOverlayDN, nil)
	disable.Replace("olcDisabled", []string{"TRUE"})
	if err := config.Modify(disable); err != nil {
		t.Fatalf("disable translucent: %v", err)
	}
	_, err = client.Search(ldap.NewSearchRequest(
		translucentTestRemoteOnlyDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid"},
		nil,
	))
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)
	_, err = client.Compare(translucentTestMergedDN, "telephoneNumber", "100")
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchAttribute)

	enable := ldap.NewModifyRequest(translucentTestOverlayDN, nil)
	enable.Replace("olcDisabled", []string{"FALSE"})
	if err := config.Modify(enable); err != nil {
		t.Fatalf("re-enable translucent: %v", err)
	}
	matched, err := client.Compare(translucentTestMergedDN, "telephoneNumber", "100")
	if err != nil || !matched {
		t.Fatalf("Compare after reload = %t, %v", matched, err)
	}

	invalidURI := ldap.NewModifyRequest(translucentTestBackendDN, nil)
	invalidURI.Replace("olcDbURI", []string{"ldap://[invalid"})
	err = config.Modify(invalidURI)
	assertLDAPResultCode(t, err, ldap.LDAPResultConstraintViolation)
	matched, err = client.Compare(translucentTestMergedDN, "telephoneNumber", "100")
	if err != nil || !matched {
		t.Fatalf("Compare after invalid URI rollback = %t, %v", matched, err)
	}

	err = config.Del(ldap.NewDelRequest(translucentTestBackendDN, nil))
	assertLDAPResultCode(t, err, ldap.LDAPResultConstraintViolation)
	matched, err = client.Compare(translucentTestMergedDN, "telephoneNumber", "100")
	if err != nil || !matched {
		t.Fatalf("Compare after child delete rollback = %t, %v", matched, err)
	}
}

func startTranslucentTestPair(t *testing.T) (*ldap.Conn, string, func()) {
	t.Helper()
	remoteStore := storage.NewMemory()
	seedOnlineConfiguration(t, remoteStore)
	putTranslucentTestEntries(t, remoteStore, translucentRemoteTestEntries()...)
	remoteAddress, stopRemote := startServer(t, remoteStore, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})

	localStore := storage.NewMemory()
	seedOnlineConfiguration(t, localStore)
	putTranslucentTestEntries(
		t,
		localStore,
		append(
			[]directory.Entry{
				translucentTestOverlayEntry(translucentTestOverlayDN, false),
				translucentTestBackendEntry(
					translucentTestBackendDN,
					"{0}ldap",
					"ldap://"+remoteAddress,
				),
			},
			translucentLocalTestEntries()...,
		)...,
	)
	localAddress, stopLocal := startServer(t, localStore, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	client, err := ldap.DialURL("ldap://" + localAddress)
	if err != nil {
		stopLocal()
		stopRemote()
		t.Fatalf("DialURL(local): %v", err)
	}
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		client.Close()
		stopLocal()
		stopRemote()
		t.Fatalf("Bind(local): %v", err)
	}
	stop := func() {
		stopLocal()
		stopRemote()
		_ = localStore.Close()
		_ = remoteStore.Close()
	}
	return client, localAddress, stop
}

func translucentRemoteTestEntries() []directory.Entry {
	return []directory.Entry{
		{
			DN: translucentTestBaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit")},
				{Description: "ou", Values: stringValues("translucent")},
			},
		},
		translucentPersonEntry(
			translucentTestMergedDN,
			"merged",
			"Remote Merged",
			[]string{"remote-one", "remote-two"},
			"100",
		),
		translucentPersonEntry(
			translucentTestRemoteOnlyDN,
			"remote-only",
			"Remote Only",
			[]string{"remote-only"},
			"101",
		),
		translucentPersonEntry(
			translucentTestFilterDN,
			"filter",
			"Filter Candidate",
			[]string{"remote-match"},
			"102",
		),
	}
}

func translucentLocalTestEntries() []directory.Entry {
	return []directory.Entry{
		{
			DN: translucentTestBaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit")},
				{Description: "ou", Values: stringValues("translucent")},
			},
		},
		{
			DN: translucentTestMergedDN,
			Attributes: []directory.Attribute{
				{Description: "description", Values: stringValues("local-only")},
			},
		},
		{
			DN: translucentTestStaleDN,
			Attributes: []directory.Attribute{
				{Description: "description", Values: stringValues("stale")},
			},
		},
		{
			DN: translucentTestFilterDN,
			Attributes: []directory.Attribute{
				{Description: "description", Values: stringValues("local-miss")},
			},
		},
	}
}

func translucentPersonEntry(
	dn,
	uid,
	cn string,
	descriptions []string,
	telephone string,
) directory.Entry {
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues(uid)},
			{Description: "cn", Values: stringValues(cn)},
			{Description: "sn", Values: stringValues("Translucent")},
			{Description: "description", Values: stringValues(descriptions...)},
			{Description: "telephoneNumber", Values: stringValues(telephone)},
		},
	}
}

func translucentTestOverlayEntry(dn string, disabled bool) directory.Entry {
	rdn := strings.SplitN(dn, ",", 2)[0]
	_, overlayValue, _ := strings.Cut(rdn, "=")
	entry := directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values: stringValues(
					"olcOverlayConfig",
					"olcTranslucentConfig",
				),
			},
			{Description: "olcOverlay", Values: stringValues(overlayValue)},
		},
	}
	if disabled {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "olcDisabled",
			Values:      stringValues("TRUE"),
		})
	}
	return entry
}

func translucentTestBackendEntry(dn, backend, uri string) directory.Entry {
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values: stringValues(
					"olcDatabaseConfig",
					"olcTranslucentDatabase",
				),
			},
			{Description: "olcDatabase", Values: stringValues(backend)},
			{Description: "olcDbURI", Values: stringValues(uri)},
		},
	}
}

func putTranslucentTestEntries(
	t *testing.T,
	store storage.Store,
	entries ...directory.Entry,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed translucent entries: %v", err)
	}
}
