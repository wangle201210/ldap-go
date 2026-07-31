package server

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestParseOpenLDAPTimeInterval(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value string
		want  time.Duration
	}{
		{value: "0", want: 0},
		{value: "42", want: 42 * time.Second},
		{value: "1d2h3m4s", want: 26*time.Hour + 3*time.Minute + 4*time.Second},
		{value: "2h30m", want: 2*time.Hour + 30*time.Minute},
		{value: "1d2", want: 24*time.Hour + 2*time.Second},
	}
	for _, test := range tests {
		test := test
		t.Run(test.value, func(t *testing.T) {
			t.Parallel()
			got, err := parseOpenLDAPTimeInterval(test.value)
			if err != nil {
				t.Fatalf("parseOpenLDAPTimeInterval(%q): %v", test.value, err)
			}
			if got != test.want {
				t.Fatalf(
					"parseOpenLDAPTimeInterval(%q) = %s, want %s",
					test.value,
					got,
					test.want,
				)
			}
		})
	}
}

func TestParseOpenLDAPTimeIntervalRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"",
		"-1",
		"1x",
		"1h2d",
		"1h2h",
		"1s2",
		"18446744073709551615d",
	} {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := parseOpenLDAPTimeInterval(value); err == nil {
				t.Fatalf("parseOpenLDAPTimeInterval(%q) succeeded", value)
			}
		})
	}
}

func TestLoadDDSRuntimeConfigurationDefaults(t *testing.T) {
	t.Parallel()

	config, err := loadDDSRuntimeConfiguration(
		ddsOverlayEntry(),
		runtimeDatabase{name: "{1}mdb"},
	)
	if err != nil {
		t.Fatalf("loadDDSRuntimeConfiguration(): %v", err)
	}
	if !config.enabled ||
		config.maxTTL != ddsDefaultMaxTTL ||
		config.minTTL != 0 ||
		config.defaultTTL != 0 ||
		config.effectiveDefaultTTL() != ddsDefaultMaxTTL ||
		config.interval != ddsDefaultCheck ||
		config.tolerance != 0 ||
		config.maxDynamicObjects != 0 {
		t.Fatalf("default DDS configuration = %#v", config)
	}
}

func TestLoadDDSRuntimeConfigurationValues(t *testing.T) {
	t.Parallel()

	entry := ddsOverlayEntry()
	entry.Attributes = append(entry.Attributes,
		directory.Attribute{
			Description: "olcDDSstate",
			Values:      stringValues("TRUE"),
		},
		directory.Attribute{
			Description: "olcDDSmaxTtl",
			Values:      stringValues("2d"),
		},
		directory.Attribute{
			Description: "olcDDSminTtl",
			Values:      stringValues("1h"),
		},
		directory.Attribute{
			Description: "olcDDSdefaultTtl",
			Values:      stringValues("2h"),
		},
		directory.Attribute{
			Description: "olcDDSinterval",
			Values:      stringValues("10m"),
		},
		directory.Attribute{
			Description: "olcDDStolerance",
			Values:      stringValues("30s"),
		},
		directory.Attribute{
			Description: "olcDDSmaxDynamicObjects",
			Values:      stringValues("25"),
		},
	)

	config, err := loadDDSRuntimeConfiguration(
		entry,
		runtimeDatabase{name: "{1}mdb"},
	)
	if err != nil {
		t.Fatalf("loadDDSRuntimeConfiguration(): %v", err)
	}
	if !config.enabled ||
		config.maxTTL != 48*time.Hour ||
		config.minTTL != time.Hour ||
		config.defaultTTL != 2*time.Hour ||
		config.effectiveDefaultTTL() != 2*time.Hour ||
		config.interval != 10*time.Minute ||
		config.tolerance != 30*time.Second ||
		config.maxDynamicObjects != 25 {
		t.Fatalf("DDS configuration = %#v", config)
	}
}

func TestLoadDDSRuntimeConfigurationExplicitZeroTTL(t *testing.T) {
	t.Parallel()

	entry := ddsOverlayEntry()
	entry.Attributes = append(entry.Attributes,
		directory.Attribute{
			Description: "olcDDSminTtl",
			Values:      stringValues("0"),
		},
		directory.Attribute{
			Description: "olcDDSdefaultTtl",
			Values:      stringValues("0"),
		},
	)

	config, err := loadDDSRuntimeConfiguration(
		entry,
		runtimeDatabase{name: "{1}mdb"},
	)
	if err != nil {
		t.Fatalf("loadDDSRuntimeConfiguration(): %v", err)
	}
	if config.minTTL != ddsDefaultMaxTTL ||
		config.defaultTTL != ddsDefaultMaxTTL {
		t.Fatalf("explicit zero DDS TTLs = %#v", config)
	}
}

func TestLoadDDSRuntimeConfigurationRejectsInvalidSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		database   runtimeDatabase
		attributes []directory.Attribute
		want       string
	}{
		{
			name:     "global overlay",
			database: runtimeDatabase{name: "{-1}frontend"},
			want:     "global overlay",
		},
		{
			name:     "shadow database",
			database: runtimeDatabase{name: "{1}mdb", shadow: true},
			want:     "shadow database",
		},
		{
			name:     "maximum below one day",
			database: runtimeDatabase{name: "{1}mdb"},
			attributes: []directory.Attribute{{
				Description: "olcDDSmaxTtl",
				Values:      stringValues("86399"),
			}},
			want: "must be between",
		},
		{
			name:     "maximum above RFC limit",
			database: runtimeDatabase{name: "{1}mdb"},
			attributes: []directory.Attribute{{
				Description: "olcDDSmaxTtl",
				Values:      stringValues("31557601"),
			}},
			want: "must be between",
		},
		{
			name:     "minimum above maximum",
			database: runtimeDatabase{name: "{1}mdb"},
			attributes: []directory.Attribute{
				{
					Description: "olcDDSmaxTtl",
					Values:      stringValues("1d"),
				},
				{
					Description: "olcDDSminTtl",
					Values:      stringValues("2d"),
				},
			},
			want: "min TTL",
		},
		{
			name:     "default above maximum",
			database: runtimeDatabase{name: "{1}mdb"},
			attributes: []directory.Attribute{
				{
					Description: "olcDDSmaxTtl",
					Values:      stringValues("1d"),
				},
				{
					Description: "olcDDSdefaultTtl",
					Values:      stringValues("2d"),
				},
			},
			want: "default TTL",
		},
		{
			name:     "zero interval",
			database: runtimeDatabase{name: "{1}mdb"},
			attributes: []directory.Attribute{{
				Description: "olcDDSinterval",
				Values:      stringValues("0"),
			}},
			want: "must be positive",
		},
		{
			name:     "negative maximum objects",
			database: runtimeDatabase{name: "{1}mdb"},
			attributes: []directory.Attribute{{
				Description: "olcDDSmaxDynamicObjects",
				Values:      stringValues("-1"),
			}},
			want: "invalid value",
		},
		{
			name:     "multiple values",
			database: runtimeDatabase{name: "{1}mdb"},
			attributes: []directory.Attribute{{
				Description: "olcDDSmaxTtl",
				Values:      stringValues("1d", "2d"),
			}},
			want: "single-valued",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			entry := ddsOverlayEntry()
			entry.Attributes = append(entry.Attributes, test.attributes...)
			_, err := loadDDSRuntimeConfiguration(entry, test.database)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf(
					"loadDDSRuntimeConfiguration() error = %v, want %q",
					err,
					test.want,
				)
			}
		})
	}
}

func TestDDSAddAndWriteConstraints(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDDSDirectory(t, store,
		directory.Attribute{
			Description: "olcDDSdefaultTtl",
			Values:      stringValues("1h"),
		},
	)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindDDSRootClient(t, address)
	defer client.Close()

	dynamicDN := "cn=lease,ou=people,dc=example,dc=com"
	addDynamic := newDynamicRoleAddRequest(dynamicDN, "lease")
	addDynamic.Attribute("entryTtl", []string{"7"})
	addDynamic.Attribute("entryExpireTimestamp", []string{"20000101000000Z"})
	addedAt := time.Now()
	if err := client.Add(addDynamic); err != nil {
		t.Fatalf("Add(dynamicObject): %v", err)
	}

	stored := readStoredEntry(t, store, dynamicDN)
	assertStoredDDSTTL(t, stored, 3600)
	expires, err := time.Parse(
		"20060102150405Z",
		string(stored.Values("entryExpireTimestamp")[0]),
	)
	if err != nil {
		t.Fatalf("parse entryExpireTimestamp: %v", err)
	}
	if expires.Before(addedAt.Add(3598*time.Second)) ||
		expires.After(time.Now().Add(3601*time.Second)) {
		t.Fatalf("entryExpireTimestamp = %s, want about one hour from add", expires)
	}

	root, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedExtension", "dynamicSubtrees"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(root DSE): %v", err)
	}
	if len(root.Entries) != 1 ||
		containsString(
			root.Entries[0].GetAttributeValues("supportedExtension"),
			dynamicRefreshOID,
		) ||
		!containsString(
			root.Entries[0].GetAttributeValues("dynamicSubtrees"),
			"dc=example,dc=com",
		) {
		t.Fatalf("DDS root DSE = %#v", root.Entries)
	}

	searched, err := client.Search(ldap.NewSearchRequest(
		dynamicDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"entryTtl"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(dynamicObject): %v", err)
	}
	if len(searched.Entries) != 1 {
		t.Fatalf("dynamic search entries = %d, want 1", len(searched.Entries))
	}
	remaining, err := strconv.ParseInt(
		searched.Entries[0].GetAttributeValue("entryTtl"),
		10,
		64,
	)
	if err != nil || remaining < 3598 || remaining > 3600 {
		t.Fatalf("search entryTtl = %d, error = %v", remaining, err)
	}

	modifyTTL := ldap.NewModifyRequest(dynamicDN, nil)
	modifyTTL.Replace("entryTtl", []string{"1800"})
	assertLDAPResultCode(
		t,
		client.Modify(modifyTTL),
		ldap.LDAPResultConstraintViolation,
	)

	removeDynamicClass := ldap.NewModifyRequest(dynamicDN, nil)
	removeDynamicClass.Delete("objectClass", []string{"dynamicObject"})
	assertLDAPResultCode(
		t,
		client.Modify(removeDynamicClass),
		ldap.LDAPResultObjectClassViolation,
	)

	staticChild := ldap.NewAddRequest("cn=static,"+dynamicDN, nil)
	staticChild.Attribute("objectClass", []string{"organizationalRole"})
	staticChild.Attribute("cn", []string{"static"})
	assertLDAPResultCode(
		t,
		client.Add(staticChild),
		ldap.LDAPResultConstraintViolation,
	)

	dynamicChildDN := "cn=child," + dynamicDN
	if err := client.Add(newDynamicRoleAddRequest(dynamicChildDN, "child")); err != nil {
		t.Fatalf("Add(dynamic child): %v", err)
	}

	alias := ldap.NewAddRequest("cn=alias,ou=people,dc=example,dc=com", nil)
	alias.Attribute("objectClass", []string{"alias", "extensibleObject", "dynamicObject"})
	alias.Attribute("cn", []string{"alias"})
	alias.Attribute("aliasedObjectName", []string{dynamicDN})
	assertLDAPResultCode(
		t,
		client.Add(alias),
		ldap.LDAPResultObjectClassViolation,
	)

	staticDN := "cn=static-move,ou=people,dc=example,dc=com"
	static := ldap.NewAddRequest(staticDN, nil)
	static.Attribute("objectClass", []string{"organizationalRole"})
	static.Attribute("cn", []string{"static-move"})
	if err := client.Add(static); err != nil {
		t.Fatalf("Add(static entry): %v", err)
	}
	makeDynamic := ldap.NewModifyRequest(staticDN, nil)
	makeDynamic.Add("objectClass", []string{"dynamicObject"})
	assertLDAPResultCode(
		t,
		client.Modify(makeDynamic),
		ldap.LDAPResultObjectClassViolation,
	)
	moveStatic := ldap.NewModifyDNRequest(
		staticDN,
		"cn=static-move",
		true,
		dynamicDN,
	)
	assertLDAPResultCode(
		t,
		client.ModifyDN(moveStatic),
		ldap.LDAPResultConstraintViolation,
	)
}

func TestDDSMaximumDynamicObjects(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDDSDirectory(t, store,
		directory.Attribute{
			Description: "olcDDSmaxDynamicObjects",
			Values:      stringValues("1"),
		},
	)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindDDSRootClient(t, address)
	defer client.Close()

	firstDN := "cn=first,ou=people,dc=example,dc=com"
	if err := client.Add(newDynamicRoleAddRequest(firstDN, "first")); err != nil {
		t.Fatalf("Add(first dynamicObject): %v", err)
	}
	secondDN := "cn=second,ou=people,dc=example,dc=com"
	assertLDAPResultCode(
		t,
		client.Add(newDynamicRoleAddRequest(secondDN, "second")),
		ldap.LDAPResultUnwillingToPerform,
	)

	second, err := directory.ParseDN(secondDN)
	if err != nil {
		t.Fatalf("ParseDN(second): %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Get(second)
		return err
	}); err == nil {
		t.Fatal("rejected dynamicObject was persisted")
	}
}

func TestDDSDynamicRefresh(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDDSDirectory(t, store,
		directory.Attribute{
			Description: "olcDDSmaxTtl",
			Values:      stringValues("1d"),
		},
		directory.Attribute{
			Description: "olcDDSminTtl",
			Values:      stringValues("30s"),
		},
		directory.Attribute{
			Description: "olcDDSdefaultTtl",
			Values:      stringValues("1h"),
		},
	)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindDDSRootClient(t, address)
	defer client.Close()

	dynamicDN := "cn=refresh,ou=people,dc=example,dc=com"
	if err := client.Add(newDynamicRoleAddRequest(dynamicDN, "refresh")); err != nil {
		t.Fatalf("Add(dynamicObject): %v", err)
	}
	before := readStoredEntry(t, store, dynamicDN)

	refreshedAt := time.Now()
	responseTTL, err := requestDynamicRefresh(client, dynamicDN, 10)
	if err != nil {
		t.Fatalf("Refresh(dynamicObject): %v", err)
	}
	if responseTTL != 30 {
		t.Fatalf("Refresh response TTL = %d, want 30", responseTTL)
	}
	after := readStoredEntry(t, store, dynamicDN)
	assertStoredDDSTTL(t, after, 30)
	expires, err := parseDDSExpiration(
		string(after.Values("entryExpireTimestamp")[0]),
	)
	if err != nil {
		t.Fatalf("parse refreshed expiration: %v", err)
	}
	if expires.Before(refreshedAt.Add(28*time.Second)) ||
		expires.After(time.Now().Add(31*time.Second)) {
		t.Fatalf("refreshed expiration = %s", expires)
	}
	if string(after.Values("entryCSN")[0]) ==
		string(before.Values("entryCSN")[0]) {
		t.Fatal("Refresh did not update entryCSN")
	}

	_, err = requestDynamicRefresh(client, dynamicDN, 86401)
	assertLDAPResultCode(t, err, ldap.LDAPResultSizeLimitExceeded)
	_, err = requestDynamicRefresh(client, dynamicDN, 0)
	assertLDAPResultCode(t, err, ldap.LDAPResultProtocolError)
	_, err = requestDynamicRefresh(client, dynamicDN, 31557601)
	assertLDAPResultCode(t, err, ldap.LDAPResultProtocolError)
	_, err = requestDynamicRefresh(
		client,
		"ou=people,dc=example,dc=com",
		30,
	)
	assertLDAPResultCode(t, err, ldap.LDAPResultObjectClassViolation)
	_, err = requestDynamicRefresh(
		client,
		"cn=missing,ou=people,dc=example,dc=com",
		30,
	)
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)

	anonymousValue := ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		string(ldapwire.EncodeDynamicRefreshRequestValue(dynamicDN, 30)),
		"requestValue",
	)
	anonymous, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(anonymous): %v", err)
	}
	defer anonymous.Close()
	_, err = anonymous.Extended(
		ldap.NewExtendedRequest(dynamicRefreshOID, anonymousValue),
	)
	assertLDAPResultCode(t, err, ldap.LDAPResultStrongAuthRequired)

	user, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(user): %v", err)
	}
	defer user.Close()
	if err := user.Bind(
		"uid=alice,ou=people,dc=example,dc=com",
		"secret",
	); err != nil {
		t.Fatalf("Bind(user): %v", err)
	}
	_, err = requestDynamicRefresh(user, dynamicDN, 30)
	assertLDAPResultCode(t, err, ldap.LDAPResultInsufficientAccessRights)
}

func TestDDSDynamicRefreshRejectsMalformedValue(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDDSDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindDDSRootClient(t, address)
	defer client.Close()

	_, err := client.Extended(ldap.NewExtendedRequest(dynamicRefreshOID, nil))
	assertLDAPResultCode(t, err, ldap.LDAPResultProtocolError)
	for _, raw := range [][]byte{
		{},
		{0x30, 0x00},
		{0x30, 0x03, 0x80, 0x01, 'x'},
	} {
		value := ber.NewString(
			ber.ClassContext,
			ber.TypePrimitive,
			1,
			string(raw),
			"requestValue",
		)
		_, err := client.Extended(
			ldap.NewExtendedRequest(dynamicRefreshOID, value),
		)
		assertLDAPResultCode(t, err, ldap.LDAPResultProtocolError)
	}
}

func TestExpireDDSDatabaseDefersNonLeafAndDeletesDeepestFirst(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDDSDirectory(t, store)
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	now := time.Date(2026, time.July, 31, 11, 0, 0, 0, time.UTC)
	parentDN, err := directory.ParseDN(
		"cn=parent,ou=people,dc=example,dc=com",
	)
	if err != nil {
		t.Fatalf("ParseDN(parent): %v", err)
	}
	childDN, err := directory.ParseDN(
		"cn=child,cn=parent,ou=people,dc=example,dc=com",
	)
	if err != nil {
		t.Fatalf("ParseDN(child): %v", err)
	}
	database := databaseForDN(instance.runtime.Load(), parentDN)
	if database == nil {
		t.Fatal("DDS database was not loaded")
	}
	parent := ddsStoredRoleEntry(
		parentDN.String(),
		"parent",
		now.Add(-time.Minute),
	)
	child := ddsStoredRoleEntry(
		childDN.String(),
		"child",
		now.Add(time.Minute),
	)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.PutIn(database.partition, parent, false); err != nil {
			return err
		}
		return writer.PutIn(database.partition, child, false)
	}); err != nil {
		t.Fatalf("seed dynamic hierarchy: %v", err)
	}

	if err := instance.expireDDSDatabase(
		context.Background(),
		*database,
		now,
	); err != nil {
		t.Fatalf("expireDDSDatabase(non-leaf): %v", err)
	}
	assertStoredEntryExists(t, store, parentDN, true)
	assertStoredEntryExists(t, store, childDN, true)

	child.ReplaceValues(
		"entryExpireTimestamp",
		stringValues(formatDDSExpiration(now.Add(-time.Minute))),
	)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.PutIn(database.partition, child, true)
	}); err != nil {
		t.Fatalf("expire dynamic child: %v", err)
	}
	if err := instance.expireDDSDatabase(
		context.Background(),
		*database,
		now,
	); err != nil {
		t.Fatalf("expireDDSDatabase(hierarchy): %v", err)
	}
	assertStoredEntryExists(t, store, childDN, false)
	assertStoredEntryExists(t, store, parentDN, false)
}

func TestExpireDDSDatabasePublishesSyncDelete(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedSyncProviderDirectory(t, store)
	overlay := ddsOverlayEntry()
	overlay.DN = "olcOverlay={1}dds,olcDatabase={1}mdb,cn=config"
	overlay.ReplaceValues("olcOverlay", stringValues("{1}dds"))
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(overlay, false)
	}); err != nil {
		t.Fatalf("seed DDS overlay: %v", err)
	}
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	dn, err := directory.ParseDN(
		"cn=sync-expiry,ou=people,dc=example,dc=com",
	)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	database := databaseForDN(instance.runtime.Load(), dn)
	if database == nil {
		t.Fatal("DDS sync provider database was not loaded")
	}
	entry := ddsStoredRoleEntry(
		dn.String(),
		"sync-expiry",
		time.Now().Add(-time.Minute),
	)
	entry.ReplaceValues(
		"entryUUID",
		stringValues("10000000-0000-4000-8000-000000000001"),
	)
	entry.ReplaceValues(
		"entryCSN",
		stringValues("20260731120000.000000Z#000001#000#000000"),
	)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.PutIn(database.partition, entry, false)
	}); err != nil {
		t.Fatalf("seed expiring sync entry: %v", err)
	}

	subscription := instance.syncChanges.subscribe([]string{database.partition})
	defer subscription.unsubscribe()
	if err := instance.expireDDSDatabase(
		context.Background(),
		*database,
		time.Now(),
	); err != nil {
		t.Fatalf("expireDDSDatabase(): %v", err)
	}
	select {
	case change := <-subscription.events:
		if !change.hasBefore ||
			change.hasAfter ||
			change.before.DN != dn.String() ||
			change.partition != database.partition ||
			change.providerPartition != database.partition {
			t.Fatalf("DDS expiration sync change = %#v", change)
		}
	case <-time.After(time.Second):
		t.Fatal("DDS expiration did not publish a sync delete")
	}
}

func TestExpireDDSDatabaseHonorsTolerance(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDDSDirectory(t, store,
		directory.Attribute{
			Description: "olcDDStolerance",
			Values:      stringValues("10s"),
		},
	)
	instance, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	dn, err := directory.ParseDN(
		"cn=tolerated,ou=people,dc=example,dc=com",
	)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	database := databaseForDN(instance.runtime.Load(), dn)
	if database == nil {
		t.Fatal("DDS database was not loaded")
	}
	entry := ddsStoredRoleEntry(
		dn.String(),
		"tolerated",
		now.Add(-5*time.Second),
	)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.PutIn(database.partition, entry, false)
	}); err != nil {
		t.Fatalf("seed tolerated entry: %v", err)
	}

	if err := instance.expireDDSDatabase(
		context.Background(),
		*database,
		now,
	); err != nil {
		t.Fatalf("expireDDSDatabase(within tolerance): %v", err)
	}
	assertStoredEntryExists(t, store, dn, true)
	if err := instance.expireDDSDatabase(
		context.Background(),
		*database,
		now.Add(6*time.Second),
	); err != nil {
		t.Fatalf("expireDDSDatabase(after tolerance): %v", err)
	}
	assertStoredEntryExists(t, store, dn, false)
}

func TestDDSServerExpiresPersistedObjectAfterRestart(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDDSDirectory(t, store,
		directory.Attribute{
			Description: "olcDDSdefaultTtl",
			Values:      stringValues("1s"),
		},
		directory.Attribute{
			Description: "olcDDSinterval",
			Values:      stringValues("1s"),
		},
	)
	config := Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	}

	address, stop := startServer(t, store, config)
	client := bindDDSRootClient(t, address)
	dn := "cn=restart-expiry,ou=people,dc=example,dc=com"
	if err := client.Add(newDynamicRoleAddRequest(dn, "restart-expiry")); err != nil {
		t.Fatalf("Add(dynamicObject): %v", err)
	}
	client.Close()
	stop()

	time.Sleep(1100 * time.Millisecond)
	_, stop = startServer(t, store, config)
	defer stop()

	parsed, err := directory.ParseDN(dn)
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		exists := storedEntryExists(t, store, parsed)
		if !exists {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dynamicObject %s did not expire after restart", dn)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestDDSDynamicObjectRequiresEnabledOverlay(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindDDSRootClient(t, address)
	defer client.Close()

	assertLDAPResultCode(
		t,
		client.Add(newDynamicRoleAddRequest(
			"cn=unsupported,ou=people,dc=example,dc=com",
			"unsupported",
		)),
		ldap.LDAPResultObjectClassViolation,
	)

	root, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedExtension", "dynamicSubtrees"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(root DSE): %v", err)
	}
	if len(root.Entries) != 1 {
		t.Fatalf("root DSE entries = %d, want 1", len(root.Entries))
	}
	if containsString(
		root.Entries[0].GetAttributeValues("supportedExtension"),
		dynamicRefreshOID,
	) || len(root.Entries[0].GetAttributeValues("dynamicSubtrees")) != 0 {
		t.Fatalf("root DSE advertised disabled DDS: %#v", root.Entries[0])
	}

	_, err = requestDynamicRefresh(
		client,
		"uid=alice,ou=people,dc=example,dc=com",
		60,
	)
	assertLDAPResultCode(
		t,
		err,
		ldap.LDAPResultUnavailableCriticalExtension,
	)
}

func TestDDSDisabledOverlayAllowsInertDynamicObject(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDDSDirectory(t, store,
		directory.Attribute{
			Description: "olcDDSstate",
			Values:      stringValues("FALSE"),
		},
	)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()
	client := bindDDSRootClient(t, address)
	defer client.Close()

	dn := "cn=inert,ou=people,dc=example,dc=com"
	if err := client.Add(newDynamicRoleAddRequest(dn, "inert")); err != nil {
		t.Fatalf("Add(inert dynamicObject): %v", err)
	}
	stored := readStoredEntry(t, store, dn)
	if stored.HasAttribute("entryTtl") ||
		stored.HasAttribute("entryExpireTimestamp") {
		t.Fatalf("disabled DDS generated lifetime attributes: %#v", stored)
	}

	root, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dynamicSubtrees"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(root DSE): %v", err)
	}
	if len(root.Entries) != 1 ||
		len(root.Entries[0].GetAttributeValues("dynamicSubtrees")) != 0 {
		t.Fatalf("disabled DDS dynamicSubtrees = %#v", root.Entries)
	}
	_, err = requestDynamicRefresh(client, dn, 60)
	assertLDAPResultCode(
		t,
		err,
		ldap.LDAPResultUnwillingToPerform,
	)
}

func TestDDSOnlineConfigurationLifecycle(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	dataClient := bindDDSRootClient(t, address)
	defer dataClient.Close()
	configClient, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(config): %v", err)
	}
	defer configClient.Close()
	if err := configClient.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("config root Bind(): %v", err)
	}

	dynamicDN := "cn=online-dds,ou=people,dc=example,dc=com"
	assertLDAPResultCode(
		t,
		dataClient.Add(newDynamicRoleAddRequest(dynamicDN, "online-dds")),
		ldap.LDAPResultObjectClassViolation,
	)

	overlayDN := "olcOverlay={0}dds,olcDatabase={1}mdb,cn=config"
	addOverlay := ldap.NewAddRequest(overlayDN, nil)
	addOverlay.Attribute("objectClass", []string{"olcOverlayConfig"})
	addOverlay.Attribute("olcOverlay", []string{"{0}dds"})
	addOverlay.Attribute("olcDDSdefaultTtl", []string{"1h"})
	addOverlay.Attribute("olcDDSinterval", []string{"1s"})
	if err := configClient.Add(addOverlay); err != nil {
		t.Fatalf("Add(DDS overlay): %v", err)
	}
	if err := dataClient.Add(
		newDynamicRoleAddRequest(dynamicDN, "online-dds"),
	); err != nil {
		t.Fatalf("Add(dynamicObject after online enable): %v", err)
	}
	assertStoredDDSTTL(t, readStoredEntry(t, store, dynamicDN), 3600)

	disable := ldap.NewModifyRequest(overlayDN, nil)
	disable.Replace("olcDDSstate", []string{"FALSE"})
	if err := configClient.Modify(disable); err != nil {
		t.Fatalf("disable DDS overlay: %v", err)
	}
	inertDN := "cn=online-inert,ou=people,dc=example,dc=com"
	if err := dataClient.Add(
		newDynamicRoleAddRequest(inertDN, "online-inert"),
	); err != nil {
		t.Fatalf("Add(inert dynamicObject): %v", err)
	}
	inert := readStoredEntry(t, store, inertDN)
	if inert.HasAttribute("entryTtl") ||
		inert.HasAttribute("entryExpireTimestamp") {
		t.Fatalf("disabled online DDS generated lifetime: %#v", inert)
	}

	if err := configClient.Del(ldap.NewDelRequest(overlayDN, nil)); err != nil {
		t.Fatalf("Delete(DDS overlay): %v", err)
	}
	assertLDAPResultCode(
		t,
		dataClient.Add(newDynamicRoleAddRequest(
			"cn=online-unsupported,ou=people,dc=example,dc=com",
			"online-unsupported",
		)),
		ldap.LDAPResultObjectClassViolation,
	)
}

func TestProjectDDSRemainingTTL(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 31, 10, 0, 0, 0, time.UTC)
	source := directory.Entry{
		DN: "cn=lease,dc=example,dc=com",
		Attributes: []directory.Attribute{
			{
				Description: "entryTtl",
				Values:      stringValues("60"),
			},
			{
				Description: "entryExpireTimestamp",
				Values:      stringValues(formatDDSExpiration(now.Add(45 * time.Second))),
			},
		},
	}
	readable := source.Without("entryExpireTimestamp")

	projected := projectDDSRemainingTTL(readable, source, now)
	assertStoredDDSTTL(t, projected, 45)
	expired := projectDDSRemainingTTL(readable, source, now.Add(time.Minute))
	assertStoredDDSTTL(t, expired, 0)

	typesOnly := readable.Clone()
	typesOnly.ReplaceValues("entryTtl", nil)
	typesOnly.Attributes = append(typesOnly.Attributes, directory.Attribute{
		Description: "entryTtl",
	})
	projectedTypesOnly := projectDDSRemainingTTL(typesOnly, source, now)
	if !projectedTypesOnly.HasAttribute("entryTtl") ||
		len(projectedTypesOnly.Values("entryTtl")) != 0 {
		t.Fatalf("types-only entryTtl = %#v", projectedTypesOnly)
	}
}

func ddsOverlayEntry() directory.Entry {
	return directory.Entry{
		DN: "olcOverlay={0}dds,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcOverlay",
			Values:      stringValues("{0}dds"),
		}},
	}
}

func seedDDSDirectory(
	t *testing.T,
	store storage.Store,
	attributes ...directory.Attribute,
) {
	t.Helper()
	seedDirectory(t, store)
	overlay := ddsOverlayEntry()
	overlay.Attributes = append(overlay.Attributes, attributes...)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(overlay, false)
	}); err != nil {
		t.Fatalf("seed DDS overlay: %v", err)
	}
}

func bindDDSRootClient(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	if err := client.Bind(
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	); err != nil {
		client.Close()
		t.Fatalf("root Bind(): %v", err)
	}
	return client
}

func newDynamicRoleAddRequest(dn, cn string) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute(
		"objectClass",
		[]string{"top", "organizationalRole", "dynamicObject"},
	)
	request.Attribute("cn", []string{cn})
	return request
}

func assertStoredDDSTTL(t *testing.T, entry directory.Entry, want int64) {
	t.Helper()
	values := entry.Values("entryTtl")
	if len(values) != 1 {
		t.Fatalf("entryTtl values = %q, want one value", values)
	}
	got, err := strconv.ParseInt(string(values[0]), 10, 64)
	if err != nil || got != want {
		t.Fatalf("entryTtl = %q, want %d", values[0], want)
	}
}

func requestDynamicRefresh(
	client *ldap.Conn,
	dn string,
	ttl int64,
) (int64, error) {
	value := ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		1,
		string(ldapwire.EncodeDynamicRefreshRequestValue(dn, ttl)),
		"requestValue",
	)
	response, err := client.Extended(
		ldap.NewExtendedRequest(dynamicRefreshOID, value),
	)
	if err != nil {
		return 0, err
	}
	if response.Name != dynamicRefreshOID || response.Value == nil {
		return 0, errors.New("dynamic refresh response name or value is absent")
	}
	return ldapwire.DecodeDynamicRefreshResponseValue(
		response.Value.Data.Bytes(),
	)
}

func ddsStoredRoleEntry(
	dn string,
	cn string,
	expires time.Time,
) directory.Entry {
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values: stringValues(
					"top",
					"organizationalRole",
					"dynamicObject",
				),
			},
			{Description: "cn", Values: stringValues(cn)},
			{Description: "entryTtl", Values: stringValues("60")},
			{
				Description: "entryExpireTimestamp",
				Values:      stringValues(formatDDSExpiration(expires)),
			},
		},
	}
}

func assertStoredEntryExists(
	t *testing.T,
	store storage.Store,
	dn directory.DN,
	want bool,
) {
	t.Helper()
	if got := storedEntryExists(t, store, dn); got != want {
		t.Fatalf("stored entry %s exists = %t, want %t", dn.String(), got, want)
	}
}

func storedEntryExists(
	t *testing.T,
	store storage.Store,
	dn directory.DN,
) bool {
	t.Helper()
	err := store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Get(dn)
		return err
	})
	switch {
	case err == nil:
		return true
	case errors.Is(err, storage.ErrEntryNotFound):
		return false
	default:
		t.Fatalf("read stored entry %s: %v", dn.String(), err)
		return false
	}
}
