package server

import (
	"context"
	"fmt"
	"sort"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestRWMMapWildcardAndDeletionSemantics(t *testing.T) {
	newConfiguration := func() *rwmRuntimeConfiguration {
		return &rwmRuntimeConfiguration{
			attributesToRemote: make(map[string]string),
			attributesToLocal:  make(map[string]string),
			classesToRemote:    make(map[string]string),
			classesToLocal:     make(map[string]string),
		}
	}
	apply := func(t *testing.T, configuration *rwmRuntimeConfiguration, directives ...string) {
		t.Helper()
		for _, directive := range directives {
			words, err := splitRWMConfigurationWords(directive)
			if err != nil {
				t.Fatalf("split map directive %q: %v", directive, err)
			}
			if err := applyRWMMapDirective(configuration, words); err != nil {
				t.Fatalf("apply map directive %q: %v", directive, err)
			}
		}
	}

	t.Run("attribute allow list", func(t *testing.T) {
		configuration := newConfiguration()
		apply(t, configuration, "attribute * description", "attribute *")
		if got := configuration.mapAttributeDescription("description", true); got != "description" {
			t.Fatalf("mapped description = %q, want identity", got)
		}
		if got := configuration.mapAttributeDescription("cn", true); got != "" {
			t.Fatalf("mapped cn = %q, want dropped", got)
		}
		if got := configuration.mapAttributeDescription("objectClass", false); got != "objectClass" {
			t.Fatalf("mapped objectClass = %q, want built-in identity", got)
		}
		mapped, err := configuration.mapEntryToLocal(directory.Entry{
			DN: "uid=user,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("person")},
				{Description: "description", Values: stringValues("visible")},
				{Description: "cn", Values: stringValues("hidden")},
			},
		})
		if err != nil {
			t.Fatalf("map allow-listed relay entry: %v", err)
		}
		if mapped.HasAttribute("cn") || !mapped.HasAttribute("description") ||
			!mapped.HasAttribute("objectClass") {
			t.Fatalf("mapped allow-listed relay entry = %#v", mapped.Attributes)
		}
	})

	t.Run("attribute response deletion and reset", func(t *testing.T) {
		configuration := newConfiguration()
		apply(t, configuration, "attribute description")
		if got := configuration.mapAttributeDescription("description", true); got != "description" {
			t.Fatalf("forward description = %q, want identity", got)
		}
		if got := configuration.mapAttributeDescription("description", false); got != "" {
			t.Fatalf("reverse description = %q, want dropped", got)
		}
		apply(t, configuration, "attribute *", "attribute * *")
		if got := configuration.mapAttributeDescription("cn", false); got != "cn" {
			t.Fatalf("reverse cn after * * = %q, want passthrough", got)
		}
	})

	t.Run("objectClass map initialization", func(t *testing.T) {
		configuration := newConfiguration()
		apply(t, configuration, "objectclass *")
		if got := configuration.mapObjectClass("person", false); got != "person" {
			t.Fatalf("objectclass * mapped person = %q, want passthrough", got)
		}
		apply(t, configuration, "objectclass * inetOrgPerson", "objectclass *")
		if got := configuration.mapObjectClass("inetOrgPerson", false); got != "inetOrgPerson" {
			t.Fatalf("allow-listed inetOrgPerson = %q", got)
		}
		if got := configuration.mapObjectClass("person", false); got != "" {
			t.Fatalf("non-allow-listed person = %q, want dropped", got)
		}
		mapped, err := configuration.mapEntryToLocal(directory.Entry{
			DN: "uid=user,dc=example,dc=com",
			Attributes: []directory.Attribute{{
				Description: "objectClass",
				Values:      stringValues("inetOrgPerson", "person"),
			}},
		})
		if err != nil {
			t.Fatalf("map objectClass allow-list entry: %v", err)
		}
		if got := mapped.Values("objectClass"); len(got) != 1 || string(got[0]) != "inetOrgPerson" {
			t.Fatalf("mapped objectClass values = %q", got)
		}
	})

	t.Run("objectClass response deletion", func(t *testing.T) {
		configuration := newConfiguration()
		apply(t, configuration, "objectclass inetOrgPerson")
		if got := configuration.mapObjectClass("inetOrgPerson", true); got != "inetOrgPerson" {
			t.Fatalf("forward inetOrgPerson = %q, want identity", got)
		}
		if got := configuration.mapObjectClass("inetOrgPerson", false); got != "" {
			t.Fatalf("reverse inetOrgPerson = %q, want dropped", got)
		}
	})
}

func TestLDAPRelayBackendWithRWMSuffixMassage(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedRelayConfiguration(t, store)

	address, stop := startServer(t, store, Config{})
	defer stop()

	relay, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(relay): %v", err)
	}
	defer relay.Close()
	if err := relay.Bind("cn=admin,dc=virtual,dc=test", "secret"); err != nil {
		t.Fatalf("Bind(relayed root): %v", err)
	}

	result, err := relay.Search(ldap.NewSearchRequest(
		"dc=virtual,dc=test",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"objectClass", "uid", "member"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(relay): %v", err)
	}
	assertRelaySearchDN(t, result, "uid=alice,ou=people,dc=virtual,dc=test")
	group := relaySearchEntry(t, result, "cn=staff,ou=groups,dc=virtual,dc=test")
	if got := group.GetAttributeValue("objectClass"); got != "groupOfNames" {
		t.Fatalf("relayed objectClass = %q, want groupOfNames", got)
	}
	if got := group.GetAttributeValue("member"); got != "uid=alice,ou=people,dc=virtual,dc=test" {
		t.Fatalf("relayed member = %q", got)
	}

	matched, err := relay.Compare(
		"uid=alice,ou=people,dc=virtual,dc=test",
		"uid",
		"alice",
	)
	if err != nil || !matched {
		t.Fatalf("Compare(relay) = %v, %v", matched, err)
	}

	add := ldap.NewAddRequest("uid=added,ou=people,dc=virtual,dc=test", nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"added"})
	add.Attribute("cn", []string{"Added User"})
	add.Attribute("sn", []string{"User"})
	add.Attribute("userPassword", []string{"added-secret"})
	if err := relay.Add(add); err != nil {
		t.Fatalf("Add(relay): %v", err)
	}

	modify := ldap.NewModifyRequest("uid=added,ou=people,dc=virtual,dc=test", nil)
	modify.Replace("mail", []string{"added@example.com"})
	if err := relay.Modify(modify); err != nil {
		t.Fatalf("Modify(relay): %v", err)
	}

	rename := ldap.NewModifyDNRequest(
		"uid=added,ou=people,dc=virtual,dc=test",
		"uid=renamed",
		true,
		"",
	)
	if err := relay.ModifyDN(rename); err != nil {
		t.Fatalf("ModifyDN(relay): %v", err)
	}

	direct, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(direct): %v", err)
	}
	defer direct.Close()
	if err := direct.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(direct root): %v", err)
	}
	real, err := direct.Search(ldap.NewSearchRequest(
		"uid=renamed,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"uid", "mail", "creatorsName"},
		nil,
	))
	if err != nil || len(real.Entries) != 1 {
		t.Fatalf("Search(direct added entry) entries=%d err=%v", len(real.Entries), err)
	}
	if got := real.Entries[0].GetAttributeValue("creatorsName"); got != "cn=admin,dc=example,dc=com" {
		t.Fatalf("stored creatorsName = %q", got)
	}

	groupAdd := ldap.NewAddRequest("cn=new-group,ou=groups,dc=virtual,dc=test", nil)
	groupAdd.Attribute("objectClass", []string{"groupOfNames"})
	groupAdd.Attribute("cn", []string{"new-group"})
	groupAdd.Attribute("member", []string{"uid=alice,ou=people,dc=virtual,dc=test"})
	if err := relay.Add(groupAdd); err != nil {
		t.Fatalf("Add(mapped group): %v", err)
	}
	realGroup, err := direct.Search(ldap.NewSearchRequest(
		"cn=new-group,ou=groups,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"objectClass", "uniqueMember"},
		nil,
	))
	if err != nil || len(realGroup.Entries) != 1 {
		t.Fatalf("Search(direct mapped group) entries=%d err=%v", len(realGroup.Entries), err)
	}
	if got := realGroup.Entries[0].GetAttributeValue("objectClass"); got != "groupOfUniqueNames" {
		t.Fatalf("stored objectClass = %q, want groupOfUniqueNames", got)
	}
	if got := realGroup.Entries[0].GetAttributeValue("uniqueMember"); got != "uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("stored uniqueMember = %q", got)
	}

	user, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(user): %v", err)
	}
	defer user.Close()
	if err := user.Bind(
		"uid=renamed,ou=people,dc=virtual,dc=test",
		"added-secret",
	); err != nil {
		t.Fatalf("Bind(relayed user): %v", err)
	}

	if err := relay.Del(ldap.NewDelRequest(
		"cn=new-group,ou=groups,dc=virtual,dc=test",
		nil,
	)); err != nil {
		t.Fatalf("Delete(mapped group): %v", err)
	}
	if err := relay.Del(ldap.NewDelRequest(
		"uid=renamed,ou=people,dc=virtual,dc=test",
		nil,
	)); err != nil {
		t.Fatalf("Delete(relay): %v", err)
	}
}

func TestLDAPRelayBackendSelectsDynamicTargetAfterSuffixMassage(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedRelayConfiguration(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN("olcDatabase={2}relay,cn=config")
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("olcRelay", nil)
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("remove explicit relay target: %v", err)
	}

	address, stop := startServer(t, store, Config{})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=virtual,dc=test", "secret"); err != nil {
		t.Fatalf("Bind(dynamic relay root): %v", err)
	}
	result, err := client.Search(ldap.NewSearchRequest(
		"uid=alice,ou=people,dc=virtual,dc=test",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(uid=alice)",
		[]string{"uid"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("Search(dynamic relay) entries=%d err=%v", len(result.Entries), err)
	}
}

func TestRelayConfigurationRejectsMissingExplicitTarget(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		{
			DN: "olcDatabase={1}relay,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcDatabase", Values: stringValues("{1}relay")},
				{Description: "olcSuffix", Values: stringValues("dc=virtual,dc=test")},
				{Description: "olcRelay", Values: stringValues("dc=missing,dc=test")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed invalid relay: %v", err)
	}
	if _, err := New(Config{Store: store}); err == nil {
		t.Fatal("New() accepted relay with a missing explicit target")
	}
}

func TestLDAPRelayBackendTransactionUsesMappedStorage(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedRelayConfiguration(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=virtual,dc=test",
		"secret",
	)
	defer connection.Close()
	identifier := startRawLDAPTransaction(t, connection, 2)
	entry := directory.Entry{
		DN: "uid=transaction,ou=people,dc=virtual,dc=test",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues("transaction")},
			{Description: "cn", Values: stringValues("Relay Transaction")},
			{Description: "sn", Values: stringValues("Transaction")},
		},
	}
	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			3,
			rawAddRequest(entry),
			rawTransactionSpecificationControl(identifier, true, true),
		),
		int64(ldapwire.ResultSuccess),
	)
	assertRawLDAPResult(
		t,
		sendRawLDAPOperation(
			t,
			connection,
			4,
			rawModifyReplaceRequest(entry.DN, "cn", "Committed Relay Transaction"),
			rawTransactionSpecificationControl(identifier, true, true),
		),
		int64(ldapwire.ResultSuccess),
	)
	assertRawLDAPResult(
		t,
		endRawLDAPTransaction(t, connection, 5, true, identifier),
		int64(ldapwire.ResultSuccess),
	)

	direct, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(direct): %v", err)
	}
	defer direct.Close()
	if err := direct.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(direct): %v", err)
	}
	result, err := direct.Search(ldap.NewSearchRequest(
		"uid=transaction,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("Search(transaction result) entries=%d err=%v", len(result.Entries), err)
	}
	if got := result.Entries[0].GetAttributeValue("cn"); got != "Committed Relay Transaction" {
		t.Fatalf("committed cn = %q", got)
	}
}

func TestLDAPRelayBackendSyncProviderMapsPersistentChanges(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedRelayConfiguration(t, store)
	enableRelaySyncProvider(t, store)
	address, stop := startServer(t, store, Config{})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=virtual,dc=test",
		"secret",
	)
	defer connection.Close()
	writeRawLDAPRequest(
		t,
		connection,
		2,
		rawSyncSearchRequestFor(
			t,
			"dc=virtual,dc=test",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			"(uid=*)",
		),
		rawSyncRequestControl(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshAndPersist,
		}, true),
	)

	var initial []string
	for {
		message := readRawSyncMessage(t, connection, 2)
		if message.entry != nil {
			initial = append(initial, message.entry.dn)
			continue
		}
		if message.info != nil &&
			message.info.Kind == ldapwire.SyncInfoRefreshPresent &&
			message.info.RefreshDone &&
			message.info.HasCookie {
			break
		}
		t.Fatalf("unexpected initial relay Sync response = %#v", message)
	}
	sort.Strings(initial)
	wantInitial := []string{
		"uid=alice,ou=people,dc=virtual,dc=test",
		"uid=bob,ou=people,dc=virtual,dc=test",
		"uid=carol,ou=people,dc=virtual,dc=test",
	}
	if fmt.Sprint(initial) != fmt.Sprint(wantInitial) {
		t.Fatalf("initial relay Sync DNs = %v, want %v", initial, wantInitial)
	}

	direct, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(direct): %v", err)
	}
	defer direct.Close()
	if err := direct.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(direct): %v", err)
	}
	add := ldap.NewAddRequest("uid=sync,ou=people,dc=example,dc=com", nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"sync"})
	add.Attribute("cn", []string{"Relay Sync"})
	add.Attribute("sn", []string{"Sync"})
	if err := direct.Add(add); err != nil {
		t.Fatalf("Add(direct): %v", err)
	}
	added := readRawSyncEntryState(t, connection, 2)
	if added.dn != "uid=sync,ou=people,dc=virtual,dc=test" ||
		added.state.State != ldapwire.SyncStateAdd ||
		!added.state.HasCookie {
		t.Fatalf("relayed persistent add = %#v", added)
	}

	modify := ldap.NewModifyRequest(
		"uid=sync,ou=people,dc=example,dc=com",
		nil,
	)
	modify.Replace("cn", []string{"Relay Sync Updated"})
	if err := direct.Modify(modify); err != nil {
		t.Fatalf("Modify(direct): %v", err)
	}
	modified := readRawSyncEntryState(t, connection, 2)
	if modified.dn != "uid=sync,ou=people,dc=virtual,dc=test" ||
		modified.state.State != ldapwire.SyncStateModify ||
		modified.state.EntryUUID != added.state.EntryUUID {
		t.Fatalf("relayed persistent modify = %#v", modified)
	}

	if err := direct.ModifyDN(ldap.NewModifyDNRequest(
		"uid=sync,ou=people,dc=example,dc=com",
		"uid=synced",
		true,
		"",
	)); err != nil {
		t.Fatalf("ModifyDN(direct): %v", err)
	}
	renamed := readRawSyncEntryState(t, connection, 2)
	if renamed.dn != "uid=synced,ou=people,dc=virtual,dc=test" ||
		renamed.state.State != ldapwire.SyncStateModify ||
		renamed.state.EntryUUID != added.state.EntryUUID {
		t.Fatalf("relayed persistent ModifyDN = %#v", renamed)
	}

	if err := direct.Del(ldap.NewDelRequest(
		"uid=synced,ou=people,dc=example,dc=com",
		nil,
	)); err != nil {
		t.Fatalf("Delete(direct): %v", err)
	}
	deleted := readRawSyncEntryState(t, connection, 2)
	if deleted.dn != "uid=synced,ou=people,dc=virtual,dc=test" ||
		deleted.attributeCount != 0 ||
		deleted.state.State != ldapwire.SyncStateDelete ||
		deleted.state.EntryUUID != added.state.EntryUUID {
		t.Fatalf("relayed persistent delete = %#v", deleted)
	}

	writeRawLDAPRequest(
		t,
		connection,
		3,
		rawExtendedRequest(
			cancelOID,
			ldapwire.EncodeCancelRequestValue(2),
			true,
		),
		nil,
	)
	results := make(map[int64]rawSyncMessage)
	for len(results) < 2 {
		message := readRawSyncMessage(t, connection, -1)
		results[message.messageID] = message
	}
	if results[3].resultCode != int64(ldapwire.ResultSuccess) ||
		results[2].resultCode != int64(ldapwire.ResultCanceled) {
		t.Fatalf("relay Sync cancel responses = %#v", results)
	}
}

func enableRelaySyncProvider(t *testing.T, store storage.Store) {
	t.Helper()
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		suffix, err := directory.ParseDN("dc=example,dc=com")
		if err != nil {
			return err
		}
		var entries []directory.Entry
		if err := writer.ForEach(func(entry directory.Entry) error {
			dn, err := directory.ParseDN(entry.DN)
			if err != nil {
				return err
			}
			if suffix.Equal(dn) || suffix.AncestorOf(dn) {
				entries = append(entries, entry)
			}
			return nil
		}); err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].DN < entries[j].DN
		})
		var contextCSN string
		for index := range entries {
			contextCSN = fmt.Sprintf(
				"20260802010101.%06dZ#000000#000#000000",
				index+1,
			)
			entries[index].ReplaceValues("entryUUID", stringValues(fmt.Sprintf(
				"10000000-0000-4000-8000-%012x",
				index+1,
			)))
			entries[index].ReplaceValues("entryCSN", stringValues(contextCSN))
		}
		for index := range entries {
			if entries[index].DN == suffix.String() {
				entries[index].ReplaceValues(
					"contextCSN",
					stringValues(contextCSN),
				)
			}
			if err := writer.Put(entries[index], true); err != nil {
				return err
			}
		}
		return writer.Put(directory.Entry{
			DN: "olcOverlay={1}syncprov,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
				{Description: "olcOverlay", Values: stringValues("{1}syncprov")},
			},
		}, false)
	})
	if err != nil {
		t.Fatalf("enable relay Sync provider: %v", err)
	}
}

func seedRelayConfiguration(t *testing.T, store storage.Store) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
			},
		},
		{
			DN: "olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}mdb")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				{Description: "olcRootDN", Values: stringValues("cn=admin,dc=example,dc=com")},
				{Description: "olcRootPW", Values: stringValues("secret")},
				{Description: "olcAccess", Values: stringValues("{0}to * by * read")},
			},
		},
		{
			DN: "olcDatabase={2}relay,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcRelayConfig")},
				{Description: "olcDatabase", Values: stringValues("{2}relay")},
				{Description: "olcSuffix", Values: stringValues("dc=virtual,dc=test")},
				{Description: "olcRelay", Values: stringValues("dc=example,dc=com")},
				{Description: "olcAccess", Values: stringValues(
					"{0}to attrs=userPassword by anonymous auth by self =xw by * none",
					"{1}to * by users read by * none",
				)},
			},
		},
		{
			DN: "olcOverlay={0}sssvlv,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
				{Description: "olcOverlay", Values: stringValues("{0}sssvlv")},
				{Description: "olcSssVlvMax", Values: stringValues("100")},
				{Description: "olcSssVlvMaxKeys", Values: stringValues("2")},
			},
		},
		{
			DN: "olcOverlay={0}rwm,olcDatabase={2}relay,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcRwmConfig")},
				{Description: "olcOverlay", Values: stringValues("{0}rwm")},
				{Description: "olcRwmRewrite", Values: stringValues(
					`{0}rwm-suffixmassage "dc=virtual,dc=test" "dc=example,dc=com"`,
				)},
				{Description: "olcRwmMap", Values: stringValues(
					"{0}objectClass groupOfNames groupOfUniqueNames",
					"{1}attribute member uniqueMember",
				)},
			},
		},
		{
			DN: "dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("domain")},
				{Description: "dc", Values: stringValues("example")},
			},
		},
		{
			DN: "ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit")},
				{Description: "ou", Values: stringValues("people")},
			},
		},
		{
			DN: "ou=groups,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit")},
				{Description: "ou", Values: stringValues("groups")},
			},
		},
		{
			DN: "uid=alice,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("alice")},
				{Description: "cn", Values: stringValues("Alice")},
				{Description: "sn", Values: stringValues("Example")},
				{Description: "userPassword", Values: stringValues("alice-secret")},
			},
		},
		{
			DN: "uid=bob,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("bob")},
				{Description: "cn", Values: stringValues("Bob")},
				{Description: "sn", Values: stringValues("Bob")},
			},
		},
		{
			DN: "uid=carol,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("carol")},
				{Description: "cn", Values: stringValues("Carol")},
				{Description: "sn", Values: stringValues("Carol")},
			},
		},
		{
			DN: "cn=staff,ou=groups,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("groupOfUniqueNames")},
				{Description: "cn", Values: stringValues("staff")},
				{Description: "uniqueMember", Values: stringValues("uid=alice,ou=people,dc=example,dc=com")},
			},
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com", "cn=config"})
	}); err != nil {
		t.Fatalf("seed relay configuration: %v", err)
	}
}

func assertRelaySearchDN(t *testing.T, result *ldap.SearchResult, want string) {
	t.Helper()
	_ = relaySearchEntry(t, result, want)
}

func relaySearchEntry(
	t *testing.T,
	result *ldap.SearchResult,
	want string,
) *ldap.Entry {
	t.Helper()
	for _, entry := range result.Entries {
		if entry.DN == want {
			return entry
		}
	}
	t.Fatalf("search result does not contain %q: %#v", want, result.Entries)
	return nil
}
