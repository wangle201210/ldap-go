package server

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	translucentPhase2UserDN  = "uid=phase2," + translucentTestBaseDN
	translucentPhase2StaleDN = "uid=phase2-stale," + translucentTestBaseDN
	translucentPhase2OldDN   = "uid=phase2-old," + translucentTestBaseDN
	translucentPhase2NewDN   = "uid=phase2-new," + translucentTestBaseDN
)

func TestTranslucentPhaseTwoConfiguration(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	overlay := translucentTestOverlayEntry(translucentTestOverlayDN, false)
	overlay.Attributes = append(overlay.Attributes,
		directory.Attribute{Description: "olcTranslucentStrict", Values: stringValues("TRUE")},
		directory.Attribute{Description: "olcTranslucentNoGlue", Values: stringValues("TRUE")},
		directory.Attribute{Description: "olcTranslucentLocal", Values: stringValues("employeeType, description", "roomNumber")},
		directory.Attribute{Description: "olcTranslucentRemote", Values: stringValues("carLicense")},
		directory.Attribute{Description: "olcTranslucentBindLocal", Values: stringValues("TRUE")},
		directory.Attribute{Description: "olcTranslucentPwModLocal", Values: stringValues("TRUE")},
	)
	putTranslucentTestEntries(t, store,
		overlay,
		translucentTestBackendEntry(
			translucentTestBackendDN,
			"{0}ldap",
			"ldap://127.0.0.1:389",
		),
	)

	var configuration translucentRuntimeConfiguration
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		var err error
		configuration, err = loadTranslucentRuntimeConfiguration(reader, overlay)
		return err
	}); err != nil {
		t.Fatalf("load translucent Phase 2 configuration: %v", err)
	}
	if !configuration.strict || !configuration.noGlue ||
		!configuration.bindLocal || !configuration.pwmodLocal {
		t.Fatalf("boolean configuration = %#v", configuration)
	}
	for _, attribute := range []string{"employeeType", "description", "roomNumber"} {
		if _, ok := configuration.local[strings.ToLower(attribute)]; !ok {
			t.Fatalf("local attributes omit %q: %#v", attribute, configuration.local)
		}
	}
	if _, ok := configuration.remote["carlicense"]; !ok {
		t.Fatalf("remote attributes = %#v", configuration.remote)
	}

	for _, value := range []string{
		"employeeType,,description",
		".description",
		";lang-en",
		"1.03.6",
	} {
		invalid := overlay.Clone()
		invalid.ReplaceValues("olcTranslucentLocal", stringValues(value))
		if err := store.View(context.Background(), func(reader storage.Reader) error {
			_, err := loadTranslucentRuntimeConfiguration(reader, invalid)
			return err
		}); err == nil {
			t.Fatalf("invalid split-filter attribute %q was accepted", value)
		}
	}
	invalid := overlay.Clone()
	invalid.ReplaceValues("olcTranslucentStrict", stringValues("yes"))
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		_, err := loadTranslucentRuntimeConfiguration(reader, invalid)
		return err
	}); err == nil {
		t.Fatal("non-boolean strict value was accepted")
	}
}

func TestTranslucentFilterSubsetMatchesOpenLDAPShape(t *testing.T) {
	filter, err := ldapwire.CompileFilter(
		"(&(|(employeeType=consultant)(description=local))(carLicense=RIGHT)(uid=phase2))",
	)
	if err != nil {
		t.Fatalf("CompileFilter(): %v", err)
	}
	local, ok := translucentFilterSubset(
		filter,
		translucentAttributeSet{"employeetype": {}, "description": {}},
		nil,
	)
	if !ok || local.Kind != directory.FilterOr || len(local.Children) != 2 {
		t.Fatalf("local subset = %#v, %t", local, ok)
	}
	remote, ok := translucentFilterSubset(
		filter,
		translucentAttributeSet{"carlicense": {}},
		nil,
	)
	if !ok || remote.Kind != directory.FilterEquality ||
		!strings.EqualFold(remote.Attribute, "carLicense") {
		t.Fatalf("remote subset = %#v, %t", remote, ok)
	}
	if _, ok := translucentFilterSubset(
		filter,
		translucentAttributeSet{"roomnumber": {}},
		nil,
	); ok {
		t.Fatal("unreferenced attribute produced a filter subset")
	}
}

func TestTranslucentPhaseTwoSplitFilters(t *testing.T) {
	options := translucentPhase2Options{
		local:  []string{"description"},
		remote: []string{"telephoneNumber"},
	}
	root, _, _, stop := startTranslucentPhase2Pair(t, options)
	defer stop()
	defer root.Close()

	tests := []struct {
		filter string
		want   []string
	}{
		{
			filter: "(description=local-phase2)",
			want:   []string{translucentPhase2UserDN},
		},
		{
			filter: "(telephoneNumber=100)",
			want:   []string{translucentPhase2UserDN},
		},
		{
			filter: "(&(description=local-phase2)(telephoneNumber=100))",
			want:   []string{translucentPhase2UserDN},
		},
		{
			filter: "(|(description=local-phase2)(telephoneNumber=100))",
			want:   []string{translucentPhase2UserDN},
		},
		{
			filter: "(cn=Local Phase Two)",
			want:   nil,
		},
	}
	for _, test := range tests {
		t.Run(test.filter, func(t *testing.T) {
			result, err := root.Search(ldap.NewSearchRequest(
				translucentTestBaseDN,
				ldap.ScopeWholeSubtree,
				ldap.NeverDerefAliases,
				0,
				0,
				false,
				test.filter,
				[]string{"uid"},
				nil,
			))
			if err != nil {
				t.Fatalf("Search(%s): %v", test.filter, err)
			}
			got := make([]string, 0, len(result.Entries))
			for _, entry := range result.Entries {
				got = append(got, strings.ToLower(entry.DN))
			}
			sort.Strings(got)
			want := append([]string(nil), test.want...)
			for index := range want {
				want[index] = strings.ToLower(want[index])
			}
			sort.Strings(want)
			if !slices.Equal(got, want) {
				t.Fatalf("Search(%s) DNs = %q, want %q", test.filter, got, want)
			}
		})
	}
}

func TestTranslucentPhaseTwoBindLocalAndPasswordModify(t *testing.T) {
	t.Run("bindLocal disabled", func(t *testing.T) {
		root, address, _, stop := startTranslucentPhase2Pair(t, translucentPhase2Options{})
		defer stop()
		defer root.Close()
		client := dialTranslucentPhase2(t, address)
		defer client.Close()
		err := client.Bind(translucentPhase2UserDN, "local-phase2-secret")
		assertLDAPResultCode(t, err, ldap.LDAPResultInvalidCredentials)
	})

	t.Run("remote first local fallback and pwmod", func(t *testing.T) {
		root, address, _, stop := startTranslucentPhase2Pair(t, translucentPhase2Options{
			bindLocal:  true,
			pwmodLocal: true,
		})
		defer stop()
		defer root.Close()

		remotePassword := dialTranslucentPhase2(t, address)
		defer remotePassword.Close()
		if err := remotePassword.Bind(translucentPhase2UserDN, "remote-phase2-secret"); err != nil {
			t.Fatalf("Bind(remote credential): %v", err)
		}
		localPassword := dialTranslucentPhase2(t, address)
		defer localPassword.Close()
		if err := localPassword.Bind(translucentPhase2UserDN, "local-phase2-secret"); err != nil {
			t.Fatalf("Bind(local fallback credential): %v", err)
		}

		if _, err := root.PasswordModify(ldap.NewPasswordModifyRequest(
			translucentPhase2UserDN,
			"",
			"changed-local-secret",
		)); err != nil {
			t.Fatalf("PasswordModify(local): %v", err)
		}
		changed := dialTranslucentPhase2(t, address)
		defer changed.Close()
		if err := changed.Bind(translucentPhase2UserDN, "changed-local-secret"); err != nil {
			t.Fatalf("Bind(changed local credential): %v", err)
		}
	})

	t.Run("pwmodLocal disabled", func(t *testing.T) {
		root, _, _, stop := startTranslucentPhase2Pair(t, translucentPhase2Options{
			bindLocal: true,
		})
		defer stop()
		defer root.Close()
		_, err := root.PasswordModify(ldap.NewPasswordModifyRequest(
			translucentPhase2UserDN,
			"",
			"rejected-secret",
		))
		assertLDAPResultCode(t, err, ldap.LDAPResultConstraintViolation)
	})
}

func TestTranslucentPhaseTwoWriteSemantics(t *testing.T) {
	root, address, localStore, stop := startTranslucentPhase2Pair(t, translucentPhase2Options{})
	defer stop()
	defer root.Close()

	nonRoot := dialTranslucentPhase2(t, address)
	defer nonRoot.Close()
	if err := nonRoot.Bind(translucentPhase2UserDN, "remote-phase2-secret"); err != nil {
		t.Fatalf("Bind(non-root): %v", err)
	}
	denied := ldap.NewAddRequest("uid=denied,"+translucentTestBaseDN, nil)
	denied.Attribute("uid", []string{"denied"})
	err := nonRoot.Add(denied)
	assertLDAPResultCode(t, err, ldap.LDAPResultInsufficientAccessRights)

	modify := ldap.NewModifyRequest(translucentPhase2UserDN, nil)
	modify.Replace("description", []string{"local-write"})
	if err := root.Modify(modify); err != nil {
		t.Fatalf("Modify(remote-only entry): %v", err)
	}
	assertTranslucentPhase2Attribute(t, root, translucentPhase2UserDN, "description", "local-write")

	dropDelete := ldap.NewModifyRequest(translucentPhase2UserDN, nil)
	dropDelete.Delete("telephoneNumber", nil)
	if err := root.Modify(dropDelete); err != nil {
		t.Fatalf("Modify(drop unshadowed remote delete): %v", err)
	}
	assertTranslucentPhase2Attribute(t, root, translucentPhase2UserDN, "telephoneNumber", "100")

	setStrict := translucentPhase2ConfigModify(t, address)
	setStrict.Replace("olcTranslucentStrict", []string{"TRUE"})
	if err := setStrictClient(t, address, setStrict); err != nil {
		t.Fatalf("enable strict: %v", err)
	}
	strictDelete := ldap.NewModifyRequest(translucentPhase2UserDN, nil)
	strictDelete.Delete("telephoneNumber", nil)
	err = root.Modify(strictDelete)
	assertLDAPResultCode(t, err, ldap.LDAPResultConstraintViolation)

	localOld := ldap.NewAddRequest(translucentPhase2OldDN, nil)
	localOld.Attribute("uid", []string{"phase2-old"})
	localOld.Attribute("description", []string{"renamed-override"})
	if err := root.Add(localOld); err != nil {
		t.Fatalf("Add(local override): %v", err)
	}
	if err := root.ModifyDN(ldap.NewModifyDNRequest(
		translucentPhase2OldDN,
		"uid=phase2-new",
		true,
		"",
	)); err != nil {
		t.Fatalf("ModifyDN(local override): %v", err)
	}
	assertTranslucentPhase2Attribute(t, root, translucentPhase2NewDN, "description", "renamed-override")
	assertTranslucentPhase2Attribute(t, root, translucentPhase2OldDN, "description", "remote-old")
	if err := root.Del(ldap.NewDelRequest(translucentPhase2NewDN, nil)); err != nil {
		t.Fatalf("Delete(local override): %v", err)
	}
	assertTranslucentPhase2Attribute(t, root, translucentPhase2NewDN, "description", "remote-new")

	missingParentDN := "uid=glued,ou=missing," + translucentTestBaseDN
	setNoGlue := translucentPhase2ConfigModify(t, address)
	setNoGlue.Replace("olcTranslucentNoGlue", []string{"TRUE"})
	if err := setStrictClient(t, address, setNoGlue); err != nil {
		t.Fatalf("enable noGlue: %v", err)
	}
	noGlueAdd := ldap.NewAddRequest(missingParentDN, nil)
	noGlueAdd.Attribute("uid", []string{"glued"})
	err = root.Add(noGlueAdd)
	assertLDAPResultCode(t, err, ldap.LDAPResultNoSuchObject)

	unsetNoGlue := translucentPhase2ConfigModify(t, address)
	unsetNoGlue.Replace("olcTranslucentNoGlue", []string{"FALSE"})
	if err := setStrictClient(t, address, unsetNoGlue); err != nil {
		t.Fatalf("disable noGlue: %v", err)
	}
	if err := root.Add(noGlueAdd); err != nil {
		t.Fatalf("Add(with glue): %v", err)
	}
	assertTranslucentStoredEntry(t, localStore, "ou=missing,"+translucentTestBaseDN)
	assertTranslucentStoredEntry(t, localStore, missingParentDN)
}

func TestTranslucentPhaseTwoAssertionControls(t *testing.T) {
	root, _, localStore, stop := startTranslucentPhase2Pair(t, translucentPhase2Options{})
	defer stop()
	defer root.Close()

	failedAddDN := "uid=assertion-add," + translucentTestBaseDN
	failedAdd := ldap.NewAddRequest(
		failedAddDN,
		[]ldap.Control{newAssertionControl(t, "(uid=different)")},
	)
	failedAdd.Attribute("uid", []string{"assertion-add"})
	err := root.Add(failedAdd)
	assertLDAPResultCode(t, err, ldap.LDAPResultAssertionFailed)
	failedAddParsed, parseErr := directory.ParseDN(failedAddDN)
	if parseErr != nil {
		t.Fatalf("ParseDN(%s): %v", failedAddDN, parseErr)
	}
	err = localStore.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Get(failedAddParsed)
		return err
	})
	if !errors.Is(err, storage.ErrEntryNotFound) {
		t.Fatalf("assertion-failed translucent Add stored an entry: %v", err)
	}

	failedModify := ldap.NewModifyRequest(
		translucentPhase2OldDN,
		[]ldap.Control{newAssertionControl(t, "(description=wrong)")},
	)
	failedModify.Replace("description", []string{"must-not-be-stored"})
	err = root.Modify(failedModify)
	assertLDAPResultCode(t, err, ldap.LDAPResultAssertionFailed)
	assertTranslucentPhase2Attribute(
		t,
		root,
		translucentPhase2OldDN,
		"description",
		"remote-old",
	)

	successfulModify := ldap.NewModifyRequest(
		translucentPhase2OldDN,
		[]ldap.Control{newAssertionControl(t, "(description=remote-old)")},
	)
	successfulModify.Replace("description", []string{"asserted-local"})
	if err := root.Modify(successfulModify); err != nil {
		t.Fatalf("Modify(remote-only entry with matching assertion): %v", err)
	}
	assertTranslucentPhase2Attribute(
		t,
		root,
		translucentPhase2OldDN,
		"description",
		"asserted-local",
	)
}

type translucentPhase2Options struct {
	strict     bool
	noGlue     bool
	local      []string
	remote     []string
	bindLocal  bool
	pwmodLocal bool
}

func startTranslucentPhase2Pair(
	t *testing.T,
	options translucentPhase2Options,
) (*ldap.Conn, string, storage.Store, func()) {
	t.Helper()
	remoteStore := storage.NewMemory()
	seedOnlineConfiguration(t, remoteStore)
	putTranslucentTestEntries(t, remoteStore, translucentPhase2RemoteEntries()...)
	remoteAddress, stopRemote := startServer(t, remoteStore, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})

	overlay := translucentTestOverlayEntry(translucentTestOverlayDN, false)
	appendBoolean := func(description string, value bool) {
		if value {
			overlay.Attributes = append(overlay.Attributes, directory.Attribute{
				Description: description,
				Values:      stringValues("TRUE"),
			})
		}
	}
	appendBoolean("olcTranslucentStrict", options.strict)
	appendBoolean("olcTranslucentNoGlue", options.noGlue)
	appendBoolean("olcTranslucentBindLocal", options.bindLocal)
	appendBoolean("olcTranslucentPwModLocal", options.pwmodLocal)
	if len(options.local) > 0 {
		overlay.Attributes = append(overlay.Attributes, directory.Attribute{
			Description: "olcTranslucentLocal",
			Values:      stringValues(options.local...),
		})
	}
	if len(options.remote) > 0 {
		overlay.Attributes = append(overlay.Attributes, directory.Attribute{
			Description: "olcTranslucentRemote",
			Values:      stringValues(options.remote...),
		})
	}

	localStore := storage.NewMemory()
	seedOnlineConfiguration(t, localStore)
	entries := []directory.Entry{
		overlay,
		translucentTestBackendEntry(
			translucentTestBackendDN,
			"{0}ldap",
			"ldap://"+remoteAddress,
		),
		{
			DN: translucentTestBaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit")},
				{Description: "ou", Values: stringValues("translucent")},
			},
		},
		{
			DN: translucentPhase2UserDN,
			Attributes: []directory.Attribute{
				{Description: "description", Values: stringValues("local-phase2")},
				{Description: "cn", Values: stringValues("Local Phase Two")},
				{Description: "employeeType", Values: stringValues("consultant")},
				{Description: "userPassword", Values: stringValues("local-phase2-secret")},
			},
		},
		{
			DN: translucentPhase2StaleDN,
			Attributes: []directory.Attribute{
				{Description: "employeeType", Values: stringValues("consultant")},
			},
		},
	}
	putTranslucentTestEntries(t, localStore, entries...)
	localAddress, stopLocal := startServer(t, localStore, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	root := dialTranslucentPhase2(t, localAddress)
	if err := root.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		root.Close()
		stopLocal()
		stopRemote()
		t.Fatalf("Bind(local root): %v", err)
	}
	stop := func() {
		stopLocal()
		stopRemote()
		_ = localStore.Close()
		_ = remoteStore.Close()
	}
	return root, localAddress, localStore, stop
}

func translucentPhase2RemoteEntries() []directory.Entry {
	entries := []directory.Entry{
		{
			DN: translucentTestBaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("organizationalUnit")},
				{Description: "ou", Values: stringValues("translucent")},
			},
		},
		translucentPersonEntry(
			translucentPhase2UserDN,
			"phase2",
			"Phase Two",
			[]string{"remote-phase2"},
			"100",
		),
		translucentPersonEntry(
			translucentPhase2OldDN,
			"phase2-old",
			"Phase Two Old",
			[]string{"remote-old"},
			"101",
		),
		translucentPersonEntry(
			translucentPhase2NewDN,
			"phase2-new",
			"Phase Two New",
			[]string{"remote-new"},
			"102",
		),
	}
	entries[1].Attributes = append(entries[1].Attributes,
		directory.Attribute{Description: "carLicense", Values: stringValues("RIGHT")},
		directory.Attribute{Description: "userPassword", Values: stringValues("remote-phase2-secret")},
	)
	return entries
}

func dialTranslucentPhase2(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", address, err)
	}
	return client
}

func translucentPhase2ConfigModify(t *testing.T, _ string) *ldap.ModifyRequest {
	t.Helper()
	return ldap.NewModifyRequest(translucentTestOverlayDN, nil)
}

func setStrictClient(
	t *testing.T,
	address string,
	request *ldap.ModifyRequest,
) error {
	t.Helper()
	client := dialTranslucentPhase2(t, address)
	defer client.Close()
	if err := client.Bind("cn=config", "config-secret"); err != nil {
		t.Fatalf("Bind(config): %v", err)
	}
	return client.Modify(request)
}

func assertTranslucentPhase2Attribute(
	t *testing.T,
	client *ldap.Conn,
	dn,
	attribute,
	want string,
) {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{attribute},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(%s): %v", dn, err)
	}
	if len(result.Entries) != 1 ||
		result.Entries[0].GetAttributeValue(attribute) != want {
		t.Fatalf("%s %s = %#v, want %q", dn, attribute, result.Entries, want)
	}
}

func assertTranslucentStoredEntry(t *testing.T, store storage.Store, rawDN string) {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%s): %v", rawDN, err)
	}
	err = store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Get(dn)
		return err
	})
	if err != nil {
		t.Fatalf("local translucent entry %s: %v", rawDN, err)
	}
}

func TestEnsureTranslucentParentsNoGlue(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	suffix, _ := directory.ParseDN("dc=example,dc=com")
	target, _ := directory.ParseDN("uid=user,ou=missing,dc=example,dc=com")
	database := runtimeDatabase{suffixes: []directory.DN{suffix}}
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		return ensureTranslucentParents(writer, database, target, true)
	})
	failure := asOperationFailure(err)
	if failure == nil || failure.result.Code != ldapwire.ResultNoSuchObject {
		t.Fatalf("noGlue failure = %#v, %v", failure, err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return ensureTranslucentParents(writer, database, target, false)
	}); err != nil {
		t.Fatalf("ensure glue parents: %v", err)
	}
	parent, _ := target.Parent()
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		entry, err := reader.Get(parent)
		if err != nil {
			return err
		}
		if !entry.HasValue("objectClass", []byte("glue")) {
			return errors.New("parent is not a glue entry")
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect glue parent: %v", err)
	}
}
