package server

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientMatchedValuesControl(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	dn, err := directory.ParseDN("uid=alice,ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("mail", stringValues(
			"alice@example.com",
			"alice@other.test",
			"admin@example.com",
		))
		entry.ReplaceValues("cn", stringValues("Alice Example", "Directory Admin"))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("seed matched values entry: %v", err)
	}

	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	request := ldap.NewSearchRequest(
		"uid=alice,ou=people,dc=example,dc=com",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"mail", "cn", "userPassword"},
		[]ldap.Control{matchedValuesControl(t, true,
			"(mail=*@example.com)",
			"(cn=Alice*)",
			"(userPassword=*)",
		)},
	)
	result, err := client.Search(request)
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("matched values Search() = %#v, %v", result, err)
	}
	entry := result.Entries[0]
	if got, want := entry.GetAttributeValues("mail"), []string{"alice@example.com", "admin@example.com"}; !equalStringSet(got, want) {
		t.Fatalf("matched mail = %q, want %q", got, want)
	}
	if got := entry.GetAttributeValues("cn"); len(got) != 1 || got[0] != "Alice Example" {
		t.Fatalf("matched cn = %q", got)
	}
	if values := entry.GetRawAttributeValues("userPassword"); len(values) != 0 {
		t.Fatalf("matched values exposed unreadable userPassword: %q", values)
	}
}

func TestLDAPClientMatchedValuesTypesOnlyAndEmptyFilter(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	for _, test := range []struct {
		name      string
		typesOnly bool
		control   ldap.Control
	}{
		{name: "types only", typesOnly: true, control: matchedValuesControl(t, false, "(mail=none)")},
		{name: "empty sequence", control: matchedValuesControl(t, false)},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := client.Search(ldap.NewSearchRequest(
				"uid=alice,ou=people,dc=example,dc=com",
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				0,
				0,
				test.typesOnly,
				"(objectClass=*)",
				[]string{"cn", "sn"},
				[]ldap.Control{test.control},
			))
			if err != nil || len(result.Entries) != 1 {
				t.Fatalf("Search() = %#v, %v", result, err)
			}
			entry := result.Entries[0]
			if !entryHasLDAPAttribute(entry, "cn") || !entryHasLDAPAttribute(entry, "sn") {
				t.Fatalf("returned attributes = %#v", entry.Attributes)
			}
			if test.typesOnly &&
				(len(entry.GetRawAttributeValues("cn")) != 0 || len(entry.GetRawAttributeValues("sn")) != 0) {
				t.Fatalf("typesOnly returned values: %#v", entry.Attributes)
			}
		})
	}
}

func TestLDAPClientMatchedValuesPagedEntriesRemainUnfiltered(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	alice, err := directory.ParseDN("uid=alice,ou=people,dc=example,dc=com")
	if err != nil {
		t.Fatalf("ParseDN(): %v", err)
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(alice)
		if err != nil {
			return err
		}
		entry.ReplaceValues("mail", stringValues("alice@example.com", "alice@other.test"))
		if err := writer.Put(entry, true); err != nil {
			return err
		}
		return writer.Put(directory.Entry{
			DN: "uid=bob,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("inetOrgPerson")},
				{Description: "uid", Values: stringValues("bob")},
				{Description: "cn", Values: stringValues("Bob Example")},
				{Description: "sn", Values: stringValues("Example")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed paged matched-values entry: %v", err)
	}
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind("uid=alice,ou=people,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	paging := ldap.NewControlPaging(1)
	var dns []string
	for {
		result, err := client.Search(ldap.NewSearchRequest(
			"ou=people,dc=example,dc=com",
			ldap.ScopeSingleLevel,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(uid=*)",
			[]string{"uid", "mail"},
			[]ldap.Control{paging, matchedValuesControl(t, true, "(mail=*@example.com)")},
		))
		if err != nil || len(result.Entries) != 1 {
			t.Fatalf("paged matched-values Search() = %#v, %v", result, err)
		}
		entry := result.Entries[0]
		dns = append(dns, entry.DN)
		if values := entry.GetAttributeValues("uid"); len(values) != 0 {
			t.Fatalf("matched-values page returned uid values: %q", values)
		}
		response := pagedResponseControl(t, result)
		if len(response.Cookie) == 0 {
			break
		}
		paging.SetCookie(response.Cookie)
	}
	if len(dns) != 2 || !slices.Contains(dns, "uid=alice,ou=people,dc=example,dc=com") ||
		!slices.Contains(dns, "uid=bob,ou=people,dc=example,dc=com") {
		t.Fatalf("paged matched-values DNs = %q", dns)
	}
}

func TestMatchedValuesControlValidation(t *testing.T) {
	valid := matchedValuesControl(t, true, "(cn=Alice)").(*ldap.ControlString)
	for _, test := range []struct {
		name     string
		controls []ldapwire.Control
		want     ldapwire.ResultCode
	}{
		{
			name: "duplicate",
			controls: []ldapwire.Control{
				{OID: ldapwire.MatchedValuesControlOID, Critical: true, HasValue: true, Value: []byte(valid.ControlValue)},
				{OID: ldapwire.MatchedValuesControlOID, Critical: false, HasValue: true, Value: []byte(valid.ControlValue)},
			},
			want: ldapwire.ResultProtocolError,
		},
		{
			name:     "absent",
			controls: []ldapwire.Control{{OID: ldapwire.MatchedValuesControlOID, Critical: true}},
			want:     ldapwire.ResultProtocolError,
		},
		{
			name: "empty",
			controls: []ldapwire.Control{{
				OID: ldapwire.MatchedValuesControlOID, Critical: true, HasValue: true,
			}},
			want: ldapwire.ResultProtocolError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, failure := parseRequestControls(test.controls, supportsMatchedValues)
			if failure == nil || failure.Code != test.want {
				t.Fatalf("control failure = %#v, want %d", failure, test.want)
			}
		})
	}
	if _, failure := parseRequestControls(
		[]ldapwire.Control{{OID: ldapwire.MatchedValuesControlOID, Critical: true}},
		0,
	); failure == nil || failure.Code != ldapwire.ResultUnavailableCriticalExtension {
		t.Fatalf("unsupported critical control failure = %#v", failure)
	}
	if _, failure := parseRequestControls(
		[]ldapwire.Control{{
			OID: ldapwire.MatchedValuesControlOID, HasValue: true, Value: []byte("malformed but ignored"),
		}},
		0,
	); failure != nil {
		t.Fatalf("unsupported noncritical control failure = %#v", failure)
	}
}

func TestMatchedValuesOrderingExtensibleAndOpenLDAPQuirks(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	entry := directory.Entry{
		DN: "cn=Monitor",
		Attributes: []directory.Attribute{{
			Description: "monitorCounter",
			Values:      stringValues("2", "10", "20"),
		}},
	}
	for _, test := range []struct {
		name    string
		filter  string
		want    []string
		present bool
	}{
		{name: "greater or equal uses ordering", filter: "(monitorCounter>=10)", want: []string{"10", "20"}, present: true},
		{name: "less or equal uses ordering", filter: "(monitorCounter<=10)", want: []string{"2", "10"}, present: true},
		{name: "matching rule without type", filter: "(:integerMatch:=10)", want: []string{"10"}, present: true},
		{name: "approx is inert", filter: "(monitorCounter~=10)", present: true},
		{name: "operational empty attribute retained", filter: "(monitorCounter=99)", present: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			filter, err := ldapwire.CompileFilter(test.filter)
			if err != nil {
				t.Fatalf("CompileFilter(): %v", err)
			}
			filtered := applyMatchedValuesFilter(registry, entry, []directory.Filter{filter})
			if got := directoryStringValues(filtered.Values("monitorCounter")); !equalStringSet(got, test.want) {
				t.Fatalf("filtered values = %q, want %q", got, test.want)
			}
			if filtered.HasAttribute("monitorCounter") != test.present {
				t.Fatalf("monitorCounter present = %t, want %t", filtered.HasAttribute("monitorCounter"), test.present)
			}
		})
	}
}

func TestRootDSEPublishesMatchedValuesControl(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	result, err := client.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"supportedControl"}, nil,
	))
	if err != nil || len(result.Entries) != 1 ||
		!slices.Contains(result.Entries[0].GetAttributeValues("supportedControl"), ldapwire.MatchedValuesControlOID) {
		t.Fatalf("root DSE supportedControl = %#v, %v", result, err)
	}
}

func TestMatchedValuesMalformedBERDisconnects(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	defer connection.Close()
	control := ber.NewSequence("matched values control")
	control.AppendChild(rawOctetString([]byte(ldapwire.MatchedValuesControlOID)))
	control.AppendChild(ber.NewBoolean(
		ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "criticality",
	))
	control.AppendChild(rawOctetString([]byte{0x31, 0x00}))
	writeRawLDAPRequest(
		t,
		connection,
		1,
		rawSyncSearchRequestFor(
			t,
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			"(objectClass=*)",
		),
		control,
	)
	response, err := ber.ReadPacket(connection)
	if err != nil || len(response.Children) < 2 {
		t.Fatalf("read Notice of Disconnection: %#v, %v", response, err)
	}
	messageID, err := ber.ParseInt64(response.Children[0].Data.Bytes())
	if err != nil || messageID != 0 ||
		rawLDAPResultCode(t, response.Children[1]) != int64(ldap.LDAPResultProtocolError) {
		t.Fatalf("Notice of Disconnection = %#v, %v", response, err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if _, err := connection.Read(buffer); err == nil {
		t.Fatal("connection remained open after malformed valuesReturnFilter")
	}
}

func TestPcacheStripsMatchedValuesFromCacheFill(t *testing.T) {
	controls := pcacheWithoutTransientSearchControls([]ldapwire.Control{
		{OID: pagedResultsControlOID, Critical: false},
		{OID: ldapwire.MatchedValuesControlOID, Critical: true, HasValue: true, Value: []byte{0x30, 0x00}},
		{OID: assertionControlOID, Critical: true, HasValue: true, Value: []byte{0x87, 0x02, 'c', 'n'}},
	})
	if len(controls) != 1 || controls[0].OID != assertionControlOID {
		t.Fatalf("pcache forwarded controls = %#v", controls)
	}
}

func matchedValuesControl(t *testing.T, critical bool, filters ...string) ldap.Control {
	t.Helper()
	sequence := ber.NewSequence("values return filter")
	for _, value := range filters {
		filter, err := ldap.CompileFilter(value)
		if err != nil {
			t.Fatalf("CompileFilter(%q): %v", value, err)
		}
		sequence.AppendChild(filter)
	}
	return ldap.NewControlString(
		ldapwire.MatchedValuesControlOID,
		critical,
		string(sequence.Bytes()),
	)
}

func equalStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[string]int, len(left))
	for _, value := range left {
		seen[value]++
	}
	for _, value := range right {
		if seen[value] == 0 {
			return false
		}
		seen[value]--
	}
	return true
}

func entryHasLDAPAttribute(entry *ldap.Entry, description string) bool {
	for _, attribute := range entry.Attributes {
		if attribute.Name == description {
			return true
		}
	}
	return false
}

func directoryStringValues(values [][]byte) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = string(values[index])
	}
	return result
}
