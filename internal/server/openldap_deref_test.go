package server

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestOpenLDAPReferenceDerefOverlayRegistration(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	extraData := `
dn: uid=deref-source,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: deref-source
cn: Deref Source
sn: Source
manager: uid=alice,ou=people,dc=example,dc=com
`
	request := encodeOpenLDAPDerefRequest([]ldapwire.DerefSpec{{
		DerefAttr:  "manager",
		Attributes: []string{"uid"},
	}})

	tests := []struct {
		name         string
		globalConfig string
		overlays     []string
		advertised   bool
		dataCodes    [2]int64
		dataDeref    [2]bool
		rootCodes    [2]int64
		rootDeref    [2]bool
	}{
		{
			name:      "none",
			dataCodes: [2]int64{int64(ldapwire.ResultSuccess), int64(ldapwire.ResultUnavailableCriticalExtension)},
			rootCodes: [2]int64{int64(ldapwire.ResultSuccess), int64(ldapwire.ResultUnavailableCriticalExtension)},
		},
		{
			name:       "database",
			overlays:   []string{"deref"},
			advertised: true,
			dataCodes:  [2]int64{int64(ldapwire.ResultSuccess), int64(ldapwire.ResultSuccess)},
			dataDeref:  [2]bool{true, true},
			rootCodes:  [2]int64{int64(ldapwire.ResultSuccess), int64(ldapwire.ResultUnavailableCriticalExtension)},
		},
		{
			name:         "frontend",
			globalConfig: "database frontend\noverlay deref",
			advertised:   true,
			dataCodes:    [2]int64{int64(ldapwire.ResultSuccess), int64(ldapwire.ResultSuccess)},
			dataDeref:    [2]bool{true, true},
			rootCodes:    [2]int64{int64(ldapwire.ResultSuccess), int64(ldapwire.ResultSuccess)},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			uri, stop := startOpenLDAPReferenceServerWithConfig(
				t,
				tools,
				test.overlays,
				test.globalConfig,
				"",
				extraData,
			)
			defer stop()

			advertised := openLDAPReferenceAdvertisesDeref(t, uri)
			if advertised != test.advertised {
				t.Fatalf("supportedControl advertises deref = %v, want %v", advertised, test.advertised)
			}
			for criticalIndex, critical := range []bool{false, true} {
				control := ldapwire.Control{
					OID:      ldapwire.DerefControlOID,
					Critical: critical,
					Value:    request,
					HasValue: true,
				}
				data := runOpenLDAPReferenceSearchAt(
					t,
					uri,
					"ou=people,dc=example,dc=com",
					ldap.ScopeWholeSubtree,
					"(objectClass=inetOrgPerson)",
					[]ldapwire.Control{control},
				)
				root := runOpenLDAPReferenceSearchAt(
					t,
					uri,
					"",
					ldap.ScopeBaseObject,
					"(objectClass=*)",
					[]ldapwire.Control{control},
				)
				dataDeref := openLDAPReferenceHasEntryControl(data, ldapwire.DerefControlOID)
				rootDeref := openLDAPReferenceHasEntryControl(root, ldapwire.DerefControlOID)
				if data.resultCode != test.dataCodes[criticalIndex] ||
					dataDeref != test.dataDeref[criticalIndex] {
					t.Fatalf(
						"data critical=%v: code=%d deref=%v, want code=%d deref=%v",
						critical,
						data.resultCode,
						dataDeref,
						test.dataCodes[criticalIndex],
						test.dataDeref[criticalIndex],
					)
				}
				if root.resultCode != test.rootCodes[criticalIndex] ||
					rootDeref != test.rootDeref[criticalIndex] {
					t.Fatalf(
						"Root DSE critical=%v: code=%d deref=%v, want code=%d deref=%v",
						critical,
						root.resultCode,
						rootDeref,
						test.rootCodes[criticalIndex],
						test.rootDeref[criticalIndex],
					)
				}
			}
		})
	}
}

func openLDAPReferenceAdvertisesDeref(t *testing.T, uri string) bool {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial OpenLDAP root DSE: %v", err)
	}
	defer client.Close()
	result, err := client.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedControl"},
		nil,
	))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("search OpenLDAP root DSE: %#v, %v", result, err)
	}
	return containsString(
		result.Entries[0].GetAttributeValues("supportedControl"),
		ldapwire.DerefControlOID,
	)
}

func runOpenLDAPReferenceSearchAt(
	t *testing.T,
	uri,
	baseDN string,
	scope int,
	filter string,
	controls []ldapwire.Control,
) openLDAPReferenceSearchResult {
	t.Helper()
	connection := dialAndBindRawLDAP(
		t,
		strings.TrimPrefix(uri, "ldap://"),
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	defer connection.Close()
	request := rawSyncSearchRequestFor(
		t,
		baseDN,
		scope,
		ldap.NeverDerefAliases,
		filter,
	)
	rawControls := make([]*ber.Packet, len(controls))
	for index, control := range controls {
		rawControls[index] = encodeRawLDAPControl(control)
	}
	writeOpenLDAPReferenceRequest(t, connection, 2, request, rawControls)

	var result openLDAPReferenceSearchResult
	for {
		packet, err := ber.ReadPacket(connection)
		if err != nil {
			if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
				t.Fatalf("OpenLDAP deref search timed out: %v", err)
			}
			t.Fatalf("read OpenLDAP deref search response: %v", err)
		}
		operation := packet.Children[1]
		switch uint64(operation.Tag) {
		case ldapwire.ApplicationSearchResultEntry:
			result.entries = append(result.entries, openLDAPReferenceEntry{
				dn:       operation.Children[0].Data.String(),
				controls: openLDAPReferenceControls(packet),
			})
		case ldapwire.ApplicationSearchResultDone:
			result.resultCode = rawLDAPResultCode(t, operation)
			result.controls = openLDAPReferenceControls(packet)
			return result
		default:
			t.Fatalf("unexpected OpenLDAP deref response tag %d", operation.Tag)
		}
	}
}

func openLDAPReferenceHasEntryControl(
	result openLDAPReferenceSearchResult,
	oid string,
) bool {
	for _, entry := range result.entries {
		for _, control := range entry.controls {
			if control.oid == oid {
				return true
			}
		}
	}
	return false
}

func TestOpenLDAPReferenceDerefControlValidation(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	uri, stop := startOpenLDAPReferenceServer(t, tools, []string{"deref"})
	defer stop()

	valid := encodeOpenLDAPDerefRequest([]ldapwire.DerefSpec{{
		DerefAttr:  "manager",
		Attributes: []string{"uid"},
	}})
	duplicate := encodeOpenLDAPDerefRequest([]ldapwire.DerefSpec{
		{DerefAttr: "manager", Attributes: []string{"uid"}},
		{DerefAttr: "MANAGER", Attributes: []string{"cn"}},
	})

	tests := []struct {
		name     string
		critical bool
		value    []byte
		hasValue bool
		wantCode int64
	}{
		{name: "valid", critical: true, value: valid, hasValue: true, wantCode: int64(ldapwire.ResultSuccess)},
		{name: "absent-critical", critical: true, wantCode: int64(ldapwire.ResultProtocolError)},
		{name: "absent-noncritical", wantCode: int64(ldapwire.ResultProtocolError)},
		{name: "empty-critical", critical: true, value: []byte{}, hasValue: true, wantCode: int64(ldapwire.ResultProtocolError)},
		{name: "empty-noncritical", value: []byte{}, hasValue: true, wantCode: int64(ldapwire.ResultProtocolError)},
		{name: "malformed-lenient", critical: true, value: []byte{0x30, 0x01, 0xff}, hasValue: true, wantCode: int64(ldapwire.ResultSuccess)},
		{name: "constructed-outer-tag-critical", critical: true, value: []byte{0x31, 0x00}, hasValue: true, wantCode: int64(ldapwire.ResultSuccess)},
		{name: "constructed-outer-tag-noncritical", value: []byte{0x31, 0x00}, hasValue: true, wantCode: int64(ldapwire.ResultSuccess)},
		{name: "duplicate", critical: true, value: duplicate, hasValue: true, wantCode: int64(ldapwire.ResultProtocolError)},
		{name: "unknown-deref-critical", critical: true, value: encodeOpenLDAPDerefRequest([]ldapwire.DerefSpec{{DerefAttr: "doesNotExist", Attributes: []string{"uid"}}}), hasValue: true, wantCode: int64(ldapwire.ResultProtocolError)},
		{name: "unknown-deref-noncritical", value: encodeOpenLDAPDerefRequest([]ldapwire.DerefSpec{{DerefAttr: "doesNotExist", Attributes: []string{"uid"}}}), hasValue: true, wantCode: int64(ldapwire.ResultProtocolError)},
		{name: "non-dn-critical", critical: true, value: encodeOpenLDAPDerefRequest([]ldapwire.DerefSpec{{DerefAttr: "cn", Attributes: []string{"uid"}}}), hasValue: true, wantCode: int64(ldapwire.ResultProtocolError)},
		{name: "non-dn-noncritical", value: encodeOpenLDAPDerefRequest([]ldapwire.DerefSpec{{DerefAttr: "cn", Attributes: []string{"uid"}}}), hasValue: true, wantCode: int64(ldapwire.ResultSuccess)},
		{name: "unknown-result-critical", critical: true, value: encodeOpenLDAPDerefRequest([]ldapwire.DerefSpec{{DerefAttr: "manager", Attributes: []string{"doesNotExist"}}}), hasValue: true, wantCode: int64(ldapwire.ResultProtocolError)},
		{name: "unknown-result-noncritical", value: encodeOpenLDAPDerefRequest([]ldapwire.DerefSpec{{DerefAttr: "manager", Attributes: []string{"doesNotExist"}}}), hasValue: true, wantCode: int64(ldapwire.ResultProtocolError)},
		{name: "empty-sequence-critical", critical: true, value: []byte{0x30, 0x00}, hasValue: true, wantCode: int64(ldapwire.ResultSuccess)},
		{name: "empty-sequence-noncritical", value: []byte{0x30, 0x00}, hasValue: true, wantCode: int64(ldapwire.ResultSuccess)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := runOpenLDAPReferenceSearch(t, uri, []ldapwire.Control{{
				OID:      ldapwire.DerefControlOID,
				Critical: test.critical,
				Value:    test.value,
				HasValue: test.hasValue,
			}}, false)
			if result.resultCode != test.wantCode {
				t.Fatalf("result code = %d, want %d; entries=%d", result.resultCode, test.wantCode, len(result.entries))
			}
		})
	}

	result := runOpenLDAPReferenceSearch(t, uri, []ldapwire.Control{
		{OID: ldapwire.DerefControlOID, Value: valid, HasValue: true},
		{OID: ldapwire.DerefControlOID, Value: valid, HasValue: true},
	}, false)
	if result.resultCode != int64(ldapwire.ResultProtocolError) {
		t.Fatalf("duplicate control result code = %d, want %d", result.resultCode, ldapwire.ResultProtocolError)
	}
}

func TestOpenLDAPReferenceDerefResponseSemantics(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	otherDirectory := t.TempDir()
	databaseConfig := derefResponseOpenLDAPDatabaseConfig(otherDirectory)
	uri, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		databaseConfig,
		derefResponseOpenLDAPData,
	)
	defer stopOpenLDAP()
	seedOpenLDAPDerefResponseOtherDatabase(t, uri)

	store := storage.NewMemory()
	defer store.Close()
	seedOnlineConfiguration(t, store)
	seedDerefTestSecondaryDatabase(t, store)
	seedLocalDerefResponseSemantics(t, store)
	localAddress, stopLocal := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	})
	defer stopLocal()

	openLDAP := observeDerefResponseSemantics(
		t,
		strings.TrimPrefix(uri, "ldap://"),
	)
	local := observeDerefResponseSemantics(t, localAddress)
	assertDerefResponseSemantics(
		t,
		"OpenLDAP 2.6.13",
		openLDAP,
		expectedDerefResponseSemantics(true),
	)
	assertDerefResponseSemantics(
		t,
		"ldap-go",
		local,
		expectedDerefResponseSemantics(false),
	)
}

const (
	derefResponseSourceDN         = "cn=deref-source,ou=people,dc=example,dc=com"
	derefResponseSourceValueACLDN = "cn=deref-source-value-acl," +
		"ou=people,dc=example,dc=com"
	derefResponseSourceDeniedDN = "cn=deref-source-denied," +
		"ou=people,dc=example,dc=com"
	derefResponseReadableDN = "uid=deref-readable,ou=people," +
		"dc=example,dc=com"
	derefResponseEntryHiddenDN = "uid=deref-entry-hidden,ou=people," +
		"dc=example,dc=com"
	derefResponseValueHiddenDN = "uid=deref-value-hidden,ou=people," +
		"dc=example,dc=com"
	derefResponseMissingDN = "uid=deref-missing,ou=people," +
		"dc=example,dc=com"
	derefResponseOtherDN = "uid=deref-other,dc=other,dc=com"
)

var derefResponseOpenLDAPData = `

dn: uid=deref-readable,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: deref-readable
cn: Readable Target
cn;lang-en: Readable English
sn: Target
jpegPhoto:: AP8Q
jpegPhoto:
description: visible
description: secret

dn: uid=deref-entry-hidden,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: deref-entry-hidden
cn: Entry Hidden
sn: Target

dn: uid=deref-value-hidden,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: deref-value-hidden
cn: Value Hidden
sn: Target

dn: cn=deref-source,ou=people,dc=example,dc=com
objectClass: top
objectClass: groupOfNames
cn: deref-source
member: uid=deref-readable,ou=people,dc=example,dc=com
member: uid=deref-entry-hidden,ou=people,dc=example,dc=com
member: uid=deref-missing,ou=people,dc=example,dc=com
member: uid=deref-other,dc=other,dc=com
seeAlso;lang-en: uid=deref-readable,ou=people,dc=example,dc=com

dn: cn=deref-source-value-acl,ou=people,dc=example,dc=com
objectClass: top
objectClass: groupOfNames
cn: deref-source-value-acl
member: uid=deref-readable,ou=people,dc=example,dc=com
member: uid=deref-value-hidden,ou=people,dc=example,dc=com

dn: cn=deref-source-denied,ou=people,dc=example,dc=com
objectClass: top
objectClass: groupOfNames
cn: deref-source-denied
member: uid=deref-readable,ou=people,dc=example,dc=com
`

func derefResponseAccessRules() []string {
	return []string{
		"to dn.exact=\"" + derefResponseSourceValueACLDN + "\" attrs=member " +
			"val.exact=\"" + derefResponseValueHiddenDN + "\" by anonymous none by * read",
		"to dn.exact=\"" + derefResponseSourceValueACLDN + "\" attrs=member " +
			"by anonymous read by * read",
		"to dn.exact=\"" + derefResponseSourceDeniedDN + "\" attrs=member " +
			"by anonymous none by * read",
		"to dn.exact=\"" + derefResponseSourceDN + "\" attrs=member,seeAlso " +
			"by anonymous read by * read",
		"to attrs=member,seeAlso by anonymous none by * read",
		"to dn.exact=\"" + derefResponseEntryHiddenDN + "\" attrs=entry " +
			"by anonymous none by * read",
		"to dn.exact=\"" + derefResponseReadableDN + "\" attrs=description " +
			"val.exact=\"secret\" by anonymous none by * read",
		"to dn.exact=\"" + derefResponseReadableDN + "\" attrs=uid " +
			"by anonymous none by * read",
		"to * by * read",
	}
}

func derefResponseOpenLDAPDatabaseConfig(otherDirectory string) string {
	var config strings.Builder
	for _, rule := range derefResponseAccessRules() {
		fmt.Fprintf(&config, "access %s\n", rule)
	}
	fmt.Fprintf(
		&config,
		`overlay deref

database mdb
maxsize 1073741824
suffix "dc=other,dc=com"
rootdn "cn=admin,dc=other,dc=com"
rootpw other-secret
directory %s
access to * by * read
`,
		otherDirectory,
	)
	return config.String()
}

func seedOpenLDAPDerefResponseOtherDatabase(t *testing.T, uri string) {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("dial OpenLDAP secondary database: %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,dc=other,dc=com", "other-secret"); err != nil {
		t.Fatalf("bind OpenLDAP secondary database root: %v", err)
	}
	suffix := ldap.NewAddRequest("dc=other,dc=com", nil)
	suffix.Attribute("objectClass", []string{"top", "domain"})
	suffix.Attribute("dc", []string{"other"})
	if err := client.Add(suffix); err != nil {
		t.Fatalf("add OpenLDAP secondary suffix: %v", err)
	}
	target := ldap.NewAddRequest(derefResponseOtherDN, nil)
	target.Attribute("objectClass", []string{
		"top", "person", "organizationalPerson", "inetOrgPerson",
	})
	target.Attribute("uid", []string{"deref-other"})
	target.Attribute("cn", []string{"Other Backend Target"})
	target.Attribute("sn", []string{"Target"})
	if err := client.Add(target); err != nil {
		t.Fatalf("add OpenLDAP secondary target: %v", err)
	}
}

func seedLocalDerefResponseSemantics(t *testing.T, store storage.Store) {
	t.Helper()
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		configDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		config, err := writer.Get(configDN)
		if err != nil {
			return err
		}
		access := make([][]byte, len(derefResponseAccessRules()))
		for index, rule := range derefResponseAccessRules() {
			access[index] = []byte(fmt.Sprintf("{%d}%s", index, rule))
		}
		config.ReplaceValues("olcAccess", access)
		if err := writer.Put(config, true); err != nil {
			return err
		}

		entries := []directory.Entry{
			derefTestOverlayEntry(
				"olcOverlay={0}deref,olcDatabase={1}mdb,cn=config",
				"{0}deref",
			),
			{
				DN: derefResponseReadableDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("inetOrgPerson")},
					{Description: "uid", Values: stringValues("deref-readable")},
					{Description: "cn", Values: stringValues("Readable Target")},
					{Description: "cn;lang-en", Values: stringValues("Readable English")},
					{Description: "sn", Values: stringValues("Target")},
					{Description: "jpegPhoto", Values: [][]byte{{0x00, 0xff, 0x10}, {}}},
					{Description: "description", Values: stringValues("visible", "secret")},
				},
			},
			derefTestPersonEntry(derefResponseEntryHiddenDN, "deref-entry-hidden"),
			derefTestPersonEntry(derefResponseValueHiddenDN, "deref-value-hidden"),
			{
				DN: derefResponseSourceDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("groupOfNames")},
					{Description: "cn", Values: stringValues("deref-source")},
					{Description: "member", Values: stringValues(
						derefResponseReadableDN,
						derefResponseEntryHiddenDN,
						derefResponseMissingDN,
						derefResponseOtherDN,
					)},
					{Description: "seeAlso;lang-en", Values: stringValues(derefResponseReadableDN)},
				},
			},
			{
				DN: derefResponseSourceValueACLDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("groupOfNames")},
					{Description: "cn", Values: stringValues("deref-source-value-acl")},
					{Description: "member", Values: stringValues(
						derefResponseReadableDN,
						derefResponseValueHiddenDN,
					)},
				},
			},
			{
				DN: derefResponseSourceDeniedDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("groupOfNames")},
					{Description: "cn", Values: stringValues("deref-source-denied")},
					{Description: "member", Values: stringValues(derefResponseReadableDN)},
				},
			},
			derefTestPersonEntry(derefResponseOtherDN, "deref-other"),
		}
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed local deref response fixture: %v", err)
	}
}

type derefResponseSemantics struct {
	directDescription []string
	main              []ldapwire.DerefResult
	sourceValue       []ldapwire.DerefResult
	sourceDenied      bool
}

func observeDerefResponseSemantics(
	t *testing.T,
	address string,
) derefResponseSemantics {
	t.Helper()
	directDescription := observeDirectDerefTargetDescription(t, address)
	control := ldapwire.Control{
		OID:      ldapwire.DerefControlOID,
		Critical: true,
		Value: encodeDerefTestRequest([]ldapwire.DerefSpec{
			{
				DerefAttr:  "member",
				Attributes: []string{"jpegPhoto", "description", "uid"},
			},
			{
				DerefAttr:  "seeAlso;lang-en",
				Attributes: []string{"cn;lang-en"},
			},
		}),
		HasValue: true,
	}
	search := func(baseDN string) derefTestSearchResult {
		t.Helper()
		result := runDerefTestSearch(
			t,
			address,
			"",
			"",
			baseDN,
			ldap.ScopeBaseObject,
			"(objectClass=*)",
			[]string{"cn"},
			control,
		)
		if result.code != ldapwire.ResultSuccess || len(result.entries) != 1 {
			t.Fatalf("deref semantic search %q = %#v", baseDN, result)
		}
		return result
	}

	main := search(derefResponseSourceDN)
	mainValue, ok := main.entries[0].controls[ldapwire.DerefControlOID]
	if !ok {
		t.Fatal("main deref semantic search has no entry control")
	}
	sourceValue := search(derefResponseSourceValueACLDN)
	sourceValueControl, ok := sourceValue.entries[0].controls[ldapwire.DerefControlOID]
	if !ok {
		t.Fatal("source-value ACL search has no entry control")
	}
	sourceDenied := search(derefResponseSourceDeniedDN)
	_, sourceDeniedControl := sourceDenied.entries[0].controls[ldapwire.DerefControlOID]
	return derefResponseSemantics{
		directDescription: directDescription,
		main:              decodeDerefTestResponse(t, mainValue),
		sourceValue:       decodeDerefTestResponse(t, sourceValueControl),
		sourceDenied:      sourceDeniedControl,
	}
}

func observeDirectDerefTargetDescription(t *testing.T, address string) []string {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("dial direct deref target: %v", err)
	}
	defer client.Close()
	result, err := client.Search(ldap.NewSearchRequest(
		derefResponseReadableDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"description"},
		nil,
	))
	if err != nil {
		t.Fatalf("direct deref target search: %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("direct deref target search entries = %d, want 1", len(result.Entries))
	}
	values := result.Entries[0].GetAttributeValues("description")
	if !reflect.DeepEqual(values, []string{"visible"}) {
		t.Fatalf("direct deref target description = %q, want [visible]", values)
	}
	return values
}

func expectedDerefResponseSemantics(openLDAPTargetValueLeak bool) derefResponseSemantics {
	descriptionValues := [][]byte{[]byte("visible")}
	if openLDAPTargetValueLeak {
		descriptionValues = append(descriptionValues, []byte("secret"))
	}
	readableAttributes := []ldapwire.DerefAttribute{
		{
			Type: "jpegPhoto",
			Values: [][]byte{
				{0x00, 0xff, 0x10},
				nil,
			},
		},
		{Type: "description", Values: descriptionValues},
	}
	return derefResponseSemantics{
		directDescription: []string{"visible"},
		main: []ldapwire.DerefResult{
			{
				DerefAttr:  "member",
				DerefValue: derefResponseReadableDN,
				Attributes: readableAttributes,
			},
			{DerefAttr: "member", DerefValue: derefResponseEntryHiddenDN},
			{DerefAttr: "member", DerefValue: derefResponseMissingDN},
			{DerefAttr: "member", DerefValue: derefResponseOtherDN},
			{
				DerefAttr:  "seeAlso;lang-en",
				DerefValue: derefResponseReadableDN,
				Attributes: []ldapwire.DerefAttribute{{
					Type:   "cn;lang-en",
					Values: [][]byte{[]byte("Readable English")},
				}},
			},
		},
		sourceValue: []ldapwire.DerefResult{{
			DerefAttr:  "member",
			DerefValue: derefResponseReadableDN,
			Attributes: readableAttributes,
		}},
	}
}

func assertDerefResponseSemantics(
	t *testing.T,
	name string,
	got,
	want derefResponseSemantics,
) {
	t.Helper()
	if got.sourceDenied {
		t.Fatalf("%s source-attribute ACL leaked a deref response control", name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s deref response semantics = %#v, want %#v", name, got, want)
	}
}

func encodeOpenLDAPDerefRequest(specs []ldapwire.DerefSpec) []byte {
	request := ber.NewSequence("derefRequestValue")
	for _, spec := range specs {
		encodedSpec := ber.NewSequence("derefSpec")
		encodedSpec.AppendChild(rawOctetString([]byte(spec.DerefAttr)))
		attributes := ber.NewSequence("attributes")
		for _, attribute := range spec.Attributes {
			attributes.AppendChild(rawOctetString([]byte(attribute)))
		}
		encodedSpec.AppendChild(attributes)
		request.AppendChild(encodedSpec)
	}
	return request.Bytes()
}
