package server

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	compareCoreUpperDN = "exactName=Alice+foldName=Engineering,dc=example,dc=com"
	compareCoreLowerDN = "exactName=alice+foldName=engineering,dc=example,dc=com"
	compareCoreGroupDN = "cn=compare-group,dc=example,dc=com"
	compareCoreAliasDN = "cn=compare-alias,dc=example,dc=com"
	compareCoreRefDN   = "cn=compare-referral,dc=example,dc=com"
)

func TestDNIdentityCompareCore(t *testing.T) {
	for _, backend := range []struct {
		name string
		open func(*testing.T) storage.Store
	}{
		{name: "memory", open: func(*testing.T) storage.Store { return storage.NewMemory() }},
		{name: "bolt", open: func(t *testing.T) storage.Store {
			store, err := storage.OpenBolt(filepath.Join(t.TempDir(), "ldap.db"))
			if err != nil {
				t.Fatalf("OpenBolt(): %v", err)
			}
			return store
		}},
	} {
		backend := backend
		t.Run(backend.name, func(t *testing.T) {
			testDNIdentityCompareCore(t, backend.open)
		})
	}
}

func testDNIdentityCompareCore(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) {
	address := startDNIdentityCompareCoreServer(t, openStore)
	root := bindDNIdentityCompareClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	seedDNIdentityCompareEntries(t, root)

	equivalentUpper := "foldAlias=ENGINEERING+" + dnMultiAVAExactOID +
		"=Alice,DC=EXAMPLE,DC=COM"
	equivalentMember := dnMultiAVAFoldOID + "=engineering+exactAlias=Alice," +
		"DC=EXAMPLE,DC=COM"
	differentExactMember := dnMultiAVAFoldOID + "=engineering+exactAlias=alice," +
		"dc=example,dc=com"

	t.Run("target identity", func(t *testing.T) {
		assertDNIdentityCompare(t, root, equivalentUpper, "cn", "EXACT UPPER", true)
		assertDNIdentityCompare(t, root, equivalentUpper, dnMultiAVAExactOID, "Alice", true)
		assertDNIdentityCompare(t, root, compareCoreUpperDN, "foldAlias", "ENGINEERING", true)
		assertDNIdentityCompare(t, root, compareCoreLowerDN, "cn", "Exact Lower", true)
		assertDNIdentityCompare(t, root, compareCoreLowerDN, "cn", "Exact Upper", false)
		assertDNIdentityCompareCode(
			t,
			root,
			"exactName=ALICE+foldName=engineering,dc=example,dc=com",
			"cn",
			"Exact Upper",
			ldap.LDAPResultNoSuchObject,
		)
	})

	t.Run("DN assertions", func(t *testing.T) {
		assertDNIdentityCompare(t, root, compareCoreGroupDN, "member", equivalentMember, true)
		assertDNIdentityCompare(
			t,
			root,
			compareCoreGroupDN,
			"member",
			differentExactMember,
			false,
		)
		assertDNIdentityCompare(
			t,
			root,
			compareCoreGroupDN,
			"uniqueMember",
			equivalentMember+"#'0101'B",
			true,
		)
		assertDNIdentityCompare(
			t,
			root,
			compareCoreGroupDN,
			"uniqueMember",
			equivalentMember,
			false,
		)
		assertDNIdentityCompare(
			t,
			root,
			compareCoreGroupDN,
			"uniqueMember",
			differentExactMember+"#'0101'B",
			false,
		)
	})

	t.Run("root and self ACL", func(t *testing.T) {
		assertDNIdentityCompare(t, root, compareCoreLowerDN, "description", "lower-only", true)
		self := bindDNIdentityCompareClient(t, address, equivalentUpper, "upper-secret")
		assertDNIdentityCompare(t, self, equivalentUpper, "description", "upper-only", true)
		assertDNIdentityCompareCode(
			t,
			self,
			compareCoreLowerDN,
			"description",
			"lower-only",
			ldap.LDAPResultInsufficientAccessRights,
		)
	})

	t.Run("assertion control", func(t *testing.T) {
		matching := dnIdentityCompareAssertionControl(
			t,
			"(member="+equivalentMember+")",
		)
		if code := rawDNIdentityCompare(
			t,
			address,
			compareCoreGroupDN,
			"cn",
			"compare-group",
			matching,
		); code != int64(ldap.LDAPResultCompareTrue) {
			t.Fatalf("schema-aware assertion Compare result = %d", code)
		}
		mismatch := dnIdentityCompareAssertionControl(
			t,
			"(member="+differentExactMember+")",
		)
		if code := rawDNIdentityCompare(
			t,
			address,
			compareCoreGroupDN,
			"cn",
			"compare-group",
			mismatch,
		); code != int64(ldap.LDAPResultAssertionFailed) {
			t.Fatalf("caseExact assertion Compare result = %d", code)
		}
	})

	t.Run("alias and referral ordering", func(t *testing.T) {
		assertDNIdentityCompare(
			t,
			root,
			compareCoreAliasDN,
			"aliasedObjectName",
			equivalentMember,
			true,
		)
		assertDNIdentityCompareCode(
			t,
			root,
			compareCoreAliasDN,
			"exactName",
			"Alice",
			ldap.LDAPResultNoSuchAttribute,
		)
		assertDNIdentityCompareCode(
			t,
			root,
			compareCoreRefDN,
			"cn",
			"compare-referral",
			ldap.LDAPResultReferral,
		)
		if code := rawDNIdentityCompare(
			t,
			address,
			compareCoreRefDN,
			"cn",
			"compare-referral",
			rawManageDsaITControl(),
		); code != int64(ldap.LDAPResultCompareTrue) {
			t.Fatalf("managed referral Compare result = %d", code)
		}
	})

	t.Run("result codes", func(t *testing.T) {
		assertDNIdentityCompareCode(
			t,
			root,
			"exactAlias=Alice+"+dnMultiAVAExactOID+"=Other+foldName=Engineering,"+
				"dc=example,dc=com",
			"cn",
			"Exact Upper",
			ldap.LDAPResultInvalidDNSyntax,
		)
		assertDNIdentityCompareCode(
			t,
			root,
			compareCoreUpperDN,
			"mail",
			"missing@example.com",
			ldap.LDAPResultNoSuchAttribute,
		)
		assertDNIdentityCompareCode(
			t,
			root,
			compareCoreUpperDN,
			"member",
			"not a DN",
			ldap.LDAPResultInvalidAttributeSyntax,
		)
		assertDNIdentityCompareCode(
			t,
			root,
			compareCoreUpperDN,
			"undefinedCompareAttribute",
			"value",
			ldap.LDAPResultUndefinedAttributeType,
		)
		unsupportedRead := rawDNIdentityCompareControl(preReadControlOID, true, nil)
		if code := rawDNIdentityCompare(
			t,
			address,
			equivalentUpper,
			"cn",
			"Exact Upper",
			unsupportedRead,
		); code != int64(ldap.LDAPResultUnavailableCriticalExtension) {
			t.Fatalf("critical read control Compare result = %d", code)
		}
	})
}

func startDNIdentityCompareCoreServer(
	t *testing.T,
	openStore func(*testing.T) storage.Store,
) string {
	t.Helper()
	store := openStore(t)
	t.Cleanup(func() { _ = store.Close() })
	config := strings.Replace(
		dnMultiAVAConfigLDIF,
		"olcRootPW: secret\n",
		"olcRootPW: admin-secret\n"+
			"olcAccess: {0}to attrs=userPassword by anonymous auth by self auth by * none\n"+
			"olcAccess: {1}to * by self compare by * none\n",
		1,
	)
	content := strings.Replace(
		dnMultiAVAContentLDIF,
		"objectClass: dnMultiAVAEntry\ncn: Exact Upper\n",
		"objectClass: dnMultiAVAEntry\nobjectClass: extensibleObject\n"+
			"cn: Exact Upper\ndescription: upper-only\nuserPassword: upper-secret\n",
		1,
	)
	content = strings.Replace(
		content,
		"objectClass: dnMultiAVAEntry\ncn: Exact Lower\n",
		"objectClass: dnMultiAVAEntry\nobjectClass: extensibleObject\n"+
			"cn: Exact Lower\ndescription: lower-only\nuserPassword: lower-secret\n",
		1,
	)
	for _, item := range []struct {
		database string
		ldif     string
		skip     bool
	}{
		{database: "0", ldif: config, skip: true},
		{database: "1", ldif: content},
	} {
		if _, err := migration.ImportLDIF(
			context.Background(),
			store,
			strings.NewReader(item.ldif),
			migration.ImportOptions{
				Database:             item.database,
				Replace:              true,
				SkipSchemaValidation: item.skip,
			},
		); err != nil {
			t.Fatalf("ImportLDIF(database=%s): %v", item.database, err)
		}
	}
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	return address
}

func seedDNIdentityCompareEntries(t *testing.T, client *ldap.Conn) {
	t.Helper()
	group := ldap.NewAddRequest(compareCoreGroupDN, nil)
	group.Attribute("objectClass", []string{"top", "groupOfNames", "extensibleObject"})
	group.Attribute("cn", []string{"compare-group"})
	group.Attribute("member", []string{compareCoreUpperDN})
	group.Attribute("uniqueMember", []string{compareCoreUpperDN + "#'0101'B"})
	if err := client.Add(group); err != nil {
		t.Fatalf("Add(compare group): %v", err)
	}

	alias := ldap.NewAddRequest(compareCoreAliasDN, nil)
	alias.Attribute("objectClass", []string{"top", "alias", "extensibleObject"})
	alias.Attribute("cn", []string{"compare-alias"})
	alias.Attribute("aliasedObjectName", []string{compareCoreUpperDN})
	if err := client.Add(alias); err != nil {
		t.Fatalf("Add(compare alias): %v", err)
	}

	referral := ldap.NewAddRequest(compareCoreRefDN, nil)
	referral.Attribute(
		"objectClass",
		[]string{"top", "referral", "extensibleObject"},
	)
	referral.Attribute("cn", []string{"compare-referral"})
	referral.Attribute("ref", []string{"ldap://remote.example/dc=remote,dc=example"})
	if err := client.Add(referral); err != nil {
		t.Fatalf("Add(compare referral): %v", err)
	}
}

func bindDNIdentityCompareClient(
	t *testing.T,
	address string,
	dn string,
	password string,
) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Bind(dn, password); err != nil {
		t.Fatalf("Bind(%q): %v", dn, err)
	}
	return client
}

func assertDNIdentityCompare(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	attribute string,
	assertion string,
	want bool,
) {
	t.Helper()
	matched, err := client.Compare(dn, attribute, assertion)
	if err != nil || matched != want {
		t.Fatalf(
			"Compare(%q, %q, %q) = %t, %v; want %t",
			dn,
			attribute,
			assertion,
			matched,
			err,
			want,
		)
	}
}

func assertDNIdentityCompareCode(
	t *testing.T,
	client *ldap.Conn,
	dn string,
	attribute string,
	assertion string,
	want uint16,
) {
	t.Helper()
	_, err := client.Compare(dn, attribute, assertion)
	var ldapErr *ldap.Error
	if !errors.As(err, &ldapErr) || ldapErr.ResultCode != want {
		t.Fatalf(
			"Compare(%q, %q, %q) error = %v; want result %d",
			dn,
			attribute,
			assertion,
			err,
			want,
		)
	}
}

func rawDNIdentityCompare(
	t *testing.T,
	address string,
	dn string,
	attribute string,
	assertion string,
	controls ...*ber.Packet,
) int64 {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	defer connection.Close()

	bind := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationBindRequest,
		nil,
		"BindRequest",
	)
	bind.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		3,
		"version",
	))
	bind.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		"cn=admin,dc=example,dc=com",
		"name",
	))
	bind.AppendChild(ber.NewString(
		ber.ClassContext,
		ber.TypePrimitive,
		0,
		"admin-secret",
		"simple",
	))
	writeRawLDAPRequest(t, connection, 1, bind, nil)
	if code := readRawLDAPResultCode(t, connection); code != 0 {
		t.Fatalf("raw Bind result = %d", code)
	}

	compare := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationCompareRequest,
		nil,
		"CompareRequest",
	)
	compare.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		dn,
		"entry",
	))
	ava := ber.NewSequence("AttributeValueAssertion")
	ava.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		attribute,
		"attribute",
	))
	ava.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		assertion,
		"assertion",
	))
	compare.AppendChild(ava)
	writeRawLDAPRequest(t, connection, 2, compare, controls...)
	return readRawLDAPResultCode(t, connection)
}

func dnIdentityCompareAssertionControl(t *testing.T, filter string) *ber.Packet {
	t.Helper()
	compiled, err := ldap.CompileFilter(filter)
	if err != nil {
		t.Fatalf("CompileFilter(%q): %v", filter, err)
	}
	value := compiled.Bytes()
	return rawDNIdentityCompareControl(assertionControlOID, true, value)
}

func rawDNIdentityCompareControl(
	oid string,
	critical bool,
	value []byte,
) *ber.Packet {
	control := ber.NewSequence("Control")
	control.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		oid,
		"controlType",
	))
	if critical {
		control.AppendChild(ber.NewBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"criticality",
		))
	}
	if value != nil {
		control.AppendChild(ber.NewString(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagOctetString,
			string(value),
			"controlValue",
		))
	}
	return control
}
