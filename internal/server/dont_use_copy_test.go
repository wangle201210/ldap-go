package server

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestParseDontUseCopyControl(t *testing.T) {
	t.Parallel()

	for _, critical := range []bool{false, true} {
		parsed, failure := parseRequestControls(
			[]ldapwire.Control{{
				OID:      dontUseCopyControlOID,
				Critical: critical,
			}},
			supportsDontUseCopy,
		)
		if failure != nil || !parsed.dontUseCopy {
			t.Fatalf(
				"critical %t parse = %#v, %#v",
				critical,
				parsed,
				failure,
			)
		}
	}

	_, failure := parseRequestControls(
		[]ldapwire.Control{
			{OID: dontUseCopyControlOID},
			{OID: dontUseCopyControlOID},
		},
		supportsDontUseCopy,
	)
	if failure == nil || failure.Code != ldapwire.ResultProtocolError {
		t.Fatalf("duplicate dontUseCopy result = %#v", failure)
	}

	_, failure = parseRequestControls(
		[]ldapwire.Control{{
			OID:      dontUseCopyControlOID,
			HasValue: true,
		}},
		supportsDontUseCopy,
	)
	if failure == nil || failure.Code != ldapwire.ResultProtocolError {
		t.Fatalf("valued dontUseCopy result = %#v", failure)
	}

	_, failure = parseRequestControls(
		[]ldapwire.Control{{
			OID:      dontUseCopyControlOID,
			Critical: true,
		}},
		0,
	)
	if failure == nil ||
		failure.Code != ldapwire.ResultUnavailableCriticalExtension {
		t.Fatalf("inappropriate dontUseCopy result = %#v", failure)
	}
}

func TestLDAPDontUseCopyDiscoveryAndAuthoritativeSearch(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	rootDSE, err := client.Search(ldap.NewSearchRequest(
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
	if err != nil {
		t.Fatalf("Root DSE Search(): %v", err)
	}
	if !containsString(
		rootDSE.Entries[0].GetAttributeValues("supportedControl"),
		dontUseCopyControlOID,
	) {
		t.Fatal("Root DSE does not advertise Don't Use Copy")
	}

	for _, critical := range []bool{false, true} {
		result, err := client.Search(ldap.NewSearchRequest(
			"uid=alice,ou=people,dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"uid"},
			[]ldap.Control{&ldap.ControlString{
				ControlType: dontUseCopyControlOID,
				Criticality: critical,
			}},
		))
		if err != nil {
			t.Fatalf("authoritative Search critical %t: %v", critical, err)
		}
		if len(result.Entries) != 1 ||
			result.Entries[0].GetAttributeValue("uid") != "alice" {
			t.Fatalf(
				"authoritative Search critical %t entries = %#v",
				critical,
				result.Entries,
			)
		}
	}
}

func TestLDAPDontUseCopyShadowBehavior(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDontUseCopyShadow(t, store, true)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	got := collectDontUseCopyObservations(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	want := []dontUseCopyObservation{
		{
			applicationTag: ldapwire.ApplicationSearchResultDone,
			code:           int64(ldapwire.ResultReferral),
			referrals: []string{
				"ldap://provider.example/ou=people,dc=example,dc=com??sub",
			},
		},
		{
			applicationTag: ldapwire.ApplicationSearchResultDone,
			code:           int64(ldapwire.ResultReferral),
			referrals: []string{
				"ldap://provider.example/uid=alice,ou=people,dc=example,dc=com??base",
			},
		},
		{
			applicationTag: ldapwire.ApplicationSearchResultDone,
			code:           int64(ldapwire.ResultReferral),
			referrals: []string{
				"ldap://provider.example/uid=broken-alias,ou=people,dc=example,dc=com??base",
			},
		},
		{
			applicationTag: ldapwire.ApplicationSearchResultDone,
			code:           int64(ldapwire.ResultReferral),
			referrals: []string{
				"ldap://provider.example/ou=remote,dc=example,dc=com??base",
			},
		},
		{
			applicationTag: ldapwire.ApplicationSearchResultDone,
			code:           int64(ldapwire.ResultProtocolError),
			diagnostic:     "dontUseCopy control value not absent",
		},
		{
			applicationTag: ldapwire.ApplicationCompareResponse,
			code:           int64(ldapwire.ResultUnwillingToPerform),
			diagnostic:     "copy not used",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Don't Use Copy observations = %#v, want %#v", got, want)
	}
}

func TestLDAPDontUseCopyShadowWithoutReferral(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDontUseCopyShadow(t, store, false)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	connection := dialAndBindRawLDAP(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer connection.Close()
	response := sendRawLDAPOperation(
		t,
		connection,
		2,
		rawSyncSearchRequestFor(
			t,
			"ou=people,dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			"(objectClass=*)",
		),
		rawDontUseCopyControl(true, false),
	)
	observation := observeDontUseCopyResult(t, response)
	if observation.code != int64(ldapwire.ResultUnwillingToPerform) ||
		observation.diagnostic !=
			"copy not used; no referral information available" ||
		len(observation.referrals) != 0 {
		t.Fatalf("Don't Use Copy no-referral result = %#v", observation)
	}
}

func TestOpenLDAPLDAPSearchDontUseCopyInteroperability(t *testing.T) {
	if os.Getenv(openLDAPReferenceTestsEnv) == "" {
		t.Skipf(
			"set %s=1 to run the OpenLDAP ldapsearch interoperability test",
			openLDAPReferenceTestsEnv,
		)
	}
	ldapsearch, err := exec.LookPath("ldapsearch")
	if err != nil {
		t.Skip("OpenLDAP ldapsearch is not installed")
	}

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDontUseCopyShadow(t, store, true)
	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	command := exec.Command(
		ldapsearch,
		"-LLL",
		"-x",
		"-H",
		"ldap://"+address,
		"-D",
		"cn=admin,dc=example,dc=com",
		"-w",
		"admin-secret",
		"-E",
		"!dontUseCopy",
		"-b",
		"ou=people,dc=example,dc=com",
		"-s",
		"sub",
		"(objectClass=*)",
		"dn",
	)
	output, err := command.CombinedOutput()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) ||
		exitError.ExitCode() != int(ldapwire.ResultReferral) {
		t.Fatalf("ldapsearch error = %v\n%s", err, output)
	}
	if !strings.Contains(
		string(output),
		"ldap://provider.example/ou=people,dc=example,dc=com??sub",
	) {
		t.Fatalf("ldapsearch output has no rewritten referral:\n%s", output)
	}
}

func TestOpenLDAPReferenceDontUseCopy(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)

	ldapGoStore := storage.NewMemory()
	t.Cleanup(func() { _ = ldapGoStore.Close() })
	seedDontUseCopyShadow(t, ldapGoStore, true)
	ldapGoAddress, stopLDAPGo := startServer(t, ldapGoStore, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stopLDAPGo()
	want := collectDontUseCopyObservations(
		t,
		ldapGoAddress,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)

	uri, stopOpenLDAP := startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		`updatedn "cn=replicator,dc=example,dc=com"
updateref ldap://provider.example`,
		`
dn: uid=broken-alias,ou=people,dc=example,dc=com
objectClass: top
objectClass: alias
objectClass: extensibleObject
uid: broken-alias
aliasedObjectName: uid=missing,ou=people,dc=example,dc=com

dn: ou=remote,dc=example,dc=com
objectClass: top
objectClass: referral
objectClass: extensibleObject
ou: remote
ref: ldap://named.example/dc=remote
`,
	)
	defer stopOpenLDAP()
	got := collectDontUseCopyObservations(
		t,
		strings.TrimPrefix(uri, "ldap://"),
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"OpenLDAP observations = %#v, want ldap-go %#v",
			got,
			want,
		)
	}
}

type dontUseCopyObservation struct {
	applicationTag uint64
	code           int64
	diagnostic     string
	referrals      []string
}

func collectDontUseCopyObservations(
	t *testing.T,
	address, bindDN, password string,
) []dontUseCopyObservation {
	t.Helper()
	connection := dialAndBindRawLDAP(t, address, bindDN, password)
	defer connection.Close()

	responses := []*ber.Packet{
		sendRawLDAPOperation(
			t,
			connection,
			2,
			rawSyncSearchRequestFor(
				t,
				"ou=people,dc=example,dc=com",
				ldap.ScopeWholeSubtree,
				ldap.NeverDerefAliases,
				"(objectClass=*)",
			),
			rawDontUseCopyControl(true, false),
		),
		sendRawLDAPOperation(
			t,
			connection,
			3,
			rawSyncSearchRequestFor(
				t,
				"uid=alice,ou=people,dc=example,dc=com",
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				"(objectClass=*)",
			),
			rawDontUseCopyControl(false, false),
		),
		sendRawLDAPOperation(
			t,
			connection,
			4,
			rawSyncSearchRequestFor(
				t,
				"uid=broken-alias,ou=people,dc=example,dc=com",
				ldap.ScopeBaseObject,
				ldap.DerefAlways,
				"(objectClass=*)",
			),
			rawDontUseCopyControl(true, false),
		),
		sendRawLDAPOperation(
			t,
			connection,
			5,
			rawSyncSearchRequestFor(
				t,
				"ou=remote,dc=example,dc=com",
				ldap.ScopeBaseObject,
				ldap.NeverDerefAliases,
				"(objectClass=*)",
			),
			rawDontUseCopyControl(true, false),
		),
		sendRawLDAPOperation(
			t,
			connection,
			6,
			rawSyncSearchRequestFor(
				t,
				"ou=people,dc=example,dc=com",
				ldap.ScopeWholeSubtree,
				ldap.NeverDerefAliases,
				"(objectClass=*)",
			),
			rawDontUseCopyControl(true, true),
		),
		sendRawLDAPOperation(
			t,
			connection,
			7,
			rawDontUseCopyCompareRequest(
				"uid=alice,ou=people,dc=example,dc=com",
				"uid",
				"alice",
			),
			rawDontUseCopyControl(true, false),
		),
	}
	observations := make([]dontUseCopyObservation, len(responses))
	for index, response := range responses {
		observations[index] = observeDontUseCopyResult(t, response)
	}
	return observations
}

func observeDontUseCopyResult(
	t *testing.T,
	response *ber.Packet,
) dontUseCopyObservation {
	t.Helper()
	if response == nil || len(response.Children) < 2 {
		t.Fatalf("malformed LDAP response: %#v", response)
	}
	operation := response.Children[1]
	return dontUseCopyObservation{
		applicationTag: uint64(operation.Tag),
		code:           rawLDAPResultCode(t, operation),
		diagnostic:     rawLDAPDiagnostic(response),
		referrals:      ldapResultReferrals(response),
	}
}

func rawDontUseCopyControl(critical, hasValue bool) *ber.Packet {
	control := ber.NewSequence("Don't Use Copy")
	control.AppendChild(rawOctetString([]byte(dontUseCopyControlOID)))
	if critical {
		control.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"criticality",
		))
	}
	if hasValue {
		control.AppendChild(rawOctetString(nil))
	}
	return control
}

func rawDontUseCopyCompareRequest(
	dn, attribute, assertion string,
) *ber.Packet {
	request := ber.Encode(
		ber.ClassApplication,
		ber.TypeConstructed,
		ldapwire.ApplicationCompareRequest,
		nil,
		"CompareRequest",
	)
	request.AppendChild(rawOctetString([]byte(dn)))
	ava := ber.NewSequence("AttributeValueAssertion")
	ava.AppendChild(rawOctetString([]byte(attribute)))
	ava.AppendChild(rawOctetString([]byte(assertion)))
	request.AppendChild(ava)
	return request
}

func seedDontUseCopyShadow(
	t *testing.T,
	store storage.Store,
	withReferral bool,
) {
	t.Helper()
	seedDirectory(t, store)
	configDN, err := directory.ParseDN(
		"olcDatabase={1}mdb,cn=config",
	)
	if err != nil {
		t.Fatalf("ParseDN(config): %v", err)
	}
	err = store.Update(context.Background(), func(writer storage.Writer) error {
		entry, err := writer.Get(configDN)
		if err != nil {
			return err
		}
		entry.ReplaceValues(
			"olcUpdateDN",
			stringValues("cn=replicator,dc=example,dc=com"),
		)
		if withReferral {
			entry.ReplaceValues(
				"olcUpdateRef",
				stringValues(
					"ldap://provider.example",
				),
			)
		}
		if err := writer.Put(entry, true); err != nil {
			return err
		}
		if err := writer.Put(directory.Entry{
			DN: "uid=broken-alias,ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{
					Description: "objectClass",
					Values: stringValues(
						"top",
						"alias",
						"extensibleObject",
					),
				},
				{
					Description: "uid",
					Values:      stringValues("broken-alias"),
				},
				{
					Description: "aliasedObjectName",
					Values: stringValues(
						"uid=missing,ou=people,dc=example,dc=com",
					),
				},
			},
		}, false); err != nil {
			return err
		}
		return writer.Put(directory.Entry{
			DN: "ou=remote,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{
					Description: "objectClass",
					Values: stringValues(
						"top",
						"referral",
						"extensibleObject",
					),
				},
				{
					Description: "ou",
					Values:      stringValues("remote"),
				},
				{
					Description: "ref",
					Values:      stringValues("ldap://named.example/dc=remote"),
				},
			},
		}, false)
	})
	if err != nil {
		t.Fatalf("seed Don't Use Copy shadow: %v", err)
	}
}
