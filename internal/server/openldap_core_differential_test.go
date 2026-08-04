package server

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type coreReferenceObservation struct {
	name       string
	code       uint16
	matchedDN  string
	diagnostic string
	referrals  []string
	entries    []string
}

func TestOpenLDAPReferenceCoreProtocolDifferential(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	openLDAPURI, stopOpenLDAP := startOpenLDAPReferenceServer(t, tools, nil)
	defer stopOpenLDAP()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedCoreReferenceDirectory(t, store)
	ldapGoAddress, stopLDAPGo := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("secret"),
	})
	defer stopLDAPGo()

	reference := runCoreReferenceScenario(t, openLDAPURI)
	implementation := runCoreReferenceScenario(t, "ldap://"+ldapGoAddress)
	if reflect.DeepEqual(reference, implementation) {
		return
	}
	for index := range reference {
		if reflect.DeepEqual(reference[index], implementation[index]) {
			continue
		}
		t.Errorf(
			"%s mismatch\nOpenLDAP: %#v\nldap-go:  %#v",
			reference[index].name,
			reference[index],
			implementation[index],
		)
	}
}

func seedCoreReferenceDirectory(t *testing.T, store storage.Store) {
	t.Helper()
	entries := []directory.Entry{
		{
			DN: "dc=example,dc=com",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("top", "domain")},
				{Description: "dc", Values: stringValues("example")},
			},
		},
		{
			DN: "ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{
					Description: "objectClass",
					Values:      stringValues("top", "organizationalUnit"),
				},
				{Description: "ou", Values: stringValues("people")},
			},
		},
	}
	for _, uid := range []string{"carol", "alice", "bob"} {
		entries = append(entries, directory.Entry{
			DN: "uid=" + uid + ",ou=people,dc=example,dc=com",
			Attributes: []directory.Attribute{
				{
					Description: "objectClass",
					Values: stringValues(
						"top",
						"person",
						"organizationalPerson",
						"inetOrgPerson",
					),
				},
				{Description: "uid", Values: stringValues(uid)},
				{Description: "cn", Values: stringValues(titleASCII(uid))},
				{Description: "sn", Values: stringValues(titleASCII(uid))},
			},
		})
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com"})
	}); err != nil {
		t.Fatalf("seed core reference directory: %v", err)
	}
}

func titleASCII(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

func runCoreReferenceScenario(
	t *testing.T,
	uri string,
) []coreReferenceObservation {
	t.Helper()
	var observations []coreReferenceObservation

	observations = append(observations,
		observeCoreBind(t, uri, "anonymous bind", "", ""),
		observeCoreBind(
			t,
			uri,
			"invalid root bind",
			"cn=admin,dc=example,dc=com",
			"wrong",
		),
	)

	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	observations = append(
		observations,
		observeCoreError(
			"root bind",
			client.Bind("cn=admin,dc=example,dc=com", "secret"),
		),
	)

	observations = append(observations,
		observeCoreSearch(t, client, "base search", ldap.NewSearchRequest(
			"uid=alice,ou=people,dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"objectClass", "uid", "cn", "sn"},
			nil,
		)),
		observeCoreSearch(t, client, "missing base", ldap.NewSearchRequest(
			"uid=missing,ou=people,dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"1.1"},
			nil,
		)),
		observeCoreSearch(t, client, "children scope", ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeChildren,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"1.1"},
			nil,
		)),
		observeCoreSearch(t, client, "children scope missing base", ldap.NewSearchRequest(
			"ou=missing,dc=example,dc=com",
			ldap.ScopeChildren,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"1.1"},
			nil,
		)),
		observeCoreSearch(t, client, "one-level and filter", ldap.NewSearchRequest(
			"ou=people,dc=example,dc=com",
			ldap.ScopeSingleLevel,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(&(|(uid=alice)(uid=bob))(!(sn=Carol)))",
			[]string{"uid", "cn"},
			nil,
		)),
		observeCoreSearch(t, client, "substring filter", ldap.NewSearchRequest(
			"dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(cn=*LI*)",
			[]string{"uid", "cn"},
			nil,
		)),
		observeCoreSearch(t, client, "present filter", ldap.NewSearchRequest(
			"ou=people,dc=example,dc=com",
			ldap.ScopeSingleLevel,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(uid=*)",
			[]string{"uid"},
			nil,
		)),
		observeCoreSearch(t, client, "undefined filter attribute", ldap.NewSearchRequest(
			"ou=people,dc=example,dc=com",
			ldap.ScopeSingleLevel,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(notRegistered=value)",
			[]string{"1.1"},
			nil,
		)),
		observeCoreSearch(t, client, "types only", ldap.NewSearchRequest(
			"uid=alice,ou=people,dc=example,dc=com",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			true,
			"(objectClass=*)",
			[]string{"uid", "cn"},
			nil,
		)),
		observeCoreSearchCount(t, client, "size-limited search", ldap.NewSearchRequest(
			"ou=people,dc=example,dc=com",
			ldap.ScopeSingleLevel,
			ldap.NeverDerefAliases,
			2,
			0,
			false,
			"(objectClass=inetOrgPerson)",
			[]string{"1.1"},
			nil,
		)),
	)

	archive := ldap.NewAddRequest("ou=archive,dc=example,dc=com", nil)
	archive.Attribute("objectClass", []string{"top", "organizationalUnit"})
	archive.Attribute("ou", []string{"archive"})
	observations = append(
		observations,
		observeCoreError("add archive", client.Add(archive)),
	)

	daveDN := "uid=dave,ou=people,dc=example,dc=com"
	dave := coreReferencePersonAdd(daveDN, "dave")
	dave.Attribute("description", []string{"first", "second"})
	dave.Attribute("userPassword", []string{"secret"})
	observations = append(
		observations,
		observeCoreError("add person", client.Add(dave)),
		observeCoreError("duplicate add", client.Add(coreReferencePersonAdd(daveDN, "dave"))),
		observeCoreBind(t, uri, "user bind", daveDN, "secret"),
		observeCoreBind(t, uri, "invalid user bind", daveDN, "wrong"),
	)

	missingParent := coreReferencePersonAdd(
		"uid=orphan,ou=missing,dc=example,dc=com",
		"orphan",
	)
	observations = append(
		observations,
		observeCoreError("add below missing parent", client.Add(missingParent)),
	)
	missingRequired := ldap.NewAddRequest(
		"uid=incomplete,ou=people,dc=example,dc=com",
		nil,
	)
	missingRequired.Attribute("objectClass", []string{"inetOrgPerson"})
	missingRequired.Attribute("uid", []string{"incomplete"})
	missingRequired.Attribute("cn", []string{"Incomplete"})
	observations = append(
		observations,
		observeCoreError("add missing required attribute", client.Add(missingRequired)),
		observeCoreCompare(t, client, "compare true", daveDN, "cn", "DAVE"),
		observeCoreCompare(t, client, "compare false", daveDN, "cn", "Other"),
		observeCoreCompare(t, client, "compare missing attribute", daveDN, "mail", "dave@example.com"),
		observeCoreCompare(t, client, "compare missing object", "uid=missing,ou=people,dc=example,dc=com", "uid", "missing"),
	)

	missingDN := "uid=missing,ou=people,dc=example,dc=com"
	modifyMissing := ldap.NewModifyRequest(missingDN, nil)
	modifyMissing.Replace("cn", []string{"Missing"})
	observations = append(
		observations,
		observeCoreError("modify missing object", client.Modify(modifyMissing)),
		observeCoreError("rename missing object", client.ModifyDN(ldap.NewModifyDNRequest(
			missingDN,
			"uid=still-missing",
			true,
			"",
		))),
		observeCoreError("move below missing superior", client.ModifyDN(ldap.NewModifyDNRequest(
			daveDN,
			"uid=dave",
			true,
			"ou=missing,dc=example,dc=com",
		))),
		observeCoreError("rename onto existing DN", client.ModifyDN(ldap.NewModifyDNRequest(
			daveDN,
			"uid=bob",
			true,
			"",
		))),
	)

	modify := ldap.NewModifyRequest(daveDN, nil)
	modify.Replace("cn", []string{"David Example"})
	modify.Add("mail", []string{"dave@example.com"})
	modify.Delete("description", []string{"first"})
	observations = append(
		observations,
		observeCoreError("modify mixed", client.Modify(modify)),
	)
	duplicateValue := ldap.NewModifyRequest(daveDN, nil)
	duplicateValue.Add("mail", []string{"DAVE@example.com"})
	observations = append(
		observations,
		observeCoreError("modify duplicate value", client.Modify(duplicateValue)),
	)
	missingValue := ldap.NewModifyRequest(daveDN, nil)
	missingValue.Delete("description", []string{"missing"})
	observations = append(
		observations,
		observeCoreError("modify missing value", client.Modify(missingValue)),
	)
	atomic := ldap.NewModifyRequest(daveDN, nil)
	atomic.Replace("cn", []string{"Must Roll Back"})
	atomic.Add("mail", []string{"dave@example.com"})
	observations = append(
		observations,
		observeCoreError("atomic modify failure", client.Modify(atomic)),
		observeCoreSearch(t, client, "state after modify", ldap.NewSearchRequest(
			daveDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"uid", "cn", "sn", "mail", "description"},
			nil,
		)),
	)

	childDN := "cn=profile," + daveDN
	child := ldap.NewAddRequest(childDN, nil)
	child.Attribute("objectClass", []string{"top", "organizationalRole"})
	child.Attribute("cn", []string{"profile"})
	observations = append(
		observations,
		observeCoreError("add child", client.Add(child)),
		observeCoreError("delete non-leaf", client.Del(ldap.NewDelRequest(daveDN, nil))),
	)

	renamedDN := "uid=david,ou=archive,dc=example,dc=com"
	renamedChildDN := "cn=profile," + renamedDN
	observations = append(
		observations,
		observeCoreError("move subtree", client.ModifyDN(ldap.NewModifyDNRequest(
			daveDN,
			"uid=david",
			true,
			"ou=archive,dc=example,dc=com",
		))),
		observeCoreSearch(t, client, "moved subtree", ldap.NewSearchRequest(
			renamedDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"uid", "cn", "sn", "mail"},
			nil,
		)),
		observeCoreSearch(t, client, "old DN after move", ldap.NewSearchRequest(
			daveDN,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=*)",
			[]string{"1.1"},
			nil,
		)),
		observeCoreError("delete moved child", client.Del(ldap.NewDelRequest(renamedChildDN, nil))),
		observeCoreError("delete moved person", client.Del(ldap.NewDelRequest(renamedDN, nil))),
		observeCoreError("delete missing object", client.Del(ldap.NewDelRequest(renamedDN, nil))),
	)
	return observations
}

func coreReferencePersonAdd(dn, uid string) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{
		"top",
		"person",
		"organizationalPerson",
		"inetOrgPerson",
	})
	request.Attribute("uid", []string{uid})
	request.Attribute("cn", []string{titleASCII(uid)})
	request.Attribute("sn", []string{titleASCII(uid)})
	return request
}

func observeCoreBind(
	t *testing.T,
	uri,
	name,
	dn,
	password string,
) coreReferenceObservation {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	defer client.Close()
	return observeCoreError(name, client.Bind(dn, password))
}

func observeCoreSearch(
	t *testing.T,
	client *ldap.Conn,
	name string,
	request *ldap.SearchRequest,
) coreReferenceObservation {
	t.Helper()
	result, err := client.Search(request)
	observation := observeCoreError(name, err)
	if result == nil {
		return observation
	}
	observation.referrals = append([]string(nil), result.Referrals...)
	sort.Strings(observation.referrals)
	for _, entry := range result.Entries {
		observation.entries = append(
			observation.entries,
			normalizeCoreReferenceEntry(entry),
		)
	}
	sort.Strings(observation.entries)
	return observation
}

func observeCoreSearchCount(
	t *testing.T,
	client *ldap.Conn,
	name string,
	request *ldap.SearchRequest,
) coreReferenceObservation {
	t.Helper()
	observation := observeCoreSearch(t, client, name, request)
	observation.entries = []string{fmt.Sprintf("count=%d", len(observation.entries))}
	return observation
}

func observeCoreCompare(
	t *testing.T,
	client *ldap.Conn,
	name,
	dn,
	attribute,
	value string,
) coreReferenceObservation {
	t.Helper()
	matched, err := client.Compare(dn, attribute, value)
	if err != nil {
		return observeCoreError(name, err)
	}
	code := uint16(ldap.LDAPResultCompareFalse)
	if matched {
		code = ldap.LDAPResultCompareTrue
	}
	return coreReferenceObservation{name: name, code: code}
}

func observeCoreError(name string, err error) coreReferenceObservation {
	observation := coreReferenceObservation{name: name}
	if err == nil {
		return observation
	}
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		observation.code = ldap.ErrorNetwork
		observation.diagnostic = err.Error()
		return observation
	}
	observation.code = ldapError.ResultCode
	observation.matchedDN = ldapError.MatchedDN
	if ldapError.Err != nil {
		observation.diagnostic = ldapError.Err.Error()
	}
	return observation
}

func normalizeCoreReferenceEntry(entry *ldap.Entry) string {
	attributes := make([]string, 0, len(entry.Attributes))
	for _, attribute := range entry.Attributes {
		values := make([]string, len(attribute.ByteValues))
		for index, value := range attribute.ByteValues {
			values[index] = hex.EncodeToString(value)
		}
		sort.Strings(values)
		attributes = append(attributes, fmt.Sprintf(
			"%s=%s",
			strings.ToLower(attribute.Name),
			strings.Join(values, ","),
		))
	}
	sort.Strings(attributes)
	return strings.ToLower(entry.DN) + "|" + strings.Join(attributes, "|")
}
