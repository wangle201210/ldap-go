package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const openLDAPMetaMapWildcardUID = "wildcard-map"

type openLDAPMetaMapWildcardOutcome struct {
	startupError       string
	searchCode         uint16
	attributes         []string
	descriptionMatches int
	cnMatches          int
	inetOrgMatches     int
	personMatches      int
}

func TestOpenLDAPReferenceMetaMapWildcard(t *testing.T) {
	tools := requireOpenLDAPMetaReferenceTools(t)
	assertPinnedOpenLDAPMetaReference(t, tools)
	assertPinnedOpenLDAPMetaMapSources(t)

	providerURI, stopProvider := startOpenLDAPMetaMapWildcardProvider(t, tools)
	defer stopProvider()

	allAttributes := []string{
		"cn=wildcard-map",
		"description=provider-map",
		"objectclass=inetOrgPerson,organizationalPerson,person,top",
		"sn=Wildcard",
		"uid=wildcard-map",
	}
	tests := []struct {
		name     string
		mappings []string
		want     openLDAPMetaMapWildcardOutcome
	}{
		{
			name:     "attribute star drops missing attributes and filters",
			mappings: []string{"attribute *"},
			want: openLDAPMetaMapWildcardOutcome{
				searchCode:     ldap.LDAPResultSuccess,
				attributes:     []string{"objectclass=inetOrgPerson,organizationalPerson,person,top"},
				inetOrgMatches: 1,
				personMatches:  1,
			},
		},
		{
			name:     "attribute star star passes through",
			mappings: []string{"attribute * *"},
			want: openLDAPMetaMapWildcardOutcome{
				searchCode:         ldap.LDAPResultSuccess,
				attributes:         allAttributes,
				descriptionMatches: 1,
				cnMatches:          1,
				inetOrgMatches:     1,
				personMatches:      1,
			},
		},
		{
			name: "attribute wildcard identity forms an allow list",
			mappings: []string{
				"attribute * description",
				"attribute *",
			},
			want: openLDAPMetaMapWildcardOutcome{
				searchCode: ldap.LDAPResultSuccess,
				attributes: []string{
					"description=provider-map",
					"objectclass=inetOrgPerson,organizationalPerson,person,top",
				},
				descriptionMatches: 1,
				inetOrgMatches:     1,
				personMatches:      1,
			},
		},
		{
			name:     "attribute with no destination drops only the response side",
			mappings: []string{"attribute description"},
			want: openLDAPMetaMapWildcardOutcome{
				searchCode: ldap.LDAPResultSuccess,
				attributes: []string{
					"cn=wildcard-map",
					"objectclass=inetOrgPerson,organizationalPerson,person,top",
					"sn=Wildcard",
					"uid=wildcard-map",
				},
				descriptionMatches: 1,
				cnMatches:          1,
				inetOrgMatches:     1,
				personMatches:      1,
			},
		},
		{
			name:     "objectclass star without a concrete map passes search values",
			mappings: []string{"objectclass *"},
			want: openLDAPMetaMapWildcardOutcome{
				searchCode:         ldap.LDAPResultSuccess,
				attributes:         allAttributes,
				descriptionMatches: 1,
				cnMatches:          1,
				inetOrgMatches:     1,
				personMatches:      1,
			},
		},
		{
			name:     "objectclass star star passes through",
			mappings: []string{"objectclass * *"},
			want: openLDAPMetaMapWildcardOutcome{
				searchCode:         ldap.LDAPResultSuccess,
				attributes:         allAttributes,
				descriptionMatches: 1,
				cnMatches:          1,
				inetOrgMatches:     1,
				personMatches:      1,
			},
		},
		{
			name: "objectclass wildcard identity forms an allow list",
			mappings: []string{
				"objectclass * inetOrgPerson",
				"objectclass *",
			},
			want: openLDAPMetaMapWildcardOutcome{
				searchCode: ldap.LDAPResultSuccess,
				attributes: []string{
					"cn=wildcard-map",
					"description=provider-map",
					"objectclass=inetOrgPerson",
					"sn=Wildcard",
					"uid=wildcard-map",
				},
				descriptionMatches: 1,
				cnMatches:          1,
				inetOrgMatches:     1,
				personMatches:      1,
			},
		},
		{
			name:     "objectclass with no destination drops only the response value",
			mappings: []string{"objectclass inetOrgPerson"},
			want: openLDAPMetaMapWildcardOutcome{
				searchCode: ldap.LDAPResultSuccess,
				attributes: []string{
					"cn=wildcard-map",
					"description=provider-map",
					"objectclass=organizationalPerson,person,top",
					"sn=Wildcard",
					"uid=wildcard-map",
				},
				descriptionMatches: 1,
				cnMatches:          1,
				inetOrgMatches:     1,
				personMatches:      1,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reference := func() openLDAPMetaMapWildcardOutcome {
				referenceURI, stopReference := startOpenLDAPMetaMapWildcardProxy(
					t,
					tools,
					providerURI,
					test.mappings,
				)
				defer stopReference()
				return observeOpenLDAPMetaMapWildcard(t, referenceURI)
			}()
			if !reflect.DeepEqual(reference, test.want) {
				t.Fatalf(
					"OpenLDAP 2.6.13 wildcard map fixture changed:\nwant: %#v\ngot:  %#v",
					test.want,
					reference,
				)
			}

			ldapGoURI, stopLDAPGo, startErr := startLDAPGoMetaMapWildcardProxy(
				t,
				providerURI,
				test.mappings,
			)
			got := openLDAPMetaMapWildcardOutcome{}
			if startErr != nil {
				got.startupError = startErr.Error()
			} else {
				got = func() openLDAPMetaMapWildcardOutcome {
					defer stopLDAPGo()
					return observeOpenLDAPMetaMapWildcard(t, ldapGoURI)
				}()
			}
			if !reflect.DeepEqual(got, reference) {
				t.Fatalf(
					"ldap-go olcDbMap wildcard behavior differs from OpenLDAP 2.6.13 for %q:\nOpenLDAP: %#v\nldap-go:  %#v",
					strings.Join(test.mappings, "; "),
					reference,
					got,
				)
			}
		})
	}
}

func assertPinnedOpenLDAPMetaMapSources(t *testing.T) {
	t.Helper()
	sourceRoot := os.Getenv("OPENLDAP_SOURCE")
	for relativePath, want := range map[string]string{
		filepath.Join("servers", "slapd", "back-meta", "map.c"):    "aa99ba8d1ed7b0e1ac12a5debeac2b1c6feb00d4dabddde417b8d5e15833ebe8",
		filepath.Join("servers", "slapd", "back-meta", "config.c"): "2986b25f681595913e40a53db90e50a7dd8d67a314f2b95cb117ff8b9d5834d0",
	} {
		contents, err := os.ReadFile(filepath.Join(sourceRoot, relativePath))
		if err != nil {
			t.Fatalf("read pinned OpenLDAP source %s: %v", relativePath, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(contents)); got != want {
			t.Fatalf("pinned OpenLDAP source %s SHA-256 = %s, want %s", relativePath, got, want)
		}
	}
}

func startOpenLDAPMetaMapWildcardProvider(
	t *testing.T,
	tools openLDAPReferenceTools,
) (string, func()) {
	t.Helper()
	extraData := `
dn: uid=wildcard-map,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: wildcard-map
cn: wildcard-map
sn: Wildcard
description: provider-map
`
	return startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		nil,
		"",
		"access to * by * write",
		extraData,
	)
}

func startOpenLDAPMetaMapWildcardProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerURI string,
	mappings []string,
) (string, func()) {
	t.Helper()
	directives := make([]string, 0, len(mappings))
	for _, mapping := range mappings {
		directives = append(directives, "map "+mapping)
	}
	configuration := fmt.Sprintf(`database meta
suffix "%s"
rootdn "cn=admin,%s"
rootpw secret
access to * by * write
network-timeout 1
bind-timeout 1000000
nretries 1
chase-referrals no

uri "%s/%s"
suffixmassage "%s" "dc=example,dc=com"
%s
idassert-bind bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none
idassert-authzFrom "*"`,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		providerURI,
		openLDAPMetaBaseDN,
		openLDAPMetaBaseDN,
		strings.Join(directives, "\n"),
	)
	return startOpenLDAPReferenceServerWithConfig(t, tools, nil, "", configuration, "")
}

func startLDAPGoMetaMapWildcardProxy(
	t *testing.T,
	providerURI string,
	mappings []string,
) (string, func(), error) {
	t.Helper()
	store := storage.NewMemory()
	seedLDAPGoMetaMapWildcardConfiguration(t, store, providerURI, mappings)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = store.Close()
		t.Fatalf("listen for ldap-go wildcard map fixture: %v", err)
	}
	instance, err := New(Config{Store: store})
	if err != nil {
		_ = listener.Close()
		_ = store.Close()
		return "", func() {}, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- instance.Serve(ctx, listener)
	}()
	stop := func() {
		cancel()
		select {
		case serveErr := <-done:
			if serveErr != nil {
				t.Errorf("serve ldap-go wildcard map fixture: %v", serveErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("ldap-go wildcard map fixture did not stop")
		}
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("close ldap-go wildcard map store: %v", closeErr)
		}
	}
	return "ldap://" + listener.Addr().String(), stop, nil
}

func seedLDAPGoMetaMapWildcardConfiguration(
	t *testing.T,
	store storage.Store,
	providerURI string,
	mappings []string,
) {
	t.Helper()
	databaseDN := "olcDatabase={1}meta,cn=config"
	targetAttributes := []directory.Attribute{
		{Description: "objectClass", Values: stringValues("olcMetaTargetConfig")},
		{Description: "olcMetaSub", Values: stringValues("{0}uri")},
		{Description: "olcDbURI", Values: stringValues(providerURI + "/" + openLDAPMetaBaseDN)},
		{Description: "olcDbRewrite", Values: stringValues(
			"suffixmassage \"" + openLDAPMetaBaseDN + "\" \"dc=example,dc=com\"",
		)},
		{Description: "olcDbIDAssertBind", Values: stringValues(
			`bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none`,
		)},
		{Description: "olcDbIDAssertAuthzFrom", Values: stringValues("*")},
	}
	if len(mappings) > 0 {
		targetAttributes = append(targetAttributes, directory.Attribute{
			Description: "olcDbMap",
			Values:      stringValues(mappings...),
		})
	}
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
			},
		},
		{
			DN: "olcDatabase={0}config,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{0}config")},
				{Description: "olcRootDN", Values: stringValues("cn=config")},
				{Description: "olcRootPW", Values: stringValues("config-secret")},
			},
		},
		{
			DN: databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig", "olcMetaConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}meta")},
				{Description: "olcSuffix", Values: stringValues(openLDAPMetaBaseDN)},
				{Description: "olcRootDN", Values: stringValues("cn=admin," + openLDAPMetaBaseDN)},
				{Description: "olcRootPW", Values: stringValues("secret")},
				{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
				{Description: "olcDbNretries", Values: stringValues("1")},
			},
		},
		{
			DN:         "olcMetaSub={0}uri," + databaseDN,
			Attributes: targetAttributes,
		},
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{openLDAPMetaBaseDN, "cn=config"})
	}); err != nil {
		t.Fatalf("seed ldap-go wildcard map configuration: %v", err)
	}
}

func observeOpenLDAPMetaMapWildcard(
	t *testing.T,
	proxyURI string,
) openLDAPMetaMapWildcardOutcome {
	t.Helper()
	client, err := ldap.DialURL(proxyURI)
	if err != nil {
		t.Fatalf("dial wildcard map fixture: %v", err)
	}
	defer client.Close()
	if err := client.Bind("cn=admin,"+openLDAPMetaBaseDN, "secret"); err != nil {
		t.Fatalf("bind wildcard map fixture: %v", err)
	}

	baseDN := "uid=" + openLDAPMetaMapWildcardUID + ",ou=people," + openLDAPMetaBaseDN
	all, allErr := client.Search(ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"objectClass", "uid", "cn", "sn", "description"},
		nil,
	))
	outcome := openLDAPMetaMapWildcardOutcome{
		searchCode: openLDAPMetaMapWildcardResultCode(t, allErr),
	}
	if all != nil && len(all.Entries) > 0 {
		outcome.attributes = flattenOpenLDAPMetaMapWildcardAttributes(all.Entries[0])
	}
	outcome.descriptionMatches = countOpenLDAPMetaMapWildcardFilter(
		t,
		client,
		baseDN,
		"(description=provider-map)",
	)
	outcome.cnMatches = countOpenLDAPMetaMapWildcardFilter(
		t,
		client,
		baseDN,
		"(cn=wildcard-map)",
	)
	outcome.inetOrgMatches = countOpenLDAPMetaMapWildcardFilter(
		t,
		client,
		baseDN,
		"(objectClass=inetOrgPerson)",
	)
	outcome.personMatches = countOpenLDAPMetaMapWildcardFilter(
		t,
		client,
		baseDN,
		"(objectClass=person)",
	)
	return outcome
}

func countOpenLDAPMetaMapWildcardFilter(
	t *testing.T,
	client *ldap.Conn,
	baseDN string,
	filter string,
) int {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"1.1"},
		nil,
	))
	if code := openLDAPMetaMapWildcardResultCode(t, err); code != ldap.LDAPResultSuccess {
		t.Fatalf("wildcard map Search %s returned LDAP code %d", filter, code)
	}
	return len(result.Entries)
}

func openLDAPMetaMapWildcardResultCode(t *testing.T, err error) uint16 {
	t.Helper()
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return uint16(ldapErr.ResultCode)
	}
	t.Fatalf("wildcard map operation failed without an LDAP result: %v", err)
	return ldap.LDAPResultOther
}

func flattenOpenLDAPMetaMapWildcardAttributes(entry *ldap.Entry) []string {
	attributes := make([]string, 0, len(entry.Attributes))
	for _, attribute := range entry.Attributes {
		values := append([]string(nil), attribute.Values...)
		sort.Strings(values)
		attributes = append(
			attributes,
			strings.ToLower(attribute.Name)+"="+strings.Join(values, ","),
		)
	}
	sort.Strings(attributes)
	return attributes
}
