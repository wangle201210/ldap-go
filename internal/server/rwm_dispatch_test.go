package server

import (
	"fmt"
	"slices"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestRWMRelayDispatchSkipsInactiveRuntime(t *testing.T) {
	t.Parallel()

	active := &rwmRuntimeConfiguration{rewrite: &rwmRewriteEngine{configured: true, enabled: true}}
	for _, test := range []struct {
		name     string
		relay    *relayRuntimeConfiguration
		rwm      *rwmRuntimeConfiguration
		separate bool
	}{
		{name: "local database"},
		{name: "relay without overlay", relay: &relayRuntimeConfiguration{}},
		{name: "relay without engine", relay: &relayRuntimeConfiguration{}, rwm: &rwmRuntimeConfiguration{}},
		{name: "engine off", relay: &relayRuntimeConfiguration{}, rwm: &rwmRuntimeConfiguration{rewrite: &rwmRewriteEngine{configured: true}}},
		{name: "implicit suffix mapping", relay: &relayRuntimeConfiguration{}, rwm: &rwmRuntimeConfiguration{rewrite: &rwmRewriteEngine{enabled: true}}},
		{name: "active local overlay", rwm: active},
		{name: "overlay and relay on different databases", rwm: active, separate: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			normalizer := &rwmDispatchCountingNormalizer{}
			databases := []runtimeDatabase{{
				name: "mdb", suffixes: []directory.DN{staticRuntimeDN("dc=example,dc=com")},
				dnNormalizer: normalizer, relay: test.relay, rwm: test.rwm,
			}}
			if test.separate {
				databases = append(databases, runtimeDatabase{relay: &relayRuntimeConfiguration{}})
			}
			runtime := &runtimeState{databases: databases, features: runtimeFeaturesForDatabases(databases)}
			if runtime.features.rwmRewriteRelay {
				t.Fatal("inactive runtime enabled rewrite relay dispatch")
			}
			connection := &responseBudgetBufferConnection{}
			server := &Server{}
			for _, request := range []ldapwire.Request{
				ldapwire.SearchRequest{BaseDN: "uid=alice,dc=example,dc=com"},
				ldapwire.SearchRequest{BaseDN: "uid=broken,"},
				ldapwire.BindRequest{Name: "uid=broken,"},
				ldapwire.ExtendedRequest{Name: passwordModifyOID, HasValue: true, Value: []byte{0xff}},
			} {
				handled, err := server.tryRWMRewriteRelayOperation(t.Context(), connection,
					&connectionState{runtime: runtime}, ldapwire.Message{ID: 1, Request: request})
				if handled || err != nil || connection.Len() != 0 {
					t.Fatalf("inactive dispatch for %T = %t, %v, response bytes=%d", request, handled, err, connection.Len())
				}
			}
			if normalizer.calls != 0 {
				t.Fatalf("inactive relay performed %d DN normalizations", normalizer.calls)
			}
		})
	}
}

type rwmDispatchCountingNormalizer struct{ calls int }

func (normalizer *rwmDispatchCountingNormalizer) NormalizeDNAttribute(name string, value []byte) (string, []byte, error) {
	normalizer.calls++
	return name, value, nil
}

func TestRWMRelayDispatchFeatureOnlineConfiguration(t *testing.T) {
	fixture := startRWMRewriteFixture(t, "relay", false)
	config := bindConstraintClient(t, fixture.address, "cn=config", "config-secret")
	defer config.Close()
	client := bindConstraintClient(t, fixture.address, fixture.userDN, fixture.password)
	defer client.Close()
	original := byteValuesToStrings(readStoredEntry(t, fixture.store, fixture.configDN).Values(fixture.attribute))
	active := append(slices.Clone(original),
		fmt.Sprintf("{%d}rewriteContext searchFilter", len(original)),
		fmt.Sprintf(`{%d}rewriteRule "^[(]uid=alias[)]$" "(uid=alice)" :`, len(original)+1))
	inactive := []string{`{0}rwm-suffixmassage "dc=virtual,dc=test" "dc=example,dc=com"`}
	initial := fixture.server.runtime.Load()
	if !initial.features.rwmRewriteRelay {
		t.Fatal("configured active relay was not enabled at startup")
	}
	for _, test := range []struct {
		name   string
		values []string
		active bool
	}{
		{name: "disable", values: inactive},
		{name: "enable", values: active, active: true},
		{name: "disable again", values: inactive},
		{name: "enable again", values: active, active: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			modify := ldap.NewModifyRequest(fixture.configDN, nil)
			modify.Replace(fixture.attribute, test.values)
			if err := config.Modify(modify); err != nil {
				t.Fatalf("replace rewrite configuration: %v", err)
			}
			runtime := fixture.server.runtime.Load()
			if runtime.features.rwmRewriteRelay != test.active || !initial.features.rwmRewriteRelay {
				t.Fatal("replacement feature is incorrect or mutated the old runtime")
			}
			for _, filter := range []string{"(uid=alice)", "(uid=alias)"} {
				result, err := client.Search(ldap.NewSearchRequest(fixture.userDN, ldap.ScopeBaseObject,
					ldap.NeverDerefAliases, 0, 0, false, filter, []string{"uid"}, nil))
				want := 1
				if filter == "(uid=alias)" && !test.active {
					want = 0
				}
				if err != nil || len(result.Entries) != want {
					t.Fatalf("Search(%s) = %#v, %v; want %d entries", filter, result, err, want)
				}
			}
			connection := &responseBudgetBufferConnection{}
			handled, err := fixture.server.tryRWMRewriteRelayOperation(t.Context(), connection,
				&connectionState{runtime: runtime, boundDN: fixture.userDN}, ldapwire.Message{
					ID: 7, Request: ldapwire.SearchRequest{
						BaseDN: fixture.userDN, Scope: directory.ScopeBase,
						Filter:     directory.Filter{Kind: directory.FilterEquality, Attribute: "uid", Assertion: []byte("alias")},
						Attributes: []string{"uid"},
					},
				})
			if err != nil || handled != test.active || (connection.Len() > 0) != test.active {
				t.Fatalf("direct dispatch = %t, %v, response bytes=%d", handled, err, connection.Len())
			}
		})
	}
	current := fixture.server.runtime.Load()
	invalid := ldap.NewModifyRequest(fixture.configDN, nil)
	invalid.Replace(fixture.attribute, []string{"rewriteEngine invalid"})
	if err := config.Modify(invalid); err == nil {
		t.Fatal("accepted invalid rewrite configuration")
	}
	if fixture.server.runtime.Load() != current || !current.features.rwmRewriteRelay {
		t.Fatal("rejected configuration changed the active relay feature")
	}
}
