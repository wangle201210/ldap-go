package server

import (
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLoadRuntimeShadowSettings(t *testing.T) {
	t.Parallel()

	suffix := mustSyncConsumerDN(t, "dc=example,dc=com")
	tests := []struct {
		name       string
		attributes []directory.Attribute
		consumers  []syncConsumerConfig
		wantShadow bool
		wantMulti  bool
		wantError  string
	}{
		{
			name: "single provider consumer",
			attributes: []directory.Attribute{{
				Description: "olcUpdateRef",
				Values:      stringValues("ldap://provider.example"),
			}},
			consumers:  []syncConsumerConfig{{rid: 1}},
			wantShadow: true,
		},
		{
			name: "multi provider",
			attributes: []directory.Attribute{
				{
					Description: "olcMultiProvider",
					Values:      stringValues("TRUE"),
				},
				{
					Description: "olcUpdateRef",
					Values:      stringValues("ldap://provider.example"),
				},
			},
			consumers: []syncConsumerConfig{{rid: 1}},
			wantMulti: true,
		},
		{
			name: "legacy update DN",
			attributes: []directory.Attribute{{
				Description: "olcUpdateDN",
				Values:      stringValues("cn=replicator,dc=example,dc=com"),
			}},
			wantShadow: true,
		},
		{
			name: "update ref without shadow",
			attributes: []directory.Attribute{{
				Description: "olcUpdateRef",
				Values:      stringValues("ldap://provider.example"),
			}},
			wantError: "requires",
		},
		{
			name: "multi provider without shadow",
			attributes: []directory.Attribute{{
				Description: "olcMirrorMode",
				Values:      stringValues("TRUE"),
			}},
			wantError: "requires",
		},
		{
			name: "mixed replication mechanisms",
			attributes: []directory.Attribute{{
				Description: "olcUpdateDN",
				Values:      stringValues("cn=replicator,dc=example,dc=com"),
			}},
			consumers: []syncConsumerConfig{{rid: 1}},
			wantError: "cannot combine",
		},
		{
			name: "invalid update ref",
			attributes: []directory.Attribute{{
				Description: "olcUpdateRef",
				Values:      stringValues("https://provider.example"),
			}},
			consumers: []syncConsumerConfig{{rid: 1}},
			wantError: "invalid referral",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			database := runtimeDatabase{
				name:          "{1}mdb",
				partition:     "example",
				suffixes:      []directory.DN{suffix},
				syncConsumers: test.consumers,
			}
			err := loadRuntimeShadowSettings(directory.Entry{
				DN:         "olcDatabase={1}mdb,cn=config",
				Attributes: test.attributes,
			}, &database)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf(
						"loadRuntimeShadowSettings() error = %v, want %q",
						err,
						test.wantError,
					)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadRuntimeShadowSettings(): %v", err)
			}
			if database.shadow != test.wantShadow ||
				database.multiProvider != test.wantMulti {
				t.Fatalf(
					"shadow/multi = %t/%t, want %t/%t",
					database.shadow,
					database.multiProvider,
					test.wantShadow,
					test.wantMulti,
				)
			}
		})
	}
}

func TestShadowUpdatePrecondition(t *testing.T) {
	t.Parallel()

	suffix := mustSyncConsumerDN(t, "dc=example,dc=com")
	target := mustSyncConsumerDN(
		t,
		"uid=alice,ou=people,dc=example,dc=com",
	)
	updateDN := mustSyncConsumerDN(
		t,
		"cn=replicator,dc=example,dc=com",
	)
	database := runtimeDatabase{
		suffixes:   []directory.DN{suffix},
		shadow:     true,
		updateDN:   &updateDN,
		updateRefs: []string{"ldap://provider.example/dc=remote,dc=com"},
	}
	runtime := &runtimeState{databases: []runtimeDatabase{database}}

	if result := updateOperationPrecondition(
		runtime,
		updateDN.String(),
		target,
	); result != nil {
		t.Fatalf("legacy update DN was rejected: %#v", result)
	}
	result := updateOperationPrecondition(runtime, "cn=admin,dc=example,dc=com", target)
	if result == nil || result.Code != ldapwire.ResultReferral {
		t.Fatalf("shadow result = %#v", result)
	}
	if len(result.Referrals) != 1 ||
		result.Referrals[0] !=
			"ldap://provider.example/uid=alice,ou=people,dc=remote,dc=com" {
		t.Fatalf("shadow referrals = %q", result.Referrals)
	}

	database.updateRefs = nil
	runtime.databases[0] = database
	result = updateOperationPrecondition(
		runtime,
		"cn=admin,dc=example,dc=com",
		target,
	)
	if result == nil ||
		result.Code != ldapwire.ResultUnwillingToPerform ||
		result.DiagnosticMessage != "shadow context; no update referral" {
		t.Fatalf("shadow no-referral result = %#v", result)
	}

	database.shadow = false
	database.multiProvider = true
	runtime.databases[0] = database
	if result := updateOperationPrecondition(
		runtime,
		"cn=admin,dc=example,dc=com",
		target,
	); result != nil {
		t.Fatalf("multi-provider update was rejected: %#v", result)
	}
}
