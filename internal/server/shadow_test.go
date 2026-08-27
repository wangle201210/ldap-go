package server

import (
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
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
			name: "TLCP update referral",
			attributes: []directory.Attribute{{
				Description: "olcUpdateRef",
				Values: stringValues(
					"ldap+tlcp://provider.example:1636",
				),
			}},
			consumers:  []syncConsumerConfig{{rid: 1}},
			wantShadow: true,
		},
		{
			name: "non-LDAP update referral",
			attributes: []directory.Attribute{{
				Description: "olcUpdateRef",
				Values:      stringValues("https://provider.example/directory"),
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
			name: "LDAP update ref with DN",
			attributes: []directory.Attribute{{
				Description: "olcUpdateRef",
				Values: stringValues(
					"ldap://provider.example/dc=example,dc=com",
				),
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

func TestValidateShadowUpdateRefMatchesOpenLDAPRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value string
		valid bool
	}{
		{value: "ldap://provider.example", valid: true},
		{value: "LDAP://provider.example", valid: true},
		{value: "ldaps://provider.example/", valid: true},
		{value: "ldap+tlcp://provider.example:1636", valid: true},
		{value: "https://provider.example/directory", valid: true},
		{value: "ldap://provider.example/dc=example,dc=com"},
		{value: "ldap://provider.example/?cn"},
		{value: "ldap://provider.example/??sub"},
		{value: "ldap://provider.example/???(uid=alice)"},
		{value: "ldap:provider.example"},
		{value: "not-a-uri"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.value, func(t *testing.T) {
			t.Parallel()
			got, err := validateShadowUpdateRef(test.value)
			if test.valid && (err != nil || got != test.value) {
				t.Fatalf(
					"validateShadowUpdateRef() = %q, %v; want valid",
					got,
					err,
				)
			}
			if !test.valid && err == nil {
				t.Fatalf(
					"validateShadowUpdateRef() = %q; want error",
					got,
				)
			}
		})
	}
}

func TestShadowUpdatePrecondition(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("schema.NewBuiltinRegistry(): %v", err)
	}
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
		updateRefs: []string{"ldap://provider.example"},
	}
	runtime := &runtimeState{
		schema:    registry,
		databases: []runtimeDatabase{database},
	}

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
			"ldap://provider.example/uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("shadow referrals = %q", result.Referrals)
	}

	database.updateRefs = nil
	runtime.databases[0] = database
	runtime.defaultReferrals = []string{"ldap://fallback.example"}
	result = updateOperationPrecondition(
		runtime,
		"cn=admin,dc=example,dc=com",
		target,
	)
	if result == nil ||
		result.Code != ldapwire.ResultReferral ||
		len(result.Referrals) != 1 ||
		result.Referrals[0] !=
			"ldap://fallback.example/uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("shadow global referral result = %#v", result)
	}

	runtime.defaultReferrals = nil
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

func TestShadowResultsFallBackToGlobalReferral(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("schema.NewBuiltinRegistry(): %v", err)
	}
	target := mustSyncConsumerDN(
		t,
		"uid=alice,ou=people,dc=example,dc=com",
	)
	database := runtimeDatabase{}
	runtime := &runtimeState{
		schema:           registry,
		defaultReferrals: []string{"ldap://fallback.example"},
	}

	update := shadowUpdateResult(runtime, database, target)
	if update.Code != ldapwire.ResultReferral ||
		len(update.Referrals) != 1 ||
		update.Referrals[0] !=
			"ldap://fallback.example/uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("shadow update fallback = %#v", update)
	}

	search := shadowSearchResult(
		runtime,
		database,
		target,
		directory.ScopeWholeSubtree,
	)
	if search.Code != ldapwire.ResultReferral ||
		len(search.Referrals) != 1 ||
		search.Referrals[0] !=
			"ldap://fallback.example/uid=alice,ou=people,dc=example,dc=com??sub" {
		t.Fatalf("shadow search fallback = %#v", search)
	}

	database.updateRefs = []string{"ldap://update.example"}
	explicit := shadowUpdateResult(runtime, database, target)
	if len(explicit.Referrals) != 1 ||
		explicit.Referrals[0] !=
			"ldap://update.example/uid=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("explicit update referral precedence = %#v", explicit)
	}
}

func TestShadowResultsKeepMissingReferralDiagnostics(t *testing.T) {
	t.Parallel()

	target := mustSyncConsumerDN(t, "uid=alice,dc=example,dc=com")
	update := shadowUpdateResult(&runtimeState{}, runtimeDatabase{}, target)
	if update.Code != ldapwire.ResultUnwillingToPerform ||
		update.DiagnosticMessage != "shadow context; no update referral" {
		t.Fatalf("shadow update without referral = %#v", update)
	}

	search := shadowSearchResult(
		&runtimeState{},
		runtimeDatabase{},
		target,
		directory.ScopeSingleLevel,
	)
	if search.Code != ldapwire.ResultUnwillingToPerform ||
		search.DiagnosticMessage !=
			"copy not used; no referral information available" {
		t.Fatalf("shadow search without referral = %#v", search)
	}
}
