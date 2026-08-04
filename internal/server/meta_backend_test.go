package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const metaBackendTestDatabaseDN = "olcDatabase={1}meta,cn=config"

func TestMetaBackendLoadAndLongestSuffixRoute(t *testing.T) {
	parent := metaBackendTestParent()
	parent.Attributes = append(parent.Attributes,
		directory.Attribute{
			Description: "olcDbNetworkTimeout",
			Values:      stringValues("3s"),
		},
		directory.Attribute{
			Description: "olcDbNretries",
			Values:      stringValues("1"),
		},
	)
	broad := metaBackendTestTarget(
		"{0}uri",
		`"ldap://127.0.0.1:1/dc=meta,dc=test" ldap://127.0.0.1:1389/`,
		`suffixmassage "dc=meta,dc=test" "dc=example,dc=com"`,
	)
	broad.Attributes = append(broad.Attributes,
		directory.Attribute{
			Description: "olcDbIDAssertBind",
			Values: stringValues(
				`bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none`,
			),
		},
		directory.Attribute{
			Description: "olcDbIDAssertAuthzFrom",
			Values:      stringValues("*"),
		},
	)
	specific := metaBackendTestTarget(
		"{1}uri",
		"ldap://127.0.0.1:2389/ou=team,dc=meta,dc=test",
		`suffixmassage "ou=team,dc=meta,dc=test" "ou=people,dc=example,dc=com"`,
	)

	configuration, err := loadMetaBackendTestConfiguration(parent, specific, broad)
	if err != nil {
		t.Fatalf("loadMetaBackendRuntimeConfiguration(): %v", err)
	}
	if configuration.configDNKey != strings.ToLower(metaBackendTestDatabaseDN) {
		t.Fatalf("config DN key = %q", configuration.configDNKey)
	}
	if configuration.defaultTarget != metaBackendNoDefaultTarget {
		t.Fatalf("default target = %d, want none", configuration.defaultTarget)
	}
	if len(configuration.suffixes) != 1 || len(configuration.targets) != 2 {
		t.Fatalf(
			"loaded suffixes/targets = %d/%d, want 1/2",
			len(configuration.suffixes),
			len(configuration.targets),
		)
	}
	if configuration.targets[0].order != 0 || configuration.targets[1].order != 1 {
		t.Fatalf("target order = %d, %d", configuration.targets[0].order, configuration.targets[1].order)
	}
	if configuration.targets[0].scope != directory.ScopeWholeSubtree {
		t.Fatalf("broad target scope = %d", configuration.targets[0].scope)
	}
	remotes := configuration.targets[0].ldapBackend.remotes
	if len(remotes) != 2 {
		t.Fatalf("broad target remotes = %d, want 2", len(remotes))
	}
	if remotes[0].uri != "ldap://127.0.0.1:1" ||
		remotes[1].uri != "ldap://127.0.0.1:1389" {
		t.Fatalf("ordered target remotes = %q, %q", remotes[0].uri, remotes[1].uri)
	}
	for index := range remotes {
		if remotes[index].bind.networkTimeout != 3*time.Second {
			t.Fatalf("remote %d network timeout = %s", index, remotes[index].bind.networkTimeout)
		}
		if string(remotes[index].bind.credentials) != "secret" {
			t.Fatalf("remote %d credentials were not inherited from the target", index)
		}
	}

	broadDN := mustMetaBackendDN(t, "uid=route-one,ou=people,dc=meta,dc=test")
	broadTarget, ok := configuration.targetForDN(broadDN)
	if !ok || broadTarget.order != 0 {
		t.Fatalf("broad route = %#v, %t", broadTarget, ok)
	}
	broadRemote, err := broadTarget.mapDNToRemote(broadDN)
	if err != nil {
		t.Fatalf("map broad DN to remote: %v", err)
	}
	if broadRemote.Key() != "uid=route-one,ou=people,dc=example,dc=com" {
		t.Fatalf("mapped broad DN = %q", broadRemote.String())
	}
	broadLocal, err := broadTarget.mapDNToLocal(broadRemote)
	if err != nil || !broadLocal.Equal(broadDN) {
		t.Fatalf("map broad DN to local = %q, %v", broadLocal.String(), err)
	}

	specificDN := mustMetaBackendDN(t, "uid=route-two,ou=team,dc=meta,dc=test")
	specificTarget, ok := configuration.targetForDN(specificDN)
	if !ok || specificTarget.order != 1 {
		t.Fatalf("specific route = %#v, %t", specificTarget, ok)
	}
	specificRemote, err := specificTarget.mapDNToRemote(specificDN)
	if err != nil {
		t.Fatalf("map specific DN to remote: %v", err)
	}
	if specificRemote.Key() != "uid=route-two,ou=people,dc=example,dc=com" {
		t.Fatalf("mapped specific DN = %q", specificRemote.String())
	}
	if _, ok := configuration.targetForDN(mustMetaBackendDN(t, "dc=outside,dc=test")); ok {
		t.Fatal("DN outside every target unexpectedly routed")
	}
}

func TestMetaBackendOnErrorConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		want    string
		wantErr string
	}{
		{name: "default", want: "continue"},
		{name: "continue", values: []string{"continue"}, want: "continue"},
		{name: "report case insensitive", values: []string{"REPORT"}, want: "report"},
		{name: "stop", values: []string{"stop"}, want: "stop"},
		{name: "invalid", values: []string{"ignore"}, wantErr: "invalid value"},
		{name: "multiple", values: []string{"continue", "stop"}, wantErr: "single-valued"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parent := metaBackendTestParent()
			if len(test.values) > 0 {
				parent.Attributes = append(parent.Attributes, directory.Attribute{
					Description: "olcDbOnErr",
					Values:      stringValues(test.values...),
				})
			}
			target := metaBackendTestTarget(
				"{0}uri",
				"ldap://127.0.0.1:1389/dc=meta,dc=test",
				"",
			)
			configuration, err := loadMetaBackendTestConfiguration(parent, target)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("load configuration: %v", err)
			}
			if configuration.onError != test.want {
				t.Fatalf("onError = %q, want %q", configuration.onError, test.want)
			}
		})
	}
}

func TestMetaBackendDNCacheConfiguration(t *testing.T) {
	tests := []struct {
		value   string
		want    time.Duration
		wantErr string
	}{
		{value: "disabled", want: 0},
		{value: "forever", want: -1},
		{value: "1h30m", want: 90 * time.Minute},
		{value: "later", wantErr: "invalid time interval"},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			parent := metaBackendEntryWithReplacement(
				metaBackendTestParent(),
				"olcDbDnCacheTtl",
				test.value,
			)
			target := metaBackendTestTarget(
				"{0}uri",
				"ldap://127.0.0.1:1389/dc=meta,dc=test",
				"",
			)
			configuration, err := loadMetaBackendTestConfiguration(parent, target)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("load configuration: %v", err)
			}
			if configuration.dnCacheTTL != test.want {
				t.Fatalf("dnCacheTTL = %s, want %s", configuration.dnCacheTTL, test.want)
			}
		})
	}

	target := metaBackendEntryWithReplacement(
		metaBackendTestTarget(
			"{0}uri",
			"ldap://127.0.0.1:1389/dc=meta,dc=test",
			"",
		),
		"olcDbDnCacheTtl",
		"1m",
	)
	_, err := loadMetaBackendTestConfiguration(metaBackendTestParent(), target)
	if err == nil || !strings.Contains(err.Error(), "belongs on the meta parent") {
		t.Fatalf("target olcDbDnCacheTtl error = %v", err)
	}
}

func TestMetaBackendTargetQuarantine(t *testing.T) {
	now := time.Unix(100, 0)
	target := metaBackendTargetRuntimeConfiguration{
		health: &pbindQuarantineState{now: func() time.Time { return now }},
		ldapBackend: &ldapBackendRuntimeConfiguration{remotes: []chainRemoteConfiguration{{
			quarantine: []syncConsumerRetry{{interval: time.Second, attempts: 1}},
		}}},
	}
	if !target.beginAttempt() {
		t.Fatal("initial target attempt was quarantined")
	}
	target.finishAttempt(ldapwire.ResultUnavailable)
	if target.beginAttempt() {
		t.Fatal("target attempt was allowed before quarantine interval")
	}
	now = now.Add(time.Second)
	if !target.beginAttempt() {
		t.Fatal("quarantine probe was not allowed")
	}
	if target.beginAttempt() {
		t.Fatal("concurrent quarantine probe was allowed")
	}
	target.finishAttempt(ldapwire.ResultSuccess)
	if !target.beginAttempt() {
		t.Fatal("successful probe did not clear quarantine")
	}
}

func TestMetaBackendSameSuffixOrderingAndDefaultTarget(t *testing.T) {
	first := metaBackendTestTarget(
		"{0}uri",
		"ldap://127.0.0.1:1389/dc=meta,dc=test",
		"",
	)
	second := metaBackendTestTarget(
		"{1}uri",
		"ldap://127.0.0.1:2389/dc=meta,dc=test",
		"",
	)
	dn := mustMetaBackendDN(t, "uid=user,dc=meta,dc=test")

	configuration, err := loadMetaBackendTestConfiguration(
		metaBackendTestParent(),
		second,
		first,
	)
	if err != nil {
		t.Fatalf("load ordered targets: %v", err)
	}
	targets := configuration.targetsForDN(dn)
	if len(targets) != 2 || targets[0].order != 0 || targets[1].order != 1 {
		t.Fatalf("ordered same-suffix targets = %#v", metaBackendTargetOrders(targets))
	}
	identityDN, err := targets[0].mapDNToRemote(dn)
	if err != nil || !identityDN.Equal(dn) || targets[0].rwm == nil {
		t.Fatalf("target without suffixmassage is not an identity mapping: %q, %v", identityDN.String(), err)
	}

	parent := metaBackendTestParent()
	parent.Attributes = append(parent.Attributes, directory.Attribute{
		Description: "olcDbDefaultTarget",
		Values:      stringValues("1"),
	})
	configuration, err = loadMetaBackendTestConfiguration(parent, second, first)
	if err != nil {
		t.Fatalf("load default target: %v", err)
	}
	targets = configuration.targetsForDN(dn)
	if len(targets) != 2 || targets[0].order != 1 || targets[1].order != 0 {
		t.Fatalf("default-first same-suffix targets = %#v", metaBackendTargetOrders(targets))
	}
}

func TestMetaBackendURLScope(t *testing.T) {
	suffix, scope, endpoints, err := parseMetaBackendURIs(
		"olcMetaSub={0}uri,"+metaBackendTestDatabaseDN,
		`"ldap://127.0.0.1:1389/ou=team,dc=meta,dc=test??subordinate" ldap://127.0.0.1:2389/`,
	)
	if err != nil {
		t.Fatalf("parse subordinate target URL: %v", err)
	}
	if suffix.Key() != "ou=team,dc=meta,dc=test" || scope != directory.ScopeChildren {
		t.Fatalf("parsed suffix/scope = %q/%d", suffix.String(), scope)
	}
	if len(endpoints) != 2 || endpoints[0] != "ldap://127.0.0.1:1389" ||
		endpoints[1] != "ldap://127.0.0.1:2389" {
		t.Fatalf("parsed endpoints = %#v", endpoints)
	}
}

func TestMetaBackendChildrenTargetExcludesItsBase(t *testing.T) {
	configuration := &metaBackendRuntimeConfiguration{
		targets: []metaBackendTargetRuntimeConfiguration{
			{
				configDNKey: "broad",
				suffix:      mustMetaBackendDN(t, "dc=meta,dc=test"),
				scope:       directory.ScopeWholeSubtree,
			},
			{
				configDNKey: "children",
				suffix:      mustMetaBackendDN(t, "ou=team,dc=meta,dc=test"),
				scope:       directory.ScopeChildren,
			},
		},
		defaultTarget: metaBackendNoDefaultTarget,
	}
	base, ok := configuration.targetForDN(mustMetaBackendDN(
		t,
		"ou=team,dc=meta,dc=test",
	))
	if !ok || base.configDNKey != "broad" {
		t.Fatalf("children target base route = %#v, %t", base, ok)
	}
	child, ok := configuration.targetForDN(mustMetaBackendDN(
		t,
		"uid=user,ou=team,dc=meta,dc=test",
	))
	if !ok || child.configDNKey != "children" {
		t.Fatalf("children target descendant route = %#v, %t", child, ok)
	}
}

func TestMetaBackendSubtreeAndFilterCandidateRules(t *testing.T) {
	target := metaBackendTestTarget(
		"{0}uri",
		"ldap://127.0.0.1:1389/dc=meta,dc=test",
		`suffixmassage "dc=meta,dc=test" "dc=example,dc=com"`,
	)
	target.Attributes = append(target.Attributes,
		directory.Attribute{
			Description: "olcDbSubtreeInclude",
			Values: stringValues(
				"{0}dn.subtree:ou=allowed,dc=meta,dc=test",
				"{1}dn.regex:^uid=regex,.*dc=meta,dc=test$",
			),
		},
		directory.Attribute{
			Description: "olcDbFilter",
			Values:      stringValues(`{0}^\(uid=`),
		},
		directory.Attribute{
			Description: "olcDbMap",
			Values: stringValues(
				"{0}attribute member uniqueMember",
				"{1}objectClass groupOfNames groupOfUniqueNames",
			),
		},
	)
	configuration, err := loadMetaBackendTestConfiguration(
		metaBackendTestParent(),
		target,
	)
	if err != nil {
		t.Fatalf("load target candidate rules: %v", err)
	}
	loaded := configuration.targets[0]
	if !loaded.matchesDN(
		mustMetaBackendDN(t, "uid=user,ou=allowed,dc=meta,dc=test"),
		directory.ScopeBase,
	) || !loaded.matchesDN(
		mustMetaBackendDN(t, "uid=regex,ou=other,dc=meta,dc=test"),
		directory.ScopeBase,
	) || loaded.matchesDN(
		mustMetaBackendDN(t, "uid=other,ou=other,dc=meta,dc=test"),
		directory.ScopeBase,
	) {
		t.Fatalf("subtree include rules = %#v", loaded.subtrees)
	}
	if !loaded.matchesFilter("(uid=user)") || loaded.matchesFilter("(cn=user)") {
		t.Fatalf("filter candidate rules = %#v", loaded.filters)
	}
	if got := loaded.rwm.mapAttributeDescription("member", true); got != "uniqueMember" ||
		loaded.rwm.mapAttributeDescription("uniqueMember", false) != "member" ||
		loaded.rwm.mapObjectClass("groupOfNames", true) != "groupOfUniqueNames" {
		t.Fatalf("olcDbMap runtime = %#v, mapped attribute %q", loaded.rwm, got)
	}
}

func TestMetaBackendConfigurationValidation(t *testing.T) {
	validTarget := func() directory.Entry {
		return metaBackendTestTarget(
			"{0}uri",
			"ldap://127.0.0.1:1389/dc=meta,dc=test",
			`suffixmassage "dc=meta,dc=test" "dc=example,dc=com"`,
		)
	}
	tests := []struct {
		name     string
		parent   directory.Entry
		children []directory.Entry
		contains string
	}{
		{
			name: "wrong backend",
			parent: metaBackendEntryWithReplacement(
				metaBackendTestParent(),
				"olcDatabase",
				"{1}ldap",
			),
			children: []directory.Entry{validTarget()},
			contains: "must use the meta backend",
		},
		{
			name: "missing suffix",
			parent: metaBackendEntryWithout(
				metaBackendTestParent(),
				"olcSuffix",
			),
			children: []directory.Entry{validTarget()},
			contains: "requires olcSuffix",
		},
		{
			name: "URI on parent",
			parent: metaBackendEntryWithReplacement(
				metaBackendTestParent(),
				"olcDbURI",
				"ldap://127.0.0.1:1389/dc=meta,dc=test",
			),
			children: []directory.Entry{validTarget()},
			contains: "must configure olcDbURI on olcMetaSub targets",
		},
		{
			name:     "missing target URI",
			parent:   metaBackendTestParent(),
			children: []directory.Entry{metaBackendEntryWithout(validTarget(), "olcDbURI")},
			contains: "olcDbURI must be single-valued",
		},
		{
			name:   "first URI has no DN",
			parent: metaBackendTestParent(),
			children: []directory.Entry{metaBackendEntryWithReplacement(
				validTarget(),
				"olcDbURI",
				"ldap://127.0.0.1:1389/",
			)},
			contains: "requires a target DN",
		},
		{
			name:   "second URI has a DN",
			parent: metaBackendTestParent(),
			children: []directory.Entry{metaBackendEntryWithReplacement(
				validTarget(),
				"olcDbURI",
				"ldap://127.0.0.1:1389/dc=meta,dc=test ldap://127.0.0.1:2389/dc=other",
			)},
			contains: "must not contain a target DN",
		},
		{
			name:   "duplicate target endpoint",
			parent: metaBackendTestParent(),
			children: []directory.Entry{metaBackendEntryWithReplacement(
				validTarget(),
				"olcDbURI",
				"ldap://127.0.0.1:1389/dc=meta,dc=test ldap://127.0.0.1:1389/",
			)},
			contains: "duplicates endpoint",
		},
		{
			name:   "unsupported URI scheme",
			parent: metaBackendTestParent(),
			children: []directory.Entry{metaBackendEntryWithReplacement(
				validTarget(),
				"olcDbURI",
				"http://127.0.0.1:1389/dc=meta,dc=test",
			)},
			contains: "unsupported LDAP URL scheme",
		},
		{
			name:   "unsupported URI scope",
			parent: metaBackendTestParent(),
			children: []directory.Entry{metaBackendEntryWithReplacement(
				validTarget(),
				"olcDbURI",
				"ldap://127.0.0.1:1389/dc=meta,dc=test??base",
			)},
			contains: "unsupported target scope",
		},
		{
			name:   "target outside database suffix",
			parent: metaBackendTestParent(),
			children: []directory.Entry{metaBackendEntryWithReplacement(
				validTarget(),
				"olcDbURI",
				"ldap://127.0.0.1:1389/dc=outside,dc=test",
			)},
			contains: "outside the meta database naming contexts",
		},
		{
			name:   "target RDN mismatch",
			parent: metaBackendTestParent(),
			children: []directory.Entry{metaBackendEntryWithReplacement(
				validTarget(),
				"olcMetaSub",
				"{1}uri",
			)},
			contains: "RDN must match",
		},
		{
			name:   "duplicate target order",
			parent: metaBackendTestParent(),
			children: []directory.Entry{
				validTarget(),
				metaBackendTestTarget(
					"{00}uri",
					"ldap://127.0.0.1:2389/dc=meta,dc=test",
					"",
				),
			},
			contains: "duplicate olcMetaSub order",
		},
		{
			name: "invalid default target",
			parent: metaBackendEntryWithReplacement(
				metaBackendTestParent(),
				"olcDbDefaultTarget",
				"4",
			),
			children: []directory.Entry{validTarget()},
			contains: "invalid target index",
		},
		{
			name:   "default on child",
			parent: metaBackendTestParent(),
			children: []directory.Entry{metaBackendEntryWithReplacement(
				validTarget(),
				"olcDbDefaultTarget",
				"0",
			)},
			contains: "belongs on the meta parent",
		},
		{
			name:   "multiple suffixmassage directives",
			parent: metaBackendTestParent(),
			children: []directory.Entry{metaBackendEntryWithValues(
				validTarget(),
				"olcDbRewrite",
				`suffixmassage "dc=meta,dc=test" "dc=example,dc=com"`,
				`suffixmassage "dc=meta,dc=test" "dc=second,dc=com"`,
			)},
			contains: "multiple suffixmassage directives",
		},
		{
			name:   "rewrite local suffix outside database",
			parent: metaBackendTestParent(),
			children: []directory.Entry{metaBackendEntryWithReplacement(
				validTarget(),
				"olcDbRewrite",
				`suffixmassage "dc=outside,dc=test" "dc=example,dc=com"`,
			)},
			contains: "suffixmassage local DN",
		},
		{
			name:   "database ACL on target",
			parent: metaBackendTestParent(),
			children: []directory.Entry{metaBackendEntryWithReplacement(
				validTarget(),
				"olcAccess",
				"to * by * read",
			)},
			contains: "olcAccess is not supported",
		},
		{
			name: "invalid nretries",
			parent: metaBackendEntryWithReplacement(
				metaBackendTestParent(),
				"olcDbNretries",
				"again",
			),
			children: []directory.Entry{validTarget()},
			contains: "olcDbNretries has invalid value",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadMetaBackendTestConfiguration(test.parent, test.children...)
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("error = %v, want containing %q", err, test.contains)
			}
		})
	}
}

func TestMetaBackendAllowsZeroTargets(t *testing.T) {
	configuration, err := loadMetaBackendTestConfiguration(metaBackendTestParent())
	if err != nil {
		t.Fatalf("load zero-target meta backend: %v", err)
	}
	if len(configuration.targets) != 0 {
		t.Fatalf("zero-target meta backend targets = %#v", configuration.targets)
	}
	if configuration.defaultTarget != metaBackendNoDefaultTarget {
		t.Fatalf("zero-target default target = %d", configuration.defaultTarget)
	}
}

func TestMetaBackendConfigurationCloneIsDeep(t *testing.T) {
	parent := metaBackendTestParent()
	target := metaBackendTestTarget(
		"{0}uri",
		"ldap://127.0.0.1:1389/dc=meta,dc=test",
		`suffixmassage "dc=meta,dc=test" "dc=example,dc=com"`,
	)
	target.Attributes = append(target.Attributes,
		directory.Attribute{
			Description: "olcDbIDAssertBind",
			Values: stringValues(
				`bindmethod=simple binddn="cn=admin,dc=example,dc=com" credentials=secret mode=none`,
			),
		},
		directory.Attribute{
			Description: "olcDbIDAssertAuthzFrom",
			Values:      stringValues("*"),
		},
	)
	configuration, err := loadMetaBackendTestConfiguration(parent, target)
	if err != nil {
		t.Fatalf("load configuration: %v", err)
	}
	clone := configuration.clone()
	clone.configDNKey = "changed"
	clone.suffixes[0] = mustMetaBackendDN(t, "dc=changed")
	clone.targets[0].configDNKey = "changed-target"
	clone.targets[0].ldapBackend.remotes[0].uri = "ldap://changed.invalid"
	clone.targets[0].ldapBackend.remotes[0].bind.credentials[0] = 'X'
	clone.targets[0].ldapBackend.remotes[0].identity.authzFrom[0] = "dn:*"
	clone.targets[0].ldapBackend.remotes[0].operationTimeouts[999] = time.Second
	clone.targets[0].rwm.attributesToRemote["uid"] = "cn"
	clone.targets[0].rwm.suffix = &rwmSuffixMapping{
		local:  mustMetaBackendDN(t, "dc=changed"),
		remote: mustMetaBackendDN(t, "dc=remote"),
	}

	original := configuration.targets[0]
	if configuration.configDNKey == "changed" || configuration.suffixes[0].Key() == "dc=changed" ||
		original.configDNKey == "changed-target" ||
		original.ldapBackend.remotes[0].uri == "ldap://changed.invalid" ||
		string(original.ldapBackend.remotes[0].bind.credentials) != "secret" ||
		original.ldapBackend.remotes[0].identity.authzFrom[0] != "*" ||
		len(original.ldapBackend.remotes[0].operationTimeouts) != 0 ||
		len(original.rwm.attributesToRemote) != 0 ||
		original.rwm.suffix.local.Key() != "dc=meta,dc=test" {
		t.Fatalf("mutating clone changed original: %#v", original)
	}

	routed := configuration.targetsForDN(mustMetaBackendDN(t, "uid=user,dc=meta,dc=test"))
	routed[0].ldapBackend.remotes[0].bind.credentials[0] = 'Y'
	if string(configuration.targets[0].ldapBackend.remotes[0].bind.credentials) != "secret" {
		t.Fatal("targetsForDN exposed mutable runtime state")
	}
}

func TestMetaBackendOnlineURIModificationDisablesExistingTarget(t *testing.T) {
	configuration, err := loadMetaBackendTestConfiguration(
		metaBackendTestParent(),
		metaBackendTestTarget(
			"{0}uri",
			"ldap://127.0.0.1:1389/dc=meta,dc=test",
			"",
		),
	)
	if err != nil {
		t.Fatalf("load configuration: %v", err)
	}
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("build schema registry: %v", err)
	}
	targetDN := mustMetaBackendDN(t, configuration.targets[0].configDNKey)

	for _, test := range []struct {
		name        string
		description string
		value       string
	}{
		{
			name:        "same value replace",
			description: "olcDbURI",
			value:       "ldap://127.0.0.1:1389/dc=meta,dc=test",
		},
		{
			name:        "different value replace by OID",
			description: "1.3.6.1.4.1.4203.1.12.2.3.2.0.14",
			value:       "ldap://127.0.0.1:2389/dc=meta,dc=test",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			next := &runtimeState{
				schema: registry,
				databases: []runtimeDatabase{{
					configDNKey: configuration.configDNKey,
					metaBackend: configuration.clone(),
				}},
			}
			applyMetaBackendOnlineURIModification(
				next,
				targetDN,
				[]ldapwire.Modification{{
					Operation: ldapwire.ModificationReplace,
					Attribute: directory.Attribute{
						Description: test.description,
						Values:      stringValues(test.value),
					},
				}},
			)
			target := &next.databases[0].metaBackend.targets[0]
			if !target.onlineURIUnavailable {
				t.Fatal("online URI modification left target selectable")
			}
			if _, found := next.databases[0].metaBackend.targetForDN(
				mustMetaBackendDN(t, "uid=user,dc=meta,dc=test"),
			); found {
				t.Fatal("online URI modification target was routed")
			}
		})
	}

	reloaded, err := loadMetaBackendTestConfiguration(
		metaBackendTestParent(),
		metaBackendTestTarget(
			"{0}uri",
			"ldap://127.0.0.1:2389/dc=meta,dc=test",
			"",
		),
	)
	if err != nil {
		t.Fatalf("reload persisted configuration: %v", err)
	}
	if reloaded.targets[0].onlineURIUnavailable {
		t.Fatal("freshly loaded persisted target is unavailable")
	}
}

func TestMetaBackendOnlineStatePreservesTargetsWithoutURIChanges(t *testing.T) {
	configuration, err := loadMetaBackendTestConfiguration(
		metaBackendTestParent(),
		metaBackendTestTarget(
			"{0}uri",
			"ldap://127.0.0.1:1389/dc=meta,dc=test",
			"",
		),
	)
	if err != nil {
		t.Fatalf("load configuration: %v", err)
	}
	previous := &runtimeState{databases: []runtimeDatabase{{
		configDNKey: configuration.configDNKey,
		metaBackend: configuration,
	}}}
	next := &runtimeState{databases: []runtimeDatabase{{
		configDNKey: configuration.configDNKey,
		metaBackend: configuration.clone(),
	}}}
	applyMetaBackendOnlineConfigurationState(previous, next)
	if next.databases[0].metaBackend.targets[0].onlineURIUnavailable {
		t.Fatal("unchanged target became unavailable")
	}
	changedConfiguration, err := loadMetaBackendTestConfiguration(
		metaBackendTestParent(),
		metaBackendTestTarget(
			"{0}uri",
			"ldap://127.0.0.1:2389/dc=meta,dc=test",
			"",
		),
	)
	if err != nil {
		t.Fatalf("load changed persisted configuration: %v", err)
	}
	next = &runtimeState{databases: []runtimeDatabase{{
		configDNKey: changedConfiguration.configDNKey,
		metaBackend: changedConfiguration,
	}}}
	applyMetaBackendOnlineConfigurationState(previous, next)
	if next.databases[0].metaBackend.targets[0].onlineURIUnavailable {
		t.Fatal("runtime reload inferred an online URI modification from final values")
	}

	previous.databases[0].metaBackend.targets[0].onlineURIUnavailable = true
	next = &runtimeState{databases: []runtimeDatabase{{
		configDNKey: configuration.configDNKey,
		metaBackend: configuration.clone(),
	}}}
	applyMetaBackendOnlineConfigurationState(previous, next)
	if !next.databases[0].metaBackend.targets[0].onlineURIUnavailable {
		t.Fatal("unavailable target state was not preserved")
	}

	added := configuration.clone()
	added.targets[0].configDNKey = "olcmetasub={1}uri," + configuration.configDNKey
	added.targets[0].onlineURIUnavailable = false
	next = &runtimeState{databases: []runtimeDatabase{{
		configDNKey: configuration.configDNKey,
		metaBackend: added,
	}}}
	applyMetaBackendOnlineConfigurationState(previous, next)
	if next.databases[0].metaBackend.targets[0].onlineURIUnavailable {
		t.Fatal("newly added target inherited unavailable state")
	}
}

func TestMetaBackendOnlineOtherAttributeModificationDoesNotDisableTarget(t *testing.T) {
	configuration, err := loadMetaBackendTestConfiguration(
		metaBackendTestParent(),
		metaBackendTestTarget(
			"{0}uri",
			"ldap://127.0.0.1:1389/dc=meta,dc=test",
			"",
		),
	)
	if err != nil {
		t.Fatalf("load configuration: %v", err)
	}
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("build schema registry: %v", err)
	}
	runtime := &runtimeState{
		schema: registry,
		databases: []runtimeDatabase{{
			configDNKey: configuration.configDNKey,
			metaBackend: configuration,
		}},
	}
	applyMetaBackendOnlineURIModification(
		runtime,
		mustMetaBackendDN(t, configuration.targets[0].configDNKey),
		[]ldapwire.Modification{{
			Operation: ldapwire.ModificationReplace,
			Attribute: directory.Attribute{
				Description: "olcDbNetworkTimeout",
				Values:      stringValues("5s"),
			},
		}},
	)
	if runtime.databases[0].metaBackend.targets[0].onlineURIUnavailable {
		t.Fatal("unrelated target attribute modification disabled URI routing")
	}
}

func metaBackendTestParent() directory.Entry {
	return directory.Entry{
		DN: metaBackendTestDatabaseDN,
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values:      stringValues("olcDatabaseConfig", "olcMetaConfig"),
			},
			{Description: "olcDatabase", Values: stringValues("{1}meta")},
			{Description: "olcSuffix", Values: stringValues("dc=meta,dc=test")},
		},
	}
}

func metaBackendTestTarget(marker string, uri string, rewrite string) directory.Entry {
	entry := directory.Entry{
		DN: "olcMetaSub=" + marker + "," + metaBackendTestDatabaseDN,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcMetaTargetConfig")},
			{Description: "olcMetaSub", Values: stringValues(marker)},
			{Description: "olcDbURI", Values: stringValues(uri)},
		},
	}
	if rewrite != "" {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "olcDbRewrite",
			Values:      stringValues(rewrite),
		})
	}
	return entry
}

func loadMetaBackendTestConfiguration(
	parent directory.Entry,
	children ...directory.Entry,
) (*metaBackendRuntimeConfiguration, error) {
	store := storage.NewMemory()
	defer store.Close()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		if err := writer.Put(parent, false); err != nil {
			return err
		}
		for _, child := range children {
			if err := writer.Put(child, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	var configuration *metaBackendRuntimeConfiguration
	err := store.View(context.Background(), func(reader storage.Reader) error {
		var loadErr error
		configuration, loadErr = loadMetaBackendRuntimeConfiguration(reader, parent)
		return loadErr
	})
	return configuration, err
}

func metaBackendEntryWithReplacement(
	entry directory.Entry,
	description string,
	value string,
) directory.Entry {
	entry = entry.Clone()
	entry.ReplaceValues(description, stringValues(value))
	return entry
}

func metaBackendEntryWithValues(
	entry directory.Entry,
	description string,
	values ...string,
) directory.Entry {
	entry = entry.Clone()
	entry.ReplaceValues(description, stringValues(values...))
	return entry
}

func metaBackendEntryWithout(entry directory.Entry, description string) directory.Entry {
	return entry.Without(description)
}

func mustMetaBackendDN(t *testing.T, value string) directory.DN {
	t.Helper()
	dn, err := directory.ParseDN(value)
	if err != nil {
		t.Fatalf("parse DN %q: %v", value, err)
	}
	return dn
}

func metaBackendTargetOrders(targets []metaBackendTargetRuntimeConfiguration) []int {
	orders := make([]int, len(targets))
	for index := range targets {
		orders[index] = targets[index].order
	}
	return orders
}
