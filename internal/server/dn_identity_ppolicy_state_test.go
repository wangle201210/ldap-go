package server

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	dnIdentityPPolicyStateExactOID = "1.3.6.1.4.1.99999.979.1"
	dnIdentityPPolicyStateFoldOID  = "1.3.6.1.4.1.99999.979.2"
	dnIdentityPPolicyStateSuffix   = "ppolicyStateExactName=Tenant,dc=example,dc=com"
	dnIdentityPPolicyStateUpperDN  = "ppolicyStateExactName=Alice+" +
		"ppolicyStateFoldName=Primary Team,ou=people," +
		dnIdentityPPolicyStateSuffix
	dnIdentityPPolicyStateLowerDN = "ppolicyStateExactName=alice+" +
		"ppolicyStateFoldName=Primary Team,ou=people," +
		dnIdentityPPolicyStateSuffix
	dnIdentityPPolicyStateUpperPolicyDN = "ppolicyStateExactName=Policy+" +
		"ppolicyStateFoldName=Default Team,ou=policies," +
		dnIdentityPPolicyStateSuffix
	dnIdentityPPolicyStateLowerPolicyDN = "ppolicyStateExactName=policy+" +
		"ppolicyStateFoldName=Default Team,ou=policies," +
		dnIdentityPPolicyStateSuffix
)

const (
	dnIdentityPPolicyStateEquivalentUpperDN = dnIdentityPPolicyStateFoldOID +
		"=PRIMARY TEAM+ppolicyStateExactAlias=Alice,OU=PEOPLE," +
		"ppolicyStateExactAlias=Tenant,DC=EXAMPLE,DC=COM"
	dnIdentityPPolicyStateEquivalentLowerDN = "ppolicyStateFoldAlias=primary team+" +
		dnIdentityPPolicyStateExactOID + "=alice,OU=PEOPLE," +
		"ppolicyStateExactAlias=Tenant,DC=EXAMPLE,DC=COM"
	dnIdentityPPolicyStateEquivalentUpperPolicyDN = "ppolicyStateFoldAlias=DEFAULT TEAM+" +
		dnIdentityPPolicyStateExactOID + "=Policy,OU=POLICIES," +
		"ppolicyStateExactAlias=Tenant,DC=EXAMPLE,DC=COM"
)

type dnIdentityPPolicyStateFixture struct {
	store    storage.Store
	registry *schema.Registry
	database runtimeDatabase
	runtime  *runtimeState
	server   *Server
	now      time.Time
}

func TestDNIdentityPasswordPolicyState(t *testing.T) {
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
			t.Parallel()
			fixture := newDNIdentityPPolicyStateFixture(t, backend.open(t))
			testDNIdentityPPolicyState(t, fixture)
		})
	}
}

func testDNIdentityPPolicyState(
	t *testing.T,
	fixture *dnIdentityPPolicyStateFixture,
) {
	t.Helper()

	upper := fixture.entry(t, dnIdentityPPolicyStateEquivalentUpperDN)
	lower := fixture.entry(t, dnIdentityPPolicyStateEquivalentLowerDN)
	fixture.assertPolicy(t, upper, 12)
	fixture.assertPolicy(t, lower, 24)

	failed, err := fixture.server.authenticatePasswordBind(
		t.Context(),
		fixture.runtime,
		dnIdentityPPolicyStateEquivalentLowerDN,
		[]byte("upper-secret"),
		false,
	)
	if err != nil || failed.authenticated {
		t.Fatalf("caseExact sibling Bind = %#v, %v", failed, err)
	}
	fixture.assertState(t, dnIdentityPPolicyStateUpperDN, false, false)
	fixture.assertState(t, dnIdentityPPolicyStateLowerDN, true, false)

	successful, err := fixture.server.authenticatePasswordBind(
		t.Context(),
		fixture.runtime,
		dnIdentityPPolicyStateEquivalentUpperDN,
		[]byte("upper-secret"),
		true,
	)
	if err != nil || !successful.authenticated {
		t.Fatalf("schema-equivalent Bind = %#v, %v", successful, err)
	}
	if len(successful.controls) != 1 ||
		successful.controls[0].OID != passwordPolicyControlOID {
		t.Fatalf("password policy controls = %#v", successful.controls)
	}
	fixture.assertState(t, dnIdentityPPolicyStateUpperDN, false, true)
	fixture.assertState(t, dnIdentityPPolicyStateLowerDN, true, false)

	fixture.assertSelfPolicy(t, upper)
	fixture.assertRestrictionIdentity(t)
	fixture.assertForwardUpdateIdentity(t, upper)
	fixture.assertAccountUsability(t, upper)
}

func newDNIdentityPPolicyStateFixture(
	t *testing.T,
	store storage.Store,
) *dnIdentityPPolicyStateFixture {
	t.Helper()
	t.Cleanup(func() { _ = store.Close() })
	registry := dnIdentityPPolicyStateRegistry(t)
	suffix := dnIdentityPPolicyStateDN(t, registry, dnIdentityPPolicyStateSuffix)
	upperPolicyDN := dnIdentityPPolicyStateDN(
		t,
		registry,
		dnIdentityPPolicyStateUpperPolicyDN,
	)
	database := runtimeDatabase{
		name:              "{1}mdb",
		partition:         "dn-identity-ppolicy-state",
		suffixes:          []directory.DN{suffix},
		dnNormalizer:      registry,
		lastBind:          true,
		lastBindPrecision: 0,
		ppolicy: &passwordPolicyRuntimeConfiguration{
			defaultPolicy: &upperPolicyDN,
		},
	}
	runtime := &runtimeState{
		schema:    registry,
		access:    acl.DefaultPolicy(),
		databases: []runtimeDatabase{database},
	}
	now := time.Date(2026, time.August, 23, 12, 34, 56, 0, time.UTC)
	instance := &Server{
		config: Config{
			Store:  store,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		clock:       func() time.Time { return now },
		syncChanges: newSyncChangeHub(),
	}
	fixture := &dnIdentityPPolicyStateFixture{
		store:    store,
		registry: registry,
		database: database,
		runtime:  runtime,
		server:   instance,
		now:      now,
	}
	fixture.seed(t)
	return fixture
}

func (fixture *dnIdentityPPolicyStateFixture) seed(t *testing.T) {
	t.Helper()
	entries := []directory.Entry{
		fixture.policyEntry(dnIdentityPPolicyStateUpperPolicyDN, "Policy", "12"),
		fixture.policyEntry(dnIdentityPPolicyStateLowerPolicyDN, "policy", "24"),
		fixture.userEntry(
			dnIdentityPPolicyStateUpperDN,
			"Alice",
			"upper-secret",
			dnIdentityPPolicyStateEquivalentUpperPolicyDN,
		),
		fixture.userEntry(
			dnIdentityPPolicyStateLowerDN,
			"alice",
			"lower-secret",
			dnIdentityPPolicyStateLowerPolicyDN,
		),
	}
	if err := fixture.store.Update(t.Context(), func(writer storage.Writer) error {
		tx := writerForDatabase(writer, fixture.database)
		for _, entry := range entries {
			if err := tx.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed password policy state fixture: %v", err)
	}
}

func (fixture *dnIdentityPPolicyStateFixture) policyEntry(
	dn string,
	exactName string,
	minLength string,
) directory.Entry {
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("top", "device", "pwdPolicy")},
			{Description: "cn", Values: stringValues(exactName)},
			{Description: "ppolicyStateExactAlias", Values: stringValues(exactName)},
			{Description: dnIdentityPPolicyStateFoldOID, Values: stringValues("Default Team")},
			{Description: "pwdAttribute", Values: stringValues("userPassword")},
			{Description: "pwdMinLength", Values: stringValues(minLength)},
			{Description: "pwdMaxFailure", Values: stringValues("3")},
			{Description: "pwdMaxRecordedFailure", Values: stringValues("3")},
			{Description: "pwdAllowUserChange", Values: stringValues("FALSE")},
		},
	}
}

func (fixture *dnIdentityPPolicyStateFixture) userEntry(
	dn string,
	exactName string,
	password string,
	policyDN string,
) directory.Entry {
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("top", "person")},
			{Description: "cn", Values: stringValues(exactName)},
			{Description: "sn", Values: stringValues(exactName)},
			{Description: dnIdentityPPolicyStateExactOID, Values: stringValues(exactName)},
			{Description: "ppolicyStateFoldAlias", Values: stringValues("Primary Team")},
			{Description: "userPassword", Values: stringValues(password)},
			{Description: "pwdPolicySubentry", Values: stringValues(policyDN)},
		},
	}
}

func (fixture *dnIdentityPPolicyStateFixture) entry(
	t *testing.T,
	rawDN string,
) directory.Entry {
	t.Helper()
	dn := dnIdentityPPolicyStateDN(t, fixture.registry, rawDN)
	var entry directory.Entry
	if err := fixture.store.View(t.Context(), func(reader storage.Reader) error {
		var err error
		entry, err = readerForDatabase(reader, fixture.database).Get(dn)
		return err
	}); err != nil {
		t.Fatalf("read %q: %v", rawDN, err)
	}
	return entry
}

func (fixture *dnIdentityPPolicyStateFixture) assertPolicy(
	t *testing.T,
	entry directory.Entry,
	wantMinLength int,
) {
	t.Helper()
	if err := fixture.store.View(t.Context(), func(reader storage.Reader) error {
		policy, ok := loadPasswordPolicy(
			fixture.runtime,
			reader,
			fixture.database,
			entry,
		)
		if !ok || policy.minLength != wantMinLength {
			t.Fatalf("policy for %q = %#v, %t", entry.DN, policy, ok)
		}
		return nil
	}); err != nil {
		t.Fatalf("load policy for %q: %v", entry.DN, err)
	}
}

func (fixture *dnIdentityPPolicyStateFixture) assertState(
	t *testing.T,
	rawDN string,
	wantFailure bool,
	wantLastBind bool,
) {
	t.Helper()
	entry := fixture.entry(t, rawDN)
	if got := entry.HasAttribute("pwdFailureTime"); got != wantFailure {
		t.Fatalf("%s pwdFailureTime present = %t, want %t", rawDN, got, wantFailure)
	}
	values := entry.Values("pwdLastSuccess")
	if got := len(values) == 1; got != wantLastBind {
		t.Fatalf("%s pwdLastSuccess = %q, want present %t", rawDN, values, wantLastBind)
	}
	if wantLastBind && string(values[0]) != formatPasswordPolicyTime(fixture.now) {
		t.Fatalf("%s pwdLastSuccess = %q", rawDN, values[0])
	}
}

func (fixture *dnIdentityPPolicyStateFixture) assertSelfPolicy(
	t *testing.T,
	upper directory.Entry,
) {
	t.Helper()
	changes := []ldapwire.Modification{{
		Operation: ldapwire.ModificationReplace,
		Attribute: directory.Attribute{
			Description: "userPassword",
			Values:      stringValues("replacement-password-long-enough"),
		},
	}}
	if err := fixture.store.View(t.Context(), func(reader storage.Reader) error {
		tx := readerForDatabase(reader, fixture.database)
		_, err := fixture.server.preparePasswordPolicyModification(
			fixture.runtime,
			tx,
			dnIdentityPPolicyStateEquivalentUpperDN,
			fixture.database,
			upper,
			changes,
			passwordPolicyModificationOptions{},
		)
		failure := asOperationFailure(err)
		if failure == nil || failure.result.Code != ldapwire.ResultInsufficientAccessRights {
			t.Fatalf("schema-equivalent self policy result = %#v, %v", failure, err)
		}

		_, err = fixture.server.preparePasswordPolicyModification(
			fixture.runtime,
			tx,
			dnIdentityPPolicyStateEquivalentLowerDN,
			fixture.database,
			upper,
			changes,
			passwordPolicyModificationOptions{},
		)
		if err != nil {
			t.Fatalf("caseExact sibling treated as self: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("self policy check: %v", err)
	}
}

func (fixture *dnIdentityPPolicyStateFixture) assertRestrictionIdentity(t *testing.T) {
	t.Helper()
	state := &connectionState{
		boundDN:                    dnIdentityPPolicyStateEquivalentLowerDN,
		passwordPolicyRestrictedDN: dnIdentityPPolicyStateUpperDN,
		runtime:                    fixture.runtime,
	}
	refreshPasswordPolicyRestriction(state)
	if state.passwordPolicyRestrictedDN != "" {
		t.Fatal("caseExact sibling retained another identity's restriction")
	}
	state.boundDN = dnIdentityPPolicyStateEquivalentUpperDN
	state.passwordPolicyRestrictedDN = dnIdentityPPolicyStateUpperDN
	refreshPasswordPolicyRestriction(state)
	if state.passwordPolicyRestrictedDN == "" {
		t.Fatal("schema-equivalent identity lost its password policy restriction")
	}
}

func (fixture *dnIdentityPPolicyStateFixture) assertForwardUpdateIdentity(
	t *testing.T,
	upper directory.Entry,
) {
	t.Helper()
	before := upper.Clone()
	before.DN = dnIdentityPPolicyStateEquivalentUpperDN
	after := upper.Clone()
	after.DN = dnIdentityPPolicyStateUpperDN
	after.ReplaceValues(
		"pwdFailureTime",
		stringValues(formatPasswordPolicyFailureTime(fixture.now)),
	)
	request, err := passwordPolicyForwardModifyRequest(
		fixture.runtime,
		fixture.database,
		before,
		after,
	)
	if err != nil {
		t.Fatalf("build schema-aware forward update: %v", err)
	}
	want := dnIdentityPPolicyStateDN(
		t,
		fixture.registry,
		dnIdentityPPolicyStateUpperDN,
	).String()
	if request.DN != want || len(request.Changes) != 1 ||
		request.Changes[0].Attribute.Description != "pwdFailureTime" {
		t.Fatalf("forward update = %#v, want target %q", request, want)
	}

	after.DN = dnIdentityPPolicyStateEquivalentLowerDN
	_, err = passwordPolicyForwardModifyRequest(
		fixture.runtime,
		fixture.database,
		before,
		after,
	)
	if err == nil {
		t.Fatal("forward update crossed caseExact identities")
	}
}

func (fixture *dnIdentityPPolicyStateFixture) assertAccountUsability(
	t *testing.T,
	upper directory.Entry,
) {
	t.Helper()
	selected := upper.Clone()
	selected.DN = dnIdentityPPolicyStateEquivalentUpperDN
	controls := fixture.server.passwordPolicySearchEntryControls(
		t.Context(),
		&connectionState{
			boundDN:                   dnIdentityPPolicyStateEquivalentUpperDN,
			runtime:                   fixture.runtime,
			accountUsabilityRequested: true,
		},
		selected,
	)
	if len(controls) != 1 || controls[0].OID != accountUsabilityControlOID ||
		!controls[0].HasValue {
		t.Fatalf("account usability controls = %#v", controls)
	}
}

func dnIdentityPPolicyStateRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	for _, definition := range []string{
		"( " + dnIdentityPPolicyStateExactOID +
			" NAME ( 'ppolicyStateExactName' 'ppolicyStateExactAlias' ) " +
			"EQUALITY caseExactMatch ORDERING caseExactOrderingMatch " +
			"SUBSTR caseExactSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
		"( " + dnIdentityPPolicyStateFoldOID +
			" NAME ( 'ppolicyStateFoldName' 'ppolicyStateFoldAlias' ) " +
			"EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
			"SUBSTR caseIgnoreSubstringsMatch SYNTAX " + schema.SyntaxDirectoryString + " )",
	} {
		if err := registry.ParseAndRegisterAttributeType(definition); err != nil {
			t.Fatalf("ParseAndRegisterAttributeType(%q): %v", definition, err)
		}
	}
	return registry
}

func dnIdentityPPolicyStateDN(
	t *testing.T,
	registry *schema.Registry,
	value string,
) directory.DN {
	t.Helper()
	dn, err := registry.NormalizeDN(value)
	if err != nil {
		t.Fatalf("NormalizeDN(%q): %v", value, err)
	}
	return dn
}

func TestDNIdentityPasswordPolicyStateRejectsInvalidReaderIdentity(t *testing.T) {
	t.Parallel()
	registry := dnIdentityPPolicyStateRegistry(t)
	database := runtimeDatabase{dnNormalizer: registry}
	runtime := &runtimeState{schema: registry}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.View(t.Context(), func(root storage.Reader) error {
		reader := storage.ReaderInPartitionWithNormalizer(
			root,
			"dn-identity-ppolicy-invalid",
			registry,
		)
		if !passwordPolicySameEntryDN(
			runtime,
			database,
			reader,
			dnIdentityPPolicyStateEquivalentUpperDN,
			dnIdentityPPolicyStateUpperDN,
		) {
			t.Fatal("reader normalizer rejected equivalent DN")
		}
		if passwordPolicySameEntryDN(
			runtime,
			database,
			reader,
			dnIdentityPPolicyStateEquivalentLowerDN,
			dnIdentityPPolicyStateUpperDN,
		) {
			t.Fatal("reader normalizer collapsed caseExact identities")
		}

		_, err := normalizePasswordPolicyDN(runtime, &database, reader, "not a dn")
		if err == nil {
			t.Fatal("invalid DN normalization unexpectedly succeeded")
		}
		return nil
	}); err != nil {
		t.Fatalf("reader identity view: %v", err)
	}
}
