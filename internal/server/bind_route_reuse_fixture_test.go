package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/wangle201210/ldap-go/internal/auth"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestBindRouteReuseRealFixture(t *testing.T) {
	seed := os.Getenv("LDAP_GO_BIND_ROUTE_FIXTURE")
	if seed == "" {
		t.Skip("set LDAP_GO_BIND_ROUTE_FIXTURE to a 100k CLI seed database path")
	}
	// New may migrate configuration and DN identities. Never open the seed with
	// Bolt; all initialization and the test-user write belong to this copy.
	source, err := os.Open(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	path := filepath.Join(t.TempDir(), "bind-route-fixture.db")
	destination, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	if err := errors.Join(copyErr, destination.Close()); err != nil {
		t.Fatal(err)
	}
	rawStore, err := storage.OpenBoltForServer(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := rawStore.Close(); err != nil {
			t.Error(err)
		}
	})
	const peopleDN = "ou=people,dc=scale,dc=qualification"
	const rootDN = "cn=admin,dc=scale,dc=qualification"
	const realUserDN = "uid=scale-001001," + peopleDN
	const testUID = "bind-route-reuse-fixture"
	const testUserDN = "uid=" + testUID + "," + peopleDN
	const password = "bind-route-fixture-known-password"
	instance, err := New(Config{
		Store: rawStore, RootDN: rootDN, RootPassword: []byte("dummyrootpassword"),
		MaxSearchEntries: 100100, MaxSearchCandidates: 100100,
		MaxSearchCandidateBytes: 819200000, MaxSearchMemoryBytes: 1638400000,
		// Schema and AccessPolicy stay nil, matching cmd/ldap-go runServe.
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := instance.runtime.Load()
	if runtime == nil || runtime.schema == nil || runtime.access == nil {
		t.Fatal("CLI runtime did not load schema and ACL policy")
	}
	store := instance.config.Store
	state := &connectionState{runtime: runtime, protocolVersion: 3}
	ctx := withACLSubject(t.Context(), instance.connectionACLSubject(state))
	requestFor := func(raw, supplied string) (ldapwire.Message, ldapwire.BindRequest) {
		request := ldapwire.BindRequest{Version: 3, Name: raw, Authentication: ldapwire.Authentication{Simple: []byte(supplied)}}
		return ldapwire.Message{ID: 1, Request: request}, request
	}
	logGuards := func(reader storage.Reader) {
		t.Helper()
		t.Logf("rawStore=%T store=%T reader=%T schema=%p currentRuntime=%t revision=%d plainRawBolt=%t plainStoreBolt=%t localProjection=%t features=%+v radius=%t",
			rawStore, store, reader, runtime.schema, instance.runtime.Load() == runtime, runtime.revision,
			plainBoltSearchStore(rawStore), plainBoltSearchStore(store), localProjectionReadOnly(runtime, reader), runtime.features, runtime.externalPasswords.radiusEnabled)
		for index := range runtime.databases {
			database := &runtime.databases[index]
			t.Logf("database[%d]=%s partition=%s normalizer=%T plain=%t localStorage=%t runtimeDNIdentity=%t suffixes=%d overlays=%v hidden=%t disabled=%t subordinate=%t shadow=%t relay=%t rwm=%t ppolicy=%t lastBind=%t lastBindOverlay=%t TOTP=%d",
				index, database.name, database.partition, database.dnNormalizer, simpleBindRouteDatabasePlain(database),
				databaseUsesLocalContentStorage(*database), databaseUsesRuntimeDNIdentity(*database, runtime.schema), len(database.suffixes), database.monitorOverlays,
				database.hidden, database.disabled, database.subordinate, database.shadow, database.relay != nil, database.rwm != nil,
				database.ppolicy != nil, database.lastBind, database.lastBindOverlay, len(database.totpPasswords))
		}
	}
	// Assert before inserting anything, without changing any runtime guard field.
	message, request := requestFor(realUserDN, password)
	logGuards(nil)
	if !instance.canReuseSimpleBindRoute(state, message, request) {
		t.Fatal("unmodified CLI fixture runtime is not eligible for Bind route reuse; see guard diagnostics")
	}
	proveRoute := func(raw string) (directory.DN, *runtimeDatabase) {
		t.Helper()
		dn, err := parseRuntimeConnectionDN(runtime, raw)
		if err != nil {
			t.Fatalf("handler DN %q: %v", raw, err)
		}
		database := databaseForDN(runtime, dn)
		if database == nil || !databaseUsesRuntimeDNIdentity(*database, runtime.schema) {
			t.Fatalf("handler DN %q did not select a standard local database", raw)
		}
		first, err := normalizePasswordPolicyDN(runtime, nil, nil, dn.String())
		if err != nil || first.Key() != dn.Key() || first.String() != dn.String() || databaseForDN(runtime, first) != database {
			t.Fatalf("first string normalization/routing differs for %q: %v", raw, err)
		}
		second, err := normalizePasswordPolicyDN(runtime, database, nil, dn.String())
		if err != nil || second.Key() != dn.Key() || second.String() != dn.String() {
			t.Fatalf("second string normalization differs for %q: %v", raw, err)
		}
		legacy, err := runtime.legacyDNs.parse(dn.String())
		if err != nil || isConfigurationDN(legacy) {
			t.Fatalf("rendered DN %q cannot use the content route: %v", raw, err)
		}
		if _, root := databaseAuthenticationRoot(runtime, *database, dn); root {
			t.Fatalf("fixture user %q unexpectedly uses root authentication", raw)
		}
		return dn, database
	}
	realDN, database := proveRoute(realUserDN)
	parentDN, err := parseRuntimeConnectionDN(runtime, peopleDN)
	if err != nil {
		t.Fatal(err)
	}
	var configBefore, realBefore directory.Entry
	if err := rawStore.View(ctx, func(reader storage.Reader) error {
		t.Logf("actual raw Bolt reader=%T", reader)
		var err error
		configBefore, err = reader.GetIn(configurationStoragePartition, configurationSuffix)
		return err
	}); err != nil {
		t.Fatalf("read actual cn=config: %v", err)
	}
	if err := store.View(ctx, func(reader storage.Reader) error {
		logGuards(reader)
		tx := readerForDatabase(reader, *database)
		t.Logf("actual partition reader=%T", tx)
		if !localProjectionReadOnly(runtime, reader) || !localProjectionReadOnly(runtime, tx) {
			return errors.New("actual reader stack fails local projection guard")
		}
		normalized, err := storage.NormalizeReaderDN(tx, realDN)
		if err != nil || normalized.Key() != realDN.Key() || normalized.String() != realDN.String() {
			return fmt.Errorf("actual reader DN normalization differs: %v", err)
		}
		if _, err := tx.Get(parentDN); err != nil {
			return err
		}
		realBefore, err = tx.Get(realDN)
		return err
	}); err != nil {
		t.Fatalf("read real fixture user %q: %v", realUserDN, err)
	}
	storedRealDN, err := parseRuntimeConnectionDN(runtime, realBefore.DN)
	if err != nil || storedRealDN.Key() != realDN.Key() {
		t.Fatalf("stored real-user identity differs: %v", err)
	}
	t.Logf("real configuration=%s attributes=%d; existing user=%s; route identity and database agree", configBefore.DN, len(configBefore.Attributes), realBefore.DN)

	testDN, testDatabase := proveRoute(testUserDN)
	if testDatabase != database {
		t.Fatal("test user must use the real user's database")
	}
	hash, err := auth.HashPassword([]byte(password), auth.OpenLDAPDefaultHashScheme, bytes.NewReader([]byte{1, 2, 3, 4}))
	if err != nil {
		t.Fatal(err)
	}
	entry := directory.Entry{DN: testUserDN, Attributes: []directory.Attribute{
		{Description: "objectClass", Values: stringValues("inetOrgPerson")},
		{Description: "uid", Values: stringValues(testUID)},
		{Description: "cn", Values: stringValues("Bind Route Fixture")},
		{Description: "sn", Values: stringValues("Fixture")},
		{Description: "userPassword", Values: [][]byte{hash}},
	}}
	if err := store.Update(ctx, func(writer storage.Writer) error {
		return writerForDatabase(writer, *database).Put(entry, false)
	}); err != nil {
		t.Fatalf("add test user to copy: %v", err)
	}
	if instance.runtime.Load() != runtime || instance.config.Store != store {
		t.Fatal("test-user insertion unexpectedly replaced the fixture runtime or store")
	}
	var testBefore directory.Entry
	if err := store.View(ctx, func(reader storage.Reader) error {
		var err error
		testBefore, err = readerForDatabase(reader, *database).Get(testDN)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	revision, known := instance.currentStorageSnapshotRevision(ctx)
	rawRevision, rawKnown := rawStore.CurrentStorageSnapshotRevision()
	if !known || !rawKnown {
		t.Fatal("fixture storage revision is unavailable")
	}
	type observation struct {
		wire, credentials                         []byte
		boundDN, credentialDN, mechanism, limited string
		version                                   int
	}
	run := func(t *testing.T, supplied string, reference bool) observation {
		t.Helper()
		// Keep the operation's runtime intact. An equivalent replacement only
		// makes it an old runtime, forcing handleBind's original string entry.
		if reference {
			instance.runtime.Store(new(*runtime))
			defer instance.runtime.Store(runtime)
		}
		state := &connectionState{runtime: runtime, protocolVersion: 3,
			boundDN: realUserDN, operationRealDN: realUserDN, authMechanism: "SIMPLE",
			bindCredentialDN: realUserDN, bindCredentials: []byte("previous"), passwordPolicyRestrictedDN: realUserDN}
		message, request := requestFor(testUserDN, supplied)
		if eligible := instance.canReuseSimpleBindRoute(state, message, request); eligible == reference {
			logGuards(nil)
			t.Fatalf("reference=%t route reuse eligibility=%t", reference, eligible)
		}
		capture := &smallIndexedCapture{}
		bindContext := withACLSubject(t.Context(), instance.connectionACLSubject(state))
		if err := instance.handleBind(bindContext, capture, state, message, request); err != nil {
			t.Fatal(err)
		}
		return observation{bytes.Clone(capture.Bytes()), bytes.Clone(state.bindCredentials),
			state.boundDN, state.bindCredentialDN, state.authMechanism, state.passwordPolicyRestrictedDN, state.protocolVersion}
	}
	for _, test := range []struct {
		name, supplied string
		code           ldapwire.ResultCode
	}{
		{"success", password, ldapwire.ResultSuccess},
		{"wrong", "wrong-fixture-password", ldapwire.ResultInvalidCredentials},
		{"success-again", password, ldapwire.ResultSuccess},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := observation{wire: ldapwire.EncodeBindResponse(1, ldapwire.Result{Code: test.code}, nil), version: 3}
			if test.code == ldapwire.ResultSuccess {
				want.boundDN, want.credentialDN, want.mechanism, want.credentials = testDN.String(), testDN.String(), "SIMPLE", []byte(password)
			}
			oracle := run(t, test.supplied, true)
			got := run(t, test.supplied, false)
			if !reflect.DeepEqual(oracle, want) || !reflect.DeepEqual(got, oracle) {
				t.Fatalf("Bind response/identity mismatch: stringMatchesExpected=%t reuseMatchesString=%t", reflect.DeepEqual(oracle, want), reflect.DeepEqual(got, oracle))
			}
			if after, ok := instance.currentStorageSnapshotRevision(ctx); !ok || after != revision {
				t.Fatal("Bind changed wrapped storage revision")
			}
			if after, ok := rawStore.CurrentStorageSnapshotRevision(); !ok || after != rawRevision {
				t.Fatal("Bind changed raw Bolt storage revision")
			}
		})
	}
	if err := store.View(ctx, func(reader storage.Reader) error {
		config, err := reader.GetIn(configurationStoragePartition, configurationSuffix)
		if err != nil {
			return err
		}
		tx := readerForDatabase(reader, *database)
		real, err := tx.Get(realDN)
		if err != nil {
			return err
		}
		tested, err := tx.Get(testDN)
		if err != nil {
			return err
		}
		if !config.Equal(configBefore) || !real.Equal(realBefore) || !tested.Equal(testBefore) {
			return errors.New("Bind changed cn=config, the original user or the test user")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if instance.runtime.Load() != runtime || instance.config.Store != store || !instance.canReuseSimpleBindRoute(state, message, request) {
		t.Fatal("original runtime/store or route eligibility changed")
	}
}
