package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"slices"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestDerefControlParsingAndSchemaValidation(t *testing.T) {
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	valid := encodeDerefTestRequest([]ldapwire.DerefSpec{{
		DerefAttr:  "SEEALSO",
		Attributes: []string{"jpegPhoto", "CN"},
	}})
	duplicateSpec := encodeDerefTestRequest([]ldapwire.DerefSpec{
		{DerefAttr: "seeAlso", Attributes: []string{"cn"}},
		{DerefAttr: "SEEALSO", Attributes: []string{"uid"}},
	})

	tests := []struct {
		name       string
		controls   []ldapwire.Control
		supported  requestControlSupport
		wantCode   ldapwire.ResultCode
		wantParsed bool
		wantSpecs  int
	}{
		{
			name: "unsupported critical",
			controls: []ldapwire.Control{{
				OID: ldapwire.DerefControlOID, Critical: true,
				Value: valid, HasValue: true,
			}},
			wantCode: ldapwire.ResultUnavailableCriticalExtension,
		},
		{
			name: "unsupported noncritical is ignored before decoding",
			controls: []ldapwire.Control{{
				OID:   ldapwire.DerefControlOID,
				Value: []byte{0x31, 0x00}, HasValue: true,
			}},
		},
		{
			name: "valid",
			controls: []ldapwire.Control{{
				OID:   ldapwire.DerefControlOID,
				Value: valid, HasValue: true,
			}},
			supported: supportsDeref, wantParsed: true, wantSpecs: 1,
		},
		{
			name: "absent",
			controls: []ldapwire.Control{{
				OID: ldapwire.DerefControlOID,
			}},
			supported: supportsDeref, wantCode: ldapwire.ResultProtocolError,
		},
		{
			name: "empty",
			controls: []ldapwire.Control{{
				OID: ldapwire.DerefControlOID, Value: []byte{}, HasValue: true,
			}},
			supported: supportsDeref, wantCode: ldapwire.ResultProtocolError,
		},
		{
			name: "malformed noncritical",
			controls: []ldapwire.Control{{
				OID:   ldapwire.DerefControlOID,
				Value: []byte{0x30, 0x01}, HasValue: true,
			}},
			supported: supportsDeref, wantCode: ldapwire.ResultProtocolError,
		},
		{
			name: "constructed outer tag critical",
			controls: []ldapwire.Control{{
				OID: ldapwire.DerefControlOID, Critical: true,
				Value: []byte{0x31, 0x00}, HasValue: true,
			}},
			supported: supportsDeref, wantParsed: true,
		},
		{
			name: "constructed outer tag noncritical",
			controls: []ldapwire.Control{{
				OID:   ldapwire.DerefControlOID,
				Value: []byte{0x31, 0x00}, HasValue: true,
			}},
			supported: supportsDeref, wantParsed: true,
		},
		{
			name: "duplicate specifications",
			controls: []ldapwire.Control{{
				OID:   ldapwire.DerefControlOID,
				Value: duplicateSpec, HasValue: true,
			}},
			supported: supportsDeref, wantCode: ldapwire.ResultProtocolError,
		},
		{
			name: "duplicate controls",
			controls: []ldapwire.Control{
				{OID: ldapwire.DerefControlOID, Value: valid, HasValue: true},
				{OID: ldapwire.DerefControlOID, Value: valid, HasValue: true},
			},
			supported: supportsDeref, wantCode: ldapwire.ResultProtocolError,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, failure := parseRequestControls(test.controls, test.supported)
			if test.wantCode != ldapwire.ResultSuccess {
				if failure == nil || failure.Code != test.wantCode {
					t.Fatalf("failure = %#v, want code %d", failure, test.wantCode)
				}
				return
			}
			if failure != nil {
				t.Fatalf("parseRequestControls(): %#v", failure)
			}
			if (parsed.deref != nil) != test.wantParsed {
				t.Fatalf("parsed deref = %#v, want present %v", parsed.deref, test.wantParsed)
			}
			if parsed.deref != nil {
				prepared, prepareFailure := prepareDerefControl(registry, parsed.deref)
				if prepareFailure != nil {
					t.Fatalf("prepareDerefControl(): %#v", prepareFailure)
				}
				if len(prepared.specs) != test.wantSpecs {
					t.Fatalf("prepared specs = %#v", prepared.specs)
				}
				if test.wantSpecs == 1 &&
					(prepared.specs[0].DerefAttr != "seeAlso" ||
						!slices.Equal(prepared.specs[0].Attributes, []string{"jpegPhoto", "cn"})) {
					t.Fatalf("prepared specs = %#v", prepared.specs)
				}
			}
		})
	}

	validation := []struct {
		name        string
		critical    bool
		spec        ldapwire.DerefSpec
		wantCode    ldapwire.ResultCode
		wantIgnored bool
	}{
		{
			name: "unknown deref critical", critical: true,
			spec:     ldapwire.DerefSpec{DerefAttr: "doesNotExist", Attributes: []string{"cn"}},
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name:     "unknown deref noncritical",
			spec:     ldapwire.DerefSpec{DerefAttr: "doesNotExist", Attributes: []string{"cn"}},
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name: "non DN critical", critical: true,
			spec:     ldapwire.DerefSpec{DerefAttr: "cn", Attributes: []string{"uid"}},
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name:        "non DN noncritical",
			spec:        ldapwire.DerefSpec{DerefAttr: "cn", Attributes: []string{"uid"}},
			wantIgnored: true,
		},
		{
			name: "unknown result critical", critical: true,
			spec:     ldapwire.DerefSpec{DerefAttr: "seeAlso", Attributes: []string{"doesNotExist"}},
			wantCode: ldapwire.ResultProtocolError,
		},
		{
			name:     "unknown result noncritical",
			spec:     ldapwire.DerefSpec{DerefAttr: "seeAlso", Attributes: []string{"doesNotExist"}},
			wantCode: ldapwire.ResultProtocolError,
		},
	}
	for _, test := range validation {
		t.Run(test.name, func(t *testing.T) {
			prepared, failure := prepareDerefControl(registry, &derefControlRequest{
				specs: []ldapwire.DerefSpec{test.spec}, critical: test.critical,
			})
			if test.wantCode != ldapwire.ResultSuccess {
				if failure == nil || failure.Code != test.wantCode {
					t.Fatalf("failure = %#v, want code %d", failure, test.wantCode)
				}
				return
			}
			if failure != nil {
				t.Fatalf("prepare failure = %#v", failure)
			}
			if test.wantIgnored && prepared != nil {
				t.Fatalf("prepared = %#v, want ignored", prepared)
			}
		})
	}
}

func TestLoadRuntimeDerefOverlayInstances(t *testing.T) {
	tests := []struct {
		name      string
		overlays  []directory.Entry
		wantError bool
		check     func(*testing.T, []runtimeDatabase)
	}{
		{
			name: "unindexed data overlay",
			overlays: []directory.Entry{derefTestOverlayEntry(
				"olcOverlay=deref,olcDatabase={1}mdb,cn=config",
				"deref",
			)},
			check: func(t *testing.T, databases []runtimeDatabase) {
				data := derefTestRuntimeDatabase(t, databases, "mdb")
				if !data.deref || !runtimeSupportsDeref(databases) || frontendSupportsDeref(databases) {
					t.Fatalf("runtime deref state = %#v", databases)
				}
			},
		},
		{
			name: "frontend overlay applies globally",
			overlays: []directory.Entry{derefTestOverlayEntry(
				"olcOverlay={0}deref,olcDatabase={-1}frontend,cn=config",
				"{0}deref",
			)},
			check: func(t *testing.T, databases []runtimeDatabase) {
				data := derefTestRuntimeDatabase(t, databases, "mdb")
				if !frontendSupportsDeref(databases) || !derefEnabledForDatabase(databases, data) {
					t.Fatalf("frontend deref state = %#v", databases)
				}
			},
		},
		{
			name: "one instance per database",
			overlays: []directory.Entry{
				derefTestOverlayEntry(
					"olcOverlay={0}deref,olcDatabase={1}mdb,cn=config",
					"{0}deref",
				),
				derefTestOverlayEntry(
					"olcOverlay={1}deref,olcDatabase={1}mdb,cn=config",
					"{1}deref",
				),
			},
			wantError: true,
		},
		{
			name: "instances on separate databases",
			overlays: []directory.Entry{
				derefTestOverlayEntry(
					"olcOverlay={0}deref,olcDatabase={-1}frontend,cn=config",
					"{0}deref",
				),
				derefTestOverlayEntry(
					"olcOverlay={0}deref,olcDatabase={1}mdb,cn=config",
					"{0}deref",
				),
			},
			check: func(t *testing.T, databases []runtimeDatabase) {
				if !frontendSupportsDeref(databases) || !derefTestRuntimeDatabase(t, databases, "mdb").deref {
					t.Fatalf("runtime deref state = %#v", databases)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := storage.NewMemory()
			defer store.Close()
			err := store.Update(context.Background(), func(writer storage.Writer) error {
				entries := []directory.Entry{
					{
						DN: "olcDatabase={-1}frontend,cn=config",
						Attributes: []directory.Attribute{{
							Description: "olcDatabase", Values: stringValues("{-1}frontend"),
						}},
					},
					{
						DN: "olcDatabase={1}mdb,cn=config",
						Attributes: []directory.Attribute{
							{Description: "olcDatabase", Values: stringValues("{1}mdb")},
							{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
						},
					},
				}
				entries = append(entries, test.overlays...)
				for _, entry := range entries {
					if err := writer.Put(entry, false); err != nil {
						return err
					}
				}
				return writer.SetNamingContexts([]string{"dc=example,dc=com"})
			})
			if err != nil {
				t.Fatalf("seed runtime config: %v", err)
			}
			databases, err := loadRuntimeDatabases(context.Background(), store)
			if test.wantError {
				if err == nil {
					t.Fatal("loadRuntimeDatabases() succeeded, want duplicate-overlay error")
				}
				return
			}
			if err != nil {
				t.Fatalf("loadRuntimeDatabases(): %v", err)
			}
			test.check(t, databases)
		})
	}
}

func derefTestOverlayEntry(dn, value string) directory.Entry {
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcOverlayConfig")},
			{Description: "olcOverlay", Values: stringValues(value)},
		},
	}
}

func derefTestRuntimeDatabase(
	t *testing.T,
	databases []runtimeDatabase,
	databaseTypeName string,
) runtimeDatabase {
	t.Helper()
	for _, database := range databases {
		if databaseType(database.name) == databaseTypeName {
			return database
		}
	}
	t.Fatalf("runtime database %q not found", databaseTypeName)
	return runtimeDatabase{}
}

func TestDerefOverlayOnlineLifecycleRollbackAndRestart(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedDerefTestSecondaryDatabase(t, store)

	config := Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	}
	address, stop := startServer(t, store, config)
	configClient := bindUniqueClient(t, address, "cn=config", "config-secret")
	dataClient := dialLDAPRoot(t, address)

	const sourceDN = "uid=deref-lifecycle,ou=people,dc=example,dc=com"
	source := newPersonAddRequest("deref-lifecycle")
	source.Attribute("seeAlso", []string{aliceDN})
	if err := dataClient.Add(source); err != nil {
		t.Fatalf("add deref lifecycle source: %v", err)
	}
	controlValue := encodeDerefTestRequest([]ldapwire.DerefSpec{{
		DerefAttr: "seeAlso", Attributes: []string{"uid"},
	}})
	critical := ldapwire.Control{
		OID: ldapwire.DerefControlOID, Critical: true,
		Value: controlValue, HasValue: true,
	}
	noncritical := critical
	noncritical.Critical = false

	if derefTestAdvertised(t, dataClient) {
		t.Fatal("deref control advertised without an overlay instance")
	}
	assertDerefTestSearch(
		t,
		runDerefTestSearch(t, address, syncTestRootDN, syncTestRootPassword,
			sourceDN, ldap.ScopeBaseObject, "(objectClass=*)", []string{"uid"}, critical),
		ldapwire.ResultUnavailableCriticalExtension,
		false,
	)
	assertDerefTestSearch(
		t,
		runDerefTestSearch(t, address, syncTestRootDN, syncTestRootPassword,
			sourceDN, ldap.ScopeBaseObject, "(objectClass=*)", []string{"uid"}, noncritical),
		ldapwire.ResultSuccess,
		false,
	)

	const overlayDN = "olcOverlay={0}deref,olcDatabase={1}mdb,cn=config"
	overlay := ldap.NewAddRequest(overlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig"})
	overlay.Attribute("olcOverlay", []string{"{0}deref"})
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("add online deref overlay: %v", err)
	}
	if !derefTestAdvertised(t, dataClient) {
		t.Fatal("deref control not advertised after adding an overlay instance")
	}
	assertDerefTestSearch(
		t,
		runDerefTestSearch(t, address, syncTestRootDN, syncTestRootPassword,
			sourceDN, ldap.ScopeBaseObject, "(objectClass=*)", []string{"uid"}, critical),
		ldapwire.ResultSuccess,
		true,
	)
	for _, criticality := range []bool{false, true} {
		constructedOuter := ldapwire.Control{
			OID:      ldapwire.DerefControlOID,
			Critical: criticality,
			Value:    []byte{0x31, 0x00},
			HasValue: true,
		}
		assertDerefTestSearch(
			t,
			runDerefTestSearch(t, address, syncTestRootDN, syncTestRootPassword,
				sourceDN, ldap.ScopeBaseObject, "(objectClass=*)", []string{"uid"}, constructedOuter),
			ldapwire.ResultSuccess,
			false,
		)
	}

	// Registration is process-wide, but the control remains unavailable on
	// the Root DSE and on a database without its own deref overlay.
	assertDerefTestSearch(
		t,
		runDerefTestSearch(t, address, syncTestRootDN, syncTestRootPassword,
			"", ldap.ScopeBaseObject, "(objectClass=*)", []string{"supportedControl"}, critical),
		ldapwire.ResultUnavailableCriticalExtension,
		false,
	)
	assertDerefTestSearch(
		t,
		runDerefTestSearch(t, address, syncTestRootDN, syncTestRootPassword,
			"dc=other,dc=com", ldap.ScopeBaseObject, "(objectClass=*)", []string{"dc"}, critical),
		ldapwire.ResultUnavailableCriticalExtension,
		false,
	)
	assertDerefTestSearch(
		t,
		runDerefTestSearch(t, address, syncTestRootDN, syncTestRootPassword,
			"dc=other,dc=com", ldap.ScopeBaseObject, "(objectClass=*)", []string{"dc"}, noncritical),
		ldapwire.ResultSuccess,
		false,
	)

	duplicateDN := "olcOverlay={1}deref,olcDatabase={1}mdb,cn=config"
	duplicate := ldap.NewAddRequest(duplicateDN, nil)
	duplicate.Attribute("objectClass", []string{"olcOverlayConfig"})
	duplicate.Attribute("olcOverlay", []string{"{1}deref"})
	assertLDAPResultCode(
		t,
		configClient.Add(duplicate),
		ldap.LDAPResultConstraintViolation,
	)
	if derefTestStoredEntryExists(t, store, duplicateDN) {
		t.Fatal("failed duplicate deref overlay add was not rolled back")
	}
	assertDerefTestSearch(
		t,
		runDerefTestSearch(t, address, syncTestRootDN, syncTestRootPassword,
			sourceDN, ldap.ScopeBaseObject, "(objectClass=*)", []string{"uid"}, critical),
		ldapwire.ResultSuccess,
		true,
	)

	configClient.Close()
	dataClient.Close()
	stop()

	address, stop = startServer(t, store, config)
	configClient = bindUniqueClient(t, address, "cn=config", "config-secret")
	dataClient = dialLDAPRoot(t, address)
	if !derefTestAdvertised(t, dataClient) {
		t.Fatal("deref control not advertised after enabled restart")
	}
	assertDerefTestSearch(
		t,
		runDerefTestSearch(t, address, syncTestRootDN, syncTestRootPassword,
			sourceDN, ldap.ScopeBaseObject, "(objectClass=*)", []string{"uid"}, critical),
		ldapwire.ResultSuccess,
		true,
	)

	if err := configClient.Del(ldap.NewDelRequest(overlayDN, nil)); err != nil {
		t.Fatalf("delete online deref overlay: %v", err)
	}
	if derefTestAdvertised(t, dataClient) {
		t.Fatal("deref control still advertised after deleting the last instance")
	}
	assertDerefTestSearch(
		t,
		runDerefTestSearch(t, address, syncTestRootDN, syncTestRootPassword,
			sourceDN, ldap.ScopeBaseObject, "(objectClass=*)", []string{"uid"}, critical),
		ldapwire.ResultUnavailableCriticalExtension,
		false,
	)
	assertDerefTestSearch(
		t,
		runDerefTestSearch(t, address, syncTestRootDN, syncTestRootPassword,
			sourceDN, ldap.ScopeBaseObject, "(objectClass=*)", []string{"uid"}, noncritical),
		ldapwire.ResultSuccess,
		false,
	)

	configClient.Close()
	dataClient.Close()
	stop()

	address, stop = startServer(t, store, config)
	defer stop()
	dataClient = dialLDAPRoot(t, address)
	defer dataClient.Close()
	if derefTestAdvertised(t, dataClient) {
		t.Fatal("deleted deref overlay returned after restart")
	}
	assertDerefTestSearch(
		t,
		runDerefTestSearch(t, address, syncTestRootDN, syncTestRootPassword,
			sourceDN, ldap.ScopeBaseObject, "(objectClass=*)", []string{"uid"}, critical),
		ldapwire.ResultUnavailableCriticalExtension,
		false,
	)
}

func TestDerefFrontendOverlayOnlineLifecycle(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "olcDatabase={-1}frontend,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{-1}frontend")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("seed frontend database: %v", err)
	}

	config := Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
	}
	address, stop := startServer(t, store, config)
	defer stop()
	configClient := bindUniqueClient(t, address, "cn=config", "config-secret")
	defer configClient.Close()
	dataClient := dialLDAPRoot(t, address)
	defer dataClient.Close()

	const sourceDN = "uid=deref-frontend,ou=people,dc=example,dc=com"
	source := newPersonAddRequest("deref-frontend")
	source.Attribute("seeAlso", []string{aliceDN})
	if err := dataClient.Add(source); err != nil {
		t.Fatalf("add frontend deref source: %v", err)
	}
	control := ldapwire.Control{
		OID: ldapwire.DerefControlOID, Critical: true,
		Value: encodeDerefTestRequest([]ldapwire.DerefSpec{{
			DerefAttr: "seeAlso", Attributes: []string{"uid"},
		}}),
		HasValue: true,
	}

	const overlayDN = "olcOverlay=deref,olcDatabase={-1}frontend,cn=config"
	overlay := ldap.NewAddRequest(overlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig"})
	overlay.Attribute("olcOverlay", []string{"deref"})
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("add frontend deref overlay: %v", err)
	}
	if !derefTestAdvertised(t, dataClient) {
		t.Fatal("frontend deref overlay did not publish supportedControl")
	}
	assertDerefTestSearch(
		t,
		runDerefTestSearch(t, address, syncTestRootDN, syncTestRootPassword,
			sourceDN, ldap.ScopeBaseObject, "(objectClass=*)", []string{"uid"}, control),
		ldapwire.ResultSuccess,
		true,
	)
	assertDerefTestSearch(
		t,
		runDerefTestSearch(t, address, syncTestRootDN, syncTestRootPassword,
			"", ldap.ScopeBaseObject, "(objectClass=*)", []string{"supportedControl"}, control),
		ldapwire.ResultSuccess,
		false,
	)

	if err := configClient.Del(ldap.NewDelRequest(overlayDN, nil)); err != nil {
		t.Fatalf("delete frontend deref overlay: %v", err)
	}
	if derefTestAdvertised(t, dataClient) {
		t.Fatal("frontend deref overlay remained published after deletion")
	}
}

func TestDerefResponseACLBackendAndValueSemantics(t *testing.T) {
	const (
		sourceDN           = "uid=deref-source,ou=people,dc=example,dc=com"
		sourceDeniedDN     = "uid=deref-source-denied,ou=people,dc=example,dc=com"
		collectiveOnlyDN   = "uid=deref-collective-only,ou=people,dc=example,dc=com"
		readableDN         = "uid=deref-readable,ou=people,dc=example,dc=com"
		entryHiddenDN      = "uid=deref-entry-hidden,ou=people,dc=example,dc=com"
		valueHiddenDN      = "uid=deref-value-hidden,ou=people,dc=example,dc=com"
		missingDN          = "uid=deref-missing,ou=people,dc=example,dc=com"
		otherBackendDN     = "uid=deref-other,dc=other,dc=com"
		collectiveSourceDN = "cn=deref-collective,ou=people,dc=example,dc=com"
		collectiveMarker   = "deref-source-acl"
	)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	seedDerefTestSecondaryDatabase(t, store)
	registry := collectiveServerRegistry(t)
	if err := registry.ParseAndRegisterAttributeType(
		"( 1.2.3.5 NAME 'c-member' SUP member COLLECTIVE )",
	); err != nil {
		t.Fatalf("register collective member attribute: %v", err)
	}

	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		peopleDN, err := directory.ParseDN("ou=people,dc=example,dc=com")
		if err != nil {
			return err
		}
		people, err := writer.Get(peopleDN)
		if err != nil {
			return err
		}
		people.ReplaceValues(
			"administrativeRole",
			stringValues("collectiveAttributeSpecificArea"),
		)
		if err := writer.Put(people, true); err != nil {
			return err
		}

		configDN, err := directory.ParseDN("olcDatabase={1}mdb,cn=config")
		if err != nil {
			return err
		}
		config, err := writer.Get(configDN)
		if err != nil {
			return err
		}
		config.ReplaceValues("olcAccess", stringValues(
			"{0}to attrs=userPassword by self =xw by anonymous auth by * none",
			"{1}to dn.base=\""+sourceDN+"\" attrs=member val.exact=\""+valueHiddenDN+"\" by users none",
			"{2}to dn.base=\""+sourceDeniedDN+"\" attrs=member by users none",
			"{3}to filter=\"(&(uid=deref-source)(c-description="+collectiveMarker+"))\" attrs=member,seeAlso by users read by * none",
			"{4}to attrs=member,seeAlso by users none",
			"{5}to dn.base=\""+entryHiddenDN+"\" attrs=entry by users none",
			"{6}to dn.base=\""+readableDN+"\" attrs=description val.exact=\"secret\" by users none",
			"{7}to dn.base=\""+readableDN+"\" attrs=uid by users none",
			"{8}to * by users read by * none",
		))
		if err := writer.Put(config, true); err != nil {
			return err
		}

		entries := []directory.Entry{
			derefTestOverlayEntry(
				"olcOverlay={0}deref,olcDatabase={1}mdb,cn=config",
				"{0}deref",
			),
			{
				DN: collectiveSourceDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("subentry", "collectiveAttributeSubentry")},
					{Description: "cn", Values: stringValues("deref-collective")},
					{Description: "subtreeSpecification", Values: stringValues("{}")},
					{Description: "c-description", Values: stringValues(collectiveMarker)},
					{Description: "c-member", Values: stringValues(readableDN)},
				},
			},
			{
				DN: sourceDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("inetOrgPerson")},
					{Description: "uid", Values: stringValues("deref-source")},
					{Description: "cn", Values: stringValues("Deref Source")},
					{Description: "sn", Values: stringValues("Source")},
					{Description: "member", Values: stringValues(
						readableDN,
						entryHiddenDN,
						valueHiddenDN,
						missingDN,
						otherBackendDN,
					)},
					{Description: "seeAlso", Values: stringValues(readableDN)},
				},
			},
			derefTestPersonEntry(sourceDeniedDN, "deref-source-denied", directory.Attribute{
				Description: "member", Values: stringValues(readableDN),
			}),
			derefTestPersonEntry(collectiveOnlyDN, "deref-collective-only"),
			{
				DN: readableDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("inetOrgPerson")},
					{Description: "uid", Values: stringValues("deref-readable")},
					{Description: "cn", Values: stringValues("Readable Target")},
					{Description: "sn", Values: stringValues("Target")},
					{Description: "jpegPhoto", Values: [][]byte{{0x00, 0xff, 0x10}, {}}},
					{Description: "description", Values: [][]byte{[]byte("visible"), []byte("secret"), {}}},
				},
			},
			derefTestPersonEntry(entryHiddenDN, "deref-entry-hidden"),
			derefTestPersonEntry(valueHiddenDN, "deref-value-hidden"),
			derefTestPersonEntry(otherBackendDN, "deref-other"),
		}
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed deref ACL directory: %v", err)
	}

	address, stop := startServer(t, store, Config{
		RootDN:       syncTestRootDN,
		RootPassword: []byte(syncTestRootPassword),
		Schema:       registry,
	})
	defer stop()

	control := ldapwire.Control{
		OID: ldapwire.DerefControlOID, Critical: true,
		Value: encodeDerefTestRequest([]ldapwire.DerefSpec{
			{DerefAttr: "member", Attributes: []string{"jpegPhoto", "description", "uid"}},
			{DerefAttr: "seeAlso", Attributes: []string{"cn"}},
		}),
		HasValue: true,
	}
	result := runDerefTestSearch(
		t,
		address,
		aliceDN,
		"secret",
		sourceDN,
		ldap.ScopeBaseObject,
		"(objectClass=*)",
		[]string{"uid"},
		control,
	)
	assertDerefTestSearch(t, result, ldapwire.ResultSuccess, true)
	if len(result.entries) != 1 {
		t.Fatalf("source search entries = %d, want 1", len(result.entries))
	}
	response := decodeDerefTestResponse(
		t,
		result.entries[0].controls[ldapwire.DerefControlOID],
	)
	if len(response) != 5 {
		t.Fatalf("deref response = %#v, want five visible source values", response)
	}
	wantValues := []string{
		readableDN,
		entryHiddenDN,
		missingDN,
		otherBackendDN,
		readableDN,
	}
	wantAttributes := []string{"member", "member", "member", "member", "seeAlso"}
	for index := range response {
		if response[index].DerefAttr != wantAttributes[index] ||
			response[index].DerefValue != wantValues[index] {
			t.Fatalf("deref response[%d] = %#v", index, response[index])
		}
	}
	if got := derefTestAttributeTypes(response[0].Attributes); !slices.Equal(
		got,
		[]string{"jpegPhoto", "description"},
	) {
		t.Fatalf("readable target attributes = %q", got)
	}
	if got := response[0].Attributes[0].Values; len(got) != 2 ||
		!bytes.Equal(got[0], []byte{0x00, 0xff, 0x10}) || len(got[1]) != 0 {
		t.Fatalf("binary/empty jpegPhoto values = %q", got)
	}
	if got := response[0].Attributes[1].Values; len(got) != 2 ||
		!bytes.Equal(got[0], []byte("visible")) || len(got[1]) != 0 {
		t.Fatalf("ACL-filtered description values = %q", got)
	}
	for index := 1; index <= 3; index++ {
		if len(response[index].Attributes) != 0 {
			t.Fatalf("non-readable target %d leaked attributes: %#v", index, response[index])
		}
	}
	if len(response[4].Attributes) != 1 ||
		response[4].Attributes[0].Type != "cn" ||
		len(response[4].Attributes[0].Values) != 1 ||
		string(response[4].Attributes[0].Values[0]) != "Readable Target" {
		t.Fatalf("second request specification response = %#v", response[4])
	}

	// A denied source attribute produces no response control at all.
	assertDerefTestSearch(
		t,
		runDerefTestSearch(t, address, aliceDN, "secret", sourceDeniedDN,
			ldap.ScopeBaseObject, "(objectClass=*)", []string{"uid"}, control),
		ldapwire.ResultSuccess,
		false,
	)

	// The response-side entry contains c-member, but deref values are read
	// from the underlying entry, where no member attribute exists.
	root := dialLDAPRoot(t, address)
	projected, err := root.Search(ldap.NewSearchRequest(
		collectiveOnlyDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"c-member"},
		nil,
	))
	root.Close()
	if err != nil || len(projected.Entries) != 1 ||
		projected.Entries[0].GetAttributeValue("c-member") != readableDN {
		t.Fatalf("collective source projection = %#v, %v", projected, err)
	}
	assertDerefTestSearch(
		t,
		runDerefTestSearch(t, address, aliceDN, "secret", collectiveOnlyDN,
			ldap.ScopeBaseObject, "(objectClass=*)", []string{"uid"}, control),
		ldapwire.ResultSuccess,
		false,
	)
}

func derefTestPersonEntry(
	dn,
	uid string,
	additional ...directory.Attribute,
) directory.Entry {
	entry := directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues(uid)},
			{Description: "cn", Values: stringValues(uid)},
			{Description: "sn", Values: stringValues("Target")},
		},
	}
	entry.Attributes = append(entry.Attributes, additional...)
	return entry
}

func derefTestAttributeTypes(attributes []ldapwire.DerefAttribute) []string {
	result := make([]string, len(attributes))
	for index := range attributes {
		result[index] = attributes[index].Type
	}
	return result
}

func decodeDerefTestResponse(
	t *testing.T,
	value []byte,
) []ldapwire.DerefResult {
	t.Helper()
	packet, err := ber.DecodePacketErr(value)
	if err != nil {
		t.Fatalf("decode deref response: %v", err)
	}
	if packet.ClassType != ber.ClassUniversal ||
		packet.TagType != ber.TypeConstructed ||
		packet.Tag != ber.TagSequence {
		t.Fatalf("deref response outer packet = %#v", packet)
	}
	results := make([]ldapwire.DerefResult, 0, len(packet.Children))
	for resultIndex, encoded := range packet.Children {
		if encoded.ClassType != ber.ClassUniversal ||
			encoded.TagType != ber.TypeConstructed ||
			encoded.Tag != ber.TagSequence ||
			(len(encoded.Children) != 2 && len(encoded.Children) != 3) {
			t.Fatalf("deref response result %d = %#v", resultIndex, encoded)
		}
		result := ldapwire.DerefResult{
			DerefAttr:  string(encoded.Children[0].Data.Bytes()),
			DerefValue: string(encoded.Children[1].Data.Bytes()),
		}
		if len(encoded.Children) == 3 {
			attributeList := encoded.Children[2]
			if attributeList.ClassType != ber.ClassContext ||
				attributeList.TagType != ber.TypeConstructed ||
				attributeList.Tag != 0 {
				t.Fatalf("deref response attribute list %d = %#v", resultIndex, attributeList)
			}
			for attributeIndex, partial := range attributeList.Children {
				if partial.ClassType != ber.ClassUniversal ||
					partial.TagType != ber.TypeConstructed ||
					partial.Tag != ber.TagSequence ||
					len(partial.Children) != 2 {
					t.Fatalf("deref response attribute %d/%d = %#v", resultIndex, attributeIndex, partial)
				}
				attribute := ldapwire.DerefAttribute{
					Type: string(partial.Children[0].Data.Bytes()),
				}
				for _, encodedValue := range partial.Children[1].Children {
					attribute.Values = append(
						attribute.Values,
						bytes.Clone(encodedValue.Data.Bytes()),
					)
				}
				result.Attributes = append(result.Attributes, attribute)
			}
		}
		results = append(results, result)
	}
	return results
}

func seedDerefTestSecondaryDatabase(t *testing.T, store storage.Store) {
	t.Helper()
	err := store.Update(context.Background(), func(writer storage.Writer) error {
		entries := []directory.Entry{
			{
				DN: "olcDatabase={2}mdb,cn=config",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
					{Description: "olcDatabase", Values: stringValues("{2}mdb")},
					{Description: "olcSuffix", Values: stringValues("dc=other,dc=com")},
					{Description: "olcAccess", Values: stringValues("{0}to * by * read")},
				},
			},
			{
				DN: "dc=other,dc=com",
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: stringValues("domain")},
					{Description: "dc", Values: stringValues("other")},
				},
			},
		}
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{
			"dc=example,dc=com",
			"dc=other,dc=com",
			"cn=config",
		})
	})
	if err != nil {
		t.Fatalf("seed secondary deref database: %v", err)
	}
}

func derefTestAdvertised(t *testing.T, client *ldap.Conn) bool {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
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
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("search Root DSE supportedControl: %#v, %v", result, err)
	}
	return containsString(
		result.Entries[0].GetAttributeValues("supportedControl"),
		ldapwire.DerefControlOID,
	)
}

func derefTestStoredEntryExists(
	t *testing.T,
	store storage.Store,
	rawDN string,
) bool {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", rawDN, err)
	}
	exists := false
	err = store.View(context.Background(), func(reader storage.Reader) error {
		_, err := reader.Get(dn)
		if errors.Is(err, storage.ErrEntryNotFound) {
			return nil
		}
		if err == nil {
			exists = true
		}
		return err
	})
	if err != nil {
		t.Fatalf("check stored entry %q: %v", rawDN, err)
	}
	return exists
}

type derefTestSearchEntry struct {
	dn       string
	attrs    []directory.Attribute
	controls map[string][]byte
}

type derefTestSearchResult struct {
	code    ldapwire.ResultCode
	entries []derefTestSearchEntry
}

func runDerefTestSearch(
	t *testing.T,
	address,
	bindDN,
	password,
	baseDN string,
	scope int,
	filter string,
	attributes []string,
	control ldapwire.Control,
) derefTestSearchResult {
	t.Helper()
	connection := dialAndBindRawLDAP(t, address, bindDN, password)
	defer connection.Close()

	request := rawSyncSearchRequestFor(
		t,
		baseDN,
		scope,
		ldap.NeverDerefAliases,
		filter,
	)
	attributeList := request.Children[len(request.Children)-1]
	attributeList.Children = nil
	for _, attribute := range attributes {
		attributeList.AppendChild(rawOctetString([]byte(attribute)))
	}
	writeOpenLDAPReferenceRequest(
		t,
		connection,
		2,
		request,
		[]*ber.Packet{encodeRawLDAPControl(control)},
	)

	var result derefTestSearchResult
	for {
		packet, err := ber.ReadPacket(connection)
		if err != nil {
			if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
				t.Fatalf("deref search timed out: %v", err)
			}
			t.Fatalf("read deref search response: %v", err)
		}
		if len(packet.Children) < 2 {
			t.Fatalf("malformed deref search response: %#v", packet)
		}
		operation := packet.Children[1]
		switch uint64(operation.Tag) {
		case ldapwire.ApplicationSearchResultEntry:
			entry := derefTestSearchEntry{
				dn:       string(operation.Children[0].Data.Bytes()),
				controls: derefTestMessageControls(packet),
			}
			for _, partial := range operation.Children[1].Children {
				attribute := directory.Attribute{
					Description: string(partial.Children[0].Data.Bytes()),
				}
				for _, value := range partial.Children[1].Children {
					attribute.Values = append(
						attribute.Values,
						bytes.Clone(value.Data.Bytes()),
					)
				}
				entry.attrs = append(entry.attrs, attribute)
			}
			result.entries = append(result.entries, entry)
		case ldapwire.ApplicationSearchResultDone:
			result.code = ldapwire.ResultCode(rawLDAPResultCode(t, operation))
			return result
		default:
			t.Fatalf("unexpected deref search response tag %d", operation.Tag)
		}
	}
}

func derefTestMessageControls(message *ber.Packet) map[string][]byte {
	controls := make(map[string][]byte)
	if len(message.Children) < 3 {
		return controls
	}
	for _, packet := range message.Children[2].Children {
		if len(packet.Children) == 0 {
			continue
		}
		oid := string(packet.Children[0].Data.Bytes())
		for _, child := range packet.Children[1:] {
			if child.ClassType == ber.ClassUniversal && child.Tag == ber.TagOctetString {
				controls[oid] = bytes.Clone(child.Data.Bytes())
			}
		}
	}
	return controls
}

func assertDerefTestSearch(
	t *testing.T,
	result derefTestSearchResult,
	wantCode ldapwire.ResultCode,
	wantControl bool,
) {
	t.Helper()
	if result.code != wantCode {
		t.Fatalf("search result code = %d, want %d; entries = %#v", result.code, wantCode, result.entries)
	}
	hasControl := false
	for _, entry := range result.entries {
		if _, ok := entry.controls[ldapwire.DerefControlOID]; ok {
			hasControl = true
		}
	}
	if hasControl != wantControl {
		t.Fatalf("search deref control present = %v, want %v; entries = %#v", hasControl, wantControl, result.entries)
	}
}

func encodeDerefTestRequest(specs []ldapwire.DerefSpec) []byte {
	request := ber.NewSequence("derefRequestValue")
	for _, spec := range specs {
		encodedSpec := ber.NewSequence("derefSpec")
		encodedSpec.AppendChild(rawOctetString([]byte(spec.DerefAttr)))
		attributes := ber.NewSequence("attributes")
		for _, attribute := range spec.Attributes {
			attributes.AppendChild(rawOctetString([]byte(attribute)))
		}
		encodedSpec.AppendChild(attributes)
		request.AppendChild(encodedSpec)
	}
	return request.Bytes()
}
