package server

import (
	"context"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPClientCollectiveAttributeOperations(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	setCollectiveAdministrativeRoles(
		t,
		store,
		"ou=people,dc=example,dc=com",
		"collectiveAttributeSpecificArea",
	)
	registry := collectiveServerRegistry(t)

	const (
		rootDN       = "cn=admin,dc=example,dc=com"
		rootPassword = "admin-secret"
		sourceDN     = "cn=shared,ou=people,dc=example,dc=com"
	)
	address, stop := startServer(t, store, Config{
		RootDN:       rootDN,
		RootPassword: []byte(rootPassword),
		Schema:       registry,
	})
	defer stop()

	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(rootDN, rootPassword); err != nil {
		t.Fatalf("Bind(): %v", err)
	}

	source := ldap.NewAddRequest(sourceDN, nil)
	source.Attribute("objectClass", []string{
		"subentry",
		"collectiveAttributeSubentry",
	})
	source.Attribute("cn", []string{"shared"})
	source.Attribute("subtreeSpecification", []string{"{}"})
	source.Attribute("c-description", []string{"Shared"})
	if err := client.Add(source); err != nil {
		t.Fatalf("Add(collective source): %v", err)
	}

	addBob := newPersonAddRequest("collective-bob")
	if err := client.Add(addBob); err != nil {
		t.Fatalf("Add(member): %v", err)
	}

	search := func(filter string) *ldap.SearchResult {
		t.Helper()
		result, err := client.Search(ldap.NewSearchRequest(
			"ou=people,dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			filter,
			[]string{
				"uid",
				"c-description",
				"collectiveAttributeSubentries",
			},
			nil,
		))
		if err != nil {
			t.Fatalf("Search(%q): %v", filter, err)
		}
		return result
	}
	result := search(
		"(&(objectClass=inetOrgPerson)(c-description=shared))",
	)
	if len(result.Entries) != 2 {
		t.Fatalf("collective filter entries = %d, want 2", len(result.Entries))
	}
	for _, entry := range result.Entries {
		if entry.GetAttributeValue("c-description") != "Shared" ||
			entry.GetAttributeValue("collectiveAttributeSubentries") != sourceDN {
			t.Fatalf("derived search entry = %#v", entry)
		}
	}
	for _, filter := range []string{
		"(collectiveDescription=shared)",
		"(1.2.3.4=shared)",
		"(description=shared)",
	} {
		if entries := search(
			"(&(objectClass=inetOrgPerson)" + filter + ")",
		).Entries; len(entries) != 2 {
			t.Fatalf("collective hierarchy filter %q entries = %d, want 2", filter, len(entries))
		}
	}

	for _, attribute := range []string{
		"c-description",
		"collectiveDescription",
		"1.2.3.4",
		"description",
	} {
		matches, err := client.Compare(aliceDN, attribute, "shared")
		if err != nil {
			t.Fatalf("Compare(%s): %v", attribute, err)
		}
		if !matches {
			t.Fatalf("Compare(%s) = false, want true", attribute)
		}
	}

	hierarchySelection, err := client.Search(ldap.NewSearchRequest(
		aliceDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"description"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(collective supertype selection): %v", err)
	}
	if len(hierarchySelection.Entries) != 1 ||
		hierarchySelection.Entries[0].GetAttributeValue("c-description") != "Shared" {
		t.Fatalf("collective supertype selection = %#v", hierarchySelection.Entries)
	}

	if code := rawCompareWithAssertion(
		t,
		address,
		"(c-description=shared)",
	); code != int64(ldap.LDAPResultCompareTrue) {
		t.Fatalf("Compare with collective assertion result = %d", code)
	}

	assertedModify := ldap.NewModifyRequest(
		aliceDN,
		[]ldap.Control{newAssertionControl(t, "(c-description=shared)")},
	)
	assertedModify.Replace("description", []string{"assertion matched"})
	if err := client.Modify(assertedModify); err != nil {
		t.Fatalf("Modify with collective assertion: %v", err)
	}

	rawConnection := dialAndBindRawLDAP(t, address, rootDN, rootPassword)
	defer rawConnection.Close()
	response := sendRawLDAPOperation(
		t,
		rawConnection,
		2,
		rawModifyReplaceRequest(aliceDN, "description", "read controls"),
		rawReadControl(preReadControlOID, true, "collectiveDescription"),
		rawReadControl(postReadControlOID, true, "1.2.3.4"),
	)
	assertRawLDAPResult(t, response, int64(ldap.LDAPResultSuccess))
	if singleRawValue(
		t,
		rawReadControlEntry(t, response, preReadControlOID),
		"c-description",
	) != "Shared" ||
		singleRawValue(
			t,
			rawReadControlEntry(t, response, postReadControlOID),
			"c-description",
		) != "Shared" {
		t.Fatal("read controls did not include the derived collective value")
	}

	paged, err := client.SearchWithPaging(ldap.NewSearchRequest(
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(&(objectClass=inetOrgPerson)(c-description=shared))",
		[]string{"uid", "c-description"},
		nil,
	), 1)
	if err != nil {
		t.Fatalf("SearchWithPaging(collective filter): %v", err)
	}
	if len(paged.Entries) != 2 {
		t.Fatalf("paged collective entries = %d, want 2", len(paged.Entries))
	}

	exclude := ldap.NewModifyRequest(aliceDN, nil)
	exclude.Replace("collectiveExclusions", []string{"1.2.3.4"})
	if err := client.Modify(exclude); err != nil {
		t.Fatalf("Modify(collectiveExclusions): %v", err)
	}
	excluded, err := client.Search(ldap.NewSearchRequest(
		aliceDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"c-description", "collectiveAttributeSubentries"},
		nil,
	))
	if err != nil {
		t.Fatalf("Search(excluded member): %v", err)
	}
	if len(excluded.Entries) != 1 ||
		excluded.Entries[0].GetAttributeValue("c-description") != "" ||
		excluded.Entries[0].GetAttributeValue("collectiveAttributeSubentries") != sourceDN {
		t.Fatalf("excluded member = %#v", excluded.Entries)
	}

	failedAssertion := ldap.NewModifyRequest(
		aliceDN,
		[]ldap.Control{newAssertionControl(t, "(c-description=shared)")},
	)
	failedAssertion.Replace("description", []string{"must not apply"})
	assertLDAPResultCode(
		t,
		client.Modify(failedAssertion),
		ldap.LDAPResultAssertionFailed,
	)

	clearExclusion := ldap.NewModifyRequest(aliceDN, nil)
	clearExclusion.Replace("collectiveExclusions", nil)
	if err := client.Modify(clearExclusion); err != nil {
		t.Fatalf("clear collectiveExclusions: %v", err)
	}
	updateSource := ldap.NewModifyRequest(sourceDN, nil)
	updateSource.Replace("c-description", []string{"Updated"})
	if err := client.Modify(updateSource); err != nil {
		t.Fatalf("Modify(collective source): %v", err)
	}
	updated := search(
		"(&(objectClass=inetOrgPerson)(c-description=updated))",
	)
	if len(updated.Entries) != 2 {
		t.Fatalf("updated collective entries = %d, want 2", len(updated.Entries))
	}

	modifyMember := ldap.NewModifyRequest(aliceDN, nil)
	modifyMember.Replace("c-description", []string{"illegal"})
	assertLDAPResultCode(
		t,
		client.Modify(modifyMember),
		ldap.LDAPResultObjectClassViolation,
	)
	modifyGenerated := ldap.NewModifyRequest(aliceDN, nil)
	modifyGenerated.Replace(
		"collectiveAttributeSubentries",
		[]string{sourceDN},
	)
	assertLDAPResultCode(
		t,
		client.Modify(modifyGenerated),
		ldap.LDAPResultConstraintViolation,
	)
	modifyGeneratedWithOptions := ldap.NewModifyRequest(aliceDN, nil)
	modifyGeneratedWithOptions.Replace(
		"2.5.18.12;x-origin",
		[]string{sourceDN},
	)
	assertLDAPResultCode(
		t,
		client.Modify(modifyGeneratedWithOptions),
		ldap.LDAPResultConstraintViolation,
	)

	illegalAdd := newPersonAddRequest("collective-illegal")
	illegalAdd.Attribute("c-description", []string{"illegal"})
	assertLDAPResultCode(
		t,
		client.Add(illegalAdd),
		ldap.LDAPResultObjectClassViolation,
	)
	protectedAdd := newPersonAddRequest("collective-protected")
	protectedAdd.Attribute(
		"2.5.18.12;x-origin",
		[]string{sourceDN},
	)
	if err := client.Add(protectedAdd); err != nil {
		t.Fatalf("Add(member with generated operational attribute): %v", err)
	}
	storedProtected := readStoredEntry(
		t,
		store,
		"uid=collective-protected,ou=people,dc=example,dc=com",
	)
	if registry.HasAttributeDescription(
		storedProtected,
		"collectiveAttributeSubentries",
	) {
		t.Fatalf("protected Add value reached storage: %#v", storedProtected)
	}

	storedAlice := readStoredEntry(t, store, aliceDN)
	if storedAlice.HasAttribute("c-description") ||
		registry.HasAttributeDescription(
			storedAlice,
			"collectiveAttributeSubentries",
		) ||
		storedAlice.HasAttribute("collectiveExclusions") {
		t.Fatalf("stored member contains derived state: %#v", storedAlice)
	}
}

func TestCollectiveAttributesParticipateInMemberACL(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	setCollectiveAdministrativeRoles(
		t,
		store,
		"ou=people,dc=example,dc=com",
		collectiveAttributeSpecificAreaOID,
	)
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if err := registry.ParseAndRegisterAttributeType(
		"( 1.2.3.5 NAME 'c-member' SUP member COLLECTIVE )",
	); err != nil {
		t.Fatalf("register c-member: %v", err)
	}

	bobDN := "uid=collective-acl-bob,ou=people,dc=example,dc=com"
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		bob := collectiveServerPerson(bobDN, nil)
		bob.ReplaceValues("uid", stringValues("collective-acl-bob"))
		if err := writer.Put(bob, false); err != nil {
			return err
		}
		if err := writer.Put(collectiveServerSource(
			"cn=acl,ou=people,dc=example,dc=com",
			"{}",
			directory.Attribute{
				Description: "c-member",
				Values:      stringValues(aliceDN),
			},
		), false); err != nil {
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
			"{1}to attrs=mail by dnattr=c-member write by users read by * none",
			"{2}to * by users read by * none",
		))
		return writer.Put(config, true)
	}); err != nil {
		t.Fatalf("seed collective ACL data: %v", err)
	}

	address, stop := startServer(t, store, Config{Schema: registry})
	defer stop()
	alice, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(alice): %v", err)
	}
	defer alice.Close()
	if err := alice.Bind(aliceDN, "secret"); err != nil {
		t.Fatalf("Bind(alice): %v", err)
	}
	modifyBob := ldap.NewModifyRequest(bobDN, nil)
	modifyBob.Replace("mail", []string{"allowed@example.com"})
	if err := alice.Modify(modifyBob); err != nil {
		t.Fatalf("collective dnattr-authorized Modify(): %v", err)
	}

	bob := readStoredEntry(t, store, bobDN)
	if string(bob.Values("mail")[0]) != "allowed@example.com" {
		t.Fatalf("stored Bob entry = %#v", bob)
	}
}

func TestCollectiveAttributesParticipateInSortingAndVLV(t *testing.T) {
	t.Parallel()

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedDirectory(t, store)
	setCollectiveAdministrativeRoles(
		t,
		store,
		"ou=people,dc=example,dc=com",
		"collectiveAttributeSpecificArea",
	)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		return writer.Put(directory.Entry{
			DN: "olcOverlay={0}sssvlv,olcDatabase={1}mdb,cn=config",
			Attributes: []directory.Attribute{
				{Description: "olcOverlay", Values: stringValues("{0}sssvlv")},
			},
		}, false)
	}); err != nil {
		t.Fatalf("configure sssvlv overlay: %v", err)
	}

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if err := registry.ParseAndRegisterAttributeType(
		"( 1.2.3.10 NAME 'rankValue' EQUALITY integerMatch " +
			"ORDERING integerOrderingMatch SYNTAX " + schema.SyntaxInteger + " )",
	); err != nil {
		t.Fatalf("register rankValue: %v", err)
	}
	if err := registry.ParseAndRegisterAttributeType(
		"( 1.2.3.11 NAME 'c-rankValue' SUP rankValue COLLECTIVE )",
	); err != nil {
		t.Fatalf("register c-rankValue: %v", err)
	}

	const (
		rootDN       = "cn=admin,dc=example,dc=com"
		rootPassword = "admin-secret"
	)
	address, stop := startServer(t, store, Config{
		RootDN:       rootDN,
		RootPassword: []byte(rootPassword),
		Schema:       registry,
	})
	defer stop()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	defer client.Close()
	if err := client.Bind(rootDN, rootPassword); err != nil {
		t.Fatalf("Bind(): %v", err)
	}
	if err := client.Add(newPersonAddRequest("collective-sort-bob")); err != nil {
		t.Fatalf("Add(Bob): %v", err)
	}

	for _, source := range []struct {
		cn             string
		base           string
		collectiveRank string
	}{
		{cn: "alice-rank", base: "uid=alice", collectiveRank: "2"},
		{cn: "bob-rank", base: "uid=collective-sort-bob", collectiveRank: "1"},
	} {
		add := ldap.NewAddRequest(
			"cn="+source.cn+",ou=people,dc=example,dc=com",
			nil,
		)
		add.Attribute("objectClass", []string{
			"subentry",
			"collectiveAttributeSubentry",
		})
		add.Attribute("cn", []string{source.cn})
		add.Attribute(
			"subtreeSpecification",
			[]string{`{ base "` + source.base + `" }`},
		)
		add.Attribute("c-rankValue", []string{source.collectiveRank})
		if err := client.Add(add); err != nil {
			t.Fatalf("Add(%s): %v", source.cn, err)
		}
	}

	searchRequest := func(controls []ldap.Control) *ldap.SearchRequest {
		return ldap.NewSearchRequest(
			"ou=people,dc=example,dc=com",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			"(objectClass=inetOrgPerson)",
			[]string{"uid", "c-rankValue"},
			controls,
		)
	}
	sortControl := newSortControl(ldap.SortKey{
		AttributeType: "c-rankValue",
	})
	sorted, err := client.Search(searchRequest([]ldap.Control{sortControl}))
	if err != nil {
		t.Fatalf("sorted collective Search(): %v", err)
	}
	assertSortedUIDs(t, sorted, []string{"collective-sort-bob", "alice"})

	window, err := client.Search(searchRequest([]ldap.Control{
		sortControl,
		newVirtualListViewControl(ldapwire.VirtualListViewRequest{
			ByOffset:     true,
			Offset:       2,
			ContentCount: 2,
		}),
	}))
	if err != nil {
		t.Fatalf("collective VLV Search(): %v", err)
	}
	assertSortedUIDs(t, window, []string{"alice"})
	if window.Entries[0].GetAttributeValue("c-rankValue") != "2" {
		t.Fatalf("collective VLV entry = %#v", window.Entries[0])
	}
	response := decodeVirtualListViewResponse(t, window)
	if response.TargetPosition != 2 || response.ContentCount != 2 {
		t.Fatalf("collective VLV response = %#v", response)
	}
}

func TestCollectiveAttributePlanDerivesValuesWithoutWriteback(t *testing.T) {
	t.Parallel()

	registry := collectiveServerRegistry(t)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })

	entries := []directory.Entry{
		collectiveAdministrativePointEntry(
			"ou=People,dc=example,dc=com",
			"collectiveAttributeSpecificArea",
		),
		collectiveServerSource(
			"cn=first,ou=People,dc=example,dc=com",
			"{}",
			directory.Attribute{
				Description: "c-description",
				Values:      stringValues("Shared", "First"),
			},
			directory.Attribute{
				Description: "c-description;lang-en",
				Values:      stringValues("English"),
			},
		),
		collectiveServerSource(
			"cn=second,ou=People,dc=example,dc=com",
			"{ specificationFilter item:person }",
			directory.Attribute{
				Description: "collectiveDescription",
				Values:      stringValues("shared", "Second"),
			},
		),
		collectiveServerSource(
			"cn=team,ou=People,dc=example,dc=com",
			`{ base "ou=Team", minimum 1 }`,
			directory.Attribute{
				Description: "c-description",
				Values:      stringValues("Team"),
			},
		),
		collectiveServerSource(
			"cn=broken,ou=People,dc=example,dc=com",
			"{ minimum -1 }",
			directory.Attribute{
				Description: "c-description",
				Values:      stringValues("Broken"),
			},
		),
		collectiveServerPerson(
			"uid=alice,ou=People,dc=example,dc=com",
			nil,
		),
		collectiveServerPerson(
			"uid=bob,ou=Team,ou=People,dc=example,dc=com",
			nil,
		),
		collectiveServerPerson(
			"uid=carol,ou=People,dc=example,dc=com",
			stringValues("1.2.3.4"),
		),
		collectiveServerPerson(
			"uid=dave,ou=People,dc=example,dc=com",
			stringValues("excludeAllCollectiveAttributes"),
		),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	if err := store.View(context.Background(), func(reader storage.Reader) error {
		plan, err := buildCollectiveAttributePlan(registry, reader)
		if err != nil {
			return err
		}
		if len(plan.sources) != 3 {
			t.Fatalf("collective sources = %d, want 3", len(plan.sources))
		}

		alice := collectiveStoredEntry(t, reader, "uid=alice,ou=People,dc=example,dc=com")
		derivedAlice, err := plan.apply(alice)
		if err != nil {
			return err
		}
		assertCollectiveStringValues(
			t,
			derivedAlice.Values("c-description"),
			"Shared",
			"First",
			"Second",
		)
		assertCollectiveStringValues(
			t,
			derivedAlice.Values("c-description;lang-en"),
			"English",
		)
		assertCollectiveStringValues(
			t,
			derivedAlice.Values("collectiveAttributeSubentries"),
			"cn=first,ou=People,dc=example,dc=com",
			"cn=second,ou=People,dc=example,dc=com",
		)

		bob := collectiveStoredEntry(
			t,
			reader,
			"uid=bob,ou=Team,ou=People,dc=example,dc=com",
		)
		derivedBob, err := plan.apply(bob)
		if err != nil {
			return err
		}
		assertCollectiveStringValues(
			t,
			derivedBob.Values("c-description"),
			"Shared",
			"First",
			"Second",
			"Team",
		)

		for _, name := range []string{"carol", "dave"} {
			entry := collectiveStoredEntry(
				t,
				reader,
				"uid="+name+",ou=People,dc=example,dc=com",
			)
			derived, err := plan.apply(entry)
			if err != nil {
				return err
			}
			if derived.HasAttribute("c-description") {
				t.Fatalf("%s retained an excluded collective attribute", name)
			}
			if !derived.HasAttribute("collectiveAttributeSubentries") {
				t.Fatalf("%s lost affecting subentry references", name)
			}
		}

		source := collectiveStoredEntry(
			t,
			reader,
			"cn=first,ou=People,dc=example,dc=com",
		)
		derivedSource, err := plan.apply(source)
		if err != nil {
			return err
		}
		if derivedSource.HasAttribute("collectiveAttributeSubentries") ||
			len(derivedSource.Values("c-description")) != 2 {
			t.Fatal("collective values were derived onto a subentry")
		}

		storedAlice := collectiveStoredEntry(
			t,
			reader,
			"uid=alice,ou=People,dc=example,dc=com",
		)
		if storedAlice.HasAttribute("c-description") ||
			storedAlice.HasAttribute("collectiveAttributeSubentries") {
			t.Fatal("derived collective values were written to storage")
		}
		return nil
	}); err != nil {
		t.Fatalf("evaluate collective plan: %v", err)
	}
}

func TestCollectiveAttributePlanIsNoOpWithoutSources(t *testing.T) {
	t.Parallel()

	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		plan, err := buildCollectiveAttributePlan(registry, reader)
		if err != nil {
			return err
		}
		if len(plan.sources) != 0 {
			t.Fatalf("collective sources = %d, want 0", len(plan.sources))
		}
		return nil
	}); err != nil {
		t.Fatalf("buildCollectiveAttributePlan(): %v", err)
	}
}

func TestCollectiveAttributePlanUsesObjectClassIndex(t *testing.T) {
	t.Parallel()

	registry := collectiveServerRegistry(t)
	normalizer, _, err := loadDatabaseEqualityIndexes(directory.Entry{
		DN: "olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{{
			Description: "olcDbIndex",
			Values:      stringValues("objectClass eq"),
		}},
	}, registry)
	if err != nil {
		t.Fatalf("load objectClass index: %v", err)
	}
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	entries := []directory.Entry{
		collectiveAdministrativePointEntry(
			"ou=People,dc=example,dc=com",
			"collectiveAttributeSpecificArea",
		),
		collectiveServerSource(
			"cn=indexed,ou=People,dc=example,dc=com",
			"{}",
			directory.Attribute{
				Description: "c-description",
				Values:      stringValues("Indexed"),
			},
		),
		collectiveServerPerson(
			"uid=alice,ou=People,dc=example,dc=com",
			nil,
		),
	}
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		indexed := storage.WriterInPartitionWithNormalizer(writer, "db", normalizer)
		for _, entry := range entries {
			if err := indexed.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed indexed collective store: %v", err)
	}
	if err := store.View(context.Background(), func(reader storage.Reader) error {
		indexed := storage.ReaderInPartitionWithNormalizer(reader, "db", normalizer)
		plan, err := buildCollectiveAttributePlan(registry, indexed)
		if err != nil {
			return err
		}
		if len(plan.sources) != 1 {
			t.Fatalf("indexed collective sources = %d, want 1", len(plan.sources))
		}
		personDN, err := directory.ParseDN(entries[2].DN)
		if err != nil {
			return err
		}
		person, err := indexed.Get(personDN)
		if err != nil {
			return err
		}
		derived, err := plan.apply(person)
		if err != nil {
			return err
		}
		assertCollectiveStringValues(
			t,
			derived.Values("c-description"),
			"Indexed",
		)
		return nil
	}); err != nil {
		t.Fatalf("evaluate indexed collective plan: %v", err)
	}
}

func TestCollectiveAttributePlanSharedCacheTracksStorageRevision(t *testing.T) {
	t.Parallel()

	registry := collectiveServerRegistry(t)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	shared := newCollectiveAttributePlanSharedCache()
	entry := directory.Entry{
		DN: "uid=alice,dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "objectClass",
			Values:      stringValues("top", "person"),
		}},
	}

	scans := 0
	apply := func(revision uint64) error {
		return store.View(context.Background(), func(reader storage.Reader) error {
			versioned := &collectivePlanCountingReader{
				Reader: reader, revision: revision, scans: &scans,
			}
			_, err := newCollectiveAttributePlanCache(registry, shared).apply(
				"content", versioned, entry,
			)
			return err
		})
	}

	if err := apply(7); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := apply(7); err != nil {
		t.Fatalf("cached apply: %v", err)
	}
	if scans != 1 {
		t.Fatalf("same-revision plan scans = %d, want 1", scans)
	}
	if err := apply(8); err != nil {
		t.Fatalf("new storage revision apply: %v", err)
	}
	if scans != 1 {
		t.Fatalf("unrelated storage revision plan scans = %d, want 1", scans)
	}
	shared.invalidate()
	if err := apply(8); err != nil {
		t.Fatalf("invalidated apply: %v", err)
	}
	if scans != 2 {
		t.Fatalf("new-revision plan scans = %d, want 2", scans)
	}
}

type collectivePlanCountingReader struct {
	storage.Reader
	revision uint64
	scans    *int
}

func (reader *collectivePlanCountingReader) StorageSnapshotRevision() (uint64, bool) {
	return reader.revision, true
}

func (reader *collectivePlanCountingReader) ForEach(
	visit func(directory.Entry) error,
) error {
	*reader.scans = *reader.scans + 1
	return reader.Reader.ForEach(visit)
}

func collectiveServerRegistry(t *testing.T) *schema.Registry {
	t.Helper()
	registry, err := schema.NewBuiltinRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinRegistry(): %v", err)
	}
	if err := registry.ParseAndRegisterAttributeType(
		"( 1.2.3.4 NAME ( 'c-description' 'collectiveDescription' ) " +
			"SUP description COLLECTIVE )",
	); err != nil {
		t.Fatalf("register collective attribute: %v", err)
	}
	return registry
}

func collectiveServerSource(
	dn string,
	specification string,
	attributes ...directory.Attribute,
) directory.Entry {
	entry := directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{
				Description: "objectClass",
				Values: stringValues(
					"subentry",
					"collectiveAttributeSubentry",
				),
			},
			{Description: "cn", Values: stringValues("source")},
			{
				Description: "subtreeSpecification",
				Values:      stringValues(specification),
			},
		},
	}
	entry.Attributes = append(entry.Attributes, attributes...)
	return entry
}

func collectiveAdministrativePointEntry(
	dn string,
	roles ...string,
) directory.Entry {
	return directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "administrativeRole", Values: stringValues(roles...)},
		},
	}
}

func setCollectiveAdministrativeRoles(
	t *testing.T,
	store storage.Store,
	rawDN string,
	roles ...string,
) {
	t.Helper()
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		dn, err := directory.ParseDN(rawDN)
		if err != nil {
			return err
		}
		entry, err := writer.Get(dn)
		if err != nil {
			return err
		}
		entry.ReplaceValues("administrativeRole", stringValues(roles...))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("set collective administrative roles on %q: %v", rawDN, err)
	}
}

func collectiveServerPerson(dn string, exclusions [][]byte) directory.Entry {
	entry := directory.Entry{
		DN: dn,
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("inetOrgPerson")},
			{Description: "uid", Values: stringValues("user")},
			{Description: "cn", Values: stringValues("User")},
			{Description: "sn", Values: stringValues("Example")},
		},
	}
	if len(exclusions) > 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "collectiveExclusions",
			Values:      exclusions,
		})
	}
	return entry
}

func collectiveStoredEntry(
	t *testing.T,
	reader storage.Reader,
	rawDN string,
) directory.Entry {
	t.Helper()
	dn, err := directory.ParseDN(rawDN)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", rawDN, err)
	}
	entry, err := reader.Get(dn)
	if err != nil {
		t.Fatalf("Get(%q): %v", rawDN, err)
	}
	return entry
}

func assertCollectiveStringValues(t *testing.T, actual [][]byte, expected ...string) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("values = %q, want %q", actual, expected)
	}
	for index := range expected {
		if string(actual[index]) != expected[index] {
			t.Fatalf("values = %q, want %q", actual, expected)
		}
	}
}
