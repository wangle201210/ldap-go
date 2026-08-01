package server

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const testUniqueOverlayDN = "olcOverlay={0}unique,olcDatabase={1}mdb,cn=config"

func TestUniqueOverlayOnlineLifecycleAndWrites(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	config := Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	}
	address, stop := startServer(t, store, config)

	configClient := bindUniqueClient(t, address, "cn=config", "config-secret")
	dataClient := bindUniqueClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)

	overlay := ldap.NewAddRequest(testUniqueOverlayDN, nil)
	overlay.Attribute("objectClass", []string{"olcOverlayConfig", "olcUniqueConfig"})
	overlay.Attribute("olcOverlay", []string{"{0}unique"})
	overlay.Attribute("olcUniqueURI", []string{
		"{0}ldap:///ou=people,dc=example,dc=com?uid,mail?one?" +
			"(objectClass=inetOrgPerson)",
		"{1}ignore ldap:///ou=archive,dc=example,dc=com?" +
			"objectClass,uid,cn,sn?one?(objectClass=inetOrgPerson)",
		"{2}strict ldap:///ou=people,dc=example,dc=com?" +
			"description?one?(objectClass=inetOrgPerson)",
	})
	if err := configClient.Add(overlay); err != nil {
		t.Fatalf("Add(unique overlay): %v", err)
	}

	sourceDN := "uid=unique-source,ou=people,dc=example,dc=com"
	source := uniquePersonAdd(sourceDN, "unique-source", "Source")
	source.Attribute("mail", []string{"Shared@Example.COM"})
	source.Attribute("description", []string{"source-description"})
	if err := dataClient.Add(source); err != nil {
		t.Fatalf("Add(unique source): %v", err)
	}

	duplicateUID := ldap.NewAddRequest(
		"uid=duplicate-uid,ou=people,dc=example,dc=com",
		nil,
	)
	duplicateUID.Attribute("objectClass", []string{"inetOrgPerson"})
	duplicateUID.Attribute("uid", []string{"duplicate-uid", "unique-source"})
	duplicateUID.Attribute("cn", []string{"duplicate-uid"})
	duplicateUID.Attribute("sn", []string{"Duplicate"})
	assertLDAPResultCode(
		t,
		dataClient.Add(duplicateUID),
		ldap.LDAPResultConstraintViolation,
	)

	duplicateMail := uniquePersonAdd(
		"uid=duplicate-mail,ou=people,dc=example,dc=com",
		"duplicate-mail",
		"Duplicate",
	)
	duplicateMail.Attribute("mail", []string{"shared@example.com"})
	assertLDAPResultCode(
		t,
		dataClient.Add(duplicateMail),
		ldap.LDAPResultConstraintViolation,
	)

	archive := uniquePersonAdd(
		"uid=archive-one,ou=archive,dc=example,dc=com",
		"archive-one",
		"Archive",
	)
	archive.Attribute("description", []string{"Archive Description"})
	if err := dataClient.Add(archive); err != nil {
		t.Fatalf("Add(first ignore-domain entry): %v", err)
	}
	archiveDuplicate := uniquePersonAdd(
		"uid=archive-two,ou=archive,dc=example,dc=com",
		"archive-two",
		"Different",
	)
	archiveDuplicate.Attribute("description", []string{"archive description"})
	assertLDAPResultCode(
		t,
		dataClient.Add(archiveDuplicate),
		ldap.LDAPResultConstraintViolation,
	)

	strictOne := uniquePersonAdd(
		"uid=strict-one,ou=people,dc=example,dc=com",
		"strict-one",
		"Strict",
	)
	strictOne.Attribute("description", []string{"strict-one"})
	if err := dataClient.Add(strictOne); err != nil {
		t.Fatalf("Add(strict one): %v", err)
	}
	strictTwoDN := "uid=strict-two,ou=people,dc=example,dc=com"
	strictTwo := uniquePersonAdd(strictTwoDN, "strict-two", "Strict")
	strictTwo.Attribute("description", []string{"strict-two"})
	if err := dataClient.Add(strictTwo); err != nil {
		t.Fatalf("Add(strict two): %v", err)
	}
	removeStrictValue := ldap.NewModifyRequest(strictTwoDN, nil)
	removeStrictValue.Replace("description", []string{})
	assertLDAPResultCode(
		t,
		dataClient.Modify(removeStrictValue),
		ldap.LDAPResultConstraintViolation,
	)

	duplicateModify := ldap.NewModifyRequest(sourceDN, nil)
	duplicateModify.Add("uid", []string{"alice"})
	assertLDAPResultCode(
		t,
		dataClient.Modify(duplicateModify),
		ldap.LDAPResultConstraintViolation,
	)
	rename := ldap.NewModifyDNRequest(sourceDN, "uid=alice", true, "")
	assertLDAPResultCode(
		t,
		dataClient.ModifyDN(rename),
		ldap.LDAPResultConstraintViolation,
	)

	access := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	access.Replace("olcAccess", []string{
		"{0}to attrs=userPassword by self =xw by anonymous auth by * none",
		"{1}to * by dn.exact=\"uid=alice,ou=people,dc=example,dc=com\" " +
			"write by users read by * none",
	})
	if err := configClient.Modify(access); err != nil {
		t.Fatalf("Modify(write-only test ACL): %v", err)
	}
	userClient := bindUniqueClient(
		t,
		address,
		"uid=alice,ou=people,dc=example,dc=com",
		"secret",
	)
	nonManagerRelax := uniquePersonAdd(
		"uid=normal-relax,ou=people,dc=example,dc=com",
		"normal-relax",
		"Normal",
	)
	nonManagerRelax.Controls = []ldap.Control{relaxLDAPControl()}
	nonManagerRelax.Attribute("mail", []string{"shared@example.com"})
	assertLDAPResultCode(
		t,
		userClient.Add(nonManagerRelax),
		ldap.LDAPResultConstraintViolation,
	)
	userClient.Close()

	managerRelax := uniquePersonAdd(
		"uid=manager-relax,ou=people,dc=example,dc=com",
		"manager-relax",
		"Manager",
	)
	managerRelax.Controls = []ldap.Control{relaxLDAPControl()}
	managerRelax.Attribute("mail", []string{"shared@example.com"})
	if err := dataClient.Add(managerRelax); err != nil {
		t.Fatalf("Add(manager Relax): %v", err)
	}

	multiURIValue := "ldap:///ou=people,dc=example,dc=com?uid?one?(sn=Scoped) " +
		"ldap:///ou=archive,dc=example,dc=com?mail?one"
	filtered := ldap.NewModifyRequest(testUniqueOverlayDN, nil)
	filtered.Replace("olcUniqueURI", []string{multiURIValue})
	if err := configClient.Modify(filtered); err != nil {
		t.Fatalf("Modify(filtered unique domain): %v", err)
	}
	filteredSource := uniquePersonAdd(
		"uid=filter-source,ou=people,dc=example,dc=com",
		"filter-source",
		"Scoped",
	)
	if err := dataClient.Add(filteredSource); err != nil {
		t.Fatalf("Add(filtered source): %v", err)
	}
	filteredOtherDN := "uid=filter-other,ou=people,dc=example,dc=com"
	filteredOther := uniquePersonAdd(filteredOtherDN, "filter-other", "Other")
	if err := dataClient.Add(filteredOther); err != nil {
		t.Fatalf("Add(entry outside filtered domain): %v", err)
	}
	filteredModify := ldap.NewModifyRequest(filteredOtherDN, nil)
	filteredModify.Add("uid", []string{"filter-source"})
	assertLDAPResultCode(
		t,
		dataClient.Modify(filteredModify),
		ldap.LDAPResultConstraintViolation,
	)
	archiveMailSource := uniquePersonAdd(
		"uid=archive-mail-source,ou=archive,dc=example,dc=com",
		"archive-mail-source",
		"Archive Mail Source",
	)
	archiveMailSource.Attribute("mail", []string{"archive-unique@example.com"})
	if err := dataClient.Add(archiveMailSource); err != nil {
		t.Fatalf("Add(second URI source): %v", err)
	}
	archiveMailDuplicate := uniquePersonAdd(
		"uid=archive-mail-duplicate,ou=archive,dc=example,dc=com",
		"archive-mail-duplicate",
		"Archive Mail Duplicate",
	)
	archiveMailDuplicate.Attribute("mail", []string{"ARCHIVE-UNIQUE@example.com"})
	assertLDAPResultCode(
		t,
		dataClient.Add(archiveMailDuplicate),
		ldap.LDAPResultConstraintViolation,
	)

	invalid := ldap.NewModifyRequest(testUniqueOverlayDN, nil)
	invalid.Replace("olcUniqueURI", []string{
		"ldap:///ou=people,dc=example,dc=com?undefinedUnique?one",
	})
	assertLDAPResultCode(
		t,
		configClient.Modify(invalid),
		ldap.LDAPResultConstraintViolation,
	)
	configured := readStoredEntry(t, store, testUniqueOverlayDN).Values("olcUniqueURI")
	if len(configured) != 1 || string(configured[0]) != multiURIValue {
		t.Fatalf("unique config after rollback = %q", configured)
	}

	legacy := ldap.NewModifyRequest(testUniqueOverlayDN, nil)
	legacy.Delete("olcUniqueURI", nil)
	legacy.Add("olcUniqueAttribute", []string{"description"})
	legacy.Add("olcUniqueBase", []string{"ou=people,dc=example,dc=com"})
	legacy.Add("olcUniqueStrict", []string{"FALSE"})
	if err := configClient.Modify(legacy); err != nil {
		t.Fatalf("Modify(to legacy unique configuration): %v", err)
	}
	legacyDuplicate := uniquePersonAdd(
		"uid=legacy-duplicate,ou=people,dc=example,dc=com",
		"legacy-duplicate",
		"Legacy",
	)
	legacyDuplicate.Attribute("description", []string{"SOURCE-DESCRIPTION"})
	assertLDAPResultCode(
		t,
		dataClient.Add(legacyDuplicate),
		ldap.LDAPResultConstraintViolation,
	)

	configClient.Close()
	dataClient.Close()
	stop()

	address, stop = startServer(t, store, config)
	defer stop()
	dataClient = bindUniqueClient(
		t,
		address,
		"cn=admin,dc=example,dc=com",
		"admin-secret",
	)
	defer dataClient.Close()
	restartDuplicate := uniquePersonAdd(
		"uid=restart-duplicate,ou=people,dc=example,dc=com",
		"restart-duplicate",
		"Restart",
	)
	restartDuplicate.Attribute("description", []string{"source-description"})
	assertLDAPResultCode(
		t,
		dataClient.Add(restartDuplicate),
		ldap.LDAPResultConstraintViolation,
	)
}

func TestUniqueOverlayConcurrentAddsAreAtomic(t *testing.T) {
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedOnlineConfiguration(t, store)
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		return writer.Put(uniqueOverlayEntry("{0}"), false)
	}); err != nil {
		t.Fatalf("seed unique overlay: %v", err)
	}
	if err := store.Update(t.Context(), func(writer storage.Writer) error {
		entry := uniqueOverlayEntry("{0}")
		entry.ReplaceValues("olcUniqueURI", stringValues(
			"serialize ldap:///ou=people,dc=example,dc=com?mail?one",
		))
		return writer.Put(entry, true)
	}); err != nil {
		t.Fatalf("configure serialized unique overlay: %v", err)
	}

	address, stop := startServer(t, store, Config{
		RootDN:       "cn=admin,dc=example,dc=com",
		RootPassword: []byte("admin-secret"),
	})
	defer stop()

	const requests = 16
	start := make(chan struct{})
	results := make(chan error, requests)
	var wait sync.WaitGroup
	for index := 0; index < requests; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			client, err := ldap.DialURL("ldap://" + address)
			if err != nil {
				results <- err
				return
			}
			defer client.Close()
			if err := client.Bind(
				"cn=admin,dc=example,dc=com",
				"admin-secret",
			); err != nil {
				results <- err
				return
			}
			<-start
			request := uniquePersonAdd(
				fmt.Sprintf("uid=concurrent-%d,ou=people,dc=example,dc=com", index),
				fmt.Sprintf("concurrent-%d", index),
				"Concurrent",
			)
			request.Attribute("mail", []string{"one-owner@example.com"})
			results <- client.Add(request)
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	successes := 0
	constraints := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) &&
			ldapErr.ResultCode == ldap.LDAPResultConstraintViolation {
			constraints++
			continue
		}
		t.Fatalf("concurrent Add returned %v", err)
	}
	if successes != 1 || constraints != requests-1 {
		t.Fatalf(
			"concurrent results: success=%d constraint=%d",
			successes,
			constraints,
		)
	}
}

func uniquePersonAdd(dn, uid, sn string) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"inetOrgPerson"})
	request.Attribute("uid", []string{uid})
	request.Attribute("cn", []string{uid})
	request.Attribute("sn", []string{sn})
	return request
}

func bindUniqueClient(t *testing.T, address, dn, password string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL("ldap://" + address)
	if err != nil {
		t.Fatalf("DialURL(): %v", err)
	}
	if err := client.Bind(dn, password); err != nil {
		client.Close()
		t.Fatalf("Bind(%s): %v", dn, err)
	}
	return client
}
