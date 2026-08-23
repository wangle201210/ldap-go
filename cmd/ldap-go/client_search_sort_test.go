package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func TestLDAPSearchClientSideSort(t *testing.T) {
	entries := []*ldap.Entry{
		{
			DN:         "uid=zulu,ou=people,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{ldap.NewEntryAttribute("CN", []string{"Zulu", "alpha"})},
		},
		{DN: "uid=missing,ou=people,dc=example,dc=com"},
		{
			DN:         "uid=alpha,ou=people,dc=example,dc=com",
			Attributes: []*ldap.EntryAttribute{ldap.NewEntryAttribute("cn", []string{"alpha", "Zulu"})},
		},
	}

	sorted, err := sortLDAPSearchEntries(entries, "cn")
	if err != nil {
		t.Fatalf("sortLDAPSearchEntries(cn): %v", err)
	}
	want := []string{
		"uid=missing,ou=people,dc=example,dc=com",
		"uid=alpha,ou=people,dc=example,dc=com",
		"uid=zulu,ou=people,dc=example,dc=com",
	}
	got := make([]string, len(sorted))
	for index := range sorted {
		got[index] = sorted[index].DN
	}
	if !slices.Equal(got, want) {
		t.Fatalf("sorted DNs = %q, want %q", got, want)
	}

	byDN, err := sortLDAPSearchEntries([]*ldap.Entry{entries[0], entries[2]}, "")
	if err != nil {
		t.Fatalf("sortLDAPSearchEntries(DN): %v", err)
	}
	if got := []string{byDN[0].DN, byDN[1].DN}; !slices.Equal(got, want[1:]) {
		t.Fatalf("DN-sorted entries = %q, want %q", got, want[1:])
	}
	if _, err := sortLDAPSearchEntries([]*ldap.Entry{nil}, "cn"); err == nil {
		t.Fatal("sortLDAPSearchEntries accepted a nil entry")
	}
}

func TestLDAPSearchUserFriendlyDN(t *testing.T) {
	ufn, components, err := ldapSearchUserFriendlyDN(
		`cn=Smith\, John+uid=jsmith,ou=People,dc=example,dc=com`,
	)
	if err != nil {
		t.Fatalf("ldapSearchUserFriendlyDN(): %v", err)
	}
	if want := `Smith\2C John + jsmith, People, example.com`; ufn != want {
		t.Fatalf("UFN = %q, want %q", ufn, want)
	}
	if want := []string{`Smith\2C John + jsmith`, "People", "example", "com"}; !slices.Equal(components, want) {
		t.Fatalf("UFN components = %q, want %q", components, want)
	}

	ufn, components, err = ldapSearchUserFriendlyDN(`cn=#04015a,dc=example,dc=com`)
	if err != nil {
		t.Fatalf("ldapSearchUserFriendlyDN(binary AVA): %v", err)
	}
	if ufn != "#04015A, example.com" ||
		!slices.Equal(components, []string{"#04015A", "example", "com"}) {
		t.Fatalf("binary UFN = %q, components %q", ufn, components)
	}

	ufn, components, err = ldapSearchUserFriendlyDN(`uid=alice;dc=#04015A;dc=com`)
	if err != nil {
		t.Fatalf("ldapSearchUserFriendlyDN(binary DC): %v", err)
	}
	if ufn != "" ||
		!slices.Equal(components, []string{"alice", "#04015A", "com"}) {
		t.Fatalf("binary DC UFN = %q, components %q", ufn, components)
	}

	ufn, components, err = ldapSearchUserFriendlyDN(`uid=alice,dc=\3Ainvalid,dc=example,dc=com`)
	if err != nil {
		t.Fatalf("ldapSearchUserFriendlyDN(non-printable DC): %v", err)
	}
	if ufn != "" || !slices.Equal(
		components,
		[]string{"alice", ":invalid", "example", "com"},
	) {
		t.Fatalf("non-printable DC UFN = %q, components %q", ufn, components)
	}
}

func TestLDAPSearchSortAndUFNEndToEnd(t *testing.T) {
	uri := startLDAPClientToolServer(t, nil)
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapsearch", "-H", uri, "-x",
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
			"-b", clientToolPeopleDN, "-s", "one", "-S", "cn", "-u", "-LLL",
			"(objectClass=inetOrgPerson)", "cn",
		},
		"",
	)
	if exitCode != 0 || stderr != "" {
		t.Fatalf("ldapsearch -S/-u exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	entries := parseLDAPSearchOutput(t, stdout)
	if len(entries) != 2 || entries[0].DN != "uid=alice,"+clientToolPeopleDN ||
		entries[1].DN != "uid=bob,"+clientToolPeopleDN {
		t.Fatalf("sorted ldapsearch entries = %#v", entries)
	}
	for _, want := range []string{
		"ufn: alice, people, example.com",
		"ufn: bob, people, example.com",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("ldapsearch output does not contain %q: %q", want, stdout)
		}
	}

	var output bytes.Buffer
	if err := (&ldapSearchLDIFOutput{
		writer:        &output,
		minimal:       true,
		sort:          true,
		sortAttribute: "",
		includeUFN:    true,
	}).writeEntries([]*ldap.Entry{entries[1], entries[0]}); err != nil {
		t.Fatalf("write sorted UFN LDIF: %v", err)
	}
	if !strings.HasPrefix(output.String(), "dn: uid=alice,") {
		t.Fatalf("DN-sorted LDIF = %q", output.String())
	}
}

func TestLDAPSearchSortOptionValidation(t *testing.T) {
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{"ldapsearch", "-x", "-S", "cn\nmalicious", "-LLL"},
		"",
	)
	if exitCode != 1 || stdout != "" || !strings.Contains(stderr, "invalid -S attribute") {
		t.Fatalf("unsafe -S exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
}

func TestLDAPSearchSortsEachPageLikeOpenLDAP(t *testing.T) {
	uri := startLDAPClientSortPagingServer(t)
	stdout, stderr, exitCode := runLDAPClientCommand(
		[]string{
			"ldapsearch", "-H", uri, "-x",
			"-D", clientToolRootDN, "-w", clientToolRootPassword,
			"-b", clientToolPeopleDN, "-s", "one", "-S", "cn",
			"-E", "pr=2/noprompt", "-LLL", "(objectClass=inetOrgPerson)", "cn",
		},
		"",
	)
	if exitCode != 0 || stderr != "" {
		t.Fatalf("paged ldapsearch -S exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	entries := parseLDAPSearchOutput(t, stdout)
	got := make([]string, len(entries))
	for index := range entries {
		got[index] = entries[index].DN
	}
	want := []string{
		"uid=alice," + clientToolPeopleDN,
		"uid=aaron," + clientToolPeopleDN,
		"uid=zeta," + clientToolPeopleDN,
		"uid=bob," + clientToolPeopleDN,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("page-sorted DNs = %q, want %q", got, want)
	}
}

func TestOpenLDAPReferenceLDAPSearchSortAndUFN(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") == "" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 to run the OpenLDAP ldapsearch reference test")
	}
	if got := os.Getenv("OPENLDAP_REFERENCE_VERIFIED"); got != "1" {
		t.Fatalf("OPENLDAP_REFERENCE_VERIFIED = %q, want 1", got)
	}
	referenceTool, err := exec.LookPath("ldapsearch")
	if err != nil {
		t.Fatalf("find OpenLDAP ldapsearch: %v", err)
	}
	uri := startLDAPClientSortPagingServer(t)
	arguments := []string{
		"-H", uri, "-x", "-D", clientToolRootDN, "-w", clientToolRootPassword,
		"-b", clientToolPeopleDN, "-s", "one", "-S", "cn", "-u",
		"-E", "pr=2/noprompt", "-LLL", "(objectClass=inetOrgPerson)", "cn",
	}
	referenceOutput, err := exec.Command(referenceTool, arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("OpenLDAP ldapsearch: %v\n%s", err, referenceOutput)
	}
	localOutput, localStderr, exitCode := runLDAPClientCommand(
		append([]string{"ldapsearch"}, arguments...),
		"",
	)
	if exitCode != 0 || localStderr != "" {
		t.Fatalf("ldap-go ldapsearch exit=%d stdout=%q stderr=%q", exitCode, localOutput, localStderr)
	}
	referenceEntries := parseLDAPSearchOutput(t, string(referenceOutput))
	localEntries := parseLDAPSearchOutput(t, localOutput)
	if len(localEntries) != len(referenceEntries) {
		t.Fatalf("entry count: ldap-go=%d OpenLDAP=%d", len(localEntries), len(referenceEntries))
	}
	for index := range referenceEntries {
		if localEntries[index].DN != referenceEntries[index].DN ||
			localEntries[index].GetAttributeValue("ufn") != referenceEntries[index].GetAttributeValue("ufn") {
			t.Fatalf(
				"entry %d differs: ldap-go=(%q, %q) OpenLDAP=(%q, %q)",
				index,
				localEntries[index].DN,
				localEntries[index].GetAttributeValue("ufn"),
				referenceEntries[index].DN,
				referenceEntries[index].GetAttributeValue("ufn"),
			)
		}
	}

	invalidDCBase := `dc=\3Ainvalid,` + clientToolBaseDN
	invalidArguments := []string{
		"-H", uri, "-x", "-D", clientToolRootDN, "-w", clientToolRootPassword,
		"-b", invalidDCBase, "-s", "sub", "-u", "-LLL", "(objectClass=*)", "uid",
	}
	referenceOutput, err = exec.Command(referenceTool, invalidArguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("OpenLDAP ldapsearch invalid DC UFN: %v\n%s", err, referenceOutput)
	}
	localOutput, localStderr, exitCode = runLDAPClientCommand(
		append([]string{"ldapsearch"}, invalidArguments...),
		"",
	)
	if exitCode != 0 || localStderr != "" {
		t.Fatalf(
			"ldap-go invalid DC UFN exit=%d stdout=%q stderr=%q",
			exitCode,
			localOutput,
			localStderr,
		)
	}
	if referenceUFNs, localUFNs := strings.Count(string(referenceOutput), "\nufn:\n"),
		strings.Count(localOutput, "\nufn:\n"); referenceUFNs != 2 || localUFNs != referenceUFNs {
		t.Fatalf(
			"empty invalid-DC UFN count: ldap-go=%d OpenLDAP=%d\nldap-go:\n%s\nOpenLDAP:\n%s",
			localUFNs,
			referenceUFNs,
			localOutput,
			referenceOutput,
		)
	}
}

func startLDAPClientSortPagingServer(t *testing.T) string {
	t.Helper()
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	seedLDAPClientToolDirectory(t, store)
	if err := store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range []directory.Entry{
			{
				DN: "uid=aaron," + clientToolPeopleDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: clientToolValues("inetOrgPerson")},
					{Description: "uid", Values: clientToolValues("aaron")},
					{Description: "cn", Values: clientToolValues("Zulu Example")},
					{Description: "sn", Values: clientToolValues("Example")},
				},
			},
			{
				DN: "uid=zeta," + clientToolPeopleDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: clientToolValues("inetOrgPerson")},
					{Description: "uid", Values: clientToolValues("zeta")},
					{Description: "cn", Values: clientToolValues("Aardvark Example")},
					{Description: "sn", Values: clientToolValues("Example")},
				},
			},
			{
				DN: `dc=\3Ainvalid,` + clientToolBaseDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: clientToolValues("domain")},
					{Description: "dc", Values: clientToolValues(":invalid")},
				},
			},
			{
				DN: `uid=invalid,dc=\3Ainvalid,` + clientToolBaseDN,
				Attributes: []directory.Attribute{
					{Description: "objectClass", Values: clientToolValues("inetOrgPerson")},
					{Description: "uid", Values: clientToolValues("invalid")},
					{Description: "cn", Values: clientToolValues("Invalid DC")},
					{Description: "sn", Values: clientToolValues("DC")},
				},
			},
		} {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed sort paging entries: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	instance, err := server.New(server.Config{
		Store:        store,
		RootDN:       clientToolRootDN,
		RootPassword: []byte(clientToolRootPassword),
		AccessPolicy: clientToolAccessPolicy(t),
	})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("server.New(): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve(): %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("LDAP sort paging test server did not stop")
		}
	})
	return "ldap://" + listener.Addr().String()
}
