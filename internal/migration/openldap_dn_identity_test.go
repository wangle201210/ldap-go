package migration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPDNIdentityReferenceVersion = "2.6.13"
	openLDAPDNIdentityReferenceCommit  = "d172686d3d270bc961b78f3ff00d7019c8dfb094"
)

type openLDAPDNIdentityReferenceTools struct {
	slapadd   string
	slapcat   string
	slaptest  string
	schemaDir string
}

func TestOpenLDAPReferenceLDIFDNIdentityCompatibility(t *testing.T) {
	tools := requireOpenLDAPDNIdentityReferenceTools(t)
	configLDIF, contentLDIF := generateOpenLDAPDNIdentityReferenceLDIF(t, tools)

	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(configLDIF),
		ImportOptions{
			Database:             "0",
			Replace:              true,
			SkipSchemaValidation: true,
		},
	); err != nil {
		t.Fatalf("ImportLDIF(OpenLDAP configuration): %v\n%s", err, configLDIF)
	}
	if _, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(contentLDIF),
		ImportOptions{Database: "1", Replace: true},
	); err != nil {
		t.Fatalf("ImportLDIF(OpenLDAP content): %v\n%s", err, contentLDIF)
	}

	if err := store.View(context.Background(), func(reader storage.Reader) error {
		registry, err := importedSchemaRegistry(reader, nil)
		if err != nil {
			return fmt.Errorf("load imported OpenLDAP schema: %w", err)
		}

		exactUpper := mustOpenLDAPDNIdentityDN(t, registry, "exactName=Alice,dc=example,dc=com")
		exactLower := mustOpenLDAPDNIdentityDN(t, registry, "exactName=alice,dc=example,dc=com")
		if exactUpper.Equal(exactLower) || exactUpper.Key() == exactLower.Key() {
			t.Fatal("caseExactMatch naming DNs collapsed to one ldap-go identity")
		}
		assertOpenLDAPDNIdentityEntry(t, reader, exactUpper, "exactName", "Alice")
		assertOpenLDAPDNIdentityEntry(t, reader, exactLower, "exactName", "alice")

		foldUpper := mustOpenLDAPDNIdentityDN(t, registry, "foldName=Alice,dc=example,dc=com")
		foldLower := mustOpenLDAPDNIdentityDN(t, registry, "foldName=alice,dc=example,dc=com")
		if !foldUpper.Equal(foldLower) || foldUpper.Key() != foldLower.Key() {
			t.Fatal("caseIgnoreMatch naming case variants have different ldap-go identities")
		}
		upperEntry, err := reader.Get(foldUpper)
		if err != nil {
			return fmt.Errorf("get caseIgnoreMatch entry by original-case DN: %w", err)
		}
		lowerEntry, err := reader.Get(foldLower)
		if err != nil {
			return fmt.Errorf("get caseIgnoreMatch entry by lower-case DN: %w", err)
		}
		if upperEntry.DN != lowerEntry.DN {
			t.Fatalf(
				"caseIgnoreMatch DN variants resolved to different entries: %q and %q",
				upperEntry.DN,
				lowerEntry.DN,
			)
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect imported OpenLDAP DN identities: %v", err)
	}

	_, err := ImportLDIF(
		context.Background(),
		store,
		strings.NewReader(openLDAPDNIdentityFoldDuplicateLDIF),
		ImportOptions{Database: "1"},
	)
	if !errors.Is(err, storage.ErrEntryExists) {
		t.Fatalf(
			"ImportLDIF(caseIgnoreMatch case variant) error = %v, want %v",
			err,
			storage.ErrEntryExists,
		)
	}
}

func generateOpenLDAPDNIdentityReferenceLDIF(
	t *testing.T,
	tools openLDAPDNIdentityReferenceTools,
) (string, string) {
	t.Helper()
	root := t.TempDir()
	databaseDir := filepath.Join(root, "db")
	configDir := filepath.Join(root, "slapd.d")
	if err := os.Mkdir(databaseDir, 0o700); err != nil {
		t.Fatalf("create OpenLDAP DN identity database: %v", err)
	}
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatalf("create OpenLDAP DN identity configuration directory: %v", err)
	}

	configPath := filepath.Join(root, "slapd.conf")
	config := fmt.Sprintf(`include %s
include %s

attributetype ( 1.3.6.1.4.1.99999.913.1 NAME 'exactName' EQUALITY caseExactMatch ORDERING caseExactOrderingMatch SUBSTR caseExactSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
attributetype ( 1.3.6.1.4.1.99999.913.2 NAME 'foldName' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )
objectclass ( 1.3.6.1.4.1.99999.913.3 NAME 'dnIdentityEntry' SUP top STRUCTURAL MUST cn MAY ( exactName $ foldName ) )

database mdb
maxsize 1073741824
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
directory %s
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		databaseDir,
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write OpenLDAP DN identity configuration: %v", err)
	}
	contentPath := filepath.Join(root, "content.ldif")
	if err := os.WriteFile(contentPath, []byte(openLDAPDNIdentityContentLDIF), 0o600); err != nil {
		t.Fatalf("write OpenLDAP DN identity content: %v", err)
	}

	if output, err := exec.Command(
		tools.slapadd,
		"-f", configPath,
		"-l", contentPath,
	).CombinedOutput(); err != nil {
		t.Fatalf(
			"OpenLDAP 2.6.13 rejected distinct caseExactMatch naming DNs: %v\n%s",
			err,
			output,
		)
	}
	if output, err := exec.Command(
		tools.slaptest,
		"-f", configPath,
		"-F", configDir,
	).CombinedOutput(); err != nil {
		t.Fatalf("OpenLDAP 2.6.13 slaptest: %v\n%s", err, output)
	}

	configLDIF, err := exec.Command(
		tools.slapcat,
		"-F", configDir,
		"-n", "0",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("OpenLDAP 2.6.13 slapcat configuration: %v\n%s", err, configLDIF)
	}
	contentLDIF, err := exec.Command(
		tools.slapcat,
		"-f", configPath,
		"-n", "1",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("OpenLDAP 2.6.13 slapcat content: %v\n%s", err, contentLDIF)
	}
	for _, dn := range []string{
		"exactName=Alice,dc=example,dc=com",
		"exactName=alice,dc=example,dc=com",
		"foldName=Alice,dc=example,dc=com",
	} {
		if !strings.Contains(string(contentLDIF), "dn: "+dn+"\n") {
			t.Fatalf("OpenLDAP 2.6.13 slapcat omitted %q:\n%s", dn, contentLDIF)
		}
	}

	duplicatePath := filepath.Join(root, "case-ignore-duplicate.ldif")
	if err := os.WriteFile(
		duplicatePath,
		[]byte(openLDAPDNIdentityFoldDuplicateLDIF),
		0o600,
	); err != nil {
		t.Fatalf("write OpenLDAP caseIgnoreMatch duplicate: %v", err)
	}
	output, err := exec.Command(
		tools.slapadd,
		"-f", configPath,
		"-n", "1",
		"-l", duplicatePath,
	).CombinedOutput()
	if err == nil {
		t.Fatalf(
			"OpenLDAP 2.6.13 accepted caseIgnoreMatch DN case duplicate:\n%s",
			output,
		)
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("run OpenLDAP 2.6.13 caseIgnoreMatch duplicate probe: %v\n%s", err, output)
	}

	return string(configLDIF), string(contentLDIF)
}

func requireOpenLDAPDNIdentityReferenceTools(
	t *testing.T,
) openLDAPDNIdentityReferenceTools {
	t.Helper()
	if os.Getenv("LDAP_GO_OPENLDAP_REFERENCE_TESTS") == "" {
		t.Skip("set LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 to run the OpenLDAP DN identity reference test")
	}
	if got := os.Getenv("OPENLDAP_REFERENCE_VERIFIED"); got != "1" {
		t.Fatalf("OPENLDAP_REFERENCE_VERIFIED = %q, want 1", got)
	}
	if got := os.Getenv("OPENLDAP_ACTUAL_VERSION"); got != openLDAPDNIdentityReferenceVersion {
		t.Fatalf(
			"OPENLDAP_ACTUAL_VERSION = %q, want %q",
			got,
			openLDAPDNIdentityReferenceVersion,
		)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPDNIdentityReferenceCommit {
		t.Fatalf(
			"OPENLDAP_COMMIT = %q, want %q",
			got,
			openLDAPDNIdentityReferenceCommit,
		)
	}

	findTool := func(name, configured string, candidates ...string) string {
		t.Helper()
		if configured != "" {
			if info, err := os.Stat(configured); err == nil && !info.IsDir() {
				return configured
			}
			t.Skipf("configured OpenLDAP %s was not found at %q", name, configured)
		}
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
		for _, candidate := range candidates {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate
			}
		}
		t.Skipf("OpenLDAP %s is not installed", name)
		return ""
	}

	slapadd := findTool(
		"slapadd",
		os.Getenv("OPENLDAP_SLAPADD"),
		"/opt/homebrew/opt/openldap/sbin/slapadd",
		"/usr/sbin/slapadd",
	)
	siblingTool := func(name string) string {
		t.Helper()
		return findTool(name, "", filepath.Join(filepath.Dir(slapadd), name))
	}
	schemaDir := os.Getenv("OPENLDAP_SCHEMA_DIR")
	for _, candidate := range []string{
		schemaDir,
		"/opt/homebrew/etc/openldap/schema",
		"/etc/ldap/schema",
		"/etc/openldap/schema",
	} {
		if candidate == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(candidate, "core.schema")); err == nil {
			schemaDir = candidate
			break
		}
	}
	if schemaDir == "" {
		t.Skip("OpenLDAP schema directory was not found")
	}

	return openLDAPDNIdentityReferenceTools{
		slapadd:   slapadd,
		slapcat:   siblingTool("slapcat"),
		slaptest:  siblingTool("slaptest"),
		schemaDir: schemaDir,
	}
}

func mustOpenLDAPDNIdentityDN(
	t *testing.T,
	normalizer interface {
		NormalizeDN(string) (directory.DN, error)
	},
	value string,
) directory.DN {
	t.Helper()
	dn, err := normalizer.NormalizeDN(value)
	if err != nil {
		t.Fatalf("normalize OpenLDAP DN identity %q: %v", value, err)
	}
	return dn
}

func assertOpenLDAPDNIdentityEntry(
	t *testing.T,
	reader storage.Reader,
	dn directory.DN,
	attribute string,
	want string,
) {
	t.Helper()
	entry, err := reader.Get(dn)
	if err != nil {
		t.Fatalf("get %q: %v", dn.String(), err)
	}
	values := entry.Values(attribute)
	if len(values) != 1 || string(values[0]) != want {
		t.Fatalf("%s on %q = %q, want [%q]", attribute, entry.DN, values, want)
	}
}

const openLDAPDNIdentityContentLDIF = `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: exactName=Alice,dc=example,dc=com
objectClass: top
objectClass: dnIdentityEntry
cn: Exact Upper
exactName: Alice

dn: exactName=alice,dc=example,dc=com
objectClass: top
objectClass: dnIdentityEntry
cn: Exact Lower
exactName: alice

dn: foldName=Alice,dc=example,dc=com
objectClass: top
objectClass: dnIdentityEntry
cn: Folded Name
foldName: Alice
`

const openLDAPDNIdentityFoldDuplicateLDIF = `dn: foldName=alice,dc=example,dc=com
objectClass: top
objectClass: dnIdentityEntry
cn: Folded Duplicate
foldName: alice
`
