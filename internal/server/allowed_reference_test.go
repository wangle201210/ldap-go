package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const allowedReferenceCommit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

var allowedReferenceNames = []string{
	"allowedAttributes", "allowedAttributesEffective", "allowedChildClasses", "allowedChildClassesEffective",
}

// The C module is compiled only in a disposable external oracle. This test and
// the Go server run with CGO_ENABLED=0; no native code is linked into ldap-go.
func TestOpenLDAPAllowedReference(t *testing.T) {
	if os.Getenv("LDAP_GO_OPENLDAP_ALLOWED_DOCKER_TESTS") != "1" {
		t.Skip("set LDAP_GO_OPENLDAP_ALLOWED_DOCKER_TESTS=1 and OPENLDAP_SOURCE to build the pinned allowed oracle")
	}
	container := allowedReferenceContainer(t)
	for _, placement := range []string{"database", "frontend"} {
		t.Run(placement, func(t *testing.T) {
			results := make(map[string]map[string]allowedReferenceResult)
			for _, endpoint := range []string{"native", "go"} {
				t.Run(endpoint, func(t *testing.T) {
					var address string
					if endpoint == "native" {
						address = allowedReferenceNativeServer(t, container, placement)
					} else {
						address = allowedReferenceGoServer(t, placement)
					}
					results[endpoint] = allowedReferenceCheck(t, address, placement, endpoint == "native")
				})
			}
			if results["native"] == nil || results["go"] == nil {
				return // Allow -run to select just the native oracle while developing.
			}
			exact, expectedDifferences := 0, 0
			for name, want := range results["native"] {
				got, ok := results["go"][name]
				if expectedNative, known := allowedReferenceExpectedACLCacheResult(name, true); known {
					expectedGo, _ := allowedReferenceExpectedACLCacheResult(name, false)
					if !reflect.DeepEqual(want, expectedNative) || !ok || !reflect.DeepEqual(got, expectedGo) {
						t.Errorf("EXPECTED known ACL-cache discrepancy %s: native=%+v want=%+v; Go=%+v want=%+v present=%v", name, want, expectedNative, got, expectedGo, ok)
					}
					t.Logf("EXPECTED known ACL-cache discrepancy %s: separately asserted native cached values and Go stricter filtering", name)
					expectedDifferences++
					continue
				}
				if !ok || !reflect.DeepEqual(got, want) {
					t.Errorf("%s: Go=%+v native=%+v present=%v", name, got, want, ok)
				}
				exact++
			}
			if len(results["native"]) != len(results["go"]) {
				t.Errorf("different case counts: native=%d Go=%d", len(results["native"]), len(results["go"]))
			}
			t.Logf("differential groups: exact=%d EXPECTED-known-ACL-cache-discrepancy=%d", exact, expectedDifferences)
		})
	}
}

func allowedReferenceContainer(t *testing.T) string {
	t.Helper()
	if vcReferenceCommit != allowedReferenceCommit {
		t.Fatal("VC build helper no longer uses the pinned allowed reference release")
	}
	container := vcReferenceContainer(t)
	for _, name := range []string{"contrib/slapd-modules/allowed/allowed.c", "contrib/slapd-modules/allowed/Makefile", "servers/slapd/schema/core.schema", "servers/slapd/schema/cosine.schema", "servers/slapd/schema_prep.c", "servers/slapd/back-mdb/monitor.c", "servers/slapd/acl.c", "servers/slapd/result.c"} {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		data, err := exec.CommandContext(ctx, "git", "-C", os.Getenv("OPENLDAP_SOURCE"), "show", allowedReferenceCommit+":"+name).Output()
		cancel()
		if err != nil {
			t.Fatalf("read pinned %s: %v", name, err)
		}
		want := fmt.Sprintf("%x", sha256.Sum256(data))
		got := vcReferenceDocker(t, "exec", container, "sha256sum", "/oracle/src/"+name)
		if !strings.HasPrefix(got, want+" ") {
			t.Fatalf("allowed oracle source differs from pinned commit: %s", name)
		}
	}
	vcReferenceDocker(t, "exec", container, "make", "-C", "/oracle/src/contrib/slapd-modules/allowed", "clean")
	t.Log(vcReferenceDocker(t, "exec", container, "make", "-C", "/oracle/src/contrib/slapd-modules/allowed"))
	return container
}

func allowedReferenceSchema() (attributes, classes []string) {
	for i, name := range []string{"arRequired", "arOptional", "arCanonical", "arValue", "arAuxRequired", "arAuxAttr", "arAuxChildRequired", "arDenied", "arHiddenAttr", "arAbstractAttr"} {
		names := "'" + name + "'"
		if name == "arCanonical" {
			names = "( 'arCanonical' 'arAlias' )"
		}
		attributes = append(attributes, fmt.Sprintf("( 1.3.6.1.4.1.99999.920.1.%d NAME %s EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )", i+1, names))
	}
	classes = []string{
		"( 1.3.6.1.4.1.99999.920.2.1 NAME 'arBase' SUP top STRUCTURAL MUST cn MAY description )",
		"( 1.3.6.1.4.1.99999.920.2.2 NAME 'arLeaf' SUP arBase STRUCTURAL MUST arRequired MAY ( arOptional $ arAlias $ arValue ) )",
		"( 1.3.6.1.4.1.99999.920.2.3 NAME 'arAux' SUP top AUXILIARY MUST arAuxRequired MAY arAuxAttr )",
		"( 1.3.6.1.4.1.99999.920.2.4 NAME 'arAuxChild' SUP arAux AUXILIARY MUST arAuxChildRequired )",
		"( 1.3.6.1.4.1.99999.920.2.5 NAME 'arAuxEmpty' SUP top AUXILIARY )",
		"( 1.3.6.1.4.1.99999.920.2.6 NAME 'arAuxBlocked' SUP top AUXILIARY MUST arDenied )",
		"( 1.3.6.1.4.1.99999.920.2.7 NAME 'arAuxValue' SUP top AUXILIARY MAY arValue )",
		"( 1.3.6.1.4.1.99999.920.2.8 NAME 'arHiddenAux' SUP top AUXILIARY MAY arHiddenAttr )",
		"( 1.3.6.1.4.1.99999.920.2.9 NAME 'arAbstract' SUP top ABSTRACT MAY arAbstractAttr )",
		"( 1.3.6.1.4.1.99999.920.2.10 NAME 'arUnrelated' SUP top STRUCTURAL MUST cn )",
	}
	return attributes, classes
}

func allowedReferenceACL() []string {
	return []string{
		`to dn.exact="cn=noOC,dc=example" attrs=objectClass by * search`,
		`to dn.exact="cn=hideOC,dc=example" attrs=objectClass val.exact="arHiddenAux" by * none`,
		`to dn.exact="cn=readOnly,dc=example" by * read`,
		`to dn.exact="cn=writeACL,dc=example" attrs=arOptional,arAuxRequired,arDenied by * read`,
		`to dn.exact="cn=writeACL,dc=example" attrs=objectClass val.exact="arAuxValue" by * read`,
		`to dn.exact="cn=writeACL,dc=example" attrs=arValue val.exact="stored" by * read`,
		`to dn.exact="cn=outputACL,dc=example" attrs=allowedAttributes by * none`,
		`to dn.exact="cn=outputACL,dc=example" attrs=allowedAttributesEffective val.regex="^arOptional$" by * none`,
		`to dn.exact="cn=outputACL,dc=example" attrs=allowedChildClassesEffective val.regex="^arAuxEmpty$" by * none`,
		`to dn.exact="cn=allOutputDenied,dc=example" attrs=allowedAttributes,allowedAttributesEffective,allowedChildClasses,allowedChildClassesEffective by * none`,
		`to dn.exact="cn=valuesHidden,dc=example" attrs=allowedAttributes val.regex=".+" by * none`,
		`to dn.exact="cn=valuesHidden,dc=example" attrs=allowedAttributesEffective val.regex=".+" by * none`,
		`to dn.exact="cn=valuesHidden,dc=example" attrs=allowedChildClasses val.regex=".+" by * none`,
		`to dn.exact="cn=valuesHidden,dc=example" attrs=allowedChildClassesEffective val.regex=".+" by * none`,
		`to * by * write`,
	}
}

func allowedReferenceSeed() string {
	var output strings.Builder
	output.WriteString("dn: dc=example\nobjectClass: domain\ndc: example\n\n")
	for _, name := range []string{"normal", "readOnly", "noOC", "hideOC", "writeACL", "outputACL", "allOutputDenied", "valuesHidden", "extensible"} {
		fmt.Fprintf(&output, "dn: cn=%s,dc=example\nobjectClass: arLeaf\nobjectClass: arAux\nobjectClass: arHiddenAux\ncn: %s\narRequired: required\narAuxRequired: required\narValue: stored\narHiddenAttr: hidden\n", name, name)
		if name == "extensible" {
			// Keep the entry structural class identical; extensibleObject adds no
			// declared MUST/MAY even though it permits storing other user attrs.
			output.WriteString("objectClass: extensibleObject\n")
		}
		output.WriteByte('\n')
	}
	return output.String()
}

func allowedReferenceNativeServer(t *testing.T, container, placement string) string {
	t.Helper()
	var config strings.Builder
	config.WriteString("include /oracle/src/servers/slapd/schema/core.schema\ninclude /oracle/src/servers/slapd/schema/cosine.schema\nmoduleload /oracle/src/contrib/slapd-modules/allowed/allowed.la\npidfile /oracle/allowed/slapd.pid\nargsfile /oracle/allowed/slapd.args\n")
	attributes, classes := allowedReferenceSchema()
	for _, definition := range attributes {
		fmt.Fprintln(&config, "attributetype", definition)
	}
	for _, definition := range classes {
		fmt.Fprintln(&config, "objectclass", definition)
	}
	if placement == "frontend" {
		config.WriteString("overlay allowed\n")
		for _, rule := range allowedReferenceACL() {
			fmt.Fprintln(&config, "access", rule)
		}
	}
	config.WriteString("database mdb\nsuffix dc=example\nrootdn cn=admin,dc=example\nrootpw admin-password\ndirectory /oracle/allowed/db\n")
	for _, rule := range allowedReferenceACL() {
		fmt.Fprintln(&config, "access", rule)
	}
	if placement == "database" {
		config.WriteString("overlay allowed\n")
	}
	directory := t.TempDir()
	for name, data := range map[string]string{"slapd.conf": config.String(), "seed.ldif": allowedReferenceSeed()} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	vcReferenceDocker(t, "exec", container, "sh", "-c", "rm -rf /oracle/allowed && mkdir -p /oracle/allowed/db")
	vcReferenceDocker(t, "cp", directory+"/.", container+":/oracle/allowed")
	vcReferenceDocker(t, "exec", container, "/oracle/src/servers/slapd/slapd", "-Tadd", "-f", "/oracle/allowed/slapd.conf", "-l", "/oracle/allowed/seed.ldif")
	command := exec.Command("docker", "exec", container, "/oracle/src/servers/slapd/slapd", "-f", "/oracle/allowed/slapd.conf", "-h", "ldap://0.0.0.0:1389/", "-d", "0")
	var log bytes.Buffer
	command.Stdout, command.Stderr = &log, &log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		vcReferenceDocker(t, "exec", container, "sh", "-c", "test ! -f /oracle/allowed/slapd.pid || kill $(cat /oracle/allowed/slapd.pid)")
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("native allowed process did not stop")
		}
	})
	address := vcReferenceDocker(t, "port", container, "1389/tcp")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			done <- err
			t.Fatalf("native allowed exited: %v: %s", err, log.String())
		default:
		}
		client, err := ldap.DialURL("ldap://"+address, ldap.DialWithDialer(&net.Dialer{Timeout: 100 * time.Millisecond}))
		if err == nil {
			client.SetTimeout(100 * time.Millisecond)
			err = client.UnauthenticatedBind("")
			client.Close()
			if err == nil {
				return address
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("native allowed slapd did not start")
	return ""
}

func allowedReferenceGoServer(t *testing.T, placement string) string {
	t.Helper()
	var config strings.Builder
	config.WriteString("dn: cn=config\nobjectClass: olcGlobal\ncn: config\n\ndn: cn=schema,cn=config\nobjectClass: olcSchemaConfig\ncn: schema\n\ndn: cn={9}allowed-reference,cn=schema,cn=config\nobjectClass: olcSchemaConfig\ncn: {9}allowed-reference\n")
	attributes, classes := allowedReferenceSchema()
	for _, definition := range attributes {
		fmt.Fprintln(&config, "olcAttributeTypes:", definition)
	}
	for _, definition := range classes {
		fmt.Fprintln(&config, "olcObjectClasses:", definition)
	}
	config.WriteString("\ndn: olcDatabase={-1}frontend,cn=config\nobjectClass: olcDatabaseConfig\nobjectClass: olcFrontendConfig\nolcDatabase: {-1}frontend\n")
	if placement == "frontend" {
		for i, rule := range allowedReferenceACL() {
			fmt.Fprintf(&config, "olcAccess: {%d}%s\n", i, rule)
		}
	}
	config.WriteString("\ndn: olcDatabase={1}mdb,cn=config\nobjectClass: olcDatabaseConfig\nobjectClass: olcMdbConfig\nolcDatabase: {1}mdb\nolcSuffix: dc=example\nolcRootDN: cn=admin,dc=example\nolcRootPW: admin-password\n")
	for i, rule := range allowedReferenceACL() {
		fmt.Fprintf(&config, "olcAccess: {%d}%s\n", i, rule)
	}
	parent := "olcDatabase={1}mdb,cn=config"
	if placement == "frontend" {
		parent = "olcDatabase={-1}frontend,cn=config"
	}
	fmt.Fprintf(&config, "\ndn: olcOverlay={0}allowed,%s\nobjectClass: olcOverlayConfig\nolcOverlay: {0}allowed\n\n", parent)
	store := storage.NewMemory()
	t.Cleanup(func() { _ = store.Close() })
	if _, err := migration.ImportLDIF(t.Context(), store, strings.NewReader(config.String()+allowedReferenceSeed()), migration.ImportOptions{SkipSchemaValidation: true}); err != nil {
		t.Fatal(err)
	}
	address, stop := startServer(t, store, Config{})
	t.Cleanup(stop)
	return address
}

type allowedReferenceResult struct {
	code       uint16
	entries    int
	attributes map[string][]string
}

func allowedReferenceCheck(t *testing.T, address, placement string, native bool) map[string]allowedReferenceResult {
	t.Helper()
	client, err := ldap.DialURL("ldap://"+address, ldap.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetTimeout(3 * time.Second)
	auxiliary := allowedReferenceAuxiliary(t, client, native)
	results := make(map[string]allowedReferenceResult)
	for _, test := range allowedReferenceCases(placement) {
		testName := test.name
		if _, known := allowedReferenceExpectedACLCacheResult(test.name, native); known {
			testName = "EXPECTED-known-ACL-cache-discrepancy-" + test.name
		}
		t.Run(testName, func(t *testing.T) {
			if test.root {
				err = client.Bind("cn=admin,dc=example", "admin-password")
			} else {
				err = client.UnauthenticatedBind("")
			}
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Search(ldap.NewSearchRequest(test.base, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, test.typesOnly, test.filter, test.attrs, nil))
			got := allowedReferenceResult{code: allowedReferenceCode(t, err), attributes: map[string][]string{}}
			if result != nil {
				got.entries = len(result.Entries)
				for _, entry := range result.Entries {
					for _, attribute := range entry.Attributes {
						projected := false
						for _, name := range allowedReferenceNames {
							if strings.EqualFold(attribute.Name, name) {
								projected = true
								if _, exists := got.attributes[name]; exists {
									t.Errorf("duplicate output attribute %s", name)
								}
								if attribute.Name != name {
									t.Errorf("noncanonical output attribute %q, want %q", attribute.Name, name)
								}
								values := slices.Clone(attribute.Values)
								slices.Sort(values)
								if len(slices.Compact(slices.Clone(values))) != len(values) {
									t.Errorf("duplicate values for %s: %q", name, values)
								}
								got.attributes[name] = values
							}
						}
						if !projected && len(test.attrs) != 0 && !slices.Contains(test.attrs, "*") && !slices.Contains(test.attrs, "+") {
							t.Errorf("unrequested output attribute %s", attribute.Name)
						}
					}
				}
			}
			allowedReferenceAssert(t, test, got, auxiliary, native)
			// Built-in auxiliary inventories differ. Assert the pinned native
			// inventory and both complete custom sets before cross-endpoint scope.
			for _, name := range allowedReferenceNames[2:] {
				if values, ok := got.attributes[name]; ok && !test.typesOnly {
					custom := []string{}
					for _, value := range values {
						if strings.HasPrefix(value, "ar") {
							custom = append(custom, value)
						}
					}
					got.attributes[name] = custom
				}
			}
			if want, known := allowedReferenceExpectedACLCacheResult(test.name, native); known {
				if !reflect.DeepEqual(got, want) {
					t.Errorf("EXPECTED known ACL-cache discrepancy: native=%v got=%+v want=%+v", native, got, want)
				}
			}
			results[test.name] = got
			t.Logf("code=%d entries=%d attributes=%v", got.code, got.entries, got.attributes)
		})
	}
	for _, name := range allowedReferenceNames {
		t.Run("compare-"+name, func(t *testing.T) {
			if err := client.Bind("cn=admin,dc=example", "admin-password"); err != nil {
				t.Fatal(err)
			}
			value := "1.3.6.1.4.1.99999.920.1.1"
			if strings.Contains(name, "ChildClasses") {
				value = "1.3.6.1.4.1.99999.920.2.3"
			}
			matched, err := client.Compare("cn=normal,dc=example", name, value)
			got := allowedReferenceResult{code: allowedReferenceCode(t, err)}
			if matched || got.code != ldap.LDAPResultNoSuchAttribute {
				t.Errorf("Compare projected %s: matched=%v code=%d, want noSuchAttribute", name, matched, got.code)
			}
			results["compare-"+name] = got
		})
	}
	return results
}

func allowedReferenceCode(t *testing.T, err error) uint16 {
	t.Helper()
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) {
		t.Fatal(err)
	}
	return ldapError.ResultCode
}

func allowedReferenceAuxiliary(t *testing.T, client *ldap.Conn, native bool) []string {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest("cn=subschema", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectClasses"}, nil))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("read schema inventory: %v", err)
	}
	var auxiliary []string
	for _, value := range result.Entries[0].GetAttributeValues("objectClasses") {
		class, err := schema.ParseObjectClass(value)
		if err != nil {
			t.Fatalf("parse oracle schema: %v", err)
		}
		if class.Kind == schema.ObjectClassAuxiliary {
			auxiliary = append(auxiliary, class.Names[0])
		}
	}
	if native {
		// Pinned schema_prep.c and back-mdb/monitor.c register these hidden
		// auxiliary classes. They are intentionally absent from subschema.
		auxiliary = append(auxiliary, "syncConsumerSubentry", "syncProviderSubentry", "olmMDBDatabase")
	} else {
		builtin, err := schema.NewBuiltinRegistry()
		if err != nil {
			t.Fatal(err)
		}
		for _, class := range builtin.ObjectClasses() {
			if class.Hidden && class.Kind == schema.ObjectClassAuxiliary {
				auxiliary = append(auxiliary, class.Name())
			}
		}
	}
	slices.Sort(auxiliary)
	if len(auxiliary) == 0 {
		t.Fatal("schema returned no auxiliary classes")
	}
	wantCustom := []string{"arAux", "arAuxBlocked", "arAuxChild", "arAuxEmpty", "arAuxValue", "arHiddenAux"}
	custom := slices.DeleteFunc(slices.Clone(auxiliary), func(value string) bool { return !strings.HasPrefix(value, "ar") })
	if !slices.Equal(custom, wantCustom) {
		t.Fatalf("fixture schema auxiliary classes=%q, want exactly %q", custom, wantCustom)
	}
	return auxiliary
}

type allowedReferenceCase struct {
	name, base, filter string
	attrs              []string
	root, typesOnly    bool
	noProjection       bool
	noEntry            bool
}

// These are complete fixture expectations, never derived from the response of
// either endpoint. Native reuses a cached Read(nil) answer for val.* ACLs;
// Go deliberately enforces those value restrictions. Keep this exception list
// closed: typesOnly and every other case still require cross-endpoint equality.
func allowedReferenceExpectedACLCacheResult(name string, native bool) (allowedReferenceResult, bool) {
	switch name {
	case "hideOC", "outputACL", "valuesHidden":
	default:
		return allowedReferenceResult{}, false
	}
	want := allowedReferenceResult{entries: 1, attributes: map[string][]string{}}
	if name == "valuesHidden" && !native {
		return want, true
	}
	attributes := []string{"arAuxAttr", "arAuxRequired", "arCanonical", "arHiddenAttr", "arOptional", "arRequired", "arValue", "cn", "description", "objectClass"}
	classes := []string{"arAux", "arAuxBlocked", "arAuxChild", "arAuxEmpty", "arAuxValue", "arHiddenAux"}
	want.attributes["allowedAttributes"] = slices.Clone(attributes)
	want.attributes["allowedAttributesEffective"] = slices.Clone(attributes)
	want.attributes["allowedChildClasses"] = slices.Clone(classes)
	want.attributes["allowedChildClassesEffective"] = slices.Clone(classes)
	switch name {
	case "hideOC":
		want.attributes["allowedChildClassesEffective"] = []string{"arAux", "arAuxBlocked", "arAuxChild", "arAuxEmpty", "arAuxValue"}
		if !native {
			for _, attribute := range allowedReferenceNames[:2] {
				want.attributes[attribute] = []string{"arAuxAttr", "arAuxRequired", "arCanonical", "arOptional", "arRequired", "arValue", "cn", "description", "objectClass"}
			}
		}
	case "outputACL":
		delete(want.attributes, "allowedAttributes")
		if !native {
			want.attributes["allowedAttributesEffective"] = []string{"arAuxAttr", "arAuxRequired", "arCanonical", "arHiddenAttr", "arRequired", "arValue", "cn", "description", "objectClass"}
			want.attributes["allowedChildClassesEffective"] = []string{"arAux", "arAuxBlocked", "arAuxChild", "arAuxValue", "arHiddenAux"}
		}
	}
	return want, true
}

func allowedReferenceCases(placement string) []allowedReferenceCase {
	cases := []allowedReferenceCase{
		{name: "explicit", attrs: allowedReferenceNames},
		{name: "OID", attrs: []string{"1.2.840.113556.1.4.913", "1.2.840.113556.1.4.914", "1.2.840.113556.1.4.911", "1.2.840.113556.1.4.912"}},
		{name: "plus", attrs: []string{"+"}},
		{name: "star", attrs: []string{"*"}, noProjection: true},
		{name: "default", noProjection: true},
		{name: "no-attributes", attrs: []string{"1.1"}, noProjection: true},
		{name: "types-only", attrs: allowedReferenceNames, typesOnly: true},
		{name: "no-attributes-explicit", attrs: append([]string{"1.1"}, allowedReferenceNames...)},
		{name: "root", attrs: allowedReferenceNames, root: true},
	}
	for _, name := range allowedReferenceNames {
		cases = append(cases,
			allowedReferenceCase{name: "single-" + name, attrs: []string{name}},
			allowedReferenceCase{name: "case-" + name, attrs: []string{strings.ToUpper(name)}},
			allowedReferenceCase{name: "star-explicit-" + name, attrs: []string{"*", name}},
			allowedReferenceCase{name: "filter-" + name, attrs: allowedReferenceNames, filter: "(" + name + "=*)", noEntry: true},
		)
	}
	for _, name := range []string{"readOnly", "noOC", "hideOC", "writeACL", "outputACL", "allOutputDenied", "valuesHidden", "extensible"} {
		cases = append(cases, allowedReferenceCase{name: name, base: "cn=" + name + ",dc=example", attrs: allowedReferenceNames})
	}
	for _, name := range []string{"noOC", "hideOC", "outputACL", "valuesHidden"} {
		cases = append(cases, allowedReferenceCase{name: name + "-types-only", base: "cn=" + name + ",dc=example", attrs: allowedReferenceNames, typesOnly: true})
	}
	for _, base := range []string{"", "cn=subschema"} {
		name := "rootDSE"
		if base != "" {
			name = "subschema"
		}
		cases = append(cases, allowedReferenceCase{name: name, base: base, attrs: allowedReferenceNames, noProjection: placement == "database"})
	}
	for i := range cases {
		if cases[i].base == "" && cases[i].name != "rootDSE" {
			cases[i].base = "cn=normal,dc=example"
		}
		if cases[i].filter == "" {
			cases[i].filter = "(objectClass=*)"
		}
	}
	return cases
}

func allowedReferenceAssert(t *testing.T, test allowedReferenceCase, got allowedReferenceResult, auxiliary []string, native bool) {
	t.Helper()
	test.name = strings.TrimSuffix(test.name, "-types-only")
	wantEntries := 1
	if test.noEntry {
		wantEntries = 0
	}
	if got.code != 0 || got.entries != wantEntries {
		t.Errorf("result code=%d entries=%d, want success with %d entries", got.code, got.entries, wantEntries)
	}
	if test.noProjection || test.noEntry || test.name == "noOC" || test.name == "allOutputDenied" || (!native && !test.typesOnly && test.name == "valuesHidden") {
		if len(got.attributes) != 0 {
			t.Errorf("unexpected projected attributes: %v", got.attributes)
		}
		return
	}
	for _, name := range allowedReferenceNames {
		values, present := got.attributes[name]
		requested := slices.Contains(test.attrs, "+") || slices.ContainsFunc(test.attrs, func(value string) bool { return strings.EqualFold(value, name) }) || test.name == "OID"
		if !requested {
			if present {
				t.Errorf("unrequested attribute %s", name)
			}
			continue
		}
		if (test.name == "readOnly" && strings.HasSuffix(name, "Effective")) || (test.name == "outputACL" && name == "allowedAttributes") {
			if present {
				t.Errorf("ACL should omit %s: %v", name, values)
			}
			continue
		}
		if !present {
			t.Errorf("missing requested attribute %s", name)
			continue
		}
		if test.typesOnly {
			if len(values) != 0 {
				t.Errorf("typesOnly returned %s values", name)
			}
			continue
		}
		if strings.Contains(name, "ChildClasses") {
			for _, value := range values {
				if !slices.Contains(auxiliary, value) {
					t.Errorf("non-auxiliary or noncanonical child class %q", value)
				}
			}
			want := auxiliary
			if name == "allowedChildClassesEffective" {
				want = slices.Clone(auxiliary)
				switch test.name {
				case "hideOC":
					want = slices.DeleteFunc(want, func(value string) bool { return value == "arHiddenAux" })
				case "writeACL":
					want = slices.DeleteFunc(want, func(value string) bool {
						return slices.Contains([]string{"arAux", "arAuxChild", "arAuxBlocked", "arAuxValue"}, value)
					})
				case "outputACL":
					if !native {
						want = slices.DeleteFunc(want, func(value string) bool { return value == "arAuxEmpty" })
					}
				}
			}
			checkValues := values
			if !native {
				// Some unrelated built-in module schemas are incomplete in Go.
				// Still require every custom fixture auxiliary, without intersecting
				// with what either endpoint happened to return.
				custom := func(value string) bool { return !strings.HasPrefix(value, "ar") }
				checkValues = slices.DeleteFunc(slices.Clone(values), custom)
				want = slices.DeleteFunc(slices.Clone(want), custom)
			}
			if !slices.Equal(checkValues, want) {
				t.Errorf("%s=%q, want auxiliary inventory %q", name, checkValues, want)
			}
			continue
		}
		want := []string{"objectClass", "cn", "description", "arRequired", "arOptional", "arCanonical", "arValue", "arAuxRequired", "arAuxAttr", "arHiddenAttr"}
		if test.name == "rootDSE" {
			want = []string{"cn", "objectClass"}
		} else if test.name == "subschema" {
			want = []string{"attributeTypes", "cn", "dITContentRules", "dITStructureRules", "matchingRuleUse", "matchingRules", "nameForms", "objectClass", "objectClasses", "subtreeSpecification"}
		}
		// Native first checks objectClass/output Read(nil) with a reused
		// AccessControlState. Simple val.* ACLs skip that first lookup and its
		// cached answer is reused for the subsequent values (acl.c:408,617).
		// Effective Write checks have no shared state and remain value-aware.
		if !native && test.name == "hideOC" {
			want = slices.DeleteFunc(want, func(value string) bool { return value == "arHiddenAttr" })
		}
		if name == "allowedAttributesEffective" {
			if test.name == "writeACL" {
				want = slices.DeleteFunc(want, func(value string) bool { return value == "arOptional" || value == "arAuxRequired" })
			}
			if !native && test.name == "outputACL" {
				want = slices.DeleteFunc(want, func(value string) bool { return value == "arOptional" })
			}
		}
		slices.Sort(want)
		if !slices.Equal(values, want) {
			t.Errorf("%s=%q, want complete inherited attribute set %q", name, values, want)
		}
	}
}
