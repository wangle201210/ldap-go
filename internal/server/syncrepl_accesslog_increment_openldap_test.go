package server

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const deltaIncrementReferenceCommit = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

func requireDeltaIncrementReference(t *testing.T) openLDAPReferenceTools {
	t.Helper()
	tools := requireOpenLDAPReferenceTools(t)
	if os.Getenv("OPENLDAP_REFERENCE_VERIFIED") != "1" || os.Getenv("OPENLDAP_COMMIT") != deltaIncrementReferenceCommit {
		t.Fatal("increment reference tests require the verified OpenLDAP 2.6.13 build")
	}
	version, err := exec.Command(tools.slapd, "-VV").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "slapd 2.6.13") {
		t.Fatalf("slapd version: %v: %s", err, version)
	}
	for file, hash := range map[string]string{
		"syncrepl.c": "dcb8a253965dc40cb9171bc09bfebf4e2c319ce95c45bcfa3330155342b998d9",
		"mods.c":     "163e6b5f91f4c3f4fec2ee61b184f28c83bdd9ce0e32c39158baa577e61d2078",
	} {
		source, err := os.ReadFile(filepath.Join(os.Getenv("OPENLDAP_SOURCE"), "servers", "slapd", file))
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(source)) != hash {
			t.Fatalf("%s must match pinned commit %s: %v", file, deltaIncrementReferenceCommit, err)
		}
	}
	return tools
}

// These are independent writes, in CSN order, to identical initial entries.
// Frozen providers prevent feedback between the two delivery orders. Inspect
// reqDN and reqMod as well as CSNs: a fallback refresh can log the same CSN.
func TestOpenLDAP2613DeltaIncrementInterleavings(t *testing.T) {
	tools := requireDeltaIncrementReference(t)
	for _, test := range []struct {
		name     string
		older    string
		newer    string
		want     [2][]string
		incoming [2][]string
		fallback [2]bool
	}{
		{"increments", "# 2", "# 3", [2][]string{{"15"}, {"15"}}, [2][]string{{"# 3"}, {"# 2"}}, [2]bool{}},
		{"increment_replace", "# 2", "= 20", [2][]string{{"20"}, {"20"}}, [2][]string{{"= 20"}, nil}, [2]bool{}},
		{"replace_increment", "= 20", "# 2", [2][]string{{"22"}, {"20"}}, [2][]string{{"# 2"}, {"-", "+ 20"}}, [2]bool{}},
		{"increment_delete_all", "# 2", "-", [2][]string{nil, nil}, [2][]string{{"-"}, nil}, [2]bool{}},
		{"delete_all_increment", "-", "# 2", [2][]string{{"12"}, nil}, [2][]string{{"= 12"}, {"-"}}, [2]bool{true, false}},
		{"increment_delete_value", "# 2", "- 10", [2][]string{{"12"}, nil}, [2][]string{{"- 10"}, nil}, [2]bool{false, true}},
		{"delete_value_increment", "- 10", "# 2", [2][]string{{"12"}, {"12"}}, [2][]string{{"= 12"}, {"- 10"}}, [2]bool{true, false}},
		{"increment_add", "# 2", "+ 30", [2][]string{{"12", "30"}, {"12", "32"}}, [2][]string{{"+ 30"}, {"# 2"}}, [2]bool{}},
		{"add_increment", "+ 30", "# 2", [2][]string{{"12", "32"}, {"12", "30"}}, [2][]string{{"# 2"}, {"+ 30"}}, [2]bool{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			nodes := []*deltaIncrementReferenceNode{
				newDeltaIncrementReferenceNode(t, tools, 1),
				newDeltaIncrementReferenceNode(t, tools, 2),
			}
			csns := make([]string, 2)
			original := make([][]string, 2)
			for i, mod := range []string{test.older, test.newer} {
				stop := nodes[i].process.start(t)
				client := dialLDAPRoot(t, nodes[i].process.address)
				deltaIncrementReferenceModify(t, client, "testCounter", mod)
				csns[i] = deltaIncrementReferenceEntry(t, client, deltaMPRTarget, "entryCSN").GetAttributeValue("entryCSN")
				rows := deltaIncrementReferenceLogs(t, client)
				if len(rows) != 1 {
					t.Fatalf("local write produced %d logs", len(rows))
				}
				original[i] = rows[0].GetAttributeValues("reqMod")
				_ = client.Close()
				stop()
			}
			if csns[0] >= csns[1] {
				t.Fatalf("writes not in CSN order: %q", csns)
			}
			sinks := make([]*deltaIncrementReferenceNode, 2)
			for i, node := range nodes {
				sinks[i] = newDeltaIncrementReferenceNode(t, tools, i+1)
				for _, database := range []string{"data", "log"} {
					data, err := os.ReadFile(filepath.Join(node.root, database, "data.mdb"))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(sinks[i].root, database, "data.mdb"), data, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				node.process.start(t)
			}
			clients := make([]*ldap.Conn, 2)
			for i, node := range sinks {
				node.configure(t, nodes[1-i].process.uri)
				node.process.start(t)
				clients[i] = dialLDAPRoot(t, node.process.address)
				defer clients[i].Close()
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				complete := true
				for i, client := range clients {
					state := deltaIncrementReferenceEntry(t, client, "dc=example,dc=com", "contextCSN").GetAttributeValues("contextCSN")
					for _, csn := range csns {
						complete = complete && slices.Contains(state, csn)
					}
					// Accesslog response callbacks can finish after contextCSN is
					// visible. Wait for the target row, or the fallback checkpoint.
					found := false
					for _, row := range deltaIncrementReferenceLogs(t, client) {
						if row.GetAttributeValue("entryCSN") != csns[1-i] {
							continue
						}
						wantDN := deltaMPRTarget
						if test.fallback[i] {
							wantDN = "dc=example,dc=com"
						}
						found = found || row.GetAttributeValue("reqDN") == wantDN
					}
					complete = complete && found
				}
				if complete || time.Now().After(deadline) {
					for i, client := range clients {
						entry := deltaIncrementReferenceEntry(t, client, deltaMPRTarget, "testCounter", "entryCSN")
						t.Logf("node %d values=%q entryCSN=%s cookies_complete=%v", i+1, entry.GetAttributeValues("testCounter"), entry.GetAttributeValue("entryCSN"), complete)
						if !equalStringSets(entry.GetAttributeValues("testCounter"), test.want[i]) {
							t.Errorf("node %d values=%q, want reference boundary %q", i+1, entry.GetAttributeValues("testCounter"), test.want[i])
						}
						if entry.GetAttributeValue("entryCSN") != csns[1] {
							t.Errorf("node %d lost the newer entryCSN", i+1)
						}
						var incoming *ldap.Entry
						localCount, checkpoints := 0, 0
						for _, row := range deltaIncrementReferenceLogs(t, client) {
							if row.GetAttributeValue("reqResult") != "0" {
								t.Errorf("unexpected failed accesslog: %v", row)
							}
							if row.GetAttributeValue("reqDN") != deltaMPRTarget {
								checkpoints++
								continue
							}
							if row.GetAttributeValue("entryCSN") == csns[i] {
								localCount++
								if !slices.Equal(row.GetAttributeValues("reqMod"), original[i]) {
									t.Error("local original log changed")
								}
							} else if row.GetAttributeValue("entryCSN") == csns[1-i] && incoming == nil {
								incoming = row
							} else {
								t.Errorf("unexpected or duplicate target accesslog: %v", row)
							}
						}
						if localCount != 1 || (checkpoints != 0) != test.fallback[i] {
							t.Errorf("node %d local logs=%d fallback=%v, want 1/%v", i+1, localCount, checkpoints != 0, test.fallback[i])
						}
						if test.name == "increment_delete_value" && i == 1 {
							if incoming != nil {
								t.Error("expected failed older increment to be absent from target history")
							}
							continue
						}
						if incoming == nil {
							t.Fatal("incoming target accesslog is missing")
						}
						var got []string
						for _, mod := range incoming.GetAttributeValues("reqMod") {
							if rest, ok := strings.CutPrefix(mod, "testCounter:"); ok {
								got = append(got, rest)
							}
						}
						if !slices.Equal(got, test.incoming[i]) {
							t.Errorf("node %d logged counter mods=%q, want %q", i+1, got, test.incoming[i])
						}
						if !test.fallback[i] && i == 0 && !slices.Equal(incoming.GetAttributeValues("reqMod"), original[1]) {
							t.Error("newer request did not retain its original log")
						}
						if i == 1 && !slices.Equal(incoming.GetAttributeValues("reqMod"), prefixDeltaIncrementMods(test.incoming[i])) {
							t.Error("older request no longer has the pinned reference's transformed log")
						}
						t.Logf("node %d fallback=%v incoming counter mods=%q", i+1, test.fallback[i], got)
					}
					if !complete {
						t.Fatal("replication did not consume both CSNs")
					}
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}

func prefixDeltaIncrementMods(mods []string) []string {
	result := make([]string, len(mods))
	for i, mod := range mods {
		result[i] = "testCounter:" + mod
	}
	return result
}

func TestOpenLDAP2613DeltaIncrementValueRules(t *testing.T) {
	tools := requireDeltaIncrementReference(t)
	node := newDeltaIncrementReferenceNode(t, tools, 1)
	node.process.start(t)
	client := dialLDAPRoot(t, node.process.address)
	defer client.Close()
	for _, test := range []struct {
		name      string
		attribute string
		current   []string
		operands  []string
		code      uint16
		want      []string
	}{
		{"single", "uidNumber", []string{"10"}, []string{"2"}, 0, []string{"12"}},
		{"multiple_values", "testCounter", []string{"10", "20"}, []string{"2"}, 0, []string{"12", "22"}},
		{"inherited_syntax", "testInheritedCounter", []string{"10"}, []string{"2"}, 0, []string{"12"}},
		{"negative", "testCounter", []string{"10"}, []string{"-2"}, 0, []string{"8"}},
		{"zero", "testCounter", []string{"10", "20"}, []string{"0"}, 0, []string{"10", "20"}},
		{"absent", "testCounter", nil, []string{"2"}, ldap.LDAPResultNoSuchAttribute, nil},
		{"absent_zero", "testCounter", nil, []string{"0"}, ldap.LDAPResultNoSuchAttribute, nil},
		{"no_operand", "testCounter", []string{"10"}, nil, ldap.LDAPResultProtocolError, nil},
		{"multiple_operands", "testCounter", []string{"10"}, []string{"2", "3"}, ldap.LDAPResultProtocolError, nil},
		{"empty_operand", "testCounter", []string{"10"}, []string{""}, ldap.LDAPResultInvalidAttributeSyntax, nil},
		{"non_integer_syntax", "description", []string{"10"}, []string{"2"}, ldap.LDAPResultConstraintViolation, nil},
		{"fraction", "testCounter", []string{"10"}, []string{"1.5"}, ldap.LDAPResultInvalidAttributeSyntax, nil},
		{"plus_sign", "testCounter", []string{"10"}, []string{"+2"}, ldap.LDAPResultInvalidAttributeSyntax, nil},
		{"leading_zero", "testCounter", []string{"10"}, []string{"02"}, ldap.LDAPResultInvalidAttributeSyntax, nil},
		{"negative_zero", "testCounter", []string{"10"}, []string{"-0"}, ldap.LDAPResultInvalidAttributeSyntax, nil},
		{"operand_range", "testCounter", []string{"10"}, []string{"9223372036854775808"}, ldap.LDAPResultInvalidAttributeSyntax, nil},
		{"current_range", "testCounter", []string{"9223372036854775808"}, []string{"1"}, ldap.LDAPResultInvalidAttributeSyntax, nil},
		{"zero_skips_current_range", "testCounter", []string{"9223372036854775808"}, []string{"0"}, 0, []string{"9223372036854775808"}},
		// mods.c uses unchecked signed long addition. These results describe
		// the verified 64-bit build; they are not portable arithmetic rules.
		{"native_overflow", "testCounter", []string{"9223372036854775807"}, []string{"1"}, 0, []string{"-9223372036854775808"}},
		{"native_underflow", "testCounter", []string{"-9223372036854775808"}, []string{"-1"}, 0, []string{"9223372036854775807"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reset := ldap.NewModifyRequest(deltaMPRTarget, nil)
			reset.Replace(test.attribute, test.current)
			if err := client.Modify(reset); err != nil {
				t.Fatal(err)
			}
			before := deltaIncrementReferenceEntry(t, client, deltaMPRTarget, "entryCSN").GetAttributeValue("entryCSN")
			logCount := len(deltaIncrementReferenceLogs(t, client))
			request := ldap.NewModifyRequest(deltaMPRTarget, nil)
			request.Changes = []ldap.Change{{Operation: ldap.IncrementAttribute, Modification: ldap.PartialAttribute{Type: test.attribute, Vals: test.operands}}}
			err := client.Modify(request)
			want := test.want
			if test.code == 0 {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				assertLDAPResultCode(t, err, test.code)
				want = test.current
			}
			entry := deltaIncrementReferenceEntry(t, client, deltaMPRTarget, test.attribute, "entryCSN")
			if got := entry.GetAttributeValues(test.attribute); !equalStringSets(got, want) {
				t.Fatalf("values=%q, want %q", got, want)
			}
			if test.code != 0 {
				if entry.GetAttributeValue("entryCSN") != before || len(deltaIncrementReferenceLogs(t, client)) != logCount {
					t.Fatal("failed increment advanced CSN or logged success")
				}
			} else {
				rows := deltaIncrementReferenceLogs(t, client)
				if len(rows) != logCount+1 || !slices.Contains(rows[len(rows)-1].GetAttributeValues("reqMod"), test.attribute+":# "+test.operands[0]) {
					t.Fatal("successful increment did not log its original operand")
				}
			}
		})
	}
}

type deltaIncrementReferenceNode struct {
	process *openLDAPSyncreplConsumer
	root    string
	sid     int
}

func newDeltaIncrementReferenceNode(t *testing.T, tools openLDAPReferenceTools, sid int) *deltaIncrementReferenceNode {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"data", "log"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	node := &deltaIncrementReferenceNode{
		root: root, sid: sid,
		process: &openLDAPSyncreplConsumer{tools: tools, configPath: filepath.Join(root, "slapd.conf"), address: address, uri: "ldap://" + address},
	}
	node.configure(t, "ldap://127.0.0.1:1")
	seed := `dn: dc=example,dc=com
objectClass: domain
dc: example
entryUUID: 00000000-0000-4000-8000-000000000001
entryCSN: 20200101000000.000000Z#000000#000#000000
contextCSN: 20200101000000.000000Z#000000#000#000000

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people
entryUUID: 00000000-0000-4000-8000-000000000002
entryCSN: 20200101000000.000000Z#000000#000#000000

dn: uid=alice,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: extensibleObject
uid: alice
cn: Alice
sn: Alice
testCounter: 10
uidNumber: 10
description: 10
entryUUID: 00000000-0000-4000-8000-000000000003
entryCSN: 20200101000000.000000Z#000000#000#000000

`
	command := exec.Command(tools.slapadd, "-f", node.process.configPath, "-b", "dc=example,dc=com")
	command.Stdin = strings.NewReader(seed)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("seed slapd: %v\n%s", err, output)
	}
	return node
}

func (node *deltaIncrementReferenceNode) configure(t *testing.T, provider string) {
	t.Helper()
	tools := node.process.tools
	config := fmt.Sprintf(`include %s/core.schema
include %s/cosine.schema
include %s/inetorgperson.schema
include %s/nis.schema
attributetype ( 1.3.6.1.4.1.4203.666.11.99 NAME 'testCounter' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )
attributetype ( 1.3.6.1.4.1.4203.666.11.100 NAME 'testInheritedCounter' SUP testCounter )
serverID %d
pidfile %s/slapd.pid
argsfile %s/slapd.args
database mdb
maxsize 10485760
suffix "cn=log"
rootdn "%s"
directory %s/log
index objectClass,entryCSN,reqResult,reqDN eq
overlay syncprov
syncprov-reloadhint true
syncprov-nopresent true
database mdb
maxsize 10485760
suffix "dc=example,dc=com"
rootdn "%s"
rootpw %s
directory %s/data
index objectClass,entryUUID,entryCSN eq
syncrepl rid=001 provider=%s type=refreshAndPersist retry="1 +" searchbase="dc=example,dc=com" bindmethod=simple binddn="%s" credentials=%s logbase="cn=log" logfilter="(&(objectClass=auditWriteObject)(reqResult=0))" syncdata=accesslog
multiprovider true
overlay syncprov
syncprov-checkpoint 1 1
overlay accesslog
logdb "cn=log"
logops writes
logsuccess TRUE
`, tools.schemaDir, tools.schemaDir, tools.schemaDir, tools.schemaDir,
		node.sid, node.root, node.root, syncTestRootDN, node.root,
		syncTestRootDN, syncTestRootPassword, node.root, provider, syncTestRootDN, syncTestRootPassword)
	if err := os.WriteFile(node.process.configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
}

func deltaIncrementReferenceModify(t *testing.T, client *ldap.Conn, attribute, mod string) {
	t.Helper()
	request := ldap.NewModifyRequest(deltaMPRTarget, nil)
	var values []string
	if len(mod) > 1 {
		values = []string{mod[2:]}
	}
	switch mod[0] {
	case '#':
		request.Increment(attribute, values[0])
	case '=':
		request.Replace(attribute, values)
	case '+':
		request.Add(attribute, values)
	case '-':
		request.Delete(attribute, values)
	}
	if err := client.Modify(request); err != nil {
		t.Fatalf("modify %s %s: %v", attribute, mod, err)
	}
}

func deltaIncrementReferenceEntry(t *testing.T, client *ldap.Conn, dn string, attributes ...string) *ldap.Entry {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", attributes, nil))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("read %s: %v", dn, err)
	}
	return result.Entries[0]
}

func deltaIncrementReferenceLogs(t *testing.T, client *ldap.Conn) []*ldap.Entry {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest("cn=log", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(reqType=modify)", []string{"reqDN", "reqMod", "reqResult", "entryCSN"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	return result.Entries
}
