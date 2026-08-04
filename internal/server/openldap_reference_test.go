package server

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

const (
	openLDAPReferenceTestsEnv = "LDAP_GO_OPENLDAP_REFERENCE_TESTS"
	openLDAPSlapdDebugEnv     = "LDAP_GO_OPENLDAP_SLAPD_DEBUG"
)

type openLDAPReferenceTools struct {
	slapd     string
	slapadd   string
	schemaDir string
}

func TestOpenLDAPReferenceSyncSortAndVLV(t *testing.T) {
	tools := requireOpenLDAPReferenceTools(t)
	if os.Getenv(openLDAPSlapdDebugEnv) == "" {
		t.Setenv(openLDAPSlapdDebugEnv, "16385")
	}
	syncControl := ldapwire.Control{
		OID:      syncRequestControlOID,
		Critical: true,
		Value: ldapwire.EncodeSyncRequestValue(ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshOnly,
		}),
		HasValue: true,
	}
	sortControl := ldapwire.Control{
		OID:      sortRequestControlOID,
		Critical: true,
		Value: ldapwire.EncodeSortRequestValue([]ldapwire.SortKey{{
			AttributeType: "cn",
			OrderingRule:  "caseIgnoreOrderingMatch",
		}}),
		HasValue: true,
	}
	persistentSyncControl := syncControl
	persistentSyncControl.Value = ldapwire.EncodeSyncRequestValue(
		ldapwire.SyncRequestValue{
			Mode: ldapwire.SyncRefreshAndPersist,
		},
	)
	vlvControl := ldapwire.Control{
		OID:      vlvRequestControlOID,
		Critical: true,
		Value: ldapwire.EncodeVirtualListViewRequestValue(
			ldapwire.VirtualListViewRequest{
				AfterCount:   1,
				ByOffset:     true,
				Offset:       1,
				ContentCount: 3,
			},
		),
		HasValue: true,
	}

	for _, overlays := range [][]string{
		{"syncprov", "sssvlv"},
		{"sssvlv", "syncprov"},
	} {
		name := strings.Join(overlays, "-then-")
		t.Run(name, func(t *testing.T) {
			syncprovFirst := overlays[0] == "syncprov"
			for _, test := range []struct {
				name              string
				controls          []ldapwire.Control
				persist           bool
				wantDNs           []string
				wantEntryControl  string
				wantFinalControls []string
				wantRefreshDone   bool
				wantIncomplete    bool
			}{
				{
					name:             "sync",
					controls:         []ldapwire.Control{syncControl},
					wantDNs:          openLDAPReferenceNaturalDNs(),
					wantEntryControl: syncStateControlOID,
					wantFinalControls: []string{
						syncDoneControlOID,
					},
				},
				{
					name:     "sync-then-sort",
					controls: []ldapwire.Control{syncControl, sortControl},
					wantDNs:  openLDAPReferenceSortedDNs(),
					wantEntryControl: openLDAPReferenceSortedEntryControl(
						syncprovFirst,
					),
					wantFinalControls: openLDAPReferenceSortedFinalControls(
						syncprovFirst,
						false,
					),
				},
				{
					name:     "sort-then-sync",
					controls: []ldapwire.Control{sortControl, syncControl},
					wantDNs:  openLDAPReferenceSortedDNs(),
					wantEntryControl: openLDAPReferenceSortedEntryControl(
						syncprovFirst,
					),
					wantFinalControls: openLDAPReferenceSortedFinalControls(
						syncprovFirst,
						false,
					),
				},
				{
					name: "sync-sort-vlv",
					controls: []ldapwire.Control{
						syncControl,
						sortControl,
						vlvControl,
					},
					wantDNs: openLDAPReferenceSortedDNs()[:2],
					wantEntryControl: openLDAPReferenceSortedEntryControl(
						syncprovFirst,
					),
					wantFinalControls: openLDAPReferenceSortedFinalControls(
						syncprovFirst,
						true,
					),
				},
				{
					name: "persistent-sync-sort",
					controls: []ldapwire.Control{
						persistentSyncControl,
						sortControl,
					},
					persist:          true,
					wantDNs:          openLDAPReferencePersistentDNs(syncprovFirst),
					wantEntryControl: syncStateControlOID,
					wantFinalControls: openLDAPReferencePersistentControls(
						syncprovFirst,
					),
					wantRefreshDone: !syncprovFirst,
					wantIncomplete:  syncprovFirst,
				},
				{
					name: "persistent-sync-sort-vlv",
					controls: []ldapwire.Control{
						persistentSyncControl,
						sortControl,
						vlvControl,
					},
					persist: true,
					wantDNs: openLDAPReferencePersistentVLVDNs(
						syncprovFirst,
					),
					wantEntryControl: syncStateControlOID,
					wantFinalControls: openLDAPReferencePersistentVLVControls(
						syncprovFirst,
					),
					wantRefreshDone: !syncprovFirst,
					wantIncomplete:  syncprovFirst,
				},
			} {
				t.Run(test.name, func(t *testing.T) {
					uri, stop := startOpenLDAPReferenceServer(
						t,
						tools,
						overlays,
					)
					defer stop()
					result := runOpenLDAPReferenceSearch(
						t,
						uri,
						test.controls,
						test.persist,
					)
					assertOpenLDAPReferenceSearch(
						t,
						result,
						test.wantDNs,
						test.wantEntryControl,
						test.wantFinalControls,
						test.wantRefreshDone,
						test.wantIncomplete,
					)
				})
			}
		})
	}
}

func requireOpenLDAPReferenceTools(t *testing.T) openLDAPReferenceTools {
	t.Helper()
	if os.Getenv(openLDAPReferenceTestsEnv) == "" {
		t.Skipf(
			"set %s=1 to run tests against a local OpenLDAP installation",
			openLDAPReferenceTestsEnv,
		)
	}

	find := func(name string, candidates ...string) string {
		t.Helper()
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

	slapd := os.Getenv("OPENLDAP_SLAPD")
	if slapd == "" {
		slapd = find(
			"slapd",
			"/opt/homebrew/opt/openldap/libexec/slapd",
			"/usr/lib/openldap/slapd",
			"/usr/sbin/slapd",
		)
	}
	slapadd := os.Getenv("OPENLDAP_SLAPADD")
	if slapadd == "" {
		slapadd = find(
			"slapadd",
			"/opt/homebrew/opt/openldap/sbin/slapadd",
			"/usr/sbin/slapadd",
		)
	}
	return openLDAPReferenceTools{
		slapd:     slapd,
		slapadd:   slapadd,
		schemaDir: schemaDir,
	}
}

func requireOpenLDAPACIReference(t *testing.T, tools openLDAPReferenceTools) {
	t.Helper()
	root := t.TempDir()
	databaseDir := filepath.Join(root, "db")
	if err := os.Mkdir(databaseDir, 0o700); err != nil {
		t.Fatalf("create OpenLDAP ACI probe database: %v", err)
	}
	configPath := filepath.Join(root, "slapd.conf")
	config := fmt.Sprintf(
		`include %s
database mdb
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
directory %s
access to * by dynacl/aci write
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		databaseDir,
	)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write OpenLDAP ACI probe config: %v", err)
	}
	command := exec.Command(tools.slapd, "-Ttest", "-u", "-f", configPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf(
			"OpenLDAP reference was built without dynacl/aci: %v: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}
}

func startOpenLDAPReferenceServer(
	t *testing.T,
	tools openLDAPReferenceTools,
	overlays []string,
) (string, func()) {
	t.Helper()
	return startOpenLDAPReferenceServerWithConfig(
		t,
		tools,
		overlays,
		"",
		"",
		"",
	)
}

func startOpenLDAPReferenceServerWithConfig(
	t *testing.T,
	tools openLDAPReferenceTools,
	overlays []string,
	globalConfig,
	databaseConfig,
	extraData string,
) (string, func()) {
	t.Helper()
	root := t.TempDir()
	databaseDir := filepath.Join(root, "db")
	if err := os.Mkdir(databaseDir, 0o700); err != nil {
		t.Fatalf("create OpenLDAP database directory: %v", err)
	}
	configPath := filepath.Join(root, "slapd.conf")
	dataPath := filepath.Join(root, "data.ldif")
	overlayConfig := make([]string, len(overlays))
	for index, overlay := range overlays {
		overlayConfig[index] = "overlay " + overlay
	}
	config := fmt.Sprintf(
		`include %s
include %s
include %s
pidfile %s
argsfile %s
%s

database mdb
maxsize 1073741824
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
directory %s
index objectClass eq
index entryUUID,entryCSN eq
%s
%s
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		filepath.Join(root, "slapd.pid"),
		filepath.Join(root, "slapd.args"),
		globalConfig,
		databaseDir,
		databaseConfig,
		strings.Join(overlayConfig, "\n"),
	)
	data := `dn: dc=example,dc=com
objectClass: top
objectClass: domain
dc: example

dn: ou=people,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people

dn: uid=carol,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: carol
cn: Carol
sn: Carol

dn: uid=alice,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Alice

dn: uid=bob,ou=people,dc=example,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: bob
cn: Bob
sn: Bob
` + extraData
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write OpenLDAP config: %v", err)
	}
	if err := os.WriteFile(dataPath, []byte(data), 0o600); err != nil {
		t.Fatalf("write OpenLDAP fixture: %v", err)
	}

	command := exec.Command(tools.slapadd, "-q", "-f", configPath, "-l", dataPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("seed OpenLDAP fixture: %v\n%s", err, output)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve OpenLDAP port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release OpenLDAP port: %v", err)
	}
	uri := "ldap://" + address
	var logs bytes.Buffer
	debugLevel := os.Getenv(openLDAPSlapdDebugEnv)
	if debugLevel == "" {
		debugLevel = "0"
	}
	slapd := exec.Command(
		tools.slapd,
		"-f",
		configPath,
		"-h",
		uri,
		"-d",
		debugLevel,
	)
	slapd.Stdout = &logs
	slapd.Stderr = &logs
	if err := slapd.Start(); err != nil {
		t.Fatalf("start OpenLDAP slapd: %v", err)
	}
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- slapd.Wait()
	}()
	stopped := false
	reportUnexpectedExit := func(waitErr error) {
		t.Logf(
			"OpenLDAP slapd exited before cleanup: %v\nslapd.conf:\n%s\nslapd log tail:\n%s",
			waitErr,
			config,
			openLDAPReferenceLogTail(logs.Bytes()),
		)
	}
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		defer func() {
			if t.Failed() && logs.Len() > 0 {
				t.Logf("OpenLDAP slapd log tail:\n%s", openLDAPReferenceLogTail(logs.Bytes()))
			}
		}()
		select {
		case waitErr := <-waitDone:
			reportUnexpectedExit(waitErr)
			return
		default:
		}
		if slapd.Process == nil {
			return
		}
		if err := slapd.Process.Signal(os.Interrupt); err != nil {
			_ = slapd.Process.Kill()
			<-waitDone
			return
		}
		select {
		case <-waitDone:
		case <-time.After(5 * time.Second):
			_ = slapd.Process.Kill()
			<-waitDone
		}
	}
	t.Cleanup(stop)

	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case waitErr := <-waitDone:
			stopped = true
			t.Fatalf(
				"OpenLDAP slapd exited during startup: %v\nslapd.conf:\n%s\nslapd log tail:\n%s",
				waitErr,
				config,
				openLDAPReferenceLogTail(logs.Bytes()),
			)
		default:
		}
		connection, dialErr := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		if time.Now().After(deadline) {
			stop()
			t.Fatalf("OpenLDAP slapd did not start: %v\n%s", dialErr, logs.Bytes())
		}
		time.Sleep(20 * time.Millisecond)
	}
	return uri, stop
}

func openLDAPReferenceLogTail(log []byte) string {
	const maxLogBytes = 64 << 10
	if len(log) == 0 {
		return "<empty>"
	}
	if len(log) > maxLogBytes {
		return "<truncated>\n" + string(log[len(log)-maxLogBytes:])
	}
	return string(log)
}

type openLDAPReferenceControl struct {
	oid      string
	value    []byte
	hasValue bool
}

type openLDAPReferenceEntry struct {
	dn       string
	controls []openLDAPReferenceControl
}

type openLDAPReferenceSearchResult struct {
	entries      []openLDAPReferenceEntry
	intermediate []string
	resultCode   int64
	controls     []openLDAPReferenceControl
	refreshDone  bool
	timedOut     bool
	closed       bool
}

func runOpenLDAPReferenceSearch(
	t *testing.T,
	uri string,
	controls []ldapwire.Control,
	stopAtRefreshDone bool,
) openLDAPReferenceSearchResult {
	t.Helper()
	connection := dialAndBindRawLDAP(
		t,
		strings.TrimPrefix(uri, "ldap://"),
		"cn=admin,dc=example,dc=com",
		"secret",
	)
	defer connection.Close()

	request := rawSyncSearchRequestFor(
		t,
		"ou=people,dc=example,dc=com",
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		"(objectClass=inetOrgPerson)",
	)
	rawControls := make([]*ber.Packet, len(controls))
	for index, control := range controls {
		rawControls[index] = encodeRawLDAPControl(control)
	}
	writeOpenLDAPReferenceRequest(t, connection, 2, request, rawControls)
	if stopAtRefreshDone {
		if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("set OpenLDAP persistent search deadline: %v", err)
		}
	}

	var result openLDAPReferenceSearchResult
	for {
		packet, err := ber.ReadPacket(connection)
		if err != nil {
			if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
				result.timedOut = true
				return result
			}
			if stopAtRefreshDone {
				result.closed = true
				return result
			}
			t.Fatalf("read OpenLDAP search response: %v", err)
		}
		if len(packet.Children) < 2 {
			t.Fatalf("malformed OpenLDAP search response: %#v", packet)
		}
		operation := packet.Children[1]
		switch uint64(operation.Tag) {
		case ldapwire.ApplicationSearchResultEntry:
			result.entries = append(result.entries, openLDAPReferenceEntry{
				dn:       string(operation.Children[0].Data.Bytes()),
				controls: openLDAPReferenceControls(packet),
			})
		case ldapwire.ApplicationIntermediateResponse:
			var responseName string
			var responseValue []byte
			for _, child := range operation.Children {
				if child.ClassType != ber.ClassContext {
					continue
				}
				switch child.Tag {
				case 0:
					responseName = string(child.Data.Bytes())
				case 1:
					responseValue = bytes.Clone(child.Data.Bytes())
				}
			}
			result.intermediate = append(result.intermediate, responseName)
			if stopAtRefreshDone && responseName == syncInfoOID {
				info, err := ldapwire.DecodeSyncInfoValue(responseValue)
				if err != nil {
					t.Fatalf("decode OpenLDAP SyncInfo: %v", err)
				}
				if (info.Kind == ldapwire.SyncInfoRefreshPresent ||
					info.Kind == ldapwire.SyncInfoRefreshDelete) &&
					info.RefreshDone {
					result.refreshDone = true
					result.controls = openLDAPReferenceControls(packet)
					return result
				}
			}
		case ldapwire.ApplicationSearchResultDone:
			result.resultCode = rawLDAPResultCode(t, operation)
			result.controls = openLDAPReferenceControls(packet)
			return result
		default:
			t.Fatalf(
				"unexpected OpenLDAP search response tag %d",
				operation.Tag,
			)
		}
	}
}

func encodeRawLDAPControl(control ldapwire.Control) *ber.Packet {
	packet := ber.NewSequence("Control")
	packet.AppendChild(rawOctetString([]byte(control.OID)))
	if control.Critical {
		packet.AppendChild(ber.NewLDAPBoolean(
			ber.ClassUniversal,
			ber.TypePrimitive,
			ber.TagBoolean,
			true,
			"criticality",
		))
	}
	if control.HasValue || control.Value != nil {
		packet.AppendChild(rawOctetString(control.Value))
	}
	return packet
}

func writeOpenLDAPReferenceRequest(
	t *testing.T,
	connection net.Conn,
	messageID int64,
	operation *ber.Packet,
	controls []*ber.Packet,
) {
	t.Helper()
	message := ber.NewSequence("LDAPMessage")
	message.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		messageID,
		"messageID",
	))
	message.AppendChild(operation)
	wrapper := ber.Encode(
		ber.ClassContext,
		ber.TypeConstructed,
		0,
		nil,
		"controls",
	)
	for _, control := range controls {
		wrapper.AppendChild(control)
	}
	message.AppendChild(wrapper)
	if err := ldapwire.Write(connection, message.Bytes()); err != nil {
		t.Fatalf("write OpenLDAP reference search: %v", err)
	}
}

func openLDAPReferenceControls(
	message *ber.Packet,
) []openLDAPReferenceControl {
	if len(message.Children) < 3 {
		return nil
	}
	controls := make(
		[]openLDAPReferenceControl,
		0,
		len(message.Children[2].Children),
	)
	for _, packet := range message.Children[2].Children {
		if len(packet.Children) == 0 {
			continue
		}
		control := openLDAPReferenceControl{
			oid: string(packet.Children[0].Data.Bytes()),
		}
		for _, child := range packet.Children[1:] {
			if child.ClassType == ber.ClassUniversal &&
				child.Tag == ber.TagOctetString {
				control.value = bytes.Clone(child.Data.Bytes())
				control.hasValue = true
			}
		}
		controls = append(controls, control)
	}
	return controls
}

func openLDAPReferenceNaturalDNs() []string {
	return []string{
		"uid=carol,ou=people,dc=example,dc=com",
		"uid=alice,ou=people,dc=example,dc=com",
		"uid=bob,ou=people,dc=example,dc=com",
	}
}

func openLDAPReferenceSortedDNs() []string {
	return []string{
		"uid=alice,ou=people,dc=example,dc=com",
		"uid=bob,ou=people,dc=example,dc=com",
		"uid=carol,ou=people,dc=example,dc=com",
	}
}

func openLDAPReferenceSortedEntryControl(syncprovFirst bool) string {
	if syncprovFirst {
		return syncDoneControlOID
	}
	return syncStateControlOID
}

func openLDAPReferenceSortedFinalControls(
	syncprovFirst bool,
	vlv bool,
) []string {
	controls := []string{syncDoneControlOID}
	if !syncprovFirst {
		return controls
	}
	controls = append(controls, sortResponseControlOID)
	if vlv {
		controls = append(controls, vlvResponseControlOID)
	}
	return controls
}

func openLDAPReferencePersistentDNs(syncprovFirst bool) []string {
	if syncprovFirst {
		return nil
	}
	return openLDAPReferenceSortedDNs()
}

func openLDAPReferencePersistentControls(syncprovFirst bool) []string {
	if syncprovFirst {
		return nil
	}
	return []string{sortResponseControlOID}
}

func openLDAPReferencePersistentVLVDNs(syncprovFirst bool) []string {
	if syncprovFirst {
		return nil
	}
	return openLDAPReferenceSortedDNs()[:2]
}

func openLDAPReferencePersistentVLVControls(syncprovFirst bool) []string {
	if syncprovFirst {
		return nil
	}
	return []string{sortResponseControlOID, vlvResponseControlOID}
}

func assertOpenLDAPReferenceSearch(
	t *testing.T,
	result openLDAPReferenceSearchResult,
	wantDNs []string,
	wantEntryControl string,
	wantFinalControls []string,
	wantRefreshDone bool,
	wantIncomplete bool,
) {
	t.Helper()
	gotDNs := make([]string, len(result.entries))
	for index, entry := range result.entries {
		gotDNs[index] = entry.dn
		gotControls := openLDAPReferenceControlOIDs(entry.controls)
		wantControls := []string(nil)
		if wantEntryControl != "" {
			wantControls = []string{wantEntryControl}
		}
		if !slices.Equal(gotControls, wantControls) {
			t.Fatalf(
				"entry %s controls = %q, want %q",
				entry.dn,
				gotControls,
				wantControls,
			)
		}
	}
	if !slices.Equal(gotDNs, wantDNs) {
		t.Fatalf("entry DNs = %q, want %q", gotDNs, wantDNs)
	}
	if got := openLDAPReferenceControlOIDs(result.controls); !slices.Equal(
		got,
		wantFinalControls,
	) {
		t.Fatalf("final controls = %q, want %q", got, wantFinalControls)
	}
	incomplete := result.timedOut || result.closed
	if result.refreshDone != wantRefreshDone ||
		incomplete != wantIncomplete {
		t.Fatalf(
			"completion = refreshDone %t timeout %t closed %t, want refreshDone %t incomplete %t",
			result.refreshDone,
			result.timedOut,
			result.closed,
			wantRefreshDone,
			wantIncomplete,
		)
	}
	if !result.timedOut &&
		!result.closed &&
		!result.refreshDone &&
		result.resultCode != 0 {
		t.Fatalf("search result code = %d", result.resultCode)
	}
}

func openLDAPReferenceControlOIDs(
	controls []openLDAPReferenceControl,
) []string {
	oids := make([]string, len(controls))
	for index, control := range controls {
		oids[index] = control.oid
	}
	return oids
}
