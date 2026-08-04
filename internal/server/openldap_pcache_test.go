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
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

const (
	openLDAPPcacheVersion = "2.6.13"
	openLDAPPcacheCommit  = "d172686d3d270bc961b78f3ff00d7019c8dfb094"

	openLDAPPcacheSourceSHA256 = "5a61a9098f8b74001fe852b72a4f83c8bc909e6029994182eed46bc3db678aa1"
	openLDAPPcacheTestSHA256   = "20c11fe3ac343b133695c1873418ab93245c27652723e6213ec8630d4f7bc0f9"

	pcachePhaseOneBaseDN = "ou=people,dc=example,dc=com"
)

type pcachePhaseOneAttribute struct {
	name   string
	values []string
}

type pcachePhaseOneEntry struct {
	dn         string
	attributes []pcachePhaseOneAttribute
}

type pcachePhaseOneSearch struct {
	code          uint16
	entries       []pcachePhaseOneEntry
	pagingControl bool
	transportErr  string
}

type pcachePhaseOneOutcome struct {
	startupError string

	positiveMiss pcachePhaseOneSearch
	positiveHit  pcachePhaseOneSearch
	typesOnlyHit pcachePhaseOneSearch

	negativeMiss pcachePhaseOneSearch
	negativeHit  pcachePhaseOneSearch

	exactLimitMiss pcachePhaseOneSearch
	exactLimitHit  pcachePhaseOneSearch
	overLimitMiss  pcachePhaseOneSearch
	overLimitHit   pcachePhaseOneSearch

	ttlMiss      pcachePhaseOneSearch
	ttlImmediate pcachePhaseOneSearch
	ttlExpired   pcachePhaseOneSearch

	pagedNoncritical pcachePhaseOneSearch
	pagedCritical    pcachePhaseOneSearch
}

type pcachePhaseOnePerson struct {
	uid string
	cn  string
	sn  string
}

type pcachePhaseOneProxyConfig struct {
	entryLimit       int
	consistencyCheck int
	ttl              string
	negativeTTL      string
	limitTTL         string
}

type pcachePhaseOneProxyFactory func(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerURI string,
	config pcachePhaseOneProxyConfig,
) (string, func(), error)

func TestOpenLDAPReferencePcachePhaseOne(t *testing.T) {
	tools := requireOpenLDAPPcacheReferenceTools(t)
	assertPinnedOpenLDAPPcacheReference(t, tools)

	var reference pcachePhaseOneOutcome
	t.Run("OpenLDAP fixture self assertion", func(t *testing.T) {
		reference = observePcachePhaseOne(
			t,
			tools,
			startOpenLDAPPcachePhaseOneProxy,
		)
		want := expectedPcachePhaseOneOutcome()
		if !reflect.DeepEqual(reference, want) {
			t.Fatalf(
				"OpenLDAP pcache Phase 1 fixture drifted:\n got: %#v\nwant: %#v",
				reference,
				want,
			)
		}
	})
	if t.Failed() {
		return
	}

	t.Run("ldap-go differential", func(t *testing.T) {
		got := observePcachePhaseOne(
			t,
			tools,
			startLDAPGoPcachePhaseOneProxy,
		)
		if !reflect.DeepEqual(got, reference) {
			t.Fatalf(
				"ldap-go pcache Phase 1 is not implemented or differs from OpenLDAP 2.6.13:\n%s",
				firstPcachePhaseOneDifference(reference, got),
			)
		}
	})
}

func firstPcachePhaseOneDifference(
	want,
	got pcachePhaseOneOutcome,
) string {
	if want.startupError != got.startupError {
		return fmt.Sprintf(
			"startup: OpenLDAP=%q ldap-go=%q",
			want.startupError,
			got.startupError,
		)
	}
	searches := []struct {
		name string
		want pcachePhaseOneSearch
		got  pcachePhaseOneSearch
	}{
		{"positive miss", want.positiveMiss, got.positiveMiss},
		{"positive hit after provider stop", want.positiveHit, got.positiveHit},
		{"typesOnly hit after provider stop", want.typesOnlyHit, got.typesOnlyHit},
		{"negative miss", want.negativeMiss, got.negativeMiss},
		{"negative cached hit", want.negativeHit, got.negativeHit},
		{"exact entry_limit miss", want.exactLimitMiss, got.exactLimitMiss},
		{"exact entry_limit hit", want.exactLimitHit, got.exactLimitHit},
		{"over entry_limit miss", want.overLimitMiss, got.overLimitMiss},
		{"over entry_limit hit", want.overLimitHit, got.overLimitHit},
		{"TTL miss", want.ttlMiss, got.ttlMiss},
		{"TTL immediate hit", want.ttlImmediate, got.ttlImmediate},
		{"TTL expired", want.ttlExpired, got.ttlExpired},
		{"paged noncritical", want.pagedNoncritical, got.pagedNoncritical},
		{"paged critical", want.pagedCritical, got.pagedCritical},
	}
	for _, search := range searches {
		if !reflect.DeepEqual(search.want, search.got) {
			return fmt.Sprintf(
				"%s:\nOpenLDAP: %#v\nldap-go:  %#v",
				search.name,
				search.want,
				search.got,
			)
		}
	}
	return "outcomes differ in an unclassified field"
}

func requireOpenLDAPPcacheReferenceTools(
	t *testing.T,
) openLDAPReferenceTools {
	t.Helper()
	if got := os.Getenv(openLDAPReferenceTestsEnv); got != "1" {
		t.Skipf("set %s=1 to run the pcache reference test", openLDAPReferenceTestsEnv)
	}
	tools := requireOpenLDAPReferenceTools(t)
	output, err := exec.Command(tools.slapd, "-VVV").CombinedOutput()
	if err != nil && len(output) == 0 {
		t.Fatalf("inspect pinned OpenLDAP features: %v", err)
	}
	features := make(map[string]bool)
	for _, line := range strings.Split(string(output), "\n") {
		features[strings.ToLower(strings.TrimSpace(line))] = true
	}
	for _, feature := range []string{"ldap", "mdb", "pcache"} {
		if !features[feature] {
			t.Fatalf("pinned OpenLDAP build lacks required %s support:\n%s", feature, output)
		}
	}
	return tools
}

func assertPinnedOpenLDAPPcacheReference(
	t *testing.T,
	tools openLDAPReferenceTools,
) {
	t.Helper()
	if got := os.Getenv("OPENLDAP_REFERENCE_VERIFIED"); got != "1" {
		t.Fatalf("OPENLDAP_REFERENCE_VERIFIED = %q, want 1", got)
	}
	if got := os.Getenv("OPENLDAP_ACTUAL_VERSION"); got != openLDAPPcacheVersion {
		t.Fatalf("OpenLDAP reference version = %q, want %q", got, openLDAPPcacheVersion)
	}
	if got := os.Getenv("OPENLDAP_COMMIT"); got != openLDAPPcacheCommit {
		t.Fatalf("OpenLDAP reference commit = %q, want %q", got, openLDAPPcacheCommit)
	}

	versionOutput, err := exec.Command(tools.slapd, "-VV").CombinedOutput()
	if err != nil && len(versionOutput) == 0 {
		t.Fatalf("inspect OpenLDAP version: %v", err)
	}
	if !strings.Contains(
		string(versionOutput),
		"OpenLDAP: slapd "+openLDAPPcacheVersion+" ",
	) {
		t.Fatalf(
			"pcache differential requires OpenLDAP slapd %s, got:\n%s",
			openLDAPPcacheVersion,
			versionOutput,
		)
	}

	source := os.Getenv("OPENLDAP_SOURCE")
	if source == "" {
		t.Fatal("OPENLDAP_SOURCE must name the pinned OpenLDAP checkout")
	}
	revision, err := exec.Command("git", "-C", source, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("inspect pinned OpenLDAP checkout: %v", err)
	}
	if got := strings.TrimSpace(string(revision)); got != openLDAPPcacheCommit {
		t.Fatalf("OpenLDAP source checkout = %q, want %q", got, openLDAPPcacheCommit)
	}

	pcachePath := filepath.Join(source, "servers", "slapd", "overlays", "pcache.c")
	assertOpenLDAPPcacheFile(
		t,
		pcachePath,
		openLDAPPcacheSourceSHA256,
		[]string{
			"static int\npcache_op_search(",
			"if (op->ors_attrsonly)",
			"if ( si->count < si->max )",
			"si->qtemp->negttl",
			"case SLAP_CONTROL_NONCRITICAL:",
			"slap_remove_control( op, rs, slap_cids.sc_pagedResults, NULL );",
		},
	)
	assertOpenLDAPPcacheFile(
		t,
		filepath.Join(source, "tests", "scripts", "test020-proxycache"),
		openLDAPPcacheTestSHA256,
		[]string{
			`PCACHE_ENTRY_LIMIT=${PCACHE_ENTRY_LIMIT-"6"}`,
			"CACHEABILITY=0111110111",
			"ANSWERABILITY=1110011",
			`echo "Testing cache refresh"`,
		},
	)
}

func assertOpenLDAPPcacheFile(
	t *testing.T,
	path,
	wantSHA256 string,
	anchors []string,
) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pinned OpenLDAP source %s: %v", path, err)
	}
	gotSHA256 := fmt.Sprintf("%x", sha256.Sum256(contents))
	if gotSHA256 != wantSHA256 {
		t.Fatalf("SHA-256(%s) = %s, want %s", path, gotSHA256, wantSHA256)
	}
	for _, anchor := range anchors {
		if !bytes.Contains(contents, []byte(anchor)) {
			t.Fatalf("pinned OpenLDAP source %s lacks %q", path, anchor)
		}
	}
}

func observePcachePhaseOne(
	t *testing.T,
	tools openLDAPReferenceTools,
	startProxy pcachePhaseOneProxyFactory,
) pcachePhaseOneOutcome {
	t.Helper()
	outcome := pcachePhaseOneOutcome{}
	longLived := pcachePhaseOneProxyConfig{
		entryLimit:       10,
		consistencyCheck: 1,
		ttl:              "30",
		negativeTTL:      "30",
		limitTTL:         "30",
	}

	providerURI, stopProvider := startOpenLDAPReferenceServer(t, tools, nil)
	provider := bindOverlayReferenceClient(t, providerURI, "secret")
	addPcachePhaseOnePeople(t, provider, []pcachePhaseOnePerson{
		{uid: "cached", cn: "Cached One", sn: "Cached"},
		{uid: "page1", cn: "Page One", sn: "Page"},
		{uid: "page2", cn: "Page Two", sn: "Page"},
		{uid: "page3", cn: "Page Three", sn: "Page"},
	})
	proxyURI, stopProxy, err := startProxy(t, tools, providerURI, longLived)
	if err != nil {
		outcome.startupError = err.Error()
		provider.Close()
		stopProvider()
		return outcome
	}
	proxy := bindPcachePhaseOneClient(t, proxyURI)
	outcome.positiveMiss = searchPcachePhaseOne(
		t,
		proxy,
		"(sn=Cached)",
		false,
		nil,
	)
	outcome.pagedNoncritical = searchPcachePhaseOne(
		t,
		proxy,
		"(sn=Page)",
		false,
		[]ldap.Control{ldap.NewControlPaging(1)},
	)
	outcome.pagedCritical = searchPcachePhaseOne(
		t,
		proxy,
		"(sn=Page)",
		false,
		[]ldap.Control{pcacheCriticalPagingControl{size: 1}},
	)
	provider.Close()
	stopProvider()
	outcome.positiveHit = searchPcachePhaseOne(
		t,
		proxy,
		"(sn=Cached)",
		false,
		nil,
	)
	outcome.typesOnlyHit = searchPcachePhaseOne(
		t,
		proxy,
		"(sn=Cached)",
		true,
		nil,
	)
	proxy.Close()
	stopProxy()

	providerURI, stopProvider = startOpenLDAPReferenceServer(t, tools, nil)
	provider = bindOverlayReferenceClient(t, providerURI, "secret")
	proxyURI, stopProxy, err = startProxy(t, tools, providerURI, longLived)
	if err != nil {
		outcome.startupError = err.Error()
		provider.Close()
		stopProvider()
		return outcome
	}
	proxy = bindPcachePhaseOneClient(t, proxyURI)
	outcome.negativeMiss = searchPcachePhaseOne(
		t,
		proxy,
		"(sn=Late)",
		false,
		nil,
	)
	addPcachePhaseOnePeople(t, provider, []pcachePhaseOnePerson{
		{uid: "late", cn: "Late Arrival", sn: "Late"},
	})
	outcome.negativeHit = searchPcachePhaseOne(
		t,
		proxy,
		"(sn=Late)",
		false,
		nil,
	)
	proxy.Close()
	provider.Close()
	stopProxy()
	stopProvider()

	providerURI, stopProvider = startOpenLDAPReferenceServer(t, tools, nil)
	provider = bindOverlayReferenceClient(t, providerURI, "secret")
	addPcachePhaseOnePeople(t, provider, []pcachePhaseOnePerson{
		{uid: "exact1", cn: "Exact One", sn: "Exact"},
		{uid: "exact2", cn: "Exact Two", sn: "Exact"},
		{uid: "over1", cn: "Over One", sn: "Over"},
		{uid: "over2", cn: "Over Two", sn: "Over"},
		{uid: "over3", cn: "Over Three", sn: "Over"},
	})
	limitConfig := longLived
	limitConfig.entryLimit = 2
	proxyURI, stopProxy, err = startProxy(t, tools, providerURI, limitConfig)
	if err != nil {
		outcome.startupError = err.Error()
		provider.Close()
		stopProvider()
		return outcome
	}
	proxy = bindPcachePhaseOneClient(t, proxyURI)
	outcome.exactLimitMiss = searchPcachePhaseOne(
		t,
		proxy,
		"(sn=Exact)",
		false,
		nil,
	)
	outcome.overLimitMiss = searchPcachePhaseOne(
		t,
		proxy,
		"(sn=Over)",
		false,
		nil,
	)
	provider.Close()
	stopProvider()
	outcome.exactLimitHit = searchPcachePhaseOne(
		t,
		proxy,
		"(sn=Exact)",
		false,
		nil,
	)
	outcome.overLimitHit = searchPcachePhaseOne(
		t,
		proxy,
		"(sn=Over)",
		false,
		nil,
	)
	proxy.Close()
	stopProxy()

	providerURI, stopProvider = startOpenLDAPReferenceServer(t, tools, nil)
	provider = bindOverlayReferenceClient(t, providerURI, "secret")
	addPcachePhaseOnePeople(t, provider, []pcachePhaseOnePerson{
		{uid: "ttl", cn: "TTL Entry", sn: "TTL"},
	})
	ttlConfig := longLived
	ttlConfig.ttl = "1"
	proxyURI, stopProxy, err = startProxy(t, tools, providerURI, ttlConfig)
	if err != nil {
		outcome.startupError = err.Error()
		provider.Close()
		stopProvider()
		return outcome
	}
	proxy = bindPcachePhaseOneClient(t, proxyURI)
	outcome.ttlMiss = searchPcachePhaseOne(t, proxy, "(sn=TTL)", false, nil)
	provider.Close()
	stopProvider()
	outcome.ttlImmediate = searchPcachePhaseOne(t, proxy, "(sn=TTL)", false, nil)
	outcome.ttlExpired = waitForPcachePhaseOneExpiry(t, proxy, "(sn=TTL)")
	proxy.Close()
	stopProxy()

	return outcome
}

func addPcachePhaseOnePeople(
	t *testing.T,
	client *ldap.Conn,
	people []pcachePhaseOnePerson,
) {
	t.Helper()
	for _, person := range people {
		request := ldap.NewAddRequest(
			"uid="+person.uid+","+pcachePhaseOneBaseDN,
			nil,
		)
		request.Attribute("objectClass", []string{"inetOrgPerson"})
		request.Attribute("uid", []string{person.uid})
		request.Attribute("cn", []string{person.cn})
		request.Attribute("sn", []string{person.sn})
		if err := client.Add(request); err != nil {
			t.Fatalf("add pcache provider entry %s: %v", request.DN, err)
		}
	}
}

func bindPcachePhaseOneClient(t *testing.T, uri string) *ldap.Conn {
	t.Helper()
	client, err := ldap.DialURL(uri)
	if err != nil {
		t.Fatalf("DialURL(%s): %v", uri, err)
	}
	client.SetTimeout(3 * time.Second)
	if err := client.Bind("cn=admin,dc=example,dc=com", "secret"); err != nil {
		client.Close()
		t.Fatalf("bind pcache proxy %s: %v", uri, err)
	}
	return client
}

func searchPcachePhaseOne(
	t *testing.T,
	client *ldap.Conn,
	filter string,
	typesOnly bool,
	controls []ldap.Control,
) pcachePhaseOneSearch {
	t.Helper()
	result, err := client.Search(ldap.NewSearchRequest(
		pcachePhaseOneBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		typesOnly,
		filter,
		[]string{"uid", "cn", "sn"},
		controls,
	))
	outcome := pcachePhaseOneSearch{code: ldap.LDAPResultSuccess}
	if err != nil {
		var ldapErr *ldap.Error
		if !errors.As(err, &ldapErr) {
			outcome.transportErr = err.Error()
		} else {
			outcome.code = ldapErr.ResultCode
		}
	}
	if result == nil {
		return outcome
	}
	for _, control := range result.Controls {
		if control.GetControlType() == ldap.ControlTypePaging {
			outcome.pagingControl = true
		}
	}
	for _, entry := range result.Entries {
		observed := pcachePhaseOneEntry{dn: strings.ToLower(entry.DN)}
		for _, attribute := range entry.Attributes {
			values := append([]string(nil), attribute.Values...)
			sort.Strings(values)
			observed.attributes = append(
				observed.attributes,
				pcachePhaseOneAttribute{
					name:   strings.ToLower(attribute.Name),
					values: values,
				},
			)
		}
		sort.Slice(observed.attributes, func(left, right int) bool {
			return observed.attributes[left].name < observed.attributes[right].name
		})
		outcome.entries = append(outcome.entries, observed)
	}
	sort.Slice(outcome.entries, func(left, right int) bool {
		return outcome.entries[left].dn < outcome.entries[right].dn
	})
	return outcome
}

func waitForPcachePhaseOneExpiry(
	t *testing.T,
	client *ldap.Conn,
	filter string,
) pcachePhaseOneSearch {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		outcome := searchPcachePhaseOne(t, client, filter, false, nil)
		if outcome.code != ldap.LDAPResultSuccess || outcome.transportErr != "" {
			return outcome
		}
		if time.Now().After(deadline) {
			t.Fatalf("OpenLDAP pcache entry did not expire before %s", deadline)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type pcacheCriticalPagingControl struct {
	size uint32
}

func (control pcacheCriticalPagingControl) GetControlType() string {
	return ldap.ControlTypePaging
}

func (control pcacheCriticalPagingControl) Encode() *ber.Packet {
	packet := ber.Encode(
		ber.ClassUniversal,
		ber.TypeConstructed,
		ber.TagSequence,
		nil,
		"Critical paging control",
	)
	packet.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		ldap.ControlTypePaging,
		"Control type",
	))
	packet.AppendChild(ber.NewBoolean(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagBoolean,
		true,
		"Criticality",
	))
	value := ber.Encode(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		nil,
		"Control value",
	)
	sequence := ber.Encode(
		ber.ClassUniversal,
		ber.TypeConstructed,
		ber.TagSequence,
		nil,
		"Paged results value",
	)
	sequence.AppendChild(ber.NewInteger(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagInteger,
		int64(control.size),
		"Page size",
	))
	sequence.AppendChild(ber.NewString(
		ber.ClassUniversal,
		ber.TypePrimitive,
		ber.TagOctetString,
		"",
		"Cookie",
	))
	value.AppendChild(sequence)
	packet.AppendChild(value)
	return packet
}

func (control pcacheCriticalPagingControl) String() string {
	return fmt.Sprintf("critical paging control size=%d", control.size)
}

func expectedPcachePhaseOneOutcome() pcachePhaseOneOutcome {
	cached := []pcachePhaseOnePerson{{uid: "cached", cn: "Cached One", sn: "Cached"}}
	page := []pcachePhaseOnePerson{
		{uid: "page1", cn: "Page One", sn: "Page"},
		{uid: "page2", cn: "Page Two", sn: "Page"},
		{uid: "page3", cn: "Page Three", sn: "Page"},
	}
	exact := []pcachePhaseOnePerson{
		{uid: "exact1", cn: "Exact One", sn: "Exact"},
		{uid: "exact2", cn: "Exact Two", sn: "Exact"},
	}
	over := []pcachePhaseOnePerson{
		{uid: "over1", cn: "Over One", sn: "Over"},
		{uid: "over2", cn: "Over Two", sn: "Over"},
		{uid: "over3", cn: "Over Three", sn: "Over"},
	}
	ttl := []pcachePhaseOnePerson{{uid: "ttl", cn: "TTL Entry", sn: "TTL"}}
	return pcachePhaseOneOutcome{
		positiveMiss:   expectedPcachePhaseOneSearch(cached, false),
		positiveHit:    expectedPcachePhaseOneSearch(cached, false),
		typesOnlyHit:   expectedPcachePhaseOneSearch(cached, true),
		negativeMiss:   pcachePhaseOneSearch{code: ldap.LDAPResultSuccess},
		negativeHit:    pcachePhaseOneSearch{code: ldap.LDAPResultSuccess},
		exactLimitMiss: expectedPcachePhaseOneSearch(exact, false),
		exactLimitHit:  expectedPcachePhaseOneSearch(exact, false),
		overLimitMiss:  expectedPcachePhaseOneSearch(over, false),
		overLimitHit: pcachePhaseOneSearch{
			code: ldap.LDAPResultUnavailable,
		},
		ttlMiss:      expectedPcachePhaseOneSearch(ttl, false),
		ttlImmediate: expectedPcachePhaseOneSearch(ttl, false),
		ttlExpired: pcachePhaseOneSearch{
			code: ldap.LDAPResultUnavailable,
		},
		pagedNoncritical: expectedPcachePhaseOneSearch(page, false),
		pagedCritical: pcachePhaseOneSearch{
			code: ldap.LDAPResultUnavailableCriticalExtension,
		},
	}
}

func expectedPcachePhaseOneSearch(
	people []pcachePhaseOnePerson,
	typesOnly bool,
) pcachePhaseOneSearch {
	outcome := pcachePhaseOneSearch{code: ldap.LDAPResultSuccess}
	for _, person := range people {
		attributes := []pcachePhaseOneAttribute{
			{name: "cn", values: []string{person.cn}},
			{name: "sn", values: []string{person.sn}},
			{name: "uid", values: []string{person.uid}},
		}
		if typesOnly {
			for index := range attributes {
				attributes[index].values = nil
			}
		}
		outcome.entries = append(outcome.entries, pcachePhaseOneEntry{
			dn:         "uid=" + person.uid + "," + pcachePhaseOneBaseDN,
			attributes: attributes,
		})
	}
	sort.Slice(outcome.entries, func(left, right int) bool {
		return outcome.entries[left].dn < outcome.entries[right].dn
	})
	return outcome
}

func startOpenLDAPPcachePhaseOneProxy(
	t *testing.T,
	tools openLDAPReferenceTools,
	providerURI string,
	config pcachePhaseOneProxyConfig,
) (string, func(), error) {
	t.Helper()
	root := t.TempDir()
	cacheDirectory := filepath.Join(root, "cache")
	if err := os.Mkdir(cacheDirectory, 0o700); err != nil {
		return "", nil, fmt.Errorf("create pcache MDB directory: %w", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("reserve pcache proxy port: %w", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return "", nil, fmt.Errorf("release pcache proxy port: %w", err)
	}
	uri := "ldap://" + address
	configuration := fmt.Sprintf(
		`include %s
include %s
include %s
pidfile %s
argsfile %s

database ldap
suffix "dc=example,dc=com"
rootdn "cn=admin,dc=example,dc=com"
rootpw secret
uri %s
network-timeout 1
chase-referrals FALSE

overlay pcache
pcache mdb 100 1 %d %d
pcacheAttrset 0 uid cn sn
pcacheTemplate (sn=) 0 %s %s %s
directory %s
dbnosync
index objectClass,sn eq
`,
		filepath.Join(tools.schemaDir, "core.schema"),
		filepath.Join(tools.schemaDir, "cosine.schema"),
		filepath.Join(tools.schemaDir, "inetorgperson.schema"),
		filepath.Join(root, "slapd.pid"),
		filepath.Join(root, "slapd.args"),
		providerURI,
		config.entryLimit,
		config.consistencyCheck,
		config.ttl,
		config.negativeTTL,
		config.limitTTL,
		cacheDirectory,
	)
	configPath := filepath.Join(root, "slapd.conf")
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		return "", nil, fmt.Errorf("write pcache proxy configuration: %w", err)
	}
	check := exec.Command(tools.slapd, "-Ttest", "-u", "-f", configPath)
	if output, err := check.CombinedOutput(); err != nil {
		return "", nil, fmt.Errorf(
			"validate pcache proxy configuration: %w\n%s\nconfiguration:\n%s",
			err,
			output,
			configuration,
		)
	}

	var logs bytes.Buffer
	debugLevel := os.Getenv(openLDAPSlapdDebugEnv)
	if debugLevel == "" {
		debugLevel = "0"
	}
	command := exec.Command(
		tools.slapd,
		"-f",
		configPath,
		"-h",
		uri,
		"-d",
		debugLevel,
	)
	command.Stdout = &logs
	command.Stderr = &logs
	if err := command.Start(); err != nil {
		return "", nil, fmt.Errorf("start OpenLDAP pcache proxy: %w", err)
	}
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- command.Wait()
	}()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			if command.Process != nil {
				_ = command.Process.Signal(os.Interrupt)
			}
			select {
			case <-waitDone:
			case <-time.After(5 * time.Second):
				if command.Process != nil {
					_ = command.Process.Kill()
				}
				<-waitDone
			}
		})
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case waitErr := <-waitDone:
			return "", nil, fmt.Errorf(
				"OpenLDAP pcache proxy exited during startup: %v\nconfiguration:\n%s\nlog:\n%s",
				waitErr,
				configuration,
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
			return "", nil, fmt.Errorf(
				"OpenLDAP pcache proxy did not start: %v\n%s",
				dialErr,
				openLDAPReferenceLogTail(logs.Bytes()),
			)
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Cleanup(stop)
	return uri, stop, nil
}

func startLDAPGoPcachePhaseOneProxy(
	t *testing.T,
	_ openLDAPReferenceTools,
	providerURI string,
	config pcachePhaseOneProxyConfig,
) (string, func(), error) {
	t.Helper()
	store := storage.NewMemory()
	if err := seedLDAPGoPcachePhaseOneConfiguration(
		store,
		providerURI,
		config,
	); err != nil {
		_ = store.Close()
		return "", nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = store.Close()
		return "", nil, fmt.Errorf("listen for ldap-go pcache proxy: %w", err)
	}
	instance, err := New(Config{Store: store})
	if err != nil {
		_ = listener.Close()
		_ = store.Close()
		return "", nil, fmt.Errorf("start ldap-go with pcache configuration: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- instance.Serve(ctx, listener)
	}()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			select {
			case serveErr := <-done:
				if serveErr != nil {
					t.Errorf("ldap-go pcache proxy Serve(): %v", serveErr)
				}
			case <-time.After(5 * time.Second):
				t.Error("ldap-go pcache proxy did not stop")
			}
			_ = store.Close()
		})
	}
	t.Cleanup(stop)
	return "ldap://" + listener.Addr().String(), stop, nil
}

func seedLDAPGoPcachePhaseOneConfiguration(
	store storage.Store,
	providerURI string,
	config pcachePhaseOneProxyConfig,
) error {
	databaseDN := "olcDatabase={1}ldap,cn=config"
	entries := []directory.Entry{
		{
			DN: "cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcGlobal")},
				{Description: "cn", Values: stringValues("config")},
			},
		},
		{
			DN: "olcDatabase={0}config,cn=config",
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{0}config")},
				{Description: "olcRootDN", Values: stringValues("cn=config")},
				{Description: "olcRootPW", Values: stringValues("config-secret")},
			},
		},
		{
			DN: databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcDatabaseConfig")},
				{Description: "olcDatabase", Values: stringValues("{1}ldap")},
				{Description: "olcSuffix", Values: stringValues("dc=example,dc=com")},
				{Description: "olcRootDN", Values: stringValues("cn=admin,dc=example,dc=com")},
				{Description: "olcRootPW", Values: stringValues("secret")},
				{Description: "olcDbURI", Values: stringValues(providerURI)},
				{Description: "olcDbNetworkTimeout", Values: stringValues("1s")},
				{Description: "olcDbChaseReferrals", Values: stringValues("FALSE")},
			},
		},
		{
			DN: "olcOverlay={0}pcache," + databaseDN,
			Attributes: []directory.Attribute{
				{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcPcacheConfig")},
				{Description: "olcOverlay", Values: stringValues("{0}pcache")},
				{
					Description: "olcPcache",
					Values: stringValues(fmt.Sprintf(
						"mdb 100 1 %d %d",
						config.entryLimit,
						config.consistencyCheck,
					)),
				},
				{Description: "olcPcacheAttrset", Values: stringValues("0 uid cn sn")},
				{
					Description: "olcPcacheTemplate",
					Values: stringValues(fmt.Sprintf(
						"(sn=) 0 %s %s %s",
						config.ttl,
						config.negativeTTL,
						config.limitTTL,
					)),
				},
			},
		},
	}
	return store.Update(context.Background(), func(writer storage.Writer) error {
		for _, entry := range entries {
			if err := writer.Put(entry, false); err != nil {
				return err
			}
		}
		return writer.SetNamingContexts([]string{"dc=example,dc=com", "cn=config"})
	})
}
