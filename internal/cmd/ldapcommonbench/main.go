// ldapcommonbench compares common SDK operations on explicit disposable servers.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

var stageNames = []string{"userBind", "userBindWrong", "nonrootBase", "nonrootEquality", "memberEquality", "groupBase", "nestedMembership"}

type endpoint struct {
	Name string `json:"name"`
	URI  string `json:"uri"`
}

type options struct {
	Endpoints       []endpoint    `json:"endpoints"`
	Base            string        `json:"base"`
	RootBindDN      string        `json:"root_bind_dn"`
	RootPasswordEnv string        `json:"root_password_env"`
	People          string        `json:"people,omitempty"`
	UID             string        `json:"uid,omitempty"`
	Entries         int           `json:"entries"`
	N               int           `json:"n"`
	Repeats         int           `json:"repeats"`
	Stages          []string      `json:"stages"`
	GroupSizes      []int         `json:"group_sizes"`
	SetupDisposable bool          `json:"setup_disposable"`
	Timeout         time.Duration `json:"-"`
	password        string
}

type sample struct {
	Endpoint             string    `json:"endpoint"`
	Stage                string    `json:"stage"`
	Method               string    `json:"method"`
	Members              int       `json:"members,omitzero"`
	Repeat               int       `json:"repeat"`
	Operations           int       `json:"operations"`
	Completed            int       `json:"completed"`
	Requests             int       `json:"requests"`
	TotalMS              float64   `json:"total_ms"`
	LatencyMS            []float64 `json:"latency_ms"`
	VerificationRequests int       `json:"verification_requests"`
	VerificationMS       float64   `json:"verification_ms"`
}

type report struct {
	Config      *options  `json:"config,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	RunDN       string    `json:"run_dn,omitempty"`
	TimeoutMS   float64   `json:"timeout_ms"`
	SetupAdds   int       `json:"setup_adds"`
	CleanupDone []string  `json:"cleanup_done"`
	Samples     []*sample `json:"samples"`
	Error       string    `json:"error"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := execute(ctx, os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func execute(ctx context.Context, args []string, lookup func(string) (string, bool), out, stderr io.Writer) int {
	r := report{StartedAt: time.Now().UTC(), Samples: []*sample{}, CleanupDone: []string{}}
	c, err := parseOptions(args, lookup, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	code := 2
	if err == nil {
		r.Config, r.TimeoutMS = &c, float64(c.Timeout)/float64(time.Millisecond)
		err = probe(ctx, c, &r)
		code = 1
	}
	if err == nil {
		code = 0
	} else {
		r.Error = err.Error()
	}
	if err := json.NewEncoder(out).Encode(r); err != nil {
		fmt.Fprintf(stderr, "write JSON: %v\n", err)
		return 1
	}
	return code
}

func parseOptions(args []string, lookup func(string) (string, bool), stderr io.Writer) (options, error) {
	var c options
	f := flag.NewFlagSet("ldapcommonbench", flag.ContinueOnError)
	f.SetOutput(stderr)
	f.Func("endpoint", "repeatable name=ldap://host:port (or ldaps://); at least one required", func(value string) error {
		name, uri, ok := strings.Cut(value, "=")
		u, err := url.Parse(uri)
		if !ok || strings.TrimSpace(name) == "" || err != nil || u == nil ||
			(u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Hostname() == "" || u.User != nil ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return errors.New("endpoint requires name=ldap[s]://host[:port] without credentials, base, query or fragment")
		}
		if port := u.Port(); port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return errors.New("endpoint port must be in [1,65535]")
			}
		}
		for _, e := range c.Endpoints {
			if e.Name == name || e.URI == uri {
				return errors.New("endpoint names and URIs must be unique")
			}
		}
		c.Endpoints = append(c.Endpoints, endpoint{name, uri})
		return nil
	})
	f.StringVar(&c.Base, "base", "", "required disposable data base DN")
	f.StringVar(&c.RootBindDN, "root-bind-dn", "", "required setup/cleanup Bind DN")
	f.StringVar(&c.RootPasswordEnv, "root-password-env", "", "required environment variable containing root password")
	f.BoolVar(&c.SetupDisposable, "setup-disposable", false, "authorize isolated fixture writes on disposable task copies")
	f.IntVar(&c.N, "n", 100, "operations per endpoint, method and repeat, in [1,100000]")
	f.IntVar(&c.Repeats, "repeats", 3, "repeats per method, in [1,100]")
	f.DurationVar(&c.Timeout, "timeout", 10*time.Second, "connect/request timeout, in (0,5m]")
	f.StringVar(&c.People, "people", "", "optional existing scale UID pool below base; never modified")
	f.IntVar(&c.Entries, "entries", 100000, "contiguous existing scale-%06d pool size, in [1,999999]")
	f.StringVar(&c.UID, "uid", "", "optional fixed existing UID for Base/equality; requires -people")
	stages := f.String("stages", "all", "comma-separated stages (base/equality aliases supported): "+strings.Join(stageNames, ","))
	sizes := f.String("group-sizes", "10,1000", "distinct direct-group member counts, each in [8,10000]")
	if err := f.Parse(args); err != nil {
		return c, err
	}
	if f.NArg() != 0 || !c.SetupDisposable || len(c.Endpoints) == 0 {
		return c, errors.New("require -setup-disposable and at least one -endpoint; positional arguments are unsupported")
	}
	for name, value := range map[string]string{"base": c.Base, "root-bind-dn": c.RootBindDN} {
		if dn, err := ldap.ParseDN(value); err != nil || len(dn.RDNs) == 0 {
			return c, fmt.Errorf("-%s requires a valid nonempty DN", name)
		}
	}
	base, _ := ldap.ParseDN(c.Base)
	config, _ := ldap.ParseDN("cn=config")
	if base.EqualFold(config) || config.AncestorOfFold(base) {
		return c, errors.New("-base must be a data suffix, not cn=config")
	}
	if c.People != "" {
		people, err := ldap.ParseDN(c.People)
		if err != nil || !base.AncestorOfFold(people) {
			return c, errors.New("-people must be a valid DN below -base")
		}
	} else if c.UID != "" {
		return c, errors.New("-uid requires -people")
	}
	if c.N < 1 || c.N > 100000 || c.Repeats < 1 || c.Repeats > 100 || c.Entries < 1 || c.Entries > 999999 {
		return c, errors.New("-n, -repeats or -entries outside documented bounds")
	}
	if c.Timeout <= 0 || c.Timeout > 5*time.Minute {
		return c, errors.New("-timeout must be in (0,5m]")
	}
	if *stages == "all" {
		c.Stages = slices.Clone(stageNames)
	} else {
		for name := range strings.SplitSeq(*stages, ",") {
			if name == "base" {
				name = "nonrootBase"
			} else if name == "equality" {
				name = "nonrootEquality"
			}
			if !slices.Contains(stageNames, name) || slices.Contains(c.Stages, name) {
				return c, fmt.Errorf("unknown or duplicate stage %q", name)
			}
			c.Stages = append(c.Stages, name)
		}
	}
	for value := range strings.SplitSeq(*sizes, ",") {
		n, err := strconv.Atoi(value)
		if err != nil || n < 8 || n > 10000 || slices.Contains(c.GroupSizes, n) {
			return c, errors.New("-group-sizes requires unique integers in [8,10000]")
		}
		c.GroupSizes = append(c.GroupSizes, n)
	}
	if c.People != "" && needsGroups(c) && slices.Max(c.GroupSizes)-8 > c.Entries {
		return c, errors.New("existing pool too small for -group-sizes")
	}
	if c.RootPasswordEnv == "" || strings.ContainsAny(c.RootPasswordEnv, "=\x00") {
		return c, errors.New("-root-password-env requires an environment variable name")
	}
	var ok bool
	if c.password, ok = lookup(c.RootPasswordEnv); !ok || c.password == "" {
		return c, errors.New("root password environment variable must be set and nonempty")
	}
	return c, nil
}

func needsGroups(c options) bool {
	return slices.Contains(c.Stages, "memberEquality") || slices.Contains(c.Stages, "groupBase") || slices.Contains(c.Stages, "nestedMembership")
}

type fixture struct {
	runDN, password        string
	entries, users, groups []*ldap.Entry
	pool                   []*ldap.Entry
	parents                map[string][]*ldap.Entry
	direct                 int
}

func buildFixture(c options, token, password string) fixture {
	f := fixture{runDN: "ou=ldapcommonbench-" + token + "," + c.Base, password: password}
	f.entries = append(f.entries, ldap.NewEntry(f.runDN, map[string][]string{
		"objectClass": {"top", "organizationalUnit"}, "ou": {"ldapcommonbench-" + token}, "description": {token},
	}))
	count := 8
	if needsGroups(c) && c.People == "" {
		count = max(count, slices.Max(c.GroupSizes))
	}
	for i := range count {
		uid := fmt.Sprintf("common-%s-%06d", token, i+1)
		attrs := map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson"}, "uid": {uid}, "cn": {uid}, "sn": {"Common Bench"}}
		if i == 0 {
			attrs["userPassword"] = []string{ssha(password)}
		} else if i == 1 {
			attrs["userPassword"] = []string{password}
		}
		entry := ldap.NewEntry("uid="+uid+","+f.runDN, attrs)
		f.users = append(f.users, entry)
		f.entries = append(f.entries, entry)
	}
	if !needsGroups(c) {
		return f
	}
	members := make([]string, 0, slices.Max(c.GroupSizes))
	for _, user := range f.users {
		members = append(members, user.DN)
	}
	for i := len(members); i < slices.Max(c.GroupSizes); i++ {
		entry := scaleEntry(c, fmt.Sprintf("scale-%06d", i-7))
		f.pool = append(f.pool, entry)
		members = append(members, entry.DN)
	}
	addGroup := func(name string, members []string) {
		entry := ldap.NewEntry("cn="+name+","+f.runDN, map[string][]string{"objectClass": {"top", "groupOfNames"}, "cn": {name}, "member": slices.Clone(members)})
		f.groups = append(f.groups, entry)
		f.entries = append(f.entries, entry)
	}
	for _, size := range c.GroupSizes {
		addGroup(fmt.Sprintf("direct-%d", size), members[:size])
	}
	f.direct = len(f.groups)
	// user -> nested-1 -> nested-2 -> nested-3 -> nested-1 forms a bounded cycle.
	for i := range 3 {
		previous := (i+2)%3 + 1
		addGroup(fmt.Sprintf("nested-%d", i+1), []string{f.users[i].DN, fmt.Sprintf("cn=nested-%d,%s", previous, f.runDN)})
	}
	f.parents = make(map[string][]*ldap.Entry)
	for _, group := range f.groups {
		for _, member := range group.GetAttributeValues("member") {
			key, _ := valuesKey(member, true)
			f.parents[key] = append(f.parents[key], project(group, "cn"))
		}
	}
	return f
}

func ssha(password string) string {
	salt := []byte(rand.Text())
	h := sha1.New() // Intentional LDAP SSHA fixture, not a password-storage recommendation.
	_, _ = h.Write([]byte(password))
	_, _ = h.Write(salt)
	return "{SSHA}" + base64.StdEncoding.EncodeToString(append(h.Sum(nil), salt...))
}

func scaleEntry(c options, uid string) *ldap.Entry {
	return ldap.NewEntry("uid="+ldap.EscapeDN(uid)+","+c.People, map[string][]string{"uid": {uid}})
}

func target(c options, f fixture, iteration int) *ldap.Entry {
	if c.People == "" {
		return project(f.users[iteration%8], "uid", "cn", "sn")
	}
	uid := c.UID
	if uid == "" {
		count := min(c.N, c.Entries)
		uid = fmt.Sprintf("scale-%06d", 1+(iteration%count)*(c.Entries-1)/max(1, count-1))
	}
	return scaleEntry(c, uid)
}

func project(entry *ldap.Entry, attrs ...string) *ldap.Entry {
	values := make(map[string][]string, len(attrs))
	for _, attr := range attrs {
		values[attr] = entry.GetEqualFoldAttributeValues(attr)
	}
	return ldap.NewEntry(entry.DN, values)
}

type client interface {
	Bind(string, string) error
	WhoAmI([]ldap.Control) (*ldap.WhoAmIResult, error)
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Add(*ldap.AddRequest) error
	Del(*ldap.DelRequest) error
	Close() error
}

// Time only SDK calls; request construction and result assertions stay outside.
type timedClient struct {
	client
	elapsed  time.Duration
	requests int
}

func (c *timedClient) Bind(dn, password string) error {
	start := time.Now()
	err := c.client.Bind(dn, password)
	c.elapsed += time.Since(start)
	c.requests++
	return err
}

func (c *timedClient) Search(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	start := time.Now()
	result, err := c.client.Search(request)
	c.elapsed += time.Since(start)
	c.requests++
	return result, err
}

func dial(c options, e endpoint) (client, error) {
	conn, err := ldap.DialURL(e.URI, ldap.DialWithDialer(&net.Dialer{Timeout: c.Timeout}))
	if err == nil {
		conn.SetTimeout(c.Timeout)
	}
	return conn, err
}

func sameDN(a, b string) bool {
	x, ex := ldap.ParseDN(a)
	y, ey := ldap.ParseDN(b)
	return ex == nil && ey == nil && x.EqualFold(y)
}

func identity(conn client, dn string) error {
	got, err := conn.WhoAmI(nil)
	if err != nil {
		return err
	}
	if got != nil && ((dn == "" && got.AuthzID == "") || (dn != "" && strings.HasPrefix(got.AuthzID, "dn:") && sameDN(got.AuthzID[3:], dn))) {
		return nil
	}
	return fmt.Errorf("WhoAmI identity mismatch; expected DN %q", dn)
}

func bind(conn client, dn, password string) error {
	if err := conn.Bind(dn, password); err != nil {
		return err
	}
	return identity(conn, dn)
}

// Normalize the known DN-valued attributes as sets, preserving cardinality.
func valuesKey(value string, dn bool) (string, error) {
	if !dn {
		return value, nil
	}
	parsed, err := ldap.ParseDN(value)
	if err != nil || len(parsed.RDNs) == 0 {
		return "", fmt.Errorf("invalid result DN %q", value)
	}
	for _, rdn := range parsed.RDNs {
		for _, attr := range rdn.Attributes {
			attr.Type, attr.Value = strings.ToLower(attr.Type), strings.ToLower(attr.Value)
		}
	}
	return parsed.String(), nil
}

func assertValues(got, want []string, dn bool) error {
	if len(got) != len(want) {
		return fmt.Errorf("value count %d, want %d", len(got), len(want))
	}
	remaining := make(map[string]bool, len(want))
	for _, value := range want {
		key, err := valuesKey(value, dn)
		if err != nil || remaining[key] {
			return errors.New("invalid or duplicate expected value")
		}
		remaining[key] = true
	}
	for _, value := range got {
		key, err := valuesKey(value, dn)
		if err != nil || !remaining[key] {
			return errors.New("unexpected or duplicate result value")
		}
		delete(remaining, key)
	}
	return nil
}

func assertEntries(result *ldap.SearchResult, want []*ldap.Entry) error {
	if result == nil || len(result.Referrals) != 0 || len(result.Entries) != len(want) {
		return fmt.Errorf("missing result, referrals or entry count mismatch; want %d", len(want))
	}
	seen := make(map[int]bool, len(want))
	for _, got := range result.Entries {
		index := slices.IndexFunc(want, func(e *ldap.Entry) bool { return got != nil && sameDN(got.DN, e.DN) })
		if index < 0 || seen[index] || len(got.Attributes) != len(want[index].Attributes) {
			return errors.New("unexpected/duplicate entry or attribute count")
		}
		seen[index] = true
		for _, attr := range want[index].Attributes {
			if err := assertValues(got.GetEqualFoldAttributeValues(attr.Name), attr.Values, strings.EqualFold(attr.Name, "member")); err != nil {
				return fmt.Errorf("%s at %q: %w", attr.Name, got.DN, err)
			}
		}
	}
	return nil
}

func search(conn client, base string, scope int, filter string, want []*ldap.Entry, attrs ...string) error {
	result, err := conn.Search(ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, len(want)+1, 0, false, filter, attrs, nil))
	if err != nil {
		return err
	}
	return assertEntries(result, want)
}

func expectBase(conn client, entry *ldap.Entry, attrs ...string) error {
	return search(conn, entry.DN, ldap.ScopeBaseObject, "(objectClass=*)", []*ldap.Entry{project(entry, attrs...)}, attrs...)
}

func cleanup(conn client, f fixture, dns []string) error {
	if err := expectBase(conn, f.entries[0], "description"); err != nil {
		return fmt.Errorf("cleanup ownership %q: %w", f.runDN, err)
	}
	var failures []error
	for _, dn := range slices.Backward(dns) {
		if err := conn.Del(ldap.NewDelRequest(dn, nil)); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			failures = append(failures, fmt.Errorf("delete %q: %w", dn, err))
		}
	}
	_, err := conn.Search(ldap.NewSearchRequest(f.runDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{"1.1"}, nil))
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		failures = append(failures, fmt.Errorf("cleanup absence %q: expected noSuchObject, got %v", f.runDN, err))
	}
	return errors.Join(failures...)
}

func probe(ctx context.Context, c options, r *report) (err error) {
	f := buildFixture(c, strings.ToLower(rand.Text()), rand.Text())
	r.RunDN = f.runDN
	var conns []client
	owned := make([][]string, len(c.Endpoints))
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
		for i, dns := range owned {
			if len(dns) == 0 {
				continue
			}
			conn, cleanErr := dial(c, c.Endpoints[i])
			if cleanErr == nil {
				cleanErr = bind(conn, c.RootBindDN, c.password)
				if cleanErr == nil {
					cleanErr = cleanup(conn, f, dns)
				}
				_ = conn.Close()
			}
			if cleanErr != nil {
				err = errors.Join(err, fmt.Errorf("%s cleanup: %w", c.Endpoints[i].Name, cleanErr))
			} else {
				r.CleanupDone = append(r.CleanupDone, c.Endpoints[i].Name)
			}
		}
	}()
	for i, e := range c.Endpoints {
		if err := ctx.Err(); err != nil {
			return err
		}
		conn, err := dial(c, e)
		if err != nil {
			return fmt.Errorf("%s connect: %w", e.Name, err)
		}
		conns = append(conns, conn)
		if err := bind(conn, c.RootBindDN, c.password); err != nil {
			return fmt.Errorf("%s root Bind: %w", e.Name, err)
		}
		for j, entry := range f.entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			// Once the OU is owned, track attempts too: a lost Add reply may still commit.
			if j != 0 {
				owned[i] = append(owned[i], entry.DN)
			}
			add := ldap.NewAddRequest(entry.DN, nil)
			for _, attr := range entry.Attributes {
				add.Attribute(attr.Name, attr.Values)
			}
			if err := conn.Add(add); err != nil {
				return fmt.Errorf("%s setup %q (lost initial OU reply requires orphan inspection): %w", e.Name, entry.DN, err)
			}
			r.SetupAdds++
			if j == 0 {
				owned[i] = append(owned[i], entry.DN)
			}
		}
		if err := bind(conn, f.users[0].DN, f.password); err != nil {
			return fmt.Errorf("%s service Bind: %w", e.Name, err)
		}
		// Explicit pool references must resolve, using only exact Base reads.
		for _, entry := range f.pool {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := expectBase(conn, entry, "uid"); err != nil {
				return fmt.Errorf("%s seed pool: %w", e.Name, err)
			}
		}
	}
	for _, b := range benchmarks(c, f) {
		for repeat := range c.Repeats {
			if err := measure(ctx, c, f, b, repeat, conns, r); err != nil {
				return fmt.Errorf("%s/%s repeat %d: %w", b.name, b.method, repeat+1, err)
			}
		}
	}
	return nil
}

type benchmark struct {
	name, method string
	user         *ldap.Entry
	group        *ldap.Entry
}

func benchmarks(c options, f fixture) []benchmark {
	var result []benchmark
	for _, name := range c.Stages {
		switch name {
		case "userBind", "userBindWrong":
			result = append(result, benchmark{name, "simple_bind_ssha", f.users[0], nil}, benchmark{name, "simple_bind_plaintext", f.users[1], nil})
		case "groupBase":
			for _, group := range f.groups[:f.direct] {
				result = append(result, benchmark{name, "base_member_values", f.users[0], group})
			}
		default:
			method := "search_" + name
			if name == "nestedMembership" {
				method = "client_bfs_member_equality"
			}
			result = append(result, benchmark{name, method, f.users[0], nil})
		}
	}
	return result
}

type traversal struct {
	queue []string
	seen  []string
}

// One portable member-equality query per step; discoveries are checked before enqueue.
func (t *traversal) step(conn client, f fixture) error {
	member := t.queue[0]
	key, _ := valuesKey(member, true)
	want := f.parents[key]
	result, err := conn.Search(ldap.NewSearchRequest(f.runDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, len(f.groups)+1, 0, false, "(member="+ldap.EscapeFilter(member)+")", []string{"cn"}, nil))
	if err != nil {
		return err
	}
	if err := assertEntries(result, want); err != nil {
		return err
	}
	t.queue = t.queue[1:]
	var discovered []string
	for _, entry := range result.Entries {
		key, _ := valuesKey(entry.DN, true)
		discovered = append(discovered, key)
	}
	slices.Sort(discovered)
	for _, dn := range discovered {
		if !slices.Contains(t.seen, dn) {
			t.seen = append(t.seen, dn)
			t.queue = append(t.queue, dn)
		}
	}
	return nil
}

func request(conn client, c options, f fixture, b benchmark, iteration int, walk *traversal) error {
	switch b.name {
	case "userBind":
		return conn.Bind(b.user.DN, f.password)
	case "userBindWrong":
		err := conn.Bind(b.user.DN, f.password+"-wrong")
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return fmt.Errorf("wrong Bind: expected invalidCredentials, got %v", err)
		}
		return nil
	case "nonrootBase", "nonrootEquality":
		entry := target(c, f, iteration)
		attrs := []string{"uid"}
		if c.People == "" {
			attrs = append(attrs, "cn", "sn")
		}
		if b.name == "nonrootBase" {
			return expectBase(conn, entry, attrs...)
		}
		base := c.Base
		if c.People != "" {
			base = c.People
		}
		return search(conn, base, ldap.ScopeWholeSubtree, "(uid="+ldap.EscapeFilter(entry.GetAttributeValue("uid"))+")", []*ldap.Entry{entry}, attrs...)
	case "groupBase":
		return expectBase(conn, b.group, "member")
	case "memberEquality", "nestedMembership":
		if err := walk.step(conn, f); err != nil {
			return err
		}
		if b.name == "nestedMembership" && len(walk.queue) == 0 {
			groups := f.groups[:f.direct]
			if iteration%8 < 3 {
				groups = f.groups
			}
			var want []string
			for _, group := range groups {
				want = append(want, group.DN)
			}
			return assertValues(walk.seen, want, true)
		}
		return nil
	}
	return fmt.Errorf("unknown stage %q", b.name)
}

func (s *sample) verify(fn func() error) error {
	start := time.Now()
	err := fn()
	s.VerificationRequests++
	s.VerificationMS += float64(time.Since(start)) / float64(time.Millisecond)
	return err
}

func (s *sample) bind(conn client, dn, password string) error {
	if err := s.verify(func() error { return conn.Bind(dn, password) }); err != nil {
		return err
	}
	return s.verify(func() error { return identity(conn, dn) })
}

func measure(ctx context.Context, c options, f fixture, b benchmark, repeat int, conns []client, r *report) error {
	rows := make([]*sample, len(conns))
	for i, conn := range conns {
		if err := ctx.Err(); err != nil {
			return err
		}
		s := &sample{Endpoint: c.Endpoints[i].Name, Stage: b.name, Method: b.method, Repeat: repeat + 1, LatencyMS: []float64{}}
		if b.group != nil {
			s.Members = len(b.group.GetAttributeValues("member"))
		}
		rows[i] = s
		r.Samples = append(r.Samples, s)
		if err := s.bind(conn, b.user.DN, f.password); err != nil {
			return fmt.Errorf("%s preparation: %w", s.Endpoint, err)
		}
	}
	for iteration := range c.N {
		walks := make([]traversal, len(conns))
		elapsed := make([]float64, len(conns))
		for i := range walks {
			walks[i].queue = []string{f.users[iteration%8].DN}
		}
		for step := 0; ; step++ {
			pending := false
			for offset := range len(conns) {
				i := (iteration + repeat + step + offset) % len(conns)
				walk, s, conn := &walks[i], rows[i], conns[i]
				if len(walk.queue) == 0 {
					continue
				}
				pending = true
				if err := ctx.Err(); err != nil {
					return err
				}
				if step == 0 {
					s.Operations++
				}
				if b.name == "userBindWrong" {
					if err := s.bind(conn, b.user.DN, f.password); err != nil {
						return fmt.Errorf("%s rebind: %w", s.Endpoint, err)
					}
				}
				timed := &timedClient{client: conn}
				err := request(timed, c, f, b, iteration, walk)
				ms := float64(timed.elapsed) / float64(time.Millisecond)
				s.Requests += timed.requests
				s.TotalMS += ms
				elapsed[i] += ms
				if err != nil {
					return fmt.Errorf("%s operation %d request %d: %w", s.Endpoint, iteration+1, step+1, err)
				}
				dn := b.user.DN
				if b.name == "userBindWrong" {
					dn = ""
				}
				if err := s.verify(func() error { return identity(conn, dn) }); err != nil {
					return fmt.Errorf("%s: %w", s.Endpoint, err)
				}
				if b.name != "nestedMembership" {
					walk.queue = nil
				}
				if len(walk.queue) == 0 {
					s.Completed++
					s.LatencyMS = append(s.LatencyMS, elapsed[i])
				}
			}
			if !pending {
				break
			}
		}
	}
	return nil
}
