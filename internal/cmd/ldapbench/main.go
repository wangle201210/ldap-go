// ldapbench probes an explicitly supplied disposable LDAP fixture with go-ldap.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

type options struct {
	URI             string        `json:"uri"`
	BindDN          string        `json:"bind_dn"`
	Base            string        `json:"base"`
	People          string        `json:"people"`
	PasswordEnv     string        `json:"password_env"`
	UserPasswordEnv string        `json:"user_password_env,omitempty"`
	Label           string        `json:"label,omitempty"`
	ReadOnly        bool          `json:"read_only"`
	Write           bool          `json:"write"`
	N               int           `json:"n"`
	WriteBatch      int           `json:"write_batch"`
	Entries         int           `json:"entries"`
	Timeout         time.Duration `json:"-"`
	password        string
	userPassword    string
}

type stage struct {
	Name                   string   `json:"name"`
	Operations             int      `json:"operations"`
	TotalMS                float64  `json:"total_ms"`
	VerificationOperations int      `json:"verification_operations"`
	VerificationMS         float64  `json:"verification_ms"`
	Errors                 []string `json:"errors"`
}

type report struct {
	Config    *options  `json:"config,omitempty"`
	StartedAt time.Time `json:"started_at"`
	TimeoutMS float64   `json:"timeout_ms,omitempty"`
	RunDN     string    `json:"run_dn,omitempty"`
	Stages    []*stage  `json:"stages"`
	Error     string    `json:"error"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := execute(ctx, os.Args[1:], os.LookupEnv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func execute(ctx context.Context, args []string, lookup func(string) (string, bool), out, stderr io.Writer) int {
	r := &report{StartedAt: time.Now().UTC(), Stages: []*stage{}}
	c, err := parseOptions(args, lookup, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	code := 0
	if err != nil {
		code = 2
	} else {
		r.Config = &c
		r.TimeoutMS = float64(c.Timeout) / float64(time.Millisecond)
		err = probe(ctx, c, r)
		if err != nil {
			code = 1
		}
	}
	if err != nil {
		r.Error = err.Error()
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(r); err != nil {
		fmt.Fprintf(stderr, "write JSON: %v\n", err)
		return 1
	}
	return code
}

func parseOptions(args []string, lookup func(string) (string, bool), stderr io.Writer) (options, error) {
	var c options
	f := flag.NewFlagSet("ldapbench", flag.ContinueOnError)
	f.SetOutput(stderr)
	f.StringVar(&c.URI, "uri", "", "required explicit ldap:// or ldaps:// disposable fixture URI")
	f.StringVar(&c.BindDN, "bind-dn", "", "required privileged Bind DN")
	f.StringVar(&c.PasswordEnv, "password-env", "", "required environment variable containing the Bind password")
	f.StringVar(&c.UserPasswordEnv, "user-password-env", "", "environment variable containing the temporary SSHA user's password (required with -write)")
	f.StringVar(&c.Base, "base", "", "required fixture base DN; the temporary OU is created directly below it")
	f.StringVar(&c.People, "people", "", "required people DN containing uid=scale-%06d entries")
	f.StringVar(&c.Label, "label", "", "report label, e.g. before/current/native")
	f.BoolVar(&c.ReadOnly, "read-only", false, "only Bind, Compare and Search on the supplied existing fixture")
	f.BoolVar(&c.Write, "write", false, "authorize temporary writes on this disposable fixture")
	f.IntVar(&c.N, "n", 100, "operations per read/Bind/Compare stage, clamped to [1,10000]")
	f.IntVar(&c.WriteBatch, "write-batch", 100, "entries per independent write stage, clamped to [1,1000]")
	f.IntVar(&c.Entries, "entries", 100000, "existing contiguous scale fixture size, in [1,999999]")
	f.DurationVar(&c.Timeout, "timeout", 10*time.Second, "per-request and connect timeout, in (0,5m]")
	f.Usage = func() {
		fmt.Fprintln(stderr, "Usage: ldapbench -uri URI -bind-dn DN -password-env ENV -base DN -people DN (-read-only | -write -user-password-env ENV)")
		fmt.Fprintln(stderr, "Only use a disposable fixture you explicitly supply. No fixture discovery or import is performed.")
		f.PrintDefaults()
	}
	if err := f.Parse(args); err != nil {
		return c, err
	}
	if f.NArg() != 0 {
		return c, errors.New("positional arguments are not supported")
	}
	if c.Write == c.ReadOnly {
		return c, errors.New("choose exactly one of -read-only or -write")
	}
	u, err := url.Parse(c.URI)
	if err != nil || u == nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Hostname() == "" ||
		u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return c, errors.New("-uri must be an explicit ldap:// or ldaps:// host URI without credentials, base, query or fragment")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return c, errors.New("-uri port must be in [1,65535]")
		}
	}
	dns := make([]*ldap.DN, 0, 3)
	for _, item := range []struct{ name, value string }{{"bind-dn", c.BindDN}, {"base", c.Base}, {"people", c.People}} {
		dn, err := ldap.ParseDN(item.value)
		if err != nil || len(dn.RDNs) == 0 {
			return c, fmt.Errorf("-%s requires a valid nonempty DN", item.name)
		}
		dns = append(dns, dn)
	}
	if !dns[1].AncestorOfFold(dns[2]) {
		return c, errors.New("-people must be below -base")
	}
	if c.Entries < 1 || c.Entries > 999999 {
		return c, errors.New("-entries must be in [1,999999]")
	}
	if c.Timeout <= 0 || c.Timeout > 5*time.Minute {
		return c, errors.New("-timeout must be in (0,5m]")
	}
	c.N = min(10000, max(1, c.N))
	c.WriteBatch = min(1000, max(1, c.WriteBatch))
	if c.password, err = passwordFromEnv(c.PasswordEnv, lookup); err != nil {
		return c, fmt.Errorf("-password-env: %w", err)
	}
	if c.Write {
		if c.userPassword, err = passwordFromEnv(c.UserPasswordEnv, lookup); err != nil {
			return c, fmt.Errorf("-user-password-env: %w", err)
		}
	}
	return c, nil
}

func passwordFromEnv(name string, lookup func(string) (string, bool)) (string, error) {
	if name == "" || strings.ContainsAny(name, "=\x00") {
		return "", errors.New("specify an environment variable name")
	}
	value, ok := lookup(name)
	if !ok || value == "" {
		return "", fmt.Errorf("environment variable %q must be set and nonempty", name)
	}
	return value, nil
}

func (r *report) newStage(name string) *stage {
	s := &stage{Name: name, Errors: []string{}}
	r.Stages = append(r.Stages, s)
	return s
}

// Verification requests are counted and timed separately from measured SDK calls.
func (s *stage) call(verification bool, op func() error) error {
	start := time.Now()
	err := op()
	ms := float64(time.Since(start)) / float64(time.Millisecond)
	if verification {
		s.VerificationOperations++
		s.VerificationMS += ms
	} else {
		s.Operations++
		s.TotalMS += ms
	}
	if err != nil {
		s.Errors = append(s.Errors, fmt.Sprintf("operation %d, verification %d: %v", s.Operations, s.VerificationOperations, err))
	}
	return err
}

func (r *report) batch(ctx context.Context, name string, n int, op func(*stage, int) error) error {
	s := r.newStage(name)
	for i := 0; i < n; i++ {
		if err := ctx.Err(); err != nil {
			s.Errors = append(s.Errors, err.Error())
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := op(s, i); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func dial(c options) (*ldap.Conn, error) {
	conn, err := ldap.DialURL(c.URI, ldap.DialWithDialer(&net.Dialer{Timeout: c.Timeout}))
	if err == nil {
		conn.SetTimeout(c.Timeout)
	}
	return conn, err
}

func probe(ctx context.Context, c options, r *report) error {
	var conn *ldap.Conn
	if err := r.batch(ctx, "connect", 1, func(s *stage, _ int) error {
		return s.call(false, func() (err error) { conn, err = dial(c); return err })
	}); err != nil {
		return err
	}
	defer conn.Close()
	reads := []struct {
		name string
		op   func(int) error
	}{
		{"rootBind", func(int) error { return conn.Bind(c.BindDN, c.password) }},
		{"baseSearch", func(int) error { return expectEntry(conn, c.Base, "objectClass", "") }},
		{"indexedEquality", func(i int) error {
			uid := sampleUID(c, i)
			return expectUIDs(conn, c.People, "(uid="+uid+")", []string{uid})
		}},
		{"compareTrue", func(i int) error {
			uid := sampleUID(c, i)
			return expectCompare(conn, "uid="+uid+","+c.People, uid, true)
		}},
		{"compareFalse", func(i int) error {
			uid := sampleUID(c, i)
			return expectCompare(conn, "uid="+uid+","+c.People, "ldapbench-absent", false)
		}},
		{"substringPrefix", func(i int) error {
			prefix := sampleUID(c, i)[:len("scale-00000")]
			first, _ := strconv.Atoi(strings.TrimPrefix(prefix, "scale-"))
			var want []string
			for j := max(1, first*10); j <= min(c.Entries, first*10+9); j++ {
				want = append(want, fmt.Sprintf("scale-%06d", j))
			}
			return expectUIDs(conn, c.People, "(uid="+prefix+"*)", want)
		}},
		{"substringNegative", func(int) error {
			return expectUIDs(conn, c.People, "(uid=ldapbench-absent-*)", nil)
		}},
	}
	for _, read := range reads {
		if err := r.batch(ctx, read.name, c.N, func(s *stage, i int) error {
			return s.call(false, func() error { return read.op(i) })
		}); err != nil {
			return err
		}
	}
	if c.ReadOnly {
		return nil
	}
	return probeWrites(ctx, c, r, conn)
}

// Samples include both ends of the declared fixture and are identical on every run.
func sampleUID(c options, i int) string {
	count := min(c.N, c.Entries)
	n := 1 + (i%count)*(c.Entries-1)/max(1, count-1)
	return fmt.Sprintf("scale-%06d", n)
}

func search(conn *ldap.Conn, base string, scope int, filter string, limit int, attrs ...string) (*ldap.SearchResult, error) {
	result, err := conn.Search(ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, limit, 0, false, filter, attrs, nil))
	if err == nil && (result == nil || len(result.Referrals) != 0) {
		err = errors.New("missing search result or unexpected referrals")
	}
	return result, err
}

func sameDN(got, want string) bool {
	a, errA := ldap.ParseDN(got)
	b, errB := ldap.ParseDN(want)
	return errA == nil && errB == nil && a.EqualFold(b)
}

func expectEntry(conn *ldap.Conn, dn, attr, value string) error {
	result, err := search(conn, dn, ldap.ScopeBaseObject, "(objectClass=*)", 2, attr)
	if err != nil {
		return err
	}
	if len(result.Entries) != 1 || !sameDN(result.Entries[0].DN, dn) {
		return fmt.Errorf("base search did not return exactly %q", dn)
	}
	values := result.Entries[0].GetEqualFoldAttributeValues(attr)
	if len(values) == 0 || (value != "" && (len(values) != 1 || values[0] != value)) {
		return fmt.Errorf("unexpected %s values at %q", attr, dn)
	}
	return nil
}

func expectAbsent(conn *ldap.Conn, dn string) error {
	_, err := search(conn, dn, ldap.ScopeBaseObject, "(objectClass=*)", 2, "1.1")
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("expected noSuchObject at %q", dn)
}

func expectUIDs(conn *ldap.Conn, people, filter string, want []string) error {
	result, err := search(conn, people, ldap.ScopeWholeSubtree, filter, len(want)+1, "uid")
	if err != nil {
		return err
	}
	if len(result.Entries) != len(want) {
		return fmt.Errorf("%s returned %d entries, want %d", filter, len(result.Entries), len(want))
	}
	remaining := make(map[string]bool, len(want))
	for _, uid := range want {
		remaining[uid] = true
	}
	for _, entry := range result.Entries {
		values := entry.GetEqualFoldAttributeValues("uid")
		if len(values) != 1 || !remaining[values[0]] || !sameDN(entry.DN, "uid="+values[0]+","+people) {
			return fmt.Errorf("%s returned an unexpected or duplicate entry %q", filter, entry.DN)
		}
		delete(remaining, values[0])
	}
	return nil
}

func expectCompare(conn *ldap.Conn, dn, value string, want bool) error {
	got, err := conn.Compare(dn, "uid", value)
	if err == nil && got != want {
		err = fmt.Errorf("Compare at %q returned %t, want %t", dn, got, want)
	}
	return err
}

func person(dn, uid string) *ldap.AddRequest {
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	request.Attribute("uid", []string{uid})
	request.Attribute("cn", []string{uid})
	request.Attribute("sn", []string{"ldapbench"})
	request.Attribute("description", []string{"ldapbench-initial"})
	return request
}

func ssha(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	// SSHA is intentional: this probe measures the existing fixture's LDAP mechanism.
	hash := sha1.New()
	_, _ = hash.Write([]byte(password))
	_, _ = hash.Write(salt)
	return "{SSHA}" + base64.StdEncoding.EncodeToString(append(hash.Sum(nil), salt...)), nil
}

func probeWrites(ctx context.Context, c options, r *report, conn *ldap.Conn) (err error) {
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	ou := "ldapbench-" + hex.EncodeToString(token)
	r.RunDN = "ou=" + ou + "," + c.Base
	hash, err := ssha(c.userPassword)
	if err != nil {
		return err
	}
	setup := r.newStage("setup")
	request := ldap.NewAddRequest(r.RunDN, nil)
	request.Attribute("objectClass", []string{"top", "organizationalUnit"})
	request.Attribute("ou", []string{ou})
	request.Attribute("description", []string{ou})
	if err := ctx.Err(); err != nil {
		setup.Errors = append(setup.Errors, err.Error())
		return err
	}
	if err := setup.call(false, func() error { return conn.Add(request) }); err != nil {
		return fmt.Errorf("setup OU %q (check for an orphan if the response was lost): %w", r.RunDN, err)
	}
	// Only known DNs under our successfully created OU can enter the cleanup list.
	// Record attempts before sending: a timed-out write may still reach the server.
	var cleanupDNs []string
	defer func() { err = errors.Join(err, cleanup(c, r, ou, cleanupDNs)) }()
	add := func(s *stage, dn, uid, passwordHash string) error {
		cleanupDNs = append(cleanupDNs, dn)
		request := person(dn, uid)
		if passwordHash != "" {
			request.Attribute("userPassword", []string{passwordHash})
		}
		if err := s.call(false, func() error { return conn.Add(request) }); err != nil {
			return err
		}
		return s.call(true, func() error { return expectEntry(conn, dn, "uid", uid) })
	}
	userDN := "uid=bind-user," + r.RunDN
	if err := add(setup, userDN, "bind-user", hash); err != nil {
		return fmt.Errorf("setup user: %w", err)
	}
	for _, kind := range []string{"modify", "rename", "delete"} {
		for i := 0; i < c.WriteBatch; i++ {
			if err := ctx.Err(); err != nil {
				setup.Errors = append(setup.Errors, err.Error())
				return err
			}
			uid := fmt.Sprintf("%s-%06d", kind, i)
			if err := add(setup, "uid="+uid+","+r.RunDN, uid, ""); err != nil {
				return fmt.Errorf("setup %s: %w", kind, err)
			}
		}
	}
	var user *ldap.Conn
	if err := r.batch(ctx, "userConnect", 1, func(s *stage, _ int) error {
		return s.call(false, func() (err error) { user, err = dial(c); return err })
	}); err != nil {
		return err
	}
	defer user.Close()
	if err := r.batch(ctx, "userBind", c.N, func(s *stage, _ int) error {
		return s.call(false, func() error { return user.Bind(userDN, c.userPassword) })
	}); err != nil {
		return err
	}
	for _, kind := range []string{"add", "modify", "modifyDN", "delete"} {
		if err := r.batch(ctx, kind, c.WriteBatch, func(s *stage, i int) error {
			prefix := kind
			if kind == "modifyDN" {
				prefix = "rename"
			}
			uid := fmt.Sprintf("%s-%06d", prefix, i)
			dn := "uid=" + uid + "," + r.RunDN
			switch kind {
			case "add":
				return add(s, dn, uid, "")
			case "modify":
				request := ldap.NewModifyRequest(dn, nil)
				request.Replace("description", []string{"ldapbench-modified"})
				if err := s.call(false, func() error { return conn.Modify(request) }); err != nil {
					return err
				}
				return s.call(true, func() error { return expectEntry(conn, dn, "description", "ldapbench-modified") })
			case "modifyDN":
				newUID := "renamed-" + fmt.Sprintf("%06d", i)
				newDN := "uid=" + newUID + "," + r.RunDN
				cleanupDNs = append(cleanupDNs, newDN)
				request := ldap.NewModifyDNRequest(dn, "uid="+newUID, true, "")
				if err := s.call(false, func() error { return conn.ModifyDN(request) }); err != nil {
					return err
				}
				if err := s.call(true, func() error { return expectEntry(conn, newDN, "uid", newUID) }); err != nil {
					return err
				}
				return s.call(true, func() error { return expectAbsent(conn, dn) })
			default:
				if err := s.call(false, func() error { return conn.Del(ldap.NewDelRequest(dn, nil)) }); err != nil {
					return err
				}
				return s.call(true, func() error { return expectAbsent(conn, dn) })
			}
		}); err != nil {
			return err
		}
	}
	return nil
}

func cleanup(c options, r *report, marker string, dns []string) error {
	s := r.newStage("cleanup")
	// Use a fresh privileged connection even after a request failure or signal.
	var conn *ldap.Conn
	if err := s.call(false, func() (err error) { conn, err = dial(c); return err }); err != nil {
		return fmt.Errorf("cleanup connect for %q: %w", r.RunDN, err)
	}
	defer conn.Close()
	if err := s.call(false, func() error { return conn.Bind(c.BindDN, c.password) }); err != nil {
		return fmt.Errorf("cleanup Bind for %q: %w", r.RunDN, err)
	}
	if err := s.call(true, func() error { return expectEntry(conn, r.RunDN, "description", marker) }); err != nil {
		return fmt.Errorf("cleanup ownership check for %q: %w", r.RunDN, err)
	}
	var failures []error
	for i := len(dns) - 1; i >= 0; i-- {
		if err := s.call(false, func() error {
			err := conn.Del(ldap.NewDelRequest(dns[i], nil))
			if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				return nil
			}
			return err
		}); err != nil {
			failures = append(failures, fmt.Errorf("delete %q: %w", dns[i], err))
			if conn.IsClosing() {
				break
			}
		}
	}
	if err := s.call(false, func() error { return conn.Del(ldap.NewDelRequest(r.RunDN, nil)) }); err != nil {
		failures = append(failures, err)
	} else if err := s.call(true, func() error { return expectAbsent(conn, r.RunDN) }); err != nil {
		failures = append(failures, err)
	}
	if err := errors.Join(failures...); err != nil {
		return fmt.Errorf("cleanup %q: %w", r.RunDN, err)
	}
	return nil
}
