package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPClientHostPortConfiguration(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		uri  string
	}{
		{"default", nil, defaultLDAPClientURI},
		{"hostname", []string{"-h", "directory.example"}, "ldap://directory.example:389"},
		{"IPv4", []string{"-h", "127.0.0.1", "-p", "1389"}, "ldap://127.0.0.1:1389"},
		{"IPv6", []string{"-h", "::1", "-p", "1389"}, "ldap://[::1]:1389"},
		{"bracketed IPv6", []string{"-h", "[::1]", "-p", "1389"}, "ldap://[::1]:1389"},
		{"mapped IPv6", []string{"-h", "[::ffff:127.0.0.1]"}, "ldap://[::ffff:127.0.0.1]:389"},
		{"inline port", []string{"-h", "localhost:1389"}, "ldap://localhost:1389"},
		{"inline IPv6 port", []string{"-h", "[::1]:1389"}, "ldap://[::1]:1389"},
		{"bare IPv6 last segment", []string{"-h", "::1:1389"}, "ldap://[::1:1389]:389"},
		{"zero port", []string{"-h", "localhost", "-p", "0"}, defaultLDAPClientURI},
		{"signed decimal", []string{"-p", "+00389", "-h", "localhost"}, defaultLDAPClientURI},
		{"leading whitespace", []string{"-h", "localhost", "-p", " \t\r\n\v\f389"}, defaultLDAPClientURI},
		{"minimum port", []string{"-h", "localhost", "-p", "1"}, "ldap://localhost:1"},
		{"maximum port", []string{"-h", "localhost", "-p", "65535"}, "ldap://localhost:65535"},
		{"636 is cleartext", []string{"-h", "localhost", "-p", "636"}, "ldap://localhost:636"},
		{"StartTLS", []string{"-h", "localhost", "-p", "636", "-ZZ"}, "ldap://localhost:636"},
		{"attached", []string{"-hlocalhost", "-p1389"}, "ldap://localhost:1389"},
		{"assigned", []string{"-h=localhost", "-p=1389"}, "ldap://localhost:1389"},
		{"double dash", []string{"--h", "localhost", "--p", "1389"}, "ldap://localhost:1389"},
		{"LDAPS unchanged", []string{"-H", "ldaps://localhost"}, "ldaps://localhost"},
	} {
		t.Run(test.name, func(t *testing.T) {
			flags := flag.NewFlagSet("ldapwhoami", flag.ContinueOnError)
			flags.SetOutput(io.Discard)
			var options ldapClientOptions
			options.register(flags)
			defer options.clear()
			if err := options.parse(flags, append([]string{"-x"}, test.args...)); err != nil {
				t.Fatal(err)
			}
			if err := options.validate(flags); err != nil {
				t.Fatal(err)
			}
			endpoints, err := options.connectionConfigurations(flags)
			if err != nil || len(endpoints) != 1 {
				t.Fatalf("endpoints=%v err=%v", endpoints, err)
			}
			if options.uri != test.uri || endpoints[0].dialURI != test.uri {
				t.Fatalf("uri=%q dial=%q want=%q", options.uri, endpoints[0].dialURI, test.uri)
			}
			if endpoints[0].tlsConfig.ServerName != endpoints[0].parsedURI.Hostname() {
				t.Error("TLS hostname did not follow the selected host")
			}
		})
	}
}

type ldapHostPortCommandCase struct {
	command string
	args    []string
	input   string
	output  string
	code    int
}

func ldapHostPortCommandCases() []ldapHostPortCommandCase {
	alice := "uid=alice," + clientToolPeopleDN
	bob := "uid=bob," + clientToolPeopleDN
	return []ldapHostPortCommandCase{
		{command: "ldapsearch", args: []string{"-b", "", "-s", "base", "-LLL", "(objectClass=*)", "namingContexts"}, output: "namingContexts: " + clientToolBaseDN},
		{command: "ldapwhoami", output: "dn:" + clientToolRootDN},
		{command: "ldapcompare", args: []string{alice, "uid:alice"}, output: "TRUE", code: ldap.LDAPResultCompareTrue},
		{command: "ldappasswd", args: []string{"-s", "host-port-new-password", bob}},
		{command: "ldapexop", args: []string{"whoami"}, output: "dn:" + clientToolRootDN},
		{command: "ldapadd", input: "dn: ou=host-port," + clientToolBaseDN + "\nobjectClass: organizationalUnit\nou: host-port\n\n"},
		{command: "ldapmodify", input: "dn: " + alice + "\nchangetype: modify\nreplace: description\ndescription: host-port\n-\n\n"},
		{command: "ldapdelete", args: []string{bob}},
		{command: "ldapmodrdn", args: []string{"-r", bob, "uid=renamed"}},
	}
}

func ldapHostPortArgs(t *testing.T, uri string) []string {
	t.Helper()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(uri, "ldap://"))
	if err != nil {
		t.Fatal(err)
	}
	return []string{"-h", host, "-p", port}
}

func TestLDAPClientHostPortCommands(t *testing.T) {
	for _, test := range ldapHostPortCommandCases() {
		t.Run(test.command, func(t *testing.T) {
			uri := startLDAPClientToolServer(t, nil)
			args := append([]string{test.command}, ldapHostPortArgs(t, uri)...)
			args = append(args, "-x", "-D", clientToolRootDN, "-w", clientToolRootPassword)
			args = append(args, test.args...)
			stdout, stderr, code := runLDAPClientCommand(args, test.input)
			if code != test.code || stderr != "" || !strings.Contains(stdout, test.output) ||
				strings.Contains(stdout+stderr, "host-port-new-password") || strings.Contains(stdout+stderr, clientToolRootPassword) {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			switch test.command {
			case "ldappasswd":
				assertLDAPClientToolBind(t, uri, "uid=bob,"+clientToolPeopleDN, "host-port-new-password")
			case "ldapadd":
				requireLDAPWriteEntry(t, uri, "ou=host-port,"+clientToolBaseDN)
			case "ldapmodify":
				entry := requireLDAPWriteEntry(t, uri, "uid=alice,"+clientToolPeopleDN)
				if entry.GetAttributeValue("description") != "host-port" {
					t.Fatal("modify did not apply")
				}
			case "ldapdelete", "ldapmodrdn":
				assertLDAPWriteEntryAbsent(t, uri, "uid=bob,"+clientToolPeopleDN)
				if test.command == "ldapmodrdn" {
					requireLDAPWriteEntry(t, uri, "uid=renamed,"+clientToolPeopleDN)
				}
			}
		})
	}
	t.Run("health", func(t *testing.T) {
		uri := startLDAPHealthTestServer(t)
		args := append([]string{"health"}, ldapHostPortArgs(t, uri)...)
		args = append(args, "-x", "-D", clientToolRootDN, "-w", clientToolRootPassword, "-json")
		stdout, stderr, code := runLDAPClientCommand(args, "")
		if code != 0 || stderr != "" || !strings.Contains(stdout, uri) {
			t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})
	t.Run("online-backup requires LDAPI", func(t *testing.T) {
		_, stderr, code := runLDAPClientCommand([]string{"online-backup", "-x", "-h", "localhost"}, "")
		if code == 0 || !strings.Contains(stderr, "requires an ldapi:// URI list") {
			t.Fatalf("exit=%d stderr=%q", code, stderr)
		}
	})
}

func TestLDAPClientHostPortRejectsInvalidAddress(t *testing.T) {
	for _, test := range []struct {
		args    []string
		message string
	}{
		{[]string{"-h", ""}, "single non-empty host"},
		{[]string{"-h", "first second"}, "use -H"},
		{[]string{"-h", "first,second"}, "use -H"},
		{[]string{"-h", "host\tname"}, "use -H"},
		{[]string{"-h", "host\u00a0name"}, "use -H"},
		{[]string{"-h", "host\x00name"}, "use -H"},
		{[]string{"-h", "ldap://localhost"}, "use -H"},
		{[]string{"-h", "ldaps://localhost"}, "use -H"},
		{[]string{"-h", "host/path"}, "use -H"},
		{[]string{"-h", "host?query"}, "use -H"},
		{[]string{"-h", "host#fragment"}, "use -H"},
		{[]string{"-h", "user:password@host"}, "use -H"},
		{[]string{"-h", "host%20name"}, "use -H"},
		{[]string{"-h", "[::1"}, "-h requires"},
		{[]string{"-h", "[host]"}, "bracketed IPv6"},
		{[]string{"-h", "[127.0.0.1]"}, "bracketed IPv6"},
		{[]string{"-h", "[host]:389"}, "valid IPv6"},
		{[]string{"-h", "[127.0.0.1]:389"}, "valid IPv6"},
		{[]string{"-h", "host\"name"}, "use -H"},
		{[]string{"-h", "host:"}, "optional port"},
		{[]string{"-h", "host:abc"}, "unable to parse port number"},
		{[]string{"-h", "host:65536"}, "between 0 and 65535"},
		{[]string{"-h", "localhost:389", "-p", "389"}, "port in -h"},
		{[]string{"-p", "389"}, "-p without -h is invalid"},
		{[]string{"-p", "0"}, "-p without -h is invalid"},
		{[]string{"-h", "first", "-h", "second"}, "-h previously specified"},
		{[]string{"-h", "localhost", "-p", "0", "-p", "389"}, "-p previously specified"},
		{[]string{"-h", "localhost", "-p", ""}, "unable to parse port number"},
		{[]string{"-h", "localhost", "-p", "389 "}, "unable to parse port number"},
		{[]string{"-h", "localhost", "-p", "ldap"}, "unable to parse port number"},
		{[]string{"-h", "localhost", "-p", "0x185"}, "unable to parse port number"},
		{[]string{"-h", "localhost", "-p", "1_389"}, "unable to parse port number"},
		{[]string{"-h", "localhost", "-p", "389suffix"}, "unable to parse port number"},
		{[]string{"-h", "localhost", "-p", "-1"}, "between 0 and 65535"},
		{[]string{"-h", "localhost", "-p", "65536"}, "between 0 and 65535"},
		{[]string{"-h", "localhost", "-p", "4294967685"}, "unable to parse port number"},
		{[]string{"-h", "localhost", "-p", strings.Repeat("9", 80)}, "unable to parse port number"},
		{[]string{"-h", "localhost", "-tls-server-name", "localhost"}, "TLS options require"},
		{[]string{"-h", "localhost", "-Z", "-ZZ"}, "mutually exclusive"},
		{[]string{"-h"}, "flag needs an argument"},
		{[]string{"-p"}, "flag needs an argument"},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			stdout, stderr, code := runLDAPClientCommand(append([]string{"ldapwhoami", "-x"}, test.args...), "")
			if code != 1 || stdout != "" || !strings.Contains(stderr, test.message) {
				t.Fatalf("exit=%d stdout=%q stderr=%q want=%q", code, stdout, stderr, test.message)
			}
		})
	}
}

type ldapHostPortUnreadInput struct{ reads int }

func (input *ldapHostPortUnreadInput) Read([]byte) (int, error) {
	input.reads++
	return 0, errors.New("unexpected password or operation input read")
}

func TestLDAPClientHostPortAtomicValidation(t *testing.T) {
	var binds atomic.Int32
	fixture := startLDAPClientWireFixture(t, uriListReviewHandler(&binds, ldapwire.ResultSuccess))
	valid := ldapHostPortArgs(t, fixture.uri)
	failurePath := filepath.Join(t.TempDir(), "failures.ldif")
	if err := os.WriteFile(failurePath, []byte("preserve me"), 0o600); err != nil {
		t.Fatal(err)
	}
	commands := append(ldapHostPortCommandCases(), ldapHostPortCommandCase{command: "health"}, ldapHostPortCommandCase{command: "online-backup"})
	for _, test := range commands {
		t.Run(test.command, func(t *testing.T) {
			for _, invalid := range [][]string{
				{"-h", valid[1], "-p", "bad-port-secret"},
				{"-h", valid[1] + ",bad-host-secret", "-p", valid[3]},
				{"-H", fixture.uri, "-h", valid[1]},
				{"-p", "0", "-H", fixture.uri},
				{"-h", valid[1], "-H", "ldaps://secret@bad"},
				{"-H", fixture.uri + " ldap://bad:", "-p", valid[3]},
				{"-h", "localhost", "-H", ""},
			} {
				for _, password := range [][]string{{"-W"}, {"-y", "nonexistent-password-file"}, {"-w", "bind-secret"}} {
					args := append([]string{test.command, "-x", "-D", clientToolRootDN}, password...)
					args = append(args, invalid...)
					if test.command == "ldapmodify" || test.command == "ldapadd" {
						args = append(args, "-f", "nonexistent-input-file", "-S", failurePath)
					}
					args = append(args, test.args...)
					var stdout, stderr bytes.Buffer
					input := &ldapHostPortUnreadInput{}
					code := run(args, input, &stdout, &stderr, func(string) string { return "" })
					if code != 1 || stdout.Len() != 0 || input.reads != 0 || binds.Load() != 0 {
						t.Fatalf("exit=%d reads=%d binds=%d stdout=%q stderr=%q", code, input.reads, binds.Load(), stdout.String(), stderr.String())
					}
					for _, forbidden := range []string{"secret", "Enter LDAP", "nonexistent-", "unsupported"} {
						if strings.Contains(stderr.String(), forbidden) {
							t.Fatalf("address validation exposed or accessed %q: %s", forbidden, stderr.String())
						}
					}
				}
			}
		})
	}
	data, err := os.ReadFile(failurePath)
	if err != nil || string(data) != "preserve me" {
		t.Fatalf("failure file changed: %q, %v", data, err)
	}
}

func TestLDAPClientHostPortArgumentBoundaries(t *testing.T) {
	flags := flag.NewFlagSet("ldapsearch", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var options ldapClientOptions
	options.register(flags)
	defer options.clear()
	flags.Int("page-size", 0, "page size")
	flags.String("f", "", "input")
	for _, args := range [][]string{
		{"-w", "-hsecret", "-hlocalhost", "-p1389"},
		{"-w", "-psecret", "-hlocalhost", "-p1389"},
		{"-f", "-hfilename", "-hlocalhost", "-p1389"},
		{"-page-size", "2", "-hlocalhost", "-p1389"},
		{"-hlocalhost", "--", "-hoperand", "-poperand"},
		{"-hlocalhost", "cn=operand", "-hoperand", "-poperand"},
		{"-w=-hsecret", "-hlocalhost", "-p1389"},
		{"-H", "ldap://first ldap://second", "--", "-hoperand"},
	} {
		want := slices.Clone(args)
		for index, value := range want {
			if value == "-hlocalhost" {
				want = slices.Replace(want, index, index+1, "-h", "localhost")
				break
			}
		}
		if index := slices.Index(want, "-p1389"); index >= 0 {
			want = slices.Replace(want, index, index+1, "-p", "1389")
		}
		if got := normalizeLDAPClientHostPortArgs(flags, args); !slices.Equal(got, want) {
			t.Fatalf("argument boundaries changed: got=%q want=%q", got, want)
		}
	}
	for _, option := range options.unsupportedFlags {
		if option.name == "h" || option.name == "p" {
			t.Fatalf("-%s remains unsupported", option.name)
		}
	}
	for _, name := range []string{"d", "P", "I", "M", "N", "Q", "v", "V"} {
		if !slices.ContainsFunc(options.unsupportedFlags, func(option unsupportedFlag) bool { return option.name == name }) {
			t.Fatalf("unrelated unsupported flag -%s removed", name)
		}
	}
}

func TestLDAPClientHostPortDryRuns(t *testing.T) {
	var binds atomic.Int32
	fixture := startLDAPClientWireFixture(t, uriListReviewHandler(&binds, ldapwire.ResultSuccess))
	for _, test := range ldapHostPortCommandCases() {
		if test.command == "ldapsearch" || test.command == "ldapwhoami" {
			continue
		}
		t.Run(test.command, func(t *testing.T) {
			args := append([]string{test.command, "-n", "-x", "-D", clientToolRootDN, "-W"}, ldapHostPortArgs(t, fixture.uri)...)
			args = append(args, test.args...)
			stdout, stderr, code := runLDAPClientCommand(args, test.input)
			if code != 0 || stderr != "" || binds.Load() != 0 || strings.Contains(stdout, "host-port-new-password") {
				t.Fatalf("exit=%d binds=%d stdout=%q stderr=%q", code, binds.Load(), stdout, stderr)
			}
			args = append([]string{test.command, "-n", "-h", "localhost", "-p", "bad-port-secret"}, test.args...)
			stdout, stderr, code = runLDAPClientCommand(args, test.input)
			if code != 1 || stdout != "" || !strings.Contains(stderr, "unable to parse port number") ||
				strings.Contains(stderr, "secret") || binds.Load() != 0 {
				t.Fatalf("invalid dry run exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestLDAPClientHostPortPasswordAndSASL(t *testing.T) {
	for _, sasl := range []bool{false, true} {
		for _, command := range []string{"ldapwhoami", "ldapsearch", "ldapcompare"} {
			t.Run(command+map[bool]string{false: "/simple", true: "/SASL"}[sasl], func(t *testing.T) {
				const secret = "-hsecret-pvalue"
				var binds atomic.Int32
				respond := uriListReviewHandler(&binds, ldapwire.ResultSuccess)
				fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
					if request, ok := message.Request.(ldapwire.BindRequest); ok {
						auth := request.Authentication
						if auth.IsSASL != sasl || (!sasl && string(auth.Simple) != secret) ||
							(sasl && (auth.SASLMechanism != "PLAIN" || string(auth.SASLCredentials) != "\x00review\x00"+secret)) {
							t.Error("authentication arguments changed during address parsing")
						}
					}
					return respond(message)
				})
				address := ldapHostPortArgs(t, fixture.uri)
				args := []string{command, "-h" + address[1], "-p" + address[3], "-w", secret}
				if sasl {
					args = append(args, "-Y", "PLAIN", "-U", "review")
				} else {
					args = append(args, "-x", "-D", "cn=review")
				}
				wantCode := 0
				if command == "ldapsearch" {
					args = append(args, "-b", "", "-s", "base", "-LLL")
				} else if command == "ldapcompare" {
					args = append(args, "cn=review", "cn:review")
					wantCode = ldap.LDAPResultCompareTrue
				}
				stdout, stderr, code := runLDAPClientCommand(args, "")
				if code != wantCode || stderr != "" || binds.Load() != 1 || strings.Contains(stdout, secret) {
					t.Fatalf("exit=%d binds=%d stdout=%q stderr=%q", code, binds.Load(), stdout, stderr)
				}
			})
		}
	}
}

func TestLDAPClientHostPortStartTLS(t *testing.T) {
	tlsConfig, pem := newLDAPClientToolTLSConfig(t)
	secure := startLDAPClientToolServer(t, tlsConfig)
	cleartext := startLDAPClientToolServer(t, nil)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"ldapwhoami", "ldapsearch", "ldapcompare"} {
		for _, mode := range []string{"-Z", "-ZZ"} {
			for _, uri := range []string{secure, cleartext} {
				t.Run(command+mode+uri, func(t *testing.T) {
					args := append([]string{command, "-x", mode}, ldapHostPortArgs(t, uri)...)
					if uri == secure {
						args = append(args, "-tls-ca", ca)
					}
					wantCode := 0
					if command == "ldapsearch" {
						args = append(args, "-s", "base", "-b", "", "-LLL")
					} else if command == "ldapcompare" {
						args = append(args, "uid=alice,"+clientToolPeopleDN, "uid:alice")
						wantCode = ldap.LDAPResultCompareTrue
					}
					stdout, stderr, code := runLDAPClientCommand(args, "")
					if uri == cleartext && mode == "-ZZ" {
						if code == 0 || code == ldap.LDAPResultCompareTrue || stdout != "" || !strings.Contains(stderr, "StartTLS") {
							t.Fatalf("required TLS exit=%d stdout=%q stderr=%q", code, stdout, stderr)
						}
					} else if code != wantCode || (uri == secure && stderr != "") ||
						(uri == cleartext && !strings.Contains(stderr, "continuing over cleartext LDAP")) {
						t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout, stderr)
					}
				})
			}
		}
	}
}
