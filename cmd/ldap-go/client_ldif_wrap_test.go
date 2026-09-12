package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
)

func TestLDAPLDIFWrapOptions(t *testing.T) {
	for _, test := range []struct {
		args []string
		want uint64
	}{
		{nil, 0}, {[]string{"ldif-wrap"}, 0}, {[]string{"ldif_wrap=0"}, 0},
		{[]string{"ldif-wrap=1"}, 1}, {[]string{"LDIF-WRAP=NO"}, math.MaxUint64},
		{[]string{"ldif-wrap=+020"}, 20}, {[]string{"ldif_wrap= \t20"}, 20},
		{[]string{"ldif-wrap=4294967295"}, math.MaxUint32},
		{[]string{"ldif-wrap=no", "ldif-wrap=20"}, 20},
		{[]string{"ldif-wrap=20", "ldif-wrap"}, 0},
	} {
		options := ldapClientOptions{generalOptionSpecs: test.args}
		if err := options.applyGeneralOptions(flag.NewFlagSet("test", flag.ContinueOnError)); err != nil || options.ldifWrap != test.want {
			t.Fatalf("%q width=%d want=%d err=%v", test.args, options.ldifWrap, test.want, err)
		}
	}
	for _, invalid := range []string{"", "yes", "-1", "4294967296", "0x4e", "12 ", "+", "1_000"} {
		out, diagnostics, code := runLDAPClientCommand([]string{"ldapsearch", "-x", "-H", "ldap://127.0.0.1:1", "-o", "ldif-wrap=" + invalid}, "")
		if code == 0 || out != "" || !strings.Contains(diagnostics, "unable to parse ldif_wrap") {
			t.Fatalf("invalid %q: code=%d out=%q err=%q", invalid, code, out, diagnostics)
		}
	}
}

func TestLDAPLDIFWrapPreservesValues(t *testing.T) {
	for _, width := range []uint64{1, 2, 5, 20, 78, math.MaxUint64} {
		t.Run(strconv.FormatUint(width, 10), func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			writer := (&ldapClientOptions{ldifWrap: width}).ldifWriter(&out)
			for _, attr := range []struct {
				name  string
				value []byte
			}{
				{"dn", []byte("uid=alice," + clientToolPeopleDN)},
				{"description", []byte(strings.Repeat("text value ", 25) + "end")},
				{"jpegPhoto", []byte{0, 255, 1, 2, 3, 4}},
			} {
				if err := writeLDIFAttribute(writer, attr.name, attr.value); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := io.WriteString(writer, "\n"); err != nil {
				t.Fatal(err)
			}
			entries := parseLDAPSearchOutput(t, out.String())
			if len(entries) != 1 || entries[0].DN != "uid=alice,"+clientToolPeopleDN ||
				entries[0].GetAttributeValue("description") != strings.Repeat("text value ", 25)+"end" ||
				!bytes.Equal(entries[0].GetRawAttributeValue("jpegPhoto"), []byte{0, 255, 1, 2, 3, 4}) {
				t.Fatalf("LDIF changed values: %q", out.String())
			}
			if width == math.MaxUint64 && strings.Contains(out.String(), "\n ") {
				t.Fatal("no-wrap output folded")
			}
		})
	}
}

type ldapLDIFShortWriter struct{}

func (ldapLDIFShortWriter) Write(value []byte) (int, error) {
	return max(len(value)-1, 0), nil
}

func TestLDAPLDIFWrapWriterErrors(t *testing.T) {
	failure := errors.New("output failed")
	for _, test := range []struct {
		writer io.Writer
		want   error
	}{
		{ldapURLToolFailWriter{failure}, failure},
		{ldapLDIFShortWriter{}, io.ErrShortWrite},
	} {
		writer := (&ldapClientOptions{ldifWrap: 20}).ldifWriter(test.writer)
		if err := writeLDIFAttribute(writer, "description", []byte("value")); !errors.Is(err, test.want) {
			t.Fatalf("write error = %v, want %v", err, test.want)
		}
	}
}

func TestLDAPLDIFWrapOpenLDAP(t *testing.T) {
	if os.Getenv("LDAP_GO_LDIF_WRAP_EXTERNAL") != "1" {
		t.Skip("set LDAP_GO_LDIF_WRAP_EXTERNAL=1 for OpenLDAP 2.6.13 comparison")
	}
	tool := os.Getenv("OPENLDAP_LDAPSEARCH")
	if tool == "" {
		var err error
		tool, err = exec.LookPath("ldapsearch")
		if err != nil {
			t.Fatal(err)
		}
	}
	version, err := exec.Command(tool, "-VV").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "OpenLDAP: ldapsearch 2.6.13") {
		t.Fatalf("requires 2.6.13: %s %v", version, err)
	}
	for fixture, uri := range map[string]string{
		"directory":      startLDAPClientToolServer(t, nil),
		"controls":       startLDAPClientWireFixture(t, ldapSearchControlFixtureHandler).uri,
		"known controls": startLDAPClientWireFixture(t, ldapSearchKnownControlFixtureHandler).uri,
	} {
		for _, level := range []string{"", "-L", "-LL", "-LLL"} {
			// The native libldap allocator can abort at width 1; cover that value
			// in the local round-trip test rather than rely on an unstable oracle.
			for _, width := range []string{"2", "5", "20", "78", "0", "no", "4294967295"} {
				t.Run(fixture+"/"+level+"/"+width, func(t *testing.T) {
					args := []string{"-x", "-H", uri, "-b", "uid=alice," + clientToolPeopleDN, "-s", "base", "-o", "ldif-wrap=" + width}
					if level != "" {
						args = append(args, level)
					}
					args = append(args, "(objectClass=*)", "cn", "description", "jpegPhoto")
					local, diagnostics, code := runLDAPClientCommand(append([]string{"ldapsearch"}, args...), "")
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					command := exec.CommandContext(ctx, tool, args...)
					command.Env = append(os.Environ(), "LDAPNOINIT=1", "LC_ALL=C")
					var reference, stderr bytes.Buffer
					command.Stdout = &reference
					command.Stderr = &stderr
					if err := command.Run(); err != nil {
						t.Fatalf("reference: %v %s", err, &stderr)
					}
					if code != 0 || diagnostics != stderr.String() || local != reference.String() {
						t.Fatalf("local code=%d err=%q\nlocal=%q\nreference=%q stderr=%q", code, diagnostics, local, reference.String(), stderr.String())
					}
				})
			}
		}
	}
	fixture := startLDAPClientWireFixture(t, func(message ldapwire.Message) ([][]byte, error) {
		switch message.Request.(type) {
		case ldapwire.CompareRequest:
			return [][]byte{ldapwire.EncodeResultResponse(message.ID, ldap.ApplicationCompareResponse,
				ldapwire.Result{Code: ldapwire.ResultCompareTrue}, []ldapwire.Control{{
					OID: "1.2.3.4", HasValue: true, Value: bytes.Repeat([]byte{0xff, 0}, 30),
				}})}, nil
		case ldapwire.ExtendedRequest:
			return [][]byte{ldapwire.EncodeExtendedResponse(message.ID, ldapwire.Result{}, "1.2.3.4", bytes.Repeat([]byte{0xff, 0}, 30), nil)}, nil
		}
		return nil, nil
	})
	for _, toolName := range []string{"ldapcompare", "ldapexop"} {
		for _, width := range []string{"2", "20", "no"} {
			t.Run(toolName+"/"+width, func(t *testing.T) {
				args := []string{"-x", "-H", fixture.uri, "-o", "ldif-wrap=" + width}
				wantExit := 0
				if toolName == "ldapcompare" {
					args = append(args, "cn=test", "cn:test")
					wantExit = ldap.LDAPResultCompareTrue
				} else {
					args = append(args, "1.2.3.4")
				}
				out, diagnostics, code := runLDAPClientCommand(append([]string{toolName}, args...), "")
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, filepath.Join(filepath.Dir(tool), toolName), args...)
				command.Env = append(os.Environ(), "LDAPNOINIT=1", "LC_ALL=C")
				var reference, stderr bytes.Buffer
				command.Stdout = &reference
				command.Stderr = &stderr
				err := command.Run()
				if command.ProcessState == nil || command.ProcessState.ExitCode() != wantExit {
					t.Fatalf("reference: %v %s", err, &stderr)
				}
				if code != wantExit || out != reference.String() || diagnostics != stderr.String() {
					t.Fatalf("local exit=%d out=%q err=%q; reference out=%q err=%q", code, out, diagnostics, reference.String(), stderr.String())
				}
			})
		}
	}
}
