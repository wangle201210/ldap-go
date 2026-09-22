package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func fixtureArgs() []string {
	return []string{
		"-uri", "ldap://127.0.0.1:1389", "-bind-dn", "cn=admin,dc=fixture",
		"-base", "dc=fixture", "-people", "ou=people,dc=fixture", "-password-env", "ROOT_SECRET",
	}
}

func testLookup(name string) (string, bool) {
	values := map[string]string{"ROOT_SECRET": "root-test-secret", "USER_SECRET": "user-test-secret", "EMPTY_SECRET": ""}
	value, ok := values[name]
	return value, ok
}

func TestOptionsRejectUnsafeOrInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"implicit mode", nil, "exactly one"},
		{"conflicting modes", []string{"-write", "-read-only"}, "exactly one"},
		{"missing URI", []string{"-read-only", "-uri="}, "-uri"},
		{"URI credentials", []string{"-read-only", "-uri=ldap://user:secret@localhost"}, "-uri"},
		{"URI query", []string{"-read-only", "-uri=ldap://localhost/?uid"}, "-uri"},
		{"wrong scheme", []string{"-read-only", "-uri=http://localhost"}, "-uri"},
		{"invalid port", []string{"-read-only", "-uri=ldap://localhost:65536"}, "port"},
		{"missing Bind DN", []string{"-read-only", "-bind-dn="}, "bind-dn"},
		{"missing base", []string{"-read-only", "-base="}, "base"},
		{"invalid DN", []string{"-read-only", "-people=invalid"}, "people"},
		{"outside base", []string{"-read-only", "-people=ou=people,dc=other"}, "below"},
		{"missing env name", []string{"-read-only", "-password-env="}, "environment variable"},
		{"missing env value", []string{"-read-only", "-password-env=MISSING_SECRET"}, "nonempty"},
		{"empty env value", []string{"-read-only", "-password-env=EMPTY_SECRET"}, "nonempty"},
		{"write requires user env", []string{"-write"}, "user-password-env"},
		{"CLI password forbidden", []string{"-read-only", "-password=secret"}, "flag provided but not defined"},
		{"zero entries", []string{"-read-only", "-entries=0"}, "entries"},
		{"large entries", []string{"-read-only", "-entries=1000000"}, "entries"},
		{"no timeout", []string{"-read-only", "-timeout=0"}, "timeout"},
		{"huge timeout", []string{"-read-only", "-timeout=6m"}, "timeout"},
		{"positional", []string{"-read-only", "extra"}, "positional"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseOptions(append(fixtureArgs(), tt.args...), testLookup, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestOptionsBoundsAndSecrets(t *testing.T) {
	for _, tt := range []struct {
		args     []string
		n, batch int
	}{
		{[]string{"-read-only"}, 100, 100},
		{[]string{"-read-only", "-n=-10", "-write-batch=0"}, 1, 1},
		{[]string{"-write", "-user-password-env=USER_SECRET", "-n=10001", "-write-batch=1001"}, 10000, 1000},
	} {
		c, err := parseOptions(append(fixtureArgs(), tt.args...), testLookup, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if c.N != tt.n || c.WriteBatch != tt.batch || c.Entries != 100000 {
			t.Fatalf("unexpected bounds: n=%d batch=%d entries=%d", c.N, c.WriteBatch, c.Entries)
		}
		if c.password != "root-test-secret" || (c.Write && c.userPassword != "user-test-secret") || (c.ReadOnly && c.userPassword != "") {
			t.Fatal("password environment handling did not match the selected mode")
		}
		encoded, err := json.Marshal(c)
		if err != nil || bytes.Contains(encoded, []byte("test-secret")) {
			t.Fatal("config JSON must not contain password values")
		}
	}
}

func TestExecuteFailsBeforeConnectingAndEmitsJSON(t *testing.T) {
	var out bytes.Buffer
	code := execute(context.Background(), fixtureArgs(), testLookup, &out, io.Discard)
	var result report
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if code != 2 || result.Error == "" || len(result.Stages) != 0 {
		t.Fatalf("exit=%d error=%q stages=%d", code, result.Error, len(result.Stages))
	}
}

func TestSamplingCoversFixtureBounds(t *testing.T) {
	c := options{N: 100, Entries: 100000}
	if sampleUID(c, 0) != "scale-000001" || sampleUID(c, 99) != "scale-100000" || sampleUID(c, 100) != sampleUID(c, 0) {
		t.Fatal("sampling must reproducibly cover the first and last fixture entry")
	}
	c.Entries = 1
	if sampleUID(c, 99) != "scale-000001" {
		t.Fatal("single-entry dummy fixture must remain usable")
	}
}
