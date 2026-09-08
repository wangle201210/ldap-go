package slapdconf

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseFileContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ParseFileContext(ctx, "unused", ParseOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("ParseFileContext error = %v", err)
	}
}

func TestReadConfigurationFileCancellation(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := readConfigurationFile(ctx, reader, 1024)
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("read error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not interrupt the read")
	}
}

func TestParseIncludesAndContinuations(t *testing.T) {
	base := t.TempDir()
	for name, text := range map[string]string{
		"slapd.conf":         "# comment\r\ninclude \"nested schema.conf\"\r\ndatabase mdb\r\ninclude database.conf\r\n",
		"nested schema.conf": "include attribute.schema\nobjectclass ( 1.2.3 NAME 'example' SUP top AUXILIARY\n  MAY exampleAttr )\n",
		"attribute.schema":   "attributetype ( 1.2.3.4 NAME 'exampleAttr'\n  DESC 'a description' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )\n",
		"database.conf":      "suffix dc=example\nrootpw \"# secret\"\naccess to * \\\nby * read\n",
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	directives, err := ParseFile(filepath.Join(base, "slapd.conf"), ParseOptions{IncludeBaseDir: base})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, directive := range directives {
		names = append(names, directive.Name)
	}
	if want := []string{"attributetype", "objectclass", "database", "suffix", "rootpw", "access"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("expansion = %v", names)
	}
	if directives[0].Position.Path != filepath.Join(base, "attribute.schema") || directives[5].Position.Line != 3 {
		t.Fatalf("positions = %+v", directives)
	}
	if got := directives[4].Arguments; !reflect.DeepEqual(got, []string{"# secret"}) {
		t.Fatalf("password = %q", got)
	}
	if got := directives[5].Arguments; !reflect.DeepEqual(got, []string{"to", "*", "by", "*", "read"}) {
		t.Fatalf("ACL = %q", got)
	}
}

func TestParseRejectsMalformedInput(t *testing.T) {
	for _, text := range []string{
		"rootpw \"unterminated\n", "access to * \\\n", "access to * \\",
		" continuation\n", "rootpw bad\x00secret\n", "include\n", "include one two\n",
	} {
		t.Run(strings.ReplaceAll(text, "\n", "_"), func(t *testing.T) {
			path := configFile(t, text)
			got, err := ParseFile(path, ParseOptions{})
			var located *ParseError
			if err == nil || !errors.As(err, &located) || located.Position.Path != path || len(got) != 0 {
				t.Fatalf("parse = %v, %v", got, err)
			}
		})
	}
}

func TestParseLimitsAndCycles(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "slapd.conf")
	child := filepath.Join(base, "child.conf")
	if err := os.WriteFile(path, []byte("include child.conf\ninclude child.conf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(child, []byte("database monitor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, options := range []ParseOptions{
		{MaxFileBytes: 8}, {MaxFileBytes: 40, MaxTotalBytes: 50}, {MaxLogicalLineBytes: 5}, {MaxFiles: 2},
	} {
		options.IncludeBaseDir = base
		if _, err := ParseFile(path, options); err == nil {
			t.Fatalf("accepted limits %+v", options)
		}
	}
	if directives, err := ParseFile(path, ParseOptions{IncludeBaseDir: base}); err != nil || len(directives) != 2 {
		t.Fatalf("repeated nonrecursive include = %v, %v", directives, err)
	}
	if err := os.WriteFile(child, []byte("include slapd.conf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFile(path, ParseOptions{IncludeBaseDir: base}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle = %v", err)
	}
	if err := os.WriteFile(child, []byte("include alias.conf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, filepath.Join(base, "alias.conf")); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFile(path, ParseOptions{IncludeBaseDir: base}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("symlink cycle = %v", err)
	}
	if _, err := ParseFile(path, ParseOptions{IncludeBaseDir: base, MaxIncludeDepth: 1}); err == nil || !strings.Contains(err.Error(), "depth") {
		t.Fatalf("depth = %v", err)
	}
}

func FuzzLogicalLinesAndArguments(f *testing.F) {
	for _, seed := range []string{"access to *\n  by * read\n", "rootpw \"a\\\"b\"\n", "# comment\n", "include core.schema\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 8192 {
			t.Skip()
		}
		lines, err := logicalLines("fuzz.conf", []byte(input), 4096)
		if err != nil {
			return
		}
		for _, line := range lines {
			if line.line < 1 || len(line.text) > 4096 {
				t.Fatalf("invalid line %+v", line)
			}
			_, _ = splitArguments(line.text)
		}
	})
}
