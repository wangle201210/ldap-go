// Command slapdconf-convert migrates legacy OpenLDAP configuration using Go only.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/wangle201210/ldap-go/internal/migration/slapdconf"
	"github.com/wangle201210/ldap-go/internal/storage"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("slapdconf-convert", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("f", "", "slapd.conf input path (required)")
	output := flags.String("out", "", "new LDIF file; default is stdout")
	database := flags.String("db", "", "new ldap-go bbolt database instead of LDIF")
	check := flags.Bool("check", false, "validate without writing output")
	base := flags.String("include-base", "", "base for relative includes; default is working directory")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *input == "" || flags.NArg() != 0 {
		return errors.New("-f slapd.conf is required; positional arguments are not accepted")
	}
	if (*output != "" && *database != "") || (*check && (*output != "" || *database != "")) {
		return errors.New("-out, -db and -check are mutually exclusive")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	document, err := slapdconf.ConvertFileContext(ctx, *input, slapdconf.ParseOptions{IncludeBaseDir: *base})
	if err != nil {
		return err
	}
	if *check {
		_, err = fmt.Fprintln(stderr, "configuration OK")
		return err
	}
	if *database != "" {
		return writeDatabase(ctx, document, *database)
	}
	if *output != "" && *output != "-" {
		return writeLDIF(ctx, document, *output)
	}
	return document.WriteLDIF(stdout)
}

func writeLDIF(ctx context.Context, document slapdconf.Document, path string) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".slapdconf-*.ldif")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	writeErr := document.WriteLDIF(file)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if err := errors.Join(writeErr, file.Close(), ctx.Err()); err != nil {
		return err
	}
	// A same-filesystem hard link publishes the complete 0600 file atomically
	// and refuses every existing destination, including symlinks.
	return os.Link(file.Name(), path)
}

func writeDatabase(ctx context.Context, document slapdconf.Document, path string) (err error) {
	directory, err := os.MkdirTemp(filepath.Dir(path), ".slapdconf-db-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	store, err := storage.OpenBolt(filepath.Join(directory, "config.db"))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, store.Close()) }()
	if err := document.Import(ctx, store); err != nil {
		return err
	}
	_, err = store.Backup(ctx, path, false)
	return err
}
