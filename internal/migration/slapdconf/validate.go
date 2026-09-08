package slapdconf

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/wangle201210/ldap-go/internal/migration"
	"github.com/wangle201210/ldap-go/internal/server"
	"github.com/wangle201210/ldap-go/internal/storage"
)

// Validate loads the complete tree in disposable Go memory and runs the same
// validation used by offline import. It starts no listeners or replication.
// Referenced TLS files must be accessible to the converting process.
func (document Document) Validate(ctx context.Context) error {
	store := storage.NewMemory()
	defer store.Close()
	return document.Import(ctx, store)
}

func (document Document) validateTLSMaterial() error {
	for _, entry := range document.Entries {
		if entry.DN != "cn=config" {
			continue
		}
		certificate, key := false, false
		source := entry.Position
		hasTLS := false
		for _, attribute := range entry.Attributes {
			switch attribute.Name {
			case "olcTLSCertificateFile":
				certificate = true
			case "olcTLSCertificateKeyFile":
				key = true
			}
			if strings.HasPrefix(attribute.Name, "olcTLS") && !hasTLS {
				hasTLS = true
				if len(attribute.Sources) > 0 {
					source = attribute.Sources[0]
				}
			}
		}
		if hasTLS && (!certificate || !key) {
			return sourceError(source, errors.New("TLS settings require both TLSCertificateFile and TLSCertificateKeyFile; ldap-go cannot apply standalone TLS defaults"))
		}
	}
	return nil
}

// Import atomically imports and validates the converted configuration. The
// caller owns the store. Existing entries are never implicitly replaced.
func (document Document) Import(ctx context.Context, store storage.Store) error {
	if ctx == nil || store == nil {
		return errors.New("import context and store are required")
	}
	if err := document.validateTLSMaterial(); err != nil {
		return err
	}
	var input bytes.Buffer
	if err := document.WriteLDIF(&input); err != nil {
		return err
	}
	_, err := migration.ImportLDIF(ctx, store, &input, migration.ImportOptions{
		ValidateConfigTransaction: func(reader storage.Reader) error {
			_, err := server.ValidateConfigurationReader(ctx, server.Config{Store: store}, reader)
			return err
		},
	})
	return document.locateError(err)
}

// Runtime validators identify entries and attributes. Preserve that diagnostic
// and attach the closest originating directive without parsing error values.
func (document Document) locateError(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	var selected *Entry
	bestScore := 0
	for i := range document.Entries {
		entry := &document.Entries[i]
		score := 0
		if strings.Contains(message, strings.ToLower(entry.DN)) {
			score = len(entry.DN)
		}
		for _, attribute := range entry.Attributes {
			if len(attribute.Values) == 0 {
				continue
			}
			if attribute.Name == "olcDatabase" && strings.Contains(message, strings.ToLower(attribute.Values[0])) {
				score = len(entry.DN)
			}
			if attribute.Name == "olcOverlay" {
				_, name, _ := strings.Cut(attribute.Values[0], "}")
				_, parent, _ := strings.Cut(entry.DN, ",olcDatabase=")
				database, _, _ := strings.Cut(parent, ",")
				if name != "" && database != "" && strings.Contains(message, strings.ToLower(database)) && strings.Contains(message, strings.ToLower(name)+" overlay") {
					score = len(entry.DN)
				}
			}
		}
		if score > bestScore {
			selected = entry
			bestScore = score
		}
	}
	position := Position{}
	if len(document.Entries) > 0 {
		position = document.Entries[0].Position
	}
	if selected != nil {
		if selected.Position.Path != "" {
			position = selected.Position
		}
		for _, attribute := range selected.Attributes {
			if len(attribute.Sources) > 0 && strings.Contains(message, strings.ToLower(attribute.Name)) {
				position = attribute.Sources[0]
				break
			}
		}
	}
	return sourceError(position, err)
}
