package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type defaultSearchBaseConfiguration struct {
	dn         directory.DN
	configured bool
}

func validateDefaultSearchBaseOnlineChanges(
	changes []ldapwire.Modification,
) error {
	for _, change := range changes {
		attribute := strings.SplitN(change.Attribute.Description, ";", 2)[0]
		if !strings.EqualFold(attribute, "olcDefaultSearchBase") ||
			change.Operation == ldapwire.ModificationDelete {
			continue
		}
		return operationFailed(
			ldapwire.ResultConstraintViolation,
			"olcDefaultSearchBase can only be set while loading configuration",
		)
	}
	return nil
}

func normalizeDefaultSearchBaseConfiguration(
	ctx context.Context,
	store storage.Store,
) error {
	type update struct {
		partition string
		entry     directory.Entry
	}

	return store.Update(ctx, func(writer storage.Writer) error {
		var updates []update
		err := writer.ForEachPartition(func(
			partition string,
			entry directory.Entry,
		) error {
			entryDN, err := directory.ParseDN(entry.DN)
			if err != nil {
				return fmt.Errorf("parse entry DN %q: %w", entry.DN, err)
			}
			if !configurationSuffix.Equal(entryDN) {
				databaseValues := entry.Values("olcDatabase")
				if len(databaseValues) != 1 ||
					databaseType(string(databaseValues[0])) != "frontend" {
					return nil
				}
			}
			values := entry.Values("olcDefaultSearchBase")
			if len(values) != 1 {
				return nil
			}
			raw := strings.TrimSpace(string(values[0]))
			if raw == "" {
				return nil
			}
			dn, err := directory.ParseDN(raw)
			if err != nil {
				return fmt.Errorf(
					"parse %s olcDefaultSearchBase: %w",
					entry.DN,
					err,
				)
			}
			canonical := dn.String()
			if string(values[0]) == canonical {
				return nil
			}
			entry.ReplaceValues(
				"olcDefaultSearchBase",
				[][]byte{[]byte(canonical)},
			)
			updates = append(updates, update{partition: partition, entry: entry})
			return nil
		})
		if err != nil {
			return err
		}
		for _, item := range updates {
			if err := writer.PutIn(item.partition, item.entry, true); err != nil {
				return fmt.Errorf(
					"normalize %s olcDefaultSearchBase: %w",
					item.entry.DN,
					err,
				)
			}
		}
		return nil
	})
}

func loadDefaultSearchBase(
	reader storage.Reader,
) (defaultSearchBaseConfiguration, error) {
	global, err := loadDefaultSearchBaseFromEntry(reader, configurationSuffix)
	if err != nil {
		return defaultSearchBaseConfiguration{}, err
	}

	frontend := defaultSearchBaseConfiguration{}
	frontendFound := false
	err = reader.ForEach(func(entry directory.Entry) error {
		values := entry.Values("olcDatabase")
		if len(values) == 0 {
			return nil
		}
		if databaseType(string(values[0])) != "frontend" {
			if len(entry.Values("olcDefaultSearchBase")) != 0 {
				return fmt.Errorf(
					"%s olcDefaultSearchBase is only valid on cn=config or the frontend database",
					entry.DN,
				)
			}
			return nil
		}
		candidate, err := parseDefaultSearchBaseEntry(entry)
		if err != nil {
			return err
		}
		if !candidate.configured {
			return nil
		}
		if frontendFound {
			return errors.New("multiple frontend database entries define a default search base")
		}
		frontend = candidate
		frontendFound = true
		return nil
	})
	if err != nil {
		return defaultSearchBaseConfiguration{}, err
	}
	if frontendFound {
		return frontend, nil
	}
	return global, nil
}

func loadDefaultSearchBaseFromEntry(
	reader storage.Reader,
	dn directory.DN,
) (defaultSearchBaseConfiguration, error) {
	entry, err := reader.Get(dn)
	switch {
	case errors.Is(err, storage.ErrEntryNotFound):
		return defaultSearchBaseConfiguration{}, nil
	case err != nil:
		return defaultSearchBaseConfiguration{}, err
	}
	return parseDefaultSearchBaseEntry(entry)
}

func parseDefaultSearchBaseEntry(
	entry directory.Entry,
) (defaultSearchBaseConfiguration, error) {
	values := entry.Values("olcDefaultSearchBase")
	if len(values) == 0 {
		return defaultSearchBaseConfiguration{}, nil
	}
	if len(values) != 1 {
		return defaultSearchBaseConfiguration{}, fmt.Errorf(
			"%s olcDefaultSearchBase must have exactly one value",
			entry.DN,
		)
	}
	raw := strings.TrimSpace(string(values[0]))
	if raw == "" {
		return defaultSearchBaseConfiguration{}, nil
	}
	parsed, err := directory.ParseDN(raw)
	if err != nil {
		return defaultSearchBaseConfiguration{}, fmt.Errorf(
			"parse %s olcDefaultSearchBase: %w",
			entry.DN,
			err,
		)
	}
	return defaultSearchBaseConfiguration{dn: parsed, configured: true}, nil
}
