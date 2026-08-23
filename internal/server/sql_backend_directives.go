package server

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-ldap/ldif"
	"github.com/wangle201210/ldap-go/internal/directory"
)

func readSQLBaseObjectFile(path string) ([]byte, [sha256.Size]byte, error) {
	var empty [sha256.Size]byte
	if !filepath.IsAbs(path) {
		return nil, empty, errors.New("file path must be absolute")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, empty, fmt.Errorf("inspect file: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, empty, errors.New("symbolic links are not allowed")
	}
	if !before.Mode().IsRegular() {
		return nil, empty, errors.New("path is not a regular file")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, empty, fmt.Errorf("open containing directory: %w", err)
	}
	defer root.Close()
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, empty, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, empty, fmt.Errorf("inspect opened file: %w", err)
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, empty, errors.New("file identity changed while opening")
	}
	if opened.Size() < 0 || opened.Size() > maxSQLBaseObjectFileSize {
		return nil, empty, fmt.Errorf(
			"file size %d exceeds %d bytes",
			opened.Size(),
			maxSQLBaseObjectFileSize,
		)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSQLBaseObjectFileSize+1))
	if err != nil {
		return nil, empty, fmt.Errorf("read file: %w", err)
	}
	if len(data) > maxSQLBaseObjectFileSize {
		return nil, empty, fmt.Errorf("file exceeds %d bytes", maxSQLBaseObjectFileSize)
	}
	return data, sha256.Sum256(data), nil
}

func (configuration *sqlBackendRuntimeConfiguration) prepareSQLLayers(
	entry directory.Entry,
) error {
	var mapping *sqlDNLayer
	for _, raw := range configuration.layers {
		value, err := stripRWMOrderingPrefix(raw)
		if err != nil {
			return fmt.Errorf("%s olcSqlLayer: %w", entry.DN, err)
		}
		words, err := splitRWMConfigurationWords(value)
		if err != nil {
			return fmt.Errorf("%s olcSqlLayer: %w", entry.DN, err)
		}
		if len(words) == 1 && strings.EqualFold(words[0], "identity") {
			continue
		}
		if len(words) != 3 || !strings.EqualFold(words[0], "suffixmassage") {
			name := ""
			if len(words) != 0 {
				name = words[0]
			}
			return fmt.Errorf(
				"%s olcSqlLayer %q requires an unavailable native back-sql plugin; supported built-ins are identity and suffixmassage <ldap-suffix> <sql-suffix>",
				entry.DN,
				name,
			)
		}
		if mapping != nil {
			return fmt.Errorf("%s olcSqlLayer supports only one non-identity layer", entry.DN)
		}
		local, err := directory.ParseDN(words[1])
		if err != nil || local.Depth() == 0 {
			return fmt.Errorf("%s olcSqlLayer has invalid LDAP suffix %q", entry.DN, words[1])
		}
		remote, err := directory.ParseDN(words[2])
		if err != nil || remote.Depth() == 0 {
			return fmt.Errorf("%s olcSqlLayer has invalid SQL suffix %q", entry.DN, words[2])
		}
		suffixes := entry.Values("olcSuffix")
		if len(suffixes) != 1 {
			return fmt.Errorf("%s olcSqlLayer suffixmassage requires exactly one olcSuffix", entry.DN)
		}
		configured, err := directory.ParseDN(string(suffixes[0]))
		if err != nil || !configured.Equal(local) {
			return fmt.Errorf(
				"%s olcSqlLayer LDAP suffix %q must equal olcSuffix",
				entry.DN,
				words[1],
			)
		}
		mapping = &sqlDNLayer{kind: "suffixmassage", local: local, remote: remote}
	}
	configuration.dnLayer = mapping
	return nil
}

func cloneSQLDNLayer(layer *sqlDNLayer) *sqlDNLayer {
	if layer == nil {
		return nil
	}
	clone := *layer
	return &clone
}

func parseSQLScopeTemplate(value string) (sqlScopeTemplate, error) {
	canonical := strings.ToUpper(strings.Join(strings.Fields(value), " "))
	switch canonical {
	case "LDAP_ENTRIES.DN LIKE ?":
		return sqlScopeTemplateLike, nil
	case "UPPER(LDAP_ENTRIES.DN) LIKE UPPER(?)":
		return sqlScopeTemplateUpperLike, nil
	default:
		return sqlScopeTemplateNone, errors.New(
			"only the parameterized templates 'ldap_entries.dn LIKE ?' and 'UPPER(ldap_entries.dn) LIKE UPPER(?)' are portable and injection-safe",
		)
	}
}

func (template sqlScopeTemplate) queryExpression() string {
	switch template {
	case sqlScopeTemplateLike:
		return "ldap_entries.dn LIKE ?"
	case sqlScopeTemplateUpperLike:
		return "UPPER(ldap_entries.dn) LIKE UPPER(?)"
	default:
		return ""
	}
}

func (configuration *sqlBackendRuntimeConfiguration) normalizeLayerDN(
	dn directory.DN,
) (directory.DN, error) {
	if configuration.registry == nil {
		return dn, nil
	}
	return configuration.registry.NormalizeDN(dn.String())
}

func (configuration *sqlBackendRuntimeConfiguration) serverSuffixes() []directory.DN {
	result := make([]directory.DN, 0, len(configuration.suffixes))
	for _, raw := range configuration.suffixes {
		dn, err := directory.ParseDN(raw)
		if err == nil {
			result = append(result, dn)
		}
	}
	return result
}

func (configuration *sqlBackendRuntimeConfiguration) mapLDAPDNToSQL(
	dn directory.DN,
) (directory.DN, error) {
	if configuration.dnLayer == nil {
		return configuration.normalizeLayerDN(dn)
	}
	local, err := configuration.normalizeLayerDN(configuration.dnLayer.local)
	if err != nil {
		return directory.DN{}, err
	}
	remote, err := configuration.normalizeLayerDN(configuration.dnLayer.remote)
	if err != nil {
		return directory.DN{}, err
	}
	dn, err = configuration.normalizeLayerDN(dn)
	if err != nil {
		return directory.DN{}, err
	}
	if !local.Equal(dn) && !local.AncestorOf(dn) {
		return directory.DN{}, fmt.Errorf("DN %q is outside SQL layer LDAP suffix", dn.String())
	}
	return dn.ReplaceAncestor(local, remote)
}

func (configuration *sqlBackendRuntimeConfiguration) mapSQLDNToLDAP(
	dn directory.DN,
) (directory.DN, error) {
	if configuration.dnLayer == nil {
		return configuration.normalizeLayerDN(dn)
	}
	local, err := configuration.normalizeLayerDN(configuration.dnLayer.local)
	if err != nil {
		return directory.DN{}, err
	}
	remote, err := configuration.normalizeLayerDN(configuration.dnLayer.remote)
	if err != nil {
		return directory.DN{}, err
	}
	dn, err = configuration.normalizeLayerDN(dn)
	if err != nil {
		return directory.DN{}, err
	}
	if !remote.Equal(dn) && !remote.AncestorOf(dn) {
		return directory.DN{}, fmt.Errorf("stored DN %q is outside SQL layer suffix", dn.String())
	}
	return dn.ReplaceAncestor(remote, local)
}

func (configuration *sqlBackendRuntimeConfiguration) prepareBaseObjectFile() error {
	if len(configuration.baseObjectData) == 0 {
		configuration.baseObjectEntry = &directory.Entry{DN: configuration.baseObjectSuffix}
		return nil
	}
	suffix, err := configuration.registry.NormalizeDN(configuration.baseObjectSuffix)
	if err != nil {
		return fmt.Errorf("SQL-backend olcSqlBaseObject suffix: %w", err)
	}
	entry := directory.Entry{DN: suffix.String()}
	document := &ldif.LDIF{}
	records := 0
	for record, parseErr := range ldif.UnmarshalEntries(
		bytes.NewReader(configuration.baseObjectData),
		document,
	) {
		if parseErr != nil {
			return fmt.Errorf("parse LDIF: %w", parseErr)
		}
		if record == nil {
			continue
		}
		records++
		if records > maxSQLBaseObjectRecords {
			return fmt.Errorf("LDIF exceeds %d records", maxSQLBaseObjectRecords)
		}
		if record.Entry == nil {
			return errors.New("LDIF change records are not accepted")
		}
		recordDN, err := configuration.registry.NormalizeDN(record.Entry.DN)
		if err != nil || !recordDN.Equal(suffix) {
			return fmt.Errorf("LDIF entry DN %q is not the SQL suffix", record.Entry.DN)
		}
		for _, attribute := range record.Entry.Attributes {
			if _, found, err := configuration.registry.EffectiveAttributeType(attribute.Name); err != nil {
				return fmt.Errorf("LDIF attribute %q: %w", attribute.Name, err)
			} else if !found {
				return fmt.Errorf("LDIF attribute %q is undefined", attribute.Name)
			}
			for _, value := range attribute.ByteValues {
				if err := configuration.registry.ValidateAttributeValue(attribute.Name, value); err != nil {
					return fmt.Errorf("LDIF attribute %q: %w", attribute.Name, err)
				}
				appendSQLAttributeValue(&entry, attribute.Name, value)
			}
		}
	}
	configuration.baseObjectEntry = &entry
	return nil
}
