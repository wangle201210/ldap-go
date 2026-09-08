// Package mdbentry implements OpenLDAP 2.6.13 back-mdb entry limits without LMDB.
package mdbentry

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
)

const Attribute = "olcDbMaxEntrySize"
const AttributeOID = "1.3.6.1.4.1.4203.1.12.2.4.12.4"

var ErrTooLarge = errors.New("entry size limit exceeded")

type ConfigError struct {
	Code uint16
	Text string
}

func (e *ConfigError) Error() string { return Attribute + ": " + e.Text }

func IsAttribute(name string) bool {
	base, _, _ := strings.Cut(name, ";")
	return strings.EqualFold(base, Attribute) || base == AttributeOID
}

// ParseValue applies LDAP Integer syntax before config.c's unsigned conversion.
func ParseValue(value string) (uint64, error) {
	digits := value
	if strings.HasPrefix(digits, "-") {
		digits = digits[1:]
	}
	valid := len(digits) > 0 && (digits[0] != '0' || value == "0")
	for i := range len(digits) {
		valid = valid && digits[i] >= '0' && digits[i] <= '9'
	}
	if !valid {
		return 0, &ConfigError{21, "invalid Integer syntax"}
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, &ConfigError{19, "unable to parse as unsigned long"}
	}
	return n, nil
}

// ParseDirective matches lutil_atoulx(..., 0), including octal and hexadecimal.
func ParseDirective(value string) (uint64, error) {
	value = strings.TrimPrefix(value, "+")
	base, digits := 10, value
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		base, digits = 16, value[2:]
	} else if len(value) > 1 && value[0] == '0' {
		base = 8
	}
	return strconv.ParseUint(digits, base, 64)
}

// Configuration returns zero when absent. Only an MDB database may own it.
func Configuration(entry directory.Entry) (uint64, error) {
	var limit uint64
	seen := false
	for _, attr := range entry.Attributes {
		if !IsAttribute(attr.Description) {
			continue
		}
		if strings.Contains(attr.Description, ";") {
			return 0, &ConfigError{17, "attribute options are not supported"}
		}
		if seen || len(attr.Values) != 1 {
			return 0, &ConfigError{19, "must be single-valued"}
		}
		seen = true
		var err error
		limit, err = ParseValue(string(attr.Values[0]))
		if err != nil {
			return 0, err
		}
	}
	if !seen {
		return 0, nil
	}
	db := entry.Values("olcDatabase")
	dn, err := directory.ParseDN(entry.DN)
	parent, hasParent := dn.Parent()
	backend := ""
	if len(db) == 1 {
		_, backend, _ = strings.Cut(string(db[0]), "}")
		if backend == "" {
			backend = string(db[0])
		}
	}
	if err != nil || !hasParent || !strings.EqualFold(parent.String(), "cn=config") || !strings.EqualFold(backend, "mdb") {
		return 0, &ConfigError{65, "requires an MDB database configuration entry"}
	}
	return limit, nil
}

// Check counts ec.len in back-mdb/id2entry.c at d172686d3d270bc961b78f3ff00d7019c8dfb094.
// DNs, attribute names, and final alignment padding are not counted. Subtracting
// from the budget avoids overflow and rejects large raw values before normalizing.
func Check(entry directory.Entry, registry *schema.Registry, limit uint64) error {
	if limit == 0 {
		return nil
	}
	if registry == nil {
		return errors.New("entry size accounting requires a schema registry")
	}
	remaining := limit
	consume := func(n uint64) bool {
		if n > remaining {
			return false
		}
		remaining -= n
		return true
	}
	if !consume(16) {
		return ErrTooLarge
	}
	for _, attr := range entry.Attributes {
		if virtualAttribute(attr.Description) {
			continue
		}
		if !consume(8) {
			return ErrTooLarge
		}
		for _, value := range attr.Values {
			size, err := registry.MDBRawValueSize(attr.Description, value)
			if err != nil {
				return err
			}
			if !consume(size) || !consume(5) {
				return ErrTooLarge
			}
		}
	}
	for _, attr := range entry.Attributes {
		if virtualAttribute(attr.Description) || attr.RawNormalized {
			continue
		}
		for _, value := range attr.Values {
			n, separate, err := registry.MDBNormalizedValueSize(attr.Description, value)
			if err != nil {
				return fmt.Errorf("measure %s: %w", attr.Description, err)
			}
			if separate && (!consume(n) || !consume(5)) {
				return ErrTooLarge
			}
		}
	}
	return nil
}

func virtualAttribute(name string) bool {
	return strings.EqualFold(name, "subschemaSubentry") || name == "2.5.18.10" ||
		strings.EqualFold(name, "entryDN") || name == "1.3.6.1.1.20" ||
		strings.EqualFold(name, "hasSubordinates") || name == "2.5.18.9"
}
