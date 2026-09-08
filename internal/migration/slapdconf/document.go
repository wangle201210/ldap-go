package slapdconf

import (
	"errors"
	"fmt"
	"io"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
)

// Attribute is one ordered LDIF attribute and its values.
type Attribute struct {
	Name    string
	Values  []string
	Sources []Position
}

// Entry is a deterministic cn=config LDIF entry.
type Entry struct {
	DN         string
	Attributes []Attribute
	Position   Position
}

// Document is a converted, parent-before-child cn=config tree.
type Document struct {
	Entries []Entry
}

// WriteLDIF writes canonical RFC 2849 LDIF with OpenLDAP's 76-column folding.
func (document Document) WriteLDIF(writer io.Writer) error {
	if writer == nil {
		return errors.New("LDIF writer is required")
	}
	for _, entry := range document.Entries {
		converted := &ldap.Entry{DN: entry.DN}
		for _, attribute := range entry.Attributes {
			converted.Attributes = append(converted.Attributes, &ldap.EntryAttribute{
				Name:   attribute.Name,
				Values: append([]string(nil), attribute.Values...),
			})
		}
		if err := ldif.Dump(writer, 76, converted); err != nil {
			return fmt.Errorf("write LDIF entry %q: %w", entry.DN, err)
		}
	}
	return nil
}

type mutableEntry struct {
	position   Position
	dn         string
	attributes []Attribute
	byName     map[string]int
	ordered    map[string]int
}

func newMutableEntry(dn string, objectClasses ...string) *mutableEntry {
	entry := &mutableEntry{
		dn:      dn,
		byName:  make(map[string]int),
		ordered: make(map[string]int),
	}
	if len(objectClasses) > 0 {
		entry.attributes = append(entry.attributes, Attribute{
			Name:   "objectClass",
			Values: append([]string(nil), objectClasses...),
		})
		entry.byName["objectclass"] = 0
	}
	return entry
}

func (entry *mutableEntry) add(name, value string, ordered bool) {
	key := strings.ToLower(name)
	if ordered {
		value = fmt.Sprintf("{%d}%s", entry.ordered[key], value)
		entry.ordered[key]++
	}
	if index, exists := entry.byName[key]; exists {
		entry.attributes[index].Values = append(entry.attributes[index].Values, value)
		return
	}
	entry.byName[key] = len(entry.attributes)
	entry.attributes = append(entry.attributes, Attribute{Name: name, Values: []string{value}})
}

func (entry *mutableEntry) set(name, value string) error {
	key := strings.ToLower(name)
	if index, exists := entry.byName[key]; exists && len(entry.attributes[index].Values) > 0 {
		return fmt.Errorf("attribute %s is already configured", name)
	}
	entry.add(name, value, false)
	return nil
}

func (entry *mutableEntry) addObjectClass(name string) {
	key := "objectclass"
	index, exists := entry.byName[key]
	if !exists {
		entry.byName[key] = len(entry.attributes)
		entry.attributes = append(entry.attributes, Attribute{Name: "objectClass"})
		index = len(entry.attributes) - 1
	}
	for _, existing := range entry.attributes[index].Values {
		if strings.EqualFold(existing, name) {
			return
		}
	}
	entry.attributes[index].Values = append(entry.attributes[index].Values, name)
}

func (entry *mutableEntry) freeze() Entry {
	attributes := make([]Attribute, len(entry.attributes))
	for index, attribute := range entry.attributes {
		attributes[index] = Attribute{
			Name:    attribute.Name,
			Values:  append([]string(nil), attribute.Values...),
			Sources: append([]Position(nil), attribute.Sources...),
		}
	}
	return Entry{DN: entry.dn, Attributes: attributes, Position: entry.position}
}

func (entry *mutableEntry) source(name string, position Position) {
	index := entry.byName[strings.ToLower(name)]
	entry.attributes[index].Sources = append(entry.attributes[index].Sources, position)
}

func quoteArgument(value string) string {
	if value != "" && !strings.ContainsAny(value, " \t\\\"'") {
		return value
	}
	var encoded strings.Builder
	encoded.WriteByte('"')
	for _, character := range value {
		if character == '\\' || character == '"' {
			encoded.WriteByte('\\')
		}
		encoded.WriteRune(character)
	}
	encoded.WriteByte('"')
	return encoded.String()
}

func joinArguments(arguments []string) string {
	encoded := make([]string, len(arguments))
	for index, argument := range arguments {
		encoded[index] = quoteArgument(argument)
	}
	return strings.Join(encoded, " ")
}

func escapeDNValue(value string) string {
	return ldap.EscapeDN(value)
}
