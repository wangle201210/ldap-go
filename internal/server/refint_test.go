package server

import (
	"strings"
	"testing"

	"github.com/wangle201210/ldap-go/internal/directory"
)

func TestLoadRefintRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	entry := refintOverlayEntry(
		"{2}",
		[]string{"member managerRef", "memberA"},
		"cn=placeholder,dc=example,dc=com",
	)
	entry.Attributes = append(entry.Attributes, directory.Attribute{
		Description: "olcRefintModifiersName",
		Values:      stringValues("cn=repair,dc=example,dc=com"),
	})
	configuration, err := loadRefintRuntimeConfiguration(entry, memberOfTestDatabase(t))
	if err != nil {
		t.Fatalf("loadRefintRuntimeConfiguration(): %v", err)
	}
	if strings.Join(configuration.attributes, ",") != "member,managerRef,memberA" ||
		configuration.nothing == nil ||
		configuration.nothing.Key() != "cn=placeholder,dc=example,dc=com" ||
		configuration.modifierDN.Key() != "cn=repair,dc=example,dc=com" {
		t.Fatalf("configuration = %#v", configuration)
	}
}

func TestLoadRefintRuntimeConfigurationRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	for name, attribute := range map[string]directory.Attribute{
		"empty attribute": {
			Description: "olcRefintAttribute",
			Values:      stringValues(" "),
		},
		"multiple nothing": {
			Description: "olcRefintNothing",
			Values: stringValues(
				"cn=one,dc=example,dc=com",
				"cn=two,dc=example,dc=com",
			),
		},
		"invalid nothing": {
			Description: "olcRefintNothing",
			Values:      stringValues("not a DN"),
		},
		"invalid modifier": {
			Description: "olcRefintModifiersName",
			Values:      stringValues("not a DN"),
		},
	} {
		attribute := attribute
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			entry := directory.Entry{
				DN:         "olcOverlay=refint,olcDatabase={1}mdb,cn=config",
				Attributes: []directory.Attribute{attribute},
			}
			if _, err := loadRefintRuntimeConfiguration(
				entry,
				memberOfTestDatabase(t),
			); err == nil {
				t.Fatal("invalid refint configuration was accepted")
			}
		})
	}
}

func TestRefintMutateAttributeSubtreeAndNothing(t *testing.T) {
	t.Parallel()

	registry := memberOfTestRegistry(t)
	oldDN, _ := directory.ParseDN("ou=old,dc=example,dc=com")
	newDN, _ := directory.ParseDN("ou=new,dc=example,dc=com")
	nothing, _ := directory.ParseDN("cn=nothing,dc=example,dc=com")
	entry := directory.Entry{
		DN: "uid=holder,ou=people,dc=example,dc=com",
		Attributes: []directory.Attribute{{
			Description: "managerRef",
			Values: stringValues(
				"uid=one,ou=old,dc=example,dc=com",
				"uid=outside,dc=example,dc=com",
			),
		}},
	}
	if !refintMutateAttribute(
		registry,
		&entry,
		"managerRef",
		oldDN,
		&newDN,
		true,
		&nothing,
	) {
		t.Fatal("subtree rename reported no change")
	}
	want, _ := directory.ParseDN("uid=one,ou=new,dc=example,dc=com")
	if !containsDNValue(entry.Values("managerRef"), want) {
		t.Fatalf("renamed values = %q", entry.Values("managerRef"))
	}

	entry.ReplaceValues("managerRef", stringValues(oldDN.String()))
	if !refintMutateAttribute(
		registry,
		&entry,
		"managerRef",
		oldDN,
		nil,
		false,
		&nothing,
	) || !containsDNValue(entry.Values("managerRef"), nothing) {
		t.Fatalf("delete placeholder values = %q", entry.Values("managerRef"))
	}
}

func refintOverlayEntry(
	order string,
	attributes []string,
	nothing string,
) directory.Entry {
	entry := directory.Entry{
		DN: "olcOverlay=" + order + "refint,olcDatabase={1}mdb,cn=config",
		Attributes: []directory.Attribute{
			{Description: "objectClass", Values: stringValues("olcOverlayConfig", "olcRefintConfig")},
			{Description: "olcOverlay", Values: stringValues(order + "refint")},
		},
	}
	if len(attributes) > 0 {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "olcRefintAttribute",
			Values:      stringValues(attributes...),
		})
	}
	if nothing != "" {
		entry.Attributes = append(entry.Attributes, directory.Attribute{
			Description: "olcRefintNothing",
			Values:      stringValues(nothing),
		})
	}
	return entry
}
