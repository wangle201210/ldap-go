package server

import (
	"errors"
	"fmt"
	"strings"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type refintRuntimeConfiguration struct {
	attributes []string
	nothing    *directory.DN
	modifierDN directory.DN
}

func loadRefintRuntimeConfiguration(
	entry directory.Entry,
	database runtimeDatabase,
) (refintRuntimeConfiguration, error) {
	if databaseType(database.name) == "frontend" {
		return refintRuntimeConfiguration{}, fmt.Errorf(
			"%s refint overlay cannot be global",
			entry.DN,
		)
	}
	if len(database.suffixes) == 0 {
		return refintRuntimeConfiguration{}, fmt.Errorf(
			"%s refint overlay requires a database suffix",
			entry.DN,
		)
	}
	modifierDN, err := directory.ParseDN("cn=Referential Integrity Overlay")
	if err != nil {
		return refintRuntimeConfiguration{}, err
	}
	configuration := refintRuntimeConfiguration{modifierDN: modifierDN}
	for _, raw := range entry.Values("olcRefintAttribute") {
		attributes, parseErr := tokenizeOpenLDAPConfig(string(raw))
		if parseErr != nil {
			return refintRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRefintAttribute: %w",
				entry.DN,
				parseErr,
			)
		}
		if len(attributes) == 0 {
			return refintRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRefintAttribute must not be empty",
				entry.DN,
			)
		}
		configuration.attributes = append(configuration.attributes, attributes...)
	}

	nothingValues := entry.Values("olcRefintNothing")
	if len(nothingValues) > 1 {
		return refintRuntimeConfiguration{}, fmt.Errorf(
			"%s olcRefintNothing must be single-valued",
			entry.DN,
		)
	}
	if len(nothingValues) == 1 {
		nothing, parseErr := directory.ParseDN(string(nothingValues[0]))
		if parseErr != nil {
			return refintRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRefintNothing: %w",
				entry.DN,
				parseErr,
			)
		}
		configuration.nothing = &nothing
	}

	modifierValues := entry.Values("olcRefintModifiersName")
	if len(modifierValues) > 1 {
		return refintRuntimeConfiguration{}, fmt.Errorf(
			"%s olcRefintModifiersName must be single-valued",
			entry.DN,
		)
	}
	if len(modifierValues) == 1 {
		modifier, parseErr := directory.ParseDN(string(modifierValues[0]))
		if parseErr != nil {
			return refintRuntimeConfiguration{}, fmt.Errorf(
				"%s olcRefintModifiersName: %w",
				entry.DN,
				parseErr,
			)
		}
		configuration.modifierDN = modifier
	}
	return configuration, nil
}

func validateRefintSchema(
	registry *schema.Registry,
	configurations []refintRuntimeConfiguration,
) error {
	for _, configuration := range configurations {
		for _, attribute := range configuration.attributes {
			if strings.TrimSpace(attribute) == "" {
				return fmt.Errorf("empty refint attribute type")
			}
			if _, found := registry.AttributeType(attribute); !found {
				return fmt.Errorf("undefined attribute type %q", attribute)
			}
		}
	}
	return nil
}

func applyRefintDelete(
	runtime *runtimeState,
	writer storage.Writer,
	database runtimeDatabase,
	oldDN directory.DN,
) error {
	return applyRefintChange(runtime, writer, database, oldDN, nil, false)
}

func applyRefintModifyDN(
	runtime *runtimeState,
	writer storage.Writer,
	database runtimeDatabase,
	oldDN,
	newDN directory.DN,
	subtree bool,
) error {
	return applyRefintChange(runtime, writer, database, oldDN, &newDN, subtree)
}

func applyRefintChange(
	runtime *runtimeState,
	writer storage.Writer,
	database runtimeDatabase,
	oldDN directory.DN,
	newDN *directory.DN,
	subtree bool,
) error {
	if len(database.refint) == 0 {
		return nil
	}
	base, err := runtime.schema.NormalizeDN(database.suffixes[0].String())
	if err != nil {
		return err
	}
	oldDN, err = runtime.schema.NormalizeDN(oldDN.String())
	if err != nil {
		return err
	}
	if newDN != nil {
		normalized, normalizeErr := runtime.schema.NormalizeDN(newDN.String())
		if normalizeErr != nil {
			return normalizeErr
		}
		newDN = &normalized
	}
	for _, configuration := range database.refint {
		if len(configuration.attributes) == 0 {
			continue
		}
		var candidates []directory.DN
		if err := writer.ForEach(func(entry directory.Entry) error {
			entryDN, err := runtime.schema.NormalizeDN(entry.DN)
			if err != nil {
				return err
			}
			if directory.InScope(base, entryDN, directory.ScopeWholeSubtree) {
				candidates = append(candidates, entryDN)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, candidateDN := range candidates {
			entry, err := writer.Get(candidateDN)
			if errors.Is(err, storage.ErrEntryNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			changed := false
			for _, attribute := range configuration.attributes {
				if refintMutateAttribute(
					runtime.schema,
					&entry,
					attribute,
					oldDN,
					newDN,
					subtree,
					configuration.nothing,
				) {
					changed = true
				}
			}
			if !changed {
				continue
			}
			if database.lastMod {
				entry.ReplaceValues(
					"modifiersName",
					stringValues(configuration.modifierDN.String()),
				)
			}
			if err := runtime.schema.ValidateEntry(entry); err != nil {
				continue
			}
			if err := writer.Put(entry, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func refintMutateAttribute(
	registry *schema.Registry,
	entry *directory.Entry,
	description string,
	oldDN directory.DN,
	newDN *directory.DN,
	subtree bool,
	nothing *directory.DN,
) bool {
	var err error
	oldDN, err = registry.NormalizeDN(oldDN.String())
	if err != nil {
		return false
	}
	if newDN != nil {
		normalized, normalizeErr := registry.NormalizeDN(newDN.String())
		if normalizeErr != nil {
			return false
		}
		newDN = &normalized
	}
	if nothing != nil {
		normalized, normalizeErr := registry.NormalizeDN(nothing.String())
		if normalizeErr != nil {
			return false
		}
		nothing = &normalized
	}
	changed := false
	attributes := entry.Attributes[:0]
	for _, attribute := range entry.Attributes {
		if !registry.AttributeDescriptionSubtype(attribute.Description, description) {
			attributes = append(attributes, attribute)
			continue
		}
		attributeChanged := false
		values := make([][]byte, 0, len(attribute.Values))
		for _, value := range attribute.Values {
			candidate, err := registry.NormalizeDN(string(value))
			matches := err == nil && (candidate.Equal(oldDN) ||
				(subtree && oldDN.AncestorOf(candidate)))
			if !matches {
				if err == nil && containsDNValue(values, candidate, registry) {
					continue
				}
				values = append(values, value)
				continue
			}
			changed = true
			attributeChanged = true
			if newDN == nil {
				continue
			}
			replacement, err := candidate.ReplaceAncestor(oldDN, *newDN)
			if err != nil {
				values = append(values, value)
				continue
			}
			if !containsDNValue(values, replacement, registry) {
				values = append(values, []byte(replacement.String()))
			}
		}
		if len(values) == 0 && attributeChanged && nothing != nil {
			values = append(values, []byte(nothing.String()))
		}
		attribute.Values = values
		if len(values) > 0 {
			attributes = append(attributes, attribute)
		}
	}
	entry.Attributes = attributes
	return changed
}

func containsDNValue(
	values [][]byte,
	target directory.DN,
	registries ...*schema.Registry,
) bool {
	var registry *schema.Registry
	if len(registries) > 0 {
		registry = registries[0]
	}
	if registry != nil {
		normalized, err := registry.NormalizeDN(target.String())
		if err != nil {
			return false
		}
		target = normalized
	}
	for _, value := range values {
		var candidate directory.DN
		var err error
		if registry == nil {
			candidate, err = directory.ParseDN(string(value))
		} else {
			candidate, err = registry.NormalizeDN(string(value))
		}
		if err == nil && candidate.Equal(target) {
			return true
		}
	}
	return false
}
