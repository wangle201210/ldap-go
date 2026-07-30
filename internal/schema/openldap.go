package schema

import (
	"context"
	"fmt"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type LoadResult struct {
	AttributeTypes int
	ObjectClasses  int
}

// LoadOpenLDAPConfig loads schema descriptions from cn=config-style entries.
// Attribute types are registered before object classes regardless of entry
// order, matching slapd's schema dependency model.
func LoadOpenLDAPConfig(
	ctx context.Context,
	store storage.Store,
	registry *Registry,
) (LoadResult, error) {
	var result LoadResult
	err := store.View(ctx, func(reader storage.Reader) error {
		var err error
		result, err = LoadOpenLDAPConfigReader(reader, registry)
		return err
	})
	return result, err
}

func LoadOpenLDAPConfigReader(
	reader storage.Reader,
	registry *Registry,
) (LoadResult, error) {
	if registry == nil {
		return LoadResult{}, fmt.Errorf("schema registry is required")
	}
	configSuffix, err := directory.ParseDN("cn=config")
	if err != nil {
		return LoadResult{}, err
	}

	var attributeDescriptions []string
	var objectClassDescriptions []string
	if err := reader.ForEach(func(entry directory.Entry) error {
		entryDN, err := directory.ParseDN(entry.DN)
		if err != nil {
			return fmt.Errorf("parse configuration entry DN %q: %w", entry.DN, err)
		}
		if !configSuffix.Equal(entryDN) && !configSuffix.AncestorOf(entryDN) {
			return nil
		}
		for _, value := range entry.Values("olcAttributeTypes") {
			attributeDescriptions = append(attributeDescriptions, string(value))
		}
		for _, value := range entry.Values("olcObjectClasses") {
			objectClassDescriptions = append(objectClassDescriptions, string(value))
		}
		return nil
	}); err != nil {
		return LoadResult{}, fmt.Errorf("scan OpenLDAP schema entries: %w", err)
	}

	result := LoadResult{}
	for _, description := range attributeDescriptions {
		attribute, err := ParseAttributeType(description)
		if err != nil {
			return LoadResult{}, fmt.Errorf("parse olcAttributeTypes: %w", err)
		}
		if err := registry.UpsertAttributeType(attribute); err != nil {
			return LoadResult{}, fmt.Errorf("register olcAttributeTypes %q: %w", attribute.Name(), err)
		}
		result.AttributeTypes++
	}
	for _, description := range objectClassDescriptions {
		objectClass, err := ParseObjectClass(description)
		if err != nil {
			return LoadResult{}, fmt.Errorf("parse olcObjectClasses: %w", err)
		}
		if err := registry.UpsertObjectClass(objectClass); err != nil {
			return LoadResult{}, fmt.Errorf("register olcObjectClasses %q: %w", objectClass.Name(), err)
		}
		result.ObjectClasses++
	}
	return result, nil
}
