package server

import (
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/schema"
)

func (normalizer *databaseEqualityIndexNormalizer) ParseDNIdentity(value string) (directory.DN, error) {
	if registry, ok := normalizer.registry.(*schema.Registry); ok && registry != nil {
		return registry.NormalizeDNCached(value)
	}
	return directory.ParseDNWithNormalizer(value, normalizer)
}
