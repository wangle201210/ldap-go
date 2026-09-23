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

// Published runtime schemas opt into DN parsing reuse; ACL decisions and entry
// reads remain live. Embedding preserves the registry's other normalization APIs.
type aclDNNormalizer struct {
	*schema.Registry
}

func (normalizer aclDNNormalizer) ParseDNIdentity(value string) (directory.DN, error) {
	return normalizer.NormalizeDNCached(value)
}
