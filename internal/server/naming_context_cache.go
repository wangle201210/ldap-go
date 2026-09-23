package server

import (
	"crypto/sha256"

	"github.com/wangle201210/ldap-go/internal/schema"
)

// Runtime schemas are immutable operation snapshots. Unknown storage callers
// and custom normalizers do not opt into incremental naming-context inference.
type runtimeNamingContextNormalizer struct {
	*schema.Registry
}

func (normalizer runtimeNamingContextNormalizer) NamingContextCacheFingerprint() ([sha256.Size]byte, bool) {
	if normalizer.Registry == nil {
		return [sha256.Size]byte{}, false
	}
	return normalizer.Registry.DNIdentityFingerprint(), true
}
