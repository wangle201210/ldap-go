package server

import "github.com/wangle201210/ldap-go/internal/directory"

// The by-value database wrappers capture only the normalizer before entering
// these helpers. Both operands must use that snapshot, even if a callback
// replaces the caller's database normalizer while processing the first DN.
func normalizeRuntimeDN(
	normalizer directory.DNAttributeNormalizer,
	dn directory.DN,
) (directory.DN, error) {
	return parseRuntimeDN(dn.String(), normalizer)
}

func databaseDNEqualWithNormalizer(
	normalizer directory.DNAttributeNormalizer,
	left directory.DN,
	right directory.DN,
) bool {
	if normalizer == nil {
		if equal, _, ok := left.SimpleLegacyDisplayRelation(right); ok {
			return equal
		}
	}
	left, err := normalizeRuntimeDN(normalizer, left)
	if err != nil {
		return false
	}
	right, err = normalizeRuntimeDN(normalizer, right)
	return err == nil && left.Equal(right)
}

func databaseDNAtOrBelowWithNormalizer(
	normalizer directory.DNAttributeNormalizer,
	dn directory.DN,
	base directory.DN,
) bool {
	if normalizer == nil {
		if equal, ancestor, ok := base.SimpleLegacyDisplayRelation(dn); ok {
			return equal || ancestor
		}
	}
	dn, err := normalizeRuntimeDN(normalizer, dn)
	if err != nil {
		return false
	}
	base, err = normalizeRuntimeDN(normalizer, base)
	return err == nil && (base.Equal(dn) || base.AncestorOf(dn))
}

func databaseDNStrictlyBelowWithNormalizer(
	normalizer directory.DNAttributeNormalizer,
	dn directory.DN,
	base directory.DN,
) bool {
	if normalizer == nil {
		if _, ancestor, ok := base.SimpleLegacyDisplayRelation(dn); ok {
			return ancestor
		}
	}
	dn, err := normalizeRuntimeDN(normalizer, dn)
	if err != nil {
		return false
	}
	base, err = normalizeRuntimeDN(normalizer, base)
	return err == nil && base.AncestorOf(dn)
}
