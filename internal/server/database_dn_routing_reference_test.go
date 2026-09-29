package server

import "github.com/wangle201210/ldap-go/internal/directory"

// Retain the 059e82d call boundaries as well as its logic for direct old/new
// benchmarks. In particular, do not forward these through the new helpers.
func routingBeforeNormalize(database runtimeDatabase, dn directory.DN) (directory.DN, error) {
	return parseRuntimeDN(dn.String(), database.dnNormalizer)
}

func routingBeforeEqual(database runtimeDatabase, left, right directory.DN) bool {
	if database.dnNormalizer == nil {
		if equal, _, ok := left.SimpleLegacyDisplayRelation(right); ok {
			return equal
		}
	}
	left, err := routingBeforeNormalize(database, left)
	if err != nil {
		return false
	}
	right, err = routingBeforeNormalize(database, right)
	return err == nil && left.Equal(right)
}

func routingBeforeAtOrBelow(database runtimeDatabase, dn, base directory.DN) bool {
	if database.dnNormalizer == nil {
		if equal, ancestor, ok := base.SimpleLegacyDisplayRelation(dn); ok {
			return equal || ancestor
		}
	}
	dn, err := routingBeforeNormalize(database, dn)
	if err != nil {
		return false
	}
	base, err = routingBeforeNormalize(database, base)
	return err == nil && (base.Equal(dn) || base.AncestorOf(dn))
}

func routingBeforeStrictlyBelow(database runtimeDatabase, dn, base directory.DN) bool {
	if database.dnNormalizer == nil {
		if _, ancestor, ok := base.SimpleLegacyDisplayRelation(dn); ok {
			return ancestor
		}
	}
	dn, err := routingBeforeNormalize(database, dn)
	if err != nil {
		return false
	}
	base, err = routingBeforeNormalize(database, base)
	return err == nil && base.AncestorOf(dn)
}

func routingBeforeIndexForDN(databases []runtimeDatabase, dn directory.DN) int {
	bestIndex := -1
	bestDepth := -1
	for index := range databases {
		if databases[index].hidden || databases[index].disabled {
			continue
		}
		for _, suffix := range databases[index].suffixes {
			if !routingBeforeAtOrBelow(databases[index], dn, suffix) {
				continue
			}
			if suffix.Depth() > bestDepth {
				bestIndex = index
				bestDepth = suffix.Depth()
			}
		}
	}
	return bestIndex
}
