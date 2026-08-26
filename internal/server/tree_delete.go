package server

import (
	"sort"

	"github.com/wangle201210/ldap-go/internal/acl"
	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/ldapwire"
	"github.com/wangle201210/ldap-go/internal/storage"
)

type treeDeletePreflighter interface {
	treeDeletePreflight(directory.DN) error
}

type treeDeleteEntry struct {
	entry directory.Entry
	dn    directory.DN
}

func (server *Server) prepareSQLTreeDelete(
	runtime *runtimeState,
	tx storage.Writer,
	boundDN string,
	base directory.DN,
	collectivePlan *collectiveAttributePlan,
) ([]directory.Entry, error) {
	comparisonBase, err := storage.NormalizeReaderDN(tx, base)
	if err != nil {
		return nil, err
	}
	preflight, ok := tx.(treeDeletePreflighter)
	if !ok {
		return nil, operationFailed(
			ldapwire.ResultUnwillingToPerform,
			"subtree delete not possible",
		)
	}
	items := make([]treeDeleteEntry, 0)
	err = tx.ForEach(func(entry directory.Entry) error {
		candidate, err := directory.ParseDN(entry.DN)
		if err != nil {
			return err
		}
		candidate, err = storage.NormalizeReaderDN(tx, candidate)
		if err != nil {
			return err
		}
		if !candidate.Equal(comparisonBase) && !comparisonBase.AncestorOf(candidate) {
			return nil
		}
		logicalEntry, err := collectivePlan.apply(entry)
		if err != nil {
			return err
		}
		if !server.allowed(
			runtime,
			tx,
			boundDN,
			logicalEntry,
			"entry",
			nil,
			acl.WriteDelete,
		) || !server.allowed(
			runtime,
			tx,
			boundDN,
			logicalEntry,
			"children",
			nil,
			acl.WriteDelete,
		) {
			return operationFailed(ldapwire.ResultInsufficientAccessRights, "")
		}
		if err := preflight.treeDeletePreflight(candidate); err != nil {
			return err
		}
		items = append(items, treeDeleteEntry{entry: entry, dn: candidate})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(left, right int) bool {
		if items[left].dn.Depth() != items[right].dn.Depth() {
			return items[left].dn.Depth() > items[right].dn.Depth()
		}
		return items[left].dn.NormalizedString() > items[right].dn.NormalizedString()
	})
	entries := make([]directory.Entry, len(items))
	for index := range items {
		entries[index] = items[index].entry
	}
	return entries, nil
}
