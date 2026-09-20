package server

import (
	"errors"

	"github.com/wangle201210/ldap-go/internal/directory"
	"github.com/wangle201210/ldap-go/internal/storage"
)

// A provider sends the renamed parent without changing descendant entryCSNs.
// Move the descendants in the same transaction as the parent and sync cookie.
func moveSyncConsumerDescendants(
	writer, content storage.Writer,
	config syncConsumerConfig,
	oldDN, newDN directory.DN,
) error {
	if oldDN.AncestorOf(newDN) {
		return errors.New("replicated subtree cannot move beneath itself")
	}
	type move struct {
		oldDN directory.DN
		entry directory.Entry
	}
	var moves []move
	if err := content.ForEach(func(entry directory.Entry) error {
		candidate, err := syncConsumerParseDN(content, entry.DN)
		if err != nil {
			return err
		}
		if !oldDN.AncestorOf(candidate) {
			return nil
		}
		destination, err := candidate.ReplaceAncestor(oldDN, newDN)
		if err != nil {
			return err
		}
		if _, err := content.Get(destination); err == nil {
			return storage.ErrEntryExists
		} else if !errors.Is(err, storage.ErrEntryNotFound) {
			return err
		}
		entry.DN = destination.String()
		moves = append(moves, move{oldDN: candidate, entry: entry})
		return nil
	}); err != nil {
		return err
	}
	for _, item := range moves {
		if err := content.Delete(item.oldDN); err != nil {
			return err
		}
	}
	for _, item := range moves {
		if err := putRenamedSyncConsumerEntry(writer, content, config, item.entry, false); err != nil {
			return err
		}
	}
	return nil
}
