package storage

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func requireIncrementalNamingMetadataAccounting(t *testing.T, index *boltNamingContextIndex) {
	t.Helper()
	var expected int64
	for physical, row := range index.rows {
		expected += int64(len(physical) + len(row.raw) + 512)
		_, identity := splitPartitionedEntryKey(physical)
		if row.identity != identity {
			expected += int64(len(row.identity))
		}
		if row.parent == "" {
			continue
		}
		group, exists := index.children[row.parent]
		if !exists || row.parent != group.parent {
			t.Fatalf("row %q has no parent group", physical)
		}
		if node := index.nodes[row.identity]; node == nil || node.parent != group.parent {
			t.Fatalf("row %q disagrees with its global node's parent", physical)
		}
		if _, exists := group.identities[row.identity]; !exists {
			t.Fatalf("row %q has no child reference", physical)
		}
	}
	for parent, group := range index.children {
		expected += int64(len(parent))
		if len(group.identities) == 0 {
			t.Fatalf("unreferenced parent %q was retained", parent)
		}
		for identity := range group.identities {
			node := index.nodes[identity]
			if node == nil || node.parent != parent {
				t.Fatalf("parent %q retained a dead child reference %q", parent, identity)
			}
		}
	}
	if index.bytes != expected {
		t.Fatalf("estimated bytes = %d, want %d with each shared parent charged once", index.bytes, expected)
	}
}

func TestNamingContextIncrementalSharesMetadata(t *testing.T) {
	store := newIncrementalNamingStore(t)
	normalizer := incrementalNamingNormalizer{}
	parent := "ou=" + strings.Repeat("shared", 32) + ",dc=base"
	parentKey := incrementalNamingDN(t, parent).Key()
	const count = 32
	child := func(i int) string { return fmt.Sprintf("uid=user%d,%s", i, parent) }
	var index *boltNamingContextIndex
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		putIncrementalNamingEntry(t, tx, "data", "dc=base", false)
		for i := range count {
			putIncrementalNamingEntry(t, tx, "data", child(i), false)
		}
		putIncrementalNamingEntry(t, tx, "z", strings.ToUpper(child(0)), false)
		if _, err := incrementalNamingParity(t, tx, normalizer); err != nil {
			t.Fatal(err)
		}
		index = store.namingIndex
		requireIncrementalNamingMetadataAccounting(t, index)
		if got := len(index.children[parentKey].identities); got != count {
			t.Fatalf("parent has %d references, want %d distinct child identities", got, count)
		}
	})
	for cycle := range 4 {
		updateIncrementalNamingStore(t, store, func(tx *boltTx) {
			// Replacements must retain sharing even when their freshly decoded DN
			// and physical key have different backing storage from the warm index.
			for i := range count {
				putIncrementalNamingEntry(t, tx, "data", strings.ToUpper(child(i)), true)
			}
			if _, err := incrementalNamingParity(t, tx, normalizer); err != nil {
				t.Fatal(err)
			}
			if store.namingIndex != index {
				t.Fatalf("cycle %d rebuilt the index", cycle)
			}
			requireIncrementalNamingMetadataAccounting(t, index)
		})
	}
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		putIncrementalNamingEntry(t, tx, "parent", parent, false)
		requireIncrementalNamingContexts(t, tx, normalizer, "dc=base")
		deleteIncrementalNamingEntry(t, tx, "parent", parent)
		for i := range count {
			deleteIncrementalNamingEntry(t, tx, "data", child(i))
		}
		requireIncrementalNamingContexts(t, tx, normalizer, "dc=base", strings.ToUpper(child(0)))
		requireIncrementalNamingMetadataAccounting(t, index)
		if got := len(index.children[parentKey].identities); got != 1 {
			t.Fatalf("surviving duplicate has %d parent references, want 1", got)
		}
		deleteIncrementalNamingEntry(t, tx, "z", child(0))
		requireIncrementalNamingContexts(t, tx, normalizer, "dc=base")
		if len(index.children) != 0 {
			t.Fatal("last child deletion retained interned parent keys")
		}
	})
	for cycle := range 8 {
		updateIncrementalNamingStore(t, store, func(tx *boltTx) {
			baseline := index.bytes
			raw := fmt.Sprintf("uid=leaf,ou=branch%d,%s", cycle, parent)
			putIncrementalNamingEntry(t, tx, "data", raw, false)
			requireIncrementalNamingContexts(t, tx, normalizer, "dc=base", raw)
			requireIncrementalNamingMetadataAccounting(t, index)
			deleteIncrementalNamingEntry(t, tx, "data", raw)
			requireIncrementalNamingContexts(t, tx, normalizer, "dc=base")
			if index.bytes != baseline || len(index.children) != 0 || store.namingIndex != index {
				t.Fatalf("cycle %d did not prune its interned metadata", cycle)
			}
		})
	}
}

func TestNamingContextIncrementalRetainedHeap(t *testing.T) {
	store := newIncrementalNamingStore(t)
	normalizer := incrementalNamingNormalizer{}
	const count = 256
	parent := "ou=" + strings.Repeat("p", 4096) + ",dc=base"
	updateIncrementalNamingStore(t, store, func(tx *boltTx) {
		for i := range count {
			putIncrementalNamingEntry(t, tx, "data", fmt.Sprintf("uid=user%d,%s", i, parent), false)
		}
	})
	liveHeap := func() int64 {
		// Empty both generations of temporary parser/codec pools before sampling.
		runtime.GC()
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		return int64(stats.HeapAlloc)
	}
	before := liveHeap()
	var index *boltNamingContextIndex
	if err := store.View(t.Context(), func(reader Reader) error {
		fingerprint, _ := normalizer.NamingContextCacheFingerprint()
		var err error
		index, err = reader.(*boltTx).buildNamingContextIndex(normalizer, fingerprint)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	retained := liveHeap() - before
	// Long DNs make either a per-row parent copy or a second identity copy
	// exceed this allowance for map storage, size classes and runtime noise.
	var stringsBytes int64
	for physical, row := range index.rows {
		stringsBytes += int64(len(physical) + len(row.raw))
	}
	for parent := range index.children {
		stringsBytes += int64(len(parent))
	}
	maximum := stringsBytes + count*1024 + (256 << 10)
	t.Logf("retained heap: %d bytes; shared string payload: %d; ceiling: %d", retained, stringsBytes, maximum)
	if retained > maximum {
		t.Fatalf("retained %d bytes, exceeds %d-byte shared-metadata ceiling", retained, maximum)
	}
	requireIncrementalNamingMetadataAccounting(t, index)
	for physical := range index.rows {
		index.remove(physical)
	}
	if index.bytes != 0 || len(index.rows)+len(index.nodes)+len(index.children)+len(index.roots) != 0 {
		t.Fatal("deletion retained derived metadata")
	}
	if remaining := liveHeap() - before; remaining > 512<<10 {
		t.Fatalf("empty index retained %d bytes after pruning", remaining)
	}
	runtime.KeepAlive(index)
	runtime.KeepAlive(store)
}
