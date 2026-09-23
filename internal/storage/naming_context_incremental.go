package storage

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/wangle201210/ldap-go/internal/directory"
)

// Opt-in providers are immutable, deterministic schema snapshots for their
// entire lifetime. The fingerprint covers normalization and canonical-name rules.
type namingContextCacheNormalizer interface {
	directory.DNAttributeNormalizer
	NamingContextCacheFingerprint() ([sha256.Size]byte, bool)
}

const maxNamingContextIndexBytes = 256 << 20

var errNamingContextIndexCapacity = errors.New("naming context index capacity exceeded")

type namingContextIndexRow struct {
	identity string
	parent   string
	raw      string
}

type namingContextIndexNode struct {
	parent string
	winner string
	owners map[string]struct{} // Allocated only for duplicate global identities.
}

// Access is restricted to managed write transactions under Bolt.updateMu.
// Rows contain owned DN metadata, never attributes or mmap-backed slices.
type boltNamingContextIndex struct {
	revision    uint64
	fingerprint [sha256.Size]byte
	normalizer  directory.DNAttributeNormalizer
	configDN    directory.DN
	rows        map[string]namingContextIndexRow
	nodes       map[string]*namingContextIndexNode
	children    map[string]map[string]struct{}
	roots       map[string]string
	bytes       int64
}

// InferNamingContextsIncremental reuses validated DN metadata only for tracked
// Bolt write transactions and explicitly immutable normalizers. Other readers
// retain the ordered metadata scan. This does not update NamingContexts itself.
func InferNamingContextsIncremental(reader Reader, normalizer directory.DNAttributeNormalizer) ([]string, error) {
	tx, ok := reader.(*boltTx)
	provider, trusted := normalizer.(namingContextCacheNormalizer)
	if !ok || tx.namingStore == nil || !trusted {
		return InferNamingContextsMetadataWithNormalizer(reader, normalizer)
	}
	fingerprint, immutable := provider.NamingContextCacheFingerprint()
	if !immutable {
		return InferNamingContextsMetadataWithNormalizer(reader, normalizer)
	}
	index := tx.namingStore.namingIndex
	if index != nil && index.fingerprint != fingerprint {
		tx.invalidateNamingContextIndex()
		index = nil
	}
	var err error
	if index == nil {
		index, err = tx.buildNamingContextIndex(normalizer, fingerprint)
		if err == nil {
			tx.namingStore.namingIndex = index
			tx.namingIndexChanged = true
			clear(tx.namingDirty)
		}
	} else {
		err = tx.syncNamingContextIndex()
		if err == nil && len(index.rows) != 0 {
			err = tx.ctx.Err()
		}
	}
	if err != nil {
		tx.invalidateNamingContextIndex()
		if errors.Is(err, errNamingContextIndexCapacity) {
			return InferNamingContextsMetadataWithNormalizer(reader, normalizer)
		}
		return nil, fmt.Errorf("scan directory entries: %w", err)
	}
	keys := slices.Sorted(maps.Keys(index.roots))
	contexts := make([]string, len(keys))
	for i, key := range keys {
		contexts[i] = index.roots[key]
	}
	return contexts, nil
}

func (tx *boltTx) buildNamingContextIndex(normalizer directory.DNAttributeNormalizer, fingerprint [sha256.Size]byte) (*boltNamingContextIndex, error) {
	configDN, err := directory.ParseDN("cn=config")
	if err != nil {
		return nil, err
	}
	index := &boltNamingContextIndex{
		fingerprint: fingerprint, normalizer: normalizer, configDN: configDN,
		rows: make(map[string]namingContextIndexRow), nodes: make(map[string]*namingContextIndexNode),
		children: make(map[string]map[string]struct{}), roots: make(map[string]string),
	}
	err = tx.entries.ForEach(func(key, value []byte) error {
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		physical := string(key)
		row, err := index.decodeRow(physical, value)
		if err != nil {
			return err
		}
		return index.put(physical, row)
	})
	return index, err
}

func (index *boltNamingContextIndex) decodeRow(physical string, value []byte) (namingContextIndexRow, error) {
	partition, identity := splitPartitionedEntryKey(physical)
	entry, dn, err := decodeNamingContextMetadataDN(identity, value)
	if err != nil {
		return namingContextIndexRow{}, err
	}
	if partition != OpenLDAPConfigPartition && !index.configDN.Equal(dn) && !index.configDN.AncestorOf(dn) {
		dn, err = dn.NormalizeWith(index.normalizer)
		if err != nil {
			return namingContextIndexRow{}, err
		}
	}
	row := namingContextIndexRow{raw: entry.DN}
	if dn.Depth() != 0 {
		row.identity = dn.Key()
		if dn.Depth() > 1 {
			row.parent, _ = dn.ParentKey()
		}
	}
	return row, nil
}

func namingContextRowBytes(physical string, row namingContextIndexRow) int64 {
	return int64(len(physical)) + int64(len(row.identity)) + int64(len(row.parent)) + int64(len(row.raw)) + 512
}

func (index *boltNamingContextIndex) put(physical string, row namingContextIndexRow) error {
	if previous, exists := index.rows[physical]; exists {
		if previous.identity == row.identity {
			index.bytes += namingContextRowBytes(physical, row) - namingContextRowBytes(physical, previous)
			index.rows[physical] = row
			index.refreshRoot(row.identity)
			return index.checkCapacity()
		}
		index.remove(physical)
	}
	index.rows[physical] = row
	index.bytes += namingContextRowBytes(physical, row)
	if row.identity == "" {
		return index.checkCapacity()
	}
	node := index.nodes[row.identity]
	if node == nil {
		node = &namingContextIndexNode{parent: row.parent, winner: physical}
		index.nodes[row.identity] = node
		if row.parent != "" {
			if index.children[row.parent] == nil {
				index.children[row.parent] = make(map[string]struct{})
			}
			index.children[row.parent][row.identity] = struct{}{}
		}
		for child := range maps.Keys(index.children[row.identity]) {
			index.refreshRoot(child)
		}
	} else {
		if node.owners == nil {
			node.owners = map[string]struct{}{node.winner: {}}
		}
		node.owners[physical] = struct{}{}
		if physical > node.winner {
			node.winner = physical
		}
	}
	index.refreshRoot(row.identity)
	return index.checkCapacity()
}

func (index *boltNamingContextIndex) remove(physical string) {
	row, exists := index.rows[physical]
	if !exists {
		return
	}
	delete(index.rows, physical)
	index.bytes -= namingContextRowBytes(physical, row)
	if row.identity == "" {
		return
	}
	node := index.nodes[row.identity]
	if node.owners != nil {
		delete(node.owners, physical)
		if physical == node.winner {
			node.winner = ""
			for owner := range maps.Keys(node.owners) {
				if owner > node.winner {
					node.winner = owner
				}
			}
		}
		if len(node.owners) == 1 {
			node.owners = nil
		}
		index.refreshRoot(row.identity)
		return
	}
	delete(index.nodes, row.identity)
	delete(index.roots, row.identity)
	if siblings := index.children[row.parent]; siblings != nil {
		delete(siblings, row.identity)
		if len(siblings) == 0 {
			delete(index.children, row.parent)
		}
	}
	for child := range maps.Keys(index.children[row.identity]) {
		index.refreshRoot(child)
	}
}

func (index *boltNamingContextIndex) refreshRoot(identity string) {
	node := index.nodes[identity]
	if node == nil {
		return
	}
	if node.parent == "" || index.nodes[node.parent] == nil {
		index.roots[identity] = index.rows[node.winner].raw
	} else {
		delete(index.roots, identity)
	}
}

func (index *boltNamingContextIndex) checkCapacity() error {
	if index.bytes > maxNamingContextIndexBytes {
		return errNamingContextIndexCapacity
	}
	return nil
}

func (tx *boltTx) trackNamingContextMutation(key []byte) {
	if tx.namingStore == nil || tx.namingStore.namingIndex == nil {
		return
	}
	if tx.namingDirty == nil {
		tx.namingDirty = make(map[string]struct{})
	}
	tx.namingDirty[string(key)] = struct{}{}
}

func (tx *boltTx) invalidateNamingContextIndex() {
	if tx.namingStore != nil {
		tx.namingStore.namingIndex = nil
	}
	clear(tx.namingDirty)
}

func (tx *boltTx) syncNamingContextIndex() error {
	index := tx.namingStore.namingIndex
	for _, physical := range slices.Sorted(maps.Keys(tx.namingDirty)) {
		value := tx.entries.Get([]byte(physical))
		if value == nil {
			// A present zero-length value must still reach the decoder. Get
			// alone cannot distinguish it from a removed entry.
			key, raw := tx.entries.Cursor().Seek([]byte(physical))
			if !bytes.Equal(key, []byte(physical)) {
				tx.namingIndexChanged = true
				index.remove(physical)
				continue
			}
			value = raw
		}
		if err := tx.ctx.Err(); err != nil {
			return err
		}
		tx.namingIndexChanged = true
		row, err := index.decodeRow(physical, value)
		if err != nil {
			return err
		}
		if err := index.put(physical, row); err != nil {
			return err
		}
	}
	clear(tx.namingDirty)
	return nil
}

func (tx *boltTx) finishNamingContextIndex() {
	if tx.namingStore == nil || tx.namingStore.namingIndex == nil || len(tx.namingDirty) == 0 {
		return
	}
	// Writes that do not request inference retain their original error timing.
	// An invalid derived update drops the cache; the next inference scans again.
	if err := tx.syncNamingContextIndex(); err != nil {
		tx.invalidateNamingContextIndex()
	}
}
