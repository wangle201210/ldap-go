package server

const pagedSnapshotChunkSize = 4096

// Small snapshots retain normal slice growth. Large snapshots accumulate fixed
// chunks and compact once, avoiding repeated copies of every preceding item.
type pagedSnapshotBuilder struct {
	items  []pagedSortedItem
	chunks [][]pagedSortedItem
	count  int
}

func (builder *pagedSnapshotBuilder) append(item pagedSortedItem) {
	if len(builder.items) == cap(builder.items) && cap(builder.items) >= pagedSnapshotChunkSize {
		builder.chunks = append(builder.chunks, builder.items)
		builder.items = make([]pagedSortedItem, 0, pagedSnapshotChunkSize)
	}
	builder.items = append(builder.items, item)
	builder.count++
}

func (builder *pagedSnapshotBuilder) last() *pagedSortedItem {
	return &builder.items[len(builder.items)-1]
}

func (builder *pagedSnapshotBuilder) finish() []pagedSortedItem {
	items := builder.items
	if len(builder.chunks) != 0 {
		items = make([]pagedSortedItem, builder.count)
		offset := 0
		for _, chunk := range builder.chunks {
			offset += copy(items[offset:], chunk)
		}
		copy(items[offset:], builder.items)
	}
	*builder = pagedSnapshotBuilder{}
	return items
}
