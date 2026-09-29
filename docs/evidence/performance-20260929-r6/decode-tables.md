# R6 Search decode component

Five repetitions per case: before uses 1s benchtime, current uses 500ms.
The unequal sample durations and shared host limit causal claims.
`Long` is the existing affected fixture with a real before/current comparison.
Equality and Presence are already-fast short controls; their slower medians remain visible.
`GroupBase` and `MemberEquality` were added after the before benchmark was compiled.
Their reference is current PacketReference, not the before executable.
The unanchored before selection also ran Bind/Compare PacketReference cases; all remain
in the raw log and TSVs. The current selection is anchored. Unmatched cases are not paired.

| Fixture | Comparison | Unit | Reference | Current | Reduction |
| --- | --- | --- | ---: | ---: | ---: |
| Equality | before/current; already-fast control | ns/op | 271.9 | 283.3 | -4.2% |
| Equality | before/current; already-fast control | B/op | 432 | 432 | 0.0% |
| Equality | before/current; already-fast control | allocs/op | 10 | 10 | 0.0% |
| Presence | before/current; already-fast control | ns/op | 173 | 181.5 | -4.9% |
| Presence | before/current; already-fast control | B/op | 360 | 360 | 0.0% |
| Presence | before/current; already-fast control | allocs/op | 5 | 5 | 0.0% |
| Long | before/current | ns/op | 7019 | 392.4 | 94.4% |
| Long | before/current | B/op | 14968 | 968 | 93.5% |
| Long | before/current | allocs/op | 214 | 12 | 94.4% |
| GroupBase | current PacketReference/current fast decoder | ns/op | 4662 | 269.1 | 94.2% |
| GroupBase | current PacketReference/current fast decoder | B/op | 9960 | 544 | 94.5% |
| GroupBase | current PacketReference/current fast decoder | allocs/op | 145 | 9 | 93.8% |
| MemberEquality | current PacketReference/current fast decoder | ns/op | 5645 | 345.4 | 93.9% |
| MemberEquality | current PacketReference/current fast decoder | B/op | 12368 | 744 | 94.0% |
| MemberEquality | current PacketReference/current fast decoder | allocs/op | 177 | 10 | 94.4% |

Component measurements do not establish per-operation SDK parity or production performance.
