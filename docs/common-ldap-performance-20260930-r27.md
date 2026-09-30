# R27: monitor completion and equality posting cleanup

R27 is a small production optimization on top of the R22 server. It combines
the adjacent monitor connection-state and operation-completion updates into one
lock and one timestamp, while preserving counters, current addresses,
authorization DN and audit publication order. It also skips a redundant
`sort.Strings` for Bolt equality postings; Bolt's cursor already returns the
posting suffixes in byte order. Other index implementations retain their sort.

The changes are committed in `eb38dc6` and `6aa5ab7`, on top of main `70e018d`.
The full Go test suite, vet and 355 OpenLDAP differential checks passed on the
monitor candidate; the combined main checkout passed the full Go test suite,
vet and the same differential matrix again.

## Same-process network diagnostic

Three 1-second repeats compare the shipped R22 server binary with the monitor
candidate using the existing 100k fixture. This is a component diagnostic,
not the formal seven-batch OpenLDAP qualification. Medians were:

| Operation | Before ns/op | Candidate ns/op | Change |
| --- | ---: | ---: | ---: |
| Non-root Base | 83,524 | 84,915 | +1.7% |
| Non-root equality | 94,887 | 91,072 | -4.0% |

The host is variable and the Base result is slightly slower, so these numbers
do not establish a universal speedup. The monitor change is retained because
it removes duplicated synchronization and timestamp work without changing the
operation contract; the posting change is limited to the ordering guarantee
already provided by the Bolt cursor.

The existing R22/R23/R26 tables remain the authoritative multi-endpoint
comparisons. Common-operation parity remains unmet.
