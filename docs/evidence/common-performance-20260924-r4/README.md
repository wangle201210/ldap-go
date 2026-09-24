# R4 common-operation evidence

Source root: `/var/tmp/ldap-go-common-perf-20260924-r4`.
Baseline: `aaf8350`. Final current executable: `current-sized`.
The [archived R4 report](../../common-ldap-performance-20260924-r4.md) contains interpretation and limits.

## Accepted measurements

- `explicit-sized/` and `default-sized/` contain unchanged copies of `hot.json`,
  `distributed.json`, `groups.json`, `smoke.json`, `concurrent.tsv` and
  `validation.tsv` from the identically named source directories.
- `common-explicit-sized.sh.txt` and `common-default-sized.sh.txt` are byte-for-byte
  copies of the replay scripts; `.txt` was appended to the filenames only.
  The corresponding `.log.txt` files retain terminal completion messages.
- `go-test-sized.txt`, `go-vet-sized.txt` and `openldap-differential-sized.txt`
  are final validation logs. The coordinating run confirmed all three exit 0.
  Vet produced no output. Native validation records 355 PASS lines including
  subtests, zero skips, and terminal PASS. The Go server package reports 136.749s.
- Both smoke runs and all measured runs report no error and cleanup for all
  three endpoints. All six accepted ordinary-attribute exports have 100,002
  entries, checksum `2143929969` and 42,712,438 canonical bytes.

## Calculations

`medians.tsv` groups samples by source run, batch, stage, method, member count
and endpoint. Each measured group has exactly repeats 1, 2 and 3, with
`completed == operations`; its median is the middle sorted `total_ms` value.
The two `groupBase` member counts are separate rows. Bind plaintext and SSHA
methods are separate rows. Smoke samples are excluded from timing summaries.

For each row, relative performance is `openldap_ms / current_ms * 100` and time
reduction is `(1 - current_ms / before_ms) * 100`. Calculations use unrounded
medians; reports display milliseconds to two decimals and percentages to one.
The TSV retains nine decimals. Nested membership counts 100 traversals and
417 actual SDK searches per measured batch.

Concurrent medians use only repeats 1, 2 and 3; repeat 0 is warmup. Default
before/current/native medians are 188/187/208 ms, giving 111.2% relative performance
and 0.5% time reduction. Explicit medians are 190/186/208 ms, giving 111.8% and
2.1%. The explicit native 330 ms sample is retained, not discarded.

## Initial attempt

`diagnostics/explicit-final/` preserves all six raw files from the initial
explicit-ACL R4 run. Its entries in `medians.tsv` are diagnostic only and are
not accepted final current measurements. Both initial `common-*-final.sh`
scripts are copied under `diagnostics/` with `.txt` appended; the available
explicit completion log is preserved there too.

The initial shortcut required `request.SizeLimit == 0`, but the unchanged SDK
uses `len(want)+1` (2 for ordinary Base/UID reads) and `len(groups)+1` (6 for
nested discovery). Every measured search therefore fell back. The final
implementation supports positive limits with the general handler's projection,
partial-size-result and memory-error ordering. The explicit replay script diff
changes only output-directory and current-executable paths.

The supplied source tree contained no `default-final/` directory or initial
default-ACL raw results. Only its replay script is archived; no data were
fabricated or copied from another run to fill that gap.

## Executable identity

SHA-256 verified against the supplied executable files:

```text
before         c73d07d1e70afc60030999f9fe001b1b420cfd88dc9fa92dcb4e4dd6a8fec258
current-sized  bf22f861ebe6a5e2eebfaea08bf11ed42f3acee4c9cf997760d3747786e322c4
```

The parity goal remains open. The existing operational-attribute gap is retained
in the report with its R2 reference. These artifacts do not establish non-root
concurrent throughput, TLS performance or full OpenLDAP compatibility.
