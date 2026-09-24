# R7 common-operation evidence

Source: `/var/tmp/ldap-go-common-perf-20260924-r7`; baseline `ac7182c`.
The [current report](../../common-ldap-performance.md) interprets this run.
The [R6 archive](../../common-ldap-performance-20260924-r6.md) is the exact
previous report. OpenLDAP parity remains unachieved.

## Accepted evidence

- `explicit-final/` and `default-final/` contain unchanged `smoke.json`,
  `hot.json`, `distributed.json`, `groups.json`, `concurrent.tsv` and
  `validation.tsv`. Both scripts exited 0; completion logs are archived.
  All six exports match 100,002 entries, POSIX checksum 2143929969 and
  42,712,438 canonical bytes.
- `go-test.txt`, `go-vet.txt` and `openldap-differential.txt` are unchanged
  completed logs. The coordinator confirmed pure-Go tests and vet success;
  vet's empty log is expected. Native validation has 355 PASS records.
- `display-bench.txt` and `text-cache-bench.txt` preserve the completed
  component measurements. Incremental text reuse is assessed using warm
  `DNAndRender` versus warm `retainedText`, not composite uncached/cached
  assertion normalization. No general SDK speedup follows from these results.
- `common-explicit.sh.txt` and `common-default.sh.txt` retain the accepted
  30-second timeout. The only archival changes are a comment, an environment
  requirement and replacement of the literal fixture password with
  `LDAP_BENCH_PASSWORD`. Existing local fixture/native paths must be supplied
  for replay. Binaries, databases, passwords and large exports are excluded.

## Calculations

`medians.tsv` contains 72 endpoint groups. Keys match R6: run, batch, stage,
method, member count and endpoint. Medians use three `total_ms` batches;
SSHA/plaintext and 10/1,000-member groups stay separate. All samples are retained.
The helper checks errors, cleanup, repeats and completed counts, and excludes
smoke from the measured tables. Nested batches have 100 traversals and 417
timed requests. Relative performance is `openldap/current*100`; reduction is
`(1-current/before)*100`, calculated before rounding. From this directory:

```sh
python3 calculate.py.txt explicit-final default-final --output medians.tsv
```

Concurrent CLI medians exclude warmup repeat 0 and use repeats 1-3: explicit
212/208/225 ms and default 197/198/207 ms (before/current/OpenLDAP). They are
root-bound wall-clock checks, separate from non-root SDK measurements.
Explicit SSHA Bind is 7.3% slower by medians, with paired slowdowns of 0.44%,
0.26% and 12.25%; default SSHA Bind is 0.7% slower. No outlier is removed,
no uniform gain is claimed, and shared-host timing lacks causal certainty.

## Failed attempt and identity

`diagnostics/explicit-initial/` preserves the initial smoke/hot/distributed/group
JSON, server error logs and original replay recipe with its password removed.
The 10-second timeout occurred during current's direct-1000 setup after 24 adds;
group samples are empty and before/current cleanup is recorded. None of the
initial timing data is included in accepted tables. Both accepted runs used
fresh fixtures and a 30-second timeout; SDK timing boundaries were unchanged.

Executable SHA-256 supplied by the coordinator:

```text
before (ac7182c)  f65475df23fa7fa127f688dd6ee475263fdf978af437efecb9a5f009509a46e2
current           9d77bb8edafc272b239a40af57fa8ce5518ee4c758f45ab75dd50e7d15850981
```

Documentation preparation ran no tests, builds or benchmarks. No further
benchmark/recheck is planned at this checkpoint. The report retains the known
R2 operational-attribute gap and scope limits.
