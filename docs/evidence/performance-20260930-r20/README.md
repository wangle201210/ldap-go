# R20 Request Allocation Evidence

**REJECTED / NOT_SHIPPED.** Main decision: REJECTED_NOT_SHIPPED. Reduced allocations did not establish a stable improvement in the independent CLI workload or close the native gap.

Read [overview](overview.txt), [core comparisons](comparisons.tsv), [negative core observations](negative-comparisons.tsv), [network allocation and timing](components/network/comparisons.tsv), [separate read diagnostics](diagnostics/comparisons.tsv), and [exploratory provenance](exploratory/provenance.tsv). Network results include SDK and server allocations and are kept separate from native comparisons.

Inspect [raw samples](samples.tsv), [checks](checks.tsv), [all export checks](export-checks.tsv), [diagnostic export checks](diagnostics/export-checks.tsv), [actual module metadata](binary-metadata.tsv), [source reconstruction](source/RECONSTRUCTION.txt), [source hashes](source-hashes.tsv), and [counts](summary.tsv).

The native reference was rebuilt after external fixture loss. See [recovery provenance](recovery/provenance.json), [recovery hashes](recovery/hashes.tsv), [native tool checks](recovery/native-tool-checks.tsv) and [canonical checks](recovery/checks.tsv). Wrapper and actual executable hashes are separate. No older native PASS is substituted.

R20 REQUEST ALLOCATION EVIDENCE

Evidence completeness is independent of adoption. Main decision: REJECTED_NOT_SHIPPED.
Disposition: REJECTED / NOT_SHIPPED. The current endpoint always denotes the measured rejected candidate, independent of later production rollback. Allocation reductions alone do not justify adoption.
Main assessment: The combined candidate saved three allocations in the same-process TCP/SDK benchmark but median Base/equality latency increased 8.9%/5.5%. Independent process results were mixed; startup/port-swap Base/equality remained 2.54%/0.87% slower. Retain all evidence, withdraw both optimizations, and retain only the generic opt-in benchmark as tooling. Native per-operation parity is not achieved.

Source baseline: bf510d8f2becd4c023fe04a7df8b8dd1681e1d11 (R19 production plus docs-only scheduling). Frozen before CLI SHA256: 8337870fb7ccd7c6a2849d2bcd21b05f5df11d022c658e401fcd4054fccadf98; actual embedded 8918569 dirty.
Measured current candidate SHA256: 1c179ea706042d9647e7c158272576261576ede0e87d6f140864ca786c888550; actual embedded bf510d8f2becd4c023fe04a7df8b8dd1681e1d11, modified=true.

Scope: operationQueue reuses inline[1] pointer storage, clears old slots on growth, and copies discardPending results to owned storage before unlock. Audit identity skips Store for equal values; clone has an independent mutable wrapper sharing an immutable two-string snapshot. Credential Clone/clear, FIFO, fences, budgets, cancellation, authorization and error order are intended unchanged. No DN, Bind route, read buffer or GOMAXPROCS change.

Core: five scripts, 31 JSON, 840 samples, 144 medians, 48 comparisons, 15 exports. Negative time reductions: 21/48. Below OpenLDAP throughput: 47/48. All negative observations retained; no universal speedup or native-parity claim.
Read diagnostics: separate default A/A and startup/port swap; 10 JSON, 84 samples, 12 medians, four comparisons, six exports. Fixed UID scale-001001; Base/equality, 1000 x 7. A/A Go labels both use current. Swap starts current first on 29481 and before second on 29482. No pooling or correction.
Network: six logs, three fixed alternating rounds, 12 samples, four medians and six metric comparisons. Actual bf510d8 production and candidate test binaries use the same opt-in benchmark source. Real TCP and SDK with private 100k database copies; allocation totals include SDK plus server. Both timing regressions and allocation reductions remain in the tables. This is not pure server allocation or a native comparison.
Exploratory: historical isolated queue and audit-identity candidate/old-control logs kept separately. They are not actual bf510d8 before and do not establish final candidate behavior.
Validation: main focused server PASS 0.079s; full Go, vet and 355 native PASS records. No fuzz or race run this round; no older DN fuzz imported.

Recovery: previous fixed native environment, original native fixture and old canonical reference disappeared before native validation/macros. Main retained full Go/vet results, rebuilt pinned OpenLDAP 2.6.13 and regenerated the canonical/native fixture from the retained Go seed. Native and macros in this archive are new R20 runs after recovery; the recovered canonical independently matches the original hash. Recovery source paths, scripts/logs, actual native version and hashes are retained under recovery/.

Recovered data equivalence covers canonical user attributes. The new native MDB physical layout and generated operational attributes are not claimed identical to the removed fixture. openldap-1 is only a task-local alias for the reconstructed native-seed directory.

Native executable provenance: the env entrypoint is a libtool shell wrapper. Its hash is distinct from servers/slapd/.libs/slapd, the actual arm64 Mach-O executable. All entries in the provided native-tool manifest are independently checked; reference-builder source is read from immutable bf510d8 and matched to the recorded hash, never from live main.

All 21 exports verified against the original canonical fixture: 100002 entries, cksum 2143929969, 42712438 bytes, SHA256 5dbd9fc0096a98c9a4818972cbc612fb1af150c581c930c604123854549852a0.
Seven macro scripts use APFS cp -c. Setup/warmup are outside operation timing. COW, fixed endpoint order and warm caches remain limitations; distributed targets do not establish cold-cache performance.
Source reconstruction: baseline plus tracked patch and five new .raw files; main-frozen inputs at /tmp/ldap-go-r20-evidence-source. Full changed server.go/operation.go are not duplicated. Actual module metadata and source hashes are archived, without asserting reproducible builds.
Raw JSON/TSV/logs/scripts, checks, counters and all 21 export attestations are retained. Databases, canonical contents, executables, credentials and binary profiles are not bundled. SHA256SUMS covers every artifact except itself.
Main completion signal: generator/main-finished.json. Formal report and adoption decision belong to main. This worker executes no build/test/bench and hashes only after main completion.

The [formal R19 report](../../common-ldap-performance.md) remains the shipped-performance report. This separate R20 archive documents the rejected candidate. SHA256SUMS includes this top-level README.
