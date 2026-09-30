# R20 Evidence Handoff

Final main handoff is complete and records `REJECTED_NOT_SHIPPED`. The seven macros and 21 exports completed. `preparation.json` and the incomplete example below are retained as preparation history, not the final state; use `main-finished.json`, the top-level README, summary and checks for final evidence.

The generator writes only `docs/evidence/performance-20260930-r20/`. It never runs build, test, bench, native validation, macro scripts, or source-freezing commands. `--inspect` reads the inventory without hashing or publishing. Do not run `--main-finished` until main explicitly confirms that network, validation, recovery, build/hash and all seven macro scripts are complete and quiescent.

The final archive supports a rejected candidate. `main_decision` and `main_assessment` are copied from main; neither is inferred from successful evidence checks. Missing, incomplete, changed or inconsistent inputs stop publication. `preparation.json` records a limited earlier snapshot of frozen-source inventory, main-recorded hashes and the fresh native PASS log; it is not a macro completion signal and contains no worker-computed hashes.

Main supplies `generator/main-finished.json` using the adjacent example's schema. The example itself must never be renamed into a completion signal while incomplete. Completion booleans, exit codes, actual current hash, network commands and recovery details must describe observed final state. Network commands must contain no credentials. The benchmark source hash is supplied after main completion; it is checked against the frozen source. Keep the six network logs and their exact alternating order, including timing regressions.

Main also provides an immutable source snapshot, by default `/tmp/ldap-go-r20-evidence-source` (override with `frozen_source_root` in the final handoff). This worker cannot write outside its two authorized locations. The snapshot must contain repository-relative copies of:

- `internal/server/operation.go` and `internal/server/server.go`.
- `internal/server/audit_identity_bench_test.go` and `internal/server/audit_identity_test.go`.
- `internal/server/operation_queue_buffer_bench_test.go` and `internal/server/operation_queue_buffer_test.go`.
- `internal/server/network_common_bench_test.go`.
- `internal/cmd/ldapcommonbench/main.go` and `internal/cmd/ldapcommonbench/group_compare_test.go`.
- `internal/cmd/ldapbench/main.go` and `internal/cmd/ldifcanonical/main.go`.
- `go.mod` and `go.sum`.
- `tracked.patch`, from `git diff --full-index --binary bf510d8f2becd4c023fe04a7df8b8dd1681e1d11 -- internal/server/operation.go internal/server/server.go` while the measured candidate is still intact.

Main confirms the frozen snapshot matches the candidate used by both current executables, including when the candidate is later rejected. Do not freeze reverted production as the measured candidate. The generator reconstructs other Go/module files from the immutable baseline. It archives two tracked diffs and five new `.raw` files, without duplicate complete changed sources. Test binaries may lack embedded VCS fields; actual metadata is retained rather than invented.

Native recovery is part of provenance. Record the lost original environment/fixtures, the actual rebuilt OpenLDAP binary/environment/version log and source commit, the recovered native fixture root, the retained Go seed, reconstructed Go canonical path and native round-trip canonical path. Supply explicit sanitized recovery scripts/logs as `recovery.artifacts` with unique `recovery/raw/*.txt` (or `.json`/`.tsv`/`.raw`) archive names. Do not include full environment contents, passwords, credential files, databases or LDIF/canonical content. Only a fixed allowlist of pin/verified/path environment metadata is retained. The final native version log must identify slapd 2.6.13; the environment must match pin `d172686d3d270bc961b78f3ff00d7019c8dfb094` and VERIFIED=1. Auxiliary CLI executable paths default to `/var/tmp/ldap-go-r20-reference-recovery/{ldapbench,ldifcanonical}` and can be overridden in `auxiliary_binaries`.

All seven final scripts must reference the rebuilt environment and recovered `source_dir`; their method, access modes, APFS cloning, endpoint mappings and populations stay fixed. Retain the full Go/vet logs already completed, fresh `openldap-differential.txt` (355 PASS records, 26 top-level cases), final `validate.sh`, and final executable hash output. Preserve the recovery interruption/resume history in sanitized recovery logs/scripts. No old native PASS or fuzz log is a substitute for this round.

Recovery is now main-confirmed complete, and macros have started. The example names the available recovery README, export/import scripts, recorded hashes, logs and pre-recovery validation script. Its `recovery.completed=true` is not overall completion: `macro_finished` and the main completion signal remain unset. The native fixture is newly constructed; matching canonical user attributes do not imply identical physical MDB layout or generated operational attributes. Source generation continues to read the frozen `/tmp` candidate and immutable baseline, independent of subsequent live-main changes.

After main finishes, the generator hashes both recovered canonicals and the seed, rebuilt native and Go executables, 21 exports, frozen/reconstructed source and archive files. The Go and native round-trip canonicals must have identical original content. The canonical and every export must match 100002 lines, 42712438 bytes, cksum 2143929969 and SHA256 `5dbd9fc0096a98c9a4818972cbc612fb1af150c581c930c604123854549852a0`. Databases and canonical contents are not bundled. Top-level README is generated before SHA256SUMS and included in it.

Generation command: `node /var/tmp/ldap-go-perf-20260930-r20-request/generate-evidence.mjs --main-finished`. `--inspect` remains read-only. The final completion record and SHA256SUMS are part of the delivered archive; do not replace them with the incomplete example.
