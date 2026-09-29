# Source Reconstruction

Start with a clean checkout of baseline `15f428a9f409c00e9de02a5b0d6ed81053e47c36` in a separate working directory. Apply `source/tracked.patch.txt` with `git apply`. Copy each file under `source/new/` into that checkout at the same relative path after removing only its final `.txt` suffix. New-file inventory is in `source/provenance.json`. Verify every resulting Go source and module file against `source-hashes.tsv`.

The patch is relative to the baseline commit, not the embedded revision of the retained production executable. No whole `server.go` or `ppolicy.go` copy is bundled. CLI source copies are convenience references; the patch and new-file inventory remain authoritative for reconstruction. Hashes cover all final Go sources and `go.mod/go.sum`, not a standalone repository or build environment. Source hashes are derived from stable captured bytes and patch final blob identities are checked.

For the portable baseline benchmark, use a clean baseline production checkout plus only `internal/server/bind_handler_bench_test.go` from the reconstructed candidate. It is benchmark instrumentation, not production baseline source. Main-reported invocation parameters, source revisions and log names are retained in `generator/main-finished.json`. This evidence generator does not execute those commands.

Independent frozen-source directory: /var/tmp/ldap-go-perf-20260930-r18/frozen-source. Its ten relevant Go files and source-changes.patch were checked against the completed archive. Other Go/module files are identified by the immutable accepted baseline 15f428a9f409c00e9de02a5b0d6ed81053e47c36; reconstruction does not depend on live main.
