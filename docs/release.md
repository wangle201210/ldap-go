# Release and Upgrade Gate

Every candidate release must prove data portability before it can be published.
The gate builds both the previous release and the current tree, creates a real
bbolt fixture with the previous binary, and verifies that the current binary
can consume it without relying on binary file compatibility with OpenLDAP.

## Local Checks

Run the script contract checks first:

```sh
make release-check
```

Run the N-1 upgrade, backup/restore, and LDIF round-trip gate:

```sh
RELEASE_PREVIOUS_REF=v1.2.3 make release-upgrade-gate
```

`RELEASE_PREVIOUS_REF` may be a tag or commit. When it is omitted, the gate
selects the newest `v*` tag reachable from `HEAD` that does not point at `HEAD`.
Repositories without a release tag fall back to `HEAD^` only to bootstrap the
first release. Tagged CI sets `RELEASE_REQUIRE_PREVIOUS_TAG=1`, so a published
release can never silently use that fallback.

When both N-1 and current CLIs expose selected-database import/export, the gate
uses the enhanced fixture. It contains a persisted `cn=config`, stable database
`entryUUID` values, a custom `caseExactMatch`/`caseIgnoreMatch` schema,
multi-AVA naming, configured equality/substring indexes, and two independent
content partitions. Older compatibility baselines that lack these CLI features
use the original single-partition fixture and record
`fixture_profile=legacy`; that result does not prove the enhanced semantics.

The gate performs all of the following:

1. Builds the selected N-1 source and the current source independently.
2. Imports the canonical fixture with the N-1 binary.
3. Opens, checks, rebuilds, and exports the N-1 database with the current binary.
   The canonical per-partition exports must remain byte-for-byte equal to the
   N-1 exports.
4. Restores an N-1 backup with the current binary and compares canonical LDIF.
5. Creates and restores a current backup and compares canonical LDIF.
6. Reimports current LDIF into an empty database and exports it again. For the
   enhanced fixture, the gate unfolds LDIF continuations, associates every
   value with its DN, sorts that multiset, and requires semantic equality. This
   deliberately ignores only entry/attribute ordering and line folding;
   values, duplicates, and DN ownership must remain exact. The legacy fixture
   retains its historical byte-for-byte comparison.
7. For the enhanced fixture, starts the current server on a loopback ephemeral
   port after upgrade, N-1 restore, current restore, and LDIF reimport. Indexed
   LDAP searches must preserve case-exact identity, case-ignore matching, and
   visibility of the second partition.
8. Records commit identities, fixture profile, reports, backups, LDIF evidence,
   live-query evidence, and SHA256 hashes.

Use a new artifact path when evidence must be retained:

```sh
RELEASE_ARTIFACT_DIR="$PWD/out/upgrade-v1.2.3" \
RELEASE_PREVIOUS_REF=v1.2.3 \
make release-upgrade-gate
```

The destination must not already exist. Without `RELEASE_ARTIFACT_DIR`, the
script creates and reports a temporary directory but does not remove the
evidence after completion.

## Release Archives

Build the supported static binaries and verify their checksum manifest:

```sh
RELEASE_VERSION=v1.3.0 \
RELEASE_ARTIFACT_DIR="$PWD/out/v1.3.0" \
make release-build
```

The build matrix is Linux amd64/arm64, macOS amd64/arm64, Windows amd64, and
FreeBSD amd64. Unix binaries are packaged as `tar.gz`; Windows is packaged as
`zip`. Each archive includes the binary, README, and license. `SHA256SUMS`
covers every archive and is verified immediately after it is generated.
Local builds require Go, Git, tar, zip, and either `sha256sum` or `shasum`.

`make release-gate` runs script checks, the upgrade gate, and release builds.
Set separate artifact directories only when invoking the component targets;
the aggregate target intentionally uses temporary directories.

## Continuous Gate

`.github/workflows/release-gate.yml` runs on pull requests, pushes to `main`,
and manual dispatch. It uploads upgrade evidence and cross-platform archives
for every run. A manual run can supply a `previous_ref`; otherwise tag
selection follows the local rules above.

`.github/workflows/release.yml` runs only for `v*` tags. It requires a real
previous tag, repeats the upgrade gate, builds and verifies all archives, and
creates the GitHub release with `SHA256SUMS`. A failure in fixture creation,
database upgrade, restore, LDIF comparison, any platform build, or checksum
verification blocks publication.

## Nightly Production Evidence

`.github/workflows/nightly-production.yml` is intentionally separate from pull
request CI. It runs every day at `18:17 UTC` and by manual dispatch, with four
parallel, independently timed jobs:

- the pinned OpenLDAP 2.6.13 strict differential suite at commit
  `d172686d3d270bc961b78f3ff00d7019c8dfb094`;
- production qualification smoke followed by a fault-injected bounded soak;
- all parser fuzz targets for 10 seconds each with parallelism 2;
- the six-target `CGO_ENABLED=0` platform build matrix.

Manual runs may set `soak_seconds` from 60 through 1800 and
`soak_connections` from 1 through 64. The reusable
`scripts/qualification/nightly.sh` validates those limits before creating any
artifacts. Its defaults are 300 seconds, 16 clients, and two forced restarts.
Nightly evidence is retained for 14 days. The strict job builds only the pinned
source and verifies the source commit; caching is limited to that source clone.
Its Linux dependencies include a temporary MIT KDC toolchain, so the strict
runner also exercises the real GSSAPI differential instead of treating it as an
unavailable optional environment. The full strict log is retained on success
and failure.

The nightly matrix is strong evidence for the bounded configuration it runs. It
does not prove multi-hour endurance, every host OS at runtime, every ODBC/SASL
provider, or arbitrary network and disk failure schedules. Run a longer
environment-specific qualification outside this bounded shared-runner gate
before a high-risk deployment.

Before pushing the first release tag, create an explicit baseline tag or run
the gate with `RELEASE_PREVIOUS_REF` against the intended compatibility base.
