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

The gate performs all of the following:

1. Builds the selected N-1 source and the current source independently.
2. Imports the canonical fixture with the N-1 binary.
3. Opens, checks, rebuilds, and exports the N-1 database with the current binary.
   The canonical export must remain byte-for-byte equal to the N-1 export.
4. Restores an N-1 backup with the current binary and compares canonical LDIF.
5. Creates and restores a current backup and compares canonical LDIF.
6. Reimports current LDIF into an empty database, exports it again, and requires
   byte-for-byte equality.
7. Records commit identities, reports, backups, LDIF evidence, and SHA256 hashes.

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

Before pushing the first release tag, create an explicit baseline tag or run
the gate with `RELEASE_PREVIOUS_REF` against the intended compatibility base.
