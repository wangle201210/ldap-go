# R20 Reference Recovery

The original fixed native build environment, round4 fixture directory and
round15 canonical file disappeared during R20 qualification. The Go full suite
and vet had passed; native validation stopped before execution when loading the
missing environment. No old native PASS record is substituted for this round.

The retained R20 member-index.db was copied privately and served by the frozen
R19 binary. Its online user-attribute export restored 100,002 entries with
cksum 2143929969, 42,712,438 canonical bytes and exactly the committed canonical
SHA256. Neither the original retained Go seed nor project data was modified.

OpenLDAP 2.6.13 was rebuilt from clean commit
d172686d3d270bc961b78f3ff00d7019c8dfb094 with the repository reference builder.
The native fixture config follows scripts/qualification/compare-openldap.sh.
The recovered content is imported into a fresh native MDB, then exported and
compared against the recovered canonical file before any performance run.
The openldap-1 symlink refers to this task's native-seed directory solely to
retain the existing benchmark script layout.

Rebuilding the executable and MDB can change binary hashes, physical page layout
and generated operational attributes. They are not claimed identical to the
removed originals. Paired Go versions and the rebuilt native reference are
measured afresh, using identical verified user data and the original workload.
All Go builds remain CGO_ENABLED=0; the native C reference is a separate program.

Recovery scripts, build/version logs and hashes are provenance artifacts.
Password files and fixture configs containing credentials must not be archived.
Raw LDIF, canonical contents and database binaries also remain outside Git.
