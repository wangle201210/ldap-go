# R23: input-buffer experiment and verified TLS qualification

Production LDAP server logic remains R22 (`baf3811`, baseline repository commit
`3b0cd35`). Only verified-TLS support for `internal/cmd/ldapcommonbench` is shipped
in `6ebae9b`. The 1 KiB TCP input-buffer candidate is **not shipped**.

## Input-buffer decision

The isolated candidate is `cbf335d` in
`/var/tmp/ldap-go-tcp-input-20260930`, including the earlier `b8c6f16` wrapper.
It wraps owned native TCP accepts below activity/TLS/SASL, tracks close and read
deadlines, and keeps custom listener/classifier paths unchanged. Response writes
still use the original transport path. Added state costs at least 1 KiB per
buffered connection, separate from pending-operation budgets.

Three 100k plaintext comparisons use R22 before, buffered candidate current and
pinned OpenLDAP. Each has seven 1000-call batches per case. Base reductions are
+1.0%/-1.4%/+0.2% (default/explicit/swap); SSHA Bind is slower in all three.
Equality observations are mixed. The small inconsistent observations do not
justify the additional state and lifecycle complexity. No gain is claimed.

756 batches and nine canonical exports pass. Raw samples and negative results
are preserved. This is a rejected optimization, not a replacement production
performance table. The native BER implementation also makes prefix/body reads;
read-call count alone was never root-cause proof.

Wrapper unit tests passed in 0.183s. Focused server StartTLS/Bind/shutdown and new
buffer/TLS/SASL cases passed in 4.302s; selected CLI checks passed in 0.300s and
the explicit buffered-listener combination test passed separately. Vet passed
for server and CLI. The first focused build encountered an unfinished test's
unused import; it was removed before the passing run. These are selected tests,
not a full candidate/native regression qualification. Synthetic final-SASL
boundary cases use real security wrappers but do not prove authentication/KDC
negotiation. Synthetic socket errors retain timeout/closed classification but
use canonical `tcp` rather than necessarily preserving native `tcp4`/`tcp6`.

## TLS benchmark tooling and results

The tool accepts `-tls-ca` and `-start-tls`; all peers retain chain and hostname
verification, and failures close connections. CA parsing is outside timing.
StartTLS has a socket deadline through the exchange/handshake, cleared before
normal requests. Defaults retain plaintext behavior. A custom CA bundle replaces
system roots. There is no insecure option.

The tool's tests pass in 0.970s and vet passes. The first run exposed a macOS
system-verifier error-wording difference; the test now checks certificate
verification failure while retaining handshake rejection and peer-close checks.
No production TLS verification was loosened.

`tls-ldaps` and `tls-starttls` measure the **shipped R22 server**, not the buffer
candidate, against the same pinned OpenLDAP using the updated shared SDK tool.
Two endpoints rotate per call. Each transport has seven 1000-call batches per
case, default access, fresh independently writable 100k fixture copies, and the
same temporary ECDSA P-256 certificate/key on both endpoints. Verification stays
enabled. Cipher/version preferences remain implementation defaults; negotiated
parameters are not pinned or recorded. Handshakes, setup and identity checks
are outside timing. These are reused-connection operation results, not handshake
or transport-to-transport comparisons.

336 formal TLS batches and four canonical exports pass. The two 2-call smoke
runs are separate. Explicit ACL/distributed/broad reads/writes are not rerun
over TLS. Every export has 100002 entries, cksum2143929969 and42712438 bytes;
physical MDB layout/generated operational attributes are not asserted equal.

All Go work uses `CGO_ENABLED=0`; no race detector. Source reconstruction patches,
exact build metadata, tool/server executable hashes, summaries and compressed
JSON samples are archived. Decompress JSON before running summary scripts on
an archive copy. Replays require the documented R20 recovered seeds/reference.
Certificate public data is retained; private keys and temporary credentials are
removed after tests. SHA256SUMS covers archived artifacts.

Common-operation parity remains unmet. No aggregate write advantage offsets
slower reads. Future write-path and storage-copy investigations are separate
from this rejected input-buffer experiment.
