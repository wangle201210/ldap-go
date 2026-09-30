# R23: verified TLS results and rejected input buffering

September 30, 2026; 100,000 users, Apple M1 Pro, Go 1.26.4 with
`CGO_ENABLED=0`, pinned OpenLDAP 2.6.13. **Server production logic remains R22.**
The benchmark tool now supports verified LDAPS and StartTLS (`6ebae9b`).
Common operations still have not individually matched native performance.

## LDAPS and StartTLS

Default access, seven batches of 1,000 calls per row, median summed timed SDK
request duration. Relative = `OpenLDAP/ldap-go * 100%`; 100% means parity.
Frequency is qualitative. Both endpoints share one temporary ECDSA P-256
certificate/key per run; certificate and hostname verification remain enabled.

| Operation | Typical use | ldap-go LDAPS | OpenLDAP LDAPS | Relative | ldap-go StartTLS | OpenLDAP StartTLS | Relative |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 88.11 ms | 73.97 ms | 84.0% | 84.94 ms | 69.04 ms | 81.3% |
| Non-root Base, hot | High | 100.77 ms | 86.98 ms | 86.3% | 92.10 ms | 80.47 ms | 87.4% |
| Non-root equality, hot | Very high | 100.63 ms | 85.10 ms | 84.6% | 103.03 ms | 86.73 ms | 84.2% |
| Group1000 Compare, first | Medium | 98.33 ms | 80.29 ms | 81.7% | 95.77 ms | 78.29 ms | 81.7% |
| Group1000 Compare, last | Medium | 112.92 ms | 84.95 ms | 75.2% | 111.73 ms | 84.96 ms | 76.0% |
| Group1000 Compare, missing | Medium | 109.80 ms | 84.94 ms | 77.4% | 103.60 ms | 80.30 ms | 77.5% |

First/last follows fixture insertion order, not assumed native storage order.
The two endpoints rotate per request. Setup, TLS negotiation, identity checks
and cleanup are excluded. Cipher/version preferences remain implementation
defaults; negotiated parameters were not pinned or recorded. These rows are
not handshake measurements or evidence that one transport is faster than
another. Do not combine them with separate plaintext runs.

All **336 formal TLS batches and four canonical exports** passed. Each export
contains 100,002 matching user-data entries. Explicit ACL, distributed lookups,
group discovery/traversal and broad reads/writes were not rerun over TLS.

## Rejected input buffer

A separate candidate added a fixed 1 KiB input buffer below activity tracking,
TLS and SASL, with deadline/close handling and native-listener ownership gates.
The additional memory and lifecycle complexity were not justified by stable
latency improvement, so it was not merged into production.

Paired time reduction = `(1-current/before)*100%`; negative means slower.

| Operation | Default | Explicit ACL | Startup/port swap |
| --- | ---: | ---: | ---: |
| User Bind, SSHA | -0.4% | -0.5% | -1.4% |
| Non-root Base | 1.0% | -1.4% | 0.2% |
| Non-root equality | -0.4% | 1.7% | 1.3% |

All other cases remain in the evidence. The swap is independent, not pooled
with primary statistics. These observations do not prove statistical effects
or universal equivalence. The candidate's **756 batches and nine exports** pass
result/data checks, but performance did not qualify it for adoption.

Selected wrapper, TLS/security-layer, Bind, shutdown and CLI composition tests
passed, as did candidate vet. No full candidate/native regression claim is
made. Forced-prefetch SASL layer tests use synthetic final authentication input;
they do not certify a full KDC negotiation. Socket timeout/closed classification
is preserved, with a known `tcp` versus `tcp4`/`tcp6` error-metadata difference.

## Reproduce and inspect

Use the existing [common benchmark](../internal/cmd/ldapcommonbench/README.md#verified-tls)
with `-tls-ca /path/to/ca.pem`; use `ldaps://` endpoints or add `-start-tls` to
`ldap://` endpoints. All setup, measured and cleanup connections verify TLS
before their first Bind. There is no insecure verification flag.

[R23 evidence](evidence/performance-20260930-r23/README.md) preserves raw samples,
scripts, summaries, source patches, hashes and validation logs, including the
rejected candidate and negative results. Tool tests and vet pass; tests cover
trust, hostnames, upgrade order, failure closure, handshake timeout and deadline
clearing. A platform-specific certificate-error wording expectation was corrected
without weakening TLS verification.

The production plaintext comparison remains [R22](common-ldap-performance-20260930-r22.md).
No physical MDB-layout, generated-operational-attribute, universal compatibility
or overall parity claim is made. Faster writes do not offset slower reads.
