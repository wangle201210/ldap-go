# OpenLDAP compatibility matrix

Baseline: OpenLDAP 2.6.x, with OpenLDAP 2.6.13 used by the initial differential
test environment.

Status values:

- `planned`: no passing implementation claim;
- `partial`: a documented subset has conformance tests;
- `compatible`: standards tests and OpenLDAP differential tests pass;
- `n/a`: deliberately inapplicable, with rationale recorded.

No row may become `compatible` based only on unit tests.

## Completeness audit

The reproducible verification baseline is the OpenLDAP 2.6.13 release commit,
and ldap-go is not a complete drop-in replacement. No matrix row is currently
marked `compatible`; planned backends, overlays, operational tooling, SASL
security layers, and protocol edge cases remain. The supported
migration boundary is semantic `slapcat` LDIF, not OpenLDAP MDB binary files.
Content and `cn=config` values can be preserved by the importer, but only the
features explicitly listed below have matching runtime behavior. Passing one
listed differential does not establish compatibility for all OpenLDAP
functions, configurations, or directory data.

## LDAPv3 protocol

| Area | Status | Required evidence |
| --- | --- | --- |
| BER framing and LDAPMessage | partial | RFC malformed-input corpus and client interoperability; unknown application operations match OpenLDAP's message-ID-zero `protocolError` Notice of Disconnection and connection close |
| Bind: anonymous and simple | partial | RFC 4511/4513, `olcAllows` LDAPv2/anonymous forms, `olcDisallows`, and OpenLDAP differential tests pass |
| Bind: SASL | partial | EXTERNAL, PLAIN, CRAM-MD5, DIGEST-MD5 `qop=auth`, multi-round SCRAM-SHA-1/256/512, and `olcAuthzPolicy` proxy identities pass; OpenLDAP 2.6.13 PLAIN, CRAM-MD5, DIGEST-MD5, and SCRAM-SHA-256 `ldapwhoami` pass; GSSAPI and security layers remain |
| Search and SearchResultReference | partial | scope, named-referral, all alias deref modes, limits, attributes, typesOnly |
| Filters and matching | partial | RFC 4515 corpus and schema-aware differential tests |
| Modify | partial | atomic modification and error-order differential tests |
| Add | partial | parent/schema/ACL/operational-attribute tests |
| Delete | partial | leaf/subtree/referral behavior tests |
| ModifyDN | partial | rename/move/subtree and RDN-value tests |
| Compare | partial | matching-rule and ACL disclosure tests |
| Abandon and cancellation | partial | active Search, response suppression, same-connection, and state-barrier tests pass |
| Unbind and disconnect notices | partial | connection-state tests |
| Referrals, aliases, and ManageDsaIT | partial | RFC 3296 referrals, RFC 4511/4512 aliases, OpenLDAP 2.6.13 differentials, and chain-overlay integration tests pass |
| LDAP URLs and attribute options | partial | referral DN/scope rewrite passes; full RFC 4516 and language options remain |

## Controls and extended operations

| Area | Status | Required evidence |
| --- | --- | --- |
| StartTLS | partial | RFC 4511/4513 state machine plus OpenLDAP `tls_2_anon`/`tls_authc` identity ordering tests pass; broader slapd TLS differentials remain |
| Password Modify | partial | RFC 3062 core plus ppolicy old-password, quality, minimum-age, history, reset, hashing, response-control integration, and transaction-generated password commit/rollback pass; broader cross-overlay cases remain |
| Who Am I? | partial | RFC 4532 simple-bind and StartTLS identity tests pass |
| Cancel | partial | RFC 3909 BER, result, ordering, isolation, and OpenLDAP 2.6.13 differential tests pass |
| Assertion | partial | RFC 4528 Add/Modify/Delete/ModifyDN/Search/Compare atomic tests pass |
| Pre-read and post-read | partial | RFC 4527 Add/Modify/Delete/ModifyDN transaction and ACL tests pass |
| No-Op and permissive modify | partial | hidden OpenLDAP controls, validation, all four update operations, atomic memory/bbolt rollback, read-control interaction, transaction composition, and OpenLDAP 2.6.13 MDB differentials pass |
| Paged results | partial | RFC 2696 Go-client, cookie, ACL, limit, glue, and mutation tests pass |
| Server-side sorting | partial | RFC 2891/OpenLDAP 2.6.13 CLI, Go-client, matching, ACL, paging, and mutation tests pass |
| VLV | partial | OpenLDAP 2.6.13 CLI, Go-client, BER, offset, assertion, multi-context, ACL, limit, and error tests pass |
| ManageDsaIT | partial | RFC 3296 Search/write/Password Modify and OpenLDAP 2.6.13 referral differential tests pass |
| Proxied Authorization | partial | RFC 4370 operation scope, BER/error handling, per-operation ACL identity, transaction identity capture, `olcAuthzPolicy`, all documented rule forms, global allow/disallow flags, restart/rollback, and OpenLDAP 2.6.13 differentials pass |
| Subentries | partial | RFC 3672 schema/control, visibility, paging, write rules, and OpenLDAP 2.6.13 differential tests pass |
| Don't Use Copy | partial | RFC 6171 Search/Compare, shadow referrals, chain routing, alias/referral ordering, `dontusecopy_non_critical`, OpenLDAP `ldapsearch`, and slapd differentials pass |
| LDAP Sync | partial | RFC 4533 BER, refreshOnly, refreshAndPersist, present/session-log refresh, `delcsn`, dynamic contextCSN, cancellation, restart, Sort/VLV, glue, OpenLDAP 2.6.13 ldapsearch, and schema-aware base/scope/present/delete DN routing pass; broader provider and overlay-order topologies remain |
| LDAP transactions (RFC 5805/OpenLDAP) | partial | strict BER, connection state, Add/Modify/Delete/ModifyDN/Password Modify, generated-password commit/rollback, bounded configurable queues, Aborted Transaction Notice, Bind/Unbind no-notice aborts, per-update proxy identities, memory/bbolt rollback, OpenLDAP `ldapmodify`, and pinned source/slapd differential tests pass; pre/post-read, proxied authorization on Start, and broader extension interactions remain |
| Dynamic refresh | partial | RFC 2589 BER/TTL/ACL behavior, OpenLDAP `ldapexop`, and slapd differentials pass; broader overlay-order and replication topologies remain |

## Data model and schema

| Area | Status | Required evidence |
| --- | --- | --- |
| DN/RDN parsing and normalization | partial | schema-aware v2 identity uses naming-attribute equality rules, canonical attribute names, alias/OID equivalence, caseExact/caseIgnore separation, canonical multi-AVA ordering, duplicate canonical-AVA rejection, and normalized display text distinct from storage keys; core operations, routing, controls, Sync, proxy paths, and implemented overlays have Memory/bbolt coverage, and the multi-AVA runtime sequence passes a pinned OpenLDAP 2.6.13 differential; arbitrary custom matching-rule modules and complete RFC/OpenLDAP normalization parity remain |
| Core syntaxes and matching rules | partial | RFC 4517 schema-aware corpus plus pinned `slapadd` checks for arbitrary-precision INTEGER, GeneralizedTime hour/offset forms, authzMatch, default equality normalization, covered OpenLDAP binary syntax validators, required `;binary`, and explicit value validation pass; arbitrary module-provided syntax validators and matching-rule implementations remain unsupported |
| Standard operational attributes | partial | create/modify/rename differential tests |
| Subschema subentry | partial | discovery and schema publication tests |
| Runtime schema through `cn=config` | partial | add/modify/delete/restart tests, imported `olcAttributeOptions` exact/trailing-`-`/`range=` handling, range Search/Modify behavior, ordered `olcLdapSyntaxes` declarations and `X-SUBST` inheritance, idempotent built-in syntax restore, and atomic offline configuration validation pass; executable third-party validators, complete schema-module loading, and every OpenLDAP schema description remain unsupported |
| Collective attributes | partial | RFC 3671 schema, propagation, merge/exclusions, filtering, Compare, controls, paging, sorting/VLV, and ACL tests pass; X.501 administrative-area boundaries and OpenLDAP differential remain |
| DIT content/name/structure rules | partial | OpenLDAP `olcDitContentRules` parsing, publication, enforcement, online/restart, real slapcat import, and slapd differentials pass; RFC 4512 name-form/structure-rule parsing, publication, RDN/SUP enforcement, governing rule maintenance, and Relax behavior pass; OpenLDAP 2.6 exposes no equivalent runtime configuration for a differential |

## Authentication, authorization, and security

| Area | Status | Required evidence |
| --- | --- | --- |
| OpenLDAP and SM3 password schemes | partial | portable digest/SSHA/SM3/PBKDF2-SM3 hash and migration vectors; OpenLDAP contrib SHA-256/384/512 salted and unsalted schemes, `{PBKDF2}`, `{PBKDF2-SHA1}`, `{PBKDF2-SHA256}`, `{PBKDF2-SHA512}`, `{APR1}`, and `{BSDMD5}` pass bidirectional Password Modify/import/Bind differentials; verify-only Netscape `{NS-MTA-MD5}` and external `{RADIUS}` pass pinned module, import, Bind, transaction, and wire-level tests; `{TOTP1}`, `{TOTP256}`, `{TOTP512}`, and all three `ANDPW` variants pass hashing, replay, Relax-managed `authTimestamp`, and pinned module differentials; external Kerberos remains |
| Password policy overlay | partial | OpenLDAP schema/config and LDIF round trips, default/per-entry policy selection, lockout/delay, expiry/warnings/grace, reset restrictions, history, quality/age rules, last-bind/max-idle, hashing, standard/Netscape/account-usability controls, online reload, chain-backed forwarded state updates, race tests, and OpenLDAP 2.6.13 differentials pass; native `check_password()` modules remain |
| OpenLDAP ACL grammar and evaluation | partial | filter/value/object-class targets; real/effective DN and level selectors; static/dynamic groups and set expressions; DN/value capture expansion; peer/domain/sockname/sockurl and IPv4/IPv6/path selectors; overall/transport/TLS/SASL SSF; `OpenLDAPaci`; and direct OpenLDAP target, expansion/group, connection/level, and ACI differentials pass; unlisted grammar and dynacl modules remain |
| SASL server authentication | partial | EXTERNAL, PLAIN, CRAM-MD5, DIGEST-MD5 `qop=auth`, SCRAM-SHA-1/256/512, transport SSF policy, `olcSaslHost`, direct/LDAP-URL `olcAuthzRegexp`, `olcAuthzPolicy`, `authzTo`/`authzFrom`, group/LDAP-URL rules, Cyrus credential forms, proxy-backed auxprop/auth-check searches, OpenLDAP `other(80)` backend-failure mapping, and OpenLDAP CLI interoperability pass; GSSAPI, SCRAM-PLUS, and DIGEST security layers remain |
| SASL client authentication | partial | syncrepl EXTERNAL/PLAIN/CRAM-MD5/DIGEST-MD5/SCRAM-SHA-1/256/512 pass; DIGEST-MD5 covers multiple offered realms, configured realm validation, `authzid`, provider-host `digest-uri`, and strict `rspauth`; GSSAPI password/keytab/FILE-cache paths pass unit coverage; only DIGEST `qop=auth` is supported, and a real KDC topology, SCRAM-PLUS, and SASL security layers remain |
| Security strength factors | partial | TLS cipher, TLCP SM4, Unix-socket, minimum SSF, PLAIN advertisement policy, and ACL `ssf`/`transport_ssf`/`tls_ssf`/`sasl_ssf` selectors pass; negotiated SASL-layer SSF remains unavailable |
| TLS and mutual TLS | partial | LDAPS/StartTLS/client cert and syncrepl CA/SAN/CRL policies pass; global `olcTLS*` certificate/key/CA/CRL, client verification, protocol minimum, exact ciphers, and `olcTLSCRLCheck=none/peer/all` build or stage an immutable context. PEM/DER CRLs enforce issuer signature, validity, serial revocation and `removeFromCRL`; online TLS/CRL rotation preserves old connections and rolls back invalid updates. Unsupported OpenSSL selectors, CA-directory lookup, indirect/delta CRLs, DH/random/curve directives, TLS 1.3 cipher selection, and the broader slapd TLS matrix remain |
| National cryptography transport | partial | GB/T 38636 TLCP dual-server-cert, mutual-client-cert, and ECDHE syncrepl matrix |
| Audit and security logging | partial | credential-free operation metadata, result codes, identities, transport SSF, malformed-message coverage, HMAC-SHA-256 chaining, verified restart append, CLI verification, concurrency/race, and tamper tests pass; OpenLDAP accesslog and flat-file auditlog records, rotation, proxy identities, frontend scope, and transaction behavior pass slapd differentials; broader cross-overlay and OS fault matrices remain |

## Storage, configuration, and migration

| Area | Status | Required evidence |
| --- | --- | --- |
| Transactional durable backend | partial | crash, atomicity, recovery, and race tests pass; schema-aware v2 DN keys preserve caseExact and merge caseIgnore/alias/OID/multi-AVA equivalents. Memory and bbolt persist configured `eq`, `pres`, `sub`, `subinitial`, `subany`, `subfinal`, and `ordering` indexes, maintain them transactionally across writes/renames, rebuild for legacy/config changes, and preserve/check them through backup/restore/compact. Substring indexes use bounded initial/final anchors and 3-grams with an overflow candidate set that prevents false negatives; short unconstrained `subany` filters fall back to scans. Ordering serves `>=`/`<=`, including order-preserving LDAP INTEGER keys and generalizedTime keys aligned with the schema comparator for whole and fractional seconds. `AND` may use an indexed subset, while `OR` requires every branch; all candidates still receive full LDAP evaluation. Raw writes invalidate indexes and safely fall back to scans. `approx`, `nolang`, `default`, missing matching rules, and rules without a proven equivalent normalization are rejected |
| Multiple suffixes and subordinate DBs | partial | runtime partition/hidden/glue/paging/syncprov tests plus pinned offline default-primary, most-specific `-b`, hidden/disabled fallback, selected-superior-to-subordinate routing, superior LastMod/root-DN policy, glued replacement, glued `slapcat`, physical `-g`, and duplicate-suffix rejection pass; broader nested glue/backend combinations remain |
| `cn=config` online configuration | partial | OpenLDAP LDIF import, online changes, and immutable runtime publication pass; complete backend/module-specific validation hooks remain |
| `slapcat` content LDIF import/export | partial | semantic round trips, atomic rollback including API dry-run, default/explicit database selection and no-database rejection, glue-subordinate import/export/replacement and `-g`, `config`/`mdb`/`ldif`/`wt`/`null` callback policy, proxy-backend rejection, built-in and supported imported schema validation, ordered `olcLdapSyntaxes`/`X-SUBST`, AttributeDescription/options/`;binary` checks, selected default equality normalizers, RDN-value completion, `structuralObjectClass`, selected-database LastMod, `-S`, root/subentry/config `contextCSN`, selected-database suffix/final-parent checks, and supplied operational metadata pass; complete slapd parser/normalizer behavior, executable custom syntax and matching-rule modules, diagnostics, native backend file layouts, and every OpenLDAP data shape remain unverified |
| `slapcat` `cn=config` import | partial | real OpenLDAP 2.6.13 `slapcat -n 0` schema/config import and same-transaction hierarchy/schema/runtime validation pass; unsupported configuration modules and values still reject or lack equivalent runtime behavior |
| Backup, restore, database rebuild, check | partial | offline bbolt page/bucket/key/JSON/DN validation, multi-partition and metadata-preserving snapshot/restore, atomic publication, overwrite protection, corruption/cancellation tests, and rebuild round trips pass; online backup, crash injection at each filesystem boundary, and OpenLDAP tool output parity remain |
| Monitor backend | partial | Root DSE discovery, all 13 standard monitor branches, dynamic connection/operation/statistics/time/database/overlay state, Search/Compare/ACL/paging/limits, matched DN, runtime read-only/restriction changes, and OpenLDAP 2.6.13 differentials pass; complete backend/overlay inventories and worker/runtime internals remain |
| Null backend | partial | `olcDbBindAllowed`/`olcDbDoSearch`, synthetic Search, Bind/root Bind, discarded writes, Compare, Assertion, paging, typesOnly, read controls, No-Op, and a null-enabled OpenLDAP differential pass |
| Relay backend | partial | explicit and suffix-massage-selected local targets, bidirectional storage views, Bind/Search/Compare/writes/transactions, ACL translation, inherited sort and sync-provider configuration, direct attribute/objectClass/DN-value mappings, and an OpenLDAP differential pass; arbitrary rewrites, relay chains, and broader overlay combinations remain |
| LDAP and meta proxy backends | partial | `olcDatabase=ldap` forwards Bind, Search, Compare, writes, Password Modify, Dynamic Refresh, and Who Am I? with ordered URI failover, health-preferred endpoint recovery, single-URI reconnect, Simple identity reuse, root/native SASL identity assertion, proxy authorization, password-based SASL auxprop/auth-check searches, Abandon/Cancel, remote diagnostics, default five-hop referral chasing, and online rollback; `olcDatabase=meta` adds multi-target routing/Search union, target/default selection, suffix massage, direct and wildcard/drop attribute/objectClass maps, subtree/filter rules, result namespace rewriting, client-pr, onerr, quarantine, DN-route caching, health-preferred URI recovery, connection reuse/expiry/use-temporary, bind polling, controls, Abandon/Cancel, mapped SASL authorization IDs and rules, `olcDbProtocolVersion` 2/3, privileged `olcDbConnectionPoolMax` cross-frontend reuse, pool caps, busy-connection reuse and temporary overflow, plus online target creation, pre-connection URI updates, and sibling-target isolation, with pinned OpenLDAP 2.6.13 differentials/source contracts and local protocol topologies; GSSAPI and SASL security-layer proxy Bind, complete referral rebind behavior, full librewrite, complete multi-target connection categories, active-connection topology mutation, target deletion/reordering, local/frontend overlay execution, and transaction forwarding remain. OpenLDAP 2.6.13 itself can abort in `back-meta/conn.c` when a target URI changes after a multi-target metaconn exists, so that unsafe path is documented rather than treated as a compatibility target. |
| Socket backend | partial | exact schema, fresh Unix socket per request, Bind/Search/Compare/writes/Password Modify/Unbind, connection fields, LDIF/Base64/filter encoding, frontend validation, Relax, shadow Don't Use Copy, cancellation, reload and pinned differentials pass. Search parses bounded bare-LDIF/ENTRY/REFERRAL records and streams each ACL-projected entry before one final RESULT; partial Cancel/Abandon and malformed-midstream behavior are covered. RFC 5805 updates are rejected with `unwillingToPerform` during queueing before socket I/O, with a whole-queue commit guard. Critical chaining and critical Bind password-policy controls are rejected before dialing, while unsupported noncritical controls are ignored. The protocol layer supports a strict sole `CONTINUE` response and one-way overlay `ENTRY`/`RESULT` encoding, but socket-overlay configuration and callback dispatch, referrals/response controls in overlay `RESULT`, the complete global-control matrix, and bug-for-bug acceptance of a missing database RESULT remain unsupported |
| SQL backend (`back-sql`) | partial | Registers the exact OpenLDAP 2.6.13 `olcSqlConfig` schema, opens the configured `database/sql` driver (ODBC by default), adapts standard `sql.Out` values to the godbc procedure-output API, and loads standard/custom objectClass and attribute mappings. Mapped Bind/Search/Compare support frontend schema and matching validation, scope, ACLs, controls, binary values, inherited object classes, `structuralObjectClass`, deterministic `entryUUID`, and `hasSubordinates`. Add/Modify/Delete/leaf-ModifyDN execute mapping procedures and `ldap_entries` changes on one pinned connection; non-autocommit writes use one SQL transaction, while `olcSqlAutocommit` cannot roll back a No-Op or later failure. Add resolves a created row by mapping key rather than DN spelling, Delete validates its object procedure before attribute side effects, and ModifyDN invokes procedures only for actual RDN-value deltas. One LDAP read view pins one connection and, when autocommit is disabled, prefers a repeatable-read/read-only transaction before falling back to driver-default transaction options. Parameterized presence candidates cover mapped attributes and equality candidates cover object classes. Mapped-attribute equality falls back to a full entry-ID scan because mapping metadata cannot prove SQL column types or comparison semantics; this includes octet, case-ignore, IA5, and list matching. Partial `AND` planning is allowed, but `OR` falls back unless every branch is plannable; final LDAP filter evaluation remains authoritative. Requested/filter attributes plus `olcSqlFetchAttrs` prune mapping reads unless `olcSqlFetchAllAttrs` is true, preserving binary bytes. `olcSqlBaseObject: TRUE` synthesizes the suffix entry and de-duplicates an equivalent mapped row. Pure-Go SQLite planner/write tests pass. A live pinned OpenLDAP 2.6.13 SQLite ODBC differential passes equivalent Bind, scope/filter Search, Compare, binary, inherited-objectClass, deterministic operational-attribute, mapped Add/Modify/leaf-ModifyDN/Delete, No-Op, rollback-failure, and successful lifecycle observations without Oracle; that existing live fixture does not establish parity for every newly supported planner/fetch/base-object directive. Startup and online/offline configuration paths validate connectivity and mapping metadata, not every configured SQL statement or procedure path. Requests known to write distinct SQL backends, including an applicable SQL-to-SQL accesslog target, are rejected before DML because independent databases cannot be atomically committed without XA. A later local-store commit failure can still occur after a SQL commit, and SQL-backed RFC 5805 transactions are rejected. Non-SQLite RDBMS matrices, file-mode `olcSqlBaseObject`, native `olcSqlLayer`, custom scope templates, subtree shortcuts, `olcSqlCheckSchema`, remaining `olcSql*` directives, dynamic operational metadata, and an external Perl adapter remain unsupported or unverified |

OpenLDAP MDB binary files are not a stable interchange format. Canonical
`slapcat` LDIF is the direct migration contract. MDB indexes are not migrated;
the memory and bbolt engines rebuild their own `olcDbIndex`-derived
equality/presence/substring/ordering layout. Atomic imports parse and validate
all pending content inside one write transaction, retaining the pending entry
set until database routing is known; `slapadd -c` is the documented exception
and commits independent successful content records. Large-import memory use,
write-lock duration, index selectivity, and crash/fault behavior at scale do
not yet have a production qualification gate.

## Overlays

| Area | Status | Required evidence |
| --- | --- | --- |
| accesslog | partial | successful Add/Delete/Modify/ModDN and Password Modify, failed writes, Search/Compare, Bind/Unbind/Abandon, database-targeted Extended, request/result/control/referral fields, atomic successful source/log commits, `reqMod`, `reqOld`/`reqOldAttr`, branch `olcAccessLogBase`, `olcAccessLogSuccess`, `auditContext`, source-derived multi-SID context/min CSNs, purge, stale-cookie rejection, online rollback, ldap-go delta topology, and OpenLDAP 2.6.13 record differentials pass; arbitrary unknown-operation routing, cross-overlay ordering, and broader fault matrices remain |
| auditlog | partial | database and frontend `olcAuditlogFile`, successful Add/Modify/Password Modify/ModDN/Delete, LastMod modifications, proxy `realdn`, LDIF Base64/folding, No-Op and failed-write exclusion, online rollback/restart, real `slapcat` config import, external rotation, non-fatal file errors, concurrent appends, RFC 5805 commit/abort/rollback behavior, and OpenLDAP 2.6.13 semantic differentials pass; broader cross-overlay ordering and platform filesystem fault matrices remain |
| autoca | partial | built-in OpenLDAP 2.6.13 PKI/config schema, writable database-local singleton lifecycle, startup CA creation and DER reuse, strict ordered certificate/private-key Search trigger, user/server RSA issuance, email/IP SANs, PKCS#8 persistence, root/self rules, final response ACL filtering, concurrent one-pair hardening, and a pinned OpenLDAP 2.6.13 semantic differential pass; the explicit ldap-go `olcAutoCAProfile=sm2-sm3` extension issues SM2 certificates signed with SM3; automatic `olcAutoCAlocalDN` TLS-context installation, legacy 512-bit RSA, exact OpenSSL extension encoding, replication/cross-overlay matrices, and CA rotation remain |
| chain | partial | imported `olcChainConfig`/child back-ldap entries; Search continuation, Compare, writes, Password Modify, Dynamic Refresh, identity assertion, TLS/TLCP, chaining behavior, schema/filter policies, session tracking, nested referrals, and ppolicy forwarding pass; connection pooling/quarantine scheduling, full SASL rebind coverage, and OpenLDAP differential fixtures remain |
| collect | partial | ordered database/frontend `olcCollectInfo`, overlapping response-only projections, normalization without de-duplication, requested attributes/typesOnly, Paging/Sort/VLV/ManageDsaIT, source and target ACLs, Modify protection, online rollback/restart, and a pinned OpenLDAP 2.6.13 differential pass; synthesized operational template attributes and broader glue/proxy/cross-overlay matrices remain; hardened divergences check every Modify element and protect the base type of optioned attributes |
| constraint | partial | all six rule types, `restrict=`, Add/Modify/ModifyDN, Relax, online/restart, rollback, and slapd differential pass; cross-overlay ordering and locale-dependent regex edges remain |
| DDS | partial | OpenLDAP config, add/modify/modDN constraints, live TTL, limits, expiry/restart, sync delete publication, disabled state, and slapd differential tests pass |
| deref control overlay | partial | `olcOverlay: deref` lifecycle, database/frontend control registration, source/target/value ACL filtering, same-backend resolution, binary/empty values, and gated OpenLDAP 2.6.13 differential tests; hardened divergence: OpenLDAP 2.6.13 leaks a target value denied by value-level ACL through the deref response even though direct Search hides it, while ldap-go filters it |
| dynlist and dyngroup | partial | default and ordered multiple attrsets, arbitrary/mapped projections, local LDAP URL variants and restrictions, DN members, memberOf, static/dynamic nesting, filters, Compare, `dgIdentity`/`dgAuthz`, ACLs, ManageDsaIT, paging quirks, online/restart behavior, real config import, and OpenLDAP 2.6.13 differentials pass; cross-overlay ordering, large-directory performance, and broader glue/replication matrices remain |
| homedir | partial | `olcSkeletonPath`, minimum UID, ordered POSIX mappings, Add/Modify/ModifyDN/Delete lifecycle, IGNORE/DELETE/ARCHIVE, post-commit effects, online rollback, skeleton copy, rename, selective chown, tar archive, traversal/symlink/root/recursive-source boundaries, repeated/race tests, and OpenLDAP 2.6 DELETE/ARCHIVE filesystem differentials pass; FIFO skeleton entries, non-root ownership differential coverage, POSIX-only ownership, one instance per database/frontend, libc-regex edge parity, and byte-identical OpenLDAP tar output remain |
| memberof and refint | partial | current `cn=config` forms, multiple instances, custom DN/nameAndOptionalUID attributes and group classes, `groupOfNames`/`groupOfUniqueNames`, dangling ignore/drop/error, Relax, AddCheck, member refint, refint exact/subtree repair and Nothing placeholders, Add/Modify/Delete/ModifyDN, online/restart/rollback, real `slapcat` import, and OpenLDAP 2.6.13 differentials pass; global overlays, cross-overlay ordering, replication topologies, and fault-path parity remain |
| nestgroup | partial | database/frontend placement, multiple instances and bases, default/custom DN or Name And Optional UID attributes, all four flags, request-aware values and equality-filter expansion, negative-filter response recheck, cycles/dangling paths, ACLs, ManageDsaIT, paging/Sort/VLV, limits, online disable/delete/re-add/restart, and a pinned OpenLDAP 2.6.13 fixture plus differential pass; complete glue/proxy/replication and arbitrary cross-overlay order matrices remain |
| otp | partial | built-in OpenLDAP 2.6.13 OATH schema, writable database-local singleton lifecycle, HOTP/TOTP Simple Bind, static-password suffix splitting, replay state, Password Modify bypass, hidden internal reads, atomic same-token concurrency hardening, and a pinned OpenLDAP 2.6.13 fixture plus differential pass; replication-topology guarantees, HMAC-SM3, encrypted seed envelopes, and arbitrary cross-overlay ordering remain |
| pbind | partial | database-local Simple Bind forwarding, ordered multi-endpoint `olcDbURI` failover, `olcDbStartTLS` TLS parameters, network timeout, active retrylist quarantine with single-probe concurrency, request controls, remote result/referral/response-control propagation, live StartTLS trust/fallback tests, local two-server topology, and optional OpenLDAP `back_ldap` differential pass; per-attempt dialing, connection pooling, broader TLS platform failures, and non-Simple mechanisms remain |
| remoteauth | partial | ordered mappings, DN/domain attributes, default domain/realm, domain truncation, file-backed multi-provider realms, retries, store-on-success, required TLS policy and live SHA-256/SM3 peer-key pin tests, local-password precedence, no-`userPassword` eligibility, `olcPasswordHash` writeback including `{PBKDF2-SM3}` and OpenLDAP-compatible cleartext fallback for verify-only schemes, local two-server topology, and OpenLDAP 2.6 delegation/writeback/provider-loss differential pass; connection pooling and a broader TLS platform failure matrix remain |
| pcache | partial | database-local `olcPcacheConfig` on back-ldap, canonical keys, positive/negative caching, TTL/TTR/offline/LRU/limits, paging, concurrent reload-safe state and pinned Phase 1/2 differentials pass. Containment covers schema-aware equality, OpenLDAP-direction substring, unordered AND/OR, aliases and extensible filters. `olcPcacheValidate` rechecks provider responses and atomically invalidates failed TTR refreshes while provider errors preserve old cache; `olcPcachePosition=head/tail` is accepted where the current exclusive callback architecture is observably equivalent. Bind cache stores non-cleartext verifiers with TTL/offline/limits/reload safety. Persist reproduces observed no-restore behavior; private DB and query-delete controls remain explicitly unsupported, and arbitrary overlay ordering is not claimed |
| ppolicy | partial | core Bind/Add/Modify/Password Modify policy behavior, operational state, controls, migration, online configuration, chain-backed `ppolicy_forward_updates`, and OpenLDAP 2.6.13 differentials pass; native checker-module execution remains |
| retcode | partial | static/in-directory results, hidden schema, ACL, wire effects, online/restart, real config import, and slapd differentials pass; default-referral and cross-overlay matrices remain |
| rwm | partial | one- and two-argument `rwm-suffixmassage`, direct and wildcard/drop attribute/objectClass mappings, DN/nameAndOptionalUID/LDAP-URL value translation, filter/assertion translation, and relay/back-meta differentials pass; arbitrary rewrite contexts/rules, normalization controls, and remaining map flags remain |
| seqmod | partial | database/frontend singleton configuration, Add/Modify/ModifyDN/Delete and write Extended-operation serialization, disabled state, online delete/re-add/restart, cancellation/race coverage, and pinned OpenLDAP 2.6.13 configuration/basic-operation differentials pass; complete transaction, replication, and arbitrary cross-overlay ordering matrices remain |
| sssvlv | partial | RFC 2891 sorting, VLV, RFC 2696 interaction, and global/per-connection limits pass |
| syncprov | partial | cn=config gating, refresh/persist stream, configured SIDs, multi-SID cookies, `delcsn`, contextCSN checkpointing, session-log policies, Sort/VLV, glue providers, and OpenLDAP CLI interoperability pass |
| translucent | partial | database-local single-instance `olcTranslucentConfig` with one captive `olcTranslucentDatabase` LDAP target, disabled/reload/rollback validation, remote-anchored Search, whole-attribute local override, stale-local suppression, remote-only entries, complete-filter recheck, recursive local/remote split filters, Compare attribute shadow/fallback, remote-first Bind plus `bindLocal` fallback and health-preferred URI recovery, local `pwmodLocal`, `strict`, `noGlue`, root-only local-shadow Add/Modify/Delete/ModifyDN, Assertion on Add/merged Modify views, ManageDsaIT bypass, and pinned OpenLDAP 2.6.13 source-contract plus Phase 1/2 differential passes; other advanced controls, OpenLDAP's non-root Modify-through-local-ACL edge, frontend/multiple instances, and arbitrary cross-overlay ordering/side effects remain |
| unique | partial | URI and legacy config, independent domains/multiple URIs, `strict`/`ignore`/`serialize`, Add/Modify/ModifyDN, managed Relax, atomic concurrency, online/restart/rollback, real `slapcat` import, and OpenLDAP 2.6.13 differentials pass; cross-overlay ordering and auditing pre-existing duplicates remain |
| valsort | partial | alpha/numeric/weighted ordering, hidden raw control, Add/Modify validation, Paging/Sort/VLV, Sync bypass, online/restart, real `slapcat` import, and OpenLDAP 2.6.13 differential pass; global/glue and cross-overlay ordering matrices remain |
| OTP-related contrib password modules | partial | OpenLDAP pw-totp `{TOTP1}`, `{TOTP256}`, `{TOTP512}`, and all three `ANDPW` variants; fixed 30-second/six-digit credentials, current/previous-window rules, non-replicated `authTimestamp`, root/ordinary/TOTP successful-Bind timestamp updates, Password Modify hashing, database/frontend and duplicate placement, online disable/delete/restart, and a dynamically built pinned OpenLDAP 2.6.13 module differential pass; SHA-2 nested passwords are supported; ldap-go intentionally makes first-use replay prevention atomic where OpenLDAP's separate check/update can admit concurrent attempts; other unsupported nested/dynamic schemes, replication topologies, proxy databases, and arbitrary overlay ordering remain |

## Replication and operations

| Area | Status | Required evidence |
| --- | --- | --- |
| Syncrepl consumer | partial | ordered `olcSyncrepl` loading plus ldap-go, OpenLDAP 2.6.13 standard, accesslog delta, and protocol-level fake DSEE retro changelog initial/persist/restart/recovery topologies pass; tag-based Sync Info compatibility, initial-refresh timeout semantics, DIGEST-MD5 realm/authzid/server-proof handling, and schema-aware local/remote DN routing pass; real Oracle DSEE and broader provider variants remain unverified |
| Syncprov provider | partial | OpenLDAP 2.6.13 ldapsearch, overlay-order Sort/VLV, slapd consumer initial/persist/restart topology, and schema-aware context/checkpoint/tombstone/session-log state across Memory/bbolt pass; broader topology suite remains |
| Delta-syncrepl | partial | OpenLDAP and ldap-go accesslog `reqMod` replay, durable cookies, refresh fallback, purge/minCSN gap recovery, and ldap-go provider-to-consumer Add/Modify/Password Modify/ModDN/Delete topology pass; DSEE `syncdata=changelog` covers Root DSE bounds, initial/gap snapshots, LDIF Add/Modify/ModDN/Delete replay, durable `lastChangeNumber`, and Persistent Search against a protocol-level fake provider; real Oracle DSEE, attribute-level multi-provider conflicts, and broader failure topologies remain unverified |
| Multi-provider and mirror mode | partial | `olcServerID`, writable `olcMultiProvider`/`olcMirrorMode`, durable UUID tombstones, three-node relay/restart/offline conflict convergence, and OpenLDAP 2.6 bidirectional topology pass; delta attribute-level conflicts and broader failure matrices remain |
| Fractional and sparse replication | partial | attrs/exattrs, filter exit/reentry, mandatory UUID/CSN, and suffix-massage convergence pass; broader schema/topology cases remain |
| Connection and operation monitoring | partial | concurrent connection lifecycle, operation/response counters, Search/Compare/ACL/paging, and OpenLDAP 2.6.13 `cn=Monitor` differential tests pass; OS descriptor and exact worker-pool internals remain |
| Dynamic logging and runtime limits | partial | monitor Log modification behavior, database `readOnly`, operation restrictions, online enforcement, rollback, and OpenLDAP 2.6.13 differential sequences pass; dynamic logger category routing and the remaining limits remain |
| Graceful restart and zero-loss shutdown | partial | SIGINT/SIGTERM stop admission, drain accepted queued operations, preserve and durably commit in-flight writes, abandon persistent Sync, bound the drain with configurable forced cancellation, and pass timeout/race tests; SIGHUP restart, listener inheritance, and zero-downtime process handoff remain |
| `lloadd` behavior | partial | bounded BER, message-ID/final ownership, pools/scheduling/limits, ProxyAuthz, auth-only SASL pinning, affinity, Abandon/Cancel, LDAPI and recovery pass. `read_pause` suspends client reads while capacity is exhausted and resumes on capacity or disconnect; `verify_credentials` maps Simple Bind to the OpenLDAP VC exop on regular pools, fails explicitly when unavailable and rejects SASL continuation. Client/upstream TLS and service Simple/PLAIN/CRAM/DIGEST/SCRAM plus keepalive/TCP user timeout are covered. Trusted `pldap://`/`pldaps://` listeners parse PROXY v2 TCP4/TCP6/LOCAL before LDAP and before implicit TLS, retain logical/transport addresses, consume bounded opaque options, and expose valid TLVs best-effort without rejecting malformed option encoding; ordinary LDAP/LDAPS reject the header. VC requires ProxyAuthz; PROXY v1, UDP/UNIX families, GSSAPI, VC SASL continuation/cookies/security layers, true isolate pools, dynamic topology, config/monitor, and complete daemon parity remain |

## Command-line compatibility

| Area | Status | Required evidence |
| --- | --- | --- |
| Server daemon and config validation | partial | lifecycle and config diagnostics |
| `slapadd` / `slapcat` equivalents | partial | `slapadd` supports `-l/-b/-n/-c/-g/-q/-s/-u/-S/-w` and `-o schema-check=yes\|no` / `value-check=yes\|no`; `slapcat` supports `-l/-b/-n/-g/-s` for the tested subset. Default-primary and explicit selection, glue-subordinate import/export, backend callback policy, schema/options/normalizer, LastMod/CSN, root and `olcSyncUseSubentry` context, atomic `cn=config`, dry-run, round-trip, and exit-code cases pass. Without `-c`, import and the direct API remain atomic. Content `-c` depth-batches records, retries a failed batch individually, retains successes, reports record failures, exits nonzero on partial failure, supports disposable `-c -u`, and rejects `cn=config`. `-q` disables value checking only; schema checking remains independently controlled by `-s` / `schema-check=no`, and `objectClass` remains required. Parsing, routing, hierarchy, and storage consistency still run, and quick mode warns and disables explicit `value-check=yes`. Exact OpenLDAP batching/diagnostics, native backend-file behavior, broader `-c` dependency cases, and historical-option parity remain unsupported |
| Offline database check/rebuild equivalents | partial | validated atomic bbolt check/compact commands, aliases, round trips, corruption rejection, and exit-code tests pass; OpenLDAP tool output parity and secondary-index formats are inapplicable to bbolt |
| `slaptest` / `slapdn` equivalents | partial | strict read-only database/config/schema validation, normalized/pretty DN output, multi-DN handling, option validation, no-create behavior, and exit-code tests pass; exact diagnostic formatting and the full slapd.conf conversion surface remain |
| `slappasswd` equivalent | partial | `{SSHA}`, all six contrib SHA-2 schemes, all four contrib PBKDF2 schemes, `{APR1}`, `{BSDMD5}`, `{SM3}`, `{SSM3}`, `{PBKDF2-SM3}`, and all six pw-totp schemes, stdin/file/argument/random input, newline control, secret clearing, unsupported `{CRYPT}` rejection, verify-only `{NS-MTA-MD5}` and `{RADIUS}` rejection, and option/exit-code tests pass; other OpenLDAP module-provided schemes remain |
| LDAP client tools | partial | built-in search/whoami/compare/passwd/exop/write/delete/modrdn cover simple/SASL Bind, LDAP/LDAPS/StartTLS, LDIF, controls and referral chasing. `ldapsearch` adds bounded `-f` batch filters with `%s`, `-F` file-URL prefixes, secure `-t/-T` value files, critical paging, client-side `-S` attribute or UFN-component sorting, and `-u` UFN output. Paging is sorted page by page, not globally. The covered OpenLDAP UFN forms omit attribute types, join multi-AVA RDNs, fold trailing `dc` RDNs into a dotted domain, emit escaped bytes as uppercase hexadecimal, and preserve hexadecimal BER AVAs. Prompt/critical paging with referral chasing is explicitly rejected; arbitrary locale-dependent ordering is not claimed. `ldapcompare` sends generic `-e` and `-M`/`-MM` ManageDsaIT controls through a raw Compare path with referrals and SASL PLAIN; historical Compare `-E` remains rejected. `ldapexop passwd` reuses `ldappasswd` password sources/options, controls, generated-password decoding, and dry-run behavior. Auth-only SASL supports PLAIN/CRAM/DIGEST/SCRAM/EXTERNAL. GSSAPI, channel binding/security layers, `-c`, repeated `-tt`, interactive SASL, complete referral rebind behavior and full historical options remain |
| Load balancer tooling | partial | `ldap-go lloadd` parses standalone OpenLDAP-style configuration, validates the runnable subset and rejects unsupported settings with `-test-config`, serves multiple LDAP, LDAPS, StartTLS, escaped-authority/three-slash LDAPI, and PROXY-v2 `pldap`/`pldaps` listeners, exposes listener/log and certificate/key overrides, maps config-file upstream LDAPS/StartTLS, service SASL, keepalive, and TCP user-timeout settings, and is exercised by unit, race, TLS/PROXY topology, pinned-source, and live OpenLDAP 2.6.13 tests. A PROXY command strictly parses TCP4/TCP6 addresses; PROXY and LOCAL consume up to 520 bytes of opaque options, LOCAL ignores family, and valid PROXY TLVs are exposed best-effort without rejecting malformed option encoding. PROXY v1 and non-TCP families for the PROXY command, the historical daemon option/signal/logging surface, embedded slapd-module mode, and runtime config/monitor administration remain unsupported |

## Implemented subset evidence

The first runnable subset includes bounded BER framing; LDAPv3 anonymous/simple
Bind; Root DSE; base, one-level, and subtree Search; boolean, equality,
presence, substring, ordering, approximate, and basic extensible filters;
Unbind; Add, Modify (including increment), leaf Delete, subtree ModifyDN,
Compare; a transactional bbolt backend; and atomic content LDIF import/export.
Content naming uses a schema-aware v2 DN identity rather than a global
case-fold. Each AVA resolves aliases and numeric OIDs to its canonical
attribute and applies that attribute's equality rule. Multi-AVA RDNs reject a
canonical attribute repeated through aliases/options, sort AVAs in OpenLDAP
order, and preserve caseExact distinctions while folding caseIgnore values.
`NormalizedString()` supplies canonical LDAP text to regex, SQL, and protocol
paths; the opaque `dn:v2:` key remains storage-only. Legacy v1 entries remain
readable and are lazily rewritten on successful replace/delete operations.
Memory and bbolt tests cover equivalent aliases/OIDs and fail-closed ambiguous
legacy/v2 records; `cn=config` keeps its established legacy identity because
its ordered configuration RDNs are not content-schema DNs.
StartTLS and implicit LDAPS use a shared pluggable secure-transport interface;
the standard TLS adapter requires TLS 1.2 or newer, publishes the StartTLS OID,
and resets an authenticated connection to anonymous after a successful upgrade.
The GB/T 38636 TLCP adapter requires separate SM2 signing/encryption
certificates and has an end-to-end LDAP Bind/Search test fixed to
`ECC_SM4_GCM_SM3`. It intentionally does not claim RFC 8998 TLS 1.3
compatibility.
When no explicit transport configuration overrides it, the supported global
`olcTLS*` attributes build that TLS context from inline DER/PEM or file-backed
certificate, key, and CA material. Online replacement publishes the candidate
context only after the configuration transaction commits. New LDAPS and
StartTLS handshakes receive the rotated certificate while established
connections retain their original state; invalid material and unsupported
directives roll back both storage and runtime publication.
Verified standard TLS and TLCP client certificate chains expose their
normalized Subject DN to SASL EXTERNAL. Root DSE publishes EXTERNAL only on a
connection with such an identity. Empty authorization identities bind as the
certificate DN; non-empty authorization identities use the shared OpenLDAP
proxy authorization policy. Tests cover EXTERNAL root authorization, Who Am
I, simple-Bind state replacement, and both implicit TLCP and
StartTLS-to-TLCP paths.
SASL PLAIN authenticates mapped directory entries through the same
`userPassword` and `auth` ACL path as simple Bind. For back-ldap/back-meta
entries, PLAIN and the other password-based mechanisms perform isolated remote
auxprop searches without changing the frontend Bind state. Back-ldap prefers
`olcDbACLBind` and falls back to IDAssert when its bind method is `none`;
back-meta uses the selected target's IDAssert configuration and maps request
and response namespaces. Infrastructure failures return OpenLDAP-compatible
`other(80)` with an empty diagnostic while keeping the frontend connection
usable. Root DSE publishes PLAIN only
when `olcSaslSecProps` permits it for the connection's TLS, TLCP, or Unix
external SSF, or when `noplain` is disabled. `olcSaslRealm` and ordered
`olcAuthzRegexp` rules support direct DN and local LDAP URL mappings across
local and proxy backends; URL searches require exactly one result and
OpenLDAP-compatible privileged auth-check access.
Self and database-root authorization plus `olcAuthzPolicy`, hidden ordered
`authzTo`, and `authzFrom` rules are shared by all implemented SASL
mechanisms.
CRAM-MD5 follows Cyrus SASL's server-first exchange, 1024-byte input bound,
lowercase HMAC-MD5 response, self authorization, and `olcSaslHost` challenge
format. It shares the identity mapping and anonymous `auth` ACL path but
requires a raw or `{CLEARTEXT}` password; one-way hashes cannot provide its
HMAC key. Tests cover configured-host challenges, malformed initial data,
wrong and hashed passwords, ACL denial, and OpenLDAP `ldapwhoami`
interoperability.
DIGEST-MD5 implements the bounded RFC 2831 directive grammar, Cyrus
nonce/realm challenge, nonce-count and LDAP digest-URI validation, historical
Latin-1 fallback, constant-time response verification, and mutual `rspauth`.
Credential lookup accepts ACL-visible raw or `{CLEARTEXT}` passwords and the
legacy binary `cmusaslsecretDIGEST-MD5` attribute. The RFC digest vector,
malformed parser cases, all credential forms, ACL denial, independent
`go-ldap`, and OpenLDAP Cyrus clients pass. Only `qop=auth` is advertised;
`auth-int`, `auth-conf`, and fast reauthentication remain pending.
SCRAM-SHA-1/256/512 use a connection-scoped multi-round Bind state and reject
interleaved operations as OpenLDAP does. Credential lookup accepts ACL-visible
raw or `{CLEARTEXT}` `userPassword` values and Cyrus-compatible
`authPassword` StoredKey/ServerKey records. Imported one-way `userPassword`
hashes cannot supply SCRAM verifier keys. Tests cover absent initial responses,
server proofs, all three hashes, malformed credentials, ACL denial, and
OpenLDAP SCRAM-SHA-256 interoperability. SCRAM-PLUS and negotiated SASL
integrity/privacy layers remain pending.
Network Add generates `entryUUID`, `entryCSN`, creator/modifier names, and
create/modify timestamps, `structuralObjectClass`, and `subschemaSubentry`.
Modify and ModifyDN update modification metadata.

RFC 5805 transactions advertise the Start Transaction and End Transaction
extended operations plus the Transaction Specification control. The wire codec
accepts OpenLDAP's explicitly present zero-length transaction identifier and
strictly validates transaction end request and response values. A connection
queues Add, Modify, Delete, ModifyDN, and Password Modify without holding a
database lock. If Password Modify omits the new password, ldap-go generates it
once while admitting the operation, returns it in that operation's immediate
RFC 3062 response, and stores the same generated value in the queued request.
End Transaction commit replays the ordered queue through one storage writer, so
later operations observe earlier ones and any operation failure rolls back
entries, metadata, runtime changes, and Sync publication. The failure result,
original update message ID, and update response controls are returned in
`txnEndRes`. RFC 5805's `txnEndRes` has no field for an update ExtendedResponse
value, so a generated password cannot conformingly be moved to End Transaction.

The queue defaults to at most 1000 operations and 16 MiB of re-encoded retained
requests. `Config.MaxTransactionOperations` /
`Config.MaxTransactionQueuedBytes` and the corresponding
`-transaction-max-operations` / `-transaction-max-queued-bytes` flags configure
lower or higher positive bounds; zero selects the Go API defaults. Crossing a
bound clears all retained values and sends an unsolicited ExtendedResponse with
message ID zero, result `adminLimitExceeded`, response name `1.3.6.1.1.21.4`,
and an explicitly present transaction identifier. Explicit abort discards the
queue normally. Bind, Unbind, and connection close abort without notice, as RFC
5805 requires. A transaction is restricted to one storage partition;
configuration writes and cross-database operations are rejected.

OpenLDAP 2.6.13 `ldapmodify -E txn=commit/abort` interoperates with ldap-go.
Raw BER differentials against slapd verify duplicate-Add failure ordering,
failed message ID reporting, full rollback, and Bind's no-notice abort. A pinned
source and wire test also records an OpenLDAP 2.6.13 limitation: its transaction
control is registered only for update protocol operations, so transactional
Password Modify is rejected with `unavailableCriticalExtension` before the
transaction branch in `passwd.c` is reached. ldap-go implements the RFC 5805
Password Modify combination instead of copying that unreachable behavior. Like
OpenLDAP 2.6.13, pre-read and post-read controls remain rejected in a
transaction. Each queued update captures its effective proxied identity; the
proxy control is unavailable on Start and End Transaction themselves.

RFC 6171 Don't Use Copy is advertised in Root DSE and accepted on Search and
Compare only. The control requires an absent value; duplicate or valued
controls return `protocolError`. Matching OpenLDAP's default behavior,
non-critical requests are also honored unless
`olcDisallows: dontusecopy_non_critical` rejects them with OpenLDAP's
`protocolError` diagnostic.
Authoritative databases, including writable multi-provider databases, answer
normally. A single-provider shadow Search rejects before alias dereferencing,
filtering, Sync setup, or other copied-data processing and returns a
request-DN/scope-rewritten `olcUpdateRef`; without one it returns
`unwillingToPerform`. Shadow Compare returns `unwillingToPerform` with
`copy not used`, matching slapd MDB. Imported LDAP-form `olcUpdateRef` values
are validated with OpenLDAP's global-referral restriction: DN, attribute,
scope, and filter URL components are forbidden, while non-LDAP URIs remain
valid. OpenLDAP `ldapsearch -E '!dontUseCopy'` interoperability and raw BER
differentials cover criticality, invalid values, broken aliases, named
referrals, URL rewriting, and Compare. With an active chain overlay, shadow
referrals are sent through its configured remote backend.

OpenLDAP's database-local `constraint` overlay loads ordered
`olcConstraintAttribute` values and rejects duplicate or frontend instances.
The `regex`, `negregex`, and byte-oriented `size` rules validate Add values and
Modify/ModifyDN add-or-replace values; `count` evaluates the complete value
count after a modification sequence. Local `ldap:///` URI rules run an
unlimited internal search with the requester's ACL identity, while
`restrict=` base/scope/filter matching is evaluated as the database root.
ACL set expressions support `this`, `user`, literals, union, intersection,
concatenation, parent traversal, `/` and `->` attribute paths, transitive
chasing, numeric OIDs/options, and local LDAP URL gathers. Chased values use
their equality-rule normalized forms, matching slapd's `a_nvals` behavior.
Operational attributes, pure deletes outside count bookkeeping, Relax
operations, and replicated shadow updates bypass the same checks as slapd.
Configuration changes validate schema/filter references atomically, roll back
on error, and survive restart. TCP tests cover all rule types, restrictions,
transaction rollback, Rename and Relax; a gated OpenLDAP 2.6.13 fixture runs
the same operation sequence against both servers. Ordering interactions with
other overlays and locale-specific POSIX regular-expression behavior remain
for a broader differential matrix.

OpenLDAP's single-instance `collect` overlay accepts ordered
`olcCollectInfo: "<template DN>" <attribute>,...` values on both a data
database and the frontend. Template DNs are normalized for duplicate checks;
rules run by descending normalized-DN string length with stable order for
equal lengths. Every matching ancestor contributes equality-normalized values
to the final Search response, including duplicates from local values,
overlapping rules, or repeated configured attributes. A template does not
project onto itself, and a missing template has no effect. Database values are
appended before frontend values.

The projection is intentionally later than filter, Compare, and Sort
evaluation. Requested attributes, `1.1`, `+`, `typesOnly`, paging, VLV,
ManageDsaIT, template and target entry/attribute/value ACLs, and valsort then
operate on the appropriate stored or response view. This mechanism is separate
from RFC 3671 collective attributes, which remain logical values visible to
filters and Compare. Configuration Add/Modify/Delete, replacement rollback,
overlay deletion, duplicate rejection, and restart are tested. Like slapd,
`collect` does not intercept Add, ModifyDN, or Delete. Descendant Modify returns
`unwillingToPerform (53)`. Unlike OpenLDAP 2.6.13, ldap-go examines every
modification instead of only the first and compares the base attribute type so
an option such as `description;lang-en` cannot bypass a configured
`description` rule. The stable differential hard-asserts both upstream bypasses
and ldap-go's rollback-preserving fixes. Projection of backend-synthesized
operational attributes and broader glue, proxy, replication, and overlay-order
combinations remain outside the current claim.

The `nestgroup` overlay loads multiple database or frontend instances with
independent member/memberOf attributes, group bases, flags, and disabled state.
Search expands response values only when the relevant attribute is requested.
Positive equality filters are expanded through the nested graph; equality
assertions below an odd number of NOT operators remain unchanged and trigger a
full response-entry filter recheck only when value projection is active. This
preserves OpenLDAP's requested-attribute and `typesOnly` behavior. Compare reads
stored values, and ManageDsaIT bypasses the overlay entirely.

Traversal de-duplicates cycles, self-cycles, overlapping bases, and duplicate
paths. Parent discovery for member/memberOf value traversal uses the requester's
Search ACL where slapd performs an internal search, while memberOf-filter child
entry lookup follows slapd's ACL-bypassing entry-get path; final candidate ACLs
still apply. The request-scoped graph is isolated per storage partition and
bounded to 100,000 entries, 500,000 edges, depth 256, and 100,000 expanded
values. Exceeding a bound returns `adminLimitExceeded`; these explicit bounds
are a hardening difference from slapd. Imported custom configuration attributes
are retained rather than reproducing OpenLDAP 2.6.13's observed
`slapd.conf`-to-`slapd.d` custom-attribute loss.

Database `olcLimits` now applies exact bound-DN `size.soft` and `size.hard`
rules before paging state is created. An absent client size limit uses soft;
a requested value is retained when smaller and clamped by hard when larger;
database roots bypass subject rules. Other OpenLDAP selectors and time,
unchecked, and paged-results-specific limit fields remain outside this claim.

OpenLDAP's database-local `unique` overlay loads both current
`olcUniqueURI` domains and the legacy `olcUniqueBase`, `olcUniqueAttribute`,
`olcUniqueIgnore`, and `olcUniqueStrict` attributes. Local LDAP URLs support
base selection, one/subtree/children scope, attribute lists, multiple URLs per
domain, and schema-aware filters. `strict`, `ignore`, and `serialize` keywords
follow slapd's accepted ordering; configuration rejects remote URLs, base
scope, out-of-database DNs, undefined schema references, legacy/URI mixing,
and noncanonical filters. Add, non-delete Modify values, and new ModifyDN RDN
values are checked using equality matching rules while operational attributes
are excluded. Relax bypass requires `manage` access, and replicated shadow
updates use the replication path that bypasses client overlays. Memory and
bbolt writes already serialize their transaction boundary, so uniqueness is
atomic even without the optional `serialize` keyword. Online changes roll back
on validation errors and survive restart. Concurrent TCP writes, real
`slapcat -n 0` configuration import, and a same-sequence OpenLDAP 2.6.13 slapd
differential pass. Like slapd, enabling the overlay does not retroactively scan
or repair duplicate values already present.

OpenLDAP's single-instance `valsort` overlay loads ordered
`olcValSortAttr` values in the `<attribute> <dn> <sort-type> [secondary]`
form. Alpha and numeric ascending/descending rules use the attribute's
normalized equality value; numeric rules are restricted to Integer and
Numeric String syntax. Weighted rules parse C-style base-zero integer prefixes,
sort by weight with an optional secondary rule, and remove the prefix from
Search responses. Add and Modify reject missing or malformed weights with the
same result codes and diagnostics as slapd. Existing malformed data retains
slapd's observable partial-prefix-removal behavior, and rules for single-valued
attribute types are accepted but ignored.

Sorting is response-only and leaves stored and exported values unchanged. The
hidden `1.3.6.1.4.1.4203.666.5.14` control selects raw values, is parsed with
strict BER handling, and is intentionally omitted from Root DSE
`supportedControl`. LDAP Sync responses bypass the overlay. Ordinary Search,
sorted paging, and both initial and context-backed VLV windows apply the same
rule set. Online configuration changes validate atomically, roll back on
failure, and survive restart. A process-level OpenLDAP 2.6.13 differential
covers ordering, raw values, weight validation, single-value prefix removal,
and hidden-control discovery; a separate `slaptest -> slapcat -n 0` fixture
imports the generated `olcValSortConfig` entry unchanged and verifies runtime
behavior. Global/frontend overlays, glued multi-database searches, and ordering
against other response-rewriting overlays still need broader differentials, so
the row remains `partial`.

OpenLDAP's `retcode` overlay loads `olcRetcodeParent`, ordered
`olcRetcodeItem`, `olcRetcodeInDir`, and `olcRetcodeSleep` configuration. Static
items accept OpenLDAP's C base-zero result codes, operation masks and aliases,
diagnostic text, matched DNs, referrals, fixed or randomized delays,
unsolicited responses, and pre/post-response disconnects. Their synthetic
`errObject` entries support base, one-level, and subtree behavior, schema-aware
filters, size limits, entry/attribute/filter ACLs, requested attributes, and
`typesOnly`. Successful synthetic Bind also establishes the requested
authorization identity, matching slapd.

The hidden `errAbsObject`, `errObject`, and `errAuxObject` schema plus all eight
`err*` attribute types are available for stored in-directory responses without
being published by `cn=Subschema`. Add, Bind, Compare, Delete, Modify,
ModifyDN, Search, Password Modify, and Dynamic Refresh exercise the same
stored-entry response path. Result-zero fallthrough, referral precedence,
ManageDsaIT's operation-specific OpenLDAP behavior, base-zero stored codes,
unsolicited data, and abrupt disconnects are covered. Online configuration
updates validate and roll back atomically, survive restart, and accept a real
`slaptest -> slapcat -n 0` `olcRetcodeConfig` entry unchanged. Process-level
OpenLDAP 2.6.13 differentials cover static and in-directory operation results,
synthetic-search ACLs, successful Bind identity, and stored-value parsing.

OpenLDAP 2.6.13 emits an invalid duplicate response sequence for an
in-directory Extended operation; common Go clients report an unexpected
response. ldap-go intentionally returns one protocol-valid ExtendedResponse
instead. Global `olcReferral` fallback for a referral item without `ref`,
multiple/frontend instance ordering, glued searches, and composition with
other controls and overlays still need broader parity tests, so the row remains
`partial`.

OpenLDAP's database-local `memberof` overlay loads multiple
`olcMemberOfConfig` instances and supports `olcMemberOfDN`, all three dangling
reference modes and configurable result codes, `olcMemberOfRefInt`,
`olcMemberOfAddCheck`, and custom group/member/memberOf schema identifiers.
The standard `memberOf` operational attribute is built in and protected from
client writes. Group Add and Modify maintain reverse membership; group Delete
and individual group/member ModifyDN repair the corresponding references.
Member Delete and ModifyDN update groups when `olcMemberOfRefInt` is enabled.
Relax bypasses dangling checks, self references are ignored, and AddCheck
discovers groups that predate a newly added member.

The built-in core schema includes `member`, `uniqueMember`, `groupOfNames`,
`groupOfUniqueNames`, and their standard optional group attributes. Name And
Optional UID validation and `uniqueMemberMatch` follow OpenLDAP's trailing
BitString detection and DN normalization. A `groupOfUniqueNames` differential
also covers Compare, AddCheck, and member ModifyDN. As documented by OpenLDAP's
memberof implementation, a `uniqueMember` value with an actual optional UID is
valid and matchable but is not resolved as a member DN; it therefore does not
gain `memberOf` or follow that entry's ModifyDN. Values without the optional UID
participate normally.

The database-local `refint` overlay loads multiple `olcRefintConfig` instances,
tokenizes all `olcRefintAttribute` values, and honors `olcRefintNothing` and
`olcRefintModifiersName`. Delete and ModifyDN repair exact references, while a
non-leaf ModifyDN also preserves relative names below the renamed subtree.
Unlike slapd's queued best-effort repair, ldap-go performs these dependent
updates in the initiating storage transaction, so a storage failure rolls the
whole write back. Internal repairs do not create separate CSNs or Sync events,
matching the overlay's non-replicated internal modifications.

Online configuration validation is atomic, survives restart, and accepts real
`slapcat -n 0` entries unchanged. TCP lifecycle tests and same-operation
OpenLDAP 2.6.13 differentials cover the normal result and data states. Global
overlay instances, cross-overlay order, replicated provider/consumer
configurations, and injected dependent-update failures need broader parity
tests, so this row remains `partial`.

RFC 2589 and OpenLDAP's DDS overlay are enabled per database by
`olcOverlay=dds`. The runtime loads `olcDDSstate`, maximum, minimum, and default
TTL, expiration interval and tolerance, and the dynamic-object count limit.
Dynamic Add rejects aliases and referrals, prevents static children below a
dynamic parent, generates `entryTtl` plus the hidden
`entryExpireTimestamp`, and enforces the count limit in the storage write
transaction. Modify cannot convert between static and dynamic entries, direct
client modification of lifetime attributes is rejected, and ModifyDN cannot
move a static entry below a dynamic new superior.

Refresh uses strict RFC 2589 BER, applies the configured min/max TTL, requires
`manage` access to `entryTtl`, updates LastMod/CSN metadata atomically, and
returns the effective client refresh period. Search projects remaining TTL
without rewriting the stored refresh value. A server-lifecycle worker honors
the configured interval and tolerance, deletes expired entries deepest-first,
defers non-leaf parents, resumes from persisted expiration timestamps after
restart, and publishes syncprov deletes. Canonical slapcat LDIF preserves
`dynamicObject`, `entryTtl`, and OpenLDAP's private
`entryExpireTimestamp`; the private attribute is accepted by schema but omitted
from Subschema publication.

Root DSE publishes enabled suffixes through `dynamicSubtrees`. OpenLDAP loads
Refresh with `SLAP_EXOP_HIDE`, so neither slapd nor ldap-go lists its OID in
`supportedExtension`; clients can issue the operation directly. With
`olcDDSstate: FALSE`, the object class remains accepted but no lifetime is
generated or managed. OpenLDAP 2.6.13 differential tests cover Add, Search,
Refresh, Modify, ModifyDN, limits, disabled state, and parent/child expiration;
the OpenLDAP `ldapexop refresh` client interoperates with ldap-go. Complex
ordering with other overlays and replicated DDS exclusion topologies remain
pending.

The schema registry parses OpenLDAP `{n}`-ordered `olcAttributeTypes` and
`olcObjectClasses`, applies object-class and syntax checks to writes, and uses
registered matching rules for Search and Compare. Root DSE discovery and the
read-only `cn=Subschema` entry publish built-in and imported definitions.
Attribute selection distinguishes user attributes (`*`) from operational
attributes (`+`).

OpenLDAP `{n}`-ordered `olcDitContentRules` values load after their custom
attribute types and object classes. Rules are indexed by the exact structural
object class, published as `dITContentRules` in `cn=Subschema`, and enforce
their auxiliary-class allowlist plus `MUST`, `MAY`, `NOT`, and `OBSOLETE`
semantics on Add and Modify. Registration rejects unknown/non-auxiliary classes,
unknown or operational attributes, conflicting lists, and duplicate rules.
Online replacement is atomic and rolls back invalid configuration; restart
reloads the persisted rule. A generated OpenLDAP
`slaptest -> slapcat -n 0` entry imports unchanged, and process-level
differentials match slapd result codes and diagnostics. OpenLDAP 2.6 does not
expose writable `cn=config` fields or slapd registration/enforcement paths for
name forms or DIT structure rules: it declares the hidden subschema attributes
and provides client-side `libldap` parsers only. ldap-go additionally implements
RFC 4512 Name Form and DIT Structure Rule descriptions in its base schema
registry. It validates structural-class and naming-attribute dependencies,
rejects duplicate, missing, and cyclic rule hierarchies, publishes `nameForms`
and `dITStructureRules`, and implements their RFC 4517 first-component matching
rules. Add, Modify, and ModifyDN enforce RDN `MUST`/`MAY` sets and `SUP`
relationships transactionally, maintain the protected
`governingStructureRule` operational attribute, and return `namingViolation`
on failure. The Relax control can bypass these additional naming constraints.
These definitions can be supplied through the server's base schema registry;
they are deliberately not represented as fictional OpenLDAP `olc*` fields.

RFC 3296 `ref` and `referral` schema definitions are built in, and
ManageDsaIT is advertised through Root DSE `supportedControl`. Without the
control, a base referral returns result code 10 with matched DN and rewritten
LDAP URLs; one-level and subtree searches emit application tag 19
SearchResultReference responses independently of the search filter. Requests
below a referral replace the local referral suffix with the URL DN, preserve
an explicit URL scope, and otherwise add OpenLDAP-compatible `base`, `one`, or
`sub` scope fields. URI labels are removed before transmission, while non-LDAP
URIs are preserved.

ManageDsaIT makes an exact referral entry visible to Search and manageable by
Modify, Delete, ModifyDN, Compare, and Password Modify. Add, Modify, Delete,
ModifyDN, Compare, base/subtree Search, missing descendants, one-level scope,
duplicate controls, and forbidden control values have TCP or unit coverage.
Adding a child below a referral still returns a referral because the referral
DSE is not a naming context for local descendants. Process-level differential
tests against OpenLDAP 2.6.13 cover result codes, matched DNs, URL DN/scope
rewrites, SearchResultReference behavior, and managed updates.

RFC 4512 `alias` and `aliasedObjectName` schema definitions are also built in.
Search implements `neverDerefAliases`, `derefInSearching`,
`derefFindingBaseObj`, and `derefAlways`, including recursive alias chains,
base DNs below an alias, target-DN SearchResultEntry names, and expansion of
one-level or subtree search scopes outside the original subtree. The base alias
is retained when only searching aliases are dereferenced, matching OpenLDAP.
Broken and circular aliases fail base resolution with alias result codes and
matched DNs but are ignored while expanding search scopes. The per-database
`olcMaxDerefDepth` setting is loaded from `cn=config` and defaults to 15.
Exact target scopes are coalesced while overlapping target subtrees remain
distinct, preserving OpenLDAP MDB's observable duplicate-entry behavior.
Paging, server-side sorting, VLV, Add-parent, ModifyDN-superior, ordinary
Modify/Compare/Delete, and Bind rejection have TCP coverage. Process-level
OpenLDAP 2.6.13 differentials cover all four modes, base descendants, broken
targets, loops, and overlapping scopes. One intentional edge-case difference
is recorded: after a positive `olcMaxDerefDepth` is exceeded, OpenLDAP 2.6.13
MDB can emit success with a matched DN and the diagnostic `maximum deref depth
exceeded` because a successful intermediate lookup overwrites result code 36.
`ldap-go` consistently returns `aliasDereferencingProblem` (36) for that
failure. Referral chasing is handled by an imported `chain` overlay.

RFC 3672 `subentry`, `subtreeSpecification`, and `administrativeRole` schema
definitions are built in, and the Subentries control is advertised through
Root DSE. Without the control, one-level and subtree searches omit subentries
while base searches retain them. A TRUE value returns only subentries and a
FALSE value only normal entries for all ordinary database searches. Control
values use OpenLDAP-compatible strict three-octet BER validation; absent,
malformed, and duplicate values return `protocolError`.

Visibility is enforced before the user filter, referral handling, and read
ACLs, and therefore composes with alias routes, RFC 2696 paging, sorting, and
VLV candidate construction. Subentries cannot be used for Bind, and Add
rejects a subentry parent with `objectClassViolation`. Modify, Compare,
ModifyDN, and Delete of the subentry itself remain ordinary operations.
OpenLDAP 2.6.13 MDB also permits ModifyDN to move an existing normal entry
under a subentry even though direct Add at the same DN is rejected; `ldap-go`
preserves that observable edge behavior. The synthetic `cn=Subschema` entry
publishes `subentry` and `structuralObjectClass: subentry`, and, like OpenLDAP's
frontend special entry, remains base-searchable regardless of a FALSE
Subentries control. Process-level differentials cover base, one-level, and
subtree visibility, TRUE/FALSE values, special entries, malformed values,
Bind, and parent rules.

RFC 3671 support builds on a strict RFC 3672 GSER parser for subtree bases,
specific exclusions, minimum/maximum depth, and object-class refinements. The
13 standard `c-*` attribute types and the collective system schema are built
in. A collective-attribute subentry contributes values to normal entries in
its scope; values from multiple sources are merged and deduplicated using
schema equality rules. `collectiveExclusions`, including
`excludeAllCollectiveAttributes`, suppress values without hiding the generated
`collectiveAttributeSubentries` source references.

Derived values exist only on the logical entry assembled inside a read
transaction. They are evaluated before filters, Compare, Assertion, read
controls, paging, sorting, and ACL `dnattr` checks, and are never written back
to member entries. Members cannot add or modify collective values or generated
source references, while a source-subentry update becomes visible
immediately. TCP tests cover these paths as well as multi-source propagation
and optioned attributes. An imported malformed subtree specification remains
readable but cannot define a propagation scope.

OpenLDAP 2.6 keeps its collective schema behind a development build option and
does not provide mainline value propagation suitable for process
differentials. X.501 specific/inner administrative-area boundary nesting and
DIT content-rule interaction also remain pending. The feature therefore
remains `partial`.

RFC 4533 LDAP Sync is advertised only when the target runtime contains an
OpenLDAP `syncprov` overlay. Overlay loading follows the database parent in
`cn=config`, rejects duplicates, and requires `olcLastMod: TRUE`. The request,
state, done, and info values use strict BER codecs, including default Boolean
handling and exact 16-byte wire UUIDs. Sync searches reject
`derefInSearching` and `derefAlways`, paged-results combinations, duplicate or
malformed controls, and unsupported critical target contexts.

`refreshOnly` takes one storage snapshot. A new consumer receives entries with
Sync State `add`; a returning consumer receives changed entries plus chunked
`syncIdSet` present UUIDs, allowing it to infer deletions. Cookies use
OpenLDAP's `rid=...,csn=...` layout, add `delcsn=...` when a delete set needs
its exact change CSN, and preserve one context CSN per server ID.
`olcServerID` accepts OpenLDAP's decimal, `0x` hexadecimal, and
`<ID> <listener-URL>` forms. URI-qualified values select exactly one local
listener; multi-provider databases require a non-zero SID. The selected local
SID context is committed atomically with each successful
Add/Modify/Password Modify/Delete/ModifyDN and survives restart, including
delete-only progress. Legacy stores containing a single SID 000 metadata value
upgrade in place to a durable multi-SID context vector.

`olcSpCheckpoint` writes the current SID-sorted context vector to the first
database suffix after either its committed-operation threshold or elapsed
minute threshold. The counter and timestamp are transactional metadata, and
the internal suffix update does not create another CSN or Sync event.
`olcSpSessionlog` retains the configured number of committed non-Add changes
in a provider-local memory window while retaining each change's actual data
partition. A covered cookie receives entries first, followed by disappearing
UUIDs with `refreshDeletes=TRUE` and progressive cookies carrying each delete
batch's exact `delcsn`, including filter and scope exits. Adds are recovered
from the normal entry scan. An evicted, incomplete, or not-yet-published
window falls back to Present processing.

Without a configured session log, `olcSpNoPresent: TRUE` suppresses Present
processing and marks the refresh as delete-based, matching the upstream
setting's documented log-database-only contract. With
`olcSpReloadHint: TRUE`, a stale cookie that cannot be anchored by any retained
entry CSN receives `syncRefreshRequired` unless the request sets `reloadHint`;
with the hint, the cookie is discarded and a full refresh is returned.

For ordinary operations, the provider dynamically replaces any stored
`contextCSN` copy on the first database suffix with the current, SID-sorted
vector. Search exposes it when explicitly requested or selected by `+`;
Compare and RFC 4527 pre/post-read controls use the same live value. `*` does
not select it, and clients cannot add or modify it. RFC 4533 responses strip
`dSAOperation` attributes, including `contextCSN`, so provider-local state is
not synchronized as entry content. The built-in OpenLDAP CSN syntax validates
both `entryCSN` and `contextCSN`, including normalization of the OpenLDAP 2.3
no-fraction/two-digit-SID form.

For a glued tree, every data route resolves an effective provider within its
own glue hierarchy. A syncprov directly attached to a subordinate database
wins; otherwise the nearest syncprov ancestor, including the primary database,
owns the context, checkpoint, session log, and persistent subscription. This
matches OpenLDAP's common single-primary-provider and per-branch-provider
layouts. Independent naming contexts do not inherit a provider merely because
their suffix is textually below another database. Entry reads and scope checks
continue to use the actual data partition, so a primary provider can refresh
and stream the complete glued tree without merging backend storage.

`refreshAndPersist` subscribes before taking its refresh snapshot, then emits
full add/modify entries, empty delete entries, and new-cookie intermediate
responses for changes outside the filter. Filter-entry and filter-exit
transitions become add and delete respectively. Abandon and RFC 3909 Cancel
stop the operation; a changed search base or an overflowing bounded event
queue terminates it with `syncRefreshRequired` (4096). Collective values are
not synchronized onto member entries. TCP tests cover these paths, and the
pinned OpenLDAP 2.6.13 `ldapsearch -E !sync=ro` client is run as an optional
process-level interoperability test. A real OpenLDAP 2.6.13 syncrepl consumer
also converges from an empty MDB, applies persistent Add/Modify/Delete events,
and catches up through the same cookie after it is stopped, provider changes
accumulate, and the consumer restarts.

The ldap-go syncrepl consumer parses ordered `olcSyncrepl` values into an
immutable runtime configuration, including search, fractional attribute,
retry, bind, timeout, TLS, suffix-massage, and delta-related fields. Duplicate
RIDs, invalid local bases, malformed filters, and incomplete retry or delta
settings fail `cn=config` validation. Workers start and stop with `Serve`, and
online configuration replacement cancels the previous partition/RID worker
before starting its replacement. Online tests add a consumer to a running
database, reject and roll back an invalid replacement while the old worker
continues, stop it by deleting `olcSyncrepl`, and re-enable it to catch up.

Standard RFC 4533 consumption supports refresh-only and
refresh-and-persist, provider URI failover, simple bind, StartTLS/LDAPS, SASL
EXTERNAL, PLAIN, CRAM-MD5, DIGEST-MD5, GSSAPI, and SCRAM-SHA-1/256/512,
Present/Delete UUID sets, DN suffix massage, and durable opaque cookies.
The consumer decodes Sync Info optional fields by ASN.1 tag through a bounded
connection adapter, accepting legal OpenLDAP encodings that omit the cookie or
default Boolean. For refresh-and-persist, `timeout=` is enforced through the
initial refresh-done response and does not terminate a healthy persistent
stream.
EXTERNAL, DIGEST-MD5, and SCRAM carry `authzid`. DIGEST-MD5 accepts repeated
realm directives, selects the configured realm only when the provider offered
it (or otherwise selects the first offered realm), forms `ldap/<provider-host>`
as its `digest-uri`, and strictly validates the final `rspauth`. It selects only
`qop=auth`. SASL defaults and numeric `secprops` are enforced without silently
enabling plaintext authentication. Options that require credential delegation,
stronger mechanism classifications, channel binding, or a SASL security layer
fail explicitly. Entry upserts, UUID-based
renames/deletes, cookie updates, and derived context CSNs use storage
transactions. Present completion removes only local entries in the configured
scope and filter that were not reported by the provider. An in-process
provider/consumer topology verifies initial convergence, persistent
Add/Modify/Delete, consumer shutdown, offline provider changes, restart with
the same store, cookie catch-up, and stale-entry removal. Gated reverse process
topologies use real OpenLDAP 2.6.13 syncprov/MDB providers for both simple bind
and SCRAM-SHA-256, with the SCRAM case enabled when its Cyrus SASL plugin is
available.

GSSAPI uses the provider hostname as `ldap/<host>`. An explicitly present
`credentials` field supplies a password, including an intentionally empty
password. Without it, `KRB5_CLIENT_KTNAME`/`KRB5_KTNAME` select a keytab or
`KRB5CCNAME` selects a credential cache; the Unix default is
`/tmp/krb5cc_<uid>`. The pure-Go Kerberos implementation accepts bare or
`FILE:` paths (and `WRFILE:` keytabs), rejects unsupported KCM/API/KEYRING/DIR
cache types explicitly, and obtains Kerberos configuration from `KRB5_CONFIG`
or the platform file default. It currently selects the RFC 4752 no-security
layer, so `minssf` must already be met by TLS, TLCP, or ldapi.

Consumer TCP setup honors `network-timeout`, `keepalive`, and, on Linux,
`tcp-user-timeout`. A failed `starttls=critical` aborts the cycle;
`starttls=yes` continues on the same plaintext connection only when the LDAP
server rejects the extension; network, framing, and TLS handshake failures
still abort the cycle because connection state is no longer trustworthy.
LDAPS and StartTLS support client certificates, CA files/directories, OpenLDAP
`tls_reqcert` and `tls_reqsan` hostname policies, `peer`/`all` CRL checks,
protocol minima, common OpenSSL cipher names and operators, and Go-supported
curve selection. Go cannot configure TLS 1.3 cipher suites or reproduce the
complete OpenSSL cipher-expression grammar.

Implicit `ldap+tlcp://` providers run the same RFC 4533 consumer over GB/T 38636.
Both server signing and encryption certificates are chain-checked, including
hostname and CRL policy. Mutual authentication uses `tls_cert`/`tls_key` as the
client signing pair; the ldap-go extensions `tlcp_enc_cert`/`tlcp_enc_key`
supply the second client pair required by ECDHE SM4/SM3 suites. An end-to-end
topology verifies SASL EXTERNAL, initial refresh, and persistent modification
over mutual ECDHE TLCP.

OpenLDAP accesslog delta-syncrepl uses the configured `logbase` and
`logfilter` after an empty consumer completes a conventional refresh-only
search. Audit add, modify, modrdn, and delete records are parsed from ordered
`reqMod` values and applied with the corresponding cookie in one transaction.
Single-valued add/delete compatibility, DN-valued suffix massage, operation
CSN idempotency, and subtree rename are handled explicitly. A provider
`syncRefreshRequired` result or a local replay conflict clears only that
consumer RID's cookie; the next cycle performs a full standard refresh before
returning to the log stream. A gated OpenLDAP 2.6.13 accesslog fixture verifies
online replay, stopped-consumer catch-up, deliberate local-state loss,
automatic full recovery, and continued modrdn/delete persistence.

DSEE retro changelog mode uses `syncdata=changelog` and requires `logbase` but
not an accesslog `logfilter`. It reads `firstChangeNumber` and
`lastChangeNumber` from the Root DSE. Missing, zero, out-of-range, or reset
state triggers an ordinary full search of the replicated suffix; snapshot
completion removes stale local entries and atomically stores the provider's
last change number. Sequential one-level changelog searches parse the `changes`
attribute as LDIF and replay Add, Modify, ModDN, and Delete while advancing the
per-RID metadata and operational `lastChangeNumber` in the same transaction.
An unsafe change-number gap rolls back the operation, resets replay state, and
forces a full refresh on the next cycle; transient connection failures retain
the durable position. Refresh-and-persist adds the Netscape Persistent Search
control. Unit and protocol-level fake DSEE tests cover UUID conversion,
snapshot cleanup, gap rollback, all four operations, restart without a second
snapshot, and persistent streaming. No real Oracle DSEE or `dsadm` topology has
been run, so this remains a partial compatibility claim.

The provider-side accesslog accepts `olcAccessLogDB`, all named operation groups
from `olcAccessLogOps`, branch-scoped `olcAccessLogBase`,
`olcAccessLogSuccess`, `olcAccessLogOld`, `olcAccessLogOldAttr`, and
`olcAccessLogPurge`. Add, Delete, Modify, ModDN, and Password Modify produce
OpenLDAP-shaped audit entries in the same storage transaction as a successful
source change. Failed writes and completed read/session operations are appended
after their result is known. Search/Compare, Bind/Unbind/Abandon, and
database-targeted Extended records include their operation-specific fields;
common fields include request/result metadata, controls, referrals, and error
text. Frontend-only Extended operations such as Who Am I are not attributed to
a database overlay, matching slapd. Password request data is deliberately not
copied into `reqData`; the resulting hash is recorded by auditModify.

The accesslog database exposes source-derived `entryCSN`, `contextCSN`, and
`minCSN`; the source suffix exposes dynamic `auditContext`. Purge advances
`minCSN`, and syncprov rejects a cookie below that boundary with
`syncRefreshRequired`. Real slapd differentials compare write/read/session and
failure classes, DNs, result fields, Search and Compare parameters, Bind and
Abandon fields, modifications, old values, renames, password hashing,
UUID/CSN metadata, and timestamps.

The flat-file auditlog overlay accepts the OpenLDAP `olcAuditlogFile`
configuration on a data database or the frontend. Each successful Add,
Modify, Password Modify, ModDN, or Delete appends one OpenLDAP-shaped LDIF
record per applicable overlay. Add records contain the final entry, Modify
records include backend-added LastMod changes, password values are always
Base64 encoded, and proxy authorization records retain both the effective
identity and `realdn`. The file is opened in append mode for every record, so
external rename-based rotation works without a signal; open, write, or close
errors are logged but do not change a successful LDAP result.

The file is deliberately not enlisted in an RFC 5805 storage transaction.
Queued operations produce no output before End Transaction, and an explicit
abort produces none. During commit replay, however, each successful operation
is appended immediately. If a later operation fails and the database rolls
back, the earlier audit record remains, matching OpenLDAP's response-callback
behavior. Differential tests cover this edge, frontend and database overlays,
proxy identities, No-Op and failed writes, all four change types plus Password
Modify, external rotation, binary and folded LDIF, and Increment/delete-all
modifications. Local tests add online configuration rollback, restart,
unavailable paths, and concurrent/race coverage. A migration case generates
`slapd.d`, exports the real `olcAuditlogConfig` entry with `slapcat -n 0`,
imports the folded LDIF unchanged, and verifies runtime logging.

Single-provider consumer databases follow OpenLDAP shadow rules. External
updates return rewritten `olcUpdateRef` referrals, or
`shadow context; no update referral` when none is configured. Legacy
`olcUpdateDN` may write a shadow, while `olcMultiProvider` and its
`olcMirrorMode` alias make the database externally writable. Conflicting
shadow mechanisms and update referrals on non-shadow databases fail runtime
validation.

Fractional tests verify `attrs`/`exattrs`, mandatory entry UUID/CSN retrieval,
and persistence of excluded binary/password attributes across provider
modifications. Filter exit emits a delete and re-entry emits an add.
Refresh-only polling converges on its configured interval. Suffix massage maps
remote entry DNs and schema-recognized DN-valued attributes into the local
suffix; update referrals map a local target back to the provider suffix.

Sync composes with RFC 2891 sorting and VLV after candidates from all database
routes have been collected. Refresh-only entries always carry Sync State, and
SearchResultDone carries Sync Done plus Sort/VLV result controls.
Refresh-and-persist places Sort/VLV result controls on the refresh-done
intermediate response. A gated OpenLDAP 2.6.13 fixture records that slapd's
observable response changes with `syncprov`/`sssvlv` overlay order, including
lost or misplaced controls and an incomplete persistent combination.
`ldap-go` deliberately keeps one protocol-coherent response shape independent
of configuration order.

Standard syncrepl multi-provider nodes compare whole-entry and delete CSNs
before applying remote changes, preserve local entries not covered by a
refreshPresent cookie, and republish committed remote data and context-only
advances through syncprov. Equal-CSN delete batches remain distinct events,
and durable UUID tombstones reject a stale remote re-add after the original
entry has disappeared. A newer re-add clears the tombstone. An in-process SID
1/2/3 topology passes bidirectional relay, concurrent-write convergence,
middle-node outage/restart catch-up, writes made at both outer nodes while the
middle node is offline, and delete-versus-stale-modify convergence. A gated
OpenLDAP 2.6 topology passes bidirectional online writes between slapd SID 2
and ldap-go SID 1. `olcMirrorMode` is accepted as OpenLDAP's alias for
`olcMultiProvider`; active/passive writer selection remains the responsibility
of the external load balancer.

This provider does not yet implement arbitrary accesslog unknown-operation
routing, `olcSpSessionlogSource`, the optional sync-provider subentry context,
or an exhaustive `slapd` topology matrix. The consumer still lacks SASL
integrity/privacy layers, full OpenSSL cipher-expression compatibility,
delta-syncrepl's complete attribute-level conflict history, real Oracle DSEE
interoperability evidence, and broader OpenLDAP provider variants. The
replication rows therefore remain `partial`.

The database-local `pbind` overlay intercepts non-anonymous Simple Bind and
forwards the original Bind DN, credential, and request controls to the
whitespace-separated LDAP endpoints in `olcDbURI`. Providers are tried in
configuration order after dial, TLS, framing, or other transport failures; an
LDAP Bind result, including invalid credentials, is authoritative and is not
retried on another endpoint. The returned result code, matched DN, diagnostic,
referrals, and response controls are copied to the client. Successful remote
authentication establishes the original local Bind DN, while a configured
local-only password is deliberately not consulted.

`olcDbStartTLS` loads the optional/critical StartTLS mode plus certificate,
key, CA, SAN/certificate requirement, cipher, curve, CRL, and protocol-minimum
parameters. `olcDbNetworkTimeout` bounds dialing and the Bind exchange.
`olcDbQuarantine` drives an OpenLDAP-style shared health state: after all
providers fail with transport errors, requests are rejected until the active
retry interval expires, one concurrent probe is admitted, finite retry blocks
advance to the next interval, and any completed non-`unavailable` LDAP result
clears quarantine. Connection pooling is not yet implemented, so each provider
attempt opens a new connection. A local two-server
topology verifies remote credentials, ordered failover, local-password
exclusion, identity establishment, and provider unavailability. A gated,
optional OpenLDAP 2.6.13 `back_ldap` differential compares successful and
failed credentials, Who Am I? identity, and the unavailable-provider result.
It skips when the selected slapd build omits the `ldap` backend.

An imported `olcDatabase=ldap` naming-context backend proxies Bind, Search,
Compare, Add, Modify, ModifyDN, Delete, Password Modify, Dynamic Refresh, and
Who Am I? to ordered `olcDbURI` endpoints. It reuses a successful Simple Bind
identity when permitted, applies configured root identity assertion, and
forwards an authorized proxied identity. Abandon and Cancel reach the active
remote operation, transport failures advance to the next URI, and provider
LDAP results remain authoritative. RFC 5805 transactions are rejected because
the current implementation cannot make remote updates atomic. Database-local
ACLs and recognized overlays directly attached to this proxy backend are also
rejected during startup or online reload: proxy dispatch precedes local
overlay execution, so accepting either would silently bypass configured
policy. Frontend overlays are not yet executed around proxy responses and are
documented as an unsupported composition. For this back-ldap path, connections
are opened per operation, but a successful endpoint is remembered and moved to
the front of subsequent Bind and operation attempts, matching OpenLDAP's
registered URL-list callback. Password-based SASL Bind is completed by the local
server while remote auxiliary credentials and authorization rules are read
through the privileged auth-check identity; native outbound SASL identity
assertion uses the selected provider host and authorization ID. Pooling,
GSSAPI and SASL security layers, paged-cookie
continuity across reconnects, and complete referral rebind behavior remain.

An imported `olcDatabase=meta` adds target selection and Search union over the
same outbound executor. The implemented mapping path covers suffix massage,
direct attribute/object-class mappings, wildcard allowlists, response-side
drop mappings, DN-valued attributes, LDAP URL DNs, and request/result namespace
translation. Strict OpenLDAP 2.6.13 differentials cover Cancel and Abandon,
Bind polling, those wildcard/drop mappings, and `olcDbProtocolVersion` 2/3.
Privileged identity-assertion transports also implement the verified
`olcDbConnectionPoolMax` subset: eligible connections are reused across
frontend clients and concurrent operations are multiplexed by LDAP message ID.
Targets retain a healthy preferred URI, fail over when it becomes unavailable,
and probe a recovered URI after the preferred endpoint fails. Back-ldap and
back-meta referral chasing both enforce OpenLDAP's default five-hop limit and
return `loopDetect(54)` at exhaustion.
This is not a claim of complete OpenLDAP pool parity; full multi-target
connection-category accounting and rebind transitions remain.

The online target lifecycle follows the stable 2.6.13 observations. A
zero-target meta parent accepts its first `olcMetaTargetConfig` or `olcMetaSub`.
Modifying an existing target URI returns success and persists the configuration,
but that target is unavailable in the current process until restart. Deleting
the sole target returns `unwillingToPerform` (53), so a subsequent Add of the
same target DN returns `entryAlreadyExists` (68). OpenLDAP 2.6.13 triggers an
upstream assertion when a second target is added while an existing target
connection is active; that unstable path is excluded from the differential
oracle. GSSAPI and SASL security layers, complete referral rebind behavior,
full librewrite, complete multi-target connection categories, and broader
dynamic topology remain unsupported compatibility claims.

An imported `olcDatabase=sock` owns no local data partition. The runtime opens
one Unix stream socket per operation, writes the same command, message ID,
optional connection metadata, suffix, and operation body used by OpenLDAP
2.6.13, then consumes LDIF Search entries followed by a RESULT record. Bind,
Search, Compare, Add, Modify, ModifyDN, Delete, Password Modify through
EXTENDED, and Unbind are covered by one pinned differential that compares both
LDAP client outcomes and the external process's request fields. Unbind is sent
to every configured socket database, while Abandon and Cancel close the active
socket through the operation context.

A second pinned differential covers the frontend boundary before the socket is
opened. Add and Modify attribute descriptions, syntaxes, cardinality, and
duplicate values are checked; Compare assertions are validated against the
equality matching rule's assertion syntax and normalized; ModifyDN validates
both destination components and rejects cross-database moves; and anonymous
Password Modify is rejected. It also pins
OpenLDAP 2.6.13's acceptance and delegation of an empty Modify change list.
Relax is accepted on update operations only with manage ACL access. Don't Use
Copy is accepted on Search and Compare; a shadow Search returns its update
referrals or the same unavailable diagnostic as OpenLDAP. Critical chaining
and critical password-policy on Bind fail with
`unavailableCriticalExtension` before delegation; unsupported noncritical
controls are ignored rather than leaked into the socket request.

An RFC 5805 update routed to back-sock fails with `unwillingToPerform` during
transaction queue admission, before the Unix socket is opened. A second
commit-time pass scans the whole queue and identifies the first sock-targeted
message before a storage transaction, password preflight, or external call.
This is explicit rejection, not transaction participation.

Database mode preserves back-sock's limited pre-operation ACL checks: Add
checks `entry` write-add; Bind checks `entry` auth; Compare checks `entry`
compare; Delete checks `entry` write-delete; Modify checks `entry` write; and
ModifyDN checks write or write-delete when moving to a new superior. Returned
Search entries then pass entry and attribute/value read ACLs plus the client's
attribute projection. The parser requires a terminating RESULT and rejects
unsafe line injection and trailing records. OpenLDAP 2.6.13 contains a
documented FIXME where early EOF can accidentally become success; ldap-go
keeps the fail-closed behavior. RESULT `matched` and `info` text preserves all
bytes after the colon, including the conventional leading space, matching
OpenLDAP's `str2result()`. The protocol package separately accepts a sole
`CONTINUE` record for overlay interception and encodes one-way overlay `ENTRY`
and `RESULT` notifications without database suffix fields. `RESULT` cannot
represent referrals or response controls. The socket-overlay `cn=config`
loader, operation wrapper, callback chain, forwarded response hooks, and the
complete global-control matrix remain outside this compatibility claim.

The database-local `remoteauth` overlay takes over Simple Bind only when the
local target entry exists, has no `userPassword`, and provides the configured
`olcRemoteAuthDNAttribute` plus either
`olcRemoteAuthDomainAttribute` or `olcRemoteAuthDefaultDomain`. Existing local
passwords therefore retain priority and use the ordinary verifier. Ordered
`olcRemoteAuthMapping` values map the domain prefix to a realm; text after the
first backslash or colon is removed before lookup, and an unmatched domain uses
`olcRemoteAuthDefaultRealm`. A realm can name one LDAP endpoint directly or a
line-oriented `file://` provider list. Providers are tried in order for each
`olcRemoteAuthRetryCount` round; invalid credentials terminate immediately,
while transport failures and other remote results permit provider/retry
progression.

The required `olcRemoteAuthTLS` value loads StartTLS and the same outbound TLS
policy. Ordered `olcRemoteAuthTLSPeerkeyHash` values pin each provider hostname's leaf public
key with SHA-1/256/384/512 or SM3 and fail closed on cleartext, absent, or
mismatched peers. When `olcRemoteAuthStore` is enabled, a successful credential
is hashed with the first effective `olcPasswordHash` scheme (default `{SSHA}`;
national-cryptography schemes such as `{PBKDF2-SM3}` are accepted) and written
to the local entry without replacing a concurrently added password. Matching
OpenLDAP, any hash-generation failure, including a selected verify-only scheme,
falls back to cleartext storage and
emits a warning; administrators requiring hashed writeback must not combine
that setting with `{NS-MTA-MD5}`. The local
two-server topology verifies delegation, bad credentials, writeback, local
fallback after provider shutdown, local-password precedence, and provider
failures. Live StartTLS cases verify valid SHA-256/SM3 pins, untrusted
certificates, wrong digests, and missing host pins. A gated OpenLDAP 2.6
`remoteauth` differential compares delegated and local Bind, writeback, bad
credentials, and provider loss; transport failure follows OpenLDAP's
`operationsError` result while a received LDAP result remains authoritative.
Connection pooling and a broader platform TLS matrix remain outside the tested
boundary. Both overlay rows therefore remain `partial`.

Current password verification covers cleartext, `{CLEARTEXT}`, `{SHA}`,
`{SSHA}`, `{MD5}`, `{SMD5}`, the OpenLDAP contrib `{SHA256}`, `{SSHA256}`,
`{SHA384}`, `{SSHA384}`, `{SHA512}`, and `{SSHA512}` schemes, `{SM3}`,
`{SSM3}`, `{PBKDF2-SM3}`, and the OpenLDAP contrib `{PBKDF2}`,
`{PBKDF2-SHA1}`, `{PBKDF2-SHA256}`, and `{PBKDF2-SHA512}` schemes. SHA-2
generation uses the contrib module's
eight-byte salt and passes a pinned 2.6.13 bidirectional dynamic-module
differential. New
national-cryptography password values use `{PBKDF2-SM3}` with a random 16-byte
salt, a 32-byte derived key, and 100,000 iterations by default. The textual
layout follows OpenLDAP's contributed PBKDF2 scheme:
`{PBKDF2-SM3}<iterations>$<salt>$<derived-key>`, using unpadded adapted
base64. Verification rejects iteration counts above 10,000,000 to bound Bind
work from untrusted stored values. `{SM3}` and `{SSM3}` are accepted for
existing deployments but are not recommended for newly stored passwords.
These three SM3 scheme names are not built into upstream OpenLDAP; reverse
migration requires a corresponding OpenLDAP password module or patch.

The upstream PBKDF2 schemes generate 10,000 iterations with a random 16-byte
salt and 20, 32, or 64 derived bytes for SHA-1, SHA-256, or SHA-512. The
`{PBKDF2}` name aliases `{PBKDF2-SHA1}`. Pinned dynamic-module tests exercise
Password Modify and imported Simple Bind in both directions. Verification is
intentionally stricter than OpenLDAP 2.6.13 for selected manually constructed
values: ldap-go rejects non-decimal iteration text, extra fields, and
iterations above 1,000,000 before deriving a key. Adapted Base64 whitespace,
padding, and nonzero tail-bit behavior are matched directly against the pinned
module. OpenLDAP's module uses unbounded `atoi` and `memcmp`; ldap-go keeps the
work bound and compares derived keys in constant time.

The contrib `{APR1}` and `{BSDMD5}` schemes store standard Base64 over the
16-byte PHK-MD5 digest followed by the salt. They are not Apache/BSD crypt text
records despite using `$apr1$` and `$1$` as internal digest magic values.
Generation matches the module's eight-character salt alphabet and 1,000-round
algorithm, and pinned dynamic-module tests cover Password Modify, import, and
Simple Bind in both directions. Verification accepts imported noncanonical
salts up to 64 bytes and compares the digest in constant time. These MD5-based
schemes reject credentials above 4 KiB before hashing to bound unauthenticated
Bind work and reject stored encodings above 4 KiB before scanning. They are
migration formats, not recommended defaults for new credentials.

The contrib Netscape `{NS-MTA-MD5}` scheme is verify-only. Its 64-byte payload
contains 32 lowercase MD5 hexadecimal bytes followed by a 32-byte salt, and
the digest covers `salt || 0x59 || password || 0xf7 || salt`. Imported values
authenticate in both OpenLDAP and ldap-go under a pinned module differential.
Because the module registers no hash function, OpenLDAP accepts the name in
`password-hash` but Password Modify fails with `other(80)`; ldap-go preserves
the same configuration and operation behavior. `slappasswd -h` recognizes the
scheme but reports that it has no hash function.

The contrib `{RADIUS}` scheme is also verify-only. Its payload is the exact
RADIUS User-Name, including an allowed empty value; the supplied LDAP
credential becomes RADIUS User-Password and the canonical local hostname
becomes NAS-Identifier. NUL bytes fail closed. Matching libradius, passwords
longer than 128 bytes are truncated, User-Name and NAS-Identifier are limited
to 253 bytes, valid Access-Reject/Access-Challenge responses stop failover, and
timeouts or malformed responses consume the configured attempts before the
next authentication server is tried. Nonzero dead-time marks an exhausted
server dead for the configured interval and allows it to be reprobed later in
the same request. Retries reuse the same packet and UDP source socket, while a
server change preserves Identifier and Request Authenticator but re-encrypts
PAP with that server's complete shared secret. IPv4/FQDN `radius.conf` entries,
the `radius/udp` service lookup with port 1812 fallback, default
timeout/attempt counts, ten-server limit, quoted fields,
dead-time and bind-address behavior, and the 1,023-byte line boundary follow the
pinned libradius parser. The selected source address and a valid Response
Authenticator are mandatory. When attribute 80 is present, its
Message-Authenticator HMAC-MD5 is verified with the request Authenticator,
matching SSL-enabled libradius. Response authentication covers the declared
packet length and ignores UDP trailing bytes, while an independently
authenticated response Identifier is not compared again with the request
Identifier. Each check reloads the file and all checks in the process are
serialized by one mutex, as in `pw-radius`; parsed line buffers and temporary
shared-secret fields are cleared after the server configuration is cloned.

An imported `olcModuleLoad: pw-radius... config=/path/radius.conf` selects the
first `config=` argument. The command-line `-radius-config` and
`-radius-nas-identifier` options are ldap-go operator overrides. LDIF migration
preserves `{RADIUS}<username>` and the module-load value, but never embeds the
external `radius.conf` or its shared secrets; those files need a separate,
permission-restricted deployment step. RADIUS PAP protects a password with the
shared secret on the wire but does not provide channel encryption or server
identity, so the UDP path still requires a trusted network or an authenticated
encrypted tunnel. Password Modify and ppolicy can verify existing `{RADIUS}`
values, but selecting it for a new hash returns `other(80)`. Matching OpenLDAP's
transaction replay point, LDAP Transactions defer RADIUS verification until
End Transaction commit. The commit pre-acquires all applicable seqmod locks and
iterates rollback-only ordered replay: each pass stops at the first unknown
external pair, performs that ordered RADIUS sequence outside the directory
writer, and restarts with the real result. Atomic replay then consumes only the
prepared results. ACL and ppolicy checks rerun in both ordered views. A failed
old-password check prevents history and later-operation requests, and
multi-valued passwords follow the exact accepted value. The commit replay
preserves the first failed message ID, its response controls, and auditlog
behavior. Rollback passes use private CSN/accesslog clocks and therefore do not
advance the clocks used by committed writes. A concurrent new external pair
fails with `busy` and requires a client retry, while an unrelated earlier
attribute or policy change inside the
transaction is handled in order. RADIUS-enabled Modify and Password Modify are
rejected in transactions with active `translucent` or effective `chain`
configuration because those remote LDAP effects cannot participate in the
rollback preflight. This prevents stale external-history acceptance, duplicate
remote effects, and the ordinary-write/transaction lock-order inversion. Online
`olcModuleLoad` deletion/replacement, every `olcModulePath` modification, and
deletion of an `olcModuleList` entry are rejected because OpenLDAP cannot unload
a live password module or insert a module path online. Module attributes added
to any non-`olcModuleList` configuration entry are rejected as well.

`ldap-go passwd` generates `{PBKDF2-SM3}` values. It reads the cleartext from
`LDAP_GO_PASSWORD` or bounded standard input and never accepts it as a
positional command argument.

RFC 3062 Password Modify is advertised in Root DSE and supports the bound
identity or an explicit target DN, optional old-password verification,
client-supplied passwords, server-generated passwords, ACL enforcement, and
normal schema/operational-attribute updates in one storage transaction. The
frontend database's `olcPasswordHash` values select one or more output hashes;
the OpenLDAP default is `{SSHA}`, the contrib SHA-2 and PBKDF2 names preserve
OpenLDAP interoperability, and `{PBKDF2-SM3}` enables the costed SM3 format.
Legacy placement on `cn=config` is also accepted. Online changes are validated
as part of the runtime snapshot and unsupported schemes roll back.

An imported OpenLDAP `ppolicy` overlay applies its default or per-entry
`pwdPolicySubentry` policy to simple Bind, Add, Modify, and Password Modify.
Implemented policy behavior includes start/end validity, permanent and timed
lockout, exponential temporary delay, failure intervals, password expiry and
warnings, grace login limits/expiry, reset-only sessions, minimum age,
minimum/maximum byte length, history, user-change/safe-modify rules,
`ppolicy_hash_cleartext`, `olcLastBind` precision, and `pwdMaxIdle`. Password
changes maintain the OpenLDAP operational state attributes, and administrator
changes honor `pwdMustChange`. Root DSE and operation handling include the
Behera password-policy control, SunDS account-usability control, and optional
Netscape expired/expiring controls. Configuration, policy, and account state
survive `slapcat`-style LDIF import/export/reimport, and online overlay changes
replace the runtime atomically.

Two extension paths remain. OpenLDAP native `check_password()` shared objects
use slapd's C `Entry` ABI and are preserved during migration but are not loaded
by the Go server. A configured `olcPPolicyCheckModule` therefore fails closed
when `pwdUseCheckModule` requests it; `pwdUseCheckModule` without a configured
module follows the tested OpenLDAP build and is ignored. On a shadow database,
`olcPPolicyForwardUpdates` suppresses local policy-state writes and forwards an
internal Relax-rules Modify through `olcUpdateRef` and the active chain overlay.
Failed and successful Bind state updates are applied only at the provider in
the two-server integration topology.

RFC 4528 Assertion is published through Root DSE `supportedControl`. The BER
filter is decoded strictly and evaluated inside the same storage transaction
as Add, Modify, Delete, and ModifyDN; failed assertions return result code 122
without side effects. Search evaluates the assertion against its base entry,
and Compare against its target entry. Tests cover duplicate/missing/empty
control values, malformed and trailing BER, noncritical handling, schema-aware
matching, and successful/failed atomic operations.

RFC 4527 pre-read and post-read are also published through Root DSE
`supportedControl`. Pre-read applies to Modify, Delete, and ModifyDN; post-read
applies to Add, Modify, and ModifyDN. Their AttributeSelection values are
decoded strictly, and response values contain the required SearchResultEntry
application payload. Snapshots are generated inside the write transaction,
use normal entry and attribute read ACLs, honor `*`, `+`, `1.1`, explicit
attributes, and the empty default selection, and are only returned after a
successful commit. Tests cover old/new values and DNs, operational attributes,
password-value filtering, malformed and duplicate controls, operation
applicability, and rollback after a critical post-read failure. OpenLDAP
differential fixtures remain pending.

RFC 4511 Abandon and RFC 3909 Cancel use a connection-local operation registry.
The connection reader can accept either request while the serial operation
worker is scanning or transmitting an active Search. Abandon cancels the
Search context, immediately suppresses further entries, and sends no
SearchResultDone. A successful Cancel waits for the target Search to return
`canceled` (118), then sends an ExtendedResponse success with no responseName
or responseValue. Message IDs cannot cross LDAP associations. Bind and
StartTLS remain read barriers, and complete BER PDUs share one write lock.

Request values use strict BER for `SEQUENCE { cancelID MessageID }`; absent,
empty, malformed, unknown, finalizing, pending, and non-cancelable targets map
to the RFC result codes. Deterministic TCP tests pause the storage scan and
cover response ordering, connection reuse, Root DSE discovery, and cross-
connection rejection. Process-level probes against OpenLDAP 2.6.13 match
result codes, diagnostics, and target-before-Cancel response ordering for
normal cases. Two strict RFC differences are intentional: `ldap-go` rejects
trailing bytes after cancelRequestValue and returns `cannotCancel` when a
Cancel targets its own message ID; OpenLDAP 2.6.13 accepts the trailing data
and returns success for self-cancel despite RFC 3909 declaring Cancel
non-cancelable.

Cancel and Abandon currently interrupt Search only. Running update operations
return `cannotCancel`, pending Search follows OpenLDAP's `cannotCancel`
behavior, and ordinary operations on one connection execute serially. Update
cancellation, discretionary update Abandon, and OpenLDAP-style parallel
operation execution remain before these rows can become `compatible`.

RFC 2696 simple paged results are published through Root DSE
`supportedControl`. Request and response values use strict BER decoding and an
opaque, connection-local cookie; only the latest cookie can continue a search,
and it is bound to the authenticated identity, request semantics, control
criticality, and current runtime configuration. Page size may change between
requests. Completion returns an empty cookie, while a size-zero continuation
abandons the sequence. Continuation uses a database-route and normalized-DN
cursor, preserves the total search size limit across pages, applies normal
filter and read ACL processing before page boundaries, and reports a zero size
estimate to avoid disclosing unreadable candidates. Tests cover malformed,
old, and reused cookies, Bind reset, changed requests, empty initial requests,
cross-database glue searches, mutation between pages, and
`github.com/go-ldap/ldap/v3` interoperability. OpenLDAP process-level
differential fixtures remain pending.

RFC 2891 server-side sorting is advertised only when an OpenLDAP `sssvlv`
overlay is loaded. Overlay settings are bound to their parent database, while
a frontend overlay applies globally; `olcSssVlvMaxKeys` is validated and
defaults to five. Request and response values use strict BER. The server sorts
the complete ACL-visible candidate set before size limits or RFC 2696 page
boundaries, supports multiple keys, reverse order, absent and multi-valued
attributes, and resolves default or explicitly named/OID ordering rules through
the active schema. Sorted paging preserves the initial ordered route/DN set,
excludes later additions, skips deletions, and re-evaluates current entry and
attribute ACLs on continuation.

OpenLDAP-compatible request failures return direct LDAP result codes 16, 18,
and 53 for unknown attributes, unavailable ordering rules, and excessive key
counts; duplicate alias keys remain accepted. Process-level differential tests
against OpenLDAP 2.6.13 using `ldapsearch -E sss -E pr` pass for multi-key,
reverse, absent-value, paging, and error cases. `olcSssVlvMaxKeys`,
`olcSssVlvMax`, and `olcSssVlvMaxPerConn` are loaded per overlay with defaults
of five, eight, and five. Eight matches half of OpenLDAP's default 16-worker
pool. Regular sorts hold a transient lease; sorted paging and VLV retain leases
for their cookie/context lifetime. A target and frontend overlay each account
for the same request, and saturation returns OpenLDAP's LDAP `busy` result 51
without sort, paging, or VLV response controls.

One known differential remains for sort plus paging plus a total size limit:
OpenLDAP's overlay can report `sizeLimitExceeded` on an earlier page, while
`ldap-go` reports it when the cumulative limit is reached; both return the same
globally sorted top-N entries. Same-connection request intake and Abandon now
work, but ordinary operations still execute serially instead of using
OpenLDAP's worker-level concurrency, so the `sssvlv` row remains partial.

Virtual list views from `draft-ietf-ldapext-ldapv3-vlv-09` use strict BER and
are advertised with the `sssvlv` overlay. They require an RFC 2891 sort control
and reject RFC 2696 paging on the same search. Offset, proportional offset,
greater-than-or-equal assertion, reverse ordering, absent values, empty result
sets, and OpenLDAP's historical target-position-zero behavior are covered.
OpenLDAP 2.6.13 uses VLV result values 76 and 77 for a missing sort control and
an out-of-range offset; `ldap-go` follows those deployed values.

Each successful initial request creates a random 16-byte, connection-local
context bound to the authenticated identity, search semantics, sort request,
and runtime configuration. Up to `olcSssVlvMaxPerConn` contexts can coexist.
Continuations retain the initially sorted route/DN set, exclude later
additions, skip deletions, re-read current values, reapply entry and attribute
ACLs, and enforce the search size limit for every window. Bind, StartTLS,
connection close, and runtime replacement invalidate all contexts and release
their leases. Process-level tests with OpenLDAP 2.6.13 `ldapsearch` pass
discovery, offset windows, response controls, and missing-sort errors. Unlike
OpenLDAP's pointer-derived context, an `ldap-go` context cannot be reused with
changed query semantics.

The ACL evaluator loads ordered `olcAccess` values from frontend and database
entries. Targets support exact/base, one-level, subtree, children, and regular
expression DNs; filters; individual, user/operational wildcard, and
object-class attribute sets; and equality, matching-rule, regex, or DN-scoped
values. Regular-expression target DN captures (`$1` and peers) and target-value
captures (`${v1}` and peers) expand into DN, group, set, domain, and other
eligible subject selectors.

Subjects include anonymous/users/self and their real-identity forms, exact and
relative-level DNs, DN attributes, configurable static or dynamic groups, set
expressions, `peername`, `sockname`, `domain`, `sockurl`, IPv4/IPv6 networks,
Unix paths, and overall/transport/TLS/SASL SSF thresholds. Access levels,
`=`, `+`, and `-` privileges, `stop`/`continue`/`break`, and OpenLDAP's implicit
clauses are retained. `OpenLDAPaci` and custom attributes using the same syntax
participate through `aci`/`dynacl/aci`, including scoped grant/deny evaluation.
Search/Compare/Bind and all write operations enforce attribute or pseudo-
attribute access. Add/delete privileges (`a`/`z`), Replace semantics,
`olcAddContentAcl`, ModifyDN parent/RDN checks, DN-syntax-only `selfwrite`, root
bypass, default read access, and the `cn=config` default-none exception follow
the slapd implementation.

Direct OpenLDAP differentials cover target filters/value/object-class sets,
DN and value capture expansion, static/dynamic groups, connection and level
selectors, and `OpenLDAPaci`. The row remains `partial`: unlisted ACL grammar,
other dynacl plugins, and the full cross-operation/overlay matrix are not
claimed. Configurations using an unsupported selector fail server startup
instead of silently weakening access control.

Runtime database selection loads `olcDatabase`, all `olcSuffix` values,
`olcRootDN`, and `olcRootPW` from imported `cn=config` entries. Longest-suffix
selection scopes root authentication and ACL bypass to one database. Hashed
root passwords use the same supported OpenLDAP password schemes as entry
passwords; an unset root password falls back to normal entry authentication,
while an explicitly empty value disables simple Bind for that root DN.
Configuration-like attributes outside `cn=config` are ignored by schema, ACL,
and runtime database loaders.

Online Add, Modify, Delete, and in-tree ModifyDN operations under `cn=config`
build schema, ACL, and database routing as one immutable snapshot inside the
write transaction. Invalid supported configuration rolls back the directory
change; a successful commit atomically publishes the new snapshot. Tests cover
immediate ACL and root-password changes, schema publication/removal, rollback,
and concurrent searches during repeated ACL reloads. The complete OpenLDAP
configuration schema, backend/module-specific mutation hooks, ordered-entry
renumbering, and full differential error behavior remain pending.

Runtime database settings also load `olcReadOnly` and `olcLastMod`, including
the frontend read-only restriction, plus database-local `olcMaxDerefDepth`,
while global `olcAllows: update_anon`
controls whether anonymous updates may reach ACL evaluation. Update
restrictions run before ACL checks, and database root DNs do not bypass
read-only mode. With `olcLastMod: FALSE`, Add, Modify, and ModifyDN stop
generating UUID, CSN, creator, and timestamp metadata while schema operational
attributes remain available. Online changes and invalid-value rollback are
covered through TCP client tests. `olcAllows: bind_v2`, `bind_anon_cred`, and
`bind_anon_dn` enable OpenLDAP's historical LDAPv2 Bind and two deprecated
anonymous Bind forms. Unsupported protocol versions and malformed Bind DNs
use slapd's result ordering and diagnostics. `proxy_authz_anon` permits an
anonymous connection to send the RFC 4370 control; ordinary authorization
still prevents that identity from assuming a non-anonymous DN.

Global `olcDisallows` loads case-insensitive, whitespace-separated feature
sets from an imported `cn=config`. `bind_anon` and `bind_simple` follow
OpenLDAP's result-code, diagnostic, and `olcAllows` precedence.
`tls_2_anon` and `tls_authc` preserve OpenLDAP's ordering: by default an
authenticated StartTLS request first becomes anonymous, while both flags are
required to reject it without dropping the identity. This ordering also runs
before TLS availability is checked. `dontusecopy_non_critical` rejects a
non-critical RFC 6171 control. Online replacement/deletion, unknown-feature
rollback, restart, and a process-level slapd differential pass.
`proxy_authz_non_critical` requires RFC 4370 controls to be critical and uses
slapd's protocol-error diagnostic. Proxy controls otherwise follow
OpenLDAP's default acceptance of non-critical requests. Both proxy switches
support online replacement, rollback, and restart.
`olcRestrict`, `olcRequires`, listener permissions, and SSF-based update
requirements also remain pending.

Every configured database now has an isolated storage partition, keyed by its
imported configuration-entry UUID when available. Existing single-namespace
stores are partitioned atomically at startup. Bind, Search, Compare, and write
operations only see the selected partition; ModifyDN rejects cross-database
moves with `affectsMultipleDSAs`. `olcHidden` databases are skipped during
selection and Root DSE publication, while their entries remain isolated and
may use the same DN as a visible database. Online hide/show changes and suffix
conflict rollback are covered by TCP tests. `olcDisabled` databases are also
removed from operation routing but, matching slapd, remain published in Root
DSE and retain their isolated data. Online disable/enable changes and invalid-
value rollback are covered through TCP tests. Root DSE `namingContexts`,
`configContext`, and `monitorContext` values are built from the same runtime
snapshot. Database-selective import/export accepts a slapcat-style numeric
index, an `olcDatabase` value, or a configuration-entry DN; tests import and
export identical DNs from visible and hidden databases independently.
`olcSubordinate: TRUE`, `FALSE`, and `advertise` are loaded and validated with
OpenLDAP's single-suffix restriction. Base searches stay in the selected
backend; one-level and subtree searches fan out across the applicable
subordinate partitions with shared limits. Unadvertised subordinate suffixes
are omitted from Root DSE, while `advertise` publishes them. Bind and writes
still select the most-specific backend, empty subordinate suffix entries can be
created online, and cross-database ModifyDN returns `affectsMultipleDSAs`.
Online setting changes and invalid-value rollback are covered by TCP tests.
Glue interactions with controls and explicitly positioned overlays remain
pending.

Evidence currently consists of package tests, TCP interoperability tests using
`github.com/go-ldap/ldap/v3`, import/export semantic round trips, and manual
process-level operations using OpenLDAP 2.6.13 `ldapsearch`, `ldapadd`,
`ldapmodify`, `ldapcompare`, `ldapmodrdn`, and `ldapdelete`. Rows remain
`partial` because the complete RFC 4517 syntax/matching-rule set, executable
third-party schema modules, complete referral/rebind behavior, unlisted
controls, the remaining ACL grammar and differential suite, GSSAPI and SASL
security layers, subtree-delete control, and full OpenLDAP differential
fixtures are still pending.

Schema bootstrap was also exercised by importing the unmodified Homebrew
OpenLDAP 2.6 `core`, `cosine`, `inetorgperson`, `nis`, and `openldap` schema
LDIF files, starting `ldap-go` from that database, and reading Root DSE and
`cn=Subschema` with OpenLDAP `ldapsearch`.

ACL behavior was aligned against `OPENLDAP_REL_ENG_2_6` revision
`04a19039e8d13dc06316e2d90994d6ff2812eb3d`, primarily
`servers/slapd/acl.c`, `servers/slapd/aclparse.c`, the MDB operation
implementations, and `slapd.access(5)`.
