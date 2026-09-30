# R21: bounded reuse for large-group Compare

September 30, 2026; 100,000 users, Apple M1 Pro, Go 1.26.4 with
`CGO_ENABLED=0`, OpenLDAP 2.6.13. Baseline source is `17e0390`, whose production
logic remains R19. The retained R19 binary is reused; the rejected R20 binary
is not a baseline.

Implementation commit: `b9db7f3`. It is source-identical to the validated
isolated worktree commit `c9dfa66`.

**Common-operation parity remains unmet.** Large-group last/missing Compare
improves 11.5%-14.2% in the primary runs, with 12.8%/14.3% in the independent
startup/port swap. Other cases include negative observations. Faster operations
do not offset slower ones for acceptance.

## Common operations

Seven batches of 1,000 SDK calls per row; values are medians of summed timed
request durations. Setup, connection, identity checks and cleanup are untimed.
Frequency is qualitative and application-dependent.

Relative performance = `OpenLDAP/current * 100%`; 100% means parity and higher
is better. Compare versions within a run, not across historical rounds.

| Operation | Typical use | ldap-go, default | OpenLDAP, default | Relative, default | Relative, explicit ACL |
| --- | --- | ---: | ---: | ---: | ---: |
| User Bind, SSHA | Very high | 97.70 ms | 77.66 ms | 79.5% | 81.2% |
| Non-root Base, hot | High | 116.51 ms | 94.39 ms | 81.0% | 78.5% |
| Non-root equality, hot | Very high | 104.33 ms | 83.94 ms | 80.5% | 83.9% |
| Group1000 Compare, first | Medium | 107.71 ms | 81.83 ms | 76.0% | 77.6% |
| Group1000 Compare, last | Medium | 133.63 ms | 91.48 ms | 68.5% | 70.8% |
| Group1000 Compare, missing | Medium | 119.89 ms | 84.88 ms | 70.8% | 70.2% |

First/last refers to fixture insertion order, not assumed native storage order.
Primary Bind/Base/equality time changes versus their paired baseline are
-1.6%/-1.6%/+0.7% for default access and -0.4%/-1.6%/+1.5% with explicit ACL.
Negative values mean slower. These paths have no new comparison logic; the
measurements do not establish that all negative observations are noise.

Group discovery, large-group Base, nested traversal, distributed reads and
writes were not rerun in R21. Their [R19 report](common-ldap-performance.md)
and older reports remain historical, not measurements of this revision.

## Paired group results

Time reduction = `(1-current/before)*100%`, using unrounded medians.

| Access | Members | Assertion | Before | Current | OpenLDAP | Time reduction |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| Default | 10 | First | 98.09 ms | 98.22 ms | 79.69 ms | -0.1% |
| Default | 10 | Last | 92.54 ms | 92.63 ms | 74.86 ms | -0.1% |
| Default | 10 | Missing | 102.90 ms | 104.23 ms | 82.25 ms | -1.3% |
| Default | 1,000 | First | 109.88 ms | 107.71 ms | 81.83 ms | 2.0% |
| Default | 1,000 | Last | 151.41 ms | 133.63 ms | 91.48 ms | 11.7% |
| Default | 1,000 | Missing | 138.92 ms | 119.89 ms | 84.88 ms | 13.7% |
| Explicit ACL | 10 | First | 98.56 ms | 98.97 ms | 80.83 ms | -0.4% |
| Explicit ACL | 10 | Last | 91.80 ms | 92.07 ms | 73.91 ms | -0.3% |
| Explicit ACL | 10 | Missing | 98.64 ms | 99.07 ms | 79.40 ms | -0.4% |
| Explicit ACL | 1,000 | First | 112.51 ms | 113.00 ms | 87.65 ms | -0.4% |
| Explicit ACL | 1,000 | Last | 149.34 ms | 128.14 ms | 90.78 ms | 14.2% |
| Explicit ACL | 1,000 | Missing | 150.76 ms | 133.44 ms | 93.67 ms | 11.5% |

The independent swap changes both startup order and ports. Large-group
first/last/missing changes are -3.5%/+12.8%/+14.3%; small-group changes are
+1.8%/-3.1%/-1.0%. These remain separate from primary results. There is no
universal speedup, statistical-significance or regression-free claim.

## Implementation and costs

The runtime retains immutable prefixes of successful raw-to-normalized DN
translations for exact `member` Compare on groups with at least 32 values.
Every reuse verifies Registry identity, schema generation and the current raw
bytes at the same position. Current entry reads, ACL, referral, assertion,
early-match and first-error order remain authoritative. Changed values and
unsupported attribute selections fall back to the original comparison path.

At most one new value is retained per call. Each token is capped at 4,096
positions and 256 KiB accounted retention. The runtime container caps records
at 64 and accounted live plus reserved storage at 8 MiB, including retired
tokens still borrowed by active calls. This is not a process RSS bound; old
runtimes, the existing DN cache and parser temporaries are separate.

Common ASCII attribute names are folded on the stack during eligibility checks;
other spellings retain the original selector. A raw-identical first member
chooses the original comparator before cache acquisition. Byte equality never
proves a DN match or suppresses earlier errors.

Warming is not free. The initial eight-value fill experiment approximately
doubled artificial cold-DN-cache last/missing component time and was rejected.
The one-value version limits that penalty, but 1,001-call progressive episodes
still allocate about 19.5 MB to construct successive immutable prefixes. In
those component episodes, last was about 1% slower and missing about 7% slower
than the previous comparator. Repeated hot use provides the benefit; frequent
group churn or a working set larger than the retention budget may not benefit.

The first measured last-member network batch includes progressive warming;
later repetitions and the following missing-member stage reuse it. Raw samples
are retained rather than replaced with warm-only measurements. Artificial reset
and progressive-episode diagnostics precede the final attribute-name and
first-member refinements and are not final end-to-end results.

## Handler components

Three alternating before/final 500 ms repeats, using the same root-bound
fixture. These loops include progressive warming and then repeated hot calls;
they are not cold-start or network latency measurements.

| Members | Case | Before ns/op | Current ns/op | Before B/op | Current B/op | Before allocs/op | Current allocs/op |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | First | 9,720 | 10,121 | 9,688 | 9,688 | 101 | 101 |
| 10 | Last | 11,308 | 11,266 | 9,768 | 9,768 | 105 | 105 |
| 10 | Missing | 11,532 | 12,454 | 9,856 | 9,856 | 110 | 110 |
| 1,000 | First | 25,588 | 25,373 | 82,456 | 82,456 | 102 | 102 |
| 1,000 | Last | 61,681 | 36,868 | 82,537 | 83,707 | 106 | 108 |
| 1,000 | Missing | 54,600 | 31,871 | 82,624 | 82,392 | 111 | 100 |

Large last/missing component time decreases about 40%/42%. Small first/missing
are 4.1%/8.0% slower in this diagnostic despite unchanged allocation counts;
these observations are retained, not dismissed as noise. Their network changes
are smaller and are reported separately above. Allocation figures shown are
from the median-time sample; all repeats remain in the evidence.

## Evidence and validation

[Evidence](evidence/performance-20260930-r21/README.md) includes compressed raw
samples, all positive and negative results, scripts, source reconstruction and
executable hashes. The summary verifies **756 completed batches and nine
canonical exports**, each containing 100,002 matching user-data entries.
The three earlier prototype runs and their nine exports remain separate.

Full Go tests passed (schema 96.704s, server 159.621s, storage 24.635s,
webadmin 0.299s), as did `go vet ./...` and 355 native differential checks
(11.429s). Focused tests cover schema/alias/options/error parity, immutable
token ownership, memory accounting and concurrent use. Handler tests warm all
1,000 positions through actual requests, then verify complete wire responses
and storage-callback order across late-member changes, deletion/recreation,
schema changes, ACL, referral and assertion failures. Independent static review
found no new semantic defect; this is not a proof of universal compatibility.

The reference environment is the same pinned OpenLDAP source rebuilt for R20;
user data matches the recovered canonical fixture. Physical MDB layout and
generated operational attributes are not claimed identical to the removed old
fixture. The [known operational-attribute gap](common-ldap-performance-20260924-r2.md#existing-operational-attribute-gap)
remains outside this passing matrix. No CGO, race-detector or complete OpenLDAP
compatibility claim is made.

```text
before  8337870fb7ccd7c6a2849d2bcd21b05f5df11d022c658e401fcd4054fccadf98
current d337fbcdf8d6e8956332fe802fbc85abe966908aa52c0b34cf47fd27ff89c6d9
```
