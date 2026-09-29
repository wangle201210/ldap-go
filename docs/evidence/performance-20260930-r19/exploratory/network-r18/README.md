# Separate R18 Network Diagnostic

These profiles use R18 (8918569) source plus the archived opt-in benchmark.
The SDK client and server share one Go process and a real loopback TCP socket.
They are not R19 before/current measurements or an OpenLDAP comparison.
Each case used 20 seconds, CGO_ENABLED=0, a private copy of the 100k default
seed, the qualification search limits and a nonroot SSHA reader.

The Go test CPU profile includes setup, client work and background work. The
text tables filter stacks containing runConnectionOperation; percentages still
use total process samples. Handler stacks may include setup requests. Raw
binary profiles and test executables remain outside the repository.

The observed write syscall samples dominate the filtered handler stacks.
Small search responses already batch entry and done into one write. The BER
reader reads a two-byte header and then the body, with an extra length read for
long-form lengths. Buffering was explored statically but not implemented:
raw-connection deadline/Close bypasses, custom reader error boundaries and
TLS/SASL transition ownership need additional proof. OpenLDAP's inspected TCP
path does not install its generic Sockbuf readahead layer; that layer appears
in the inspected UDP path. No end-to-end gain is inferred from these profiles.

The first Base setup failed on ENOSPC during fixture copying, before timing.
Only the fresh successful runs are copied here. Failed setup logs and profiles
remain in /var/tmp/ldap-go-network-profile-r18/failed-setup and are excluded.
