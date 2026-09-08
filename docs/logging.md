# OpenLDAP Logfile Configuration

The global `cn=config` attributes `olcLogFile`, `olcLogFileFormat`,
`olcLogFileOnly`, and `olcLogFileRotate` are supported at startup and through
online Modify. They route ldap-go's structured events selected by `olcLogLevel`
or `cn=Log,cn=Monitor`; they do not recreate slapd's internal debug messages or
its per-operation trace stream.

| Attribute | Behavior |
| --- | --- |
| `olcLogFile` | Append to an existing regular file or create it with mode `0640`, subject to umask. Deletion closes the destination. |
| `olcLogFileFormat` | Case-insensitive `default`/`debug`, `syslog-utc`, `syslog-localtime`, or `rfc3339-utc`. Deletion restores debug format. |
| `olcLogFileOnly` | `TRUE` suppresses the process handler after a successful file write. Absent, `FALSE`, or deleted values retain the process handler. |
| `olcLogFileRotate` | `max Mbytes hours`: 1-99 archives; at least one limit must be nonzero. Zero disables that limit. Deletion disables rotation. |

Rotation occurs before a write would exceed the byte limit (1 MiB = 1048576
bytes) or when the age limit has been reached. Archives use `.01` for the most
recent and `.02` onwards for older files. Rotation uses unique temporary names
and preserves an existing unrelated `.tmp`. Existing nonempty files use Unix
inode change time as the initial age, matching slapd; Windows uses modification
time. Empty files start aging when opened. Limits are evaluated on writes, not
by a timer. Same-path online changes retain the file's age and size accounting.

Validation parses settings without opening files. Startup and online runtime
preparation open a candidate only after other configuration checks succeed.
Activation transfers the prepared descriptor after storage commits, without a
second open. Failed transactions preserve both persisted settings and the live
destination, close candidate descriptors, and leave existing file contents
untouched. A newly created empty candidate file can remain after rollback.
Out-of-order runtime activation closes discarded candidates. Shutdown closes
the active destination after draining operations and background workers.

The implementation and tests contain no cgo. Live tests use the external pinned
OpenLDAP 2.6.13 executable and compare Modify result codes, stored values,
deletion, numeric rotation syntax, and actual timestamp-prefix shapes. A pinned
`logging.c` source contract checks rotation limits, naming, and creation flags.
The syntax matrix disables output before modifying rotation limits: the pinned
reference was observed deadlocking in `logfile_mutex` during concurrent logging
and reconfiguration. Concurrent rotation/reconfiguration checks run against Go;
this OpenLDAP race is not reproduced as a compatibility requirement.

Deliberate differences from slapd:

- Symlinks, hardlinks, directories, devices, and FIFOs are refused as logfile
  targets. The containing directory is pinned by an `os.Root` descriptor, and
  rotation verifies the active inode before renaming. Rotation refuses
  non-regular archive targets. The directory must be administered by a trusted
  account; these checks do not make arbitrary concurrent directory mutations
  transactional.
- Failed writes or rotation fall back to the process handler even when
  `olcLogFileOnly` is true. With no destination, file-only never discards records.
  Rotation failure keeps the writable descriptor; staging files containing old
  records are preserved if an archive rename cannot finish.
- Size thresholds use the actual encoded Go record length. Slapd tests the
  length of its debug prefix before substituting another format. Go debug
  records use `0x0` for the thread token and preserve structured attributes;
  there is no stable operating-system thread identity for a goroutine.
- Hours exceeding Go's duration range are rejected. Byte arithmetic uses 64
  bits instead of reproducing unsigned intermediate overflow in slapd.
- Multiline messages, keys, and values are quoted to keep each record on one
  line. Bound attributes retain their original slog group scope.

Run the focused checks with:

```sh
CGO_ENABLED=0 go test ./internal/server -run 'LogFile|LogLevel|MonitorLog|ActivateRuntime' -count=1
CGO_ENABLED=0 go test -race ./internal/server -run 'LogFile|MonitorLog|ActivateRuntime' -count=3
. /path/to/openldap-reference.env
CGO_ENABLED=0 LDAP_GO_OPENLDAP_REFERENCE_TESTS=1 go test ./internal/server -run 'TestOpenLDAPReference.*LogFile|TestOpenLDAP2613LogFileSourceContract' -count=1
```

The race command above works without cgo on macOS; toolchains on some other
platforms require cgo enabled for the race runtime itself.
