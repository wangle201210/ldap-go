---
name: ldap-go-webadmin-review
description: Review ldap-go Web administration UI, browser behavior, API integration, accessibility, i18n, performance, and E2E evidence. Use for frontend reviews and before shipping Web Admin changes.
---

# ldap-go Web Admin Review

Review the current workspace, not only the latest diff. Start with `git status --short` and include tracked and untracked files relevant to Web Admin.

## Scope

Primary files:

- `internal/webadmin/static/index.html`
- `internal/webadmin/static/app.js`
- `internal/webadmin/static/styles.css`
- `internal/webadmin/*_test.go`
- `cmd/ldap-go/web_admin*.go`

Read API handlers when frontend behavior depends on response limits, partial success, ACLs, referrals, or cancellation.

## Required Review Areas

1. Session isolation: logout, 401, account replacement, localStorage namespacing, cached DNs and selected targets.
2. Async correctness: capture mutation targets before `await`, latest-wins reads, cancellation, paging history, retry safety after `applied` or `unknown`.
3. Contract and performance: discover server limits instead of hardcoding; avoid `*, +`, per-row/per-attribute requests, unbounded DOM creation, and whole-file reads before client checks.
4. Workflows: login, tree/search, CRUD, rename/move, password, group membership, bulk, LDIF/CSV, binary, schema, monitor, export.
5. Accessibility: tree/table semantics, focus after hidden-pane transitions, dialogs, errors, live regions, menus, focus contrast, keyboard-only operation.
6. Responsive UI: at least 1440x900, 900x800, 390x844, 320x568, and low-height landscape.
7. i18n: English and Simplified Chinese visible text, dynamic errors/toasts, ARIA/title, persisted locale, and no translated LDAP values.
8. Test evidence: browser-executed success and failure paths with screenshots; source-string assertions are not sufficient.

## Verification

Run the repository equivalents that exist:

```sh
go test ./internal/webadmin ./cmd/ldap-go
go test -race ./internal/webadmin
go vet ./internal/webadmin ./cmd/ldap-go
node --check internal/webadmin/static/app.js
git diff --check
```

Use the available browser-control tool. If browser execution is unavailable, state that limitation and use DOM execution only as partial evidence; do not claim visual or E2E coverage.

Report findings first, ordered by severity, with file and line references. Distinguish repository bugs from LinaPro/Vben-specific conventions that do not apply to this vanilla frontend.
