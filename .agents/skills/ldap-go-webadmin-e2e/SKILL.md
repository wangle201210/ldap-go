---
name: ldap-go-webadmin-e2e
description: Create and run browser E2E coverage for ldap-go Web Admin against real disposable LDAP and Web processes, including CRUD, bulk, import/export, i18n, accessibility, and responsive screenshots.
---

# ldap-go Web Admin E2E

Use a real disposable `ldap-go serve` process and a real `ldap-go web-admin` process. Do not replace LDAP behavior with request mocks for release-gate tests.

## Organization

Store tests under `tests/e2e/webadmin/` using `TC{NNN}-{brief-name}.spec.js`. Keep shared browser helpers in `tests/e2e/support/`. Every test must create unique DNs and clean them in `finally` or fixture teardown.

## Minimum Cases

- Authentication, logout, session replacement, and cross-account state clearing.
- Tree loading, filter search, paging, and server limit discovery.
- Create, read back, edit, rename/move, password reset, delete, ACL denial.
- Group direct/nested membership.
- Bulk partial failure, unknown result, and retry protection.
- LDIF/CSV import partial success and export content.
- Binary preview, replacement, download, deletion, and size rejection.
- English/Chinese text, ARIA labels, dynamic errors, and locale persistence.
- Keyboard-only tree/table/dialog flows and mobile pane transitions.

## Viewports And Screenshots

Capture viewport screenshots after initial load, dialogs, successful mutations, error states, search results, and mobile detail views at:

- 1440x900
- 900x800
- 390x844
- 320x568

Store temporary screenshots below `temp/<YYYYMMDD>/` and remove them unless the task requests artifacts. Check for overlap, clipped text, hidden actions, untranslated keys, stale loading states, and obscured sticky controls.

Assertions must prove the resulting LDAP state, not only that a button exists or a dialog closed. Run each test independently and as part of the full suite.
