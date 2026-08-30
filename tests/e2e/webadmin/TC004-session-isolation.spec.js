const {
  test,
  expect,
  login,
  openEntryFromResults,
  openLogin,
  rowForDN,
  runSearch,
  waitForWorkspace
} = require("../support/fixtures");

const SAVED_QUERY_KEY = "ldap-go.webadmin.savedQueries";
const QUERY_HISTORY_KEY = "ldap-go.webadmin.queryHistory";

test("TC004 logout isolates directory state and saved queries by account", async ({ page, e2e }) => {
  const queryName = `Session query ${e2e.runID}`;

  await page.addInitScript(({ savedQueryKey, queryHistoryKey }) => {
    localStorage.setItem(savedQueryKey, JSON.stringify([{ name: "legacy query", query: {} }]));
    localStorage.setItem(queryHistoryKey, JSON.stringify([{ base: "dc=legacy,dc=test" }]));
  }, { savedQueryKey: SAVED_QUERY_KEY, queryHistoryKey: QUERY_HISTORY_KEY });

  await openLogin(page, e2e);
  await login(page, e2e);

  await expect(rowForDN(page, e2e.peopleDN)).toBeVisible();
  await expect(page.locator(`#directory-tree .tree-node[data-dn="${e2e.baseDN}"]`)).toBeVisible();
  await expect(page.locator(`#directory-tree .tree-node[data-dn="${e2e.peopleDN}"]`)).toBeVisible();

  await runSearch(page, {
    base: e2e.peopleDN,
    scope: "sub",
    filter: `(uid=${e2e.fixtureUID})`
  });
  await openEntryFromResults(page, e2e.fixtureDN);

  page.once("dialog", async (dialog) => {
    expect(dialog.type()).toBe("prompt");
    await dialog.accept(queryName);
  });
  await page.locator("#save-query").click();
  await expect(page.locator("#saved-query-list")).toContainText(queryName);

  const storage = await page.evaluate(({ bindDN, savedQueryKey, queryHistoryKey }) => {
    const bytes = new TextEncoder().encode(`${window.location.origin}\0${bindDN.toLowerCase()}`);
    let raw = "";
    bytes.forEach((value) => { raw += String.fromCharCode(value); });
    const scope = window.btoa(raw).replace(/=+$/, "");
    const scopedSavedQueryKey = `${savedQueryKey}.${scope}`;
    const scopedQueryHistoryKey = `${queryHistoryKey}.${scope}`;
    return {
      legacySavedQuery: localStorage.getItem(savedQueryKey),
      legacyQueryHistory: localStorage.getItem(queryHistoryKey),
      scopedSavedQueryKey,
      scopedQueryHistoryKey,
      savedQueries: JSON.parse(localStorage.getItem(scopedSavedQueryKey) || "[]"),
      queryHistory: JSON.parse(localStorage.getItem(scopedQueryHistoryKey) || "[]"),
      keys: Object.keys(localStorage)
    };
  }, { bindDN: e2e.rootDN, savedQueryKey: SAVED_QUERY_KEY, queryHistoryKey: QUERY_HISTORY_KEY });

  expect(storage.legacySavedQuery).toBeNull();
  expect(storage.legacyQueryHistory).toBeNull();
  expect(storage.keys).toContain(storage.scopedSavedQueryKey);
  expect(storage.keys).toContain(storage.scopedQueryHistoryKey);
  expect(storage.savedQueries).toContainEqual(expect.objectContaining({ name: queryName }));
  expect(storage.queryHistory).toEqual(expect.arrayContaining([
    expect.objectContaining({ base: e2e.peopleDN, filter: `(uid=${e2e.fixtureUID})` })
  ]));

	await page.locator("#search-tab").click();
	await page.locator("#search-filter").fill(`(description=session-secret-${e2e.runID})`);
	await page.locator("#import-button").click();
	await page.locator("#import-content").fill(`dn: uid=session-secret-${e2e.runID},${e2e.peopleDN}`);
	await page.locator("#import-dialog .modal-actions .close-dialog").click();
	await page.locator("#account-button").click();
	await page.locator("#menu-import-csv").click();
	await page.locator("#csv-import-content").fill(`uid\nsession-secret-${e2e.runID}`);
	await page.locator("#csv-import-dialog .modal-actions .close-dialog").click();

  await page.locator("#account-button").click();
  const logoutResponse = page.waitForResponse((response) =>
    response.url().endsWith("/api/logout") && response.request().method() === "POST"
  );
  await page.locator("#logout-button").click();
  expect((await logoutResponse).ok()).toBeTruthy();

  await expect(page.locator("#login-dialog")).toBeVisible();
  await expect(page.locator("#entry-table-body tr")).toHaveCount(0);
  await expect(rowForDN(page, e2e.fixtureDN)).toHaveCount(0);
  await expect(page.locator("#detail-dn")).toBeEmpty();
  await expect(page.locator("#detail-view")).toBeHidden();
  await expect(page.locator("#directory-tree .tree-node")).toHaveCount(0);
  await expect(page.locator("#saved-query-list option", { hasText: queryName })).toHaveCount(0);
	await expect(page.locator("#search-filter")).toHaveValue("(objectClass=*)");
	await expect(page.locator("#import-content")).toHaveValue("");
	await expect(page.locator("#csv-import-content")).toHaveValue("");

	  await login(page, e2e, { dn: e2e.secondaryDN, password: e2e.secondaryPassword });
	  await waitForWorkspace(page);
	  await expect(page.locator("#account-dn")).toHaveText(e2e.secondaryDN);
	  await expect(page.locator("#saved-query-list option", { hasText: queryName })).toHaveCount(0);
	  await expect(page.locator("#recent-query-list")).not.toContainText(`(uid=${e2e.fixtureUID})`);
	  await page.locator("#account-button").click();
	  const secondaryLogout = page.waitForResponse((response) =>
	    response.url().endsWith("/api/logout") && response.request().method() === "POST"
	  );
	  await page.locator("#logout-button").click();
	  expect((await secondaryLogout).ok()).toBeTruthy();
	  await expect(page.locator("#login-dialog")).toBeVisible();

	  await login(page, e2e);
	  await waitForWorkspace(page);
  await expect(rowForDN(page, e2e.peopleDN)).toBeVisible();
  await page.locator("#tree-tab").click();
  await expect(page.locator(`#directory-tree .tree-node[data-dn="${e2e.baseDN}"]`)).toBeVisible();
  await expect(page.locator(`#directory-tree .tree-node[data-dn="${e2e.peopleDN}"]`)).toBeVisible();
  await expect(page.locator("#saved-query-list")).toContainText(queryName);
});
