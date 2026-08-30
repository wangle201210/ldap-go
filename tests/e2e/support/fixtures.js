const { test: base, expect, request } = require("@playwright/test");
const { loadEnvironment } = require("./runtime");

const test = base.extend({
  e2e: [async ({}, use) => use(loadEnvironment()), { scope: "worker" }]
});

async function openLogin(page, e2e) {
  await page.goto(e2e.webURL, { waitUntil: "domcontentloaded" });
  await expect(page.locator("#login-dialog")).toBeVisible();
  await expect(page.locator("#app-shell")).toHaveAttribute("aria-busy", /^(true|false)$/);
}

async function login(page, e2e, credentials = {}, options = {}) {
  if (!page.url().startsWith(e2e.webURL)) await openLogin(page, e2e);
  const bindDN = credentials.dn || e2e.rootDN;
  const password = credentials.password || e2e.rootPassword;
  await page.locator("#login-dn").fill(bindDN);
  await page.locator("#login-password").fill(password);
  const responsePromise = page.waitForResponse((response) =>
    response.url().endsWith("/api/login") && response.request().method() === "POST"
  );
  await page.locator("#login-submit").click();
  const response = await responsePromise;
  expect(response.ok(), `login response: ${response.status()} ${await response.text()}`).toBeTruthy();
  await expect(page.locator("#login-dialog")).not.toBeVisible();
  await expect(page.locator("#account-dn")).toHaveText(bindDN);
  if (options.waitForWorkspace !== false) await waitForWorkspace(page);
}

async function waitForWorkspace(page) {
  await expect(page.locator("#app-shell")).toHaveAttribute("aria-busy", "false");
  await expect(page.locator("#connection-label")).toHaveText(/^(Connected|已连接)$/);
  await expect(page.locator("#entry-table-wrap")).toBeVisible();
  await expect(page.locator("#content-state")).toBeHidden();
}

async function runSearch(page, query) {
  await page.locator("#search-tab").click();
  await page.locator("#search-base").fill(query.base);
  await page.locator("#search-filter").fill(query.filter || "(objectClass=*)");
  await page.locator("#search-scope").selectOption(query.scope || "sub");
  await page.locator("#search-size").fill(String(query.size || 50));
  await page.locator("#search-attributes").fill(query.attributes || "objectClass,uid,cn,sn,description,modifyTimestamp");
  const responsePromise = page.waitForResponse((response) =>
    response.url().endsWith("/api/search") && response.request().method() === "POST"
  );
  await page.locator("#search-form button[type='submit']").click();
  const response = await responsePromise;
  expect(response.ok(), `search response: ${response.status()} ${await response.text()}`).toBeTruthy();
  await expect.poll(async () => {
    const state = page.locator("#content-state");
    return await state.isVisible() ? await state.locator("strong").textContent() : "complete";
  }).not.toMatch(/Loading entries|正在加载条目/);
}

function rowForDN(page, dn) {
  return page.locator(`#entry-table-body tr[data-dn="${dn.replaceAll('"', '\\"')}"]`);
}

async function openEntryFromResults(page, dn) {
  const row = rowForDN(page, dn);
  await expect(row).toBeVisible();
  await row.click();
  await expect(page.locator("#detail-dn")).toHaveText(dn);
  await expect(page.locator("#detail-view")).toBeVisible();
}

async function findAttributeRow(page, container, attribute) {
  const rows = page.locator(`${container} .attribute-row`);
  for (let index = 0; index < await rows.count(); index += 1) {
    const row = rows.nth(index);
    if ((await row.locator(".attribute-name").inputValue()).toLowerCase() === attribute.toLowerCase()) {
      return row;
    }
  }
  throw new Error(`attribute row ${attribute} was not rendered in ${container}`);
}

async function fillAttribute(page, container, attribute, value) {
  const row = await findAttributeRow(page, container, attribute);
  const control = row.locator(".attribute-values, .schema-value-control").first();
  await control.fill(value);
}

async function fillPersonDialog(page, dn, values) {
  await page.locator("#new-entry-dn").fill(dn);
  await page.locator("#new-entry-dn").blur();
  await fillAttribute(page, "#new-entry-attribute-list", "uid", values.uid);
  await fillAttribute(page, "#new-entry-attribute-list", "cn", values.cn);
  await fillAttribute(page, "#new-entry-attribute-list", "sn", values.sn);
  if (values.mail !== undefined) {
    await fillAttribute(page, "#new-entry-attribute-list", "mail", values.mail);
  }
  if (values.description !== undefined) {
    await fillAttribute(page, "#new-entry-attribute-list", "description", values.description);
  }
}

async function cleanupEntry(e2e, dn) {
  const context = await request.newContext({
    baseURL: e2e.webURL,
    extraHTTPHeaders: { Origin: e2e.webURL }
  });
  try {
    const loginResponse = await context.post("/api/login", {
      data: { bind_dn: e2e.rootDN, password: e2e.rootPassword }
    });
	    if (!loginResponse.ok()) throw new Error(`cleanup login failed: ${loginResponse.status()} ${await loginResponse.text()}`);
    const session = await loginResponse.json();
	    const deletion = await context.delete("/api/entries", {
      headers: { "X-CSRF-Token": session.csrf_token },
      data: { dn }
    });
	    if (!deletion.ok() && deletion.status() !== 404) {
	      throw new Error(`cleanup delete failed for ${dn}: ${deletion.status()} ${await deletion.text()}`);
	    }
	    const logout = await context.post("/api/logout", {
      headers: { "X-CSRF-Token": session.csrf_token },
      data: {}
    });
	    if (!logout.ok()) throw new Error(`cleanup logout failed: ${logout.status()} ${await logout.text()}`);
  } finally {
    await context.dispose();
  }
}

module.exports = {
  test,
  expect,
  cleanupEntry,
  fillAttribute,
  fillPersonDialog,
  findAttributeRow,
  login,
  openEntryFromResults,
  openLogin,
  rowForDN,
  runSearch,
  waitForWorkspace
};
