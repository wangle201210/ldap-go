const {
  test,
  expect,
  cleanupEntry,
  fillPersonDialog,
  findAttributeRow,
  login,
  openEntryFromResults,
  openLogin,
  runSearch
} = require("../support/fixtures");

test("TC005 discovers server limits and omits blank optional Person attributes", async ({ page, e2e }) => {
  const uid = `limits-${e2e.runID}`;
  const dn = `uid=${uid},${e2e.peopleDN}`;

  await openLogin(page, e2e);
  const capabilitiesResponse = page.waitForResponse((response) =>
    response.url().endsWith("/api/capabilities") && response.request().method() === "GET"
  );
	const initialSearchRequest = page.waitForRequest((request) =>
	  request.url().endsWith("/api/search") && request.method() === "POST"
	);
  await login(page, e2e);

  const capabilities = await capabilitiesResponse;
  expect(capabilities.ok(), `capabilities response: ${capabilities.status()} ${await capabilities.text()}`).toBeTruthy();
  await expect(capabilities.json()).resolves.toMatchObject({ max_search_size: 100 });
  await expect(page.locator("#search-size")).toHaveAttribute("max", "100");
  await expect(page.locator("#search-size")).toHaveValue("100");
	const initialSearch = (await initialSearchRequest).postDataJSON();
	expect(initialSearch).toMatchObject({ size_limit: 100, page_size: 100 });

  try {
    await page.locator("#new-entry-button").click();
    await expect(page.locator("#entry-dialog")).toBeVisible();
	const personSuggestions = await page.locator("#attribute-name-options option").evaluateAll((options) => options.map((option) => option.value.toLowerCase()));
	expect(personSuggestions).toEqual(expect.arrayContaining(["cn", "sn", "userpassword"]));
	expect(personSuggestions).not.toContain("olcpasswordhash");
	await page.locator("#new-entry-template").selectOption("custom");
	await expect.poll(() => page.locator("#attribute-name-options option").evaluateAll((options) => options.map((option) => option.value.toLowerCase()))).toContain("olcpasswordhash");
	await page.locator("#new-entry-template").selectOption("person");
    await fillPersonDialog(page, dn, {
      uid,
      cn: `Limits User ${e2e.runID}`,
      sn: "OptionalFields"
    });

    const createRequestPromise = page.waitForRequest((request) =>
      request.url().endsWith("/api/entries") && request.method() === "POST"
    );
    const createResponsePromise = page.waitForResponse((response) =>
      response.url().endsWith("/api/entries") && response.request().method() === "POST"
    );
    await page.locator("#entry-form button[type='submit']").click();

    const createRequest = await createRequestPromise;
    const payload = createRequest.postDataJSON();
    const attributes = Object.fromEntries(
      Object.entries(payload.attributes || {}).map(([name, values]) => [name.toLowerCase(), values])
    );
    expect(attributes).not.toHaveProperty("mail");
    expect(attributes).not.toHaveProperty("description");
    expect(Object.values(attributes)).not.toContainEqual([]);

    const createResponse = await createResponsePromise;
    const createBody = await createResponse.text();
    expect(createResponse.ok(), `create entry: ${createResponse.status()} ${createBody}`).toBeTruthy();
    await expect(page.locator("#entry-dialog")).not.toBeVisible();

    await runSearch(page, { base: dn, scope: "base" });
    await openEntryFromResults(page, dn);
    await expect((await findAttributeRow(page, "#attribute-list", "uid")).locator(".attribute-values")).toHaveValue(uid);
    await expect((await findAttributeRow(page, "#attribute-list", "cn")).locator(".attribute-values")).toHaveValue(`Limits User ${e2e.runID}`);
    await expect((await findAttributeRow(page, "#attribute-list", "sn")).locator(".attribute-values")).toHaveValue("OptionalFields");
  } finally {
    await cleanupEntry(e2e, dn);
  }
});
