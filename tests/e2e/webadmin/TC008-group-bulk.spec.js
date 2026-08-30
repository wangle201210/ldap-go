const {
  test,
  expect,
  cleanupEntry,
  fillAttribute,
  fillPersonDialog,
  findAttributeRow,
  login,
  openEntryFromResults,
  openLogin,
  runSearch
} = require("../support/fixtures");

async function expectOK(responsePromise, operation) {
  const response = await responsePromise;
  const body = await response.text();
  expect(response.ok(), `${operation}: ${response.status()} ${body}`).toBeTruthy();
  return body ? JSON.parse(body) : null;
}

async function createPerson(page, dn, values) {
  await page.locator("#new-entry-button").click();
  await expect(page.locator("#entry-dialog")).toBeVisible();
  await page.locator("#new-entry-template").selectOption("person");
  await fillPersonDialog(page, dn, values);

  const responsePromise = page.waitForResponse((response) =>
    response.url().endsWith("/api/entries") && response.request().method() === "POST"
  );
  await page.locator("#entry-form button[type='submit']").click();
  await expectOK(responsePromise, "create temporary member");
  await expect(page.locator("#entry-dialog")).not.toBeVisible();
  await expect(page.locator("#detail-dn")).toHaveText(dn);
}

async function createGroup(page, dn, cn, initialMember) {
  await page.locator("#new-entry-button").click();
  await expect(page.locator("#entry-dialog")).toBeVisible();
  await page.locator("#new-entry-template").selectOption("group");
  await page.locator("#new-entry-dn").fill(dn);
  await page.locator("#new-entry-dn").blur();
  await fillAttribute(page, "#new-entry-attribute-list", "cn", cn);
  await fillAttribute(page, "#new-entry-attribute-list", "member", initialMember);
  await fillAttribute(page, "#new-entry-attribute-list", "description", "created by TC008");

  const responsePromise = page.waitForResponse((response) =>
    response.url().endsWith("/api/entries") && response.request().method() === "POST"
  );
  await page.locator("#entry-form button[type='submit']").click();
  await expectOK(responsePromise, "create groupOfNames");
  await expect(page.locator("#entry-dialog")).not.toBeVisible();
  await expect(page.locator("#detail-dn")).toHaveText(dn);
}

function memberRow(page, memberDN) {
  return page.locator("#group-member-list .group-member-row").filter({ hasText: memberDN });
}

async function reopenGroup(page, groupDN) {
  await runSearch(page, {
    base: groupDN,
    scope: "base",
    attributes: "objectClass,cn,member,description"
  });
  await openEntryFromResults(page, groupDN);
  await expect(page.locator("#group-members")).toBeVisible();
}

async function callBulkInCurrentSession(page, requestBody) {
  return page.evaluate(async (body) => {
    const sessionResponse = await fetch("/api/session", {
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    });
    const sessionText = await sessionResponse.text();
    if (!sessionResponse.ok) {
      return { ok: false, status: sessionResponse.status, body: sessionText, stage: "session" };
    }
    const session = JSON.parse(sessionText);
    const response = await fetch("/api/bulk", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-CSRF-Token": session.csrf_token
      },
      body: JSON.stringify(body)
    });
    const text = await response.text();
    return {
      ok: response.ok,
      status: response.status,
      body: text ? JSON.parse(text) : null,
      stage: "bulk"
    };
  }, requestBody);
}

test("TC008 manages direct and nested group relationships and reports partial bulk results", async ({ page, e2e }, testInfo) => {
  const memberUID = `group-member-${e2e.runID}`;
  const memberDN = `uid=${memberUID},${e2e.peopleDN}`;
  const groupCN = `group-${e2e.runID}`;
  const groupDN = `cn=${groupCN},${e2e.baseDN}`;
	const parentGroupCN = `parent-group-${e2e.runID}`;
	const parentGroupDN = `cn=${parentGroupCN},${e2e.baseDN}`;
  const missingDN = `uid=missing-${e2e.runID},${e2e.peopleDN}`;
  const bulkDescription = `updated by TC008 ${e2e.runID}`;

  await openLogin(page, e2e);
  await login(page, e2e);

  try {
    await createPerson(page, memberDN, {
      uid: memberUID,
      cn: `Group Member ${e2e.runID}`,
      sn: "Member",
      description: "temporary TC008 member"
    });
    await createGroup(page, groupDN, groupCN, e2e.fixtureDN);
	await createGroup(page, parentGroupDN, parentGroupCN, groupDN);
	await reopenGroup(page, groupDN);

    const objectClassRow = await findAttributeRow(page, "#attribute-list", "objectClass");
    await expect(objectClassRow.locator(".attribute-values")).toHaveValue(/(?:^|\n)groupOfNames(?:\n|$)/);
    await expect(page.locator("#group-members")).toBeVisible();
    await expect(memberRow(page, e2e.fixtureDN)).toHaveCount(1);
    await expect(memberRow(page, e2e.fixtureDN).locator("small")).toHaveText(/^(Direct|直接成员)$/);

	await page.setViewportSize({ width: 320, height: 568 });
	await page.locator('#language-switch [data-language="zh-CN"]').click();
	await expect(page.locator("#browse-group-members")).toHaveText("浏览成员");
	await page.locator("#browse-group-members").click();
	await expect(page.locator("#member-picker-dialog")).toBeVisible();
	await expect(page.locator("#member-picker-base")).toBeFocused();
	await expect(page.locator("#member-picker-title")).toHaveText("选择组成员");
	await expect(page.locator("label[for='member-picker-base']")).toHaveText("搜索基础 DN");
	await expect(page.locator("#member-picker-target")).toHaveText(groupDN);
	await page.locator("#member-picker-base").fill(e2e.peopleDN);
	await page.locator("#member-picker-filter").fill(`(uid=${memberUID})`);
	const pickerSearchResponse = page.waitForResponse((response) =>
	  response.url().endsWith("/api/search") && response.request().method() === "POST" &&
	  response.request().postDataJSON().filter === `(uid=${memberUID})`
	);
	await page.locator("#member-picker-search").click();
	await expectOK(pickerSearchResponse, "search member picker");
	const pickerResult = page.locator("#member-picker-results .member-picker-result").filter({ hasText: memberDN });
	await expect(pickerResult).toHaveCount(1);
	await pickerResult.locator('input[type="checkbox"]').focus();
	await page.keyboard.press("Space");
	await expect(pickerResult.locator('input[type="checkbox"]')).toBeChecked();
	await expect(page.locator("#member-picker-add")).toBeEnabled();
	const pickerGeometry = await page.locator("#member-picker-dialog").evaluate((dialog) => {
	  const box = dialog.getBoundingClientRect();
	  const results = dialog.querySelector("#member-picker-results");
	  return {
		left: box.left, right: box.right, top: box.top, bottom: box.bottom,
		viewportWidth: window.innerWidth, viewportHeight: window.innerHeight,
		resultsClientWidth: results.clientWidth, resultsScrollWidth: results.scrollWidth
	  };
	});
	expect(pickerGeometry.left).toBeGreaterThanOrEqual(-1);
	expect(pickerGeometry.right).toBeLessThanOrEqual(pickerGeometry.viewportWidth + 1);
	expect(pickerGeometry.top).toBeGreaterThanOrEqual(-1);
	expect(pickerGeometry.bottom).toBeLessThanOrEqual(pickerGeometry.viewportHeight + 1);
	expect(pickerGeometry.resultsScrollWidth).toBeLessThanOrEqual(pickerGeometry.resultsClientWidth + 1);
	await page.screenshot({ path: testInfo.outputPath("tc008-member-picker.png"), fullPage: true });
	const addResponse = page.waitForResponse((response) =>
	  response.url().endsWith("/api/groups") && response.request().method() === "PATCH"
	);
	await page.locator("#member-picker-add").click();
	await expect(expectOK(addResponse, "add direct group member")).resolves.toMatchObject({
      dn: groupDN,
      atomic: true,
      results: [{ operation: "add", attribute: "member", values: [memberDN], status: "applied" }]
	});
	await expect(page.locator("#member-picker-dialog")).not.toBeVisible();
	await expect(memberRow(page, memberDN)).toHaveCount(1);
	await page.locator('#language-switch [data-language="en"]').click();
	await page.setViewportSize({ width: 1440, height: 900 });

	await runSearch(page, {
	  base: memberDN,
	  scope: "base",
	  attributes: "objectClass,uid,cn,sn,description"
	});
	await openEntryFromResults(page, memberDN);
	await expect(page.locator("#entry-memberships")).toBeVisible();
	const directMembershipResponse = page.waitForResponse((response) =>
	  response.url().includes("/api/groups?") && response.url().includes("member_dn=") && response.url().includes("nested=false")
	);
	await page.locator("#refresh-entry-memberships").click();
	const directMemberships = await expectOK(directMembershipResponse, "load direct group memberships");
	expect(directMemberships.memberships.groups).toEqual([
	  expect.objectContaining({
		dn: groupDN, direct: true, depth: 0,
		references: [{ attribute: "member", value: memberDN }]
	  })
	]);
	await expect(page.locator("#entry-membership-list .entry-membership-row").filter({ hasText: groupDN })).toContainText("Direct");

	const nestedMembershipResponse = page.waitForResponse((response) =>
	  response.url().includes("/api/groups?") && response.url().includes("member_dn=") && response.url().includes("nested=true")
	);
	await page.locator("#include-nested-memberships").check();
	const nestedMemberships = await expectOK(nestedMembershipResponse, "load nested group memberships");
	expect(nestedMemberships.memberships.groups).toEqual([
	  expect.objectContaining({
		dn: groupDN, direct: true, depth: 0,
		references: [{ attribute: "member", value: memberDN }]
	  }),
	  expect.objectContaining({
		dn: parentGroupDN, direct: false, depth: 1, via_dn: groupDN,
		references: [{ attribute: "member", value: groupDN }]
	  })
	]);
	await expect(page.locator("#entry-membership-list .entry-membership-row").filter({ hasText: parentGroupDN })).toContainText(groupDN);
	await page.setViewportSize({ width: 390, height: 844 });
	const membershipGeometry = await page.locator("#entry-memberships").evaluate((section) => ({
	  clientWidth: section.clientWidth,
	  scrollWidth: section.scrollWidth,
	  viewportWidth: window.innerWidth,
	  right: section.getBoundingClientRect().right
	}));
	expect(membershipGeometry.scrollWidth).toBeLessThanOrEqual(membershipGeometry.clientWidth + 1);
	expect(membershipGeometry.right).toBeLessThanOrEqual(membershipGeometry.viewportWidth + 1);
	await page.screenshot({ path: testInfo.outputPath("tc008-user-memberships.png"), fullPage: true });
	await page.setViewportSize({ width: 1440, height: 900 });

	await reopenGroup(page, groupDN);
    await expect(memberRow(page, e2e.fixtureDN)).toHaveCount(1);
    await expect(memberRow(page, memberDN)).toHaveCount(1);
    await expect(memberRow(page, memberDN).locator("small")).toHaveText(/^(Direct|直接成员)$/);

    const addedMemberRow = memberRow(page, memberDN);
    await addedMemberRow.locator("input[type='checkbox']").check();
    await expect(page.locator("#remove-group-members")).toBeEnabled();
    const removeResponse = page.waitForResponse((response) =>
      response.url().endsWith("/api/groups") && response.request().method() === "PATCH"
    );
    await page.locator("#remove-group-members").click();
    await expect(expectOK(removeResponse, "remove direct group member")).resolves.toMatchObject({
      dn: groupDN,
      atomic: true,
      results: [{ operation: "remove", attribute: "member", values: [memberDN], status: "applied" }]
    });
    await expect(memberRow(page, memberDN)).toHaveCount(0);

    await reopenGroup(page, groupDN);
    await expect(memberRow(page, e2e.fixtureDN)).toHaveCount(1);
    await expect(memberRow(page, memberDN)).toHaveCount(0);

	await runSearch(page, {
	  base: e2e.baseDN,
	  scope: "sub",
	  filter: `(|(uid=${memberUID})(cn=${groupCN}))`,
	  attributes: "objectClass,uid,cn,mail,description"
	});
	const memberResult = page.locator(`#entry-table-body tr[data-dn="${memberDN}"]`);
	const groupResult = page.locator(`#entry-table-body tr[data-dn="${groupDN}"]`);
	await memberResult.locator('input[type="checkbox"]').check();
	await groupResult.locator('input[type="checkbox"]').check();
	await page.locator("#bulk-modify-button").click();
	await page.locator("#bulk-operation").selectOption("replace");
	await page.locator("#bulk-attribute").fill("mail");
	await page.locator("#bulk-values").fill(`${memberUID}@example.test`);
	await page.locator("#bulk-continue").check();
	const uiBulkResponse = page.waitForResponse((response) =>
	  response.url().endsWith("/api/bulk") && response.request().method() === "POST"
	);
	await page.locator("#bulk-modify-form button[type='submit']").click();
	const uiBulk = await uiBulkResponse;
	const uiBulkBody = await uiBulk.json();
	expect(uiBulk.ok(), JSON.stringify(uiBulkBody)).toBeTruthy();
	expect(uiBulkBody).toMatchObject({ applied: 1, failed: 1, unknown: 0 });
	await expect(page.locator("#bulk-modify-dialog")).toBeVisible();
	await expect(page.locator("#bulk-modify-error")).toContainText(groupDN);
	await page.locator("#bulk-modify-dialog .modal-actions .close-dialog").click();

    const bulkResult = await callBulkInCurrentSession(page, {
      action: "modify",
      dns: [memberDN, missingDN],
      changes: [{ operation: "replace", attribute: "description", values: [bulkDescription] }],
      continue_on_error: true
    });
    expect(bulkResult.stage, JSON.stringify(bulkResult)).toBe("bulk");
    expect(bulkResult.ok, JSON.stringify(bulkResult.body)).toBeTruthy();
    expect(bulkResult.status).toBe(200);
    expect(bulkResult.body).toMatchObject({
      action: "modify",
      applied: 1,
      failed: 1,
      unknown: 0,
      results: [
        { dn: memberDN, success: true, status: "applied" },
        { dn: missingDN, success: false, status: "failed" }
      ]
    });
    expect(bulkResult.body.results).toHaveLength(2);
    expect(bulkResult.body.results[1].error).toMatchObject({
      code: "ldap_error",
      ldap_result_code: 32
    });

    await runSearch(page, {
      base: memberDN,
      scope: "base",
      attributes: "objectClass,uid,cn,sn,description"
    });
    await openEntryFromResults(page, memberDN);
    const descriptionRow = await findAttributeRow(page, "#attribute-list", "description");
    await expect(descriptionRow.locator(".attribute-values, .schema-value-control").first()).toHaveValue(bulkDescription);
  } finally {
	await cleanupEntry(e2e, parentGroupDN);
    await cleanupEntry(e2e, groupDN);
    await cleanupEntry(e2e, memberDN);
  }
});
