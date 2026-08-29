(function () {
  "use strict";

  const state = {
    csrf: "",
    session: null,
    rootDN: "",
    namingContexts: [],
    baseDN: "",
    entries: [],
    selectedDN: "",
    selectedEntry: null,
    schema: { objectClasses: [], attributeTypes: [] },
	schemaView: "classes",
    monitor: null,
    currentQuery: null,
    activeRequests: 0,
    editorDirty: false,
    treeNodes: new Map(),
	confirmResolve: null,
	searchSequence: 0,
	entrySequence: 0,
	pageHistory: [],
	currentPageCookie: "",
	nextPageCookie: ""
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  const elements = {
    shell: $("#app-shell"),
    workspace: $("#workspace"),
    activity: $("#activity-line"),
    connectionDot: $("#connection-dot"),
    connectionLabel: $("#connection-label"),
    rootLabel: $("#root-label"),
    accountButton: $("#account-button"),
    accountMenu: $("#account-menu"),
    accountName: $("#account-name"),
    accountDN: $("#account-dn"),
    accountAvatar: $("#account-avatar"),
    tree: $("#directory-tree"),
    treeCount: $("#tree-count"),
    searchForm: $("#search-form"),
    contentState: $("#content-state"),
    tableWrap: $("#entry-table-wrap"),
    tableBody: $("#entry-table-body"),
    listView: $("#list-view"),
    detailView: $("#detail-view"),
    listButton: $("#list-view-button"),
    detailButton: $("#detail-view-button"),
    contentTitle: $("#content-title"),
    contentSubtitle: $("#content-subtitle"),
    breadcrumb: $("#breadcrumb"),
    resultSummary: $("#result-summary"),
	previousPage: $("#previous-page"),
	nextPage: $("#next-page"),
    detailName: $("#detail-name"),
    detailDN: $("#detail-dn"),
    detailKind: $("#detail-kind"),
    detailAvatar: $("#detail-avatar"),
    detailStatus: $("#detail-status"),
    attributeList: $("#attribute-list"),
    attributeCount: $("#attribute-count"),
    editorStatus: $("#editor-status"),
    entryEditor: $("#entry-editor"),
    schemaList: $("#schema-list"),
    schemaSearch: $("#schema-search"),
    monitorHealth: $("#monitor-health"),
    metricGrid: $("#metric-grid"),
    monitorList: $("#monitor-list"),
    loginDialog: $("#login-dialog"),
    loginForm: $("#login-form"),
    loginError: $("#login-error"),
    entryDialog: $("#entry-dialog"),
    renameDialog: $("#rename-dialog"),
    passwordDialog: $("#password-dialog"),
    importDialog: $("#import-dialog"),
    confirmDialog: $("#confirm-dialog"),
    toastRegion: $("#toast-region")
  };

  class APIError extends Error {
    constructor(message, status, details) {
      super(message);
      this.name = "APIError";
      this.status = status;
      this.details = details;
    }
  }

  function drawDirectoryMark(canvas) {
    if (!canvas) return;
    const ratio = window.devicePixelRatio || 1;
    const cssWidth = Number(canvas.getAttribute("width"));
    const cssHeight = Number(canvas.getAttribute("height"));
    canvas.width = cssWidth * ratio;
    canvas.height = cssHeight * ratio;
    const context = canvas.getContext("2d");
    context.scale(ratio, ratio);
    context.clearRect(0, 0, cssWidth, cssHeight);
    context.fillStyle = "#e6f5f0";
    context.strokeStyle = "#70cbb4";
    context.lineWidth = 1.5;
    const points = [
      [cssWidth / 2, 7],
      [9, cssHeight - 9],
      [cssWidth / 2, cssHeight - 9],
      [cssWidth - 9, cssHeight - 9]
    ];
    context.beginPath();
    context.moveTo(points[0][0], points[0][1] + 4);
    context.lineTo(points[0][0], cssHeight / 2);
    context.lineTo(points[1][0], cssHeight / 2);
    context.moveTo(points[0][0], cssHeight / 2);
    context.lineTo(points[3][0], cssHeight / 2);
    points.slice(1).forEach((point) => {
      context.moveTo(point[0], cssHeight / 2);
      context.lineTo(point[0], point[1] - 4);
    });
    context.stroke();
    points.forEach((point, index) => {
      const size = index === 0 ? 9 : 7;
      context.fillStyle = index === 0 ? "#54c9a8" : "#e6f5f0";
      context.strokeStyle = "#70cbb4";
      context.fillRect(point[0] - size / 2, point[1] - size / 2, size, size);
      context.strokeRect(point[0] - size / 2, point[1] - size / 2, size, size);
    });
  }

  function setBusy(active) {
    state.activeRequests += active ? 1 : -1;
    state.activeRequests = Math.max(0, state.activeRequests);
    elements.activity.hidden = state.activeRequests === 0;
    elements.shell.setAttribute("aria-busy", state.activeRequests > 0 ? "true" : "false");
  }

  function csrfFrom(data) {
    if (!data || typeof data !== "object") return "";
    return data.csrfToken || data.csrf_token || data.csrf || data.token || (data.session && csrfFrom(data.session)) || "";
  }

  function errorMessage(data, fallback) {
    if (!data) return fallback;
    if (typeof data === "string") return data.trim() || fallback;
    if (data.error && typeof data.error === "object") {
	  const message = data.error.message || data.error.code || fallback;
	  return Number.isInteger(data.error.applied) && data.error.applied > 0
	    ? `${message} (${data.error.applied} changes already applied)`
	    : message;
    }
    return data.error || data.message || data.diagnostic || data.detail || fallback;
  }

  async function api(path, options = {}) {
    const method = options.method || "GET";
    const headers = new Headers(options.headers || {});
    headers.set("Accept", options.accept || "application/json");
    let body = options.body;
    if (body !== undefined && body !== null && !options.rawBody && !(body instanceof FormData)) {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(body);
    }
    if (!["GET", "HEAD", "OPTIONS"].includes(method) && state.csrf && path !== "/api/login") {
      headers.set("X-CSRF-Token", state.csrf);
    }
    setBusy(true);
    try {
      const response = await fetch(path, { method, headers, body, credentials: "same-origin" });
      let data = null;
	  if (options.responseType === "blob" && response.ok) {
        data = await response.blob();
      } else if (response.status !== 204) {
        const contentType = response.headers.get("content-type") || "";
        if (contentType.includes("json")) {
          data = await response.json().catch(() => null);
        } else {
          data = await response.text().catch(() => "");
        }
      }
      if (!response.ok) {
        if (response.status === 401 && path !== "/api/login" && path !== "/api/session") showLogin();
        throw new APIError(errorMessage(data, `${method} ${path} failed`), response.status, data);
      }
      const token = csrfFrom(data);
      if (token) state.csrf = token;
      return { data, response };
    } catch (error) {
      if (error instanceof APIError) throw error;
      throw new APIError(error.message || "The server could not be reached", 0, null);
    } finally {
      setBusy(false);
    }
  }

  function showLogin(message = "") {
    setConnection("error", "Authentication required");
    elements.loginError.hidden = !message;
    elements.loginError.textContent = message;
    if (!elements.loginDialog.open) elements.loginDialog.showModal();
    requestAnimationFrame(() => $("#login-dn").focus());
  }

  function setConnection(kind, label) {
    elements.connectionDot.className = `status-dot ${kind || ""}`.trim();
    elements.connectionLabel.textContent = label;
  }

  function setSession(session) {
    state.session = session || {};
    const user = session.user && typeof session.user === "object" ? session.user : {};
    const dn = session.dn || session.bind_dn || session.bindDN || session.bindDn || user.dn || user.name || "Administrator";
    const name = session.displayName || user.displayName || user.cn || rdnValue(dn) || "Administrator";
    elements.accountName.textContent = name;
    elements.accountDN.textContent = dn;
    elements.accountAvatar.textContent = initials(name);
    setConnection("online", "Connected");
  }

  function sessionAuthenticated(data) {
    if (!data || typeof data !== "object") return false;
    if (data.authenticated === false || data.loggedIn === false || data.logged_in === false) return false;
    return data.authenticated === true || data.loggedIn === true || data.logged_in === true || Boolean(data.dn || data.bind_dn || data.bindDN || data.user || data.session);
  }

  function unwrap(data, keys) {
    let current = data;
    if (current && current.data !== undefined && Object.keys(current).length <= 3) current = current.data;
    for (const key of keys) {
      if (current && current[key] !== undefined) return current[key];
    }
    return current;
  }

  function toValues(value) {
    if (value === null || value === undefined) return [];
    if (Array.isArray(value)) return value.map((item) => item === null || item === undefined ? "" : String(item));
    if (typeof value === "object" && Array.isArray(value.values)) return toValues(value.values);
    if (typeof value === "object" && Array.isArray(value.vals)) return toValues(value.vals);
    return [String(value)];
  }

  function normalizeAttributes(attributes) {
    const result = {};
    if (!attributes) return result;
    if (Array.isArray(attributes)) {
      attributes.forEach((attribute) => {
        if (!attribute || typeof attribute !== "object") return;
        const name = attribute.name || attribute.type || attribute.attribute || attribute.description;
        if (name) result[name] = toValues(attribute.values !== undefined ? attribute.values : attribute.vals !== undefined ? attribute.vals : attribute.value);
      });
      return result;
    }
    if (typeof attributes === "object") {
      Object.entries(attributes).forEach(([name, value]) => { result[name] = toValues(value); });
    }
    return result;
  }

  function normalizeEntry(entry) {
    if (typeof entry === "string") return { dn: entry, attributes: {} };
    const source = entry && entry.entry && typeof entry.entry === "object" ? entry.entry : (entry || {});
    const attributes = normalizeAttributes(source.attributes || source.attrs || source.attributesByName);
	const binaryAttributes = normalizeAttributes(source.binary_attributes || source.binaryAttributes);
    const dn = source.dn || source.distinguishedName || source.distinguished_name || source.name || firstAttribute(attributes, "entryDN") || "";
	return { ...source, dn: String(dn), attributes, binaryAttributes };
  }

  function normalizeEntries(data) {
    const raw = unwrap(data, ["entries", "results", "items"]);
    if (!raw) return [];
    if (Array.isArray(raw)) return raw.map(normalizeEntry).filter((entry) => entry.dn);
    if (typeof raw === "object" && raw.dn) return [normalizeEntry(raw)];
    return [];
  }

  function attributeValues(entry, name) {
    if (!entry || !entry.attributes) return [];
    const key = Object.keys(entry.attributes).find((candidate) => candidate.toLowerCase() === name.toLowerCase());
    return key ? toValues(entry.attributes[key]) : [];
  }

  function firstAttribute(attributes, name) {
    const key = Object.keys(attributes || {}).find((candidate) => candidate.toLowerCase() === name.toLowerCase());
    return key ? toValues(attributes[key])[0] || "" : "";
  }

  function splitDN(dn) {
    const parts = [];
    let part = "";
    let escaped = false;
    let quoted = false;
    for (const character of String(dn || "")) {
      if (escaped) { part += character; escaped = false; continue; }
      if (character === "\\") { part += character; escaped = true; continue; }
      if (character === '"') { part += character; quoted = !quoted; continue; }
      if (character === "," && !quoted) { parts.push(part.trim()); part = ""; continue; }
      part += character;
    }
    if (part.trim()) parts.push(part.trim());
    return parts;
  }

  function parentDN(dn) { return splitDN(dn).slice(1).join(","); }
  function rdn(dn) { return splitDN(dn)[0] || String(dn || ""); }
  function rdnValue(dn) {
    const value = rdn(dn);
    const index = value.indexOf("=");
    return (index >= 0 ? value.slice(index + 1) : value).replace(/\\([,=+<>#;"\\])/g, "$1");
  }
  function initials(value) {
    const words = String(value || "A").replace(/[=,]/g, " ").split(/\s+/).filter(Boolean);
    return words.slice(0, 2).map((word) => word[0]).join("").toUpperCase() || "A";
  }
  function shortClass(value) {
    const text = String(value || "EN");
    const capitals = text.match(/[A-Z]/g);
    return (capitals && capitals.length >= 2 ? capitals.slice(0, 2).join("") : text.slice(0, 2)).toUpperCase();
  }
  function entryType(entry) {
    const classes = attributeValues(entry, "objectClass").filter((value) => value.toLowerCase() !== "top");
    return classes[classes.length - 1] || "entry";
  }
  function formatDate(value) {
    if (!value) return "-";
    const generalized = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(String(value));
    const date = generalized ? new Date(`${generalized[1]}-${generalized[2]}-${generalized[3]}T${generalized[4]}:${generalized[5]}:${generalized[6]}Z`) : new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" }).format(date);
  }

  function showState(kind, title, message, action) {
    elements.contentState.className = `state-view ${kind || ""}`.trim();
    elements.contentState.replaceChildren();
    if (kind === "loading") {
      const spinner = document.createElement("div");
      spinner.className = "spinner";
      spinner.setAttribute("aria-hidden", "true");
      elements.contentState.append(spinner);
    } else {
      const symbol = document.createElement("div");
      symbol.className = "state-symbol";
      symbol.setAttribute("aria-hidden", "true");
      symbol.textContent = kind === "error" ? "!" : "0";
      elements.contentState.append(symbol);
    }
    const heading = document.createElement("strong");
    heading.textContent = title;
    elements.contentState.append(heading);
    if (message) {
      const paragraph = document.createElement("p");
      paragraph.textContent = message;
      elements.contentState.append(paragraph);
    }
    if (action) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "button quiet";
      button.textContent = action.label;
      button.addEventListener("click", action.handler);
      elements.contentState.append(button);
    }
    elements.contentState.hidden = false;
    elements.tableWrap.hidden = true;
  }

  function toast(title, message = "", kind = "success") {
    const item = document.createElement("div");
    item.className = `toast ${kind}`;
    item.setAttribute("role", kind === "error" ? "alert" : "status");
    const icon = document.createElement("strong");
    icon.textContent = kind === "error" ? "!" : "OK";
    const copy = document.createElement("div");
    const heading = document.createElement("strong");
    heading.textContent = title;
    const detail = document.createElement("span");
    detail.textContent = message;
    copy.append(heading, detail);
    const close = document.createElement("button");
    close.type = "button";
    close.setAttribute("aria-label", "Dismiss notification");
    close.textContent = "\u00d7";
    close.addEventListener("click", () => item.remove());
    item.append(icon, copy, close);
    elements.toastRegion.append(item);
    window.setTimeout(() => item.remove(), kind === "error" ? 9000 : 5000);
  }

  function setFieldError(element, message) {
    element.textContent = message || "";
    element.hidden = !message;
  }

  async function initialize() {
    drawDirectoryMark($("#brand-mark"));
    drawDirectoryMark($("#login-mark"));
    bindEvents();
    try {
      const { data } = await api("/api/session");
      if (!sessionAuthenticated(data)) { showLogin(); return; }
      setSession(unwrap(data, ["session"]));
      await loadWorkspace();
    } catch (error) {
      if (error.status === 401) showLogin();
      else {
        setConnection("error", "Server unavailable");
        showState("error", "Directory unavailable", error.message, { label: "Retry", handler: () => window.location.reload() });
      }
    } finally {
      elements.shell.setAttribute("aria-busy", "false");
    }
  }

  async function loadWorkspace() {
    const { data } = await api("/api/root-dse");
    const rootData = unwrap(data, ["root", "rootDSE"]);
    const rootEntry = normalizeEntry(rootData);
    const contexts = rootData && (rootData.namingContexts || rootData.naming_contexts || rootData.contexts);
    const entryContexts = attributeValues(rootEntry, "namingContexts");
    state.namingContexts = entryContexts.length ? entryContexts : (Array.isArray(contexts) ? contexts.map(String) : contexts ? [String(contexts)] : []);
    state.rootDN = String((typeof rootData === "string" ? rootData : "") || (rootData && (rootData.rootDN || rootData.rootDn || rootData.baseDN || rootData.base)) || state.namingContexts[0] || "");
    if (!state.namingContexts.length) state.namingContexts = [state.rootDN];
    state.baseDN = state.rootDN;
    elements.rootLabel.textContent = state.namingContexts.length > 1 ? `${state.namingContexts.length} naming contexts` : state.rootDN || "Root DSE";
    $("#search-base").value = state.rootDN;
    buildTreeRoot();
    await Promise.allSettled([
      ...state.namingContexts.map((dn) => loadTreeChildren(dn)),
      runSearch({ base: state.rootDN, scope: "one", filter: "(objectClass=*)", attributes: "*, +", size: 500 }),
      loadSchema()
    ]);
  }

  function buildTreeRoot() {
    state.treeNodes.clear();
    elements.tree.replaceChildren();
    state.namingContexts.forEach((dn) => elements.tree.append(createTreeNode(dn, 0, true).element));
    selectTreeRow(state.rootDN);
    renderBreadcrumb(state.rootDN);
  }

  function createTreeNode(dn, depth, expanded = false) {
    const container = document.createElement("div");
    container.className = "tree-node";
    container.dataset.dn = dn;
    const row = document.createElement("div");
    row.className = "tree-node-row";
    row.setAttribute("role", "treeitem");
    row.setAttribute("aria-level", String(depth + 1));
    row.setAttribute("aria-expanded", String(expanded));
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "tree-toggle";
    toggle.setAttribute("aria-label", `Expand ${rdnValue(dn) || "root"}`);
    toggle.textContent = expanded ? "\u25be" : "\u203a";
    const icon = document.createElement("span");
    icon.className = "tree-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = depth === 0 ? "DC" : "DN";
    const select = document.createElement("button");
    select.type = "button";
    select.className = "tree-select";
    select.title = dn || "Root DSE";
    select.textContent = rdnValue(dn) || "Root DSE";
    const count = document.createElement("span");
    count.className = "tree-count";
    const children = document.createElement("div");
    children.className = "tree-children";
    children.setAttribute("role", "group");
    children.hidden = !expanded;
    toggle.addEventListener("click", async () => {
      const model = state.treeNodes.get(dn);
      if (!model.loaded) await loadTreeChildren(dn);
      const open = model.children.hidden;
      model.children.hidden = !open;
      model.toggle.textContent = open ? "\u25be" : "\u203a";
      model.row.setAttribute("aria-expanded", String(open));
    });
    select.addEventListener("click", async () => {
      state.baseDN = dn;
      $("#search-base").value = dn;
      selectTreeRow(dn);
      await runSearch({ base: dn, scope: "one", filter: "(objectClass=*)", attributes: "*, +", size: 500 });
      setMobileView("content");
    });
	select.addEventListener("keydown", (event) => {
	  const visible = $$(".tree-select", elements.tree).filter((button) => !button.closest(".tree-children")?.hidden);
	  const index = visible.indexOf(select);
	  if (event.key === "ArrowDown" && index < visible.length - 1) {
		event.preventDefault(); visible[index + 1].focus();
	  } else if (event.key === "ArrowUp" && index > 0) {
		event.preventDefault(); visible[index - 1].focus();
	  } else if (event.key === "ArrowRight") {
		event.preventDefault(); if (children.hidden) toggle.click();
	  } else if (event.key === "ArrowLeft") {
		event.preventDefault();
		if (!children.hidden) toggle.click();
		else {
		  const parent = container.parentElement?.closest(".tree-node")?.querySelector(":scope > .tree-node-row .tree-select");
		  if (parent) parent.focus();
		}
	  }
	});
    row.append(toggle, icon, select, count);
    container.append(row, children);
    const model = { dn, depth, element: container, row, toggle, count, children, loaded: false };
    state.treeNodes.set(dn, model);
    return model;
  }

  async function loadTreeChildren(dn, force = false) {
    const node = state.treeNodes.get(dn);
    if (!node || (node.loaded && !force)) return;
    node.children.hidden = false;
    node.children.replaceChildren();
    const loading = document.createElement("div");
    loading.className = "tree-loading";
    loading.textContent = "Loading";
    node.children.append(loading);
    try {
	  const entries = [];
	  let cookie = "";
	  for (let page = 0; page < 20; page += 1) {
		const { data } = await api("/api/search", {
		  method: "POST",
		  body: searchRequest({ base: dn, scope: "one", filter: "(objectClass=*)", attributes: "objectClass", size: 5000 }, cookie, 250)
		});
		entries.push(...normalizeEntries(data));
		cookie = data && (data.page_cookie || data.pageCookie) || "";
		if (!cookie) break;
	  }
	  entries.sort((a, b) => a.dn.localeCompare(b.dn));
      node.children.replaceChildren();
      entries.forEach((entry) => node.children.append(createTreeNode(entry.dn, node.depth + 1).element));
      node.loaded = true;
      node.count.textContent = entries.length ? String(entries.length) : "";
      if (!entries.length) node.toggle.classList.add("empty");
      node.toggle.textContent = "\u25be";
      node.row.setAttribute("aria-expanded", "true");
      elements.treeCount.textContent = `${state.treeNodes.size} ${state.treeNodes.size === 1 ? "entry" : "entries"} loaded`;
    } catch (error) {
      node.children.replaceChildren();
      const failure = document.createElement("button");
      failure.type = "button";
      failure.className = "text-button tree-loading";
      failure.textContent = "Retry loading";
      failure.addEventListener("click", () => loadTreeChildren(dn, true));
      node.children.append(failure);
      toast("Tree load failed", error.message, "error");
    }
  }

  function selectTreeRow(dn) {
    state.treeNodes.forEach((node) => node.row.classList.toggle("selected", node.dn === dn));
  }

  function queryFromForm() {
    const form = new FormData(elements.searchForm);
    return {
      base: String(form.get("base") || state.rootDN),
      scope: String(form.get("scope") || "sub"),
      filter: String(form.get("filter") || "(objectClass=*)"),
      attributes: String(form.get("attributes") || "*, +"),
      size: Number(form.get("size") || 500)
    };
  }

  function attributeSelectors(value) {
    if (Array.isArray(value)) return value.map(String).map((item) => item.trim()).filter(Boolean);
    return String(value || "").split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);
  }

	function searchRequest(query, cookie = "", pageSize = 200) {
	const request = {
      base_dn: query.base || "",
      scope: query.scope || "sub",
      filter: query.filter || "(objectClass=*)",
      attributes: attributeSelectors(query.attributes || "*, +"),
	  size_limit: Number(query.size || 500),
	  page_size: Math.min(Number(query.size || 500), pageSize)
    };
	if (cookie) request.page_cookie = cookie;
	return request;
  }

	async function runSearch(query = queryFromForm(), cookie = null) {
	const sequence = ++state.searchSequence;
	if (cookie === null) {
	  state.pageHistory = [];
	  state.currentPageCookie = "";
	  state.nextPageCookie = "";
	  cookie = "";
	}
    state.currentQuery = query;
    state.baseDN = query.base;
    showListView();
    showState("loading", "Loading entries", "");
    elements.contentTitle.textContent = rdnValue(query.base) || "Directory entries";
    elements.contentSubtitle.textContent = query.base || "Root DSE";
    renderBreadcrumb(query.base);
    try {
	  const { data } = await api("/api/search", { method: "POST", body: searchRequest(query, cookie) });
	  if (sequence !== state.searchSequence) return;
      state.entries = normalizeEntries(data);
	  state.currentPageCookie = cookie;
	  state.nextPageCookie = data && (data.page_cookie || data.pageCookie) || "";
      renderEntries();
    } catch (error) {
	  if (sequence !== state.searchSequence) return;
      state.entries = [];
      elements.resultSummary.textContent = "Search failed";
      showState("error", "Search failed", error.message, { label: "Retry", handler: () => runSearch(query) });
    }
  }

  function renderEntries() {
    elements.tableBody.replaceChildren();
    elements.resultSummary.textContent = `${state.entries.length} ${state.entries.length === 1 ? "entry" : "entries"}`;
	elements.previousPage.disabled = state.pageHistory.length === 0;
	elements.nextPage.disabled = !state.nextPageCookie;
    if (!state.entries.length) {
      showState("empty", "No entries found", state.currentQuery ? state.currentQuery.filter : "");
      return;
    }
    const fragment = document.createDocumentFragment();
    state.entries.forEach((entry) => {
      const row = document.createElement("tr");
      row.tabIndex = 0;
      row.dataset.dn = entry.dn;
      row.classList.toggle("selected", entry.dn === state.selectedDN);
      const type = entryType(entry);
      const description = attributeValues(entry, "description")[0] || attributeValues(entry, "title")[0] || "-";
      const modified = attributeValues(entry, "modifyTimestamp")[0] || attributeValues(entry, "createTimestamp")[0];
      const nameCell = document.createElement("td");
      const nameWrap = document.createElement("div");
      nameWrap.className = "entry-name";
      const icon = document.createElement("span");
      icon.className = "entry-name-icon";
      icon.textContent = shortClass(type);
      const name = document.createElement("span");
      name.textContent = rdnValue(entry.dn);
      name.title = entry.dn;
      nameWrap.append(icon, name);
      nameCell.append(nameWrap);
      [nameCell, cell(type), cell(description), cell(formatDate(modified))].forEach((item) => row.append(item));
      const openCell = document.createElement("td");
      openCell.className = "row-open";
      openCell.textContent = "\u203a";
      row.append(openCell);
      row.addEventListener("click", () => openEntry(entry.dn));
      row.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); openEntry(entry.dn); } });
      fragment.append(row);
    });
    elements.tableBody.append(fragment);
    elements.contentState.hidden = true;
    elements.tableWrap.hidden = false;
  }

  function cell(value) {
    const element = document.createElement("td");
    element.textContent = value;
    element.title = value;
    return element;
  }

  async function openEntry(dn) {
    if (state.editorDirty && !(await confirmAction("Discard unsaved changes?", "Changes in the current entry will be lost.", "Discard"))) return;
	const sequence = ++state.entrySequence;
    state.selectedDN = dn;
    updateEntryActions(true);
    $$("tr[data-dn]", elements.tableBody).forEach((row) => row.classList.toggle("selected", row.dataset.dn === dn));
    elements.detailButton.disabled = false;
    showDetailView();
    elements.attributeList.replaceChildren();
    elements.detailName.textContent = "Loading entry";
    elements.detailDN.textContent = dn;
    try {
	  const { data } = await api(`/api/entries?${new URLSearchParams({ dn })}`);
	  if (sequence !== state.entrySequence || state.selectedDN !== dn) return;
      state.selectedEntry = normalizeEntry(unwrap(data, ["entry"]));
      renderEntryDetail(state.selectedEntry);
    } catch (error) {
	  if (sequence !== state.entrySequence || state.selectedDN !== dn) return;
      state.selectedEntry = null;
      elements.detailName.textContent = "Entry unavailable";
      const message = document.createElement("div");
      message.className = "state-view error";
      message.textContent = error.message;
      elements.attributeList.append(message);
      toast("Entry load failed", error.message, "error");
    }
  }

  function renderEntryDetail(entry) {
    state.editorDirty = false;
    const type = entryType(entry);
    const displayName = attributeValues(entry, "displayName")[0] || attributeValues(entry, "cn")[0] || rdnValue(entry.dn);
    elements.detailName.textContent = displayName;
    elements.detailDN.textContent = entry.dn;
    elements.detailKind.textContent = type;
    elements.detailAvatar.textContent = initials(displayName);
    const locked = attributeValues(entry, "pwdAccountLockedTime").length > 0;
    elements.detailStatus.textContent = locked ? "Locked" : "Active";
    elements.attributeList.replaceChildren();
    const attributes = Object.entries(entry.attributes || {}).sort(([a], [b]) => {
      const order = ["objectclass", "cn", "sn", "uid", "mail", "description"];
      const ai = order.indexOf(a.toLowerCase());
      const bi = order.indexOf(b.toLowerCase());
      if (ai !== -1 || bi !== -1) return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
      return a.localeCompare(b);
    });
	attributes.forEach(([name, values]) => addAttributeRow(name, values, { readOnly: isReadOnlyAttribute(name) }));
	Object.entries(entry.binaryAttributes || {}).sort(([a], [b]) => a.localeCompare(b)).forEach(
	  ([name, values]) => addAttributeRow(name, values, { readOnly: true, binary: true })
	);
    updateAttributeCount();
    setEditorStatus(false);
    renderSchema();
  }

	function addAttributeRow(name = "", values = [], options = {}) {
    const row = $("#attribute-row-template").content.firstElementChild.cloneNode(true);
    const nameInput = $(".attribute-name", row);
    const valuesInput = $(".attribute-values", row);
    const meta = $(".attribute-meta", row);
    nameInput.value = name;
    valuesInput.value = toValues(values).join("\n");
	meta.textContent = options.binary ? "Binary values · Base64" : schemaLabel(name);
    row.dataset.originalName = name;
	row.dataset.originalText = valuesInput.value;
	row.dataset.readOnly = options.readOnly ? "true" : "false";
	if (options.readOnly) {
	  row.classList.add("read-only");
	  nameInput.readOnly = true;
	  valuesInput.readOnly = true;
	  $(".remove-attribute", row).hidden = true;
	}
    $(".remove-attribute", row).addEventListener("click", () => { row.remove(); markDirty(); updateAttributeCount(); });
    [nameInput, valuesInput].forEach((input) => input.addEventListener("input", () => { meta.textContent = schemaLabel(nameInput.value); markDirty(); }));
    elements.attributeList.append(row);
    if (!name) nameInput.focus();
    updateAttributeCount();
  }

	const operationalReadOnlyAttributes = new Set([
	  "creatorsname", "modifiersname", "createtimestamp", "modifytimestamp",
	  "entryuuid", "entrycsn", "structuralobjectclass", "subschemasubentry",
	  "contextcsn", "hassubordinates", "entrydn"
	]);
	function isReadOnlyAttribute(name) {
	  if (operationalReadOnlyAttributes.has(String(name).toLowerCase())) return true;
	  const definition = state.schema.attributeTypes.find((attribute) => schemaName(attribute).toLowerCase() === String(name).toLowerCase());
	  const text = typeof definition === "string" ? definition : definition && definition.definition;
	  return typeof text === "string" && /\bNO-USER-MODIFICATION\b/i.test(text);
	}

  function schemaLabel(name) {
    if (!name) return "New attribute";
    const definition = state.schema.attributeTypes.find((attribute) => schemaName(attribute).toLowerCase() === name.toLowerCase());
    const syntax = definition && (definition.syntax || definition.syntaxName || definition.description || definition.desc);
    return syntax ? String(syntax) : "Directory attribute";
  }

  function markDirty() { state.editorDirty = true; setEditorStatus(true); }
  function setEditorStatus(dirty) { elements.editorStatus.textContent = dirty ? "Unsaved changes" : "No unsaved changes"; }
  function updateAttributeCount() {
    const count = $$(".attribute-row", elements.attributeList).length;
    elements.attributeCount.textContent = `${count} ${count === 1 ? "attribute" : "attributes"}`;
  }
  function collectAttributeRows(container) {
    const attributes = {};
	$$(".attribute-row", container).forEach((row) => {
      const name = $(".attribute-name", row).value.trim();
      if (!name) return;
	  const text = $(".attribute-values", row).value.replace(/\r\n/g, "\n");
	  const values = text === "" ? [] : text.split("\n");
      attributes[name] = values;
    });
    return attributes;
  }

  const entryTemplates = {
	person: {
	  rdn: "uid", classes: ["top", "person", "organizationalPerson", "inetOrgPerson"],
	  attributes: [["uid", []], ["cn", []], ["sn", []], ["mail", []], ["description", []]]
	},
	group: {
	  rdn: "cn", classes: ["top", "groupOfNames"],
	  attributes: [["cn", []], ["member", []], ["description", []]]
	},
	ou: {
	  rdn: "ou", classes: ["top", "organizationalUnit"],
	  attributes: [["ou", []], ["description", []]]
	},
	custom: { rdn: "cn", classes: ["top"], attributes: [["cn", []]] }
  };

  function addCreateAttributeRow(name = "", values = []) {
	const row = $("#attribute-row-template").content.firstElementChild.cloneNode(true);
	const nameInput = $(".attribute-name", row);
	const valuesInput = $(".attribute-values", row);
	const meta = $(".attribute-meta", row);
	nameInput.value = name;
	valuesInput.value = toValues(values).join("\n");
	meta.textContent = schemaLabel(name);
	$(".remove-attribute", row).addEventListener("click", () => row.remove());
	nameInput.addEventListener("input", () => { meta.textContent = schemaLabel(nameInput.value); });
	$("#new-entry-attribute-list").append(row);
	if (!name) nameInput.focus();
  }

  function renderEntryTemplate(name) {
	const template = entryTemplates[name] || entryTemplates.custom;
	$("#new-entry-classes").value = template.classes.join("\n");
	$("#new-entry-attribute-list").replaceChildren();
	template.attributes.forEach(([attribute, values]) => addCreateAttributeRow(attribute, values));
	$("#new-entry-dn").value = state.baseDN ? `${template.rdn}=,${state.baseDN}` : `${template.rdn}=`;
  }

	function syncCreateRDNAttribute() {
	const first = rdn($("#new-entry-dn").value.trim());
	const separator = first.indexOf("=");
	if (separator <= 0) return;
	const attribute = first.slice(0, separator).trim().toLowerCase();
	const value = first.slice(separator + 1).trim();
	if (!value) return;
	const row = $$(".attribute-row", $("#new-entry-attribute-list")).find(
	  (candidate) => $(".attribute-name", candidate).value.trim().toLowerCase() === attribute
	);
	if (row && !$(".attribute-values", row).value) $(".attribute-values", row).value = value;
  }

	function validateCreateEntry(attributes) {
	const template = $("#new-entry-template").value;
	const required = { person: ["uid", "cn", "sn"], group: ["cn", "member"], ou: ["ou"], custom: [] }[template] || [];
	for (const name of required) {
	  const key = Object.keys(attributes).find((candidate) => candidate.toLowerCase() === name);
	  if (!key || !attributes[key].some((value) => value !== "")) return `${name} is required for this entry type`;
	}
	if (template === "custom" && lines($("#new-entry-classes").value).filter((value) => value.toLowerCase() !== "top").length === 0) {
	  return "Custom entries require a structural object class";
	}
	return "";
  }

	function attributeChanges(original) {
    const originalAttributes = original && original.attributes ? original.attributes : {};
    const changes = [];
	const retainedOriginalNames = new Set();
	$$(".attribute-row", elements.attributeList).forEach((row) => {
	  if (row.dataset.readOnly === "true") return;
	  const originalName = row.dataset.originalName || "";
	  const currentName = $(".attribute-name", row).value.trim();
	  const currentText = $(".attribute-values", row).value.replace(/\r\n/g, "\n");
	  if (originalName) retainedOriginalNames.add(originalName.toLowerCase());
	  if (originalName && currentName.toLowerCase() === originalName.toLowerCase() &&
		currentText === (row.dataset.originalText || "")) return;
	  if (originalName && currentName.toLowerCase() !== originalName.toLowerCase()) {
		changes.push({ operation: "delete", attribute: originalName, values: [] });
	  }
	  if (currentName) {
		const values = currentText === "" ? [] : currentText.split("\n");
		changes.push({ operation: originalName ? "replace" : "add", attribute: currentName, values });
	  }
	});
	Object.keys(originalAttributes).forEach((name) => {
	  if (!retainedOriginalNames.has(name.toLowerCase()) && !isReadOnlyAttribute(name)) {
		changes.push({ operation: "delete", attribute: name, values: [] });
	  }
	});
    return changes;
  }

  function showListView() {
    elements.listView.hidden = false;
    elements.detailView.hidden = true;
    elements.listButton.classList.add("active");
    elements.listButton.setAttribute("aria-pressed", "true");
    elements.detailButton.classList.remove("active");
    elements.detailButton.setAttribute("aria-pressed", "false");
  }
  function showDetailView() {
    elements.listView.hidden = true;
    elements.detailView.hidden = false;
    elements.listButton.classList.remove("active");
    elements.listButton.setAttribute("aria-pressed", "false");
    elements.detailButton.classList.add("active");
    elements.detailButton.setAttribute("aria-pressed", "true");
  }
  function updateEntryActions(enabled) { $$(".entry-action").forEach((button) => { button.disabled = !enabled; }); }

  function renderBreadcrumb(dn) {
    elements.breadcrumb.replaceChildren();
    const parts = splitDN(dn);
    if (!parts.length) { elements.breadcrumb.textContent = "Root DSE"; return; }
    const visible = parts.slice(0, 5);
    visible.reverse().forEach((part, index) => {
      const originalIndex = visible.length - index - 1;
      const targetDN = parts.slice(originalIndex).join(",");
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = rdnValue(part);
      button.title = targetDN;
      button.addEventListener("click", () => runSearch({ base: targetDN, scope: "one", filter: "(objectClass=*)", attributes: "*, +", size: 500 }));
      elements.breadcrumb.append(button);
      if (index < visible.length - 1) {
        const separator = document.createElement("span");
        separator.textContent = "/";
        separator.setAttribute("aria-hidden", "true");
        elements.breadcrumb.append(separator);
      }
    });
  }

  function normalizeSchema(data) {
    const source = unwrap(data, ["schema"]);
    if (!source || typeof source !== "object") return { objectClasses: [], attributeTypes: [] };
    const definitions = source.definitions && typeof source.definitions === "object" ? source.definitions : source;
    return {
      objectClasses: arrayFrom(definitions.objectClasses || definitions.objectclasses || definitions.classes).map(parseSchemaDefinition),
	  attributeTypes: arrayFrom(definitions.attributeTypes || definitions.attributetypes || definitions.attributes).map(parseSchemaDefinition),
	  rules: ["matchingRules", "matchingRuleUse", "ldapSyntaxes", "nameForms", "dITContentRules", "dITStructureRules"].flatMap(
		(type) => arrayFrom(definitions[type]).map((definition) => ({ type, ...parseSchemaDefinition(definition) }))
	  )
    };
  }
  function arrayFrom(value) {
    if (Array.isArray(value)) return value;
    if (value && typeof value === "object") return Object.entries(value).map(([name, detail]) => typeof detail === "object" ? { name, ...detail } : { name, description: String(detail) });
    return [];
  }
  function schemaName(definition) {
	if (typeof definition === "string") {
	  const names = /\bNAME\s+(?:'([^']+)'|\(\s*'([^']+)')/i.exec(definition);
	  if (names) return names[1] || names[2] || definition;
	  return definition.trim().split(/\s+/)[0] || definition;
	}
    const name = definition && (definition.name || definition.names || definition.Name || definition.oid);
    return Array.isArray(name) ? String(name[0] || "") : String(name || "");
  }
  function parseSchemaDefinition(definition) {
    if (typeof definition !== "string") return definition;
    const nameList = /\bNAME\s+\(\s*([^)]*)\)/i.exec(definition);
    const singleName = /\bNAME\s+'([^']+)'/i.exec(definition);
    const quoted = nameList ? [...nameList[1].matchAll(/'([^']+)'/g)].map((match) => match[1]) : [];
    const oid = /^\s*\(\s*([^\s)]+)/.exec(definition);
    const description = /\bDESC\s+'([^']*)'/i.exec(definition);
    return {
      name: quoted[0] || (singleName && singleName[1]) || (oid && oid[1]) || "Unnamed definition",
      aliases: quoted.slice(1),
      oid: oid ? oid[1] : "",
      description: description ? description[1] : "",
      definition
    };
  }
  async function loadSchema() {
    try {
      const { data } = await api("/api/schema");
      state.schema = normalizeSchema(data);
      renderSchema();
    } catch (error) {
      elements.schemaList.replaceChildren(contextMessage("Schema unavailable", error.message, true));
    }
  }
  function renderSchema() {
    const query = elements.schemaSearch.value.trim().toLowerCase();
    const selectedClasses = new Set(attributeValues(state.selectedEntry, "objectClass").map((value) => value.toLowerCase()));
	const source = state.schemaView === "attributes" ? state.schema.attributeTypes :
	  state.schemaView === "rules" ? state.schema.rules : state.schema.objectClasses;
	const classes = source.filter((definition) => {
      const text = JSON.stringify(definition).toLowerCase();
      if (query && !text.includes(query)) return false;
	  return state.schemaView !== "classes" || query || !selectedClasses.size || selectedClasses.has(schemaName(definition).toLowerCase());
    }).slice(0, 100);
    elements.schemaList.replaceChildren();
    if (!classes.length) {
	  elements.schemaList.append(contextMessage("No schema matches", query || "No definitions in this view"));
      return;
    }
    const title = document.createElement("div");
    title.className = "schema-group-title";
	title.textContent = state.schemaView === "attributes" ? "Attribute types" :
	  state.schemaView === "rules" ? "Matching and syntax rules" :
	  selectedClasses.size && !query ? "Applied to entry" : "Object classes";
    elements.schemaList.append(title);
    classes.forEach((definition) => elements.schemaList.append(schemaItem(definition)));
  }
  function schemaItem(definition) {
    const item = document.createElement("div");
    item.className = "schema-item";
    const button = document.createElement("button");
    button.type = "button";
    button.setAttribute("aria-expanded", "false");
    const badge = document.createElement("span");
    badge.className = "schema-badge";
	badge.textContent = state.schemaView === "attributes" ? "AT" : state.schemaView === "rules" ? "MR" : "OC";
    const name = document.createElement("span");
    name.className = "schema-name";
    name.textContent = schemaName(definition) || "Unnamed class";
    const chevron = document.createElement("span");
    chevron.className = "schema-chevron";
    chevron.textContent = "\u203a";
    const detail = document.createElement("div");
    detail.className = "schema-detail";
    detail.hidden = true;
    const fields = typeof definition === "string" ? { definition } : definition;
    const list = document.createElement("dl");
    Object.entries(fields || {}).filter(([key, value]) => value !== null && value !== undefined && key.toLowerCase() !== "name").slice(0, 8).forEach(([key, value]) => {
      const term = document.createElement("dt");
      term.textContent = key;
      const description = document.createElement("dd");
      description.textContent = Array.isArray(value) ? value.join(", ") : typeof value === "object" ? JSON.stringify(value) : String(value);
      list.append(term, description);
    });
    detail.append(list);
    button.append(badge, name, chevron);
    button.addEventListener("click", () => {
      const open = detail.hidden;
      detail.hidden = !open;
      button.setAttribute("aria-expanded", String(open));
      chevron.textContent = open ? "\u2304" : "\u203a";
    });
    item.append(button, detail);
    return item;
  }

  async function loadMonitor() {
    elements.monitorHealth.classList.remove("unhealthy");
    $("strong", elements.monitorHealth).textContent = "Checking server";
    $("small", elements.monitorHealth).textContent = "Waiting for monitor data";
    try {
      const { data } = await api("/api/monitor");
      state.monitor = unwrap(data, ["monitor", "metrics", "status"]);
      renderMonitor();
    } catch (error) {
      elements.monitorHealth.classList.add("unhealthy");
      $(".health-icon", elements.monitorHealth).textContent = "!";
      $("strong", elements.monitorHealth).textContent = "Monitor unavailable";
      $("small", elements.monitorHealth).textContent = error.message;
      elements.metricGrid.replaceChildren();
      elements.monitorList.replaceChildren();
    }
  }
  function flattenObject(value, prefix = "", output = []) {
    if (!value || typeof value !== "object") return output;
    Object.entries(value).forEach(([key, item]) => {
      const name = prefix ? `${prefix}.${key}` : key;
      if (item !== null && typeof item === "object" && !Array.isArray(item)) flattenObject(item, name, output);
      else output.push([name, Array.isArray(item) ? item.join(", ") : item]);
    });
    return output;
  }
  function renderMonitor() {
    const monitorEntries = normalizeEntries(state.monitor);
    const rows = monitorEntries.length ? monitorRows(monitorEntries, state.monitor) : flattenObject(state.monitor);
    const healthValue = rows.find(([key]) => /health|status|state/i.test(key));
    const unhealthy = healthValue && /down|fail|error|unhealthy|stopped/i.test(String(healthValue[1]));
    elements.monitorHealth.classList.toggle("unhealthy", Boolean(unhealthy));
    $(".health-icon", elements.monitorHealth).textContent = unhealthy ? "!" : "\u2713";
	$("strong", elements.monitorHealth).textContent = unhealthy ? "Monitor reports an issue" : "Monitor responding";
	$("small", elements.monitorHealth).textContent = healthValue ? String(healthValue[1]) : "LDAP Monitor data is available";
    const preferred = rows.filter(([key, value]) => /connection|operation|entry|uptime|thread|memory/i.test(key) && value !== "").slice(0, 6);
    const metrics = preferred.length ? preferred : rows.slice(0, 6);
    elements.metricGrid.replaceChildren();
    metrics.forEach(([key, value]) => {
      const wrapper = document.createElement("div");
      const term = document.createElement("dt");
      term.textContent = key.split(".").pop();
      term.title = key;
      const detail = document.createElement("dd");
      detail.textContent = formatMetric(value);
      detail.title = String(value);
      wrapper.append(term, detail);
      elements.metricGrid.append(wrapper);
    });
    elements.monitorList.replaceChildren();
    rows.filter(([key]) => !metrics.some(([metricKey]) => metricKey === key)).slice(0, 30).forEach(([key, value]) => {
      const row = document.createElement("div");
      row.className = "monitor-row";
      const name = document.createElement("span");
      name.textContent = key;
      const detail = document.createElement("span");
      detail.textContent = String(value);
      detail.title = String(value);
      row.append(name, detail);
      elements.monitorList.append(row);
    });
  }
  function monitorRows(entries, monitor) {
    const rows = [];
    if (monitor && monitor.base_dn) rows.push(["base_dn", monitor.base_dn]);
    entries.forEach((entry) => {
      const prefix = rdnValue(entry.dn) || entry.dn;
      Object.entries(entry.attributes).forEach(([name, values]) => rows.push([`${prefix}.${name}`, toValues(values).join(", ")]));
    });
    return rows;
  }
  function formatMetric(value) {
    if (typeof value === "number") return new Intl.NumberFormat().format(value);
    const numeric = Number(value);
    if (String(value).trim() && Number.isFinite(numeric)) return new Intl.NumberFormat().format(numeric);
    return String(value === undefined || value === null ? "-" : value);
  }
  function contextMessage(title, message, error = false) {
    const wrapper = document.createElement("div");
    wrapper.className = `state-view ${error ? "error" : ""}`.trim();
    wrapper.classList.add("context-message");
    const heading = document.createElement("strong");
    heading.textContent = title;
    const copy = document.createElement("p");
    copy.textContent = message || "";
    wrapper.append(heading, copy);
    return wrapper;
  }

  function openDialog(dialog) {
	const error = $(".form-error", dialog);
	if (error) setFieldError(error, "");
    if (!dialog.open) dialog.showModal();
  }
  function closeDialog(dialog) { if (dialog.open) dialog.close(); }
	function setFormSubmitting(form, submitting) {
	$$("button[type='submit']", form).forEach((button) => { button.disabled = submitting; });
	form.setAttribute("aria-busy", String(submitting));
  }
  function confirmAction(title, message, confirmLabel = "Confirm") {
    if (state.confirmResolve) state.confirmResolve(false);
    $("#confirm-title").textContent = title;
    $("#confirm-message").textContent = message;
    $("#confirm-submit").textContent = confirmLabel;
    openDialog(elements.confirmDialog);
    return new Promise((resolve) => { state.confirmResolve = resolve; });
  }
  function resolveConfirm(value) {
    if (!state.confirmResolve) return;
    const resolve = state.confirmResolve;
    state.confirmResolve = null;
    closeDialog(elements.confirmDialog);
    resolve(value);
  }

  function setMobileView(view) {
    elements.workspace.dataset.mobileView = view;
    $$("[data-mobile-view]").forEach((button) => button.classList.toggle("active", button.dataset.mobileView === view));
  }

  async function refreshAfterMutation(preferredDN = "") {
    if (preferredDN) state.selectedDN = preferredDN;
    await Promise.allSettled([runSearch(state.currentQuery || queryFromForm()), refreshTreeBranch(state.baseDN)]);
  }
  async function refreshTreeBranch(dn) {
    const node = state.treeNodes.get(dn) || state.treeNodes.get(parentDN(dn)) || state.treeNodes.get(state.rootDN);
    if (node) await loadTreeChildren(node.dn, true);
  }

  async function exportLDIF() {
    const query = state.currentQuery || queryFromForm();
	const params = new URLSearchParams({ base_dn: query.base, filter: query.filter, scope: query.scope || "sub" });
    try {
      const { data, response } = await api(`/api/export?${params}`, { responseType: "blob", accept: "text/plain, application/ldif" });
      const disposition = response.headers.get("content-disposition") || "";
      const match = /filename\*?=(?:UTF-8''|\")?([^";]+)/i.exec(disposition);
      const filename = match ? decodeURIComponent(match[1].replace(/"$/, "")) : "directory-export.ldif";
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.append(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      toast("Export complete", filename);
    } catch (error) { toast("Export failed", error.message, "error"); }
  }

  function bindTabs(first, second, firstPanel, secondPanel, secondLoader) {
    first.addEventListener("click", () => selectTab(true));
    second.addEventListener("click", () => { selectTab(false); if (secondLoader) secondLoader(); });
    function selectTab(isFirst) {
      first.setAttribute("aria-selected", String(isFirst));
      second.setAttribute("aria-selected", String(!isFirst));
      firstPanel.hidden = !isFirst;
      secondPanel.hidden = isFirst;
	  first.tabIndex = isFirst ? 0 : -1;
	  second.tabIndex = isFirst ? -1 : 0;
    }
	[first, second].forEach((tab) => tab.addEventListener("keydown", (event) => {
	  if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
	  event.preventDefault();
	  const target = tab === first ? second : first;
	  target.click();
	  target.focus();
	}));
	selectTab(first.getAttribute("aria-selected") === "true");
  }

  function bindEvents() {
    bindTabs($("#tree-tab"), $("#search-tab"), $("#tree-panel"), $("#search-panel"));
    bindTabs($("#schema-tab"), $("#monitor-tab"), $("#schema-panel"), $("#monitor-panel"), loadMonitor);
    elements.searchForm.addEventListener("submit", (event) => { event.preventDefault(); runSearch(); });
	elements.nextPage.addEventListener("click", () => {
	  if (!state.nextPageCookie) return;
	  state.pageHistory.push(state.currentPageCookie);
	  runSearch(state.currentQuery || queryFromForm(), state.nextPageCookie);
	});
	elements.previousPage.addEventListener("click", () => {
	  if (!state.pageHistory.length) return;
	  const cookie = state.pageHistory.pop();
	  runSearch(state.currentQuery || queryFromForm(), cookie);
	});
    $$("[data-filter]").forEach((button) => button.addEventListener("click", () => { $("#search-filter").value = button.dataset.filter; runSearch(); }));
    elements.listButton.addEventListener("click", showListView);
    elements.detailButton.addEventListener("click", () => { if (state.selectedEntry) showDetailView(); });
    $("#refresh-content").addEventListener("click", () => runSearch(state.currentQuery || queryFromForm()));
    $("#refresh-tree").addEventListener("click", () => { buildTreeRoot(); state.namingContexts.forEach((dn) => loadTreeChildren(dn)); });
    $("#refresh-schema").addEventListener("click", loadSchema);
    $("#refresh-monitor").addEventListener("click", loadMonitor);
    elements.schemaSearch.addEventListener("input", renderSchema);
	[["schema-classes", "classes"], ["schema-attributes", "attributes"], ["schema-rules", "rules"]].forEach(([id, view]) => {
	  $("#" + id).addEventListener("click", () => {
		state.schemaView = view;
		[["schema-classes", "classes"], ["schema-attributes", "attributes"], ["schema-rules", "rules"]].forEach(([buttonID, buttonView]) => {
		  const button = $("#" + buttonID);
		  button.classList.toggle("active", buttonView === view);
		  button.setAttribute("aria-pressed", String(buttonView === view));
		});
		renderSchema();
	  });
	});
    $("#copy-base").addEventListener("click", () => copyText(state.baseDN, "Base DN copied"));
    $("#copy-entry-dn").addEventListener("click", () => copyText(state.selectedDN, "Entry DN copied"));
    $("#mobile-menu").addEventListener("click", () => setMobileView("navigation"));
    $$("[data-mobile-view]").forEach((button) => button.addEventListener("click", () => setMobileView(button.dataset.mobileView)));

    elements.accountButton.addEventListener("click", (event) => {
      event.stopPropagation();
      elements.accountMenu.hidden = !elements.accountMenu.hidden;
      elements.accountButton.setAttribute("aria-expanded", String(!elements.accountMenu.hidden));
    });
    document.addEventListener("click", (event) => {
      if (!elements.accountMenu.contains(event.target) && event.target !== elements.accountButton) {
        elements.accountMenu.hidden = true;
        elements.accountButton.setAttribute("aria-expanded", "false");
      }
    });
    $("#logout-button").addEventListener("click", async () => {
      try { await api("/api/logout", { method: "POST", body: {} }); } catch (_) { /* clear local session regardless */ }
      state.csrf = "";
      state.session = null;
      elements.accountMenu.hidden = true;
      showLogin();
    });

    elements.loginForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submit = $("#login-submit");
      submit.disabled = true;
      setFieldError(elements.loginError, "");
      try {
        const { data } = await api("/api/login", { method: "POST", body: { bind_dn: $("#login-dn").value.trim(), password: $("#login-password").value } });
        state.csrf = csrfFrom(data);
        setSession(unwrap(data, ["session"]));
        closeDialog(elements.loginDialog);
        $("#login-password").value = "";
        await loadWorkspace();
      } catch (error) { setFieldError(elements.loginError, error.message); }
      finally { submit.disabled = false; }
    });
    $("#toggle-password").addEventListener("click", () => {
      const field = $("#login-password");
      const show = field.type === "password";
      field.type = show ? "text" : "password";
      $("#toggle-password").setAttribute("aria-label", show ? "Hide password" : "Show password");
    });

    $("#new-entry-button").addEventListener("click", () => {
      elements.entryDialog.querySelector("form").reset();
	  $("#new-entry-template").value = "person";
	  renderEntryTemplate("person");
      openDialog(elements.entryDialog);
      requestAnimationFrame(() => $("#new-entry-dn").focus());
    });
	$("#new-entry-template").addEventListener("change", (event) => renderEntryTemplate(event.target.value));
	$("#add-entry-attribute").addEventListener("click", () => addCreateAttributeRow());
	$("#new-entry-dn").addEventListener("blur", syncCreateRDNAttribute);
    $("#entry-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const dn = $("#new-entry-dn").value.trim();
	  const attributes = collectAttributeRows($("#new-entry-attribute-list"));
	  attributes.objectClass = lines($("#new-entry-classes").value);
	  const validationError = validateCreateEntry(attributes);
	  if (validationError) { setFieldError($("#entry-form-error"), validationError); return; }
	  setFormSubmitting(event.currentTarget, true);
      try {
        await api("/api/entries", { method: "POST", body: { dn, attributes } });
        closeDialog(elements.entryDialog);
        toast("Entry created", dn);
        await refreshAfterMutation(dn);
        await openEntry(dn);
	  } catch (error) { setFieldError($("#entry-form-error"), error.message); }
	  finally { setFormSubmitting(event.currentTarget, false); }
    });

    elements.entryEditor.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!state.selectedDN) return;
	  setFormSubmitting(event.currentTarget, true);
      try {
		const changes = attributeChanges(state.selectedEntry);
        if (!changes.length) {
          state.editorDirty = false;
          setEditorStatus(false);
          toast("No changes", state.selectedDN);
          return;
        }
        await api("/api/entries", { method: "PATCH", body: { dn: state.selectedDN, changes } });
        state.editorDirty = false;
        setEditorStatus(false);
        toast("Entry updated", state.selectedDN);
        await openEntry(state.selectedDN);
	  } catch (error) { toast("Update failed", error.message, "error"); }
	  finally { setFormSubmitting(event.currentTarget, false); }
    });
    $("#add-attribute").addEventListener("click", () => { addAttributeRow(); markDirty(); });
    $("#discard-entry").addEventListener("click", async () => { if (state.selectedDN) await openEntry(state.selectedDN); });

    $("#delete-button").addEventListener("click", async () => {
      if (!state.selectedDN) return;
      const approved = await confirmAction("Delete directory entry?", `${state.selectedDN} will be removed.`, "Delete entry");
      if (!approved) return;
	  const deleteButton = $("#delete-button");
	  deleteButton.disabled = true;
      try {
        await api("/api/entries", { method: "DELETE", body: { dn: state.selectedDN } });
        const deleted = state.selectedDN;
        state.selectedDN = "";
        state.selectedEntry = null;
        updateEntryActions(false);
        elements.detailButton.disabled = true;
        showListView();
        toast("Entry deleted", deleted);
        await refreshAfterMutation();
	  } catch (error) { toast("Delete failed", error.message, "error"); }
	  finally { deleteButton.disabled = false; }
    });

    $("#rename-button").addEventListener("click", () => {
      if (!state.selectedDN) return;
      $("#rename-rdn").value = rdn(state.selectedDN);
      $("#rename-superior").value = parentDN(state.selectedDN);
      $("#rename-delete-old").checked = true;
      openDialog(elements.renameDialog);
    });
    $("#rename-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const oldDN = state.selectedDN;
      const newRDN = $("#rename-rdn").value.trim();
      const newSuperior = $("#rename-superior").value.trim();
	  setFormSubmitting(event.currentTarget, true);
      try {
        await api("/api/entries/rename", { method: "POST", body: { dn: oldDN, new_rdn: newRDN, new_superior: newSuperior, delete_old_rdn: $("#rename-delete-old").checked } });
        const newDN = newSuperior ? `${newRDN},${newSuperior}` : newRDN;
        state.selectedDN = newDN;
        closeDialog(elements.renameDialog);
        toast("Entry renamed", newDN);
        await refreshAfterMutation(newDN);
        await openEntry(newDN);
	  } catch (error) { setFieldError($("#rename-error"), error.message); }
	  finally { setFormSubmitting(event.currentTarget, false); }
    });

    $("#password-button").addEventListener("click", () => {
      if (!state.selectedDN) return;
      $("#password-target").textContent = state.selectedDN;
      $("#password-form").reset();
      openDialog(elements.passwordDialog);
    });
    $("#password-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const password = $("#new-password").value;
      if (password !== $("#confirm-password").value) { setFieldError($("#password-error"), "Passwords do not match"); return; }
	  setFormSubmitting(event.currentTarget, true);
      try {
        await api("/api/password-modify", { method: "POST", body: { user_identity: state.selectedDN, new_password: password } });
		$("#password-form").reset();
        closeDialog(elements.passwordDialog);
        toast("Password reset", state.selectedDN);
	  } catch (error) { setFieldError($("#password-error"), error.message); }
	  finally { setFormSubmitting(event.currentTarget, false); }
    });
    $("#mobile-rename-button").addEventListener("click", () => $("#rename-button").click());
    $("#mobile-password-button").addEventListener("click", () => $("#password-button").click());
    $("#mobile-delete-button").addEventListener("click", () => $("#delete-button").click());

    [$("#import-button"), $("#menu-import")].forEach((button) => button.addEventListener("click", () => { elements.accountMenu.hidden = true; openDialog(elements.importDialog); }));
    [$("#export-button"), $("#menu-export")].forEach((button) => button.addEventListener("click", () => { elements.accountMenu.hidden = true; exportLDIF(); }));
    $("#import-file").addEventListener("change", async (event) => {
      const file = event.target.files[0];
      if (!file) return;
      $("#import-file-name").textContent = file.name;
      try { $("#import-content").value = await file.text(); }
      catch (error) { setFieldError($("#import-error"), error.message); }
    });
    $("#import-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const content = $("#import-content").value.trim();
      if (!content) { setFieldError($("#import-error"), "LDIF content is required"); return; }
      const approved = await confirmAction("Import LDIF entries?", "The server will apply the submitted directory changes.", "Import entries");
      if (!approved) return;
	  setFormSubmitting(event.currentTarget, true);
      try {
        await api("/api/import", { method: "POST", body: content, rawBody: true, headers: { "Content-Type": "application/ldif; charset=utf-8" } });
        closeDialog(elements.importDialog);
        $("#import-form").reset();
        $("#import-file-name").textContent = "Choose LDIF file";
        toast("Import complete", "Directory entries were applied");
        await refreshAfterMutation();
	  } catch (error) { setFieldError($("#import-error"), error.message); openDialog(elements.importDialog); }
	  finally { setFormSubmitting(event.currentTarget, false); }
    });

    $("#confirm-form").addEventListener("submit", (event) => { event.preventDefault(); resolveConfirm(true); });
    $("#confirm-cancel").addEventListener("click", () => resolveConfirm(false));
    elements.confirmDialog.addEventListener("cancel", (event) => { event.preventDefault(); resolveConfirm(false); });
    elements.loginDialog.addEventListener("cancel", (event) => event.preventDefault());
    $$(".close-dialog").forEach((button) => button.addEventListener("click", () => closeDialog(button.closest("dialog"))));
    $$('dialog:not(#login-dialog):not(#confirm-dialog)').forEach((dialog) => dialog.addEventListener("click", (event) => {
      if (event.target === dialog) closeDialog(dialog);
    }));
    window.addEventListener("beforeunload", (event) => { if (state.editorDirty) { event.preventDefault(); event.returnValue = ""; } });
  }

  function lines(value) { return String(value || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean); }
  async function copyText(value, success) {
    try { await navigator.clipboard.writeText(value || ""); toast(success); }
    catch (_) { toast("Copy failed", "Clipboard permission was denied", "error"); }
  }

  initialize();
})();
