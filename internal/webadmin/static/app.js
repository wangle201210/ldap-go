(function () {
  "use strict";

  const LANGUAGE_STORAGE_KEY = "ldap-go.webadmin.language";
  const QUERY_STORAGE_KEY = "ldap-go.webadmin.savedQueries";
  const QUERY_HISTORY_STORAGE_KEY = "ldap-go.webadmin.queryHistory";
  const LIST_ATTRIBUTES = "objectClass, description, title, modifyTimestamp, createTimestamp";
  const CONFIGURATION_ATTRIBUTE_SUGGESTIONS = ["olcPasswordHash"];
  const messages = {
    en: {
      "app.title": "LDAP Operations",
      "app.operations": "OPERATIONS",
      "app.secureAdministration": "Secure administration",
      "language.label": "Language",
      "language.english": "English",
      "language.chinese": "Simplified Chinese",
      "nav.skip": "Skip to directory content",
      "nav.open": "Open directory navigation",
      "nav.directory": "Directory navigation",
      "nav.workspace": "Workspace view",
      "nav.directoryView": "Directory view",
      "nav.entriesView": "Entries view",
      "nav.contextView": "Context view",
      "nav.directoryTitle": "Directory",
      "nav.entriesTitle": "Entries",
      "nav.contextTitle": "Schema and monitor",
      "nav.tools": "Directory tools",
      "nav.tree": "Tree",
      "nav.search": "Search",
      "nav.namingContext": "Naming context",
      "nav.namingContexts": "{count} naming contexts",
      "nav.directoryTree": "Directory tree",
      "nav.refreshTree": "Refresh directory tree",
      "nav.refreshTreeTitle": "Refresh tree",
      "nav.commonSearches": "Common searches",
      "nav.people": "People",
      "nav.groups": "Groups",
      "nav.locked": "Locked",
      "nav.posixAccounts": "POSIX accounts",
      "nav.organizationalUnits": "Organizational units",
      "nav.hosts": "Hosts",
      "nav.copyBase": "Copy base DN",
      "nav.currentLocation": "Current directory location",
      "nav.rootDSE": "Root DSE",
      "nav.expand": "Expand {name}",
      "nav.root": "root",
      "nav.loading": "Loading",
      "nav.retryLoading": "Retry loading",
      "nav.loadMore": "Load more",
      "nav.collapse": "Collapse {name}",
      "nav.treeLoadFailed": "Tree load failed",
      "nav.loaded.one": "{count} entry loaded",
      "nav.loaded.other": "{count} entries loaded",
      "filter.builder": "Filter builder",
      "filter.match": "Match",
      "filter.all": "All conditions",
      "filter.any": "Any condition",
      "filter.add": "Add condition",
      "filter.apply": "Apply filter",
      "filter.attribute": "Attribute",
      "filter.operator": "Filter operator",
      "filter.value": "Value",
      "filter.remove": "Remove condition",
      "filter.equals": "Equals",
      "filter.contains": "Contains",
      "filter.starts": "Starts with",
      "filter.ends": "Ends with",
      "filter.present": "Is present",
      "filter.ge": "Greater than or equal",
      "filter.le": "Less than or equal",
      "filter.approx": "Approximately",
      "filter.not": "Does not equal",
      "filter.invalid": "Every condition requires an attribute and value",
      "query.save": "Save query",
      "query.saved": "Saved queries",
      "query.name": "Query name",
      "query.savedToast": "Query saved",
      "query.recent": "Recent queries",
      "query.clearHistory": "Clear history",
      "search.base": "Base DN",
      "search.filter": "LDAP filter",
      "search.run": "Run search",
      "search.scope": "Scope",
      "search.scope.sub": "Subtree",
      "search.scope.one": "One level",
      "search.scope.base": "Base",
      "search.limit": "Limit",
      "search.attributes": "Attributes",
      "search.loading": "Loading entries",
      "search.failed": "Search failed",
      "search.retry": "Retry",
      "search.none": "No entries found",
      "search.results.none": "No results",
      "search.results.one": "{count} entry",
      "search.results.other": "{count} entries",
      "search.pages": "Search result pages",
      "search.previous": "Previous result page",
      "search.previousTitle": "Previous page",
      "search.next": "Next result page",
      "search.nextTitle": "Next page",
      "search.tooManyAttributes": "Select no more than {limit} attributes",
      "actions.import": "Import",
      "actions.export": "Export",
      "actions.importLDIF": "Import LDIF",
      "actions.importCSV": "Import CSV",
      "actions.exportLDIF": "Export LDIF",
      "actions.exportCSV": "Export CSV",
      "actions.exportJSON": "Export JSON",
      "actions.signOut": "Sign out",
      "actions.newEntry": "New entry",
      "actions.refreshEntries": "Refresh entries",
      "actions.refresh": "Refresh",
      "actions.cloneSelected": "Clone selected entry",
      "actions.clone": "Clone",
      "actions.renameSelected": "Rename selected entry",
      "actions.renameMove": "Rename or move",
      "actions.resetSelected": "Reset password for selected entry",
      "actions.resetPassword": "Reset password",
      "actions.deleteSelected": "Delete selected entry",
      "actions.delete": "Delete",
      "actions.entries": "Entries",
      "actions.attributes": "Attributes",
      "actions.rename": "Rename",
      "actions.password": "Password",
      "actions.more": "More",
      "actions.attribute": "Attribute",
      "actions.browseAttributes": "Browse attributes",
      "actions.discard": "Discard",
      "actions.save": "Save changes",
      "actions.close": "Close",
      "actions.cancel": "Cancel",
      "actions.confirm": "Confirm",
      "actions.dismiss": "Dismiss notification",
      "actions.copyFailed": "Copy failed",
      "actions.clipboardDenied": "Clipboard permission was denied",
      "actions.baseCopied": "Base DN copied",
      "actions.entryCopied": "Entry DN copied",
      "content.directoryEntries": "Directory entries",
      "content.loadingContext": "Loading directory context",
      "content.view": "Content view",
      "content.directoryEntriesLabel": "Directory entries",
      "content.relativeName": "Relative name",
      "content.type": "Type",
      "content.description": "Description",
      "content.modified": "Modified",
      "content.open": "Open",
      "content.openEntry": "Open {name}",
      "entry.attributesLabel": "Entry attributes",
      "entry.directoryEntry": "Directory entry",
      "entry.noneSelected": "No entry selected",
      "entry.copyDN": "Copy distinguished name",
      "entry.active": "Active",
      "entry.actions": "Entry actions",
      "entry.attributeCount.one": "{count} attribute",
      "entry.attributeCount.other": "{count} attributes",
      "entry.unsaved": "Unsaved changes",
      "entry.saved": "No unsaved changes",
      "entry.loading": "Loading entry",
      "entry.unavailable": "Entry unavailable",
      "entry.loadFailed": "Entry load failed",
      "entry.locked": "Locked",
      "entry.binaryValues": "Binary values · Base64",
      "entry.mixedValuesReadOnly": "Mixed text/binary values · read only",
      "entry.newAttribute": "New attribute",
      "entry.directoryAttribute": "Directory attribute",
      "entry.discardTitle": "Discard unsaved changes?",
      "entry.discardMessage": "Changes in the current entry will be lost.",
      "entry.created": "Entry created",
      "entry.noChanges": "No changes",
      "entry.updated": "Entry updated",
      "entry.updateFailed": "Update failed",
      "entry.deleteTitle": "Delete directory entry?",
      "entry.deleteMessage": "{dn} will be removed.",
      "entry.deleteConfirm": "Delete entry",
      "entry.deleted": "Entry deleted",
      "entry.deleteFailed": "Delete failed",
      "entry.renamed": "Entry renamed",
      "entry.cloneTitle": "Clone entry",
      "entry.cloneHint": "Choose a new distinguished name for the cloned entry.",
      "entry.nameFallback": "entry",
      "editor.attributeName": "Attribute name",
      "editor.values": "Values",
      "editor.removeAttribute": "Remove attribute",
      "context.directory": "Directory context",
      "context.tools": "Context tools",
      "schema.schema": "Schema",
      "schema.monitor": "Monitor",
      "schema.context": "Context",
      "schema.objectClasses": "Object classes",
      "schema.refresh": "Refresh schema",
      "schema.type": "Schema definition type",
      "schema.classes": "Classes",
      "schema.attributes": "Attributes",
      "schema.rules": "Rules",
      "schema.filter": "Filter schema",
      "schema.unavailable": "Schema unavailable",
      "schema.noMatches": "No schema matches",
      "schema.noDefinitions": "No definitions in this view",
      "schema.attributeTypes": "Attribute types",
      "schema.matchingRules": "Matching and syntax rules",
      "schema.applied": "Applied to entry",
      "schema.unnamedDefinition": "Unnamed definition",
      "schema.unnamedClass": "Unnamed class",
      "monitor.runtime": "Runtime",
      "monitor.server": "Server monitor",
      "monitor.refresh": "Refresh monitor",
      "monitor.checking": "Checking server",
      "monitor.waiting": "Waiting for monitor data",
      "monitor.unavailable": "Monitor unavailable",
      "monitor.issue": "Monitor reports an issue",
      "monitor.responding": "Monitor responding",
      "monitor.available": "LDAP Monitor data is available",
      "bulk.selectPage": "Select all entries on this page",
      "bulk.selected.one": "{count} selected",
      "bulk.selected.other": "{count} selected",
      "bulk.modify": "Modify",
      "bulk.delete": "Delete",
      "bulk.clear": "Clear",
      "bulk.title": "Modify selected entries",
      "bulk.description": "Apply one LDAP modification to the selected entries.",
      "bulk.operation": "Operation",
      "bulk.replace": "Replace",
      "bulk.add": "Add values",
      "bulk.deleteValues": "Delete values or attribute",
      "bulk.increment": "Increment",
      "bulk.attribute": "Attribute",
      "bulk.values": "Values",
      "bulk.continue": "Continue after an entry fails",
      "bulk.apply": "Apply to selected",
      "bulk.deleteTitle": "Delete selected entries?",
      "bulk.deleteMessage": "{count} directory entries will be removed.",
      "bulk.complete": "Bulk operation complete",
      "bulk.summary": "{applied} applied, {failed} failed, {unknown} unknown",
      "bulk.aborted": "Batch stopped: {reason}",
      "bulk.entryFailure": "{dn}: {message}",
      "bulk.notAttempted": "{count} entries were not attempted",
      "group.title": "Group members",
      "group.members.one": "{count} member",
      "group.members.other": "{count} members",
      "group.includeNested": "Include nested members",
      "group.memberInput": "Member DN or uid",
      "group.add": "Add member",
      "group.remove": "Remove selected",
      "group.direct": "Direct",
      "group.nested": "Nested",
      "group.loadFailed": "Group members could not be loaded",
      "group.updated": "Group membership updated",
      "binary.download": "Download",
      "binary.replace": "Replace file",
      "binary.remove": "Delete attribute",
      "binary.value": "Value {index}",
      "binary.updated": "Binary attribute updated",
      "binary.deleted": "Binary attribute deleted",
      "binary.confirmDelete": "Delete binary attribute?",
      "binary.confirmDeleteMessage": "All values of {attribute} will be removed.",
      "binary.readFailed": "Binary attribute could not be read",
      "file.tooLarge": "File exceeds the {limit} byte limit",
      "file.reading": "Wait for the selected file to finish loading",
      "api.authenticationRequired": "Authentication is required",
      "api.sessionExpired": "Your session has expired",
      "api.sessionBusy": "Another directory operation is still running",
      "api.accessDenied": "The directory denied this operation",
      "api.noSuchObject": "The directory entry does not exist",
      "api.alreadyExists": "A directory entry with that name already exists",
      "api.constraintViolation": "The submitted values violate a directory constraint",
      "api.invalidDN": "The distinguished name is invalid",
      "api.invalidRequest": "The submitted request is invalid",
      "api.bodyTooLarge": "The submitted data exceeds the server limit",
      "api.capacityReached": "The administration service is at capacity; retry shortly",
      "api.referralUnfollowed": "The directory returned a referral that was not followed",
      "api.timeout": "The directory operation timed out",
      "api.canceled": "The directory operation was canceled",
      "api.unavailable": "The directory service is unavailable",
      "session.connecting": "Connecting",
      "session.directory": "Directory",
      "session.administrator": "Administrator",
      "session.signedOut": "Not signed in",
      "session.authRequired": "Authentication required",
      "session.connected": "Connected",
      "session.serverUnavailable": "Server unavailable",
      "session.directoryUnavailable": "Directory unavailable",
      "session.serverUnreachable": "The server could not be reached",
      "session.requestFailed": "{method} {path} failed",
      "session.applied": "{message} ({count} changes already applied)",
      "login.signIn": "Sign in",
      "login.subtitle": "Use an administrator directory account.",
      "login.bindDN": "Bind DN",
      "login.password": "Password",
      "login.showPassword": "Show password",
      "login.hidePassword": "Hide password",
      "create.title": "Create entry",
      "create.description": "Add an LDAP directory entry.",
      "create.entryType": "Entry type",
      "create.person": "Person",
      "create.posixAccount": "POSIX account",
      "create.group": "Group",
      "create.uniqueGroup": "Unique-name group",
      "create.posixGroup": "POSIX group",
      "create.ou": "Organizational unit",
      "create.custom": "Custom",
      "create.dn": "Distinguished name",
      "create.objectClasses": "Object classes",
      "create.submit": "Create entry",
      "create.required": "{name} is required for this entry type",
      "create.structuralRequired": "Custom entries require a structural object class",
      "rename.title": "Rename or move",
      "rename.description": "Change the relative name or parent of this entry.",
      "rename.newRDN": "New RDN",
      "rename.newParent": "New parent DN",
      "rename.removeOld": "Remove old RDN value",
      "rename.apply": "Apply change",
      "password.credentials": "Credentials",
      "password.new": "New password",
      "password.confirm": "Confirm password",
      "password.mismatch": "Passwords do not match",
      "password.reset": "Password reset",
      "import.title": "Import entries",
      "import.description": "Import LDAP Data Interchange Format changes.",
      "import.choose": "Choose LDIF file",
      "import.utf8": "UTF-8 text",
      "import.orPaste": "or paste LDIF",
      "import.content": "LDIF content",
      "import.required": "LDIF content is required",
      "import.confirmTitle": "Import LDIF entries?",
      "import.confirmMessage": "The server will apply the submitted directory changes.",
      "import.confirm": "Import entries",
      "import.complete": "Import complete",
      "import.partial": "LDIF import partially applied",
      "import.applied": "Directory entries were applied",
      "import.partialNoRetry": "Some changes were already applied or have an unknown result. Review the records and edit or replace the LDIF before submitting again.",
      "import.changedRetryTitle": "Submit a changed LDIF batch?",
      "import.changedRetryMessage": "The previous batch was partially applied or its result is unknown. Submit only after removing every record that may already have been applied.",
      "import.changedRetryConfirm": "Submit changed batch",
      "import.recordFailure": "Record {record} ({dn}): {message}",
      "import.notAttempted": "{count} records were not attempted",
      "csv.title": "Import CSV entries",
      "csv.description": "Map CSV columns to LDAP attributes and create entries.",
      "csv.choose": "Choose CSV file",
      "csv.utf8": "UTF-8 CSV",
      "csv.base": "Base DN",
      "csv.rdn": "RDN attribute",
      "csv.classes": "Object classes",
      "csv.mapping": "Column mapping",
      "csv.mappingHint": "One CSV column=LDAP attribute per line",
      "csv.content": "CSV content",
      "csv.continue": "Continue after a row fails",
      "csv.submit": "Import entries",
      "csv.invalidMapping": "Use one CSV column=LDAP attribute mapping per line",
      "csv.complete": "CSV import complete",
      "csv.partial": "CSV import partially applied",
      "csv.partialNoRetry": "Some write results may already exist. The original CSV is retained for review, but direct retry is disabled; start a new import containing only failed or unattempted rows.",
      "csv.changedRetryTitle": "Submit a changed CSV batch?",
      "csv.changedRetryMessage": "The previous batch was partially applied or its result is unknown. Submit only after removing every row that may already have been applied.",
      "csv.changedRetryConfirm": "Submit changed batch",
      "csv.rowFailure": "Row {row}: {message}",
      "csv.notAttempted": "{count} rows were not attempted",
      "confirm.title": "Confirm action",
      "export.complete": "Export complete",
      "export.failed": "Export failed",
      "validation.required": "This field is required",
      "validation.tooShort": "Enter at least {min} characters",
      "validation.minimum": "Enter a value of at least {min}",
      "validation.maximum": "Enter a value no greater than {max}",
      "validation.invalid": "Enter a valid value"
    },
    "zh-CN": {
      "app.title": "LDAP 运维管理",
      "app.operations": "运维管理",
      "app.secureAdministration": "安全管理",
      "language.label": "语言",
      "language.english": "英文",
      "language.chinese": "简体中文",
      "nav.skip": "跳转到目录内容",
      "nav.open": "打开目录导航",
      "nav.directory": "目录导航",
      "nav.workspace": "工作区视图",
      "nav.directoryView": "目录视图",
      "nav.entriesView": "条目视图",
      "nav.contextView": "上下文视图",
      "nav.directoryTitle": "目录",
      "nav.entriesTitle": "条目",
      "nav.contextTitle": "模式与监控",
      "nav.tools": "目录工具",
      "nav.tree": "目录树",
      "nav.search": "查询",
      "nav.namingContext": "命名上下文",
      "nav.namingContexts": "{count} 个命名上下文",
      "nav.directoryTree": "目录树",
      "nav.refreshTree": "刷新目录树",
      "nav.refreshTreeTitle": "刷新目录树",
      "nav.commonSearches": "常用查询",
      "nav.people": "用户",
      "nav.groups": "用户组",
      "nav.locked": "已锁定",
      "nav.posixAccounts": "POSIX 账户",
      "nav.organizationalUnits": "组织单元",
      "nav.hosts": "主机",
      "nav.copyBase": "复制基础 DN",
      "nav.currentLocation": "当前目录位置",
      "nav.rootDSE": "Root DSE",
      "nav.expand": "展开 {name}",
      "nav.root": "根节点",
      "nav.loading": "正在加载",
      "nav.retryLoading": "重新加载",
      "nav.loadMore": "继续加载",
      "nav.collapse": "折叠 {name}",
      "nav.treeLoadFailed": "目录树加载失败",
      "nav.loaded.one": "已加载 {count} 个条目",
      "nav.loaded.other": "已加载 {count} 个条目",
      "filter.builder": "过滤器生成器",
      "filter.match": "匹配方式",
      "filter.all": "满足全部条件",
      "filter.any": "满足任一条件",
      "filter.add": "添加条件",
      "filter.apply": "应用过滤器",
      "filter.attribute": "属性",
      "filter.operator": "过滤运算符",
      "filter.value": "值",
      "filter.remove": "移除条件",
      "filter.equals": "等于",
      "filter.contains": "包含",
      "filter.starts": "开头为",
      "filter.ends": "结尾为",
      "filter.present": "属性存在",
      "filter.ge": "大于或等于",
      "filter.le": "小于或等于",
      "filter.approx": "近似匹配",
      "filter.not": "不等于",
      "filter.invalid": "每个条件都必须填写属性和值",
      "query.save": "保存查询",
      "query.saved": "已保存的查询",
      "query.name": "查询名称",
      "query.savedToast": "查询已保存",
      "query.recent": "最近查询",
      "query.clearHistory": "清除历史",
      "search.base": "基础 DN",
      "search.filter": "LDAP 过滤器",
      "search.run": "执行查询",
      "search.scope": "范围",
      "search.scope.sub": "子树",
      "search.scope.one": "单层",
      "search.scope.base": "基础对象",
      "search.limit": "数量限制",
      "search.attributes": "属性",
      "search.loading": "正在加载条目",
      "search.failed": "查询失败",
      "search.retry": "重试",
      "search.none": "未找到条目",
      "search.results.none": "无结果",
      "search.results.one": "{count} 个条目",
      "search.results.other": "{count} 个条目",
      "search.pages": "查询结果分页",
      "search.previous": "上一页查询结果",
      "search.previousTitle": "上一页",
      "search.next": "下一页查询结果",
      "search.nextTitle": "下一页",
      "search.tooManyAttributes": "最多只能选择 {limit} 个属性",
      "actions.import": "导入",
      "actions.export": "导出",
      "actions.importLDIF": "导入 LDIF",
      "actions.importCSV": "导入 CSV",
      "actions.exportLDIF": "导出 LDIF",
      "actions.exportCSV": "导出 CSV",
      "actions.exportJSON": "导出 JSON",
      "actions.signOut": "退出登录",
      "actions.newEntry": "新建条目",
      "actions.refreshEntries": "刷新条目",
      "actions.refresh": "刷新",
      "actions.cloneSelected": "克隆所选条目",
      "actions.clone": "克隆",
      "actions.renameSelected": "重命名所选条目",
      "actions.renameMove": "重命名或移动",
      "actions.resetSelected": "重置所选条目的密码",
      "actions.resetPassword": "重置密码",
      "actions.deleteSelected": "删除所选条目",
      "actions.delete": "删除",
      "actions.entries": "条目",
      "actions.attributes": "属性",
      "actions.rename": "重命名",
      "actions.password": "密码",
      "actions.more": "更多",
      "actions.attribute": "添加属性",
      "actions.browseAttributes": "浏览可用属性",
      "actions.discard": "放弃",
      "actions.save": "保存更改",
      "actions.close": "关闭",
      "actions.cancel": "取消",
      "actions.confirm": "确认",
      "actions.dismiss": "关闭通知",
      "actions.copyFailed": "复制失败",
      "actions.clipboardDenied": "浏览器拒绝了剪贴板权限",
      "actions.baseCopied": "已复制基础 DN",
      "actions.entryCopied": "已复制条目 DN",
      "content.directoryEntries": "目录条目",
      "content.loadingContext": "正在加载目录上下文",
      "content.view": "内容视图",
      "content.directoryEntriesLabel": "目录条目",
      "content.relativeName": "相对名称",
      "content.type": "类型",
      "content.description": "描述",
      "content.modified": "修改时间",
      "content.open": "打开",
      "content.openEntry": "打开 {name}",
      "entry.attributesLabel": "条目属性",
      "entry.directoryEntry": "目录条目",
      "entry.noneSelected": "未选择条目",
      "entry.copyDN": "复制可分辨名称",
      "entry.active": "正常",
      "entry.actions": "条目操作",
      "entry.attributeCount.one": "{count} 个属性",
      "entry.attributeCount.other": "{count} 个属性",
      "entry.unsaved": "有未保存的更改",
      "entry.saved": "没有未保存的更改",
      "entry.loading": "正在加载条目",
      "entry.unavailable": "条目不可用",
      "entry.loadFailed": "条目加载失败",
      "entry.locked": "已锁定",
      "entry.binaryValues": "二进制值 · Base64",
      "entry.mixedValuesReadOnly": "文本/二进制混合值 · 只读",
      "entry.newAttribute": "新属性",
      "entry.directoryAttribute": "目录属性",
      "entry.discardTitle": "放弃未保存的更改？",
      "entry.discardMessage": "当前条目中的更改将会丢失。",
      "entry.created": "条目已创建",
      "entry.noChanges": "没有更改",
      "entry.updated": "条目已更新",
      "entry.updateFailed": "更新失败",
      "entry.deleteTitle": "删除目录条目？",
      "entry.deleteMessage": "将删除 {dn}。",
      "entry.deleteConfirm": "删除条目",
      "entry.deleted": "条目已删除",
      "entry.deleteFailed": "删除失败",
      "entry.renamed": "条目已重命名",
      "entry.cloneTitle": "克隆条目",
      "entry.cloneHint": "请为克隆条目指定新的可分辨名称。",
      "entry.nameFallback": "条目",
      "editor.attributeName": "属性名称",
      "editor.values": "值",
      "editor.removeAttribute": "移除属性",
      "context.directory": "目录上下文",
      "context.tools": "上下文工具",
      "schema.schema": "模式",
      "schema.monitor": "监控",
      "schema.context": "上下文",
      "schema.objectClasses": "对象类",
      "schema.refresh": "刷新模式",
      "schema.type": "模式定义类型",
      "schema.classes": "对象类",
      "schema.attributes": "属性",
      "schema.rules": "规则",
      "schema.filter": "筛选模式",
      "schema.unavailable": "模式不可用",
      "schema.noMatches": "没有匹配的模式",
      "schema.noDefinitions": "此视图中没有定义",
      "schema.attributeTypes": "属性类型",
      "schema.matchingRules": "匹配与语法规则",
      "schema.applied": "应用于当前条目",
      "schema.unnamedDefinition": "未命名定义",
      "schema.unnamedClass": "未命名对象类",
      "monitor.runtime": "运行状态",
      "monitor.server": "服务器监控",
      "monitor.refresh": "刷新监控",
      "monitor.checking": "正在检查服务器",
      "monitor.waiting": "正在等待监控数据",
      "monitor.unavailable": "监控不可用",
      "monitor.issue": "监控报告异常",
      "monitor.responding": "监控响应正常",
      "monitor.available": "LDAP Monitor 数据可用",
      "bulk.selectPage": "选择本页全部条目",
      "bulk.selected.one": "已选择 {count} 项",
      "bulk.selected.other": "已选择 {count} 项",
      "bulk.modify": "批量修改",
      "bulk.delete": "批量删除",
      "bulk.clear": "清除选择",
      "bulk.title": "修改所选条目",
      "bulk.description": "对所选条目应用一次 LDAP 修改。",
      "bulk.operation": "操作",
      "bulk.replace": "替换",
      "bulk.add": "添加值",
      "bulk.deleteValues": "删除值或属性",
      "bulk.increment": "递增",
      "bulk.attribute": "属性",
      "bulk.values": "值",
      "bulk.continue": "单个条目失败后继续",
      "bulk.apply": "应用到所选条目",
      "bulk.deleteTitle": "删除所选条目？",
      "bulk.deleteMessage": "将删除 {count} 个目录条目。",
      "bulk.complete": "批量操作完成",
      "bulk.summary": "成功 {applied} 项，失败 {failed} 项，结果未知 {unknown} 项",
      "bulk.aborted": "批处理已停止：{reason}",
      "bulk.entryFailure": "{dn}：{message}",
      "bulk.notAttempted": "{count} 个条目未执行",
      "group.title": "组成员",
      "group.members.one": "{count} 个成员",
      "group.members.other": "{count} 个成员",
      "group.includeNested": "包含嵌套成员",
      "group.memberInput": "成员 DN 或 uid",
      "group.add": "添加成员",
      "group.remove": "移除所选成员",
      "group.direct": "直接成员",
      "group.nested": "嵌套成员",
      "group.loadFailed": "无法加载组成员",
      "group.updated": "组成员关系已更新",
      "binary.download": "下载",
      "binary.replace": "替换文件",
      "binary.remove": "删除属性",
      "binary.value": "值 {index}",
      "binary.updated": "二进制属性已更新",
      "binary.deleted": "二进制属性已删除",
      "binary.confirmDelete": "删除二进制属性？",
      "binary.confirmDeleteMessage": "将删除 {attribute} 的全部值。",
      "binary.readFailed": "无法读取二进制属性",
      "file.tooLarge": "文件超过 {limit} 字节限制",
      "file.reading": "请等待所选文件读取完成",
      "api.authenticationRequired": "需要登录后才能继续",
      "api.sessionExpired": "登录会话已过期",
      "api.sessionBusy": "另一个目录操作仍在执行，请稍候",
      "api.accessDenied": "目录服务器拒绝了此操作",
      "api.noSuchObject": "目录条目不存在",
      "api.alreadyExists": "同名目录条目已存在",
      "api.constraintViolation": "提交的值不符合目录约束",
      "api.invalidDN": "可分辨名称格式无效",
      "api.invalidRequest": "提交的请求无效",
      "api.bodyTooLarge": "提交的数据超过服务器限制",
      "api.capacityReached": "管理服务当前繁忙，请稍后重试",
      "api.referralUnfollowed": "目录服务器返回了未跟随的引用",
      "api.timeout": "目录操作超时",
      "api.canceled": "目录操作已取消",
      "api.unavailable": "目录服务当前不可用",
      "session.connecting": "正在连接",
      "session.directory": "目录",
      "session.administrator": "管理员",
      "session.signedOut": "未登录",
      "session.authRequired": "需要登录",
      "session.connected": "已连接",
      "session.serverUnavailable": "服务器不可用",
      "session.directoryUnavailable": "目录不可用",
      "session.serverUnreachable": "无法连接服务器",
      "session.requestFailed": "{method} {path} 请求失败",
      "session.applied": "{message}（已有 {count} 项更改成功应用）",
      "login.signIn": "登录",
      "login.subtitle": "请使用目录管理员账号。",
      "login.bindDN": "绑定 DN",
      "login.password": "密码",
      "login.showPassword": "显示密码",
      "login.hidePassword": "隐藏密码",
      "create.title": "创建条目",
      "create.description": "添加一个 LDAP 目录条目。",
      "create.entryType": "条目类型",
      "create.person": "用户",
      "create.posixAccount": "POSIX 账户",
      "create.group": "用户组",
      "create.uniqueGroup": "唯一名称组",
      "create.posixGroup": "POSIX 用户组",
      "create.ou": "组织单元",
      "create.custom": "自定义",
      "create.dn": "可分辨名称",
      "create.objectClasses": "对象类",
      "create.submit": "创建条目",
      "create.required": "此条目类型必须填写 {name}",
      "create.structuralRequired": "自定义条目必须包含一个结构型对象类",
      "rename.title": "重命名或移动",
      "rename.description": "修改此条目的相对名称或父级。",
      "rename.newRDN": "新 RDN",
      "rename.newParent": "新父级 DN",
      "rename.removeOld": "移除旧 RDN 值",
      "rename.apply": "应用更改",
      "password.credentials": "凭据",
      "password.new": "新密码",
      "password.confirm": "确认密码",
      "password.mismatch": "两次输入的密码不一致",
      "password.reset": "密码已重置",
      "import.title": "导入条目",
      "import.description": "导入 LDAP 数据交换格式中的目录变更。",
      "import.choose": "选择 LDIF 文件",
      "import.utf8": "UTF-8 文本",
      "import.orPaste": "或粘贴 LDIF",
      "import.content": "LDIF 内容",
      "import.required": "必须提供 LDIF 内容",
      "import.confirmTitle": "导入 LDIF 条目？",
      "import.confirmMessage": "服务器将应用所提交的目录更改。",
      "import.confirm": "导入条目",
      "import.complete": "导入完成",
      "import.partial": "LDIF 导入已部分执行",
      "import.applied": "目录条目已应用",
      "import.partialNoRetry": "部分变更已成功或结果未知。请核对记录并编辑或更换 LDIF 后再提交，不能直接重试原内容。",
      "import.changedRetryTitle": "提交修改后的 LDIF 批次？",
      "import.changedRetryMessage": "上一批次已部分成功或结果未知。请先删除所有可能已经执行的记录，再提交修改后的批次。",
      "import.changedRetryConfirm": "提交修改后的批次",
      "import.recordFailure": "第 {record} 条（{dn}）：{message}",
      "import.notAttempted": "{count} 条记录未执行",
      "csv.title": "导入 CSV 条目",
      "csv.description": "将 CSV 列映射为 LDAP 属性并创建条目。",
      "csv.choose": "选择 CSV 文件",
      "csv.utf8": "UTF-8 CSV",
      "csv.base": "基础 DN",
      "csv.rdn": "RDN 属性",
      "csv.classes": "对象类",
      "csv.mapping": "列映射",
      "csv.mappingHint": "每行填写 CSV 列名=LDAP 属性",
      "csv.content": "CSV 内容",
      "csv.continue": "单行失败后继续",
      "csv.submit": "导入条目",
      "csv.invalidMapping": "每行必须使用 CSV 列名=LDAP 属性格式",
      "csv.complete": "CSV 导入完成",
      "csv.partial": "CSV 导入已部分执行",
      "csv.partialNoRetry": "部分写入结果可能已存在。原 CSV 会保留供核对，但已禁止直接重试；请重新开始并仅导入失败或未执行的行。",
      "csv.changedRetryTitle": "提交修改后的 CSV 批次？",
      "csv.changedRetryMessage": "上一批次已部分成功或结果未知。请先删除所有可能已经执行的行，再提交修改后的批次。",
      "csv.changedRetryConfirm": "提交修改后的批次",
      "csv.rowFailure": "第 {row} 行：{message}",
      "csv.notAttempted": "{count} 行未执行",
      "confirm.title": "确认操作",
      "export.complete": "导出完成",
      "export.failed": "导出失败",
      "validation.required": "此字段为必填项",
      "validation.tooShort": "请至少输入 {min} 个字符",
      "validation.minimum": "请输入不小于 {min} 的值",
      "validation.maximum": "请输入不大于 {max} 的值",
      "validation.invalid": "请输入有效值"
    }
  };

  const liveTranslations = new Map();
  const submittingControls = new WeakMap();
  let sessionAPIQueue = Promise.resolve();
  const SESSION_SERIAL_API_PATHS = new Set([
	"/api/logout", "/api/session", "/api/capabilities", "/api/root-dse", "/api/root", "/api/search", "/api/entries", "/api/entry",
	"/api/entries/rename", "/api/rename", "/api/password-modify", "/api/password",
	"/api/schema", "/api/monitor", "/api/export", "/api/data-export", "/api/import",
	"/api/bulk", "/api/groups", "/api/binary", "/api/csv-import"
  ]);
  const translationObserver = new MutationObserver(() => {
    for (const element of liveTranslations.keys()) {
      if (!element.isConnected) liveTranslations.delete(element);
    }
  });
  translationObserver.observe(document.documentElement, { childList: true, subtree: true });

  function hasLanguage(language) {
    return Object.prototype.hasOwnProperty.call(messages, language);
  }

  function preferredLanguage() {
    try {
      const saved = window.localStorage.getItem(LANGUAGE_STORAGE_KEY);
      if (hasLanguage(saved)) return saved;
    } catch (_) { /* storage can be unavailable in hardened browsers */ }
    return String(navigator.language || "en").toLowerCase().startsWith("zh") ? "zh-CN" : "en";
  }

  function t(key, params = {}) {
    const language = state && hasLanguage(state.language) ? state.language : "en";
    const template = messages[language][key] || messages.en[key] || key;
    return template.replace(/\{([A-Za-z0-9_]+)\}/g, (_, name) => String(params[name] === undefined ? `{${name}}` : params[name]));
  }

  function localize(element, key, params = {}, property = "textContent") {
    if (!element) return;
    const bindings = liveTranslations.get(element) || new Map();
    bindings.set(property, { key, params, property });
    liveTranslations.set(element, bindings);
    const values = typeof params === "function" ? params() : params;
    if (property === "direct") setDirectText(element, t(key, values));
    else if (property.startsWith("attr:")) element.setAttribute(property.slice(5), t(key, values));
    else element[property] = t(key, values);
  }

  function renderDynamic(element, render, property = "textContent") {
    if (!element) return;
    const bindings = liveTranslations.get(element) || new Map();
    bindings.set(property, { render, property });
    liveTranslations.set(element, bindings);
    element[property] = render();
  }

  function clearLocalization(element) {
    if (element) liveTranslations.delete(element);
  }

  function translated(key, params = {}) { return { key, params }; }

  function setDisplayText(element, value) {
    if (value && typeof value === "object" && value.key) localize(element, value.key, value.params || {});
    else {
      clearLocalization(element);
      element.textContent = value === undefined || value === null ? "" : String(value);
    }
  }

  function setDirectText(element, value) {
    const textNode = Array.from(element.childNodes).find((node) => node.nodeType === Node.TEXT_NODE && node.nodeValue.trim());
    if (textNode) textNode.nodeValue = value;
    else element.append(document.createTextNode(value));
  }

  const state = {
    language: preferredLanguage(),
    csrf: "",
    session: null,
    rootDN: "",
    namingContexts: [],
		baseDN: "",
		createBaseDN: "",
    entries: [],
    selectedDN: "",
    selectedEntry: null,
	    schema: { objectClasses: [], attributeTypes: [], rules: [] },
		schemaView: "classes",
    monitor: null,
    currentQuery: null,
    activeRequests: 0,
    editorDirty: false,
    treeNodes: new Map(),
		confirmResolve: null,
		searchSequence: 0,
		entrySequence: 0,
		treeSequence: 0,
		pageHistory: [],
		currentPageCookie: "",
		nextPageCookie: "",
		selectedDNs: new Set(),
		entryDialogMode: "create",
		groupAttribute: "member",
		groupMembers: [],
		groupUpdating: false,
		csvRetryFingerprints: new Set(),
		csvFileLoading: false,
		ldifRetryFingerprints: new Set(),
		ldifFileLoading: false,
		ldifFileSequence: 0,
		csvFileSequence: 0,
		capabilities: null,
		pageLoading: false,
		sessionGeneration: 0
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  const elements = {
    shell: $("#app-shell"),
	workspace: $("#workspace"),
	mainContent: $("#main-content"),
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
    bulkToolbar: $("#bulk-toolbar"),
    bulkSelectionCount: $("#bulk-selection-count"),
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
    csvImportDialog: $("#csv-import-dialog"),
    bulkModifyDialog: $("#bulk-modify-dialog"),
    confirmDialog: $("#confirm-dialog"),
	groupMembers: $("#group-members"),
	groupMemberList: $("#group-member-list"),
	groupMemberCount: $("#group-member-count"),
    toastRegion: $("#toast-region")
  };

  function sessionDN(session = state.session) {
	if (!session || typeof session !== "object") return "";
	const user = session.user && typeof session.user === "object" ? session.user : {};
	return String(session.dn || session.bind_dn || session.bindDN || session.bindDn || user.dn || user.name || "");
  }

  function storageScope() {
	const dn = sessionDN();
	if (!dn) return "";
	const bytes = new TextEncoder().encode(`${window.location.origin}\0${dn.toLowerCase()}`);
	let raw = "";
	bytes.forEach((value) => { raw += String.fromCharCode(value); });
	return window.btoa(raw).replace(/=+$/, "");
  }

  function scopedStorageKey(base) {
	const scope = storageScope();
	return scope ? `${base}.${scope}` : "";
  }

  function resetDirectoryState() {
	state.sessionGeneration++;
	sessionAPIQueue = Promise.resolve();
	state.searchSequence++;
	state.entrySequence++;
	state.treeSequence++;
	state.csrf = "";
	state.session = null;
	state.rootDN = "";
	state.namingContexts = [];
	state.baseDN = "";
	state.createBaseDN = "";
	state.entries = [];
	state.selectedDN = "";
	state.selectedEntry = null;
	state.schema = { objectClasses: [], attributeTypes: [], rules: [] };
	state.monitor = null;
	state.currentQuery = null;
	state.editorDirty = false;
	state.treeNodes.clear();
	state.pageHistory = [];
	state.currentPageCookie = "";
	state.nextPageCookie = "";
	state.selectedDNs.clear();
	state.groupMembers = [];
	state.groupUpdating = false;
	state.groupAttribute = "member";
	state.entryDialogMode = "create";
	state.csvRetryFingerprints.clear();
	state.csvFileLoading = false;
	state.ldifRetryFingerprints.clear();
	state.ldifFileLoading = false;
	state.ldifFileSequence++;
	state.csvFileSequence++;
	state.capabilities = null;
	state.pageLoading = false;
	if (state.confirmResolve) {
	  const resolve = state.confirmResolve;
	  state.confirmResolve = null;
	  resolve(false);
	}
	elements.tree.replaceChildren();
	elements.tableBody.replaceChildren();
	elements.attributeList.replaceChildren();
	elements.schemaList.replaceChildren();
	elements.metricGrid.replaceChildren();
	elements.monitorList.replaceChildren();
	elements.breadcrumb.replaceChildren();
	elements.groupMemberList.replaceChildren();
	elements.toastRegion.replaceChildren();
	elements.searchForm.reset();
	$("#schema-search").value = "";
	$("#filter-condition-list").replaceChildren();
	addFilterCondition("objectClass", "present", "");
	[elements.entryDialog, elements.renameDialog, elements.passwordDialog, elements.importDialog,
	  elements.csvImportDialog, elements.bulkModifyDialog].forEach((dialog) => {
	  const form = $("form", dialog);
	  if (form) { setFormSubmitting(form, false); form.reset(); }
	});
	setFormSubmitting(elements.entryEditor, false);
	setFormSubmitting($("#group-member-form"), false);
	$("#new-entry-attribute-list").replaceChildren();
	$$('.form-error').forEach((error) => setFieldError(error, ""));
	localize($("#import-file-name"), "import.choose");
	localize($("#csv-import-file-name"), "csv.choose");
	elements.groupMembers.hidden = true;
	elements.tableWrap.hidden = true;
	elements.detailButton.disabled = true;
	closeAccountMenu();
	localize(elements.accountName, "session.administrator");
	localize(elements.accountDN, "session.signedOut");
	elements.accountAvatar.textContent = "A";
	updateEntryActions(false);
	clearBulkSelection();
	showListView();
	localize(elements.rootLabel, "session.directory");
	localize(elements.contentTitle, "content.directoryEntries");
	localize(elements.contentSubtitle, "content.loadingContext");
	localize(elements.resultSummary, "search.results.none");
	localize(elements.detailName, "entry.noneSelected");
	localize(elements.detailKind, "entry.directoryEntry");
	elements.detailDN.textContent = "";
	localize(elements.treeCount, "nav.loaded.other", { count: 0 });
	for (const dialog of $$('dialog:not(#login-dialog)')) closeDialog(dialog);
	renderSavedQueries();
	renderQueryHistory();
  }

  const staticTranslations = [
    ["title", "app.title"],
    [".skip-link", "nav.skip"],
    ["#mobile-menu", "nav.open", "attr:aria-label"],
    ["#mobile-menu", "nav.directory", "attr:title"],
    [".brand", "app.title", "attr:aria-label"],
    [".brand-copy small", "app.operations"],
    ["#connection-label", "session.connecting"],
    [".mobile-view-switch", "nav.workspace", "attr:aria-label"],
    [".mobile-view-switch [data-mobile-view='navigation']", "nav.directoryView", "attr:aria-label"],
    [".mobile-view-switch [data-mobile-view='navigation']", "nav.directoryTitle", "attr:title"],
    [".mobile-view-switch [data-mobile-view='content']", "nav.entriesView", "attr:aria-label"],
    [".mobile-view-switch [data-mobile-view='content']", "nav.entriesTitle", "attr:title"],
    [".mobile-view-switch [data-mobile-view='context']", "nav.contextView", "attr:aria-label"],
    [".mobile-view-switch [data-mobile-view='context']", "nav.contextTitle", "attr:title"],
    ["#import-button", "actions.import", "direct"],
    ["#export-button", "actions.export", "direct"],
    ["#menu-import", "actions.importLDIF", "direct"],
    ["#menu-import-csv", "actions.importCSV", "direct"],
    ["#menu-export", "actions.exportLDIF", "direct"],
    ["#menu-export-csv", "actions.exportCSV", "direct"],
    ["#menu-export-json", "actions.exportJSON", "direct"],
    ["#logout-button", "actions.signOut", "direct"],
    ["#navigation-pane", "nav.directory", "attr:aria-label"],
    ["#navigation-pane .pane-tabs", "nav.tools", "attr:aria-label"],
    ["#tree-tab", "nav.tree"],
    ["#search-tab", "nav.search"],
    ["#tree-panel .eyebrow", "nav.namingContext"],
    ["#tree-panel h2", "nav.directoryTree"],
    ["#refresh-tree", "nav.refreshTree", "attr:aria-label"],
    ["#refresh-tree", "nav.refreshTreeTitle", "attr:title"],
    ["#directory-tree", "nav.directoryTree", "attr:aria-label"],
    ["label[for='search-base']", "search.base"],
    ["label[for='search-filter']", "search.filter"],
    ["#search-form button[type='submit']", "search.run", "attr:aria-label"],
    ["#search-form button[type='submit']", "search.run", "attr:title"],
    ["label[for='search-scope']", "search.scope"],
    ["#search-scope option[value='sub']", "search.scope.sub"],
    ["#search-scope option[value='one']", "search.scope.one"],
    ["#search-scope option[value='base']", "search.scope.base"],
    ["label[for='search-size']", "search.limit"],
    ["label[for='search-attributes']", "search.attributes"],
    [".saved-filters", "nav.commonSearches", "attr:aria-label"],
    ["[data-filter='(objectClass=person)']", "nav.people"],
    ["[data-filter*='groupOfNames']", "nav.groups"],
    ["[data-filter='(objectClass=posixAccount)']", "nav.posixAccounts"],
    ["[data-filter='(objectClass=organizationalUnit)']", "nav.organizationalUnits"],
    ["[data-filter='(objectClass=ipHost)']", "nav.hosts"],
    ["[data-filter='(pwdAccountLockedTime=*)']", "nav.locked"],
    ["#filter-builder summary", "filter.builder"],
    ["label[for='filter-logic']", "filter.match"],
    ["#filter-logic option[value='and']", "filter.all"],
    ["#filter-logic option[value='or']", "filter.any"],
    ["#add-filter-condition", "filter.add"],
    ["#apply-filter-builder", "filter.apply"],
    ["#save-query", "query.save"],
    ["#saved-query-list", "query.saved", "attr:aria-label"],
    ["#saved-query-list option[value='']", "query.saved"],
    ["#recent-query-list", "query.recent", "attr:aria-label"],
    ["#recent-query-list option[value='']", "query.recent"],
    ["#clear-query-history", "query.clearHistory"],
    ["#tree-count", "nav.loaded.other", "text", { count: 0 }],
    ["#copy-base", "nav.copyBase"],
    ["#breadcrumb", "nav.currentLocation", "attr:aria-label"],
    ["#new-entry-button", "actions.newEntry", "direct"],
    ["#refresh-content", "actions.refreshEntries", "attr:aria-label"],
    ["#refresh-content", "actions.refresh", "attr:title"],
    ["#clone-button", "actions.cloneSelected", "attr:aria-label"],
    ["#clone-button", "actions.clone", "attr:title"],
    ["#rename-button", "actions.renameSelected", "attr:aria-label"],
    ["#rename-button", "actions.renameMove", "attr:title"],
    ["#password-button", "actions.resetSelected", "attr:aria-label"],
    ["#password-button", "actions.resetPassword", "attr:title"],
    ["#delete-button", "actions.deleteSelected", "attr:aria-label"],
    ["#delete-button", "actions.delete", "attr:title"],
    [".view-toolbar .segmented", "content.view", "attr:aria-label"],
    ["#list-view-button", "actions.entries"],
    ["#detail-view-button", "actions.attributes"],
    ["#result-summary", "search.results.none"],
    [".page-actions", "search.pages", "attr:aria-label"],
    ["#previous-page", "search.previous", "attr:aria-label"],
    ["#previous-page", "search.previousTitle", "attr:title"],
    ["#next-page", "search.next", "attr:aria-label"],
    ["#next-page", "search.nextTitle", "attr:title"],
    ["#select-page", "bulk.selectPage", "attr:aria-label"],
    ["#bulk-selection-count", "bulk.selected.other", "text", { count: 0 }],
    ["#bulk-modify-button", "bulk.modify"],
    ["#bulk-delete-button", "bulk.delete"],
    ["#bulk-clear-button", "bulk.clear"],
    ["#list-view", "content.directoryEntriesLabel", "attr:aria-label"],
    ["#content-state strong", "search.loading"],
    ["#column-relative-name", "content.relativeName"],
    ["#column-type", "content.type"],
    ["#column-description", "content.description"],
    ["#column-modified", "content.modified"],
    ["#column-open", "content.open"],
    ["#detail-view", "entry.attributesLabel", "attr:aria-label"],
    ["#copy-entry-dn", "entry.copyDN", "attr:title"],
    ["#detail-status", "entry.active"],
    [".mobile-detail-actions", "entry.actions", "attr:aria-label"],
	    ["#mobile-rename-button", "actions.rename", "direct"],
	    ["#mobile-password-button", "actions.password", "direct"],
	    ["#mobile-clone-button", "actions.clone", "direct"],
	    ["#mobile-clone-button", "actions.cloneSelected", "attr:aria-label"],
	    ["#mobile-clone-button", "actions.clone", "attr:title"],
	    ["#mobile-entry-more summary", "actions.more", "attr:aria-label"],
	    ["#mobile-entry-more summary", "actions.more", "attr:title"],
	    ["#mobile-entry-more .mobile-more-label", "actions.more"],
	    ["#mobile-delete-button", "actions.delete", "direct"],
	    ["#mobile-delete-button", "actions.deleteSelected", "attr:aria-label"],
	    ["#mobile-delete-button", "actions.delete", "attr:title"],
    ["#group-members h3", "group.title"],
    ["#group-member-count", "group.members.other", "text", { count: 0 }],
    ["label[for='include-nested-members'] span", "group.includeNested"],
    ["label[for='group-member-value']", "group.memberInput"],
    ["#group-member-form button[type='submit']", "group.add"],
    ["#remove-group-members", "group.remove"],
    ["#entry-editor .editor-heading h3", "actions.attributes"],
    ["#attribute-count", "entry.attributeCount.other", "text", { count: 0 }],
    ["#add-attribute", "actions.attribute", "direct"],
    ["#browse-attributes", "actions.browseAttributes"],
    ["#editor-status", "entry.saved"],
    ["#discard-entry", "actions.discard"],
    ["#save-entry", "actions.save"],
    ["#context-pane", "context.directory", "attr:aria-label"],
    ["#context-pane > .pane-tabs", "context.tools", "attr:aria-label"],
    ["#schema-tab", "schema.schema"],
    ["#monitor-tab", "schema.monitor"],
    ["#schema-panel .eyebrow", "schema.context"],
    ["#schema-panel h2", "schema.objectClasses"],
    ["#refresh-schema", "schema.refresh", "attr:aria-label"],
    ["#refresh-schema", "schema.refresh", "attr:title"],
    [".schema-modes", "schema.type", "attr:aria-label"],
    ["#schema-classes", "schema.classes"],
    ["#schema-attributes", "schema.attributes"],
    ["#schema-rules", "schema.rules"],
    ["label[for='schema-search']", "schema.filter"],
    ["#schema-search", "schema.filter", "attr:placeholder"],
    ["#monitor-panel .eyebrow", "monitor.runtime"],
    ["#monitor-panel h2", "monitor.server"],
    ["#refresh-monitor", "monitor.refresh", "attr:aria-label"],
    ["#refresh-monitor", "monitor.refresh", "attr:title"],
    ["#monitor-health strong", "monitor.checking"],
    ["#monitor-health small", "monitor.waiting"],
    [".login-brand strong", "app.title"],
    [".login-brand span", "app.secureAdministration"],
    ["#login-title", "login.signIn"],
    ["#login-form .modal-subtitle", "login.subtitle"],
    ["label[for='login-dn']", "login.bindDN"],
    ["label[for='login-password']", "login.password"],
    ["#toggle-password", "login.showPassword", "attr:aria-label"],
    ["#toggle-password", "login.showPassword", "attr:title"],
    ["#login-submit", "login.signIn"],
    ["#entry-dialog .eyebrow", "session.directory"],
	    ["#entry-dialog-title", "create.title"],
	    ["#entry-dialog-description", "create.description"],
    ["#entry-dialog .modal-header .close-dialog", "actions.close", "attr:aria-label"],
    ["#entry-dialog .modal-header .close-dialog", "actions.close", "attr:title"],
    ["label[for='new-entry-template']", "create.entryType"],
    ["#new-entry-template option[value='person']", "create.person"],
    ["#new-entry-template option[value='posixAccount']", "create.posixAccount"],
    ["#new-entry-template option[value='group']", "create.group"],
    ["#new-entry-template option[value='uniqueGroup']", "create.uniqueGroup"],
    ["#new-entry-template option[value='posixGroup']", "create.posixGroup"],
    ["#new-entry-template option[value='ou']", "create.ou"],
    ["#new-entry-template option[value='custom']", "create.custom"],
    ["label[for='new-entry-dn']", "create.dn"],
    ["label[for='new-entry-classes']", "create.objectClasses"],
    ["#entry-form .create-attributes-heading h3", "actions.attributes"],
    ["#add-entry-attribute", "actions.attribute", "direct"],
    ["#entry-form .modal-actions .close-dialog", "actions.cancel"],
    ["#entry-form .modal-actions button[type='submit']", "create.submit"],
    ["#rename-dialog .eyebrow", "session.directory"],
	    ["#rename-dialog-title", "rename.title"],
	    ["#rename-dialog-description", "rename.description"],
    ["#rename-dialog .modal-header .close-dialog", "actions.close", "attr:aria-label"],
    ["#rename-dialog .modal-header .close-dialog", "actions.close", "attr:title"],
    ["label[for='rename-rdn']", "rename.newRDN"],
    ["label[for='rename-superior']", "rename.newParent"],
    ["#rename-delete-old + span", "rename.removeOld"],
    ["#rename-form .modal-actions .close-dialog", "actions.cancel"],
    ["#rename-form .modal-actions button[type='submit']", "rename.apply"],
    ["#password-dialog .eyebrow", "password.credentials"],
    ["#password-dialog-title", "actions.resetPassword"],
    ["#password-dialog .modal-header .close-dialog", "actions.close", "attr:aria-label"],
    ["#password-dialog .modal-header .close-dialog", "actions.close", "attr:title"],
    ["label[for='new-password']", "password.new"],
    ["label[for='confirm-password']", "password.confirm"],
    ["#password-form .modal-actions .close-dialog", "actions.cancel"],
    ["#password-form .modal-actions button[type='submit']", "actions.resetPassword"],
	    ["#import-dialog-title", "import.title"],
	    ["#import-dialog-description", "import.description"],
    ["#import-dialog .modal-header .close-dialog", "actions.close", "attr:aria-label"],
    ["#import-dialog .modal-header .close-dialog", "actions.close", "attr:title"],
    [".file-picker small", "import.utf8"],
    [".divider-label span", "import.orPaste"],
    ["label[for='import-content']", "import.content"],
    ["#import-form .modal-actions .close-dialog", "actions.cancel"],
    ["#import-form .modal-actions button[type='submit']", "actions.import"],
	    ["#csv-import-title", "csv.title"],
	    ["#csv-import-description", "csv.description"],
    ["#csv-import-dialog .modal-header .close-dialog", "actions.close", "attr:aria-label"],
    ["#csv-import-dialog .modal-header .close-dialog", "actions.close", "attr:title"],
    ["#csv-import-dialog .file-picker small", "csv.utf8"],
    ["label[for='csv-import-base']", "csv.base"],
    ["label[for='csv-import-rdn']", "csv.rdn"],
    ["label[for='csv-import-classes']", "csv.classes"],
    ["label[for='csv-import-mapping']", "csv.mapping"],
    ["label[for='csv-import-mapping'] + textarea + small", "csv.mappingHint"],
    ["label[for='csv-import-content']", "csv.content"],
    ["label[for='csv-import-continue'] span", "csv.continue"],
    ["#csv-import-form .modal-actions .close-dialog", "actions.cancel"],
    ["#csv-import-form .modal-actions button[type='submit']", "csv.submit"],
    ["#bulk-modify-dialog .eyebrow", "session.directory"],
	    ["#bulk-modify-title", "bulk.title"],
	    ["#bulk-modify-description", "bulk.description"],
    ["#bulk-modify-dialog .modal-header .close-dialog", "actions.close", "attr:aria-label"],
    ["#bulk-modify-dialog .modal-header .close-dialog", "actions.close", "attr:title"],
    ["label[for='bulk-operation']", "bulk.operation"],
    ["#bulk-operation option[value='replace']", "bulk.replace"],
    ["#bulk-operation option[value='add']", "bulk.add"],
    ["#bulk-operation option[value='delete']", "bulk.deleteValues"],
    ["#bulk-operation option[value='increment']", "bulk.increment"],
    ["label[for='bulk-attribute']", "bulk.attribute"],
    ["label[for='bulk-values']", "bulk.values"],
    ["label[for='bulk-continue'] span", "bulk.continue"],
    ["#bulk-modify-form .modal-actions .close-dialog", "actions.cancel"],
    ["#bulk-modify-form .modal-actions button[type='submit']", "bulk.apply"],
    ["#confirm-title", "confirm.title"],
    ["#confirm-cancel", "actions.cancel"],
    ["#confirm-submit", "actions.confirm"]
  ];

  function applyStaticTranslations() {
    staticTranslations.forEach(([selector, key, mode = "text", params = {}]) => {
      $$(selector).forEach((element) => {
        if (mode === "direct") setDirectText(element, t(key, params));
        else if (mode.startsWith("attr:")) element.setAttribute(mode.slice(5), t(key, params));
        else element.textContent = t(key, params);
      });
    });
  }

  function applyLanguage(language, persist = true) {
    state.language = hasLanguage(language) ? language : "en";
    document.documentElement.lang = state.language;
    if (persist) {
      try { window.localStorage.setItem(LANGUAGE_STORAGE_KEY, state.language); }
      catch (_) { /* storage can be unavailable in hardened browsers */ }
    }
    applyStaticTranslations();
    for (const [element, bindings] of liveTranslations) {
      if (!element.isConnected) { liveTranslations.delete(element); continue; }
      for (const binding of bindings.values()) {
        if (binding.render) {
          element[binding.property] = binding.render();
          continue;
        }
        const values = typeof binding.params === "function" ? binding.params() : binding.params;
        if (binding.property === "direct") setDirectText(element, t(binding.key, values));
        else if (binding.property.startsWith("attr:")) element.setAttribute(binding.property.slice(5), t(binding.key, values));
        else element[binding.property] = t(binding.key, values);
      }
    }
    $$("[data-language]").forEach((button) => button.setAttribute("aria-pressed", String(button.dataset.language === state.language)));
    $$(".language-switch").forEach((control) => control.setAttribute("aria-label", t("language.label")));
    $$("[data-language='en']").forEach((button) => { button.title = t("language.english"); });
    $$("[data-language='zh-CN']").forEach((button) => { button.title = t("language.chinese"); });
    if (state.session) setSession(state.session);
    else {
      localize(elements.accountName, "session.administrator");
      localize(elements.accountDN, "session.signedOut");
    }
    if (state.namingContexts.length > 1) localize(elements.rootLabel, "nav.namingContexts", { count: state.namingContexts.length });
    else if (state.rootDN) {
      clearLocalization(elements.rootLabel);
      elements.rootLabel.textContent = state.rootDN;
    } else localize(elements.rootLabel, "session.directory");
    if (state.currentQuery) {
      const currentName = rdnValue(state.currentQuery.base);
      if (currentName) {
        clearLocalization(elements.contentTitle);
        elements.contentTitle.textContent = currentName;
      } else localize(elements.contentTitle, "content.directoryEntries");
      if (state.currentQuery.base) {
        clearLocalization(elements.contentSubtitle);
        elements.contentSubtitle.textContent = state.currentQuery.base;
      } else localize(elements.contentSubtitle, "nav.rootDSE");
    } else {
      localize(elements.contentTitle, "content.directoryEntries");
      localize(elements.contentSubtitle, "content.loadingContext");
    }
    if (!state.selectedEntry) {
      if (!liveTranslations.has(elements.detailKind)) localize(elements.detailKind, "entry.directoryEntry");
      if (!liveTranslations.has(elements.detailName)) localize(elements.detailName, "entry.noneSelected");
    }
    if (!$("#import-file").files.length) localize($("#import-file-name"), "import.choose");
    if (!$("#csv-import-file").files.length) localize($("#csv-import-file-name"), "csv.choose");
    $$('[data-localized-validation="true"]').forEach(refreshNativeValidation);
    renderSavedQueries();
    renderQueryHistory();
  }

  class APIError extends Error {
    constructor(message, status, details) {
      super(message);
      this.name = "APIError";
      this.status = status;
      this.details = details;
    }
  }

  class SupersededRequestError extends Error {
	constructor() {
	  super("request superseded before execution");
	  this.name = "SupersededRequestError";
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
		  const errorKeys = {
			authentication_required: "api.authenticationRequired",
			session_expired: "api.sessionExpired",
			session_busy: "api.sessionBusy",
			ldap_referral_unfollowed: "api.referralUnfollowed",
			request_body_too_large: "api.bodyTooLarge",
			operation_capacity_reached: "api.capacityReached",
			ldap_transport_error: "api.unavailable",
			ldap_result_unknown: "api.unavailable",
			invalid_dn: "api.invalidDN",
			invalid_request: "api.invalidRequest",
			invalid_credentials: "api.authenticationRequired",
			csrf_failed: "api.accessDenied",
			origin_forbidden: "api.accessDenied",
			import_deadline_exceeded: "api.timeout",
			import_canceled: "api.canceled",
			administration_closing: "api.unavailable"
		  };
		  const ldapResultKeys = {
			19: "api.constraintViolation",
			32: "api.noSuchObject",
			49: "api.authenticationRequired",
			50: "api.accessDenied",
			51: "api.sessionBusy",
			52: "api.unavailable",
			53: "api.constraintViolation",
			64: "api.invalidDN",
			65: "api.constraintViolation",
			68: "api.alreadyExists",
			80: "api.unavailable"
		  };
		  const key = errorKeys[data.error.code] || ldapResultKeys[Number(data.error.ldap_result_code)] ||
			(String(data.error.code || "").startsWith("invalid_") ? "api.invalidRequest" : "");
		  const message = key ? t(key) : data.error.message || data.error.code || fallback;
			  return Number.isInteger(data.error.applied) && data.error.applied > 0
			    ? t("session.applied", { message, count: data.error.applied })
		    : message;
    }
    return data.error || data.message || data.diagnostic || data.detail || fallback;
  }

  function api(path, options = {}) {
		const generation = state.sessionGeneration;
		const execute = () => {
		  if (generation !== state.sessionGeneration) throw new SupersededRequestError();
		  if (typeof options.stale === "function" && options.stale()) throw new SupersededRequestError();
		  return apiRequest(path, options).then((result) => {
			if (generation !== state.sessionGeneration) throw new SupersededRequestError();
			return result;
		  });
		};
		const pathname = new URL(path, window.location.origin).pathname;
		if (!SESSION_SERIAL_API_PATHS.has(pathname)) return execute();
	    const pending = sessionAPIQueue.then(execute, execute);
	    sessionAPIQueue = pending.catch(() => {});
	    return pending;
  }

  async function apiRequest(path, options = {}) {
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
        throw new APIError(errorMessage(data, t("session.requestFailed", { method, path })), response.status, data);
      }
      const token = csrfFrom(data);
      if (token) state.csrf = token;
      return { data, response };
    } catch (error) {
      if (error instanceof APIError) throw error;
      throw new APIError(error.message || t("session.serverUnreachable"), 0, null);
    } finally {
      setBusy(false);
    }
  }

  function showLogin(message = "") {
	resetDirectoryState();
    setConnection("error", "session.authRequired");
    clearLocalization(elements.loginError);
    elements.loginError.hidden = !message;
    elements.loginError.textContent = message;
    if (!elements.loginDialog.open) elements.loginDialog.showModal();
    requestAnimationFrame(() => $("#login-dn").focus());
  }

  function setConnection(kind, labelKey) {
    elements.connectionDot.className = `status-dot ${kind || ""}`.trim();
    localize(elements.connectionLabel, labelKey);
  }

  function setSession(session) {
	const previousDN = sessionDN();
	const nextDN = sessionDN(session);
	if (previousDN && previousDN.toLowerCase() !== nextDN.toLowerCase()) resetDirectoryState();
	const value = session && typeof session === "object" ? session : {};
	    state.session = value;
	    const user = value.user && typeof value.user === "object" ? value.user : {};
	    const dn = value.dn || value.bind_dn || value.bindDN || value.bindDn || user.dn || user.name || t("session.administrator");
	    const name = value.displayName || user.displayName || user.cn || rdnValue(dn) || t("session.administrator");
    clearLocalization(elements.accountName);
    clearLocalization(elements.accountDN);
    elements.accountName.textContent = name;
    elements.accountDN.textContent = dn;
    elements.accountAvatar.textContent = initials(name);
    setConnection("online", "session.connected");
	renderSavedQueries();
	renderQueryHistory();
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
  function unescapedIndex(value, target) {
	let escaped = false;
	let quoted = false;
	for (let index = 0; index < String(value).length; index += 1) {
	  const character = String(value)[index];
	  if (escaped) { escaped = false; continue; }
	  if (character === "\\") { escaped = true; continue; }
	  if (character === '"') { quoted = !quoted; continue; }
	  if (!quoted && character === target) return index;
	}
	return -1;
  }
  function decodeDNValue(value) {
	let output = "";
	let bytes = [];
	const flush = () => {
	  if (bytes.length) output += new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(bytes));
	  bytes = [];
	};
	for (let index = 0; index < String(value).length; index += 1) {
	  const character = String(value)[index];
	  if (character !== "\\") { flush(); output += character; continue; }
	  const hex = String(value).slice(index + 1, index + 3);
	  if (/^[0-9A-Fa-f]{2}$/.test(hex)) { bytes.push(Number.parseInt(hex, 16)); index += 2; continue; }
	  flush();
	  if (index + 1 < String(value).length) output += String(value)[++index];
	}
	flush();
	return output;
  }
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
    return classes[classes.length - 1] || "";
  }
  function formatDate(value) {
    if (!value) return "-";
    const generalized = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(String(value));
    const date = generalized ? new Date(`${generalized[1]}-${generalized[2]}-${generalized[3]}T${generalized[4]}:${generalized[5]}:${generalized[6]}Z`) : new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : new Intl.DateTimeFormat(state.language, { year: "numeric", month: "short", day: "numeric" }).format(date);
  }

  function showState(kind, titleKey, message, action) {
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
    localize(heading, titleKey);
    elements.contentState.append(heading);
    if (message) {
      const paragraph = document.createElement("p");
      setDisplayText(paragraph, message);
      elements.contentState.append(paragraph);
    }
    if (action) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "button quiet";
      localize(button, action.labelKey);
      button.addEventListener("click", action.handler);
      elements.contentState.append(button);
    }
    elements.contentState.hidden = false;
    elements.tableWrap.hidden = true;
  }

  function toast(titleKey, message = "", kind = "success") {
    const item = document.createElement("div");
    item.className = `toast ${kind}`;
    item.setAttribute("role", kind === "error" ? "alert" : "status");
    const icon = document.createElement("strong");
    icon.textContent = kind === "error" ? "!" : "\u2713";
    const copy = document.createElement("div");
    const heading = document.createElement("strong");
    localize(heading, titleKey);
    const detail = document.createElement("span");
    setDisplayText(detail, message);
    copy.append(heading, detail);
	    const close = document.createElement("button");
    close.type = "button";
    localize(close, "actions.dismiss", {}, "attr:aria-label");
    close.textContent = "\u00d7";
		const remove = (forced = false) => {
		  if (!forced && item.contains(document.activeElement)) {
			window.setTimeout(() => remove(false), 2000);
			return;
		  }
		  if (item.contains(document.activeElement)) elements.mainContent?.focus();
		  item.remove();
		};
	    close.addEventListener("click", () => remove(true));
	    item.append(icon, copy, close);
	    elements.toastRegion.append(item);
	    window.setTimeout(() => remove(false), kind === "error" ? 9000 : 5000);
	  }

	  function setFieldError(element, message, field = null) {
		const form = element.closest("form");
		if (form && element.id) {
		  $$(`[data-error-description="${element.id}"]`, form).forEach((candidate) => {
			candidate.removeAttribute("aria-invalid");
			const descriptions = String(candidate.getAttribute("aria-describedby") || "").split(/\s+/).filter((id) => id && id !== element.id);
			if (descriptions.length) candidate.setAttribute("aria-describedby", descriptions.join(" "));
			else candidate.removeAttribute("aria-describedby");
			delete candidate.dataset.errorDescription;
		  });
		}
	    if (message) setDisplayText(element, message);
    else {
      clearLocalization(element);
      element.textContent = "";
	    }
	    element.hidden = !message;
		if (message && form && element.id) {
		  const candidate = field && form.contains(field) ? field :
			(document.activeElement && form.contains(document.activeElement) && document.activeElement.matches("input, select, textarea") ? document.activeElement : $(":invalid", form));
		  if (candidate) {
			candidate.setAttribute("aria-invalid", "true");
			const descriptions = new Set(String(candidate.getAttribute("aria-describedby") || "").split(/\s+/).filter(Boolean));
			descriptions.add(element.id);
			candidate.setAttribute("aria-describedby", Array.from(descriptions).join(" "));
			candidate.dataset.errorDescription = element.id;
		  }
		}
	  }

  function nativeValidationMessage(field) {
    field.setCustomValidity("");
    if (field.validity.valueMissing) return t("validation.required");
    if (field.validity.tooShort) return t("validation.tooShort", { min: field.minLength });
    if (field.validity.rangeUnderflow) return t("validation.minimum", { min: field.min });
    if (field.validity.rangeOverflow) return t("validation.maximum", { max: field.max });
    if (!field.validity.valid) return t("validation.invalid");
    return "";
  }

	  function refreshNativeValidation(field) {
    const message = nativeValidationMessage(field);
	    if (message) {
	      field.setCustomValidity(message);
	      field.dataset.localizedValidation = "true";
		  field.setAttribute("aria-invalid", "true");
	    } else delete field.dataset.localizedValidation;
	  }

	  function clearNativeValidation(field) {
	    field.setCustomValidity("");
	    delete field.dataset.localizedValidation;
		if (!field.dataset.errorDescription) field.removeAttribute("aria-invalid");
	  }

  function searchMaximumSize() {
	return Math.max(1, Number(state.capabilities && state.capabilities.max_search_size || 5000));
  }

  function searchDefaultSize() {
	return Math.min(500, searchMaximumSize());
  }

  function recommendedPageSize() {
	return Math.max(1, Math.min(searchMaximumSize(), Number(state.capabilities && state.capabilities.page_size || 200)));
  }

  function requestBodyLimit() {
	return Math.max(1, Number(state.capabilities && state.capabilities.request_body_limit || 8 << 20));
  }

  function assertRequestSize(value) {
	const size = new TextEncoder().encode(typeof value === "string" ? value : JSON.stringify(value)).byteLength;
	const limit = requestBodyLimit();
	if (size > limit) throw new Error(t("file.tooLarge", { limit }));
	return value;
  }

  function assertFileSize(file) {
	const limit = requestBodyLimit();
	if (file.size > limit) throw new Error(t("file.tooLarge", { limit }));
	return file;
  }

  async function initialize() {
	try {
	  window.localStorage.removeItem(QUERY_STORAGE_KEY);
	  window.localStorage.removeItem(QUERY_HISTORY_STORAGE_KEY);
	} catch (_) { /* storage can be unavailable */ }
    applyLanguage(state.language, false);
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
        setConnection("error", "session.serverUnavailable");
        showState("error", "session.directoryUnavailable", error.message, { labelKey: "search.retry", handler: () => window.location.reload() });
      }
    } finally {
      elements.shell.setAttribute("aria-busy", "false");
    }
  }

  async function loadWorkspace() {
	const { data: capabilities } = await api("/api/capabilities");
	state.capabilities = capabilities && typeof capabilities === "object" ? capabilities : {};
	$("#search-size").max = String(searchMaximumSize());
	$("#search-size").value = String(searchDefaultSize());
    const { data } = await api("/api/root-dse");
    const rootData = unwrap(data, ["root", "rootDSE"]);
    const rootEntry = normalizeEntry(rootData);
    const contexts = rootData && (rootData.namingContexts || rootData.naming_contexts || rootData.contexts);
    const entryContexts = attributeValues(rootEntry, "namingContexts");
    state.namingContexts = entryContexts.length ? entryContexts : (Array.isArray(contexts) ? contexts.map(String) : contexts ? [String(contexts)] : []);
    state.rootDN = String((typeof rootData === "string" ? rootData : "") || (rootData && (rootData.rootDN || rootData.rootDn || rootData.baseDN || rootData.base)) || state.namingContexts[0] || "");
    if (!state.namingContexts.length) state.namingContexts = [state.rootDN];
    state.baseDN = state.rootDN;
    if (state.namingContexts.length > 1) localize(elements.rootLabel, "nav.namingContexts", { count: state.namingContexts.length });
    else {
      clearLocalization(elements.rootLabel);
      elements.rootLabel.textContent = state.rootDN || t("nav.rootDSE");
    }
    $("#search-base").value = state.rootDN;
    buildTreeRoot();
    await Promise.allSettled([
	  runSearch({ base: state.rootDN, scope: "one", filter: "(objectClass=*)", attributes: LIST_ATTRIBUTES, size: searchDefaultSize() }),
	      loadSchema(),
	      ...state.namingContexts.map((dn) => loadTreeChildren(dn))
    ]);
  }

  function buildTreeRoot() {
	state.treeSequence++;
    state.treeNodes.clear();
    elements.tree.replaceChildren();
    state.namingContexts.forEach((dn) => elements.tree.append(createTreeNode(dn, 0, true).element));
    selectTreeRow(state.rootDN);
    renderBreadcrumb(state.rootDN);
  }

  function createTreeNode(dn, depth, expanded = false, objectClasses = []) {
    const container = document.createElement("div");
    container.className = "tree-node";
    container.dataset.dn = dn;
    const row = document.createElement("div");
    row.className = "tree-node-row";
	row.setAttribute("role", "none");
	    const toggle = document.createElement("span");
	toggle.className = "tree-toggle";
	toggle.setAttribute("aria-hidden", "true");
    toggle.textContent = expanded ? "\u25be" : "\u203a";
    const icon = document.createElement("span");
    icon.className = "tree-icon";
    icon.setAttribute("aria-hidden", "true");
	const classes = toValues(objectClasses).map((value) => value.toLowerCase());
	icon.textContent = depth === 0 ? "DC" : classes.includes("organizationalunit") ? "OU" :
	  classes.some((value) => value.includes("group")) ? "GR" :
	  classes.some((value) => value === "person" || value === "inetorgperson" || value === "posixaccount") ? "US" : "DN";
    const select = document.createElement("button");
	select.type = "button";
	select.className = "tree-select";
	select.setAttribute("role", "treeitem");
	select.setAttribute("aria-level", String(depth + 1));
	select.setAttribute("aria-expanded", String(expanded));
	select.setAttribute("aria-selected", "false");
    select.title = dn || t("nav.rootDSE");
    if (rdnValue(dn)) select.textContent = rdnValue(dn);
    else localize(select, "nav.rootDSE");
    const count = document.createElement("span");
    count.className = "tree-count";
    const children = document.createElement("div");
    children.className = "tree-children";
    children.setAttribute("role", "group");
    children.hidden = !expanded;
	toggle.addEventListener("click", async () => {
	  const model = state.treeNodes.get(dn);
	  const open = model.children.hidden;
	  if (open && !model.loaded) await loadTreeChildren(dn);
	  model.children.hidden = !open;
	  model.toggle.textContent = open ? "\u25be" : "\u203a";
	  model.select.setAttribute("aria-expanded", String(open));
	  localize(model.select, open ? "nav.collapse" : "nav.expand", () => ({ name: rdnValue(dn) || t("nav.root") }), "attr:aria-label");
    });
    select.addEventListener("click", async () => {
      state.baseDN = dn;
      $("#search-base").value = dn;
      selectTreeRow(dn);
	  await runSearch({ base: dn, scope: "one", filter: "(objectClass=*)", attributes: LIST_ATTRIBUTES, size: searchDefaultSize() });
	  setMobileView("content");
	  requestAnimationFrame(() => elements.mainContent && elements.mainContent.focus());
    });
	select.addEventListener("keydown", (event) => {
	  const visible = $$(".tree-select", elements.tree).filter((button) => !button.closest("[hidden]"));
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
	const model = { dn, depth, objectClasses: toValues(objectClasses), element: container, row, select, toggle, count, children, loaded: false, nextCookie: "" };
	state.treeNodes.set(dn, model);
	localize(select, expanded ? "nav.collapse" : "nav.expand", () => ({ name: rdnValue(dn) || t("nav.root") }), "attr:aria-label");
	return model;
  }

  function clearTreeDescendants(node) {
	for (const [key, candidate] of state.treeNodes) {
	  if (candidate !== node && node.children.contains(candidate.element)) state.treeNodes.delete(key);
	}
  }

  async function loadTreeChildren(dn, force = false, append = false) {
	const node = state.treeNodes.get(dn);
	if (!node || node.loading || (node.loaded && !force && !append)) return;
	const generation = state.treeSequence;
	node.loading = true;
	node.children.hidden = false;
	if (!append) {
	  clearTreeDescendants(node);
	  node.children.replaceChildren();
	  node.nextCookie = "";
	} else {
	  $(".tree-load-more", node.children)?.remove();
	}
	const loading = document.createElement("div");
	loading.className = "tree-loading";
	localize(loading, "nav.loading");
	node.children.append(loading);
	try {
	  const { data } = await api("/api/search", {
		method: "POST",
		body: searchRequest({ base: dn, scope: "one", filter: "(objectClass=*)", attributes: "objectClass", size: searchMaximumSize() }, append ? node.nextCookie : "", Math.min(250, recommendedPageSize())),
		stale: () => generation !== state.treeSequence || state.treeNodes.get(dn) !== node
	  });
	  if (generation !== state.treeSequence || state.treeNodes.get(dn) !== node) return;
	  const entries = normalizeEntries(data);
	  entries.sort((a, b) => a.dn.localeCompare(b.dn));
	  loading.remove();
	  entries.forEach((entry) => node.children.append(createTreeNode(entry.dn, node.depth + 1, false, attributeValues(entry, "objectClass")).element));
	  node.nextCookie = data && (data.page_cookie || data.pageCookie) || "";
	  if (node.nextCookie) {
		const more = document.createElement("button");
		more.type = "button";
		more.className = "text-button tree-loading tree-load-more";
		localize(more, "nav.loadMore");
		more.addEventListener("click", () => loadTreeChildren(dn, false, true));
		node.children.append(more);
	  }
	  node.loaded = true;
	  const childCount = $(":scope > .tree-node", node.children) ? $$(":scope > .tree-node", node.children).length : 0;
	  node.count.textContent = childCount ? String(childCount) : "";
	  node.toggle.classList.toggle("empty", !childCount && !node.nextCookie);
	  node.toggle.textContent = "\u25be";
	  node.select.setAttribute("aria-expanded", "true");
	  localize(elements.treeCount, state.treeNodes.size === 1 ? "nav.loaded.one" : "nav.loaded.other", () => ({ count: state.treeNodes.size }));
	} catch (error) {
	  if (error instanceof SupersededRequestError || generation !== state.treeSequence || state.treeNodes.get(dn) !== node) return;
	  loading.remove();
	  const failure = document.createElement("button");
      failure.type = "button";
      failure.className = "text-button tree-loading";
      localize(failure, "nav.retryLoading");
	  failure.addEventListener("click", () => loadTreeChildren(dn, !append, append));
	  node.children.append(failure);
	  toast("nav.treeLoadFailed", error.message, "error");
	} finally { node.loading = false; }
  }

  function selectTreeRow(dn) {
	state.treeNodes.forEach((node) => {
	  const selected = node.dn === dn;
	  node.row.classList.toggle("selected", selected);
	  node.select.setAttribute("aria-selected", String(selected));
	  node.select.tabIndex = selected ? 0 : -1;
	});
  }

  function queryFromForm() {
    const form = new FormData(elements.searchForm);
    return {
      base: String(form.get("base") || state.rootDN),
      scope: String(form.get("scope") || "sub"),
      filter: String(form.get("filter") || "(objectClass=*)"),
	  attributes: String(form.get("attributes") || LIST_ATTRIBUTES),
	      size: Math.max(1, Math.min(searchMaximumSize(), Number(form.get("size") || searchDefaultSize())))
    };
  }

  function attributeSelectors(value) {
    if (Array.isArray(value)) return value.map(String).map((item) => item.trim()).filter(Boolean);
    return String(value || "").split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);
  }

  function escapeFilterValue(value) {
    return String(value).replace(/\\/g, "\\5c").replace(/\*/g, "\\2a").replace(/\(/g, "\\28").replace(/\)/g, "\\29").replace(/\0/g, "\\00");
  }

  function addFilterCondition(attribute = "", operator = "eq", value = "") {
    const row = $("#filter-condition-template").content.firstElementChild.cloneNode(true);
    const attributeInput = $(".filter-attribute", row);
    const operatorInput = $(".filter-operator", row);
    const valueInput = $(".filter-value", row);
    attributeInput.value = attribute;
    operatorInput.value = operator;
    valueInput.value = value;
    localize(attributeInput, "filter.attribute", {}, "attr:placeholder");
    localize(attributeInput, "filter.attribute", {}, "attr:aria-label");
    localize(operatorInput, "filter.operator", {}, "attr:aria-label");
    localize(valueInput, "filter.value", {}, "attr:placeholder");
    localize(valueInput, "filter.value", {}, "attr:aria-label");
    const optionKeys = { eq: "filter.equals", contains: "filter.contains", starts: "filter.starts", ends: "filter.ends", present: "filter.present", ge: "filter.ge", le: "filter.le", approx: "filter.approx", not: "filter.not" };
    Object.entries(optionKeys).forEach(([name, key]) => localize($(`option[value='${name}']`, operatorInput), key));
    const remove = $(".remove-filter-condition", row);
    localize(remove, "filter.remove", {}, "attr:aria-label");
    localize(remove, "filter.remove", {}, "attr:title");
    remove.addEventListener("click", () => row.remove());
    operatorInput.addEventListener("change", () => { valueInput.disabled = operatorInput.value === "present"; });
    valueInput.disabled = operator === "present";
    $("#filter-condition-list").append(row);
  }

  function filterFromBuilder() {
    const filters = $$(".filter-condition", $("#filter-condition-list")).map((row) => {
      const attribute = $(".filter-attribute", row).value.trim();
      const operator = $(".filter-operator", row).value;
      const value = escapeFilterValue($(".filter-value", row).value);
      if (!/^(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)*)(?:;[A-Za-z0-9-]+)*$/.test(attribute) || (operator !== "present" && value === "")) {
		throw new Error(t("filter.invalid"));
	  }
      const expression = operator === "present" ? `${attribute}=*` :
        operator === "contains" ? `${attribute}=*${value}*` :
        operator === "starts" ? `${attribute}=${value}*` :
        operator === "ends" ? `${attribute}=*${value}` :
        operator === "ge" ? `${attribute}>=${value}` :
        operator === "le" ? `${attribute}<=${value}` :
        operator === "approx" ? `${attribute}~=${value}` : `${attribute}=${value}`;
      return operator === "not" ? `(!(${expression}))` : `(${expression})`;
    });
    if (!filters.length) return "(objectClass=*)";
    if (filters.length === 1) return filters[0];
    return `(${$("#filter-logic").value === "or" ? "|" : "&"}${filters.join("")})`;
  }

  function storedQueries() {
    try {
	  const key = scopedStorageKey(QUERY_STORAGE_KEY);
	  if (!key) return [];
	  const parsed = JSON.parse(window.localStorage.getItem(key) || "[]");
      return Array.isArray(parsed) ? parsed.filter((item) => item && typeof item.name === "string" && item.query && typeof item.query === "object").slice(0, 50) : [];
    } catch (_) { return []; }
  }

  function renderSavedQueries() {
    const select = $("#saved-query-list");
    if (!select) return;
    const selected = select.value;
    const first = document.createElement("option");
    first.value = "";
    first.textContent = t("query.saved");
    const queries = storedQueries();
    select.replaceChildren(first);
    queries.forEach((item, index) => {
      const option = document.createElement("option");
      option.value = String(index);
      option.textContent = item.name;
      select.append(option);
    });
    if (queries[Number(selected)]) select.value = selected;
  }

  function saveCurrentQuery() {
    const name = window.prompt(t("query.name"), rdnValue(queryFromForm().base) || t("query.saved"));
    if (!name || !name.trim()) return;
    const queries = storedQueries();
    queries.push({ name: name.trim().slice(0, 80), query: queryFromForm() });
	const key = scopedStorageKey(QUERY_STORAGE_KEY);
	if (!key) return;
	try { window.localStorage.setItem(key, JSON.stringify(queries.slice(-50))); }
    catch (_) { return; }
    renderSavedQueries();
    toast("query.savedToast", name.trim());
  }

  function queryHistory() {
    try {
	  const key = scopedStorageKey(QUERY_HISTORY_STORAGE_KEY);
	  if (!key) return [];
	  const parsed = JSON.parse(window.localStorage.getItem(key) || "[]");
      return Array.isArray(parsed) ? parsed.filter((item) => item && typeof item === "object").slice(0, 20) : [];
    } catch (_) { return []; }
  }

  function recordQueryHistory(query) {
    const normalized = {
      base: String(query.base || ""), scope: String(query.scope || "sub"),
	  filter: String(query.filter || "(objectClass=*)"), attributes: String(query.attributes || LIST_ATTRIBUTES),
	      size: Number(query.size || searchDefaultSize())
    };
    const signature = JSON.stringify(normalized);
    const history = queryHistory().filter((item) => JSON.stringify(item) !== signature);
    history.unshift(normalized);
	const key = scopedStorageKey(QUERY_HISTORY_STORAGE_KEY);
	if (!key) return;
	try { window.localStorage.setItem(key, JSON.stringify(history.slice(0, 20))); }
    catch (_) { return; }
    renderQueryHistory();
  }

  function renderQueryHistory() {
    const select = $("#recent-query-list");
    if (!select) return;
    const first = document.createElement("option");
    first.value = "";
    first.textContent = t("query.recent");
    select.replaceChildren(first);
    queryHistory().forEach((query, index) => {
      const option = document.createElement("option");
      option.value = String(index);
      option.textContent = `${query.filter} · ${rdnValue(query.base) || t("nav.rootDSE")}`;
      select.append(option);
    });
  }

  function applyStoredQuery(query) {
    if (!query || typeof query !== "object") return;
    $("#search-base").value = String(query.base || state.rootDN);
    $("#search-filter").value = String(query.filter || "(objectClass=*)");
    $("#search-scope").value = ["base", "one", "sub"].includes(query.scope) ? query.scope : "sub";
	    $("#search-size").value = String(Math.max(1, Math.min(searchMaximumSize(), Number(query.size) > 0 ? Number(query.size) : searchDefaultSize())));
	$("#search-attributes").value = String(query.attributes || LIST_ATTRIBUTES);
    runSearch(queryFromForm());
  }

	function searchRequest(query, cookie = "", pageSize = recommendedPageSize()) {
		const attributes = attributeSelectors(query.attributes || LIST_ATTRIBUTES);
		const attributeLimit = Math.max(1, Number(state.capabilities && state.capabilities.max_attributes || 128));
		if (attributes.length > attributeLimit) throw new Error(t("search.tooManyAttributes", { limit: attributeLimit }));
		const request = {
      base_dn: query.base || "",
      scope: query.scope || "sub",
      filter: query.filter || "(objectClass=*)",
		  attributes,
	  size_limit: Math.min(searchMaximumSize(), Number(query.size || searchDefaultSize())),
	  page_size: Math.min(searchMaximumSize(), Number(query.size || searchDefaultSize()), pageSize)
    };
	if (cookie) request.page_cookie = cookie;
	return request;
	}
	function queryIdentity(query) {
	  return JSON.stringify({
		base: String(query && query.base || ""), scope: String(query && query.scope || "sub"),
		filter: String(query && query.filter || "(objectClass=*)"),
		attributes: attributeSelectors(query && query.attributes || LIST_ATTRIBUTES), size: Number(query && query.size || searchDefaultSize())
	  });
	}

	async function runSearch(query = queryFromForm(), cookie = null, pageTransition = null) {
		const sequence = ++state.searchSequence;
		state.pageLoading = true;
		updatePagination();
		setMobileView("content");
		if (cookie === null) {
	  if (state.currentQuery && queryIdentity(state.currentQuery) !== queryIdentity(query)) clearBulkSelection();
	  recordQueryHistory(query);
	  state.pageHistory = [];
	  state.currentPageCookie = "";
	  state.nextPageCookie = "";
	  cookie = "";
	}
    state.currentQuery = query;
    state.baseDN = query.base;
    showListView();
    showState("loading", "search.loading", "");
    if (rdnValue(query.base)) {
      clearLocalization(elements.contentTitle);
      elements.contentTitle.textContent = rdnValue(query.base);
    } else localize(elements.contentTitle, "content.directoryEntries");
    if (query.base) {
      clearLocalization(elements.contentSubtitle);
      elements.contentSubtitle.textContent = query.base;
    } else localize(elements.contentSubtitle, "nav.rootDSE");
    renderBreadcrumb(query.base);
    try {
	  const { data } = await api("/api/search", {
		method: "POST", body: searchRequest(query, cookie), stale: () => sequence !== state.searchSequence
	  });
		  if (sequence !== state.searchSequence) return false;
	      state.entries = normalizeEntries(data);
		  state.currentPageCookie = cookie;
		  if (pageTransition) {
			const history = Array.isArray(pageTransition.history) ? pageTransition.history.slice() : [];
			state.pageHistory = pageTransition.type === "next" ? [...history, pageTransition.from] : history.slice(0, -1);
		  }
		  state.nextPageCookie = data && (data.page_cookie || data.pageCookie) || "";
	      renderEntries();
		  return true;
	    } catch (error) {
		  if (sequence !== state.searchSequence || error instanceof SupersededRequestError) return false;
	      state.entries = [];
	      localize(elements.resultSummary, "search.failed");
	      showState("error", "search.failed", error.message, { labelKey: "search.retry", handler: () => runSearch(query, cookie, pageTransition) });
		  return false;
	    } finally {
		  if (sequence === state.searchSequence) {
			state.pageLoading = false;
			updatePagination();
		  }
		}
	  }

	  function updatePagination() {
		elements.previousPage.disabled = state.pageLoading || state.pageHistory.length === 0;
		elements.nextPage.disabled = state.pageLoading || !state.nextPageCookie;
		elements.previousPage.setAttribute("aria-busy", String(state.pageLoading));
		elements.nextPage.setAttribute("aria-busy", String(state.pageLoading));
	  }

  function renderEntries() {
    elements.tableBody.replaceChildren();
    localize(elements.resultSummary, state.entries.length === 1 ? "search.results.one" : "search.results.other", () => ({ count: state.entries.length }));
		updatePagination();
    if (!state.entries.length) {
      showState("empty", "search.none", state.currentQuery ? state.currentQuery.filter : "");
      return;
    }
    const fragment = document.createDocumentFragment();
	    state.entries.forEach((entry, entryIndex) => {
	      const row = document.createElement("tr");
	      row.tabIndex = entry.dn === state.selectedDN || (!state.selectedDN && entryIndex === 0) ? 0 : -1;
      row.dataset.dn = entry.dn;
      row.classList.toggle("selected", entry.dn === state.selectedDN);
      const selectionCell = document.createElement("td");
      selectionCell.className = "selection-column";
      const selection = document.createElement("input");
      selection.type = "checkbox";
      selection.checked = state.selectedDNs.has(entry.dn);
      selection.setAttribute("aria-label", entry.dn);
      selection.addEventListener("click", (event) => event.stopPropagation());
      selection.addEventListener("keydown", (event) => event.stopPropagation());
      selection.addEventListener("change", () => {
        if (selection.checked) state.selectedDNs.add(entry.dn);
        else state.selectedDNs.delete(entry.dn);
        updateBulkSelection();
      });
      selectionCell.append(selection);
      const type = entryType(entry);
      const description = attributeValues(entry, "description")[0] || attributeValues(entry, "title")[0] || "-";
      const modified = attributeValues(entry, "modifyTimestamp")[0] || attributeValues(entry, "createTimestamp")[0];
      const nameCell = document.createElement("td");
      const nameWrap = document.createElement("div");
      nameWrap.className = "entry-name";
      const icon = document.createElement("span");
      icon.className = "entry-name-icon";
      icon.textContent = shortClass(type || "EN");
      const name = document.createElement("span");
      name.textContent = rdnValue(entry.dn);
      name.title = entry.dn;
      nameWrap.append(icon, name);
      nameCell.append(nameWrap);
      const modifiedCell = cell("");
      renderDynamic(modifiedCell, () => formatDate(modified));
      const typeCell = cell(type);
      if (!type) localize(typeCell, "entry.nameFallback");
      [selectionCell, nameCell, typeCell, cell(description), modifiedCell].forEach((item) => row.append(item));
      const openCell = document.createElement("td");
      openCell.className = "row-open";
      openCell.textContent = "\u203a";
      row.append(openCell);
      row.addEventListener("click", () => openEntry(entry.dn));
	      row.addEventListener("keydown", (event) => {
			if (event.key === "Enter" || event.key === " ") {
			  event.preventDefault();
			  openEntry(entry.dn);
			} else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
			  const rows = $$("tr[data-dn]", elements.tableBody);
			  const index = rows.indexOf(row);
			  const target = rows[index + (event.key === "ArrowDown" ? 1 : -1)];
			  if (target) {
				event.preventDefault();
				rows.forEach((candidate) => { candidate.tabIndex = candidate === target ? 0 : -1; });
				target.focus();
			  }
			}
		  });
      fragment.append(row);
    });
    elements.tableBody.append(fragment);
    updateBulkSelection();
    elements.contentState.hidden = true;
    elements.tableWrap.hidden = false;
  }

  function updateBulkSelection() {
    const count = state.selectedDNs.size;
    elements.bulkToolbar.hidden = count === 0;
    localize(elements.bulkSelectionCount, count === 1 ? "bulk.selected.one" : "bulk.selected.other", { count });
    const visible = state.entries.map((entry) => entry.dn);
    const selectedVisible = visible.filter((dn) => state.selectedDNs.has(dn)).length;
    const selectPage = $("#select-page");
    selectPage.checked = visible.length > 0 && selectedVisible === visible.length;
    selectPage.indeterminate = selectedVisible > 0 && selectedVisible < visible.length;
  }

  function clearBulkSelection() {
    state.selectedDNs.clear();
    $$(".selection-column input", elements.tableBody).forEach((input) => { input.checked = false; });
    updateBulkSelection();
  }

  function cell(value) {
    const element = document.createElement("td");
    element.textContent = value;
    element.title = value;
    return element;
  }

	  async function confirmEditorDiscard() {
		if (!state.editorDirty) return true;
		const approved = await confirmAction("entry.discardTitle", translated("entry.discardMessage"), "actions.discard");
		if (approved) {
		  state.editorDirty = false;
		  setEditorStatus(false);
		  if (state.selectedEntry) renderEntryDetail(state.selectedEntry);
		}
		return approved;
	  }

	  async function openEntry(dn) {
	    if (!(await confirmEditorDiscard())) return;
	const sequence = ++state.entrySequence;
    state.selectedDN = dn;
	state.selectedEntry = null;
	elements.groupMembers.hidden = true;
	elements.groupMemberList.replaceChildren();
	    updateEntryActions(false);
    $$("tr[data-dn]", elements.tableBody).forEach((row) => row.classList.toggle("selected", row.dataset.dn === dn));
    elements.detailButton.disabled = false;
    showDetailView();
    elements.attributeList.replaceChildren();
    localize(elements.detailName, "entry.loading");
    elements.detailDN.textContent = dn;
    try {
	  const { data } = await api(`/api/entries?${new URLSearchParams({ dn })}`, {
		stale: () => sequence !== state.entrySequence || state.selectedDN !== dn
	  });
		  if (sequence !== state.entrySequence || state.selectedDN !== dn) return;
	      state.selectedEntry = normalizeEntry(unwrap(data, ["entry"]));
	      renderEntryDetail(state.selectedEntry);
		  updateEntryActions(true);
		  requestAnimationFrame(() => {
			elements.detailName.tabIndex = -1;
			elements.detailName.focus();
		  });
    } catch (error) {
	  if (sequence !== state.entrySequence || state.selectedDN !== dn) return;
	      state.selectedEntry = null;
		  updateEntryActions(false);
      localize(elements.detailName, "entry.unavailable");
      const message = document.createElement("div");
      message.className = "state-view error";
      message.textContent = error.message;
      elements.attributeList.append(message);
      toast("entry.loadFailed", error.message, "error");
    }
  }

  function renderEntryDetail(entry) {
    state.editorDirty = false;
    const type = entryType(entry);
    const displayName = attributeValues(entry, "displayName")[0] || attributeValues(entry, "cn")[0] || rdnValue(entry.dn);
    clearLocalization(elements.detailName);
    elements.detailName.textContent = displayName;
    elements.detailDN.textContent = entry.dn;
    if (type) {
      clearLocalization(elements.detailKind);
      elements.detailKind.textContent = type;
    } else localize(elements.detailKind, "entry.nameFallback");
    elements.detailAvatar.textContent = initials(displayName);
    const locked = attributeValues(entry, "pwdAccountLockedTime").length > 0;
    localize(elements.detailStatus, locked ? "entry.locked" : "entry.active");
    elements.attributeList.replaceChildren();
    const attributes = Object.entries(entry.attributes || {}).sort(([a], [b]) => {
      const order = ["objectclass", "cn", "sn", "uid", "mail", "description"];
      const ai = order.indexOf(a.toLowerCase());
      const bi = order.indexOf(b.toLowerCase());
      if (ai !== -1 || bi !== -1) return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
      return a.localeCompare(b);
    });
	const binaryNames = new Set(Object.keys(entry.binaryAttributes || {}).map((name) => name.toLowerCase()));
	attributes.forEach(([name, values]) => {
	  const mixed = binaryNames.has(name.toLowerCase());
	  addAttributeRow(name, values, { readOnly: mixed || isReadOnlyAttribute(name), mixed });
	});
	Object.entries(entry.binaryAttributes || {}).sort(([a], [b]) => a.localeCompare(b)).forEach(
	  ([name, values]) => addAttributeRow(name, values, { readOnly: true, binary: true, mixed: Object.keys(entry.attributes || {}).some((textName) => textName.toLowerCase() === name.toLowerCase()) })
	);
	    updateAttributeCount();
	    setEditorStatus(false);
	    renderAttributeSuggestions();
	    renderSchema();
    $("#include-nested-members").checked = false;
    renderGroupMembers(entry, false);
  }

  function groupAttribute(entry) {
    const classes = attributeValues(entry, "objectClass").map((value) => value.toLowerCase());
    if (classes.includes("groupofuniquenames")) return "uniqueMember";
    if (classes.includes("posixgroup")) return "memberUid";
    if (classes.includes("groupofnames")) return "member";
    return "";
  }

  function normalizeGroupMembers(data, directValues, attribute) {
    const source = unwrap(data, ["result"]);
    const nested = source && source.nested;
    if (!nested) return directValues.map((value) => ({ value, nested: false, source: state.selectedDN }));
    const key = attribute === "uniqueMember" ? "uniqueMember" : attribute === "memberUid" ? "memberUid" : "member";
    const direct = new Set(directValues);
    const result = directValues.map((value) => ({ value, nested: false, source: state.selectedDN }));
    toValues(nested[key]).forEach((value) => {
      if (!direct.has(value)) result.push({ value, nested: true, source: "" });
    });
    return result;
  }

  async function renderGroupMembers(entry, requestNested) {
	const sequence = state.entrySequence;
    const attribute = groupAttribute(entry);
    elements.groupMembers.hidden = !attribute;
    if (!attribute) return;
    state.groupAttribute = attribute;
    const directValues = attributeValues(entry, attribute);
    let members = directValues.map((value) => ({ value, nested: false, source: entry.dn }));
    if (requestNested) {
      try {
		const params = new URLSearchParams({ base_dn: namingContextForDN(entry.dn), dn: entry.dn, nested: "true" });
        const { data } = await api(`/api/groups?${params}`);
		if (sequence !== state.entrySequence || state.selectedDN !== entry.dn) return;
        members = normalizeGroupMembers(data, directValues, attribute);
      } catch (error) {
		if (sequence !== state.entrySequence || state.selectedDN !== entry.dn) return;
        setFieldError($("#group-member-error"), error.message);
        toast("group.loadFailed", error.message, "error");
      }
    }
	if (sequence !== state.entrySequence || state.selectedDN !== entry.dn) return;
    state.groupMembers = members;
    elements.groupMemberList.replaceChildren();
    members.forEach((member) => {
      const row = document.createElement("label");
      row.className = "group-member-row";
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = member.value;
      checkbox.disabled = member.nested;
      checkbox.addEventListener("change", () => {
        $("#remove-group-members").disabled = !$$('input:checked', elements.groupMemberList).length;
      });
      const value = document.createElement("span");
      value.textContent = member.value;
      value.title = member.value;
      const kind = document.createElement("small");
      localize(kind, member.nested ? "group.nested" : "group.direct");
      row.append(checkbox, value, kind);
      elements.groupMemberList.append(row);
    });
    localize(elements.groupMemberCount, members.length === 1 ? "group.members.one" : "group.members.other", { count: members.length });
    $("#remove-group-members").disabled = true;
  }

  function namingContextForDN(dn) {
	const parts = splitDN(dn).map((part) => part.toLowerCase());
	return state.namingContexts.find((context) => {
	  const suffix = splitDN(context).map((part) => part.toLowerCase());
	  return suffix.length <= parts.length && suffix.every((part, index) => parts[parts.length - suffix.length + index] === part);
	}) || state.rootDN;
  }

	  async function updateGroupMembers(add, remove) {
	    if (state.groupUpdating || !state.selectedEntry || !state.groupAttribute) return;
		const dn = state.selectedEntry.dn;
		const attribute = state.groupAttribute;
		state.groupUpdating = true;
		setFormSubmitting($("#group-member-form"), true);
		$("#remove-group-members").disabled = true;
	    setFieldError($("#group-member-error"), "");
    try {
      const changes = [];
      if (add.length) changes.push({ operation: "add", attribute, values: add });
      if (remove.length) changes.push({ operation: "remove", attribute, values: remove });
      await api("/api/groups", { method: "PATCH", body: { dn, changes } });
	  if (state.selectedDN !== dn) return;
      toast("group.updated", dn);
	  await refreshAfterMutation([dn]);
	  if (state.selectedDN !== dn) return;
      await openEntry(dn);
	    } catch (error) { if (state.selectedDN === dn) setFieldError($("#group-member-error"), error.message); }
		finally {
		  state.groupUpdating = false;
		  setFormSubmitting($("#group-member-form"), false);
		  $("#remove-group-members").disabled = !$$('input:checked', elements.groupMemberList).length;
		}
	  }

	  async function openCloneDialog() {
	    if (!state.selectedEntry) return;
		if (!(await confirmEditorDiscard())) return;
    state.entryDialogMode = "clone";
    $("#entry-form").reset();
    $("#new-entry-template").value = "custom";
    localize($("#entry-dialog-title"), "entry.cloneTitle");
    const source = state.selectedEntry;
    $("#new-entry-classes").value = attributeValues(source, "objectClass").join("\n");
    $("#new-entry-attribute-list").replaceChildren();
    Object.entries(source.attributes || {}).filter(([name]) =>
      name.toLowerCase() !== "objectclass" && name.toLowerCase() !== "userpassword" && !isReadOnlyAttribute(name)
    ).forEach(([name, values]) => addCreateAttributeRow(name, values));
	const sourceRDN = rdn(source.dn);
	const separator = unescapedIndex(sourceRDN, "=");
	const sourceType = sourceRDN.slice(0, separator);
	const sourceAttributes = Object.entries(source.attributes || {});
	const matchingAttribute = sourceAttributes.find(([name]) => attributeNamesEquivalent(name, sourceType));
	const sourceAttribute = matchingAttribute && matchingAttribute[0] ||
	  (separator > 0 && /^(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)*)$/.test(sourceType) ? sourceType : "cn");
	const randomSuffix = window.crypto.getRandomValues(new Uint32Array(1))[0].toString(36);
	const clonedRDN = `${sourceAttribute}=copy-${randomSuffix}`;
    $("#new-entry-dn").value = parentDN(source.dn) ? `${clonedRDN},${parentDN(source.dn)}` : clonedRDN;
	    syncCreateRDNAttribute();
	    openDialog(elements.entryDialog);
		renderAttributeSuggestions();
	    requestAnimationFrame(() => $("#new-entry-dn").focus());
  }

		function addAttributeRow(name = "", values = [], options = {}) {
    const row = $("#attribute-row-template").content.firstElementChild.cloneNode(true);
	localizeAttributeRow(row);
    const nameInput = $(".attribute-name", row);
		let valuesInput = $(".attribute-values", row);
    const meta = $(".attribute-meta", row);
    nameInput.value = name;
		valuesInput = configureAttributeEditor(row, name, valuesInput, values);
		valuesInput.value = toValues(values).join("\n");
	setAttributeMeta(meta, name, options.binary);
    row.dataset.originalName = name;
	row.dataset.originalText = valuesInput.value;
	row.dataset.readOnly = options.readOnly ? "true" : "false";
		if (options.readOnly) {
	  row.classList.add("read-only");
	  nameInput.readOnly = true;
	  valuesInput.readOnly = true;
		  $(".remove-attribute", row).hidden = true;
		}
		if (options.mixed) localize(meta, "entry.mixedValuesReadOnly");
		if (options.binary) loadBinaryTools(row, name, !options.mixed, values);
	    $(".remove-attribute", row).addEventListener("click", () => {
	  const affectedObjectClasses = attributeNamesEquivalent(nameInput.value.trim(), "objectClass") ||
		attributeNamesEquivalent(row.dataset.originalName, "objectClass");
	  row.remove();
	  markDirty();
	  updateAttributeCount();
		  if (affectedObjectClasses) renderEditedSchemaContext();
	});
	const bindValueInput = (input) => input.addEventListener("input", () => {
	  markDirty();
		  if (attributeNamesEquivalent(nameInput.value.trim(), "objectClass")) renderEditedSchemaContext();
	});
	bindValueInput(valuesInput);
	let previousName = nameInput.value;
	nameInput.addEventListener("input", () => {
	  const affectsObjectClasses = attributeNamesEquivalent(previousName, "objectClass") || attributeNamesEquivalent(nameInput.value.trim(), "objectClass");
	  previousName = nameInput.value.trim();
	  setAttributeMeta(meta, nameInput.value, false);
	  markDirty();
		  if (affectsObjectClasses) renderEditedSchemaContext();
	});
	nameInput.addEventListener("change", () => {
	  const current = $(".attribute-values", row);
	  const value = current.value;
	  const configured = configureAttributeEditor(row, nameInput.value.trim(), current, value === "" ? [] : value.split(/\r?\n/));
	  configured.value = value;
	  if (configured !== current) bindValueInput(configured);
	});
    elements.attributeList.append(row);
    if (!name) nameInput.focus();
	    updateAttributeCount();
	  }

	  function renderEditedSchemaContext() {
		renderAttributeSuggestions();
		renderSchema();
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

  function setAttributeMeta(element, name, binary = false) {
    if (binary) { localize(element, "entry.binaryValues"); return; }
    if (!name) { localize(element, "entry.newAttribute"); return; }
    const definition = state.schema.attributeTypes.find((attribute) => schemaName(attribute).toLowerCase() === name.toLowerCase());
    const syntax = definition && (definition.syntax || definition.syntaxName || definition.description || definition.desc);
    if (syntax) {
      clearLocalization(element);
      element.textContent = String(syntax);
    } else localize(element, "entry.directoryAttribute");
  }

  function attributeSyntax(name) {
    const definition = state.schema.attributeTypes.find((attribute) => schemaName(attribute).toLowerCase() === String(name).toLowerCase());
    const text = typeof definition === "string" ? definition : definition && (definition.definition || definition.syntax || definition.syntaxName || "");
    if (/1\.3\.6\.1\.4\.1\.1466\.115\.121\.1\.7(?:\{|\s|$)/.test(text) || /\bBOOLEAN\b/i.test(text)) return "boolean";
    if (/1\.3\.6\.1\.4\.1\.1466\.115\.121\.1\.27(?:\{|\s|$)/.test(text) || /\bINTEGER\b/i.test(text)) return "integer";
    if (/1\.3\.6\.1\.4\.1\.1466\.115\.121\.1\.24(?:\{|\s|$)/.test(text) || /Generalized Time/i.test(text)) return "time";
    if (/1\.3\.6\.1\.4\.1\.1466\.115\.121\.1\.12(?:\{|\s|$)/.test(text) || /Distinguished Name/i.test(text)) return "dn";
    return "text";
  }

  function configureAttributeEditor(row, name, textarea, values) {
    const syntax = attributeSyntax(name);
    const list = toValues(values);
	const booleanCompatible = list.length === 0 || /^(?:TRUE|FALSE)$/.test(list[0]);
	const integerCompatible = list.length === 0 || /^-?(?:0|[1-9][0-9]*)$/.test(list[0]);
    if (syntax === "boolean" && list.length <= 1 && booleanCompatible) {
	  if (textarea.tagName === "SELECT") { row.dataset.editor = "boolean"; return textarea; }
      const select = document.createElement("select");
      select.className = textarea.className;
      ["", "TRUE", "FALSE"].forEach((value) => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value || "-";
        select.append(option);
      });
      textarea.replaceWith(select);
      row.dataset.editor = "boolean";
      return select;
    }
    if (syntax === "integer" && list.length <= 1 && integerCompatible) {
	  if (textarea.tagName === "INPUT" && textarea.type === "number") { row.dataset.editor = "integer"; return textarea; }
      const input = document.createElement("input");
      input.type = "number";
      input.step = "1";
      input.className = textarea.className;
      textarea.replaceWith(input);
      row.dataset.editor = "integer";
      return input;
    }
	if (textarea.tagName !== "TEXTAREA") {
	  const replacement = document.createElement("textarea");
	  replacement.rows = 2;
	  replacement.className = textarea.className;
	  textarea.replaceWith(replacement);
	  textarea = replacement;
	}
    row.dataset.editor = syntax;
    return textarea;
  }

  function base64Blob(value, mimeType) {
    const raw = window.atob(value);
    const bytes = new Uint8Array(raw.length);
    for (let index = 0; index < raw.length; index += 1) bytes[index] = raw.charCodeAt(index);
    return new Blob([bytes], { type: mimeType || "application/octet-stream" });
  }

  function bufferBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let raw = "";
    for (let offset = 0; offset < bytes.length; offset += 32768) {
      raw += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
    }
    return window.btoa(raw);
  }

  function detectBinaryMIME(value) {
	const raw = window.atob(value);
	const byte = (index) => raw.charCodeAt(index) || 0;
	if (byte(0) === 0xff && byte(1) === 0xd8 && byte(2) === 0xff) return "image/jpeg";
	if (byte(0) === 0x89 && raw.slice(1, 4) === "PNG") return "image/png";
	if (raw.slice(0, 3) === "GIF") return "image/gif";
	if (raw.slice(0, 4) === "RIFF" && raw.slice(8, 12) === "WEBP") return "image/webp";
	return "application/octet-stream";
  }

  function loadBinaryTools(row, attribute, mutable = true, encodedValues = []) {
    const tools = document.createElement("div");
    tools.className = "binary-tools";
    row.append(tools);
	const targetDN = state.selectedDN;
	const values = toValues(encodedValues);
	try {
      values.forEach((value, index) => {
        const item = document.createElement("div");
        item.className = "binary-value";
		const mime = detectBinaryMIME(value);
        if (["image/jpeg", "image/png", "image/gif", "image/webp"].includes(mime)) {
          const image = document.createElement("img");
          localize(image, "binary.value", { index: index + 1 }, "attr:alt");
          const imageURL = URL.createObjectURL(base64Blob(value, mime));
          image.src = imageURL;
          image.addEventListener("load", () => URL.revokeObjectURL(imageURL), { once: true });
          image.addEventListener("error", () => URL.revokeObjectURL(imageURL), { once: true });
          item.append(image);
        }
        const download = document.createElement("button");
        download.type = "button";
        download.className = "button quiet";
        localize(download, "binary.download");
        download.addEventListener("click", () => {
          const url = URL.createObjectURL(base64Blob(value, mime));
          const link = document.createElement("a");
          link.href = url;
          link.download = `${attribute.replace(/[^A-Za-z0-9._-]/g, "_")}-${index + 1}.bin`;
          document.body.append(link);
          link.click();
          link.remove();
          URL.revokeObjectURL(url);
        });
        item.append(download);
        tools.append(item);
      });
      if (!mutable) return;
      const actions = document.createElement("div");
      actions.className = "binary-actions";
      const input = document.createElement("input");
      input.type = "file";
      input.hidden = true;
	      const replace = document.createElement("button");
	      replace.type = "button";
	      replace.className = "button quiet";
	      localize(replace, "binary.replace");
	      replace.addEventListener("click", () => input.click());
		  let fileSequence = 0;
		  input.addEventListener("change", async () => {
			const file = input.files && input.files[0];
			if (!file) return;
			const sequence = ++fileSequence;
			const generation = state.sessionGeneration;
			const readTargetDN = targetDN;
			input.disabled = true;
			replace.disabled = true;
			remove.disabled = true;
			actions.setAttribute("aria-busy", "true");
			try {
				  const limit = Number(state.capabilities && state.capabilities.binary_max_value_bytes || 1 << 20);
			  if (file.size > limit) throw new Error(t("file.tooLarge", { limit }));
			  const encoded = bufferBase64(await file.arrayBuffer());
			  if (sequence !== fileSequence || generation !== state.sessionGeneration || state.selectedDN !== readTargetDN) return;
			  await api("/api/binary", { method: "PUT", body: { dn: readTargetDN, attribute, values_base64: [encoded] } });
			  toast("binary.updated", attribute);
			  await refreshAfterMutation([readTargetDN]);
			  if (state.selectedDN === readTargetDN) await openEntry(readTargetDN);
		        } catch (error) {
			  if (sequence !== fileSequence || generation !== state.sessionGeneration || error instanceof SupersededRequestError) return;
			  toast("binary.readFailed", error.message, "error");
			}
			finally {
			  if (sequence === fileSequence) {
				input.value = "";
				input.disabled = false;
				replace.disabled = false;
				remove.disabled = false;
				actions.setAttribute("aria-busy", "false");
			  }
			}
	      });
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "button quiet danger-text";
      localize(remove, "binary.remove");
      remove.addEventListener("click", async () => {
        const approved = await confirmAction("binary.confirmDelete", translated("binary.confirmDeleteMessage", { attribute }), "binary.remove");
        if (!approved) return;
        try {
		  await api(`/api/binary?${new URLSearchParams({ dn: targetDN, attribute })}`, { method: "DELETE" });
		  toast("binary.deleted", attribute);
		  await refreshAfterMutation([targetDN]);
		  if (state.selectedDN === targetDN) await openEntry(targetDN);
        } catch (error) { toast("entry.updateFailed", error.message, "error"); }
      });
      actions.append(input, replace, remove);
      tools.append(actions);
    } catch (error) {
      const message = document.createElement("span");
      localize(message, "binary.readFailed");
      message.title = error.message;
      tools.append(message);
    }
  }

  function localizeAttributeRow(row) {
    const labels = $$("label", row);
    localize(labels[0], "editor.attributeName", {}, "direct");
    localize(labels[1], "editor.values", {}, "direct");
    const remove = $(".remove-attribute", row);
    localize(remove, "editor.removeAttribute", {}, "attr:aria-label");
    localize(remove, "editor.removeAttribute", {}, "attr:title");
  }

  function markDirty() { state.editorDirty = true; setEditorStatus(true); }
  function setEditorStatus(dirty) { localize(elements.editorStatus, dirty ? "entry.unsaved" : "entry.saved"); }
  function updateAttributeCount() {
    const count = $$(".attribute-row", elements.attributeList).length;
    localize(elements.attributeCount, count === 1 ? "entry.attributeCount.one" : "entry.attributeCount.other", () => ({ count: $$(".attribute-row", elements.attributeList).length }));
  }
  function collectAttributeRows(container) {
    const attributes = {};
		$$(".attribute-row", container).forEach((row) => {
      const name = $(".attribute-name", row).value.trim();
      if (!name) return;
		  const text = $(".attribute-values", row).value.replace(/\r\n/g, "\n");
		  const values = text === "" ? [] : text.split("\n").filter((value) => value !== "");
		  if (!values.length) return;
		  const existing = Object.keys(attributes).find((candidate) => candidate.toLowerCase() === name.toLowerCase());
	      if (existing) attributes[existing].push(...values);
		  else attributes[name] = values;
    });
    return attributes;
  }

  const entryTemplates = {
	person: {
	  rdn: "uid", classes: ["top", "person", "organizationalPerson", "inetOrgPerson"],
	  attributes: [["uid", []], ["cn", []], ["sn", []], ["mail", []], ["description", []]]
	},
	posixAccount: {
	  rdn: "uid", classes: ["top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount"],
	  attributes: [["uid", []], ["cn", []], ["sn", []], ["uidNumber", []], ["gidNumber", []], ["homeDirectory", []], ["loginShell", ["/bin/sh"]], ["mail", []]]
	},
	group: {
	  rdn: "cn", classes: ["top", "groupOfNames"],
	  attributes: [["cn", []], ["member", []], ["description", []]]
	},
	uniqueGroup: {
	  rdn: "cn", classes: ["top", "groupOfUniqueNames"],
	  attributes: [["cn", []], ["uniqueMember", []], ["description", []]]
	},
	posixGroup: {
	  rdn: "cn", classes: ["top", "posixGroup"],
	  attributes: [["cn", []], ["gidNumber", []], ["memberUid", []], ["description", []]]
	},
	ou: {
	  rdn: "ou", classes: ["top", "organizationalUnit"],
	  attributes: [["ou", []], ["description", []]]
	},
	custom: { rdn: "cn", classes: ["top"], attributes: [["cn", []]] }
  };

  function addCreateAttributeRow(name = "", values = []) {
	const row = $("#attribute-row-template").content.firstElementChild.cloneNode(true);
	localizeAttributeRow(row);
	const nameInput = $(".attribute-name", row);
		let valuesInput = $(".attribute-values", row);
	const meta = $(".attribute-meta", row);
	nameInput.value = name;
		valuesInput = configureAttributeEditor(row, name, valuesInput, values);
		valuesInput.value = toValues(values).join("\n");
	setAttributeMeta(meta, name);
	$(".remove-attribute", row).addEventListener("click", () => row.remove());
	nameInput.addEventListener("input", () => { setAttributeMeta(meta, nameInput.value); });
	nameInput.addEventListener("change", () => {
	  const current = $(".attribute-values", row);
	  const value = current.value;
	  const configured = configureAttributeEditor(row, nameInput.value.trim(), current, value === "" ? [] : value.split(/\r?\n/));
	  configured.value = value;
	});
	$("#new-entry-attribute-list").append(row);
	if (!name) nameInput.focus();
  }

  function renderEntryTemplate(name) {
	const template = entryTemplates[name] || entryTemplates.custom;
	$("#new-entry-classes").value = template.classes.join("\n");
	$("#new-entry-attribute-list").replaceChildren();
	template.attributes.forEach(([attribute, values]) => addCreateAttributeRow(attribute, values));
		const base = state.createBaseDN || state.baseDN;
		$("#new-entry-dn").value = base ? `${template.rdn}=,${base}` : `${template.rdn}=`;
		renderAttributeSuggestions();
	  }

  function creationBaseDN() {
	const model = state.treeNodes.get(state.baseDN);
	const classes = new Set(toValues(model && model.objectClasses).map((value) => value.toLowerCase()));
	const leaf = [...classes].some((value) => value === "person" || value === "inetorgperson" || value === "posixaccount" || value.includes("group"));
	return leaf ? parentDN(state.baseDN) : state.baseDN;
  }

	function syncCreateRDNAttribute() {
	const first = rdn($("#new-entry-dn").value.trim());
	if (unescapedIndex(first, "+") >= 0) return;
	const separator = unescapedIndex(first, "=");
	if (separator <= 0) return;
	const attribute = first.slice(0, separator).trim().toLowerCase();
	const value = decodeDNValue(first.slice(separator + 1).trim());
	if (!value) return;
	const row = $$(".attribute-row", $("#new-entry-attribute-list")).find(
	  (candidate) => attributeNamesEquivalent($(".attribute-name", candidate).value.trim(), attribute)
	);
	if (row && (!$(".attribute-values", row).value || state.entryDialogMode === "clone")) $(".attribute-values", row).value = value;
  }

  function attributeNamesEquivalent(left, right) {
	const standardAttributeOIDs = {
	  "2.5.4.1": "aliasedobjectname", "2.5.4.2": "knowledgeinformation",
	  "2.5.4.3": "cn", "2.5.4.4": "sn", "2.5.4.5": "serialnumber", "2.5.4.6": "c",
	  "2.5.4.7": "l", "2.5.4.8": "st", "2.5.4.9": "street", "2.5.4.10": "o",
	  "2.5.4.11": "ou", "2.5.4.12": "title", "2.5.4.13": "description",
	  "2.5.4.15": "businesscategory", "2.5.4.16": "postaladdress", "2.5.4.17": "postalcode",
	  "2.5.4.18": "postofficebox", "2.5.4.19": "physicaldeliveryofficename",
	  "2.5.4.20": "telephonenumber", "2.5.4.31": "member", "2.5.4.32": "owner",
	  "2.5.4.33": "roleoccupant", "2.5.4.34": "seealso", "2.5.4.35": "userpassword",
	  "2.5.4.41": "name", "2.5.4.42": "givenname", "2.5.4.43": "initials",
	  "2.5.4.44": "generationqualifier", "2.5.4.46": "dnqualifier", "2.5.4.49": "distinguishedname",
	  "2.5.4.50": "uniquemember", "2.5.4.51": "houseidentifier", "2.5.4.54": "dmdname",
	  "2.5.4.65": "pseudonym", "0.9.2342.19200300.100.1.1": "uid",
	  "0.9.2342.19200300.100.1.3": "mail", "0.9.2342.19200300.100.1.25": "dc",
	  "0.9.2342.19200300.100.1.37": "associateddomain"
	};
	const leftName = standardAttributeOIDs[String(left).toLowerCase()] || String(left).toLowerCase();
	const rightName = standardAttributeOIDs[String(right).toLowerCase()] || String(right).toLowerCase();
	if (leftName === rightName) return true;
	return state.schema.attributeTypes.some((definition) => {
	  const names = [schemaName(definition), definition && definition.oid, ...arrayFrom(definition && definition.aliases)].filter(Boolean).map((value) => String(value).toLowerCase());
	  return names.includes(String(left).toLowerCase()) && names.includes(String(right).toLowerCase());
	});
  }

	function validateCreateEntry(attributes) {
	const template = $("#new-entry-template").value;
	const required = {
	  person: ["uid", "cn", "sn"],
	  posixAccount: ["uid", "cn", "sn", "uidNumber", "gidNumber", "homeDirectory"],
	  group: ["cn", "member"], uniqueGroup: ["cn", "uniqueMember"],
	  posixGroup: ["cn", "gidNumber"], ou: ["ou"], custom: []
	}[template] || [];
	for (const name of required) {
	  const key = Object.keys(attributes).find((candidate) => candidate.toLowerCase() === name);
	  if (!key || !attributes[key].some((value) => value !== "")) return translated("create.required", { name });
	}
	if (template === "custom" && lines($("#new-entry-classes").value).filter((value) => value.toLowerCase() !== "top").length === 0) {
	  return translated("create.structuralRequired");
	}
	return "";
  }

	function attributeChanges(original) {
    const originalAttributes = original && original.attributes ? original.attributes : {};
    const changes = [];
	const retainedOriginalNames = new Set();
	$$(".attribute-row", elements.attributeList).forEach((row) => {
	  const originalName = row.dataset.originalName || "";
	  if (originalName) retainedOriginalNames.add(originalName.toLowerCase());
	  if (row.dataset.readOnly === "true") return;
	  const currentName = $(".attribute-name", row).value.trim();
	  const currentText = $(".attribute-values", row).value.replace(/\r\n/g, "\n");
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
	  function updateEntryActions(enabled) {
		$$(`.entry-action, #mobile-rename-button, #mobile-password-button, #mobile-clone-button, #mobile-delete-button`).forEach((button) => {
		  button.disabled = !enabled;
		});
		const more = $("#mobile-entry-more");
		if (more) {
		  if (!enabled) more.removeAttribute("open");
		  more.classList.toggle("disabled", !enabled);
		}
	  }

  function renderBreadcrumb(dn) {
    elements.breadcrumb.replaceChildren();
    const parts = splitDN(dn);
    if (!parts.length) { localize(elements.breadcrumb, "nav.rootDSE"); return; }
    const visible = parts.slice(0, 5);
    visible.reverse().forEach((part, index) => {
      const originalIndex = visible.length - index - 1;
      const targetDN = parts.slice(originalIndex).join(",");
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = rdnValue(part);
      button.title = targetDN;
	  button.addEventListener("click", () => runSearch({ base: targetDN, scope: "one", filter: "(objectClass=*)", attributes: LIST_ATTRIBUTES, size: searchDefaultSize() }));
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
    if (!source || typeof source !== "object") return { objectClasses: [], attributeTypes: [], rules: [] };
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
      name: quoted[0] || (singleName && singleName[1]) || (oid && oid[1]) || "",
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
      renderAttributeSuggestions();
      renderSchema();
    } catch (error) {
      elements.schemaList.replaceChildren(contextMessage("schema.unavailable", error.message, true));
    }
  }
	  function schemaDefinitionTokens(definition, keyword) {
		if (definition && typeof definition === "object") {
		  const directKey = Object.keys(definition).find((key) => key.toLowerCase() === keyword.toLowerCase());
		  if (directKey) {
			const direct = Array.isArray(definition[directKey]) ? definition[directKey] : String(definition[directKey] || "").split(/[\s$]+/);
			return direct.map((value) => String(value).replace(/^'+|'+$/g, "")).filter(Boolean);
		  }
		}
		const source = typeof definition === "string" ? definition : String(definition && definition.definition || "");
		const match = new RegExp(`\\b${keyword}\\s+(?:\\(\\s*([^)]*)\\)|([^\\s)]+))`, "i").exec(source);
		if (!match) return [];
		return String(match[1] || match[2] || "").match(/[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)*/g) || [];
	  }

	  function schemaDefinitionNames(definition) {
		return [schemaName(definition), definition && definition.oid, ...arrayFrom(definition && definition.aliases)]
		  .filter(Boolean).map((value) => String(value));
	  }

	  function currentEditorAttributeValues(name) {
		const values = [];
		$$(".attribute-row", elements.attributeList).forEach((row) => {
		  const attributeName = $(".attribute-name", row)?.value.trim() || "";
		  if (!attributeNamesEquivalent(attributeName, name)) return;
		  const control = $(".attribute-values", row);
		  if (control) values.push(...lines(control.value));
		});
		return values;
	  }

	  function suggestedAttributeNames() {
		let classNames = currentEditorAttributeValues("objectClass");
		let targetDN = state.selectedDN;
		if (elements.entryDialog.open) {
		  classNames = lines($("#new-entry-classes").value);
		  targetDN = $("#new-entry-dn").value.trim();
		}
		if (!classNames.length) return null;
		const classByName = new Map();
		state.schema.objectClasses.forEach((definition) => {
		  schemaDefinitionNames(definition).forEach((name) => classByName.set(name.toLowerCase(), definition));
		});
		const allowed = new Set(["objectclass"]);
		const denied = new Set();
		const visited = new Set();
		const resolved = new Set();
		const resolvedIdentifiers = new Set();
		const visit = (name) => {
		  const normalized = String(name).toLowerCase();
		  if (visited.has(normalized)) return;
		  visited.add(normalized);
		  const definition = classByName.get(normalized);
		  if (!definition) return;
		  resolved.add(normalized);
		  schemaDefinitionNames(definition).forEach((identifier) => resolvedIdentifiers.add(identifier.toLowerCase()));
		  schemaDefinitionTokens(definition, "MUST").forEach((attribute) => allowed.add(attribute.toLowerCase()));
		  schemaDefinitionTokens(definition, "MAY").forEach((attribute) => allowed.add(attribute.toLowerCase()));
		  schemaDefinitionTokens(definition, "SUP").forEach(visit);
		};
		classNames.forEach(visit);
		if (![...resolved].some((name) => name !== "top")) return null;
		(state.schema.rules || []).filter((rule) => rule.type === "dITContentRules").forEach((rule) => {
		  if (!schemaDefinitionNames(rule).some((identifier) => resolvedIdentifiers.has(identifier.toLowerCase()))) return;
		  schemaDefinitionTokens(rule, "MUST").forEach((attribute) => allowed.add(attribute.toLowerCase()));
		  schemaDefinitionTokens(rule, "MAY").forEach((attribute) => allowed.add(attribute.toLowerCase()));
		  schemaDefinitionTokens(rule, "NOT").forEach((attribute) => denied.add(attribute.toLowerCase()));
		});
		const targetRDN = rdn(targetDN);
		const separator = unescapedIndex(targetRDN, "=");
		if (separator > 0) allowed.add(targetRDN.slice(0, separator).trim().toLowerCase());
		if (allowed.size === 1) return null;
		return { allowed, denied };
	  }

	  function renderAttributeSuggestions() {
		const constraints = suggestedAttributeNames();
	    const names = state.schema.attributeTypes.filter((definition) => {
		  if (!constraints) return true;
		  const identifiers = schemaDefinitionNames(definition).map((name) => name.toLowerCase());
		  return identifiers.some((name) => constraints.allowed.has(name)) && !identifiers.some((name) => constraints.denied.has(name));
		}).map(schemaName).filter(Boolean);
		CONFIGURATION_ATTRIBUTE_SUGGESTIONS.forEach((name) => {
		  if ((!constraints || constraints.allowed.has(name.toLowerCase())) && !names.some((candidate) => candidate.toLowerCase() === name.toLowerCase())) names.push(name);
		});
		names.sort((left, right) => left.localeCompare(right));
	    $("#attribute-name-options").replaceChildren(...names.slice(0, 1000).map((name) => {
      const option = document.createElement("option");
      option.value = name;
      return option;
    }));
  }
  function renderSchema() {
    const query = elements.schemaSearch.value.trim().toLowerCase();
	    const selectedClasses = new Set((state.selectedEntry ? currentEditorAttributeValues("objectClass") : []).map((value) => value.toLowerCase()));
	const source = state.schemaView === "attributes" ? state.schema.attributeTypes :
	  state.schemaView === "rules" ? state.schema.rules : state.schema.objectClasses;
	const classes = source.filter((definition) => {
      const text = JSON.stringify(definition).toLowerCase();
      if (query && !text.includes(query)) return false;
	  return state.schemaView !== "classes" || query || !selectedClasses.size || selectedClasses.has(schemaName(definition).toLowerCase());
    }).slice(0, 100);
    elements.schemaList.replaceChildren();
    if (!classes.length) {
	  elements.schemaList.append(contextMessage("schema.noMatches", query || translated("schema.noDefinitions")));
      return;
    }
    const title = document.createElement("div");
    title.className = "schema-group-title";
	localize(title, state.schemaView === "attributes" ? "schema.attributeTypes" :
	  state.schemaView === "rules" ? "schema.matchingRules" :
	  selectedClasses.size && !query ? "schema.applied" : "schema.objectClasses");
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
    if (schemaName(definition)) name.textContent = schemaName(definition);
    else localize(name, "schema.unnamedClass");
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
    localize($("strong", elements.monitorHealth), "monitor.checking");
    localize($("small", elements.monitorHealth), "monitor.waiting");
    try {
      const { data } = await api("/api/monitor");
      state.monitor = unwrap(data, ["monitor", "metrics", "status"]);
      renderMonitor();
    } catch (error) {
      elements.monitorHealth.classList.add("unhealthy");
      $(".health-icon", elements.monitorHealth).textContent = "!";
      localize($("strong", elements.monitorHealth), "monitor.unavailable");
      renderDynamic($("small", elements.monitorHealth), () => error.message);
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
	localize($("strong", elements.monitorHealth), unhealthy ? "monitor.issue" : "monitor.responding");
	if (healthValue) {
	  renderDynamic($("small", elements.monitorHealth), () => String(healthValue[1]));
	} else localize($("small", elements.monitorHealth), "monitor.available");
    const preferred = rows.filter(([key, value]) => /connection|operation|entry|uptime|thread|memory/i.test(key) && value !== "").slice(0, 6);
    const metrics = preferred.length ? preferred : rows.slice(0, 6);
    elements.metricGrid.replaceChildren();
    metrics.forEach(([key, value]) => {
      const wrapper = document.createElement("div");
      const term = document.createElement("dt");
      term.textContent = key.split(".").pop();
      term.title = key;
      const detail = document.createElement("dd");
      renderDynamic(detail, () => formatMetric(value));
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
    if (typeof value === "number") return new Intl.NumberFormat(state.language).format(value);
    const numeric = Number(value);
    if (String(value).trim() && Number.isFinite(numeric)) return new Intl.NumberFormat(state.language).format(numeric);
    return String(value === undefined || value === null ? "-" : value);
  }
  function contextMessage(titleKey, message, error = false) {
    const wrapper = document.createElement("div");
    wrapper.className = `state-view ${error ? "error" : ""}`.trim();
    wrapper.classList.add("context-message");
    const heading = document.createElement("strong");
    localize(heading, titleKey);
    const copy = document.createElement("p");
    setDisplayText(copy, message || "");
    wrapper.append(heading, copy);
    return wrapper;
  }

  function openDialog(dialog) {
	if (dialog.open) return;
	const error = $(".form-error", dialog);
	if (error) setFieldError(error, "");
    $$("input, select, textarea", dialog).forEach(clearNativeValidation);
	    dialog.showModal();
	requestAnimationFrame(() => {
	  if (!dialog.open) return;
	  const target = dialog === elements.confirmDialog ? $("#confirm-cancel") :
		$("[autofocus], [data-initial-focus], input:not([type='hidden']), select, textarea, button", dialog);
	  target?.focus();
	});
  }
  function closeDialog(dialog) {
	if (dialog.open) dialog.close();
	if (dialog === elements.entryDialog) renderAttributeSuggestions();
  }
	function setFormSubmitting(form, submitting) {
		if (submitting && !submittingControls.has(form)) {
		  const disabled = new Map();
		  $$("button, input, select, textarea", form).forEach((control) => {
			disabled.set(control, control.disabled);
			control.disabled = true;
		  });
		  submittingControls.set(form, disabled);
		} else if (!submitting && submittingControls.has(form)) {
		  submittingControls.get(form).forEach((wasDisabled, control) => {
			if (control.isConnected) control.disabled = wasDisabled;
		  });
		  submittingControls.delete(form);
		}
		form.setAttribute("aria-busy", String(submitting));
	  }
  function confirmAction(titleKey, message, confirmLabelKey = "actions.confirm") {
    if (state.confirmResolve) state.confirmResolve(false);
    localize($("#confirm-title"), titleKey);
    setDisplayText($("#confirm-message"), message);
    localize($("#confirm-submit"), confirmLabelKey);
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
	    $$(".mobile-view-switch [data-mobile-view]").forEach((button) => {
	  const active = button.dataset.mobileView === view;
	  button.classList.toggle("active", active);
	      button.setAttribute("aria-pressed", String(active));
	    });
		if (window.matchMedia("(max-width: 1080px)").matches) {
		  const target = view === "navigation" ? $("#navigation-pane") : view === "context" ? $("#context-pane") : elements.mainContent;
		  target?.focus();
		}
	  }

	  function closeAccountMenu(restoreFocus = false) {
		elements.accountMenu.hidden = true;
		elements.accountButton.setAttribute("aria-expanded", "false");
		$$('[role="menuitem"]', elements.accountMenu).forEach((item) => { item.tabIndex = -1; });
		if (restoreFocus) elements.accountButton.focus();
	  }

	  async function refreshAfterMutation(affectedDNs = [], branchDNs = []) {
		const detailDN = state.selectedEntry && state.selectedDN;
		const preserveDetail = Boolean(detailDN && !elements.detailView.hidden);
		const requestedBranches = branchDNs.filter(Boolean);
		affectedDNs.filter(Boolean).forEach((dn) => requestedBranches.push(parentDN(dn) || dn));
		if (!requestedBranches.length && state.baseDN) requestedBranches.push(state.baseDN);
		const treeNodes = new Map();
		requestedBranches.forEach((dn) => {
		  const node = nearestTreeNode(dn);
		  if (node) treeNodes.set(node.dn, node);
		});
	    await Promise.allSettled([
		  runSearch(state.currentQuery || queryFromForm()),
		  ...Array.from(treeNodes.values(), (node) => loadTreeChildren(node.dn, true))
		]);
		if (preserveDetail && state.selectedEntry && state.selectedDN === detailDN) showDetailView();
	  }
	  function nearestTreeNode(dn) {
		let candidate = String(dn || "");
		while (candidate) {
		  const node = state.treeNodes.get(candidate);
		  if (node) return node;
		  const parent = parentDN(candidate);
		  if (!parent || parent === candidate) break;
		  candidate = parent;
		}
		return state.treeNodes.get(state.rootDN) || null;
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
      toast("export.complete", filename);
    } catch (error) { toast("export.failed", error.message, "error"); }
  }

  async function exportData(format) {
    const query = state.currentQuery || queryFromForm();
    const params = new URLSearchParams({
      format, base_dn: query.base, filter: query.filter, scope: query.scope || "sub",
	  attributes: attributeSelectors(query.attributes || LIST_ATTRIBUTES).join(","), size_limit: String(query.size || searchDefaultSize())
    });
    try {
      const { data, response } = await api(`/api/data-export?${params}`, { responseType: "blob", accept: format === "csv" ? "text/csv" : "application/json" });
      const disposition = response.headers.get("content-disposition") || "";
      const match = /filename\*?=(?:UTF-8''|\")?([^\";]+)/i.exec(disposition);
      const filename = match ? decodeURIComponent(match[1].replace(/"$/, "")) : `directory-export.${format}`;
      const url = URL.createObjectURL(data);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.append(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      toast("export.complete", filename);
    } catch (error) { toast("export.failed", error.message, "error"); }
  }

	  async function runBulk(action, changes = [], continueOnError = false) {
    const dns = Array.from(state.selectedDNs);
    if (!dns.length) return;
    const { data } = await api("/api/bulk", { method: "POST", body: {
      action, dns, changes, continue_on_error: continueOnError
    } });
    const applied = Number(data && data.applied || 0);
    const failed = Number(data && data.failed || 0);
    const unknown = Number(data && data.unknown || 0);
	(data && data.results || []).filter((result) => result.status === "applied" || result.status === "unknown").forEach((result) => state.selectedDNs.delete(result.dn));
	updateBulkSelection();
	    const summary = data && data.aborted ? t("bulk.aborted", { reason: localizedAbortReason(data) }) : t("bulk.summary", { applied, failed, unknown });
		const details = batchResultDetails(data, 5);
	    toast("bulk.complete", [summary, details].filter(Boolean).join("\n"), failed || unknown || data && data.aborted ? "error" : "success");
    if (!failed && !unknown && !(data && data.aborted)) clearBulkSelection();
	    await refreshAfterMutation(dns);
		return data;
	  }

	  function batchResultDetails(data, limit = 10) {
		const results = data && Array.isArray(data.results) ? data.results : [];
		const failures = results.filter((result) => result.status === "failed" || result.status === "unknown").slice(0, limit).map((result) =>
		  t("bulk.entryFailure", { dn: result.dn || "?", message: errorMessage({ error: result.error }, result.status || t("api.unavailable")) })
		);
		const notAttempted = results.filter((result) => result.status === "not_attempted").length;
		if (notAttempted) failures.push(t("bulk.notAttempted", { count: notAttempted }));
		return failures.join("\n");
	  }

	  function localizedAbortReason(data) {
		const reason = String(data && data.abort_reason || "");
		if (/deadline|timed? out/i.test(reason)) return t("api.timeout");
		if (/cancel/i.test(reason)) return t("api.canceled");
		if (/closing|unavailable|unknown/i.test(reason)) return t("api.unavailable");
		return reason || t("api.unavailable");
	  }

	  function ldifResultDetails(data, limit = 10) {
		const results = data && Array.isArray(data.results) ? data.results : [];
		const failures = results.filter((result) => result.status === "failed" || result.status === "unknown").slice(0, limit).map((result) =>
		  t("import.recordFailure", {
			record: result.record || "?",
			dn: result.dn || "?",
			message: errorMessage({ error: result.error }, result.status || t("api.unavailable"))
		  })
		);
		const notAttempted = results.filter((result) => result.status === "not_attempted").length;
		if (notAttempted) failures.push(t("import.notAttempted", { count: notAttempted }));
		return failures.join("\n");
	  }

	  function stableSerialize(value) {
		if (Array.isArray(value)) return `[${value.map(stableSerialize).join(",")}]`;
		if (value && typeof value === "object") {
		  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableSerialize(value[key])}`).join(",")}}`;
		}
		return JSON.stringify(value);
	  }

	  function canonicalLDIF(value) {
		const logicalLines = [];
		String(value || "").replace(/\r\n?/g, "\n").split("\n").forEach((line) => {
		  if (line.startsWith(" ") && logicalLines.length) logicalLines[logicalLines.length - 1] += line.slice(1);
		  else logicalLines.push(line);
		});
		const records = [];
		let record = [];
		const flush = () => {
		  if (record.length) records.push(record.join("\n"));
		  record = [];
		};
		logicalLines.forEach((line) => {
		  if (!line.trim()) flush();
		  else if (!line.startsWith("#")) record.push(line);
		});
		flush();
		return records.join("\n\n");
	  }

	  function canonicalCSVBody(body) {
		return {
		  ...body,
		  csv: String(body.csv || "").replace(/\r\n?/g, "\n").replace(/\n+$/, "")
		};
	  }

	  async function batchFingerprint(kind, value) {
		const canonical = kind === "ldif" ? canonicalLDIF(value) : stableSerialize(canonicalCSVBody(value));
		if (!window.crypto || !window.crypto.subtle) return `raw:${canonical}`;
		const digest = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
		return `sha256:${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
	  }

	  function retryFingerprints(kind) {
		return kind === "ldif" ? state.ldifRetryFingerprints : state.csvRetryFingerprints;
	  }

	  function hasStructuredBatchResult(data) {
		return Boolean(data && typeof data === "object" && (
		  Array.isArray(data.results) || ["applied", "failed", "unknown", "aborted"].some((key) => Object.prototype.hasOwnProperty.call(data, key))
		));
	  }

	  function unsafeBatchOutcome(data, error = null) {
		if (!hasStructuredBatchResult(data)) return !error || !error.status || error.status >= 500;
		const applied = Number(data.applied || data.error && data.error.applied || 0);
		return applied > 0 || Number(data.unknown || 0) > 0;
	  }

	  function csvResultDetails(data, limit = 10) {
		const results = data && Array.isArray(data.results) ? data.results : [];
		const failures = results.filter((result) => result.status === "failed" || result.status === "unknown").slice(0, limit).map((result) =>
		  t("csv.rowFailure", { row: result.row || "?", message: errorMessage({ error: result.error }, result.status || t("api.unavailable")) })
		);
		const notAttempted = results.filter((result) => result.status === "not_attempted").length;
		if (notAttempted) failures.push(t("csv.notAttempted", { count: notAttempted }));
		return failures.join("\n");
	  }

	  async function approveChangedBatch(kind, fingerprint, errorElement, field) {
		const fingerprints = retryFingerprints(kind);
		if (!fingerprints.size) return true;
		if (fingerprints.has(fingerprint)) {
		  setFieldError(errorElement, translated(`${kind === "ldif" ? "import" : "csv"}.partialNoRetry`), field);
		  return false;
		}
		const prefix = kind === "ldif" ? "import" : "csv";
		return confirmAction(`${prefix}.changedRetryTitle`, translated(`${prefix}.changedRetryMessage`), `${prefix}.changedRetryConfirm`);
	  }

	  function resultDNs(data) {
		return data && Array.isArray(data.results) ? data.results.map((result) => String(result.dn || "")).filter(Boolean) : [];
	  }

  function parseCSVMapping(value) {
    const mapping = {};
    const attributes = new Set();
    for (const line of lines(value)) {
      const separator = line.indexOf("=");
      const header = separator > 0 ? line.slice(0, separator).trim() : "";
      const attribute = separator > 0 ? line.slice(separator + 1).trim() : "";
      if (!header || !attribute || Object.prototype.hasOwnProperty.call(mapping, header) || attributes.has(attribute.toLowerCase())) {
        throw new Error(t("csv.invalidMapping"));
      }
      mapping[header] = attribute;
      attributes.add(attribute.toLowerCase());
    }
    if (!Object.keys(mapping).length) throw new Error(t("csv.invalidMapping"));
    return mapping;
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
    $$("[data-language]").forEach((button) => button.addEventListener("click", () => applyLanguage(button.dataset.language)));
    document.addEventListener("invalid", (event) => {
      if (event.target.matches("input, select, textarea")) refreshNativeValidation(event.target);
    }, true);
    document.addEventListener("input", (event) => {
      if (event.target.matches("input, select, textarea")) clearNativeValidation(event.target);
    });
    document.addEventListener("change", (event) => {
      if (event.target.matches("input, select, textarea")) clearNativeValidation(event.target);
    });
    bindTabs($("#tree-tab"), $("#search-tab"), $("#tree-panel"), $("#search-panel"));
	bindTabs($("#schema-tab"), $("#monitor-tab"), $("#schema-panel"), $("#monitor-panel"), () => {
	  if (!state.monitor) loadMonitor();
	});
    elements.searchForm.addEventListener("submit", (event) => { event.preventDefault(); runSearch(); });
	addFilterCondition("objectClass", "present", "");
	$("#add-filter-condition").addEventListener("click", () => addFilterCondition());
	$("#apply-filter-builder").addEventListener("click", () => {
	  try { $("#search-filter").value = filterFromBuilder(); runSearch(); }
	  catch (error) { toast("search.failed", error.message, "error"); }
	});
	$("#save-query").addEventListener("click", saveCurrentQuery);
	$("#saved-query-list").addEventListener("change", (event) => {
	  if (event.target.value === "") return;
	  const selected = storedQueries()[Number(event.target.value)];
	  if (!selected) return;
	  applyStoredQuery(selected.query);
	});
	$("#recent-query-list").addEventListener("change", (event) => {
	  if (event.target.value !== "") applyStoredQuery(queryHistory()[Number(event.target.value)]);
	});
	$("#clear-query-history").addEventListener("click", () => {
	  const key = scopedStorageKey(QUERY_HISTORY_STORAGE_KEY);
	  try { if (key) window.localStorage.removeItem(key); } catch (_) { /* ignore */ }
	  renderQueryHistory();
	});
	elements.nextPage.addEventListener("click", async () => {
	  if (state.pageLoading || !state.nextPageCookie) return;
	  const previousCookie = state.currentPageCookie;
	  const nextCookie = state.nextPageCookie;
	  await runSearch(state.currentQuery || queryFromForm(), nextCookie, {
		type: "next", from: previousCookie, history: state.pageHistory.slice()
	  });
	});
	elements.previousPage.addEventListener("click", async () => {
	  if (state.pageLoading || !state.pageHistory.length) return;
	  const cookie = state.pageHistory[state.pageHistory.length - 1];
	  await runSearch(state.currentQuery || queryFromForm(), cookie, {
		type: "previous", history: state.pageHistory.slice()
	  });
	});
    $$("[data-filter]").forEach((button) => button.addEventListener("click", () => { $("#search-filter").value = button.dataset.filter; runSearch(); }));
	$("#select-page").addEventListener("change", (event) => {
	  state.entries.forEach((entry) => event.target.checked ? state.selectedDNs.add(entry.dn) : state.selectedDNs.delete(entry.dn));
	  $$(".selection-column input", elements.tableBody).forEach((input) => { input.checked = event.target.checked; });
	  updateBulkSelection();
	});
	$("#bulk-clear-button").addEventListener("click", clearBulkSelection);
	$("#bulk-modify-button").addEventListener("click", () => openDialog(elements.bulkModifyDialog));
	$("#bulk-delete-button").addEventListener("click", async () => {
	  const approved = await confirmAction("bulk.deleteTitle", translated("bulk.deleteMessage", { count: state.selectedDNs.size }), "bulk.delete");
	  if (!approved) return;
	  try { await runBulk("delete", [], true); }
	  catch (error) { toast("bulk.complete", error.message, "error"); }
	});
    elements.listButton.addEventListener("click", showListView);
    elements.detailButton.addEventListener("click", () => { if (state.selectedEntry) showDetailView(); });
    $("#refresh-content").addEventListener("click", () => runSearch(state.currentQuery || queryFromForm()));
	$("#clone-button").addEventListener("click", openCloneDialog);
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
    $("#copy-base").addEventListener("click", () => copyText(state.baseDN, "actions.baseCopied"));
    $("#copy-entry-dn").addEventListener("click", () => copyText(state.selectedDN, "actions.entryCopied"));
    $("#mobile-menu").addEventListener("click", () => setMobileView("navigation"));
	    $$(".mobile-view-switch [data-mobile-view]").forEach((button) => button.addEventListener("click", () => setMobileView(button.dataset.mobileView)));

	    elements.accountButton.addEventListener("click", (event) => {
	      event.stopPropagation();
		  if (!elements.accountMenu.hidden) { closeAccountMenu(); return; }
		  elements.accountMenu.hidden = false;
	      elements.accountButton.setAttribute("aria-expanded", "true");
		  const first = $("[role='menuitem']", elements.accountMenu);
		  if (first) first.tabIndex = 0;
		  requestAnimationFrame(() => first?.focus());
	    });
		elements.accountMenu.addEventListener("keydown", (event) => {
		  const items = $$('[role="menuitem"]', elements.accountMenu).filter((item) => !item.disabled);
		  const index = items.indexOf(document.activeElement);
		  const focusItem = (item) => {
			items.forEach((candidate) => { candidate.tabIndex = candidate === item ? 0 : -1; });
			item?.focus();
		  };
			  if (event.key === "Escape") {
				event.preventDefault();
				closeAccountMenu(true);
		  } else if (event.key === "ArrowDown" && items.length) {
			event.preventDefault();
			focusItem(items[(index + 1 + items.length) % items.length]);
		  } else if (event.key === "ArrowUp" && items.length) {
			event.preventDefault();
			focusItem(items[(index - 1 + items.length) % items.length]);
		  } else if (event.key === "Home" && items.length) {
			event.preventDefault(); focusItem(items[0]);
		  } else if (event.key === "End" && items.length) {
			event.preventDefault(); focusItem(items[items.length - 1]);
		  } else if (event.key === "Tab") {
			window.setTimeout(() => closeAccountMenu(), 0);
		  }
	});
	    document.addEventListener("click", (event) => {
	      if (!elements.accountMenu.contains(event.target) && event.target !== elements.accountButton) {
	        closeAccountMenu();
	      }
    });
    $("#logout-button").addEventListener("click", async () => {
      try { await api("/api/logout", { method: "POST", body: {} }); } catch (_) { /* clear local session regardless */ }
		  resetDirectoryState();
	      closeAccountMenu();
      localize(elements.accountName, "session.administrator");
      localize(elements.accountDN, "session.signedOut");
      elements.accountAvatar.textContent = "A";
      showLogin();
    });

	    elements.loginForm.addEventListener("submit", async (event) => {
	      event.preventDefault();
	      const submit = $("#login-submit");
	      submit.disabled = true;
	      setFieldError(elements.loginError, "");
		  let authenticated = false;
	      try {
	        const { data } = await api("/api/login", { method: "POST", body: { bind_dn: $("#login-dn").value.trim(), password: $("#login-password").value } });
	        state.csrf = csrfFrom(data);
	        setSession(unwrap(data, ["session"]));
	        closeDialog(elements.loginDialog);
	        $("#login-password").value = "";
			authenticated = true;
	      } catch (error) { setFieldError(elements.loginError, error.message, $("#login-password")); }
	      finally { submit.disabled = false; }
		  if (!authenticated) return;
		  try {
			await loadWorkspace();
		  } catch (error) {
			if (error.status === 401) showLogin(error.message);
			else {
			  setConnection("error", "session.serverUnavailable");
			  showState("error", "session.directoryUnavailable", error.message, { labelKey: "search.retry", handler: loadWorkspace });
			}
		  }
	    });
    $("#toggle-password").addEventListener("click", () => {
      const field = $("#login-password");
      const show = field.type === "password";
      field.type = show ? "text" : "password";
      localize($("#toggle-password"), show ? "login.hidePassword" : "login.showPassword", {}, "attr:aria-label");
      localize($("#toggle-password"), show ? "login.hidePassword" : "login.showPassword", {}, "attr:title");
    });

	    $("#new-entry-button").addEventListener("click", async () => {
		  if (!(await confirmEditorDiscard())) return;
	      elements.entryDialog.querySelector("form").reset();
	  state.createBaseDN = creationBaseDN();
	  state.entryDialogMode = "create";
	  localize($("#entry-dialog-title"), "create.title");
	  $("#new-entry-template").value = "person";
	  renderEntryTemplate("person");
      openDialog(elements.entryDialog);
	  renderAttributeSuggestions();
      requestAnimationFrame(() => $("#new-entry-dn").focus());
    });
	$("#new-entry-template").addEventListener("change", (event) => renderEntryTemplate(event.target.value));
	$("#new-entry-classes").addEventListener("input", renderAttributeSuggestions);
	$("#add-entry-attribute").addEventListener("click", () => addCreateAttributeRow());
	$("#new-entry-dn").addEventListener("input", renderAttributeSuggestions);
	$("#new-entry-dn").addEventListener("blur", syncCreateRDNAttribute);
    $("#entry-form").addEventListener("submit", async (event) => {
      event.preventDefault();
	  const submittedForm = event.currentTarget;
      const dn = $("#new-entry-dn").value.trim();
	  const attributes = collectAttributeRows($("#new-entry-attribute-list"));
	  attributes.objectClass = lines($("#new-entry-classes").value);
	  const validationError = validateCreateEntry(attributes);
	  if (validationError) { setFieldError($("#entry-form-error"), validationError); return; }
	  setFormSubmitting(submittedForm, true);
      try {
        await api("/api/entries", { method: "POST", body: { dn, attributes } });
        closeDialog(elements.entryDialog);
		state.entryDialogMode = "create";
        toast("entry.created", dn);
		        await refreshAfterMutation([dn]);
        await openEntry(dn);
	  } catch (error) { setFieldError($("#entry-form-error"), error.message, $("#new-entry-dn")); }
	  finally { setFormSubmitting(submittedForm, false); }
    });

    elements.entryEditor.addEventListener("submit", async (event) => {
      event.preventDefault();
	  const submittedForm = event.currentTarget;
	  const targetDN = state.selectedDN;
	  const targetEntry = state.selectedEntry;
	  if (!targetDN || !targetEntry) return;
	  setFormSubmitting(submittedForm, true);
      try {
		const changes = attributeChanges(targetEntry);
        if (!changes.length) {
          state.editorDirty = false;
          setEditorStatus(false);
          toast("entry.noChanges", state.selectedDN);
          return;
        }
		await api("/api/entries", { method: "PATCH", body: { dn: targetDN, changes } });
		toast("entry.updated", targetDN);
		if (state.selectedDN === targetDN) {
		  state.editorDirty = false;
		  setEditorStatus(false);
		}
		await refreshAfterMutation([targetDN]);
		if (state.selectedDN === targetDN) await openEntry(targetDN);
	  } catch (error) { toast("entry.updateFailed", error.message, "error"); }
	  finally { setFormSubmitting(submittedForm, false); }
    });
    $("#add-attribute").addEventListener("click", () => { addAttributeRow(); markDirty(); });
	$("#browse-attributes").addEventListener("click", () => {
	  $("#schema-attributes").click();
	  setMobileView("context");
	  requestAnimationFrame(() => elements.schemaSearch.focus());
	});
	    $("#discard-entry").addEventListener("click", async () => {
		  if (!state.selectedDN) return;
		  state.editorDirty = false;
		  setEditorStatus(false);
		  await openEntry(state.selectedDN);
		});

    $("#delete-button").addEventListener("click", async () => {
	  const targetDN = state.selectedDN;
	  if (!targetDN) return;
	  const approved = await confirmAction("entry.deleteTitle", translated("entry.deleteMessage", { dn: targetDN }), "entry.deleteConfirm");
      if (!approved) return;
	  const deleteButton = $("#delete-button");
	  deleteButton.disabled = true;
      try {
		await api("/api/entries", { method: "DELETE", body: { dn: targetDN } });
		state.selectedDNs.delete(targetDN);
		updateBulkSelection();
		state.entries = state.entries.filter((entry) => entry.dn !== targetDN);
		toast("entry.deleted", targetDN);
		if (state.selectedDN === targetDN) {
		  state.selectedDN = "";
		  state.selectedEntry = null;
		  state.editorDirty = false;
		  setEditorStatus(false);
		  updateEntryActions(false);
		  elements.detailButton.disabled = true;
		  showListView();
		}
		await refreshAfterMutation([targetDN]);
	  } catch (error) { toast("entry.deleteFailed", error.message, "error"); }
	  finally { deleteButton.disabled = false; }
    });

	    $("#rename-button").addEventListener("click", async () => {
	      if (!state.selectedDN) return;
		  if (!(await confirmEditorDiscard())) return;
      $("#rename-rdn").value = rdn(state.selectedDN);
      $("#rename-superior").value = parentDN(state.selectedDN);
      $("#rename-delete-old").checked = true;
      openDialog(elements.renameDialog);
    });
    $("#rename-form").addEventListener("submit", async (event) => {
      event.preventDefault();
	  const submittedForm = event.currentTarget;
      const oldDN = state.selectedDN;
      const newRDN = $("#rename-rdn").value.trim();
      const newSuperior = $("#rename-superior").value.trim();
	  setFormSubmitting(submittedForm, true);
      try {
        await api("/api/entries/rename", { method: "POST", body: { dn: oldDN, new_rdn: newRDN, new_superior: newSuperior, delete_old_rdn: $("#rename-delete-old").checked } });
		const effectiveSuperior = newSuperior || parentDN(oldDN);
		const newDN = effectiveSuperior ? `${newRDN},${effectiveSuperior}` : newRDN;
		if (state.selectedDNs.delete(oldDN)) state.selectedDNs.add(newDN);
		updateBulkSelection();
		const remainsSelected = state.selectedDN === oldDN;
		if (remainsSelected) state.selectedDN = newDN;
	      closeDialog(elements.renameDialog);
	      toast("entry.renamed", newDN);
		      await refreshAfterMutation([oldDN, newDN]);
		if (remainsSelected && state.selectedDN === newDN) await openEntry(newDN);
	  } catch (error) { setFieldError($("#rename-error"), error.message, $("#rename-rdn")); }
	  finally { setFormSubmitting(submittedForm, false); }
    });

    $("#password-button").addEventListener("click", () => {
      if (!state.selectedDN) return;
      $("#password-target").textContent = state.selectedDN;
      $("#password-form").reset();
      openDialog(elements.passwordDialog);
    });
    $("#password-form").addEventListener("submit", async (event) => {
      event.preventDefault();
	  const submittedForm = event.currentTarget;
	  const targetDN = state.selectedDN;
	  const password = $("#new-password").value;
	  if (password !== $("#confirm-password").value) { setFieldError($("#password-error"), translated("password.mismatch"), $("#confirm-password")); return; }
	  setFormSubmitting(submittedForm, true);
      try {
		await api("/api/password-modify", { method: "POST", body: { user_identity: targetDN, new_password: password } });
		$("#password-form").reset();
        closeDialog(elements.passwordDialog);
		toast("password.reset", targetDN);
	  } catch (error) { setFieldError($("#password-error"), error.message, $("#new-password")); }
	  finally { setFormSubmitting(submittedForm, false); }
    });
    $("#mobile-rename-button").addEventListener("click", () => $("#rename-button").click());
    $("#mobile-password-button").addEventListener("click", () => $("#password-button").click());
	$("#mobile-clone-button").addEventListener("click", () => $("#clone-button").click());
    $("#mobile-delete-button").addEventListener("click", () => $("#delete-button").click());
	$("#include-nested-members").addEventListener("change", () => {
	  if (state.selectedEntry) renderGroupMembers(state.selectedEntry, $("#include-nested-members").checked);
	});
	$("#group-member-form").addEventListener("submit", async (event) => {
	  event.preventDefault();
	  const value = $("#group-member-value").value.trim();
	  if (!value) return;
	  await updateGroupMembers([value], []);
	  $("#group-member-value").value = "";
	});
	$("#remove-group-members").addEventListener("click", () => {
	  const values = $$("input:checked", elements.groupMemberList).map((input) => input.value);
	  if (values.length) updateGroupMembers([], values);
	});
	$("#bulk-modify-form").addEventListener("submit", async (event) => {
	  event.preventDefault();
	  const submittedForm = event.currentTarget;
	  const changes = [{ operation: $("#bulk-operation").value, attribute: $("#bulk-attribute").value.trim(), values: lines($("#bulk-values").value) }];
	  setFormSubmitting(submittedForm, true);
		  try {
			const result = await runBulk("modify", changes, $("#bulk-continue").checked);
			if (result && !result.failed && !result.unknown && !result.aborted) closeDialog(elements.bulkModifyDialog);
			else if (result) setFieldError($("#bulk-modify-error"), batchResultDetails(result));
	  } catch (error) { setFieldError($("#bulk-modify-error"), error.message); }
	  finally { setFormSubmitting(submittedForm, false); }
	});

		[$("#import-button"), $("#menu-import")].forEach((button) => button.addEventListener("click", () => {
		  closeAccountMenu();
		  openDialog(elements.importDialog);
		  if (state.ldifRetryFingerprints.size) setFieldError($("#import-error"), translated("import.partialNoRetry"), $("#import-content"));
		}));
		$("#menu-import-csv").addEventListener("click", () => {
		  closeAccountMenu();
		  if (!$("#csv-import-base").value.trim()) $("#csv-import-base").value = state.baseDN || state.rootDN;
		  openDialog(elements.csvImportDialog);
		  if (state.csvRetryFingerprints.size) setFieldError($("#csv-import-error"), translated("csv.partialNoRetry"), $("#csv-import-content"));
		});
	    [$("#export-button"), $("#menu-export")].forEach((button) => button.addEventListener("click", () => { closeAccountMenu(); exportLDIF(); }));
		$("#menu-export-csv").addEventListener("click", () => { closeAccountMenu(); exportData("csv"); });
		$("#menu-export-json").addEventListener("click", () => { closeAccountMenu(); exportData("json"); });
	  $("#csv-import-file").addEventListener("change", async (event) => {
		const file = event.target.files[0];
		if (!file) return;
		  const sequence = ++state.csvFileSequence;
		  state.csvFileLoading = true;
		  $("#csv-import-content").value = "";
		clearLocalization($("#csv-import-file-name"));
		$("#csv-import-file-name").textContent = file.name;
		try {
		  assertFileSize(file);
		  const content = await file.text();
			if (sequence !== state.csvFileSequence) return;
			$("#csv-import-content").value = content;
			state.csvFileLoading = false;
			if (state.csvRetryFingerprints.size) setFieldError($("#csv-import-error"), translated("csv.partialNoRetry"), $("#csv-import-content"));
		  }
		  catch (error) {
			if (sequence === state.csvFileSequence) {
			  state.csvFileLoading = false;
			  setFieldError($("#csv-import-error"), error.message);
			}
		  }
		});
	$("#csv-import-content").addEventListener("input", () => {
	  state.csvFileSequence++;
	  state.csvFileLoading = false;
	  if (state.csvRetryFingerprints.size) setFieldError($("#csv-import-error"), translated("csv.partialNoRetry"), $("#csv-import-content"));
	});
	$("#csv-import-form").addEventListener("input", (event) => {
	  if (event.target.id !== "csv-import-content" && state.csvRetryFingerprints.size) {
		setFieldError($("#csv-import-error"), translated("csv.partialNoRetry"), event.target);
	  }
	});
		$("#csv-import-form").addEventListener("submit", async (event) => {
		  event.preventDefault();
		  const submittedForm = event.currentTarget;
		  if (state.csvFileLoading) { setFieldError($("#csv-import-error"), translated("file.reading"), $("#csv-import-file")); return; }
		  let body;
		  let fingerprint;
		  try {
			body = {
			csv: $("#csv-import-content").value,
			base_dn: $("#csv-import-base").value.trim(),
			rdn_attribute: $("#csv-import-rdn").value.trim(),
			object_classes: lines($("#csv-import-classes").value),
			mapping: parseCSVMapping($("#csv-import-mapping").value),
			continue_on_error: $("#csv-import-continue").checked
			};
			assertRequestSize(body);
			fingerprint = await batchFingerprint("csv", body);
		  } catch (error) {
			setFieldError($("#csv-import-error"), error.message);
			return;
		  }
		  if (!(await approveChangedBatch("csv", fingerprint, $("#csv-import-error"), $("#csv-import-content")))) return;
		  const generation = state.sessionGeneration;
		  setFormSubmitting(submittedForm, true);
		  setFieldError($("#csv-import-error"), "");
		  try {
		  const { data } = await api("/api/csv-import", { method: "POST", body });
		if (generation !== state.sessionGeneration) return;
		if (!hasStructuredBatchResult(data)) throw new APIError(t("api.unavailable"), 0, null);
		const applied = Number(data && data.applied || 0);
		const failed = Number(data && data.failed || 0);
		const unknown = Number(data && data.unknown || 0);
		const summary = data && data.aborted ? translated("bulk.aborted", { reason: localizedAbortReason(data) }) : translated("bulk.summary", { applied, failed, unknown });
		const hasIssues = failed || unknown || data && data.aborted;
		toast(hasIssues ? "csv.partial" : "csv.complete", summary, hasIssues ? "error" : "success");
		if (hasIssues) {
		  const results = data.results || [];
		  const failures = results.filter((result) => result.status === "failed" || result.status === "unknown").slice(0, 5);
		  const notAttempted = results.filter((result) => result.status === "not_attempted").length;
		  const errorElement = $("#csv-import-error");
		  renderDynamic(errorElement, () => [
			applied > 0 || unknown > 0 ? t("csv.partialNoRetry") : "",
			...failures.map((result) => t("csv.rowFailure", { row: result.row, message: errorMessage({ error: result.error }, result.status) })),
			notAttempted ? t("csv.notAttempted", { count: notAttempted }) : ""
		  ].filter(Boolean).join("\n"));
		  errorElement.hidden = false;
		  if (applied > 0 || unknown > 0) state.csvRetryFingerprints.add(fingerprint);
		} else {
		  state.csvRetryFingerprints.clear();
		  closeDialog(elements.csvImportDialog);
		  $("#csv-import-form").reset();
		  localize($("#csv-import-file-name"), "csv.choose");
		}
		if (applied > 0 || unknown > 0) await refreshAfterMutation(resultDNs(data), [body.base_dn]);
	  } catch (error) {
		if (generation !== state.sessionGeneration || error && error.status === 401 || error instanceof SupersededRequestError) return;
		const data = error && error.details && typeof error.details === "object" ? error.details : null;
		const unsafe = unsafeBatchOutcome(data, error);
		if (unsafe) state.csvRetryFingerprints.add(fingerprint);
		setFieldError($("#csv-import-error"), [error.message, unsafe ? t("csv.partialNoRetry") : "", csvResultDetails(data)].filter(Boolean).join("\n"), $("#csv-import-content"));
		if (unsafe) await refreshAfterMutation(resultDNs(data), [body.base_dn]);
	  }
	  finally { setFormSubmitting(submittedForm, false); }
	});
		    $("#import-file").addEventListener("change", async (event) => {
		      const file = event.target.files[0];
	      if (!file) return;
		  const sequence = ++state.ldifFileSequence;
		  state.ldifFileLoading = true;
		  $("#import-content").value = "";
	      clearLocalization($("#import-file-name"));
	      $("#import-file-name").textContent = file.name;
		      try {
			assertFileSize(file);
			const content = await file.text();
			if (sequence !== state.ldifFileSequence) return;
			$("#import-content").value = content;
			state.ldifFileLoading = false;
			if (state.ldifRetryFingerprints.size) setFieldError($("#import-error"), translated("import.partialNoRetry"), $("#import-content"));
		  } catch (error) {
			if (sequence === state.ldifFileSequence) {
			  state.ldifFileLoading = false;
			  setFieldError($("#import-error"), error.message);
			}
		  }
	    });
	$("#import-content").addEventListener("input", () => {
	  state.ldifFileSequence++;
	  state.ldifFileLoading = false;
	  if (state.ldifRetryFingerprints.size) setFieldError($("#import-error"), translated("import.partialNoRetry"), $("#import-content"));
	});
	    $("#import-form").addEventListener("submit", async (event) => {
	      event.preventDefault();
		  const submittedForm = event.currentTarget;
		  if (state.ldifFileLoading) { setFieldError($("#import-error"), translated("file.reading"), $("#import-file")); return; }
	      const content = $("#import-content").value;
	      if (!content.trim()) { setFieldError($("#import-error"), translated("import.required")); return; }
		  let fingerprint;
		  try {
			assertRequestSize(content);
			fingerprint = await batchFingerprint("ldif", content);
		  } catch (error) {
			setFieldError($("#import-error"), error.message, $("#import-content"));
			return;
		  }
		  const reviewingChangedBatch = state.ldifRetryFingerprints.size > 0;
		  if (!(await approveChangedBatch("ldif", fingerprint, $("#import-error"), $("#import-content")))) return;
		  if (!reviewingChangedBatch && !(await confirmAction("import.confirmTitle", translated("import.confirmMessage"), "import.confirm"))) return;
		  const generation = state.sessionGeneration;
		  setFormSubmitting(submittedForm, true);
	      try {
		        const { data } = await api("/api/import", { method: "POST", body: content, rawBody: true, headers: { "Content-Type": "application/ldif; charset=utf-8" } });
			if (generation !== state.sessionGeneration) return;
			if (!hasStructuredBatchResult(data)) throw new APIError(t("api.unavailable"), 0, null);
			const applied = Number(data && data.applied || 0);
			const failed = Number(data && data.failed || 0);
			const unknown = Number(data && data.unknown || 0);
			const hasIssues = failed > 0 || unknown > 0 || Boolean(data && data.aborted);
			if (hasIssues) {
			  if (applied > 0 || unknown > 0) state.ldifRetryFingerprints.add(fingerprint);
			  setFieldError($("#import-error"), [
				applied > 0 || unknown > 0 ? t("import.partialNoRetry") : "",
				ldifResultDetails(data)
			  ].filter(Boolean).join("\n"), $("#import-content"));
			} else {
			  state.ldifRetryFingerprints.clear();
			  closeDialog(elements.importDialog);
			  $("#import-form").reset();
			  localize($("#import-file-name"), "import.choose");
			}
			toast(hasIssues ? "import.partial" : "import.complete", t("bulk.summary", { applied, failed, unknown }), hasIssues ? "error" : "success");
			if (applied > 0 || unknown > 0) await refreshAfterMutation(resultDNs(data));
		  } catch (error) {
			if (generation !== state.sessionGeneration || error && error.status === 401 || error instanceof SupersededRequestError) return;
			const data = error && error.details && typeof error.details === "object" ? error.details : null;
			const applied = Number(data && data.applied || 0);
			const unsafe = unsafeBatchOutcome(data, error);
			if (unsafe) state.ldifRetryFingerprints.add(fingerprint);
			setFieldError($("#import-error"), [
			  error.message,
			  unsafe ? t("import.partialNoRetry") : "",
			  ldifResultDetails(data)
			].filter(Boolean).join("\n"), $("#import-content"));
			if (unsafe || applied > 0) await refreshAfterMutation(resultDNs(data));
		  }
	  finally { setFormSubmitting(submittedForm, false); }
    });

    $("#confirm-form").addEventListener("submit", (event) => { event.preventDefault(); resolveConfirm(true); });
    $("#confirm-cancel").addEventListener("click", () => resolveConfirm(false));
    elements.confirmDialog.addEventListener("cancel", (event) => { event.preventDefault(); resolveConfirm(false); });
    elements.loginDialog.addEventListener("cancel", (event) => event.preventDefault());
    $$(".close-dialog").forEach((button) => button.addEventListener("click", () => closeDialog(button.closest("dialog"))));
    window.addEventListener("beforeunload", (event) => { if (state.editorDirty) { event.preventDefault(); event.returnValue = ""; } });
  }

  function lines(value) { return String(value || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean); }
  async function copyText(value, successKey) {
    try { await navigator.clipboard.writeText(value || ""); toast(successKey); }
    catch (_) { toast("actions.copyFailed", translated("actions.clipboardDenied"), "error"); }
  }

  initialize().catch((error) => {
	elements.shell.setAttribute("aria-busy", "false");
	setConnection("error", "session.serverUnavailable");
	showState("error", "session.directoryUnavailable", error && error.message || t("session.serverUnreachable"), {
	  labelKey: "search.retry", handler: () => window.location.reload()
	});
  });
})();
