/** InsightScan Web 前端逻辑 */

let uiConfig = {};
let pollTimer = null;
let statusTimer = null;
let attackTypes = [];
/** 攻击/联调共用的四个目标下拉框状态（避免单独攻击仍用 IP 配置页本机 IP） */
let attackTargetPrefs = null;

const TARGET_SELECT_IDS = [
  "attack-target-select",
  "attack-solo-target-select",
  "defense-target-select",
  "defense-solo-target-select",
];

/** 攻击页 + 防御页联调共用的目标下拉框 */
const ATTACK_TARGET_BINDINGS = [
  ["attack-target-select", "attack-target-custom-row", "attack-target-custom"],
  ["attack-solo-target-select", "attack-solo-custom-row", "attack-solo-target-custom"],
  ["defense-target-select", "defense-target-custom-row", "defense-target-custom"],
  ["defense-solo-target-select", "defense-solo-custom-row", "defense-solo-target-custom"],
];

// ---------- 导航 ----------
document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    switchPage(btn.dataset.page);
  });
});

function switchPage(page) {
  document.querySelectorAll(".nav-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.page === page);
  });
  document.querySelectorAll(".page").forEach((p) => p.classList.remove("active"));
  document.getElementById(`page-${page}`).classList.add("active");
  if (page !== "config") {
    applyAllTargetSelectors();
  }
  if (page === "defense") {
    refreshRuntimeStatus();
  }
  if (page === "nmap-lab") {
    loadNmapComparison();
    loadReportList("nmap_lab");
  }
}

async function api(url, options = {}) {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  return res.json();
}

// ---------- 目标选择（动态） ----------
function buildTargetOptionsHtml() {
  const lip = uiConfig.local_ip || "（未配置，请去 IP 配置页检测）";
  const cidr = uiConfig.cidr || "（未配置 C 段）";
  return `
    <option value="127.0.0.1">127.0.0.1（本机回环）</option>
    <option value="local_ip">${lip}（本机局域网）</option>
    <option value="cidr">${cidr}（C 段）</option>
    <option value="custom">自定义 IP / CIDR</option>
  `;
}

function refreshAllTargetSelectOptions() {
  TARGET_SELECT_IDS.forEach((id) => {
    const sel = document.getElementById(id);
    if (!sel) return;
    const prevMode = sel.value;
    const customId = id.replace("-select", "-custom");
    const prevCustom = document.getElementById(customId)?.value || "";
    sel.innerHTML = buildTargetOptionsHtml();
    if ([...sel.options].some((o) => o.value === prevMode)) {
      sel.value = prevMode;
    }
    const customEl = document.getElementById(customId);
    if (customEl && prevCustom) customEl.value = prevCustom;
  });
}

function resolveTargetFromMode(mode, custom) {
  if (mode === "127.0.0.1") return "127.0.0.1";
  if (mode === "local_ip") return uiConfig.local_ip || uiConfig.attack_target || "127.0.0.1";
  if (mode === "cidr") return uiConfig.cidr || uiConfig.perf_target || uiConfig.attack_target || "127.0.0.1";
  return (custom || uiConfig.attack_target || "127.0.0.1").trim() || "127.0.0.1";
}

function readTargetSelector(selectId, customInputId) {
  const sel = document.getElementById(selectId);
  if (!sel) return null;
  const mode = sel.value;
  const custom = document.getElementById(customInputId)?.value.trim() || "";
  return {
    mode,
    custom,
    resolved: resolveTargetFrom(selectId, customInputId),
  };
}

function writeTargetSelector(selectId, rowId, inputId, prefs) {
  const sel = document.getElementById(selectId);
  if (!sel || !prefs) return;
  if ([...sel.options].some((o) => o.value === prefs.mode)) {
    sel.value = prefs.mode;
  } else {
    sel.value = "custom";
  }
  const row = document.getElementById(rowId);
  if (row) row.style.display = sel.value === "custom" ? "block" : "none";
  const input = document.getElementById(inputId);
  if (input && sel.value === "custom") {
    input.value = prefs.custom || "";
  }
}

function attackPrefsFromConfig(cfg) {
  const { mode, custom } = inferTargetMode(cfg);
  return {
    mode,
    custom,
    resolved: resolveTargetFromMode(mode, custom),
  };
}

function applyAttackTargetPrefs(prefs) {
  if (!prefs) return;
  attackTargetPrefs = prefs;
  ATTACK_TARGET_BINDINGS.forEach(([selId, rowId, inputId]) => {
    writeTargetSelector(selId, rowId, inputId, prefs);
  });
}

function captureAttackTargetFrom(selectId, customInputId) {
  const prefs = readTargetSelector(selectId, customInputId);
  if (prefs) applyAttackTargetPrefs(prefs);
  return attackTargetPrefs;
}

/** @deprecated */
function applyDrillTargetPrefs(prefs) {
  applyAttackTargetPrefs(prefs);
}

function captureDrillTargetFrom(selectId, customInputId) {
  return captureAttackTargetFrom(selectId, customInputId);
}

function drillPrefsFromConfig(cfg) {
  return attackPrefsFromConfig(cfg);
}

function inferTargetMode(cfg) {
  if (cfg.target_mode && cfg.target_mode !== "default") {
    return { mode: cfg.target_mode, custom: cfg.target_custom || "" };
  }
  const t = (cfg.attack_target || "").trim();
  if (!t || t === "127.0.0.1") return { mode: "127.0.0.1", custom: "" };
  if (cfg.local_ip && t === cfg.local_ip) return { mode: "local_ip", custom: "" };
  if (cfg.cidr && t === cfg.cidr) return { mode: "cidr", custom: "" };
  if (cfg.defense_attack_target && t === cfg.defense_attack_target && cfg.local_ip && t === cfg.local_ip) {
    return { mode: "local_ip", custom: "" };
  }
  return { mode: "custom", custom: t };
}

function applyTargetSelector(selectId, customRowId, customInputId, cfg) {
  const { mode, custom } = inferTargetMode(cfg);
  const sel = document.getElementById(selectId);
  const row = document.getElementById(customRowId);
  const input = document.getElementById(customInputId);
  if (!sel) return;
  if ([...sel.options].some((o) => o.value === mode)) {
    sel.value = mode;
  } else {
    sel.value = "custom";
  }
  const showCustom = sel.value === "custom";
  if (row) row.style.display = showCustom ? "block" : "none";
  if (input && showCustom) input.value = custom || cfg.attack_target || "";
}

function applyAllTargetSelectors() {
  const keep = attackTargetPrefs;
  refreshAllTargetSelectOptions();
  if (keep) {
    applyAttackTargetPrefs(keep);
  } else {
    applyAttackTargetPrefs(attackPrefsFromConfig(uiConfig));
  }
}

/** 联调/防御监听 IP：与当前页面选中的攻击/联调目标一致（IP 配置页仅提供下拉选项） */
function resolveDefenseHostForDrill(attackTarget) {
  const t = (attackTarget || "").trim();
  return t || "127.0.0.1";
}

function resolveTargetFrom(selectId, customInputId) {
  const sel = document.getElementById(selectId).value;
  if (sel === "127.0.0.1") return "127.0.0.1";
  if (sel === "local_ip") return uiConfig.local_ip || uiConfig.attack_target || "127.0.0.1";
  if (sel === "cidr") return uiConfig.cidr || uiConfig.perf_target || uiConfig.attack_target || "127.0.0.1";
  const custom = document.getElementById(customInputId)?.value.trim();
  return custom || uiConfig.attack_target || "127.0.0.1";
}

function targetPayload(selectId, customInputId) {
  const sel = document.getElementById(selectId);
  return {
    target: resolveTargetFrom(selectId, customInputId),
    target_mode: sel.value,
    target_custom: document.getElementById(customInputId)?.value.trim() || "",
  };
}

function bindTargetSelectChange(selectId, rowId) {
  const sel = document.getElementById(selectId);
  if (!sel) return;
  sel.addEventListener("change", () => {
    const row = document.getElementById(rowId);
    if (row) row.style.display = sel.value === "custom" ? "block" : "none";
  });
}

const TARGET_BINDINGS = [
  ["attack-solo-target-select", "attack-solo-custom-row"],
];

TARGET_BINDINGS.forEach(([selectId, rowId]) => {
  bindTargetSelectChange(selectId, rowId);
});

ATTACK_TARGET_BINDINGS.forEach(([selectId, rowId, inputId]) => {
  bindTargetSelectChange(selectId, rowId);
  const sel = document.getElementById(selectId);
  if (!sel) return;
  sel.addEventListener("change", () => {
    captureAttackTargetFrom(selectId, inputId);
  });
  document.getElementById(inputId)?.addEventListener("input", () => {
    if (sel.value === "custom") captureAttackTargetFrom(selectId, inputId);
  });
});

async function refreshRuntimeStatus() {
  const data = await api("/api/status");
  if (!data.success) return;
  const alert = document.getElementById("defense-pair-alert");
  if (data.running_attack) {
    alert.style.display = "block";
  } else {
    alert.style.display = "none";
  }
}

// ---------- 配置 ----------
async function loadConfig() {
  const [cfgData, typesData] = await Promise.all([
    api("/api/config"),
    api("/api/attack-types"),
  ]);
  if (typesData.types) {
    attackTypes = typesData.types;
    const hint = document.getElementById("attack-types-hint");
    if (hint) {
      hint.textContent = `项目攻击类型：${attackTypes.map((t) => t.label).join(" · ")}`;
    }
  }
  if (cfgData.success) {
    uiConfig = cfgData.config;
    attackTargetPrefs = attackPrefsFromConfig(uiConfig);
    fillConfigForm(uiConfig);
    applyAllTargetSelectors();
    syncNmapFromConfig(uiConfig, { silent: true });
    refreshRuntimeStatus();
  }
}

function fillConfigForm(cfg) {
  document.getElementById("cfg-local-ip").value = cfg.local_ip || "";
  document.getElementById("cfg-cidr").value = cfg.cidr || "";
  document.getElementById("cfg-gateway").value = cfg.gateway || "";
  document.getElementById("cfg-interface").value = cfg.interface || "";
  document.getElementById("cfg-attack-target").value = cfg.attack_target || "127.0.0.1";
  document.getElementById("cfg-defense-attack-target").value =
    cfg.defense_attack_target || cfg.local_ip || cfg.attack_target || "";
  document.getElementById("cfg-attack-ports").value = cfg.attack_ports || "22,80,443";
  document.getElementById("cfg-perf-target").value = cfg.perf_target || cfg.cidr || "";
  document.getElementById("cfg-perf-ports").value = cfg.perf_ports || "22,80,443";
  document.getElementById("defense-duration").value = cfg.defense_duration ?? 60;
  document.getElementById("defense-iptables").checked = !!cfg.defense_apply_iptables;
  document.getElementById("attack-ports").value = cfg.attack_ports || "22,80,443";
}

document.getElementById("btn-save-config").addEventListener("click", async () => {
  const localIp = document.getElementById("cfg-local-ip").value.trim();
  const attackTarget = document.getElementById("cfg-attack-target").value.trim() || "127.0.0.1";
  const inferred = inferTargetMode({
    ...uiConfig,
    local_ip: localIp,
    attack_target: attackTarget,
    cidr: document.getElementById("cfg-cidr").value.trim(),
  });
  const payload = {
    local_ip: localIp,
    cidr: document.getElementById("cfg-cidr").value.trim(),
    gateway: document.getElementById("cfg-gateway").value.trim(),
    interface: document.getElementById("cfg-interface").value.trim(),
    attack_target: attackTarget,
    defense_attack_target:
      document.getElementById("cfg-defense-attack-target").value.trim() || localIp || attackTarget,
    target_mode: inferred.mode,
    target_custom: inferred.mode === "custom" ? attackTarget : "",
    attack_ports: document.getElementById("cfg-attack-ports").value.trim(),
    perf_target: document.getElementById("cfg-perf-target").value.trim(),
    perf_ports: document.getElementById("cfg-perf-ports").value.trim(),
    defense_duration: parseInt(document.getElementById("defense-duration").value, 10) || 60,
    defense_apply_iptables: document.getElementById("defense-iptables").checked,
  };
  const data = await api("/api/config", { method: "POST", body: JSON.stringify(payload) });
  const msg = document.getElementById("config-msg");
  if (data.success) {
    uiConfig = data.config;
    attackTargetPrefs = attackPrefsFromConfig(uiConfig);
    applyAllTargetSelectors();
    syncNmapFromConfig(uiConfig);
    msg.textContent = "配置已保存，攻击/防御与 Nmap 教学页目标已同步";
    msg.className = "hint status-ok";
  } else {
    msg.textContent = data.error || "保存失败";
    msg.className = "hint status-err";
  }
});

function resolveNmapTarget(cfg) {
  const t = (
    cfg.attack_target ||
    cfg.defense_attack_target ||
    cfg.local_ip ||
    "127.0.0.1"
  ).trim();
  return t || "127.0.0.1";
}

function resolveNmapPorts(cfg) {
  return (cfg.attack_ports || "22,80,443").trim() || "22,80,443";
}

/** 读取 IP 配置页表单（含未保存的编辑）用于 Nmap 同步 */
function readConfigFormSnapshot() {
  const localIp = document.getElementById("cfg-local-ip")?.value.trim();
  const attackTarget = document.getElementById("cfg-attack-target")?.value.trim();
  const defenseTarget = document.getElementById("cfg-defense-attack-target")?.value.trim();
  const attackPorts = document.getElementById("cfg-attack-ports")?.value.trim();
  return {
    ...uiConfig,
    local_ip: localIp || uiConfig.local_ip,
    attack_target: attackTarget || uiConfig.attack_target,
    defense_attack_target: defenseTarget || uiConfig.defense_attack_target,
    attack_ports: attackPorts || uiConfig.attack_ports,
  };
}

function syncNmapFromConfig(cfg, opts = {}) {
  const targetEl = document.getElementById("nmap-target");
  const portsEl = document.getElementById("nmap-ports");
  const hintEl = document.getElementById("nmap-sync-hint");
  if (!targetEl || !portsEl) return;
  const c = cfg || uiConfig;
  const target = resolveNmapTarget(c);
  const ports = resolveNmapPorts(c);
  targetEl.value = target;
  portsEl.value = ports;
  if (hintEl) {
    if (opts.silent) {
      hintEl.textContent = `当前：目标 ${target} · 端口 ${ports}（来自 IP 配置）`;
      hintEl.className = "hint";
    } else {
      hintEl.textContent = `已同步：目标 ${target} · 端口 ${ports}`;
      hintEl.className = "hint status-ok";
    }
  }
}

async function detectNetwork(apply) {
  const data = await api("/api/network/detect", {
    method: "POST",
    body: JSON.stringify({ apply }),
  });
  const msg = document.getElementById("config-msg");
  if (data.detected) {
    if (!apply) {
      document.getElementById("cfg-local-ip").value = data.detected.local_ip || "";
      document.getElementById("cfg-cidr").value = data.detected.cidr || "";
      document.getElementById("cfg-gateway").value = data.detected.gateway || "";
      document.getElementById("cfg-interface").value = data.detected.interface || "";
      document.getElementById("cfg-perf-target").value = data.detected.cidr || "";
      if (data.detected.local_ip) {
        document.getElementById("cfg-defense-attack-target").value = data.detected.local_ip;
      }
    }
    if (data.config) {
      uiConfig = data.config;
      attackTargetPrefs = attackPrefsFromConfig(uiConfig);
      fillConfigForm(uiConfig);
      applyAllTargetSelectors();
      syncNmapFromConfig(uiConfig);
    } else {
      syncNmapFromConfig(readConfigFormSnapshot());
    }
    msg.textContent = apply
      ? "已检测并应用，攻击/防御与 Nmap 教学页目标已同步"
      : "检测完成，Nmap 教学页已预览同步，请确认后保存";
    msg.className = "hint status-ok";
  } else {
    msg.textContent = data.error || "检测失败";
    msg.className = "hint status-err";
  }
}

document.getElementById("btn-detect").addEventListener("click", () => detectNetwork(false));
document.getElementById("btn-detect-apply").addEventListener("click", () => detectNetwork(true));

function drillPayload(selectId, customInputId, extra = {}) {
  const prefs = captureAttackTargetFrom(selectId, customInputId);
  const attackTarget = prefs?.resolved || resolveTargetFrom(selectId, customInputId);
  return {
    target: attackTarget,
    target_mode: prefs?.mode || document.getElementById(selectId)?.value,
    target_custom: prefs?.custom || document.getElementById(customInputId)?.value.trim() || "",
    defense_host: resolveDefenseHostForDrill(attackTarget),
    ports: document.getElementById("attack-ports").value.trim() || uiConfig.attack_ports,
    duration: parseInt(document.getElementById("defense-duration").value, 10) || 60,
    apply_iptables: document.getElementById("defense-iptables").checked,
    ...extra,
  };
}

// ---------- 任务轮询 ----------
function stopPoll() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

function pollJob(jobId, cardId, textId, resultId, progressId, onDone) {
  stopPoll();
  document.getElementById(cardId).style.display = "block";
  document.getElementById(progressId).style.width = "30%";
  document.getElementById(textId).textContent = "启动中...";
  document.getElementById(textId).className = "";

  pollTimer = setInterval(async () => {
    const job = await api(`/api/job/${jobId}`);
    document.getElementById(textId).textContent = job.progress || job.status;
    if (job.status === "running") {
      document.getElementById(progressId).style.width = "60%";
      refreshRuntimeStatus();
    }
    if (job.status === "done") {
      stopPoll();
      document.getElementById(progressId).style.width = "100%";
      document.getElementById(textId).textContent = "完成";
      document.getElementById(textId).className = "status-ok";
      onDone(job);
      refreshRuntimeStatus();
    }
    if (job.status === "error") {
      stopPoll();
      document.getElementById(progressId).style.width = "100%";
      document.getElementById(textId).textContent = "失败: " + (job.error || "未知错误");
      document.getElementById(textId).className = "status-err";
      document.getElementById(resultId).innerHTML = `<p class="status-err">${job.error || "未知错误"}</p>`;
      refreshRuntimeStatus();
    }
  }, 2000);
}

function reportLink(dir, file) {
  const name = dir.split("/").pop() || dir.split("\\").pop() || "";
  return `/reports/${name}/${file}`;
}

/** 从 Nmap 实验结果解析 Web 可访问的报告目录（含 nmap_lab/ 前缀） */
function nmapLabReportBase(r) {
  if (r.report_web_path) return r.report_web_path;
  const dir = (r.session_dir || "").replace(/\\/g, "/");
  const idx = dir.indexOf("nmap_lab/");
  if (idx >= 0) return dir.slice(idx);
  const folder = dir.split("/").filter(Boolean).pop() || "";
  return folder ? `nmap_lab/${folder}` : "";
}

function renderSuiteSummary(r) {
  if (!r.attack_suite?.length) return "";
  let html = "<p><strong>攻击套件:</strong></p><ul>";
  r.attack_suite.forEach((a) => {
    html += `<li>${a.label || a.scan_type}: ${a.success ? "成功" : "失败"}</li>`;
  });
  html += "</ul>";
  if (r.scan_types_used) {
    html += `<p>使用类型: ${r.scan_types_used.join(", ")}</p>`;
  }
  return html;
}

function renderAttackResult(job) {
  const r = job.result || {};
  const dir = r.session_dir || "";
  let html = `<p><strong>攻击目标:</strong> ${r.target || "—"}</p>`;
  if (r.ports) html += `<p><strong>端口:</strong> ${r.ports}</p>`;
  html += renderSuiteSummary(r);
  html += `<p><strong>报告目录:</strong> ${dir}</p>`;
  if (r.reports?.html) {
    html += `<p><a href="${reportLink(dir, "attack_report.html")}" target="_blank">打开 HTML 报告</a></p>`;
  }
  if (r.scan) {
    html += `<p>主机: ${r.scan.hosts} | 端口: ${r.scan.ports} | 总耗时: ${r.scan.duration}s</p>`;
  }
  if (r.perf_benchmark?.benchmark) {
    html += "<p><strong>性能结果:</strong></p><ul>";
    r.perf_benchmark.benchmark.forEach((b) => {
      html += `<li>${b.threads} 线程 → ${b.duration_sec}s</li>`;
    });
    html += "</ul>";
  }
  document.getElementById("attack-result").innerHTML = html;
  loadReportList("attack");
}

function renderDefenseResult(job) {
  const r = job.result || {};
  const dir = r.session_dir || "";
  let html = `<p><strong>防御主机:</strong> ${r.defense_host || "—"}</p>`;
  html += `<p><strong>报告目录:</strong> ${dir}</p>`;
  html += `<p><a href="${reportLink(dir, "defense_report.md")}" target="_blank">查看防御报告</a></p>`;
  if (r.scan_detection) {
    const se = r.scan_detection.scan_events ?? 0;
    const ds = r.scan_detection.detection_sources || {};
    html += `<p>检测事件: ${r.scan_detection.total_events} | 明确扫描: ${se}</p>`;
    html += `<p>来源: syslog ${ds.syslog_events ?? 0} | 数据库 ${ds.database_events ?? 0}</p>`;
  }
  document.getElementById("defense-result").innerHTML = html;
  loadReportList("defense");
}

function renderDrillResult(job, resultId) {
  const r = job.result || {};
  let html = `
    <div class="drill-summary">
      <p><strong>攻击目标:</strong> ${r.attack_target || "—"}</p>
      <p><strong>防御主机:</strong> ${r.defense_host || "—"}</p>
      <p><strong>端口:</strong> ${r.ports || "—"}</p>
    </div>`;
  if (r.attack) {
    html += renderSuiteSummary(r.attack);
    if (r.attack.session_dir) {
      html += `<p><strong>攻击报告:</strong> <a href="${reportLink(r.attack.session_dir, "attack_report.html")}" target="_blank">打开</a></p>`;
    }
  }
  if (r.defense?.session_dir) {
    html += `<p><strong>防御报告:</strong> <a href="${reportLink(r.defense.session_dir, "defense_report.md")}" target="_blank">打开</a></p>`;
  }
  document.getElementById(resultId).innerHTML = html;
  loadReportList("attack");
  loadReportList("defense");
}

function startDrillPoll(jobId, cardPrefix) {
  document.getElementById("attack-status-card").style.display = "none";
  document.getElementById("defense-status-card").style.display = "none";
  if (cardPrefix === "defense-drill") {
    document.getElementById("drill-status-card").style.display = "none";
  } else {
    document.getElementById("defense-drill-status-card").style.display = "none";
  }
  pollJob(
    jobId,
    `${cardPrefix}-status-card`,
    `${cardPrefix}-status-text`,
    `${cardPrefix}-result`,
    `${cardPrefix}-progress`,
    (job) => renderDrillResult(job, `${cardPrefix}-result`)
  );
}

async function runDrill(fromDefensePage) {
  const btn = fromDefensePage
    ? document.getElementById("btn-drill-defense")
    : document.getElementById("btn-drill-attack");
  const selectId = fromDefensePage ? "defense-target-select" : "attack-target-select";
  const customId = fromDefensePage ? "defense-target-custom" : "attack-target-custom";
  captureAttackTargetFrom(selectId, customId);
  btn.disabled = true;
  const data = await api("/api/drill", {
    method: "POST",
    body: JSON.stringify(drillPayload(selectId, customId)),
  });
  btn.disabled = false;
  if (data.job_id) {
    applyAttackTargetPrefs(attackTargetPrefs);
    if (fromDefensePage) {
      startDrillPoll(data.job_id, "defense-drill");
    } else {
      startDrillPoll(data.job_id, "drill");
      switchPage("defense");
    }
  }
}

document.getElementById("btn-drill-attack").addEventListener("click", () => runDrill(false));
document.getElementById("btn-drill-defense").addEventListener("click", () => runDrill(true));

document.getElementById("btn-attack").addEventListener("click", async () => {
  const btn = document.getElementById("btn-attack");
  btn.disabled = true;
  captureAttackTargetFrom("attack-solo-target-select", "attack-solo-target-custom");
  const tp = targetPayload("attack-solo-target-select", "attack-solo-target-custom");
  const payload = {
    ...tp,
    ports: document.getElementById("attack-ports").value.trim(),
    perf: false,
    full_suite: true,
    with_defense: document.getElementById("attack-with-defense").checked,
  };
  const data = await api("/api/attack", { method: "POST", body: JSON.stringify(payload) });
  btn.disabled = false;
  if (!data.job_id) return;
  if (data.mode === "drill") {
    captureDrillTargetFrom("attack-solo-target-select", "attack-solo-target-custom");
    applyAttackTargetPrefs(attackTargetPrefs);
    startDrillPoll(data.job_id, "drill");
    switchPage("defense");
    return;
  }
  document.getElementById("drill-status-card").style.display = "none";
  pollJob(
    data.job_id,
    "attack-status-card",
    "attack-status-text",
    "attack-result",
    "attack-progress",
    renderAttackResult
  );
});

document.getElementById("btn-perf").addEventListener("click", async () => {
  const btn = document.getElementById("btn-perf");
  btn.disabled = true;
  captureAttackTargetFrom("attack-solo-target-select", "attack-solo-target-custom");
  const tp = targetPayload("attack-solo-target-select", "attack-solo-target-custom");
  const ports = document.getElementById("attack-ports").value.trim() || uiConfig.attack_ports || "22,80,443";
  const data = await api("/api/attack", {
    method: "POST",
    body: JSON.stringify({
      ...tp,
      target: tp.target,
      ports,
      perf: true,
    }),
  });
  btn.disabled = false;
  if (data.job_id) {
    document.getElementById("drill-status-card").style.display = "none";
    pollJob(
      data.job_id,
      "attack-status-card",
      "attack-status-text",
      "attack-result",
      "attack-progress",
      renderAttackResult
    );
  }
});

document.getElementById("btn-defense").addEventListener("click", async () => {
  const btn = document.getElementById("btn-defense");
  btn.disabled = true;
  captureAttackTargetFrom("defense-solo-target-select", "defense-solo-target-custom");
  const tp = targetPayload("defense-solo-target-select", "defense-solo-target-custom");
  const data = await api("/api/defense", {
    method: "POST",
    body: JSON.stringify({
      ...tp,
      duration: parseInt(document.getElementById("defense-duration").value, 10) || 60,
      apply_iptables: document.getElementById("defense-iptables").checked,
      defense_host: resolveDefenseHostForDrill(tp.target),
      pair_attack: true,
      auto_drill: document.getElementById("defense-auto-drill").checked,
    }),
  });
  btn.disabled = false;
  if (!data.job_id) return;
  if (data.mode === "drill") {
    applyAttackTargetPrefs(attackTargetPrefs);
    startDrillPoll(data.job_id, "defense-drill");
    return;
  }
  document.getElementById("defense-drill-status-card").style.display = "none";
  pollJob(
    data.job_id,
    "defense-status-card",
    "defense-status-text",
    "defense-result",
    "defense-progress",
    (job) => {
      let prefix = `<p class="status-ok">${data.message || "防御已接续"}</p>`;
      renderDefenseResult(job);
      document.getElementById("defense-result").innerHTML =
        prefix + document.getElementById("defense-result").innerHTML;
    }
  );
});

async function loadReportList(mode) {
  const data = await api(`/api/reports?mode=${mode}`);
  if (mode === "nmap_lab") {
    const ul = document.getElementById("nmap-report-list");
    if (!ul) return;
    ul.innerHTML = "";
    (data.reports || []).forEach((r) => {
      const li = document.createElement("li");
      li.innerHTML = `<a href="/reports/${r.name}/scan.html" target="_blank">${r.name}/scan.html</a>`;
      ul.appendChild(li);
    });
    if (!ul.children.length) {
      ul.innerHTML = "<li class='hint'>暂无 Nmap 实验输出</li>";
    }
    return;
  }
  const listId = mode === "attack" ? "attack-report-list" : "defense-report-list";
  const ul = document.getElementById(listId);
  ul.innerHTML = "";
  (data.reports || []).forEach((r) => {
    const li = document.createElement("li");
    const reportFile = mode === "attack" ? "attack_report.html" : "defense_report.md";
    li.innerHTML = `<a href="/reports/${r.name}/${reportFile}" target="_blank">${r.name}</a>`;
    ul.appendChild(li);
  });
  if (!ul.children.length) {
    ul.innerHTML = "<li class='hint'>暂无报告</li>";
  }
}

loadConfig();
loadReportList("attack");
loadReportList("defense");
statusTimer = setInterval(refreshRuntimeStatus, 5000);

// ---------- Nmap 扫描与对比教学 ----------
let nmapPollTimer = null;

function nmapTarget() {
  return document.getElementById("nmap-target").value.trim() || resolveNmapTarget(uiConfig);
}

function nmapPorts() {
  return document.getElementById("nmap-ports").value.trim() || resolveNmapPorts(uiConfig);
}

document.getElementById("btn-nmap-sync-config").addEventListener("click", () => {
  syncNmapFromConfig(readConfigFormSnapshot());
});

function stopNmapPoll() {
  if (nmapPollTimer) {
    clearInterval(nmapPollTimer);
    nmapPollTimer = null;
  }
}

function renderZenmapPanels(hosts, target) {
  const host = (hosts && hosts[0]) || { ip: target, state: "unknown", ports: [] };
  const stateIcon = host.state === "up" ? "🟢" : "🔴";
  const osLine = host.os_name
    ? `<div>OS: ${host.os_name}${host.os_accuracy ? ` (${host.os_accuracy}%)` : ""}</div>`
    : "<div>OS: 未知</div>";

  let portHtml = "";
  const openPorts = (host.ports || []).filter(
    (p) => p.state === "open" || p.state === "open|filtered"
  );
  if (openPorts.length) {
    openPorts.forEach((p) => {
      const detail = [p.product, p.version].filter(Boolean).join(" ") || "-";
      portHtml += `<div class="zenmap-port-row">${p.port}/${p.protocol || "tcp"} ${p.state} ${p.service || "-"} ${detail}</div>`;
    });
  } else {
    portHtml = "<div class='hint'>未发现开放端口</div>";
  }

  let svcHtml = "";
  (host.services || []).forEach((s) => {
    svcHtml += `<div>📦 ${s.product || "未知"} v${s.version || "?"} @ ${s.port}${s.extra ? ` (${s.extra})` : ""}</div>`;
  });

  return `
    <div class="zenmap-layout">
      <div class="zenmap-panel">
        <h3>🖥️ 主机列表面板</h3>
        <div class="zenmap-host-row">${stateIcon} <strong>${host.ip}</strong></div>
        <div>状态: ${host.state}</div>
        ${osLine}
      </div>
      <div class="zenmap-panel">
        <h3>🔌 端口 / 服务标签</h3>
        ${portHtml}
      </div>
    </div>
    ${svcHtml ? `<div class="zenmap-panel" style="margin-top:12px"><h3>📦 服务标签</h3>${svcHtml}</div>` : ""}
  `;
}

function renderNmapResult(job) {
  const r = job.result || {};
  const box = document.getElementById("nmap-result-box");
  let html = "";

  if (r.hint) {
    html += `<div class="alert-hint">${r.hint}</div>`;
  }
  if (r.error && !r.hosts) {
    html += `<p class="status-err">${r.error}</p>`;
    box.innerHTML = html;
    return;
  }
  if (r.error && r.success === false) {
    html += `<p class="status-err">${r.error}</p>`;
  }

  html += `<div class="nmap-meta">`;
  html += `<p>🎯 目标: <strong>${r.target || "—"}</strong>`;
  if (r.ports) html += ` · 端口: ${r.ports}`;
  if (r.duration != null) html += ` · ⏱️ ${r.duration}s`;
  html += `</p>`;
  if (r.nmap_command) html += `<p>💻 命令: <code>${r.nmap_command}</code></p>`;
  if (r.principle) html += `<p>📖 原理: ${r.principle}</p>`;
  if (r.features) html += `<p>✨ 特点: ${r.features}</p>`;
  html += `</div>`;

  if (r.mode === "zenmap" || (r.hosts && r.hosts.length)) {
    html += renderZenmapPanels(r.hosts, r.target);
  }

  if (r.mode === "os") {
    const matches = r.os_matches || [];
    if (matches.length) {
      html += "<p><strong>识别结果:</strong></p><ul>";
      matches.forEach((m) => {
        html += `<li>${m.name} — 置信度 ${m.accuracy}%</li>`;
      });
      html += "</ul>";
    } else if (r.no_result_hint) {
      html += `<p class="hint">${r.no_result_hint}</p>`;
    }
  }

  if (r.mode === "full_port" || r.open_port_count != null) {
    html += `<p><strong>开放端口数:</strong> ${r.open_port_count ?? 0}</p>`;
    const lst = r.open_port_list || [];
    if (lst.length) {
      html += `<p><strong>列表:</strong> ${lst.slice(0, 30).join(", ")}${lst.length > 30 ? " ..." : ""}</p>`;
    }
  } else if (r.open_port_count != null && r.mode !== "zenmap") {
    html += `<p><strong>开放端口:</strong> ${r.open_port_count}</p>`;
  }

  const base = nmapLabReportBase(r);
  if (base) {
    html += `<p>📄 报告: <a href="/reports/${base}/scan.html" target="_blank">浏览器查看 scan.html</a>`;
    html += ` · <a href="/reports/${base}/scan.xml" download>下载 scan.xml</a></p>`;
    html += `<p class="hint">scan.html 为可读报告；scan.xml 供 Zenmap 导入。</p>`;
  }

  if (r.comparison && r.comparison.summary) {
    html += `<p class="hint" style="margin-top:12px">💡 ${r.comparison.summary}</p>`;
  }

  box.innerHTML = html;
  loadReportList("nmap_lab");
}

function pollNmapJob(jobId, title) {
  stopNmapPoll();
  const card = document.getElementById("nmap-result-card");
  card.style.display = "block";
  document.getElementById("nmap-result-title").textContent = title;
  document.getElementById("nmap-progress").style.width = "30%";
  document.getElementById("nmap-status-text").textContent = "加载中，正在扫描...";
  document.getElementById("nmap-status-text").className = "";
  document.getElementById("nmap-result-box").innerHTML = "";

  nmapPollTimer = setInterval(async () => {
    const job = await api(`/api/job/${jobId}`);
    document.getElementById("nmap-status-text").textContent = job.progress || job.status;
    if (job.status === "running") {
      document.getElementById("nmap-progress").style.width = "60%";
    }
    if (job.status === "done") {
      stopNmapPoll();
      document.getElementById("nmap-progress").style.width = "100%";
      document.getElementById("nmap-status-text").textContent = "完成";
      document.getElementById("nmap-status-text").className = "status-ok";
      renderNmapResult(job);
    }
    if (job.status === "error") {
      stopNmapPoll();
      document.getElementById("nmap-progress").style.width = "100%";
      document.getElementById("nmap-status-text").textContent = "失败";
      document.getElementById("nmap-status-text").className = "status-err";
      document.getElementById("nmap-result-box").innerHTML =
        `<p class="status-err">${job.error || "未知错误"}</p>`;
    }
  }, 1500);
}

async function runNmapDemo(mode, title, btnId) {
  const btn = document.getElementById(btnId);
  if (btn) btn.disabled = true;
  const data = await api(`/api/nmap-lab/${mode}`, {
    method: "POST",
    body: JSON.stringify({ target: nmapTarget(), ports: nmapPorts() }),
  });
  if (btn) btn.disabled = false;
  if (data.job_id) {
    pollNmapJob(data.job_id, title);
  }
}

async function loadNmapComparison() {
  const data = await api("/api/nmap-lab/comparison");
  if (!data.success) return;

  const priv = data.privileges || {};
  const okAlert = document.getElementById("nmap-privilege-alert");
  const warnAlert = document.getElementById("nmap-privilege-warn");
  if (priv.can_syn_os) {
    okAlert.style.display = "block";
    okAlert.innerHTML = `<strong>✅ SYN/OS 可用</strong> — ${priv.message || ""}`;
    warnAlert.style.display = "none";
  } else if (priv.setup_hint) {
    warnAlert.style.display = "block";
    warnAlert.innerHTML =
      `<strong>SYN / OS 需额外配置</strong><pre class="code-block" style="margin-top:8px;white-space:pre-wrap">${priv.setup_hint}</pre>`;
    okAlert.style.display = "none";
  }

  const compEl = document.getElementById("nmap-static-comparison");
  const c = data.comparison || {};
  let compHtml = "";
  ["zenmap", "insightscan"].forEach((key) => {
    const block = c[key] || {};
    compHtml += `<div class="comparison-col"><h3>${block.title || key}</h3><ul>`;
    (block.points || []).forEach((pt) => {
      compHtml += `<li>${pt}</li>`;
    });
    compHtml += "</ul></div>";
  });
  compEl.innerHTML = compHtml;
  const summaryEl = document.getElementById("nmap-comparison-summary");
  if (summaryEl) summaryEl.textContent = c.summary || "";

  const tableEl = document.getElementById("nmap-scan-table");
  const rows = data.table || [];
  let tbl = `<table class="scan-table"><thead><tr>
    <th>扫描方式</th><th>权限</th><th>速度</th><th>隐蔽性</th><th>准确性</th>
  </tr></thead><tbody>`;
  rows.forEach((row) => {
    tbl += `<tr><td>${row.method}</td><td>${row.privilege}</td><td>${row.speed}</td><td>${row.stealth}</td><td>${row.accuracy}</td></tr>`;
  });
  tbl += "</tbody></table>";
  tableEl.innerHTML = tbl;

  document.getElementById("nmap-lab-questions").textContent =
    "实验思考：① 局域网扫描延迟低、结果更完整；互联网目标常 filtered。② 防御：关闭非必要端口、防火墙白名单、启用 syslog/IDS 监控扫描行为。";
}

document.getElementById("btn-nmap-zenmap").addEventListener("click", () =>
  runNmapDemo("zenmap", "Zenmap 风格演示", "btn-nmap-zenmap")
);
document.getElementById("btn-nmap-connect").addEventListener("click", () =>
  runNmapDemo("connect", "TCP Connect (-sT)", "btn-nmap-connect")
);
document.getElementById("btn-nmap-syn").addEventListener("click", () =>
  runNmapDemo("syn", "TCP SYN (-sS)", "btn-nmap-syn")
);
document.getElementById("btn-nmap-os").addEventListener("click", () =>
  runNmapDemo("os", "操作系统识别 (-O)", "btn-nmap-os")
);
document.getElementById("btn-nmap-full").addEventListener("click", () =>
  runNmapDemo("full_port", "全端口扫描 (1-1000)", "btn-nmap-full")
);

document.getElementById("btn-nmap-insightscan").addEventListener("click", async () => {
  const btn = document.getElementById("btn-nmap-insightscan");
  btn.disabled = true;
  const target = nmapTarget();
  const ports = nmapPorts();
  const resultBox = document.getElementById("nmap-insightscan-result");
  resultBox.style.display = "block";
  resultBox.innerHTML = "<p>⏳ 正在启动 InsightScan Connect 扫描 + AI 分析...</p>";

  const data = await api("/api/attack", {
    method: "POST",
    body: JSON.stringify({
      target,
      ports,
      perf: false,
      full_suite: false,
      with_defense: false,
    }),
  });
  btn.disabled = false;

  if (!data.job_id) {
    resultBox.innerHTML = `<p class="status-err">${data.error || "启动失败"}</p>`;
    return;
  }

  const pollIs = setInterval(async () => {
    const job = await api(`/api/job/${data.job_id}`);
    if (job.status === "running") {
      resultBox.innerHTML = `<p>⏳ ${job.progress || "分析中..."}</p>`;
    }
    if (job.status === "done") {
      clearInterval(pollIs);
      const r = job.result || {};
      const dir = r.session_dir || "";
      let html = `<p class="status-ok">✅ InsightScan 增强分析完成</p>`;
      html += `<p>目标: ${r.target} · 端口: ${r.ports}</p>`;
      if (r.reports?.html) {
        html += `<p><a href="${reportLink(dir, "attack_report.html")}" target="_blank">打开 AI 增强 HTML 报告</a></p>`;
      }
      html += `<p class="hint">对比上方 Zenmap 原始输出：InsightScan 增加了 AI 风险解读、批量能力与自动化报告。</p>`;
      html += `<p><button class="btn btn-secondary" type="button" id="btn-goto-attack">查看主动探测页</button></p>`;
      resultBox.innerHTML = html;
      document.getElementById("btn-goto-attack").addEventListener("click", () => switchPage("attack"));
    }
    if (job.status === "error") {
      clearInterval(pollIs);
      resultBox.innerHTML = `<p class="status-err">失败: ${job.error || "未知错误"}</p>`;
    }
  }, 2000);
});
