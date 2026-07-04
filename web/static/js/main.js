/** InsightScan Web 前端逻辑 */

let uiConfig = {};
let pollTimer = null;
let statusTimer = null;
let attackTypes = [];

const TARGET_SELECT_IDS = [
  "attack-target-select",
  "attack-solo-target-select",
  "defense-target-select",
  "defense-solo-target-select",
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
  if (page === "defense") refreshRuntimeStatus();
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
    if (sel) sel.innerHTML = buildTargetOptionsHtml();
  });
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
  refreshAllTargetSelectOptions();
  applyTargetSelector("attack-target-select", "attack-target-custom-row", "attack-target-custom", uiConfig);
  applyTargetSelector("attack-solo-target-select", "attack-solo-custom-row", "attack-solo-target-custom", uiConfig);
  applyTargetSelector("defense-target-select", "defense-target-custom-row", "defense-target-custom", uiConfig);
  applyTargetSelector("defense-solo-target-select", "defense-solo-custom-row", "defense-solo-target-custom", uiConfig);
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
  ["attack-target-select", "attack-target-custom-row"],
  ["attack-solo-target-select", "attack-solo-custom-row"],
  ["defense-target-select", "defense-target-custom-row"],
  ["defense-solo-target-select", "defense-solo-custom-row"],
];

TARGET_BINDINGS.forEach(([selectId, rowId]) => {
  bindTargetSelectChange(selectId, rowId);
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
    fillConfigForm(uiConfig);
    applyAllTargetSelectors();
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
    applyAllTargetSelectors();
    msg.textContent = "配置已保存，攻击/防御页目标已同步";
    msg.className = "hint status-ok";
  } else {
    msg.textContent = data.error || "保存失败";
    msg.className = "hint status-err";
  }
});

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
      fillConfigForm(uiConfig);
      applyAllTargetSelectors();
    }
    msg.textContent = apply ? "已检测并应用，各页目标已更新" : "检测完成，请确认后保存";
    msg.className = "hint status-ok";
  } else {
    msg.textContent = data.error || "检测失败";
    msg.className = "hint status-err";
  }
}

document.getElementById("btn-detect").addEventListener("click", () => detectNetwork(false));
document.getElementById("btn-detect-apply").addEventListener("click", () => detectNetwork(true));

function drillPayload(selectId, customInputId, extra = {}) {
  const tp = targetPayload(selectId, customInputId);
  return {
    ...tp,
    defense_host: uiConfig.local_ip || "127.0.0.1",
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
  let html = `<p><strong>防御主机:</strong> ${r.defense_host || uiConfig.local_ip || "本机"}</p>`;
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
  btn.disabled = true;
  const data = await api("/api/drill", {
    method: "POST",
    body: JSON.stringify(drillPayload(selectId, customId)),
  });
  btn.disabled = false;
  if (data.job_id) {
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
  const data = await api("/api/attack", {
    method: "POST",
    body: JSON.stringify({
      target: uiConfig.perf_target || uiConfig.cidr,
      ports: uiConfig.perf_ports || "22,80,443",
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
  const tp = targetPayload("defense-solo-target-select", "defense-solo-target-custom");
  const data = await api("/api/defense", {
    method: "POST",
    body: JSON.stringify({
      ...tp,
      duration: parseInt(document.getElementById("defense-duration").value, 10) || 60,
      apply_iptables: document.getElementById("defense-iptables").checked,
      defense_host: uiConfig.local_ip || "127.0.0.1",
      pair_attack: true,
      auto_drill: document.getElementById("defense-auto-drill").checked,
    }),
  });
  btn.disabled = false;
  if (!data.job_id) return;
  if (data.mode === "drill") {
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
