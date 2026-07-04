/** InsightScan Web 前端逻辑 */

let uiConfig = {};
let pollTimer = null;

// ---------- 导航 ----------
document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const page = btn.dataset.page;
    document.querySelectorAll(".nav-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".page").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`page-${page}`).classList.add("active");
  });
});

// ---------- API ----------
async function api(url, options = {}) {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  return res.json();
}

// ---------- 配置 ----------
async function loadConfig() {
  const data = await api("/api/config");
  if (data.success) {
    uiConfig = data.config;
    fillConfigForm(uiConfig);
    updateAttackTargetOptions();
  }
}

function fillConfigForm(cfg) {
  document.getElementById("cfg-local-ip").value = cfg.local_ip || "";
  document.getElementById("cfg-cidr").value = cfg.cidr || "";
  document.getElementById("cfg-gateway").value = cfg.gateway || "";
  document.getElementById("cfg-interface").value = cfg.interface || "";
  document.getElementById("cfg-attack-target").value = cfg.attack_target || "127.0.0.1";
  document.getElementById("cfg-attack-ports").value = cfg.attack_ports || "22,80,443";
  document.getElementById("cfg-perf-target").value = cfg.perf_target || "";
  document.getElementById("cfg-perf-ports").value = cfg.perf_ports || "22,80,443";
  document.getElementById("defense-duration").value = cfg.defense_duration ?? 60;
  document.getElementById("defense-iptables").checked = !!cfg.defense_apply_iptables;
  document.getElementById("attack-ports").value = cfg.attack_ports || "22,80,443";
}

function updateAttackTargetOptions() {
  const sel = document.getElementById("attack-target-select");
  sel.innerHTML = `
    <option value="127.0.0.1">127.0.0.1（本机）</option>
    <option value="local_ip">${uiConfig.local_ip || "本机 IP"}（局域网）</option>
    <option value="cidr">${uiConfig.cidr || "C 段"}</option>
    <option value="custom">自定义</option>
  `;
}

function resolveAttackTarget() {
  const sel = document.getElementById("attack-target-select").value;
  if (sel === "127.0.0.1") return "127.0.0.1";
  if (sel === "local_ip") return uiConfig.local_ip || "127.0.0.1";
  if (sel === "cidr") return uiConfig.cidr || uiConfig.perf_target || "127.0.0.1";
  return document.getElementById("attack-target-custom").value.trim() || "127.0.0.1";
}

document.getElementById("attack-target-select").addEventListener("change", (e) => {
  document.getElementById("attack-custom-row").style.display =
    e.target.value === "custom" ? "block" : "none";
});

document.getElementById("btn-save-config").addEventListener("click", async () => {
  const payload = {
    local_ip: document.getElementById("cfg-local-ip").value.trim(),
    cidr: document.getElementById("cfg-cidr").value.trim(),
    gateway: document.getElementById("cfg-gateway").value.trim(),
    interface: document.getElementById("cfg-interface").value.trim(),
    attack_target: document.getElementById("cfg-attack-target").value.trim(),
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
    updateAttackTargetOptions();
    msg.textContent = "配置已保存";
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
    }
    if (data.config) {
      uiConfig = data.config;
      fillConfigForm(uiConfig);
      updateAttackTargetOptions();
    }
    msg.textContent = apply ? "已检测并应用网段配置" : "检测完成，请确认后保存";
    msg.className = "hint status-ok";
  } else {
    msg.textContent = data.error || "检测失败";
    msg.className = "hint status-err";
  }
}

document.getElementById("btn-detect").addEventListener("click", () => detectNetwork(false));
document.getElementById("btn-detect-apply").addEventListener("click", () => detectNetwork(true));

// ---------- 任务轮询 ----------
function pollJob(jobId, cardId, textId, resultId, progressId, onDone) {
  if (pollTimer) clearInterval(pollTimer);
  document.getElementById(cardId).style.display = "block";
  document.getElementById(progressId).style.width = "30%";

  pollTimer = setInterval(async () => {
    const job = await api(`/api/job/${jobId}`);
    document.getElementById(textId).textContent = job.progress || job.status;

    if (job.status === "running") {
      document.getElementById(progressId).style.width = "60%";
    }
    if (job.status === "done") {
      clearInterval(pollTimer);
      document.getElementById(progressId).style.width = "100%";
      document.getElementById(textId).textContent = "完成";
      document.getElementById(textId).className = "status-ok";
      onDone(job);
    }
    if (job.status === "error") {
      clearInterval(pollTimer);
      document.getElementById(progressId).style.width = "100%";
      document.getElementById(textId).textContent = "失败: " + (job.error || "未知错误");
      document.getElementById(textId).className = "status-err";
      document.getElementById(resultId).innerHTML = `<p class="status-err">${job.error}</p>`;
    }
  }, 2000);
}

function renderAttackResult(job) {
  const r = job.result || {};
  const dir = r.session_dir || "";
  const name = dir.split("/").pop() || dir.split("\\").pop() || "";
  let html = `<p><strong>报告目录:</strong> ${dir}</p>`;
  if (r.reports?.html) {
    const rel = `/reports/${name}/attack_report.html`;
    html += `<p><a href="${rel}" target="_blank">打开 HTML 报告</a></p>`;
  }
  if (r.scan) {
    html += `<p>主机: ${r.scan.hosts} | 端口: ${r.scan.ports} | 耗时: ${r.scan.duration}s</p>`;
  }
  if (r.perf_benchmark?.benchmark) {
    html += "<p><strong>性能结果:</strong></p><ul>";
    r.perf_benchmark.benchmark.forEach((b) => {
      html += `<li>${b.threads} 线程 → ${b.duration_sec}s</li>`;
    });
    html += "</ul>";
    html += `<p><a href="/reports/${name}/perf_benchmark.md" target="_blank">查看性能报告</a></p>`;
  }
  document.getElementById("attack-result").innerHTML = html;
  loadReportList("attack");
}

function renderDefenseResult(job) {
  const r = job.result || {};
  const dir = r.session_dir || "";
  const name = dir.split("/").pop() || dir.split("\\").pop() || "";
  let html = `<p><strong>报告目录:</strong> ${dir}</p>`;
  html += `<p><a href="/reports/${name}/defense_report.md" target="_blank">查看防御报告</a></p>`;
  if (r.scan_detection) {
    const se = r.scan_detection.scan_events ?? 0;
    html += `<p>检测事件: ${r.scan_detection.total_events} | 明确扫描: ${se}</p>`;
  }
  if (r.promiscuous) {
    html += `<p>混杂模式: ${r.promiscuous.alert ? "⚠️ 告警" : "✅ 正常"}</p>`;
  }
  document.getElementById("defense-result").innerHTML = html;
  loadReportList("defense");
}

// ---------- 攻击 / 性能 ----------
document.getElementById("btn-attack").addEventListener("click", async () => {
  const btn = document.getElementById("btn-attack");
  btn.disabled = true;
  const data = await api("/api/attack", {
    method: "POST",
    body: JSON.stringify({
      target: resolveAttackTarget(),
      ports: document.getElementById("attack-ports").value.trim(),
      perf: false,
    }),
  });
  btn.disabled = false;
  if (data.job_id) {
    pollJob(data.job_id, "attack-status-card", "attack-status-text", "attack-result", "attack-progress", renderAttackResult);
  }
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
    pollJob(data.job_id, "attack-status-card", "attack-status-text", "attack-result", "attack-progress", renderAttackResult);
  }
});

// ---------- 防御 ----------
document.getElementById("btn-defense").addEventListener("click", async () => {
  const btn = document.getElementById("btn-defense");
  btn.disabled = true;
  const data = await api("/api/defense", {
    method: "POST",
    body: JSON.stringify({
      duration: parseInt(document.getElementById("defense-duration").value, 10) || 60,
      apply_iptables: document.getElementById("defense-iptables").checked,
    }),
  });
  btn.disabled = false;
  if (data.job_id) {
    pollJob(data.job_id, "defense-status-card", "defense-status-text", "defense-result", "defense-progress", renderDefenseResult);
  }
});

// ---------- 报告列表 ----------
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

// ---------- 初始化 ----------
loadConfig();
loadReportList("attack");
loadReportList("defense");
