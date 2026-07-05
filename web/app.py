"""InsightScan Web 服务：四页界面 API（含 Nmap 扫描与对比教学）。"""

import sys
import threading
import traceback
import uuid
from datetime import datetime
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from flask import Flask, jsonify, render_template, request, send_from_directory

from src.attack_mode import run_attack_mode, run_attack_suite
from src.defense_mode import run_defense_mode
from src.ui_config import detect_network, load_ui_settings, resolve_target, save_ui_settings
from src.utils import REPORTS_DIR, init_db, setup_logging

app = Flask(
    __name__,
    template_folder=str(_ROOT / "web" / "templates"),
    static_folder=str(_ROOT / "web" / "static"),
)

# 后台任务状态 {job_id: {...}}
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()

# 运行中任务索引（用于攻防接续）
_active: dict[str, dict] = {}


def _register_active(job_id: str, job_type: str, **meta) -> None:
    """登记任务元信息，供攻防联调查询。"""
    with _jobs_lock:
        _active[job_id] = {"type": job_type, "status": "pending", **meta}


def _set_active_status(job_id: str, status: str) -> None:
    with _jobs_lock:
        if job_id in _active:
            _active[job_id]["status"] = status


def _find_running_attack() -> tuple[str, dict] | tuple[None, None]:
    """查找仍在运行的攻击/性能任务。"""
    with _jobs_lock:
        for jid, info in _active.items():
            if info.get("type") in ("attack", "perf") and info.get("status") == "running":
                return jid, dict(info)
    return None, None


def _resolve_drill_targets(cfg: dict, data: dict) -> dict:
    """解析攻防联调用的攻击目标与本机防御 IP。"""
    defense_host = data.get("defense_host") or cfg.get("local_ip") or "127.0.0.1"
    attack_target = data.get("target") or resolve_target(
        cfg,
        data.get("target_mode"),
        data.get("target_custom"),
    )
    if not data.get("target") and cfg.get("defense_attack_target"):
        attack_target = cfg["defense_attack_target"]
    ports = data.get("ports") or cfg.get("attack_ports", "22,80,443")
    return {
        "attack_target": attack_target,
        "defense_host": defense_host,
        "ports": ports,
    }


def _create_job(job_type: str) -> str:
    """创建任务并返回 job_id。"""
    job_id = str(uuid.uuid4())[:8]
    with _jobs_lock:
        _jobs[job_id] = {
            "id": job_id,
            "type": job_type,
            "status": "pending",
            "progress": "等待开始...",
            "started_at": datetime.now().isoformat(),
            "result": None,
            "error": None,
        }
    return job_id


def _update_job(job_id: str, **kwargs) -> None:
    """更新任务状态。"""
    with _jobs_lock:
        if job_id in _jobs:
            _jobs[job_id].update(kwargs)


def _run_attack_job(
    job_id: str,
    target: str,
    ports: str,
    run_perf: bool = False,
    full_suite: bool = False,
    random_suite: bool = False,
) -> None:
    """后台执行主动探测。"""
    log = setup_logging()
    _set_active_status(job_id, "running")
    try:
        if full_suite or random_suite:
            label = "随机攻击套件" if random_suite else "全套攻击"
            _update_job(
                job_id, status="running",
                progress=f"{label} → {target}（connect/syn/fin）...",
            )
            result = run_attack_suite(
                target=target,
                ports=ports,
                random_subset=random_suite,
            )
        elif run_perf:
            _update_job(job_id, status="running", progress=f"性能测试 {target} ...")
            result = run_attack_mode(target=target, ports=ports, run_perf=True)
        else:
            _update_job(job_id, status="running", progress=f"正在扫描 {target} ...")
            result = run_attack_mode(target=target, ports=ports, run_perf=False)

        if "error" in result:
            _update_job(job_id, status="error", error=result["error"], progress="失败")
            _set_active_status(job_id, "error")
        else:
            _update_job(
                job_id,
                status="done",
                progress="完成",
                result={
                    "session_dir": result.get("session_dir"),
                    "task_id": result.get("task_id"),
                    "target": target,
                    "ports": ports,
                    "scan": result.get("scan"),
                    "reports": result.get("reports"),
                    "perf_benchmark": result.get("perf_benchmark"),
                    "attack_suite": result.get("attack_suite"),
                    "scan_types_used": result.get("scan_types_used"),
                    "random_subset": result.get("random_subset", False),
                },
            )
            _set_active_status(job_id, "done")
    except Exception as e:
        log.error("攻击任务异常: %s", e)
        _update_job(job_id, status="error", error=str(e), progress="异常")
        _set_active_status(job_id, "error")


def _run_defense_job(
    job_id: str,
    duration: int,
    apply_iptables: bool,
    lookback: int,
    defense_host: str = "",
) -> None:
    """后台执行被动防御。"""
    log = setup_logging()
    _set_active_status(job_id, "running")
    try:
        host_label = defense_host or "本机"
        _update_job(job_id, status="running", progress=f"正在监听 {host_label} 的被扫描行为...")
        result = run_defense_mode(
            duration_sec=duration,
            apply_iptables=apply_iptables,
            lookback_minutes=lookback,
        )
        if "error" in result:
            _update_job(job_id, status="error", error=result["error"], progress="失败")
            _set_active_status(job_id, "error")
        else:
            _update_job(
                job_id,
                status="done",
                progress="完成",
                result={
                    "session_dir": result.get("session_dir"),
                    "defense_host": defense_host,
                    "scan_detection": result.get("scan_detection"),
                    "promiscuous": result.get("promiscuous"),
                    "iptables": result.get("iptables"),
                    "events_count": len(result.get("events", [])),
                },
            )
            _set_active_status(job_id, "done")
    except Exception as e:
        log.error("防御任务异常: %s", e)
        _update_job(job_id, status="error", error=str(e), progress="异常")
        _set_active_status(job_id, "error")


def _start_attack_job(
    target: str,
    ports: str,
    run_perf: bool = False,
    full_suite: bool = False,
    random_suite: bool = False,
) -> str:
    """创建并启动攻击后台任务。"""
    job_id = _create_job("perf" if run_perf else "attack")
    _register_active(
        job_id,
        "perf" if run_perf else "attack",
        target=target,
        ports=ports,
        full_suite=full_suite,
        random_suite=random_suite,
    )
    thread = threading.Thread(
        target=_run_attack_job,
        args=(job_id, target, ports, run_perf, full_suite, random_suite),
        daemon=True,
    )
    thread.start()
    return job_id


def _start_defense_job(
    duration: int,
    apply_iptables: bool,
    lookback: int,
    defense_host: str,
) -> str:
    """创建并启动防御后台任务。"""
    job_id = _create_job("defense")
    _register_active(job_id, "defense", defense_host=defense_host)
    thread = threading.Thread(
        target=_run_defense_job,
        args=(job_id, duration, apply_iptables, lookback, defense_host),
        daemon=True,
    )
    thread.start()
    return job_id


def _run_drill_orchestrator(
    drill_id: str,
    attack_target: str,
    defense_host: str,
    ports: str,
    duration: int,
    apply_iptables: bool,
    lookback: int,
    attack_delay: float = 2.0,
) -> None:
    """先启动防御监听，再启动攻击，保证时间重叠。"""
    import time

    log = setup_logging()
    try:
        defense_job_id = _start_defense_job(duration, apply_iptables, lookback, defense_host)
        _update_job(
            drill_id,
            status="running",
            progress=f"防御已启动（监听 {defense_host}），{attack_delay:.0f}s 后发起攻击...",
            defense_job_id=defense_job_id,
        )
        time.sleep(attack_delay)
        attack_job_id = _start_attack_job(
            attack_target, ports, random_suite=True
        )
        _update_job(
            drill_id,
            status="running",
            progress=f"攻防进行中：随机攻击 {attack_target} ↔ 防御 {defense_host}",
            attack_job_id=attack_job_id,
            defense_job_id=defense_job_id,
        )

        while True:
            with _jobs_lock:
                atk = _jobs.get(attack_job_id, {})
                dfn = _jobs.get(defense_job_id, {})
            atk_done = atk.get("status") in ("done", "error")
            dfn_done = dfn.get("status") in ("done", "error")
            if atk_done and dfn_done:
                break
            time.sleep(2)

        overall = "done"
        err_parts = []
        if atk.get("status") == "error":
            overall = "error"
            err_parts.append(atk.get("error") or "攻击失败")
        if dfn.get("status") == "error":
            overall = "error"
            err_parts.append(dfn.get("error") or "防御失败")

        _update_job(
            drill_id,
            status=overall,
            progress="攻防联调完成" if overall == "done" else "攻防联调部分失败",
            error="; ".join(err_parts) if err_parts else None,
            result={
                "attack_target": attack_target,
                "defense_host": defense_host,
                "ports": ports,
                "attack_job_id": attack_job_id,
                "defense_job_id": defense_job_id,
                "attack": atk.get("result"),
                "defense": dfn.get("result"),
            },
        )
    except Exception as e:
        log.error("攻防联调异常: %s", e)
        _update_job(drill_id, status="error", error=str(e), progress="联调异常")


def _run_nmap_lab_job(job_id: str, mode: str, target: str, ports: str) -> None:
    """后台执行 Nmap 教学演示任务。"""
    log = setup_logging()
    _set_active_status(job_id, "running")
    labels = {
        "zenmap": "Zenmap 风格演示",
        "connect": "TCP Connect 扫描",
        "syn": "TCP SYN 扫描",
        "os": "操作系统识别",
        "full_port": "全端口扫描 (1-1000)",
    }
    try:
        _update_job(
            job_id,
            status="running",
            progress=f"正在执行 {labels.get(mode, mode)} → {target} ...",
        )
        if mode == "zenmap":
            from nmap_lab.zenmap_demo import run_zenmap_scan
            result = run_zenmap_scan(target, ports)
        elif mode == "connect":
            from nmap_lab.scan_types_demo import demo_tcp_connect
            result = demo_tcp_connect(target, ports)
        elif mode == "syn":
            from nmap_lab.scan_types_demo import demo_tcp_syn
            result = demo_tcp_syn(target, ports)
        elif mode == "os":
            from nmap_lab.scan_types_demo import demo_os_detection
            result = demo_os_detection(target)
        elif mode == "full_port":
            from nmap_lab.scan_types_demo import demo_full_port_scan
            result = demo_full_port_scan(target)
        else:
            result = {"error": f"未知演示模式: {mode}"}

        if result.get("error") and result.get("success") is not False:
            _update_job(job_id, status="error", error=result["error"], progress="失败")
            _set_active_status(job_id, "error")
        elif result.get("success") is False and not result.get("hosts"):
            _update_job(
                job_id,
                status="done",
                progress="完成（权限或环境限制）",
                result=result,
            )
            _set_active_status(job_id, "done")
        else:
            _update_job(
                job_id,
                status="done",
                progress="完成",
                result=result,
            )
            _set_active_status(job_id, "done")
    except Exception as e:
        log.error("Nmap 教学任务异常: %s", e)
        _update_job(job_id, status="error", error=str(e), progress="异常")
        _set_active_status(job_id, "error")


def _start_nmap_lab_job(mode: str, target: str, ports: str) -> str:
    """创建并启动 Nmap 教学后台任务。"""
    job_id = _create_job(f"nmap_{mode}")
    _register_active(job_id, f"nmap_{mode}", target=target, ports=ports, mode=mode)
    thread = threading.Thread(
        target=_run_nmap_lab_job,
        args=(job_id, mode, target, ports),
        daemon=True,
    )
    thread.start()
    return job_id


@app.route("/api/nmap-lab/<mode>", methods=["POST"])
def api_nmap_lab(mode: str):
    """Nmap 教学演示：zenmap / connect / syn / os / full_port。"""
    allowed = {"zenmap", "connect", "syn", "os", "full_port"}
    if mode not in allowed:
        return jsonify({"error": f"不支持的模式: {mode}"}), 400

    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "127.0.0.1").strip()
    ports = (data.get("ports") or "21,23,80,3306").strip()

    job_id = _start_nmap_lab_job(mode, target, ports)
    labels = {
        "zenmap": "Zenmap 演示",
        "connect": "TCP Connect",
        "syn": "TCP SYN",
        "os": "OS 识别",
        "full_port": "全端口扫描",
    }
    return jsonify({
        "success": True,
        "job_id": job_id,
        "mode": mode,
        "message": f"{labels.get(mode, mode)}已启动",
        "target": target,
        "ports": ports,
    })


@app.route("/api/nmap-lab/comparison", methods=["GET"])
def api_nmap_lab_comparison():
    """返回静态对比表与 InsightScan 差异说明。"""
    from nmap_lab.common import comparison_table_rows, insightscan_comparison_static
    from nmap_lab.common import get_privilege_status
    return jsonify({
        "success": True,
        "table": comparison_table_rows(),
        "comparison": insightscan_comparison_static(),
        "privileges": get_privilege_status(),
    })


@app.route("/")
def index():
    """主页面（四 Tab）。"""
    return render_template("index.html")


@app.route("/api/config", methods=["GET"])
def api_get_config():
    """获取 UI 配置。"""
    cfg = load_ui_settings()
    return jsonify({"success": True, "config": cfg})


@app.route("/api/config", methods=["POST"])
def api_save_config():
    """保存 UI 配置。"""
    data = request.get_json(silent=True) or {}
    result = save_ui_settings(data)
    if "error" in result:
        return jsonify(result), 400
    return jsonify({"success": True, "config": result})


@app.route("/api/network/detect", methods=["POST"])
def api_detect_network():
    """自动检测网段并可选写回配置。"""
    detected = detect_network()
    if "error" in detected and not detected.get("local_ip"):
        return jsonify(detected), 500
    apply = (request.get_json(silent=True) or {}).get("apply", False)
    if apply and detected.get("local_ip"):
        updates = {
            "local_ip": detected["local_ip"],
            "cidr": detected.get("cidr", ""),
            "interface": detected.get("interface", ""),
            "gateway": detected.get("gateway", ""),
            "perf_target": detected.get("cidr", ""),
            "defense_attack_target": detected["local_ip"],
            "attack_target": detected["local_ip"],
            "target_mode": "local_ip",
            "target_custom": "",
        }
        saved = save_ui_settings(updates)
        return jsonify({"success": True, "detected": detected, "config": saved})
    return jsonify({"success": True, "detected": detected})


@app.route("/api/status", methods=["GET"])
def api_status():
    """当前 IP 配置与运行中攻防任务（供前端接续防御）。"""
    cfg = load_ui_settings()
    attack_id, attack_info = _find_running_attack()
    defense_running = None
    with _jobs_lock:
        for jid, info in _active.items():
            if info.get("type") == "defense" and info.get("status") == "running":
                defense_running = {"job_id": jid, **info}
                break
    return jsonify({
        "success": True,
        "local_ip": cfg.get("local_ip", "127.0.0.1"),
        "cidr": cfg.get("cidr", ""),
        "defense_host": cfg.get("local_ip", "127.0.0.1"),
        "default_attack_target": cfg.get("defense_attack_target") or cfg.get("local_ip", "127.0.0.1"),
        "running_attack": {"job_id": attack_id, **attack_info} if attack_id else None,
        "running_defense": defense_running,
    })


@app.route("/api/drill", methods=["POST"])
def api_drill():
    """一键攻防联调：同一后端自动先防御、后攻击，无需第二个终端。"""
    data = request.get_json(silent=True) or {}
    cfg = load_ui_settings()
    return api_drill_with_data(data, cfg)


@app.route("/api/attack-types", methods=["GET"])
def api_attack_types():
    """返回项目支持的全部攻击扫描类型。"""
    from src.attack_mode import ATTACK_SCAN_TYPES, ATTACK_TYPE_LABELS
    return jsonify({
        "types": [
            {"id": t, "label": ATTACK_TYPE_LABELS.get(t, t)}
            for t in ATTACK_SCAN_TYPES
        ],
    })


@app.route("/api/attack", methods=["POST"])
def api_attack():
    """一键攻击 / 性能测试（异步）。"""
    data = request.get_json(silent=True) or {}
    cfg = load_ui_settings()
    run_perf = bool(data.get("perf", False))
    target = data.get("target") or resolve_target(
        cfg, data.get("target_mode"), data.get("target_custom")
    )
    if not data.get("target") and not run_perf:
        target = resolve_target(cfg)
    if run_perf:
        target = data.get("target") or cfg.get("perf_target") or cfg.get("cidr") or target
    ports = data.get("ports") or (cfg["perf_ports"] if run_perf else cfg["attack_ports"])
    with_defense = bool(data.get("with_defense", False))
    full_suite = bool(data.get("full_suite", not run_perf))

    if with_defense and not run_perf:
        drill_data = {**data, "target": target, "ports": ports}
        return api_drill_with_data(drill_data, cfg)

    job_id = _start_attack_job(
        target, ports, run_perf=run_perf, full_suite=full_suite and not run_perf
    )
    return jsonify({
        "success": True,
        "job_id": job_id,
        "message": (
            "全套攻击已启动（connect+syn+fin）" if full_suite and not run_perf
            else f"{'性能测试' if run_perf else '主动探测'}已启动"
        ),
        "target": target,
        "ports": ports,
        "full_suite": full_suite and not run_perf,
    })


def api_drill_with_data(data: dict, cfg: dict | None = None):
    """供 attack with_defense 复用的联调启动。"""
    cfg = cfg or load_ui_settings()
    targets = _resolve_drill_targets(cfg, data)
    duration = int(data.get("duration", cfg.get("defense_duration", 60)))
    apply_iptables = bool(data.get("apply_iptables", cfg.get("defense_apply_iptables", False)))
    lookback = int(data.get("lookback", 10))

    drill_id = _create_job("drill")
    _register_active(
        drill_id,
        "drill",
        attack_target=targets["attack_target"],
        defense_host=targets["defense_host"],
    )
    thread = threading.Thread(
        target=_run_drill_orchestrator,
        args=(
            drill_id,
            targets["attack_target"],
            targets["defense_host"],
            targets["ports"],
            duration,
            apply_iptables,
            lookback,
        ),
        daemon=True,
    )
    thread.start()
    return jsonify({
        "success": True,
        "job_id": drill_id,
        "mode": "drill",
        "message": "已同时启动防御监听与攻击扫描",
        **targets,
    })


@app.route("/api/defense", methods=["POST"])
def api_defense():
    """一键防御（异步）；可接续进行中的攻击，或自动触发攻防联调。"""
    data = request.get_json(silent=True) or {}
    cfg = load_ui_settings()
    duration = int(data.get("duration", cfg.get("defense_duration", 60)))
    apply_iptables = bool(data.get("apply_iptables", cfg.get("defense_apply_iptables", False)))
    lookback = int(data.get("lookback", 10))
    defense_host = data.get("defense_host") or cfg.get("local_ip", "127.0.0.1")
    pair_attack = bool(data.get("pair_attack", True))
    auto_drill = bool(data.get("auto_drill", True))

    attack_id, attack_info = _find_running_attack()
    if pair_attack and attack_id:
        defense_job_id = _start_defense_job(duration, apply_iptables, lookback, defense_host)
        return jsonify({
            "success": True,
            "job_id": defense_job_id,
            "mode": "pair",
            "message": f"已接续攻击任务，同步监听 {defense_host}",
            "attack_job_id": attack_id,
            "attack_target": attack_info.get("target"),
            "defense_host": defense_host,
        })

    if auto_drill:
        drill_data = {
            **data,
            "defense_host": defense_host,
            "target": data.get("target") or cfg.get("defense_attack_target") or defense_host,
        }
        resp = api_drill_with_data(drill_data, cfg)
        resp_data = resp.get_json()
        resp_data["mode"] = "drill"
        resp_data["message"] = "未检测到进行中的攻击，已自动启动攻防联调"
        return jsonify(resp_data)

    job_id = _start_defense_job(duration, apply_iptables, lookback, defense_host)
    return jsonify({
        "success": True,
        "job_id": job_id,
        "mode": "defense_only",
        "message": f"被动防御已启动（监听 {defense_host}）",
        "defense_host": defense_host,
    })


@app.route("/api/job/<job_id>", methods=["GET"])
def api_job_status(job_id: str):
    """查询后台任务状态。"""
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "任务不存在"}), 404
    return jsonify(job)


@app.route("/api/reports", methods=["GET"])
def api_list_reports():
    """列出最近报告目录。"""
    mode = request.args.get("mode", "all")
    reports = []

    if mode == "nmap_lab":
        nmap_lab_dir = REPORTS_DIR / "nmap_lab"
        if nmap_lab_dir.exists():
            for sub in sorted(nmap_lab_dir.iterdir(), reverse=True):
                if sub.is_dir():
                    reports.append({"name": f"nmap_lab/{sub.name}", "path": str(sub)})
                if len(reports) >= 20:
                    break
        return jsonify({"reports": reports})

    if REPORTS_DIR.exists():
        for p in sorted(REPORTS_DIR.iterdir(), reverse=True):
            if not p.is_dir():
                continue
            if mode == "attack" and not p.name.startswith("attack_"):
                continue
            if mode == "defense" and not p.name.startswith("defense_"):
                continue
            if p.name.startswith("attack_") or p.name.startswith("defense_"):
                reports.append({"name": p.name, "path": str(p)})
            if len(reports) >= 20:
                break
    return jsonify({"reports": reports})


@app.route("/reports/<path:filepath>")
def serve_report(filepath: str):
    """静态访问 reports 目录（查看 HTML/截图）。"""
    full_path = REPORTS_DIR / filepath
    if (
        filepath.endswith("scan.html")
        and not full_path.exists()
        and "nmap_lab" in filepath
    ):
        xml_path = full_path.parent / "scan.xml"
        if xml_path.exists():
            from nmap_lab.common import extract_hosts_from_xml, save_nmap_html

            xml_text = xml_path.read_text(encoding="utf-8")
            hosts = extract_hosts_from_xml(xml_text, "127.0.0.1")
            target = hosts[0].get("ip", "127.0.0.1") if hosts else "127.0.0.1"
            save_nmap_html(full_path.parent, hosts, target=target, nmap_command="nmap (from scan.xml)")
    return send_from_directory(REPORTS_DIR, filepath)


def _print_startup_banner(port: int = 8080) -> str:
    """打印访问地址；Flask 前端需在浏览器打开，不会自动弹窗。"""
    detected = detect_network()
    local_ip = detected.get("local_ip") or "127.0.0.1"
    urls = [
        f"http://127.0.0.1:{port}",
        f"http://{local_ip}:{port}",
    ]
    lines = [
        "",
        "=" * 56,
        "  InsightScan Web 控制台已启动",
        "  前端界面请在浏览器中打开（终端里不会显示页面）",
        "=" * 56,
    ]
    for url in urls:
        lines.append(f"  → {url}")
    lines.extend([
        "",
        "  四页：主动探测 | 被动防御 | IP 配置 | Nmap扫描与对比教学",
        "  推荐：一键攻防联调（单界面自动先防御后攻击）",
        "  按 Ctrl+C 停止服务",
        "=" * 56,
        "",
    ])
    print("\n".join(lines), flush=True)
    return urls[0]


def main():
    """启动 Web 服务。"""
    import os
    import webbrowser

    init_db()
    log = setup_logging()
    port = int(os.environ.get("INSIGHTSCAN_WEB_PORT", "8080"))
    local_url = _print_startup_banner(port)
    log.info("InsightScan Web 启动: http://0.0.0.0:%s", port)

    if os.environ.get("INSIGHTSCAN_NO_BROWSER", "").lower() not in ("1", "true", "yes"):
        try:
            webbrowser.open(local_url)
        except Exception:
            pass

    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
