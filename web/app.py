"""InsightScan Web 服务：三页界面 API。"""

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

from src.attack_mode import run_attack_mode
from src.defense_mode import run_defense_mode
from src.ui_config import detect_network, load_ui_settings, save_ui_settings
from src.utils import REPORTS_DIR, init_db, setup_logging

app = Flask(
    __name__,
    template_folder=str(_ROOT / "web" / "templates"),
    static_folder=str(_ROOT / "web" / "static"),
)

# 后台任务状态 {job_id: {...}}
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


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


def _run_attack_job(job_id: str, target: str, ports: str, run_perf: bool) -> None:
    """后台执行主动探测。"""
    log = setup_logging()
    try:
        _update_job(job_id, status="running", progress=f"正在扫描 {target} ...")
        result = run_attack_mode(
            target=target,
            ports=ports,
            run_perf=run_perf,
        )
        if "error" in result:
            _update_job(job_id, status="error", error=result["error"], progress="失败")
        else:
            _update_job(
                job_id,
                status="done",
                progress="完成",
                result={
                    "session_dir": result.get("session_dir"),
                    "task_id": result.get("task_id"),
                    "scan": result.get("scan"),
                    "reports": result.get("reports"),
                    "perf_benchmark": result.get("perf_benchmark"),
                },
            )
    except Exception as e:
        log.error("攻击任务异常: %s", e)
        _update_job(job_id, status="error", error=str(e), progress="异常")


def _run_defense_job(
    job_id: str, duration: int, apply_iptables: bool, lookback: int
) -> None:
    """后台执行被动防御。"""
    log = setup_logging()
    try:
        _update_job(job_id, status="running", progress="正在检测被扫描行为...")
        result = run_defense_mode(
            duration_sec=duration,
            apply_iptables=apply_iptables,
            lookback_minutes=lookback,
        )
        if "error" in result:
            _update_job(job_id, status="error", error=result["error"], progress="失败")
        else:
            _update_job(
                job_id,
                status="done",
                progress="完成",
                result={
                    "session_dir": result.get("session_dir"),
                    "scan_detection": result.get("scan_detection"),
                    "promiscuous": result.get("promiscuous"),
                    "iptables": result.get("iptables"),
                    "events_count": len(result.get("events", [])),
                },
            )
    except Exception as e:
        log.error("防御任务异常: %s", e)
        _update_job(job_id, status="error", error=str(e), progress="异常")


@app.route("/")
def index():
    """主页面（三 Tab）。"""
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
        }
        saved = save_ui_settings(updates)
        return jsonify({"success": True, "detected": detected, "config": saved})
    return jsonify({"success": True, "detected": detected})


@app.route("/api/attack", methods=["POST"])
def api_attack():
    """一键攻击 / 性能测试（异步）。"""
    data = request.get_json(silent=True) or {}
    cfg = load_ui_settings()
    run_perf = bool(data.get("perf", False))
    target = data.get("target") or (cfg["perf_target"] if run_perf else cfg["attack_target"])
    ports = data.get("ports") or (cfg["perf_ports"] if run_perf else cfg["attack_ports"])

    job_id = _create_job("perf" if run_perf else "attack")
    thread = threading.Thread(
        target=_run_attack_job,
        args=(job_id, target, ports, run_perf),
        daemon=True,
    )
    thread.start()
    return jsonify({
        "success": True,
        "job_id": job_id,
        "message": f"{'性能测试' if run_perf else '主动探测'}已启动",
        "target": target,
        "ports": ports,
    })


@app.route("/api/defense", methods=["POST"])
def api_defense():
    """一键防御（异步）。"""
    data = request.get_json(silent=True) or {}
    cfg = load_ui_settings()
    duration = int(data.get("duration", cfg.get("defense_duration", 60)))
    apply_iptables = bool(data.get("apply_iptables", cfg.get("defense_apply_iptables", False)))
    lookback = int(data.get("lookback", 60))

    job_id = _create_job("defense")
    thread = threading.Thread(
        target=_run_defense_job,
        args=(job_id, duration, apply_iptables, lookback),
        daemon=True,
    )
    thread.start()
    return jsonify({
        "success": True,
        "job_id": job_id,
        "message": "被动防御已启动",
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
        "  三页：主动探测 | 被动防御 | IP 配置",
        "  防御实验：另开终端/标签页同时跑攻击 + 防御",
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
