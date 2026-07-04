"""主动探测模式（攻击方视角）：全面扫描目标 + AI 分析 + 报告 + 截图。"""

import json
import sys
from pathlib import Path
from typing import Any, Optional

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.ai_analyzer import AIAnalyzer
from src.perf_benchmark import run_thread_benchmark
from src.protocol_analyzer import capture_with_tshark, generate_protocol_diagrams
from src.report_generator import ReportGenerator
from src.scan_engine import ScanEngine
from src.session_paths import create_session_dir
from src.utils import get_setting, init_db, setup_logging, validate_ip
from src.visual_export import save_port_bar_chart, save_risk_pie_chart


# 项目支持的全部扫描攻击类型
ATTACK_SCAN_TYPES: list[str] = ["connect", "syn", "fin"]
ATTACK_TYPE_LABELS: dict[str, str] = {
    "connect": "TCP Connect 扫描",
    "syn": "SYN 半开扫描",
    "fin": "FIN 隐蔽扫描",
}


def run_attack_suite(
    target: str,
    ports: Optional[str] = None,
    scan_types: Optional[list[str]] = None,
    random_subset: bool = False,
    run_protocol: bool = True,
) -> dict[str, Any]:
    """
    多类型攻击套件：依次执行 connect / syn / fin 扫描。

    Args:
        target: 目标 IP 或 CIDR。
        ports: 端口范围。
        scan_types: 指定扫描类型列表；为空则使用全部或随机子集。
        random_subset: True 时随机选择 1~N 种扫描类型（用于防御联调）。
        run_protocol: 是否生成协议分析图。

    Returns:
        会话结果字典。
    """
    import random

    log = setup_logging()
    init_db()

    ip_check = validate_ip(target)
    if not ip_check.get("valid"):
        return {"error": ip_check.get("error")}

    ports = ports or get_setting("scan.default_ports", "1-1000")
    all_types = [t for t in ATTACK_SCAN_TYPES if t in (scan_types or ATTACK_SCAN_TYPES)]
    if not scan_types and random_subset:
        count = random.randint(1, len(ATTACK_SCAN_TYPES))
        selected = random.sample(ATTACK_SCAN_TYPES, count)
    elif scan_types:
        selected = scan_types
    else:
        selected = list(ATTACK_SCAN_TYPES)

    session_dir = create_session_dir("attack")
    screenshots = session_dir / "screenshots"
    engine = ScanEngine()

    log.info("=== 攻击套件 ATTACK SUITE ===")
    log.info("目标: %s | 端口: %s | 类型: %s", target, ports, selected)

    suite_runs: list[dict[str, Any]] = []
    best_task_id: Optional[int] = None
    best_ports = -1
    total_duration = 0.0

    for scan_type in selected:
        label = ATTACK_TYPE_LABELS.get(scan_type, scan_type)
        log.info("[套件] %s (%s)...", label, scan_type)
        scan_result = engine.scan(target, scan_type=scan_type, ports=ports)
        entry: dict[str, Any] = {
            "scan_type": scan_type,
            "label": label,
            "task_id": scan_result.get("task_id"),
            "success": "error" not in scan_result,
            "error": scan_result.get("error"),
            "duration": scan_result.get("duration"),
            "stats": scan_result.get("stats"),
        }
        suite_runs.append(entry)
        if "error" not in scan_result:
            open_ports = scan_result.get("stats", {}).get("total_ports", 0)
            total_duration += float(scan_result.get("duration") or 0)
            if open_ports >= best_ports:
                best_ports = open_ports
                best_task_id = scan_result["task_id"]

    if not best_task_id:
        return {
            "error": "所有扫描类型均失败（SYN/FIN 需 sudo）",
            "session_dir": str(session_dir),
            "attack_suite": suite_runs,
            "scan_types_used": selected,
        }

    summary: dict[str, Any] = {
        "mode": "attack",
        "target": target,
        "session_dir": str(session_dir),
        "screenshots_dir": str(screenshots),
        "task_id": best_task_id,
        "attack_suite": suite_runs,
        "scan_types_used": selected,
        "random_subset": random_subset,
        "scan": {
            "duration": round(total_duration, 2),
            "hosts": suite_runs[-1].get("stats", {}).get("total_hosts", 0),
            "ports": best_ports,
        },
    }

    log.info("[2/5] AI 风险分析（基于最佳扫描 task_id=%s）...", best_task_id)
    ai_result = AIAnalyzer().analyze_task(best_task_id)
    summary["ai_analysis"] = {
        "total_ports": ai_result.get("total_ports", 0),
        "cache_hits": ai_result.get("cache_hits", 0),
        "api_calls": ai_result.get("api_calls", 0),
        "local_rules": ai_result.get("local_rules", 0),
        "api_key_status": ai_result.get("api_key_status", "未知"),
        "model": ai_result.get("model", ""),
    }

    log.info("[3/5] 生成报告...")
    gen = ReportGenerator()
    data = gen._load_task_data(best_task_id)
    screenshots_paths = {}
    if "error" not in data:
        counts = gen._count_risks(data["results"])
        screenshots_paths = {
            "risk_pie": save_risk_pie_chart(
                counts, screenshots / "risk_distribution.png", "Target Risk Distribution"
            ),
            "open_ports": save_port_bar_chart(
                data["results"], screenshots / "open_ports.png"
            ),
        }

    md = gen.generate(
        best_task_id, fmt="markdown",
        output_path=str(session_dir / "attack_report.md"),
        scan_duration=total_duration,
        ai_stats=summary.get("ai_analysis"),
    )
    html = gen.generate(
        best_task_id, fmt="html",
        output_path=str(session_dir / "attack_report.html"),
        session_dir=session_dir,
        scan_duration=total_duration,
        ai_stats=summary.get("ai_analysis"),
    )
    summary["reports"] = {"markdown": md.get("file_path"), "html": html.get("file_path")}

    suite_note = _render_suite_section(suite_runs, selected, random_subset)
    md_path = session_dir / "attack_report.md"
    if md_path.exists():
        md_path.write_text(md_path.read_text(encoding="utf-8") + suite_note, encoding="utf-8")

    if screenshots_paths:
        summary["screenshots"] = screenshots_paths

    if run_protocol:
        proto = generate_protocol_diagrams(session_dir)
        tshark = capture_with_tshark(session_dir)
        summary["protocol"] = {**proto, "tshark": tshark}

    findings = _build_findings(data if "error" not in data else {"results": []})
    summary["findings"] = findings
    (session_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (session_dir / "README.txt").write_text(
        _render_attack_readme(summary, findings), encoding="utf-8"
    )
    log.info("=== 攻击套件完成 === types=%s", selected)
    return summary


def _render_suite_section(
    runs: list[dict[str, Any]], selected: list[str], random_subset: bool
) -> str:
    """追加攻击套件明细到报告末尾。"""
    mode = "随机子集" if random_subset else "全套"
    lines = [
        "",
        "## 7. 攻击套件明细",
        "",
        f"- 执行模式: {mode}",
        f"- 扫描类型: {', '.join(selected)}",
        "",
        "| 类型 | 说明 | 结果 | 耗时 | 开放端口 |",
        "|------|------|------|------|---------|",
    ]
    for r in runs:
        st = r.get("scan_type", "")
        ok = "成功" if r.get("success") else f"失败: {r.get('error', '')[:40]}"
        dur = r.get("duration", "—")
        ports = r.get("stats", {}).get("total_ports", 0) if r.get("stats") else "—"
        lines.append(
            f"| {st} | {r.get('label', st)} | {ok} | {dur}s | {ports} |"
        )
    lines.append("")
    lines.append("> SYN/FIN 扫描需 root 权限；失败时可使用 `sudo python3 main.py --attack ...`")
    lines.append("")
    return "\n".join(lines)


def run_attack_mode(
    target: str,
    ports: Optional[str] = None,
    scan_type: Optional[str] = None,
    run_perf: bool = False,
    run_protocol: bool = True,
) -> dict[str, Any]:
    """
    主动探测完整流程：扫描 → AI 分析 → 报告 → 截图。

    Args:
        target: 目标 IP 或 CIDR。
        ports: 端口范围，默认 1-1000。
        scan_type: connect/syn/fin。
        run_perf: 是否运行多线程性能对比实验。
        run_protocol: 是否生成协议分析图。

    Returns:
        会话结果字典，含 session_dir。
    """
    log = setup_logging()
    init_db()

    ip_check = validate_ip(target)
    if not ip_check.get("valid"):
        return {"error": ip_check.get("error")}

    session_dir = create_session_dir("attack")
    screenshots = session_dir / "screenshots"
    ports = ports or get_setting("scan.default_ports", "1-1000")
    scan_type = scan_type or get_setting("scan.default_scan_type", "connect")

    log.info("=== 主动探测模式 ATTACK ===")
    log.info("目标: %s | 端口: %s | 输出: %s", target, ports, session_dir)

    summary: dict[str, Any] = {
        "mode": "attack",
        "target": target,
        "session_dir": str(session_dir),
        "screenshots_dir": str(screenshots),
    }

    # 1. 扫描
    log.info("[1/5] Nmap 扫描...")
    engine = ScanEngine()
    scan_result = engine.scan(target, scan_type=scan_type, ports=ports)
    if "error" in scan_result:
        return {"error": scan_result["error"], "session_dir": str(session_dir)}
    task_id = scan_result["task_id"]
    summary["task_id"] = task_id
    summary["scan"] = {
        "duration": scan_result.get("duration"),
        "hosts": scan_result["stats"]["total_hosts"],
        "ports": scan_result["stats"]["total_ports"],
    }

    # 2. AI 分析
    log.info("[2/5] AI 风险分析...")
    ai_result = AIAnalyzer().analyze_task(task_id)
    summary["ai_analysis"] = {
        "total_ports": ai_result.get("total_ports", 0),
        "cache_hits": ai_result.get("cache_hits", 0),
        "api_calls": ai_result.get("api_calls", 0),
        "local_rules": ai_result.get("local_rules", 0),
        "api_key_status": ai_result.get("api_key_status", "未知"),
        "model": ai_result.get("model", ""),
    }

    # 3. 报告（先生成图表，再生成 HTML 以便嵌入截图）
    log.info("[3/5] 生成报告...")
    gen = ReportGenerator()
    data = gen._load_task_data(task_id)
    screenshots_paths = {}
    if "error" not in data:
        counts = gen._count_risks(data["results"])
        screenshots_paths = {
            "risk_pie": save_risk_pie_chart(
                counts, screenshots / "risk_distribution.png", "Target Risk Distribution"
            ),
            "open_ports": save_port_bar_chart(
                data["results"], screenshots / "open_ports.png"
            ),
        }

    scan_duration = scan_result.get("duration")
    md = gen.generate(
        task_id, fmt="markdown",
        output_path=str(session_dir / "attack_report.md"),
        scan_duration=scan_duration,
        ai_stats=summary.get("ai_analysis"),
    )
    html = gen.generate(
        task_id, fmt="html",
        output_path=str(session_dir / "attack_report.html"),
        session_dir=session_dir,
        scan_duration=scan_duration,
        ai_stats=summary.get("ai_analysis"),
    )
    summary["reports"] = {
        "markdown": md.get("file_path"),
        "html": html.get("file_path"),
    }

    # 4. 截图路径汇总
    log.info("[4/5] 截图已生成...")
    if screenshots_paths:
        summary["screenshots"] = screenshots_paths

    # 5. 协议分析 + 性能实验（可选）
    log.info("[5/5] 协议分析 & 性能实验...")
    if run_protocol:
        proto = generate_protocol_diagrams(session_dir)
        tshark = capture_with_tshark(session_dir)
        summary["protocol"] = {**proto, "tshark": tshark}

    if run_perf:
        perf_target = target if "/" in target else get_setting(
            "security.perf_test_cidr", "192.168.1.0/24"
        )
        log.info("性能实验目标: %s（C段扫描可能耗时较长）", perf_target)
        summary["perf_benchmark"] = run_thread_benchmark(
            perf_target, ports="22,80,443", session_dir=session_dir
        )

    # 写入探测摘要
    findings = _build_findings(data if "error" not in data else {"results": []})
    summary["findings"] = findings
    summary_path = session_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    readme = _render_attack_readme(summary, findings)
    (session_dir / "README.txt").write_text(readme, encoding="utf-8")

    log.info("=== 主动探测完成 ===")
    log.info("报告目录: %s", session_dir)
    return summary


def _build_findings(data: dict[str, Any]) -> list[dict[str, Any]]:
    """整理探测发现：开放端口、服务、版本、风险。"""
    findings = []
    for r in data.get("results", []):
        detail = r.get("risk_detail", {})
        findings.append(
            {
                "host": r.get("host_ip"),
                "port": r.get("port"),
                "service": r.get("service_name"),
                "version": r.get("service_version") or r.get("banner"),
                "risk_level": r.get("risk_level", "信息"),
                "threat_type": detail.get("threat_type", ""),
                "recommendation": detail.get("recommendation", ""),
            }
        )
    return findings


def _render_attack_readme(summary: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    """生成 attack 会话说明文件。"""
    lines = [
        "InsightScan - 主动探测报告 (ATTACK MODE)",
        "=" * 50,
        f"目标: {summary.get('target')}",
        f"任务ID: {summary.get('task_id')}",
        f"扫描耗时: {summary.get('scan', {}).get('duration')}s",
        "",
        "探测内容:",
        "  - 开放端口 / 运行服务 / 版本信息 / 漏洞风险",
        "",
        "文件列表:",
        "  attack_report.md / .html  - 完整报告",
        "  screenshots/              - 风险饼图、端口图、协议分析图",
        "  summary.json              - 结构化数据",
        "",
        "发现摘要:",
    ]
    for f in findings[:20]:
        lines.append(
            f"  {f['host']}:{f['port']} {f['service']} [{f['risk_level']}] {f.get('version', '')}"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="InsightScan Attack Mode")
    p.add_argument("-t", "--target", required=True)
    p.add_argument("--ports", default=None)
    p.add_argument("--scan-type", default="connect")
    p.add_argument("--perf", action="store_true", help="运行多线程性能实验")
    args = p.parse_args()
    result = run_attack_mode(args.target, args.ports, args.scan_type, run_perf=args.perf)
    print(json.dumps(result, ensure_ascii=False, indent=2))
