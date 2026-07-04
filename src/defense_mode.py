"""被动防御模式（防守方视角）：检测被扫描、混杂模式、自动 iptables 防御。"""

import json
import sys
import time
from pathlib import Path
from typing import Any, Optional

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.scan_engine import ScanEngine
from src.security_tools import IptablesDefense, PromiscModeDetector, ScanBehaviorDetector
from src.session_paths import create_session_dir
from src.ui_config import load_ui_settings
from src.utils import get_setting, init_db, now_local_str, setup_logging
from src.visual_export import save_attack_timeline, save_promisc_chart


def run_defense_mode(
    duration_sec: int = 0,
    apply_iptables: bool = False,
    lookback_minutes: Optional[int] = None,
) -> dict[str, Any]:
    """
    被动防御完整流程：扫描检测 → 混杂模式 → 自查端口 → iptables → 报告。

    Args:
        duration_sec: 持续监控秒数，0 表示单次检测。
        apply_iptables: 是否自动部署 iptables（需 sudo）。
        lookback_minutes: 日志回溯分钟数。

    Returns:
        会话结果字典。
    """
    log = setup_logging()
    init_db()

    session_dir = create_session_dir("defense")
    screenshots = session_dir / "screenshots"

    log.info("=== 被动防御模式 DEFENSE ===")
    log.info("输出目录: %s", session_dir)
    if duration_sec > 0:
        log.info("持续监控 %d 秒...", duration_sec)

    summary: dict[str, Any] = {
        "mode": "defense",
        "session_dir": str(session_dir),
        "screenshots_dir": str(screenshots),
        "monitor_duration_sec": duration_sec,
    }
    all_events: list[dict[str, Any]] = []
    local_ips = _resolve_local_ips()
    local_scan: dict[str, Any] = {}

    rounds = max(1, duration_sec // 10) if duration_sec > 0 else 1
    for i in range(rounds):
        if rounds > 1:
            log.info("监控轮次 %d/%d", i + 1, rounds)

        # 1. 扫描行为检测（syslog + 扫描数据库）
        log.info("[1/4] 检测是否被扫描...")
        scan_detect = ScanBehaviorDetector(
            lookback_minutes=lookback_minutes,
            local_ips=local_ips,
        ).detect()
        events = scan_detect.get("events", [])
        all_events.extend(events)

        # 2. 混杂模式检测
        log.info("[2/4] 检测网卡混杂模式...")
        promisc = PromiscModeDetector().detect()

        # 3. 自查本机端口（仅在最后一轮，避免拖慢监控）
        if i == rounds - 1:
            log.info("[3/4] 自查本机暴露端口...")
            local_scan = ScanEngine().scan(
                "127.0.0.1",
                scan_type="connect",
                ports=get_setting("scan.default_ports", "1-1000"),
            )

        if duration_sec > 0 and i < rounds - 1:
            time.sleep(10)

    # 去重事件
    unique_events = _dedupe_events(all_events)
    scan_detect["events"] = unique_events
    scan_detect["total_events"] = len(unique_events)
    task_id = local_scan.get("task_id")

    # 4. iptables 自动化防御
    log.info("[4/4] 生成 iptables 防御规则...")
    scanner_ips = list({e["source_ip"] for e in unique_events if e.get("source_ip") != "unknown"})
    iptables = IptablesDefense()
    rules_result = iptables.generate_rules(
        task_id=task_id,
        scanner_ips=scanner_ips,
        block_high_risk_inbound=True,
    )
    script_path = session_dir / "iptables_defense.sh"
    if "script" in rules_result:
        iptables.save_script(rules_result["script"], script_path)

    apply_result = {"dry_run": True}
    if apply_iptables and "script" in rules_result:
        apply_result = iptables.apply_rules(script_path, dry_run=False)

    # 截图
    summary["screenshots"] = {
        "attack_timeline": save_attack_timeline(
            unique_events, screenshots / "attack_timeline.png"
        ),
        "promisc_status": save_promisc_chart(
            promisc.get("interfaces", []), screenshots / "promisc_mode_status.png"
        ),
    }

    # 报告
    report_md = _render_defense_report(
        scan_detect, promisc, local_scan, rules_result, unique_events, duration_sec
    )
    md_path = session_dir / "defense_report.md"
    md_path.write_text(report_md, encoding="utf-8")

    summary.update(
        {
            "scan_detection": {
                "total_events": len(unique_events),
                "scan_events": scan_detect.get("summary", {}).get("scan_events", 0),
                "under_attack": scan_detect.get("summary", {}).get("is_under_attack", False),
                "top_sources": scan_detect.get("summary", {}).get("top_sources", []),
                "detection_sources": scan_detect.get("detection_sources", {}),
            },
            "promiscuous": promisc,
            "local_scan_task_id": task_id,
            "iptables": {
                "script": str(script_path),
                "rule_count": rules_result.get("rule_count", 0),
                "apply_result": apply_result,
            },
            "events": unique_events[:50],
        }
    )

    (session_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
    (session_dir / "scan_events.json").write_text(
        json.dumps(unique_events, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    log.info("=== 被动防御完成 ===")
    log.info("被扫描事件: %d | 混杂模式告警: %s | iptables规则: %d",
             len(unique_events), promisc.get("alert"), rules_result.get("rule_count", 0))
    log.info("报告目录: %s", session_dir)
    return summary


def _resolve_local_ips() -> list[str]:
    """解析本机 IP 列表，供扫描数据库检测使用。"""
    cfg = load_ui_settings()
    ips = [cfg.get("local_ip", ""), "127.0.0.1"]
    return [ip for ip in ips if ip]


def _dedupe_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """事件去重。"""
    seen: set[str] = set()
    result = []
    for e in events:
        key = f"{e.get('source_ip')}:{e.get('attack_type')}:{e.get('log_line', '')[:60]}"
        if key not in seen:
            seen.add(key)
            result.append(e)
    return result


def _render_defense_report(
    scan_detect: dict[str, Any],
    promisc: dict[str, Any],
    local_scan: dict[str, Any],
    rules: dict[str, Any],
    events: list[dict[str, Any]],
    duration_sec: int = 0,
) -> str:
    """生成防御模式 Markdown 报告。"""
    summary = scan_detect.get("summary", {})
    sources = scan_detect.get("detection_sources", {})
    lines = [
        "# InsightScan 被动防御报告 (DEFENSE MODE)",
        "",
        "## 1. 被扫描检测",
        "",
        f"- 持续监控时长: **{duration_sec} 秒**" if duration_sec > 0 else "- 持续监控: 单次检测",
        f"- 日志回溯窗口: 最近 {scan_detect.get('lookback_minutes', 10)} **分钟**（查 syslog/UFW）",
        f"- 数据库联动: 检测 InsightScan/Nmap 扫描记录（Connect 扫描主要靠此通道）",
        f"- 检测时间: {scan_detect.get('checked_at', now_local_str())}（本地时间）",
        f"- 检测到事件数: {scan_detect.get('total_events', 0)}",
        f"- 明确扫描行为: {summary.get('scan_events', 0)} 次",
        f"- syslog 事件: {sources.get('syslog_events', 0)} | 数据库事件: {sources.get('database_events', 0)}",
        f"- 防火墙拦截(UFW): {summary.get('attack_types', {}).get('Blocked Probe (UFW)', 0)} 次",
        f"- 是否遭受扫描: **{'是 ⚠️' if summary.get('scan_events', 0) > 0 else '未发现明确扫描工具特征'}**",
        "",
    ]

    if summary.get("top_sources"):
        lines.append("### 攻击来源 TOP")
        lines.append("")
        lines.append("| 来源 IP | 次数 |")
        lines.append("|---------|------|")
        for ip, count in summary["top_sources"]:
            lines.append(f"| {ip} | {count} |")
        lines.append("")

    if events:
        lines.extend(["### 攻击事件详情", ""])
        for e in events[:15]:
            method = e.get("detection_method", "syslog")
            lines.append(
                f"- **{e.get('timestamp')}** `{e.get('source_ip')}` "
                f"{e.get('attack_type')} [{e.get('severity')}] ({method})"
            )
        lines.append("")

    lines.extend([
        "## 2. 网卡混杂模式检测",
        "",
        f"- 告警: **{'是 ⚠️ 可能存在嗅探/中间人攻击' if promisc.get('alert') else '否 ✅'}**",
        f"- 说明: {promisc.get('message', '')}",
        "",
        "| 网卡 | 混杂模式 |",
        "|------|---------|",
    ])
    for iface in promisc.get("interfaces", []):
        status = "是 ⚠️" if iface.get("promiscuous") else "否"
        lines.append(f"| {iface.get('interface')} | {status} |")
    lines.append("")

    lines.extend([
        "## 3. 本机高危端口暴露",
        "",
        f"- 开放端口数: {local_scan.get('stats', {}).get('total_ports', 0)}",
        f"- 扫描任务 ID: {local_scan.get('task_id', 'N/A')}",
        "",
        "## 4. iptables 自动化防御",
        "",
        f"- 生成规则数: {rules.get('rule_count', 0)}",
        "- 规则脚本: `iptables_defense.sh`",
        "- 部署命令: `sudo bash iptables_defense.sh`",
        "",
        "## 5. 截图",
        "",
        "- screenshots/attack_timeline.png - 攻击事件时间线",
        "- screenshots/promisc_mode_status.png - 网卡混杂模式状态",
        "",
    ])
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="InsightScan Defense Mode")
    p.add_argument("--duration", type=int, default=0, help="持续监控秒数")
    p.add_argument("--apply-iptables", action="store_true", help="自动部署 iptables(需sudo)")
    p.add_argument("--lookback", type=int, default=None, help="日志回溯分钟")
    args = p.parse_args()
    result = run_defense_mode(
        duration_sec=args.duration,
        apply_iptables=args.apply_iptables,
        lookback_minutes=args.lookback,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
