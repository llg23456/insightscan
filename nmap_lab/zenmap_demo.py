"""Zenmap 图形界面效果模拟：CLI 双栏展示 + XML 保存 + InsightScan 对比。"""

import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from nmap_lab.common import (
    DEFAULT_DEMO_TARGET,
    DEFAULT_ZENMAP_PORTS,
    ensure_lab_dir,
    insightscan_comparison_static,
    validate_ports,
    validate_target,
)
from nmap_lab.nmap_runner import execute_nmap_scan


def run_zenmap_scan(
    target: str,
    ports: str = DEFAULT_ZENMAP_PORTS,
) -> dict[str, Any]:
    """
    执行 Zenmap 风格扫描并返回结构化结果。

    Args:
        target: 目标 IP。
        ports: 端口列表，默认实验指导书常见端口。

    Returns:
        含 hosts、duration、xml_path、nmap_command 等字段的字典；失败含 error。
    """
    t_check = validate_target(target)
    if not t_check.get("valid"):
        return {"error": t_check.get("error", "无效目标")}

    p_check = validate_ports(ports)
    if not p_check.get("valid"):
        return {"error": p_check.get("error", "无效端口")}

    target = t_check["target"]
    ports = p_check["ports"]
    session_dir = ensure_lab_dir("zenmap")
    nmap_args = f"-sT -sV -p {ports} -T4 --version-intensity 5"
    nmap_command = f"nmap {nmap_args} {target}"

    start = time.perf_counter()
    scan_result = execute_nmap_scan(
        target=target,
        arguments=nmap_args,
        session_dir=session_dir,
        prefer_sudo=False,
    )
    duration = scan_result.get("duration") or round(time.perf_counter() - start, 2)

    if not scan_result.get("success"):
        return {
            "error": scan_result.get("error", "Nmap 扫描失败"),
            "hint": scan_result.get("hint"),
            "nmap_command": nmap_command,
        }

    hosts = scan_result.get("hosts", [])
    xml_path = scan_result.get("xml_path", "")
    try:
        cli_text = format_zenmap_cli(
            target=target,
            ports=ports,
            nmap_command=nmap_command,
            duration=duration,
            hosts=hosts,
            scanned_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        comparison = insightscan_comparison_static()
        return {
            "mode": "zenmap",
            "target": target,
            "ports": ports,
            "duration": duration,
            "nmap_args": nmap_args,
            "nmap_command": nmap_command,
            "hosts": hosts,
            "session_dir": str(session_dir),
            "report_web_path": f"nmap_lab/{session_dir.name}",
            "xml_path": str(xml_path),
            "xml_url_hint": f"reports/nmap_lab/{session_dir.name}/scan.html",
            "html_path": str(session_dir / "scan.html"),
            "cli_output": cli_text,
            "comparison": comparison,
            "open_hint": "浏览器可打开 scan.html 查看；scan.xml 供 Zenmap 导入或下载存档",
        }
    except Exception as e:
        return {"error": f"格式化输出失败: {e}", "nmap_command": nmap_command}


def format_zenmap_cli(
    target: str,
    ports: str,
    nmap_command: str,
    duration: float,
    hosts: list[dict[str, Any]],
    scanned_at: str,
) -> str:
    """
    将扫描结果格式化为 Zenmap 风格的双栏 CLI 文本。

    Args:
        target: 目标 IP。
        ports: 端口字符串。
        nmap_command: 等价 Nmap 命令。
        duration: 耗时秒数。
        hosts: 解析后的主机列表。
        scanned_at: 扫描时间字符串。

    Returns:
        多行 ASCII 文本。
    """
    lines = [
        "╔══════════════════════════════════════════════════════════════════╗",
        "║           🗺️  Zenmap 风格扫描结果（InsightScan 教学演示）          ║",
        "╚══════════════════════════════════════════════════════════════════╝",
        f"  🎯 目标: {target}    📡 端口: {ports}",
        f"  ⏱️  耗时: {duration}s    🕐 时间: {scanned_at}",
        f"  💻 命令: {nmap_command}",
        "",
    ]

    host = hosts[0] if hosts else {}
    os_label = host.get("os_name") or "未知"
    os_acc = host.get("os_accuracy", 0)
    state_emoji = "🟢" if host.get("state") == "up" else "🔴"

    left_header = "🖥️  主机列表面板"
    right_header = "🔌 端口 / 服务标签"
    sep = "─" * 34

    lines.append(f"┌{'─' * 34}┬{'─' * 34}┐")
    lines.append(f"│ {left_header:<32} │ {right_header:<32} │")
    lines.append(f"├{sep}┼{sep}┤")

    left_col = [
        f"{state_emoji} {host.get('ip', target)}",
        f"   状态: {host.get('state', 'unknown')}",
        f"   OS: {os_label}",
    ]
    if os_acc:
        left_col.append(f"   置信度: {os_acc}%")

    port_lines = []
    for p in host.get("ports", []):
        if p.get("state") not in ("open", "open|filtered"):
            continue
        svc = p.get("service") or "-"
        ver = p.get("version") or ""
        prod = p.get("product") or ""
        detail = " ".join(x for x in (prod, ver) if x).strip() or "-"
        port_lines.append(
            f"   {p.get('port')}/{p.get('protocol', 'tcp')}  "
            f"{p.get('state', '')}  {svc}  {detail}"
        )
    if not port_lines:
        port_lines = ["   （未发现开放端口）"]

    max_rows = max(len(left_col), len(port_lines))
    for i in range(max_rows):
        left = left_col[i] if i < len(left_col) else ""
        right = port_lines[i] if i < len(port_lines) else ""
        lines.append(f"│ {left:<32} │ {right:<32} │")

    lines.append(f"└{'─' * 34}┴{'─' * 34}┘")

    services = host.get("services") or []
    if services:
        lines.append("")
        lines.append("📦 服务标签")
        lines.append("─" * 40)
        for s in services:
            extra = f" ({s['extra']})" if s.get("extra") else ""
            lines.append(
                f"  • {s.get('product') or '未知产品'} "
                f"v{s.get('version') or '?'} @ 端口 {s.get('port')}{extra}"
            )

    return "\n".join(lines)


def print_insightscan_comparison(result: dict[str, Any]) -> None:
    """
    打印 Zenmap 与 InsightScan 的对比说明。

    Args:
        result: run_zenmap_scan 的返回字典。
    """
    comp = result.get("comparison") or insightscan_comparison_static()
    print("\n" + "═" * 60)
    print("📊 Zenmap/Nmap 原始输出  vs  InsightScan AI 增强")
    print("═" * 60)
    for side in ("zenmap", "insightscan"):
        block = comp.get(side, {})
        print(f"\n▶ {block.get('title', side)}")
        for pt in block.get("points", []):
            print(f"   • {pt}")
    print(f"\n💡 {comp.get('summary', '')}")
    if result.get("xml_path"):
        print(f"\n📁 XML 已保存: {result['xml_path']}")
        print(f"   {result.get('open_hint', '')}")


def main() -> None:
    """交互式 CLI 入口：输入目标 IP，默认扫描 21,23,80,3306。"""
    print("=" * 56)
    print("  InsightScan · Zenmap 教学演示")
    print("=" * 56)
    target = input(f"目标 IP [{DEFAULT_DEMO_TARGET}]: ").strip() or DEFAULT_DEMO_TARGET
    ports = input(f"端口 [{DEFAULT_ZENMAP_PORTS}]: ").strip() or DEFAULT_ZENMAP_PORTS

    print("\n⏳ 正在扫描...\n")
    result = run_zenmap_scan(target, ports)

    if "error" in result:
        print(f"❌ {result['error']}")
        return

    print(result.get("cli_output", ""))
    print_insightscan_comparison(result)


if __name__ == "__main__":
    main()
