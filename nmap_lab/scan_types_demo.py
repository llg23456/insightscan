"""扫描方式对比演示：TCP Connect / SYN / OS 识别 / 全端口扫描。"""

import sys
from typing import Any

_ROOT = __import__("pathlib").Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from nmap_lab.common import (
    DEFAULT_DEMO_TARGET,
    DEFAULT_ZENMAP_PORTS,
    FULL_PORT_RANGE,
    comparison_table_rows,
    ensure_lab_dir,
    root_required_hint,
    validate_ports,
    validate_target,
)
from nmap_lab.nmap_runner import execute_nmap_scan


def _run_nmap_scan(
    target: str,
    arguments: str,
    session_prefix: str,
    xml_name: str = "scan.xml",
    prefer_sudo: bool = False,
) -> dict[str, Any]:
    """
    执行单次 Nmap 扫描并保存 XML。

    Args:
        target: 目标 IP。
        arguments: Nmap 参数字符串。
        session_prefix: 输出目录前缀。
        xml_name: XML 文件名。
        prefer_sudo: SYN/OS 等特权扫描优先 sudo nmap。

    Returns:
        含 hosts、duration、xml_path 的字典；失败含 error。
    """
    session_dir = ensure_lab_dir(session_prefix)
    return execute_nmap_scan(
        target=target,
        arguments=arguments,
        session_dir=session_dir,
        prefer_sudo=prefer_sudo,
    )


def demo_tcp_connect(
    target: str,
    ports: str = DEFAULT_ZENMAP_PORTS,
) -> dict[str, Any]:
    """
    TCP Connect 扫描演示（-sT）：完成三次握手，可靠但易留日志。

    Args:
        target: 目标 IP。
        ports: 端口范围。

    Returns:
        演示结果字典。
    """
    check = validate_target(target)
    if not check.get("valid"):
        return {"mode": "connect", "error": check.get("error")}
    pcheck = validate_ports(ports)
    if not pcheck.get("valid"):
        return {"mode": "connect", "error": pcheck.get("error")}

    target = check["target"]
    ports = pcheck["ports"]
    args = f"-sT -p {ports} -T4"
    result = _run_nmap_scan(target, args, "connect")
    result.update({
        "mode": "connect",
        "title": "TCP Connect 扫描 (-sT)",
        "principle": "完成 TCP 三次握手，根据端口响应判断开放/关闭。",
        "features": "结果可靠，不需要 root，但会在目标日志中留下连接记录。",
        "privilege": "普通用户",
    })
    return result


def demo_tcp_syn(
    target: str,
    ports: str = DEFAULT_ZENMAP_PORTS,
) -> dict[str, Any]:
    """
    TCP SYN 半开扫描演示（-sS）：快速隐蔽，需要 root。

    Args:
        target: 目标 IP。
        ports: 端口范围。

    Returns:
        演示结果字典；权限不足时 success=False 并含 hint。
    """
    check = validate_target(target)
    if not check.get("valid"):
        return {"mode": "syn", "error": check.get("error")}
    pcheck = validate_ports(ports)
    if not pcheck.get("valid"):
        return {"mode": "syn", "error": pcheck.get("error")}

    target = check["target"]
    ports = pcheck["ports"]
    args = f"-sS -p {ports} -T4"
    result = _run_nmap_scan(target, args, "syn", prefer_sudo=True)
    result.update({
        "mode": "syn",
        "title": "TCP SYN 半开扫描 (-sS)",
        "principle": "只发送 SYN 包，不完成三次握手，根据 SYN-ACK/RST 判断端口状态。",
        "features": "速度快、较隐蔽，但需要 root 权限。",
        "privilege": "root / sudo",
    })
    return result


def demo_os_detection(target: str) -> dict[str, Any]:
    """
    操作系统识别演示（-O -T5），对应实验指导书 nmap -O -T5 目标。

    Args:
        target: 目标 IP。

    Returns:
        含 os_matches 的演示结果。
    """
    check = validate_target(target)
    if not check.get("valid"):
        return {"mode": "os", "error": check.get("error")}

    target = check["target"]
    args = "-O -T5"
    result = _run_nmap_scan(target, args, "os", prefer_sudo=True)
    host = (result.get("hosts") or [{}])[0]
    os_matches = []
    if host.get("os_name"):
        os_matches.append({
            "name": host["os_name"],
            "accuracy": host.get("os_accuracy", 0),
        })

    result.update({
        "mode": "os",
        "title": "操作系统识别 (-O)",
        "principle": "通过 TCP/IP 协议栈指纹特征推断目标操作系统。",
        "features": "实验命令: nmap -O -T5 目标；无结果时检查 root 权限与目标可达性。",
        "privilege": "root / sudo",
        "os_matches": os_matches,
        "no_result_hint": (
            "未识别到操作系统：请确认使用 sudo，且目标在线并响应探测。"
            if not os_matches and result.get("success")
            else ""
        ),
    })
    return result


def demo_full_port_scan(target: str) -> dict[str, Any]:
    """
    全端口扫描演示：说明 1-65535，实际扫描 1-1000 以控制耗时。

    Args:
        target: 目标 IP。

    Returns:
        含开放端口数量与列表的结果。
    """
    check = validate_target(target)
    if not check.get("valid"):
        return {"mode": "full_port", "error": check.get("error")}

    target = check["target"]
    args = f"-sT -p {FULL_PORT_RANGE} -T4"
    result = _run_nmap_scan(target, args, "full_port")
    open_list = [
        f"{p['port']}/{p.get('protocol', 'tcp')}"
        for p in result.get("open_ports", [])
    ]
    result.update({
        "mode": "full_port",
        "title": "全端口扫描",
        "principle": f"实验指导书命令: nmap -p 1-65535 {target}；演示使用 -p {FULL_PORT_RANGE} 避免过慢。",
        "features": f"本次扫描范围 {FULL_PORT_RANGE}，统计开放端口数量与列表。",
        "privilege": "普通用户（Connect 模式）",
        "port_range": FULL_PORT_RANGE,
        "open_port_list": open_list,
    })
    return result


def build_comparison_summary(timings: dict[str, float]) -> dict[str, Any]:
    """
    根据实测耗时生成对比总结。

    Args:
        timings: 如 {"connect": 1.2, "syn": 0.8}。

    Returns:
        对比表与加速比。
    """
    rows = comparison_table_rows()
    connect_t = timings.get("connect")
    syn_t = timings.get("syn")
    speedup = None
    if connect_t and syn_t and syn_t > 0:
        speedup = round(connect_t / syn_t, 2)

    return {
        "table": rows,
        "timings": timings,
        "speedup_syn_vs_connect": speedup,
        "speedup_note": (
            f"SYN 相对 Connect 加速约 {speedup}x"
            if speedup and speedup > 1
            else "（SYN 未成功或未执行，无法计算加速比）"
        ),
    }


def print_lab_questions() -> None:
    """打印实验思考引导问题。"""
    print("\n" + "═" * 60)
    print("📝 实验思考引导")
    print("═" * 60)
    print("""
1. 局域网 vs 互联网扫描有何区别？
   · 局域网延迟低、防火墙策略可能较松，扫描更快、结果更完整。
   · 互联网目标常经 NAT/云 WAF，端口可能 filtered，OS 识别成功率更低。

2. 如何防御端口扫描？
   · 端口管理：关闭非必要服务，仅暴露必需端口。
   · 访问控制：防火墙/安全组默认拒绝，白名单放行。
   · 日志监控：启用 syslog/IDS，检测 SYN 半开扫描与 Connect 扫描特征。
""")


def print_comparison_table(summary: dict[str, Any]) -> None:
    """
    在终端打印扫描方式对比表。

    Args:
        summary: build_comparison_summary 的返回值。
    """
    print("\n" + "═" * 72)
    print("📊 扫描方式对比总结")
    print("═" * 72)
    header = f"{'扫描方式':<22} {'权限':<12} {'速度':<8} {'隐蔽性':<18} {'准确性':<8}"
    print(header)
    print("-" * 72)
    for row in summary.get("table", []):
        print(
            f"{row['method']:<22} {row['privilege']:<12} {row['speed']:<8} "
            f"{row['stealth']:<18} {row['accuracy']:<8}"
        )
    timings = summary.get("timings", {})
    if timings:
        print("\n⏱️  实测耗时:")
        for k, v in timings.items():
            print(f"   · {k}: {v}s")
    print(f"\n{summary.get('speedup_note', '')}")


def main() -> None:
    """交互式 CLI：依次演示四种扫描方式并输出对比总结。"""
    print("=" * 56)
    print("  InsightScan · 扫描方式对比教学")
    print("=" * 56)
    target = input(f"目标 IP [{DEFAULT_DEMO_TARGET}]: ").strip() or DEFAULT_DEMO_TARGET
    ports = input(f"Connect/SYN 端口 [{DEFAULT_ZENMAP_PORTS}]: ").strip() or DEFAULT_ZENMAP_PORTS

    timings: dict[str, float] = {}
    demos = [
        ("Connect", lambda: demo_tcp_connect(target, ports)),
        ("SYN", lambda: demo_tcp_syn(target, ports)),
        ("OS", lambda: demo_os_detection(target)),
        ("全端口", lambda: demo_full_port_scan(target)),
    ]

    for label, fn in demos:
        print(f"\n{'─' * 56}\n▶ 正在演示: {label}\n")
        result = fn()
        if result.get("error") and not result.get("success", True):
            print(f"❌ {result['error']}")
            continue
        if result.get("success") is False:
            print(result.get("hint") or result.get("error") or "演示未完成")
            print(f"   等价命令: {result.get('nmap_command', '')}")
            continue

        print(f"✅ {result.get('title', label)}")
        print(f"   原理: {result.get('principle', '')}")
        print(f"   特点: {result.get('features', '')}")
        print(f"   耗时: {result.get('duration', '?')}s")
        print(f"   命令: {result.get('nmap_command', '')}")

        mode = result.get("mode")
        if mode in ("connect", "syn"):
            timings[mode] = result.get("duration", 0)
            print(f"   开放端口: {result.get('open_port_count', 0)}")
        elif mode == "os":
            matches = result.get("os_matches") or []
            if matches:
                for m in matches:
                    print(f"   OS: {m['name']} (置信度 {m['accuracy']}%)")
            else:
                print(f"   {result.get('no_result_hint') or '无 OS 识别结果'}")
        elif mode == "full_port":
            print(f"   开放端口数: {result.get('open_port_count', 0)}")
            lst = result.get("open_port_list") or []
            if lst:
                print(f"   列表: {', '.join(lst[:20])}" + (" ..." if len(lst) > 20 else ""))

        if result.get("xml_path"):
            print(f"   XML: {result['xml_path']}")

    summary = build_comparison_summary(timings)
    print_comparison_table(summary)
    print_lab_questions()


if __name__ == "__main__":
    main()
