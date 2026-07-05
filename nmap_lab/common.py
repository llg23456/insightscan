"""Nmap 教学模块公共工具：路径、验证、XML 保存、权限检测。"""

import html as html_module
import ipaddress
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# 项目根目录
_ROOT = Path(__file__).resolve().parent.parent
NMAP_LAB_REPORTS_DIR = _ROOT / "reports" / "nmap_lab"

DEFAULT_ZENMAP_PORTS = "21,23,80,3306"
DEFAULT_DEMO_TARGET = "127.0.0.1"
FULL_PORT_RANGE = "1-1000"

# Windows 上 SYN/OS 扫描通常不可用
IS_WINDOWS = sys.platform.startswith("win")


def ensure_lab_dir(prefix: str) -> Path:
    """
    创建并返回本次实验的输出目录。

    Args:
        prefix: 目录前缀，如 zenmap / connect / syn。

    Returns:
        形如 reports/nmap_lab/{prefix}_YYYYMMDD_HHMMSS/ 的路径。
    """
    NMAP_LAB_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = NMAP_LAB_REPORTS_DIR / f"{prefix}_{stamp}"
    session_dir.mkdir(parents=True, exist_ok=True)
    return session_dir


def validate_target(target: str) -> dict[str, Any]:
    """
    验证单个 IP 或 CIDR 目标（教学演示仅支持单 IP，CIDR 返回提示）。

    Args:
        target: 目标 IP 字符串。

    Returns:
        验证结果字典。
    """
    if not target or not target.strip():
        return {"valid": False, "error": "目标 IP 不能为空"}
    target = target.strip()
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return {"valid": True, "target": target, "is_cidr": True}
        except ValueError:
            return {"valid": False, "error": f"无效网段: {target}"}
    try:
        ipaddress.ip_address(target)
        return {"valid": True, "target": target, "is_cidr": False}
    except ValueError:
        return {"valid": False, "error": f"无效 IP: {target}"}


def validate_ports(ports: str) -> dict[str, Any]:
    """
    验证端口范围格式。

    Args:
        ports: 如 "21,23,80,3306" 或 "1-1000"。

    Returns:
        验证结果字典。
    """
    if not ports or not ports.strip():
        return {"valid": False, "error": "端口不能为空"}
    ports = ports.strip()
    if not re.match(r"^[\d,\-]+$", ports):
        return {"valid": False, "error": "端口格式无效，示例: 21,23,80 或 1-1000"}
    return {"valid": True, "ports": ports}


def is_root() -> bool:
    """检测当前进程是否具备 root/管理员权限。"""
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def get_privilege_status() -> dict[str, Any]:
    """返回 SYN/OS 是否可用（sudo 免密 nmap）。"""
    from nmap_lab.nmap_runner import sudo_nmap_nopasswd

    sudo_ok = sudo_nmap_nopasswd() or is_root()
    if sudo_ok:
        return {
            "can_syn_os": True,
            "sudo_nmap_nopasswd": sudo_nmap_nopasswd(),
            "message": "SYN/OS 扫描已就绪（sudo 免密 nmap）。",
            "setup_hint": "",
        }
    return {
        "can_syn_os": False,
        "sudo_nmap_nopasswd": False,
        "message": "SYN/OS 需配置 sudo 免密 nmap。",
        "setup_hint": (
            "whoami   # 先查看用户名\n"
            "echo \"$(whoami) ALL=(ALL) NOPASSWD: $(which nmap)\" | sudo tee /etc/sudoers.d/insightscan-nmap\n"
            "sudo chmod 440 /etc/sudoers.d/insightscan-nmap\n"
            "sudo -n nmap --version"
        ),
    }


def root_required_hint(scan_type: str) -> str:
    """SYN/OS 权限不足时的简短提示。"""
    if IS_WINDOWS:
        return f"⚠️ {scan_type.upper()} 扫描请在 Ubuntu VM 中运行。"
    status = get_privilege_status()
    if status.get("can_syn_os"):
        return f"⚠️ {scan_type.upper()} 扫描失败，请检查目标是否在线。"
    return f"⚠️ {scan_type.upper()} 需要 root。\n{status.get('setup_hint', '')}"


def normalize_xml_output(raw_xml: str | bytes | None) -> str:
    """
    将 Nmap XML 输出统一转为 str（部分环境 get_nmap_last_output 返回 bytes）。

    Args:
        raw_xml: Nmap 原始 XML。

    Returns:
        UTF-8 字符串。
    """
    if raw_xml is None:
        return ""
    if isinstance(raw_xml, bytes):
        return raw_xml.decode("utf-8", errors="replace")
    return str(raw_xml)


def save_nmap_xml(
    raw_xml: str | bytes | None,
    session_dir: Path,
    filename: str = "scan.xml",
) -> Path:
    """
    保存 Nmap XML 输出到实验目录。

    Args:
        raw_xml: Nmap XML 字符串或 bytes。
        session_dir: 会话目录。
        filename: 文件名，默认 scan.xml。

    Returns:
        写入文件的 Path。
    """
    xml_path = session_dir / filename
    xml_path.write_text(normalize_xml_output(raw_xml), encoding="utf-8")
    return xml_path


def save_nmap_html(
    session_dir: Path,
    hosts: list[dict[str, Any]],
    target: str,
    nmap_command: str = "",
    duration: float | None = None,
    filename: str = "scan.html",
) -> Path:
    """
    生成可在浏览器直接查看的 HTML 报告（与 scan.xml 同目录）。

    Args:
        session_dir: 会话目录。
        hosts: 解析后的主机列表。
        target: 扫描目标。
        nmap_command: 等价 Nmap 命令。
        duration: 耗时秒数。
        filename: HTML 文件名。

    Returns:
        写入文件的 Path。
    """
    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host = hosts[0] if hosts else {}
    rows_html = ""
    for p in host.get("ports", []):
        detail = " ".join(
            x for x in (p.get("product"), p.get("version")) if x
        ).strip() or "—"
        rows_html += (
            "<tr>"
            f"<td>{html_module.escape(str(p.get('port', '')))}</td>"
            f"<td>{html_module.escape(p.get('protocol', 'tcp'))}</td>"
            f"<td>{html_module.escape(p.get('state', ''))}</td>"
            f"<td>{html_module.escape(p.get('service') or '—')}</td>"
            f"<td>{html_module.escape(detail)}</td>"
            "</tr>"
        )
    if not rows_html:
        rows_html = "<tr><td colspan='5'>未发现端口记录</td></tr>"

    os_line = host.get("os_name") or "未知"
    if host.get("os_accuracy"):
        os_line += f"（置信度 {host['os_accuracy']}%）"

    duration_line = f"{duration}s" if duration is not None else "—"
    cmd_line = html_module.escape(nmap_command or "—")

    page = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Nmap 扫描报告 — {html_module.escape(target)}</title>
  <style>
    body {{ font-family: sans-serif; background: #0f0f1a; color: #eaeaea; margin: 0; padding: 24px; }}
    .wrap {{ max-width: 960px; margin: 0 auto; }}
    h1 {{ color: #e94560; font-size: 1.4rem; }}
    .meta {{ background: #16213e; padding: 16px; border-radius: 8px; margin: 16px 0; line-height: 1.8; }}
    .meta code {{ background: #0f0f1a; padding: 2px 6px; border-radius: 4px; }}
    table {{ width: 100%; border-collapse: collapse; background: #16213e; border-radius: 8px; overflow: hidden; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #333; text-align: left; }}
    th {{ background: #0f0f1a; color: #3498db; }}
    a {{ color: #3498db; }}
    .hint {{ color: #8892b0; font-size: 0.9rem; margin-top: 16px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>🗺️ Nmap 扫描报告（InsightScan 教学演示）</h1>
    <div class="meta">
      <div>🎯 目标：<strong>{html_module.escape(target)}</strong></div>
      <div>🖥️ 状态：{html_module.escape(host.get('state', 'unknown'))} · OS：{html_module.escape(os_line)}</div>
      <div>⏱️ 耗时：{html_module.escape(duration_line)} · 🕐 {html_module.escape(scanned_at)}</div>
      <div>💻 命令：<code>{cmd_line}</code></div>
    </div>
    <h2 style="color:#3498db;font-size:1.1rem;">端口 / 服务</h2>
    <table>
      <thead>
        <tr><th>端口</th><th>协议</th><th>状态</th><th>服务</th><th>版本</th></tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
    <p class="hint">
      原始 XML：<a href="scan.xml" download>下载 scan.xml</a>
      （可用 Zenmap「扫描 → 打开」导入，或文本编辑器查看）
    </p>
  </div>
</body>
</html>
"""
    html_path = session_dir / filename
    html_path.write_text(page, encoding="utf-8")
    return html_path


def extract_hosts_from_xml(xml_str: str | bytes | None, target: str) -> list[dict[str, Any]]:
    """
    从 Nmap XML 字符串解析主机与端口（sudo nmap -oX - 输出用）。

    python-nmap 0.7.1 无 analyse()，需自行解析 XML。

    Args:
        xml_str: Nmap XML。
        target: 默认目标 IP（XML 无 host 时回退）。

    Returns:
        与 extract_hosts_from_scanner 相同结构的主机列表。
    """
    import xml.etree.ElementTree as ET

    text = normalize_xml_output(xml_str)
    if not text.strip():
        return [{
            "ip": target,
            "hostname": "",
            "state": "unknown",
            "os_name": "",
            "os_accuracy": 0,
            "ports": [],
            "services": [],
        }]

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return [{
            "ip": target,
            "hostname": "",
            "state": "unknown",
            "os_name": "",
            "os_accuracy": 0,
            "ports": [],
            "services": [],
        }]

    hosts: list[dict[str, Any]] = []
    for host_el in root.findall("host"):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address")
        ip = addr_el.get("addr") if addr_el is not None else target

        state_el = host_el.find("status")
        state = state_el.get("state", "unknown") if state_el is not None else "unknown"

        hostname = ""
        hn = host_el.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")

        os_name = ""
        os_accuracy = 0
        os_matches: list[tuple[int, str]] = []
        for om in host_el.findall("os/osmatch"):
            name = om.get("name", "")
            try:
                acc = int(om.get("accuracy", 0) or 0)
            except ValueError:
                acc = 0
            if name:
                os_matches.append((acc, name))
        if os_matches:
            os_matches.sort(reverse=True)
            os_accuracy, os_name = os_matches[0]

        ports: list[dict[str, Any]] = []
        services: list[dict[str, Any]] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                try:
                    port_num = int(port_el.get("portid", 0))
                except (TypeError, ValueError):
                    continue
                proto = port_el.get("protocol", "tcp")
                state_p = port_el.find("state")
                pstate = state_p.get("state", "") if state_p is not None else ""
                svc_el = port_el.find("service")
                service = svc_el.get("name", "") if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""
                version = svc_el.get("version", "") if svc_el is not None else ""
                extrainfo = svc_el.get("extrainfo", "") if svc_el is not None else ""
                port_row = {
                    "port": port_num,
                    "protocol": proto,
                    "state": pstate,
                    "service": service,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                }
                ports.append(port_row)
                if product or version:
                    services.append({
                        "product": product,
                        "version": version,
                        "extra": extrainfo,
                        "port": port_num,
                    })

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "state": state,
            "os_name": os_name,
            "os_accuracy": os_accuracy,
            "ports": ports,
            "services": services,
        })

    if not hosts:
        hosts.append({
            "ip": target,
            "hostname": "",
            "state": "unknown",
            "os_name": "",
            "os_accuracy": 0,
            "ports": [],
            "services": [],
        })
    return hosts


def extract_hosts_from_scanner(nm: Any, target: str) -> list[dict[str, Any]]:
    """
    从 python-nmap PortScanner 对象解析主机与端口信息。

    Args:
        nm: nmap.PortScanner 实例。
        target: 扫描目标 IP。

    Returns:
        标准化主机列表。
    """
    hosts: list[dict[str, Any]] = []
    all_hosts = nm.all_hosts() or ([target] if target else [])

    for host in all_hosts:
        if host not in nm.all_hosts():
            continue
        os_name = ""
        os_accuracy = 0
        try:
            os_matches = sorted(
                nm[host].get("osmatch", []),
                key=lambda x: int(x.get("accuracy", 0)),
                reverse=True,
            )
            if os_matches:
                os_name = os_matches[0].get("name", "")
                os_accuracy = int(os_matches[0].get("accuracy", 0))
        except Exception:
            pass

        host_entry: dict[str, Any] = {
            "ip": host,
            "hostname": nm[host].hostname() or "",
            "state": nm[host].state(),
            "os_name": os_name,
            "os_accuracy": os_accuracy,
            "ports": [],
            "services": [],
        }

        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                pinfo = nm[host][proto][port]
                port_row = {
                    "port": port,
                    "protocol": proto,
                    "state": pinfo.get("state", ""),
                    "service": pinfo.get("name", ""),
                    "product": pinfo.get("product", ""),
                    "version": pinfo.get("version", ""),
                    "extrainfo": pinfo.get("extrainfo", ""),
                }
                host_entry["ports"].append(port_row)
                if port_row["product"] or port_row["version"]:
                    host_entry["services"].append({
                        "product": port_row["product"],
                        "version": port_row["version"],
                        "extra": port_row["extrainfo"],
                        "port": port,
                    })

        hosts.append(host_entry)

    if not hosts:
        hosts.append({
            "ip": target,
            "hostname": "",
            "state": "unknown",
            "os_name": "",
            "os_accuracy": 0,
            "ports": [],
            "services": [],
        })
    return hosts


def comparison_table_rows() -> list[dict[str, str]]:
    """返回扫描方式对比表的标准行（静态参考）。"""
    return [
        {
            "method": "TCP Connect (-sT)",
            "privilege": "普通用户",
            "speed": "中等",
            "stealth": "低（完整握手，易留日志）",
            "accuracy": "高",
        },
        {
            "method": "TCP SYN (-sS)",
            "privilege": "root / sudo",
            "speed": "快",
            "stealth": "较高（半开扫描）",
            "accuracy": "高",
        },
        {
            "method": "OS 识别 (-O)",
            "privilege": "root / sudo",
            "speed": "较慢",
            "stealth": "中",
            "accuracy": "依赖目标响应",
        },
        {
            "method": "全端口 (1-65535)",
            "privilege": "视扫描类型",
            "speed": "慢",
            "stealth": "低",
            "accuracy": "完整但耗时",
        },
    ]


def insightscan_comparison_static() -> dict[str, Any]:
    """Zenmap/Nmap 原始输出 vs InsightScan 的静态对比数据。"""
    return {
        "zenmap": {
            "title": "Zenmap / Nmap 原始输出",
            "points": [
                "图形化/终端展示端口与服务版本",
                "适合单次实验与教学演示",
                "XML 导出供离线查看",
                "无 AI 风险解读",
            ],
        },
        "insightscan": {
            "title": "InsightScan AI 增强",
            "points": [
                "Kimi AI 自动风险评估与报告",
                "批量网段扫描 + 多线程并发",
                "攻防联调、防御检测、性能实验一体化",
                "适合自动化分析与实验报告生成",
            ],
        },
        "summary": (
            "Zenmap 适合教学演示和单次查看；"
            "InsightScan 适合批量分析、AI 解读与自动化实验流程。"
        ),
    }
