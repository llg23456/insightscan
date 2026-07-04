"""安全防护工具：扫描行为检测、混杂模式检测、iptables 自动化防御。"""

import json
import re
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.utils import get_db_connection, get_setting, setup_logging, format_display_time, now_local_str

# 日志中识别扫描行为的正则（按优先级排列）
SCAN_PATTERNS = [
    (re.compile(r"nmap|Nmap|NMAP", re.I), "Nmap Scan", "high", "syn"),
    (re.compile(r"port scan|Port Scan|PORT SCAN", re.I), "Port Scan", "high", "connect"),
    (re.compile(r"SYN.*scan|syn flood|Possible SYN flooding", re.I), "SYN Scan/Flood", "high", "syn"),
    (re.compile(r"FIN scan|Xmas scan|Null scan", re.I), "Stealth Scan", "medium", "fin"),
    (re.compile(r"UFW BLOCK", re.I), "Blocked Probe (UFW)", "medium", "connect"),
    (re.compile(r"iptables.*DROP|REJECT", re.I), "Firewall Drop", "medium", "connect"),
]

# 从 UFW/iptables 日志提取来源 IP
SRC_PATTERN = re.compile(r"SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

DEFAULT_HIGH_RISK_PORTS = [21, 23, 445, 3389, 6379, 27017, 1433, 5900]


class ScanBehaviorDetector:
    """分析 syslog / journalctl / 扫描数据库，检测本机是否正被扫描。"""

    def __init__(
        self,
        lookback_minutes: Optional[int] = None,
        local_ips: Optional[list[str]] = None,
    ) -> None:
        self.logger = setup_logging()
        self.lookback_minutes = lookback_minutes or int(
            get_setting("security.scan_detection_minutes", 10)
        )
        self.local_ips = local_ips or []
        self.log_sources = get_setting(
            "security.log_sources",
            ["/var/log/syslog", "/var/log/auth.log"],
        )

    def detect(self) -> dict[str, Any]:
        """
        检测扫描行为。

        Returns:
            含 events 列表的字典；失败时含 error 字段。
        """
        try:
            lines = self._collect_log_lines()
            events = self._parse_lines(lines)
            db_events = self._detect_from_scan_database()
            events.extend(db_events)
            events = sorted(events, key=lambda x: x.get("timestamp", ""), reverse=True)
            summary = self._summarize(events)
            return {
                "lookback_minutes": self.lookback_minutes,
                "monitor_note": "日志回溯窗口（分钟），与持续监控秒数不同",
                "total_events": len(events),
                "events": events,
                "summary": summary,
                "checked_at": now_local_str(),
                "detection_sources": {
                    "syslog_events": len(events) - len(db_events),
                    "database_events": len(db_events),
                },
            }
        except Exception as e:
            self.logger.error("扫描行为检测失败: %s", e)
            return {"error": f"扫描行为检测失败: {e}"}

    def _detect_from_scan_database(self) -> list[dict[str, Any]]:
        """
        从 scan_tasks 表检测近期针对本机的 InsightScan/Nmap 扫描。

        Connect 扫描通常不会写入 syslog，联调实验依赖此通道。
        """
        if not self.local_ips:
            return []

        conn = get_db_connection()
        if isinstance(conn, dict):
            return []

        events: list[dict[str, Any]] = []
        targets = set(self.local_ips) | {"127.0.0.1", "localhost"}
        try:
            from datetime import timedelta

            cutoff = (
                datetime.now() - timedelta(minutes=self.lookback_minutes)
            ).strftime("%Y-%m-%d %H:%M:%S")
            rows = conn.execute(
                """
                SELECT task_id, target, scan_type, start_time, status, total_ports
                FROM scan_tasks
                WHERE start_time >= ?
                ORDER BY start_time DESC
                LIMIT 30
                """,
                (cutoff,),
            ).fetchall()

            for row in rows:
                target = row["target"] or ""
                matched = target in targets
                if not matched:
                    for lip in self.local_ips:
                        if lip and lip in target:
                            matched = True
                            break
                if not matched:
                    continue

                ts = format_display_time(row["start_time"])
                events.append(
                    {
                        "timestamp": ts,
                        "source_ip": "本机 InsightScan",
                        "attack_type": "Port Scan (InsightScan/Nmap)",
                        "scan_type": row["scan_type"] or "connect",
                        "severity": "high",
                        "detection_method": "database",
                        "task_id": row["task_id"],
                        "log_line": (
                            f"数据库记录: task_id={row['task_id']} "
                            f"target={target} ports_open={row['total_ports']} "
                            f"status={row['status']}"
                        ),
                    }
                )
        except Exception as e:
            self.logger.warning("数据库扫描检测失败: %s", e)
        finally:
            conn.close()
        return events

    def _collect_log_lines(self) -> list[str]:
        """从 journalctl 和日志文件收集最近日志行。"""
        lines: list[str] = []
        since = f"{self.lookback_minutes} min ago"

        # journalctl（Ubuntu 首选）
        for cmd in [
            ["journalctl", "--since", since, "--no-pager", "-q"],
            ["journalctl", "-k", "--since", since, "--no-pager", "-q"],
        ]:
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=30, check=False
                )
                if result.stdout:
                    lines.extend(result.stdout.splitlines())
            except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                self.logger.debug("journalctl 不可用: %s", e)

        # 传统日志文件
        for log_path in self.log_sources:
            path = Path(log_path)
            if not path.exists():
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                # 只取最后 5000 行避免过大
                lines.extend(content.splitlines()[-5000:])
            except OSError as e:
                self.logger.debug("读取日志失败 %s: %s", log_path, e)

        return lines

    def _parse_lines(self, lines: list[str]) -> list[dict[str, Any]]:
        """解析日志行，提取扫描事件。"""
        events: list[dict[str, Any]] = []
        seen: set[str] = set()

        for line in lines:
            for pattern, attack_type, severity, scan_subtype in SCAN_PATTERNS:
                if not pattern.search(line):
                    continue

                source_ip = self._extract_source_ip(line)
                if source_ip in ("127.0.0.1", "0.0.0.0", "unknown"):
                    # UFW 日志无 SRC 时跳过，避免大量 unknown 误报
                    if attack_type.startswith("Blocked") or attack_type.startswith("Firewall"):
                        if source_ip == "unknown":
                            continue
                    elif source_ip == "unknown":
                        continue

                # 同一来源+类型每 5 分钟去重
                ts = self._extract_timestamp(line)
                dedupe_key = f"{source_ip}:{attack_type}:{ts[:12]}"
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                events.append(
                    {
                        "timestamp": ts,
                        "source_ip": source_ip,
                        "attack_type": attack_type,
                        "scan_type": scan_subtype,
                        "severity": severity,
                        "log_line": line[:300],
                    }
                )
                break

        return sorted(events, key=lambda x: x.get("timestamp", ""), reverse=True)

    def _extract_source_ip(self, line: str) -> str:
        """从日志行提取攻击来源 IP，优先 SRC= 字段。"""
        src_match = SRC_PATTERN.search(line)
        if src_match:
            return src_match.group(1)
        ips = IP_PATTERN.findall(line)
        for ip in ips:
            if ip not in ("127.0.0.1", "0.0.0.0", "255.255.255.255"):
                return ip
        return "unknown"

    def _extract_timestamp(self, line: str) -> str:
        """从日志行提取时间戳。"""
        match = re.match(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
        if match:
            return match.group(1)
        match = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", line)
        if match:
            return match.group(1)
        return datetime.now().strftime("%H:%M:%S")

    def _summarize(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """汇总攻击来源与类型统计。"""
        sources: dict[str, int] = {}
        types: dict[str, int] = {}
        real_scan_events = [
            e for e in events
            if e.get("attack_type") in (
                "Nmap Scan", "Port Scan", "SYN Scan/Flood", "Stealth Scan",
                "Port Scan (InsightScan/Nmap)",
            )
        ]
        for e in events:
            src = e.get("source_ip", "unknown")
            if src != "unknown":
                sources[src] = sources.get(src, 0) + 1
            at = e.get("attack_type", "unknown")
            types[at] = types.get(at, 0) + 1
        return {
            "unique_sources": len(sources),
            "top_sources": sorted(sources.items(), key=lambda x: -x[1])[:10],
            "attack_types": types,
            "scan_events": len(real_scan_events),
            "is_under_attack": len(real_scan_events) > 0 or len(events) > 10,
        }


class PromiscModeDetector:
    """检测网卡是否处于混杂模式（promiscuous）。"""

    def __init__(self) -> None:
        self.logger = setup_logging()

    def detect(self) -> dict[str, Any]:
        """
        检测所有网卡的混杂模式状态。

        Returns:
            含 interfaces 列表的字典。
        """
        try:
            interfaces = self._check_sysfs()
            if not interfaces:
                interfaces = self._check_ip_link()
            promisc_count = sum(1 for i in interfaces if i.get("promiscuous"))
            return {
                "interfaces": interfaces,
                "promiscuous_count": promisc_count,
                "alert": promisc_count > 0,
                "message": (
                    "检测到混杂模式网卡，可能存在嗅探/中间人攻击"
                    if promisc_count > 0
                    else "所有网卡未处于混杂模式"
                ),
                "checked_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
            }
        except Exception as e:
            self.logger.error("混杂模式检测失败: %s", e)
            return {"error": f"混杂模式检测失败: {e}"}

    def _check_sysfs(self) -> list[dict[str, Any]]:
        """读取 /sys/class/net/*/flags 检测 PROMISC 标志 (0x100)。"""
        results: list[dict[str, Any]] = []
        net_path = Path("/sys/class/net")
        if not net_path.exists():
            return results

        for iface in sorted(net_path.iterdir()):
            name = iface.name
            if name == "lo":
                continue
            flags_file = iface / "flags"
            try:
                flags = int(flags_file.read_text().strip(), 16)
                promisc = bool(flags & 0x100)
                results.append(
                    {
                        "interface": name,
                        "promiscuous": promisc,
                        "flags_hex": hex(flags),
                        "method": "sysfs",
                    }
                )
            except (OSError, ValueError):
                continue
        return results

    def _check_ip_link(self) -> list[dict[str, Any]]:
        """通过 ip link 命令检测 PROMISC。"""
        results: list[dict[str, Any]] = []
        try:
            proc = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            current_iface = ""
            for line in proc.stdout.splitlines():
                match = re.match(r"^\d+:\s+(\w+)", line)
                if match:
                    current_iface = match.group(1)
                if current_iface and current_iface != "lo":
                    promisc = "PROMISC" in line
                    if "state" in line.lower() or promisc:
                        existing = next(
                            (r for r in results if r["interface"] == current_iface), None
                        )
                        if existing:
                            existing["promiscuous"] = promisc
                        else:
                            results.append(
                                {
                                    "interface": current_iface,
                                    "promiscuous": promisc,
                                    "method": "ip_link",
                                }
                            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return results


class IptablesDefense:
    """根据扫描结果和攻击检测自动生成 iptables 规则。"""

    def __init__(self) -> None:
        self.logger = setup_logging()
        self.high_risk_ports = get_setting(
            "security.high_risk_ports", DEFAULT_HIGH_RISK_PORTS
        )

    def generate_rules(
        self,
        task_id: Optional[int] = None,
        scanner_ips: Optional[list[str]] = None,
        block_high_risk_inbound: bool = True,
    ) -> dict[str, Any]:
        """
        生成 iptables 防御规则脚本。

        Args:
            task_id: 扫描任务 ID，用于识别本机高危暴露端口。
            scanner_ips: 检测到的扫描来源 IP 列表。
            block_high_risk_inbound: 是否封禁外网访问高危端口。

        Returns:
            含 rules 和 script 的字典。
        """
        try:
            rules: list[str] = [
                "#!/bin/bash",
                "# InsightScan 自动生成 iptables 防御规则",
                f"# Generated: {datetime.now().isoformat()}",
                "",
                "# 备份当前规则",
                "iptables-save > /tmp/iptables_backup_$(date +%Y%m%d_%H%M%S).rules",
                "",
            ]
            rule_entries: list[dict[str, Any]] = []

            # 封禁扫描来源 IP
            for ip in scanner_ips or []:
                if ip in ("unknown", "127.0.0.1", "0.0.0.0"):
                    continue
                cmd = f"iptables -A INPUT -s {ip} -j DROP"
                rules.append(cmd)
                rule_entries.append({"action": "block_scanner", "ip": ip, "command": cmd})

            # 封禁外网访问高危端口
            if block_high_risk_inbound:
                exposed = self._get_exposed_high_risk_ports(task_id)
                for port in exposed:
                    cmd = (
                        f"iptables -A INPUT -p tcp --dport {port} "
                        f"! -s 127.0.0.1 -j DROP"
                    )
                    rules.append(f"# Block external access to high-risk port {port}")
                    rules.append(cmd)
                    rule_entries.append(
                        {"action": "block_port", "port": port, "command": cmd}
                    )

                for port in self.high_risk_ports:
                    if port not in exposed:
                        cmd = (
                            f"iptables -A INPUT -p tcp --dport {port} "
                            f"! -s 127.0.0.1 -j DROP"
                        )
                        rules.append(f"# Prevent external access to known high-risk port {port}")
                        rules.append(cmd)
                        rule_entries.append(
                            {"action": "block_known_risk", "port": port, "command": cmd}
                        )

            rules.extend(["", "echo 'InsightScan iptables rules applied.'", ""])
            script = "\n".join(rules)

            return {
                "rule_count": len(rule_entries),
                "rules": rule_entries,
                "script": script,
            }
        except Exception as e:
            self.logger.error("iptables 规则生成失败: %s", e)
            return {"error": f"iptables 规则生成失败: {e}"}

    def _get_exposed_high_risk_ports(self, task_id: Optional[int]) -> list[int]:
        """从扫描结果中获取本机暴露的高危端口。"""
        if not task_id:
            return []
        conn = get_db_connection()
        if isinstance(conn, dict):
            return []
        try:
            rows = conn.execute(
                """
                SELECT port, risk_level FROM scan_results
                WHERE task_id = ? AND state = 'open'
                """,
                (task_id,),
            ).fetchall()
            ports = []
            for r in rows:
                if r["port"] in self.high_risk_ports or r["risk_level"] in ("高危", "中危"):
                    ports.append(r["port"])
            return sorted(set(ports))
        finally:
            conn.close()

    def apply_rules(self, script_path: Path, dry_run: bool = True) -> dict[str, Any]:
        """
        部署 iptables 规则（需要 root）。

        Args:
            script_path: 规则脚本路径。
            dry_run: True 时仅验证脚本，不执行。

        Returns:
            执行结果字典。
        """
        if dry_run:
            return {
                "success": True,
                "dry_run": True,
                "message": f"规则脚本已生成: {script_path}，请使用 sudo bash {script_path} 部署",
            }
        try:
            result = subprocess.run(
                ["sudo", "bash", str(script_path)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                return {"error": f"iptables 部署失败: {result.stderr}"}
            return {"success": True, "output": result.stdout}
        except Exception as e:
            return {"error": f"iptables 部署失败: {e}"}

    def save_script(self, script: str, output_path: Path) -> str:
        """保存规则脚本到文件。"""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(script, encoding="utf-8")
        output_path.chmod(0o755)
        return str(output_path)


if __name__ == "__main__":
    log = setup_logging()
    log.info("=== 安全工具测试 ===")

    detector = ScanBehaviorDetector(lookback_minutes=60)
    scan_result = detector.detect()
    log.info("扫描检测: events=%d under_attack=%s",
             scan_result.get("total_events", 0),
             scan_result.get("summary", {}).get("is_under_attack"))

    promisc = PromiscModeDetector().detect()
    log.info("混杂模式: alert=%s %s", promisc.get("alert"), promisc.get("message"))

    defense = IptablesDefense()
    scanner_ips = [
        e["source_ip"] for e in scan_result.get("events", [])[:5]
        if e.get("source_ip") != "unknown"
    ]
    rules = defense.generate_rules(scanner_ips=scanner_ips)
    log.info("iptables 规则数: %d", rules.get("rule_count", 0))
