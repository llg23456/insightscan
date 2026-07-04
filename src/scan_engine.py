"""扫描引擎：Nmap 调用、多线程并发、结果解析与数据库持久化。"""

import ipaddress
import json
import sqlite3
import sys
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

import nmap

# 保证从项目根目录可导入 src 包（兼容 python3 src/scan_engine.py 与 from src.scan_engine）
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.utils import (
    get_db_connection,
    get_setting,
    init_db,
    load_settings,
    now_local_str,
    setup_logging,
    validate_ip,
    validate_ports,
)

# 扫描类型与 Nmap 参数映射
# syn / fin 需要 root 权限（sudo），开发阶段以 connect 为主
SCAN_TYPE_MAP = {
    "connect": "-sT",
    "syn": "-sS",
    "fin": "-sF",
}

ROOT_REQUIRED_TYPES = {"syn", "fin"}


class ScanEngine:
    """Nmap 扫描引擎，支持多线程、结果解析与入库。"""

    def __init__(self) -> None:
        """从 settings.json 加载扫描参数。"""
        self.logger = setup_logging()
        settings = load_settings()
        if "error" in settings:
            self.logger.warning("配置加载失败，使用默认值: %s", settings["error"])
            settings = {}

        scan_cfg = settings.get("scan", {})
        self.default_ports = scan_cfg.get("default_ports", "1-1000")
        self.default_scan_type = scan_cfg.get("default_scan_type", "connect")
        self.max_threads = max(10, min(200, int(scan_cfg.get("max_threads", 50))))
        self.timeout = int(scan_cfg.get("timeout", 300))
        self.retry_count = int(scan_cfg.get("retry_count", 2))
        self._progress_lock = threading.Lock()
        self._completed_count = 0

    def scan(
        self,
        target: str,
        scan_type: Optional[str] = None,
        ports: Optional[str] = None,
        save_db: bool = True,
    ) -> dict[str, Any]:
        """
        执行扫描任务（主入口）。

        Args:
            target: 目标 IP 或 CIDR 网段。
            scan_type: connect / syn / fin，默认读取配置。
            ports: 端口范围，默认读取配置。
            save_db: 是否写入数据库。

        Returns:
            标准化扫描结果字典；失败时含 error 字段。
        """
        try:
            ip_check = validate_ip(target)
            if not ip_check.get("valid"):
                return {"error": ip_check.get("error", "无效目标")}

            ports = ports or self.default_ports
            port_check = validate_ports(ports)
            if not port_check.get("valid"):
                return {"error": port_check.get("error", "无效端口")}

            scan_type = (scan_type or self.default_scan_type).lower()
            if scan_type not in SCAN_TYPE_MAP:
                return {"error": f"不支持的扫描类型: {scan_type}，可选: connect/syn/fin"}

            if scan_type in ROOT_REQUIRED_TYPES:
                self.logger.warning(
                    "%s 扫描需要 root 权限，请使用 sudo 运行；开发阶段建议用 connect",
                    scan_type.upper(),
                )

            hosts = self._expand_targets(target)
            if not hosts:
                return {"error": f"无法解析目标: {target}"}

            if len(hosts) > 1024:
                return {"error": f"目标主机数过多 ({len(hosts)})，请缩小扫描范围"}

            task_id = None
            if save_db:
                task_id = self._create_task(target, scan_type)
                if isinstance(task_id, dict):
                    return task_id

            start_time = time.time()
            self._completed_count = 0
            total = len(hosts)
            all_hosts: list[dict[str, Any]] = []
            errors: list[str] = []

            scan_fn = self._get_scan_function(scan_type)
            thread_count = min(self.max_threads, total)
            self.logger.info(
                "开始扫描: target=%s type=%s ports=%s hosts=%d threads=%d",
                target,
                scan_type,
                ports,
                total,
                thread_count,
            )

            with ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = {
                    executor.submit(scan_fn, host, ports): host for host in hosts
                }
                for future in as_completed(futures):
                    host = futures[future]
                    try:
                        result = future.result()
                        if "error" in result:
                            errors.append(f"{host}: {result['error']}")
                        else:
                            all_hosts.extend(result.get("hosts", []))
                    except Exception as e:
                        errors.append(f"{host}: {e}")
                        self.logger.error("扫描线程异常 %s: %s", host, e)
                    finally:
                        self._update_progress(total)

            duration = round(time.time() - start_time, 2)
            total_ports = sum(len(h.get("ports", [])) for h in all_hosts)
            parsed = {
                "target": target,
                "scan_type": scan_type,
                "ports": ports,
                "duration": duration,
                "nmap_args": self._build_nmap_args(scan_type, ports),
                "thread_count": thread_count,
                "hosts": all_hosts,
                "stats": {
                    "total_hosts": len(all_hosts),
                    "total_ports": total_ports,
                    "scanned_hosts": total,
                    "errors": len(errors),
                },
            }

            if errors:
                parsed["warnings"] = errors

            if save_db and task_id is not None:
                save_result = self._save_to_db(task_id, parsed, errors)
                if "error" in save_result:
                    parsed["db_error"] = save_result["error"]
                else:
                    parsed["task_id"] = task_id
                self._update_task(
                    task_id,
                    status="completed" if not errors or all_hosts else "partial",
                    total_hosts=len(all_hosts),
                    total_ports=total_ports,
                    error_msg="; ".join(errors[:5]) if errors else None,
                )

            self.logger.info(
                "扫描完成: hosts=%d ports=%d 耗时=%ss",
                len(all_hosts),
                total_ports,
                duration,
            )
            return parsed

        except Exception as e:
            self.logger.error("扫描失败: %s", e)
            return {"error": f"扫描失败: {e}"}

    def scan_connect(self, target: str, ports: str) -> dict[str, Any]:
        """
        TCP Connect 扫描（-sT），无需 root，开发阶段主力方式。

        Args:
            target: 单个主机 IP。
            ports: 端口范围字符串。

        Returns:
            单主机扫描结果。
        """
        return self._run_single_host_scan(target, ports, "connect")

    def scan_syn(self, target: str, ports: str) -> dict[str, Any]:
        """
        TCP SYN 半连接扫描（-sS），需要 root 权限（sudo）。

        Args:
            target: 单个主机 IP。
            ports: 端口范围字符串。

        Returns:
            单主机扫描结果。
        """
        return self._run_single_host_scan(target, ports, "syn")

    def scan_fin(self, target: str, ports: str) -> dict[str, Any]:
        """
        TCP FIN 扫描（-sF），需要 root 权限（sudo）。

        Args:
            target: 单个主机 IP。
            ports: 端口范围字符串。

        Returns:
            单主机扫描结果。
        """
        return self._run_single_host_scan(target, ports, "fin")

    def _get_scan_function(self, scan_type: str) -> Callable[[str, str], dict[str, Any]]:
        """根据扫描类型返回对应扫描函数。"""
        return {
            "connect": self.scan_connect,
            "syn": self.scan_syn,
            "fin": self.scan_fin,
        }[scan_type]

    def _run_single_host_scan(
        self, target: str, ports: str, scan_type: str
    ) -> dict[str, Any]:
        """对单个主机执行 Nmap 扫描，含重试逻辑。"""
        last_error = ""
        for attempt in range(self.retry_count + 1):
            try:
                nm = nmap.PortScanner()
                arguments = self._build_nmap_args(scan_type, ports)
                self.logger.debug("Nmap 扫描 %s: nmap %s %s", target, arguments, target)
                nm.scan(hosts=target, arguments=arguments)
                hosts = self._parse_nmap_results(nm, target, scan_type)
                xml_data = self._parse_nmap_xml(nm)
                return {"hosts": hosts, "xml_parsed": xml_data}
            except nmap.PortScannerError as e:
                last_error = str(e)
                self.logger.warning(
                    "Nmap 扫描失败 (attempt %d/%d) %s: %s",
                    attempt + 1,
                    self.retry_count + 1,
                    target,
                    e,
                )
            except Exception as e:
                last_error = str(e)
                self.logger.error("扫描异常 %s: %s", target, e)
                break
        return {"error": last_error or "Nmap 扫描失败"}

    def _build_nmap_args(self, scan_type: str, ports: str) -> str:
        """构建 Nmap 参数字符串。"""
        scan_flag = SCAN_TYPE_MAP[scan_type]
        base = (
            f"{scan_flag} -p {ports} -sV --version-intensity 5 "
            f"-T4 --host-timeout {self.timeout}s"
        )
        # OS 指纹识别需要 root，仅 syn/fin 扫描时启用
        if scan_type in ROOT_REQUIRED_TYPES:
            base += " -O --osscan-guess"
        return base

    def _expand_targets(self, target: str) -> list[str]:
        """将 IP 或 CIDR 展开为主机地址列表。"""
        target = target.strip()
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                return [str(host) for host in network.hosts()]
            return [target]
        except ValueError:
            return []

    def _parse_nmap_results(
        self, nm: nmap.PortScanner, target: str, scan_type: str
    ) -> list[dict[str, Any]]:
        """将 python-nmap 结果解析为标准化 JSON 结构。"""
        hosts: list[dict[str, Any]] = []

        for host in nm.all_hosts():
            host_info: dict[str, Any] = {
                "ip": host,
                "hostname": nm[host].hostname() or "",
                "state": nm[host].state(),
                "scan_type": scan_type,
                "os_matches": self._extract_os_matches(nm, host),
                "ports": [],
            }

            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    port_info = nm[host][proto][port]
                    if port_info.get("state") not in ("open", "open|filtered"):
                        continue

                    service = port_info.get("name", "")
                    product = port_info.get("product", "")
                    version = port_info.get("version", "")
                    extrainfo = port_info.get("extrainfo", "")
                    banner_parts = [p for p in (product, version, extrainfo) if p]
                    banner = " ".join(banner_parts)

                    host_info["ports"].append(
                        {
                            "port": port,
                            "protocol": proto,
                            "state": port_info.get("state", ""),
                            "service_name": service,
                            "service_version": version,
                            "product": product,
                            "banner": banner,
                            "os_guess": self._format_os_guess(host_info["os_matches"]),
                        }
                    )

            if host_info["state"] == "up" or host_info["ports"]:
                hosts.append(host_info)

        if not hosts and target in nm.all_hosts():
            hosts.append(
                {
                    "ip": target,
                    "hostname": nm[target].hostname() or "",
                    "state": nm[target].state(),
                    "scan_type": scan_type,
                    "os_matches": self._extract_os_matches(nm, target),
                    "ports": [],
                }
            )

        return hosts

    def _extract_os_matches(
        self, nm: nmap.PortScanner, host: str
    ) -> list[dict[str, Any]]:
        """提取 OS 指纹，取置信度最高的前 3 个。"""
        try:
            os_matches = nm[host].get("osmatch", [])
            sorted_matches = sorted(
                os_matches,
                key=lambda x: int(x.get("accuracy", 0)),
                reverse=True,
            )
            return [
                {"name": m.get("name", ""), "accuracy": int(m.get("accuracy", 0))}
                for m in sorted_matches[:3]
            ]
        except (KeyError, TypeError, ValueError):
            return []

    def _format_os_guess(self, os_matches: list[dict[str, Any]]) -> str:
        """将 OS 匹配列表格式化为字符串。"""
        if not os_matches:
            return ""
        return "; ".join(f"{m['name']} ({m['accuracy']}%)" for m in os_matches)

    def _parse_nmap_xml(self, nm: nmap.PortScanner) -> dict[str, Any]:
        """解析 Nmap XML 输出为 JSON 结构（备用/实验数据采集）。"""
        try:
            xml_output = nm.get_nmap_last_output()
            if not xml_output:
                return {}
            root = ET.fromstring(xml_output)
            return {
                "nmap_version": root.get("version", ""),
                "start_time": root.get("start", ""),
                "scan_args": root.get("args", ""),
                "host_count": len(root.findall("host")),
            }
        except ET.ParseError as e:
            self.logger.debug("XML 解析失败: %s", e)
            return {"error": f"XML 解析失败: {e}"}

    def _update_progress(self, total: int) -> None:
        """线程安全地更新并输出扫描进度。"""
        with self._progress_lock:
            self._completed_count += 1
            done = self._completed_count
            pct = round(done / total * 100, 1)
            self.logger.info("扫描进度: %d/%d (%.1f%%)", done, total, pct)

    def _create_task(self, target: str, scan_type: str) -> int | dict[str, str]:
        """创建扫描任务记录，返回 task_id。"""
        conn = get_db_connection()
        if isinstance(conn, dict):
            return conn

        try:
            cursor = conn.execute(
                """
                INSERT INTO scan_tasks (target, scan_type, status, start_time)
                VALUES (?, ?, 'running', ?)
                """,
                (target, scan_type, now_local_str()),
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            self.logger.error("创建扫描任务失败: %s", e)
            return {"error": f"创建扫描任务失败: {e}"}
        finally:
            conn.close()

    def _update_task(
        self,
        task_id: int,
        status: str,
        total_hosts: int,
        total_ports: int,
        error_msg: Optional[str] = None,
    ) -> None:
        """更新扫描任务状态与统计信息。"""
        conn = get_db_connection()
        if isinstance(conn, dict):
            self.logger.error("更新任务失败: %s", conn.get("error"))
            return

        try:
            conn.execute(
                """
                UPDATE scan_tasks
                SET end_time = ?, status = ?, total_hosts = ?, total_ports = ?, error_msg = ?
                WHERE task_id = ?
                """,
                (
                    now_local_str(),
                    status,
                    total_hosts,
                    total_ports,
                    error_msg,
                    task_id,
                ),
            )
            conn.commit()
        except sqlite3.Error as e:
            self.logger.error("更新扫描任务失败: %s", e)
        finally:
            conn.close()

    def _save_to_db(
        self, task_id: int, parsed: dict[str, Any], errors: list[str]
    ) -> dict[str, Any]:
        """批量写入扫描结果并更新历史记录。"""
        conn = get_db_connection()
        if isinstance(conn, dict):
            return conn

        rows: list[tuple] = []
        now = datetime.now().isoformat(sep=" ", timespec="seconds")

        for host in parsed.get("hosts", []):
            host_ip = host.get("ip", "")
            for port_info in host.get("ports", []):
                rows.append(
                    (
                        task_id,
                        host_ip,
                        port_info.get("port"),
                        port_info.get("protocol"),
                        port_info.get("state"),
                        port_info.get("service_name"),
                        port_info.get("service_version"),
                        port_info.get("product"),
                        port_info.get("banner"),
                        port_info.get("os_guess"),
                        None,
                        None,
                    )
                )

        try:
            if rows:
                conn.executemany(
                    """
                    INSERT INTO scan_results (
                        task_id, host_ip, port, protocol, state,
                        service_name, service_version, product, banner,
                        os_guess, risk_level, risk_analysis
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
                self._update_scan_history(conn, parsed.get("hosts", []), now)

            conn.commit()
            self.logger.info("扫描结果已入库: task_id=%d, rows=%d", task_id, len(rows))
            return {"success": True, "rows": len(rows)}
        except sqlite3.Error as e:
            self.logger.error("扫描结果入库失败: %s", e)
            return {"error": f"扫描结果入库失败: {e}"}
        finally:
            conn.close()

    def _update_scan_history(
        self,
        conn: sqlite3.Connection,
        hosts: list[dict[str, Any]],
        timestamp: str,
    ) -> None:
        """更新 scan_history 表，记录端口首次/末次发现及服务变化。"""
        for host in hosts:
            host_ip = host.get("ip", "")
            for port_info in host.get("ports", []):
                port = port_info.get("port")
                protocol = port_info.get("protocol")
                current_service = self._format_service_key(port_info)

                existing = conn.execute(
                    """
                    SELECT history_id, current_service, current_state
                    FROM scan_history
                    WHERE host_ip = ? AND port = ? AND protocol = ?
                    ORDER BY last_seen DESC LIMIT 1
                    """,
                    (host_ip, port, protocol),
                ).fetchone()

                if existing is None:
                    conn.execute(
                        """
                        INSERT INTO scan_history (
                            host_ip, port, protocol, first_seen, last_seen,
                            change_type, previous_state, current_state,
                            previous_service, current_service
                        ) VALUES (?, ?, ?, ?, ?, 'new_port', NULL, ?, NULL, ?)
                        """,
                        (
                            host_ip,
                            port,
                            protocol,
                            timestamp,
                            timestamp,
                            port_info.get("state"),
                            current_service,
                        ),
                    )
                else:
                    prev_service = existing["current_service"]
                    change_type = "unchanged"
                    if prev_service != current_service:
                        change_type = "service_changed"

                    conn.execute(
                        """
                        INSERT INTO scan_history (
                            host_ip, port, protocol, first_seen, last_seen,
                            change_type, previous_state, current_state,
                            previous_service, current_service
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            host_ip,
                            port,
                            protocol,
                            timestamp,
                            timestamp,
                            change_type,
                            existing["current_state"],
                            port_info.get("state"),
                            prev_service,
                            current_service,
                        ),
                    )

    def _format_service_key(self, port_info: dict[str, Any]) -> str:
        """格式化服务标识，用于历史对比。"""
        parts = [
            port_info.get("service_name", ""),
            port_info.get("product", ""),
            port_info.get("service_version", ""),
        ]
        return "_".join(p for p in parts if p)


def parse_nmap_xml_to_json(xml_content: str) -> dict[str, Any]:
    """
    将 Nmap XML 字符串解析为标准化 JSON（独立工具函数）。

    Args:
        xml_content: Nmap XML 输出字符串。

    Returns:
        解析后的 JSON 字典；失败时含 error 字段。
    """
    try:
        root = ET.fromstring(xml_content)
        result: dict[str, Any] = {
            "nmap_version": root.get("version", ""),
            "scan_args": root.get("args", ""),
            "hosts": [],
        }

        for host_elem in root.findall("host"):
            host_data: dict[str, Any] = {"ip": "", "ports": [], "os_matches": []}

            for addr in host_elem.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    host_data["ip"] = addr.get("addr", "")

            status = host_elem.find("status")
            if status is not None:
                host_data["state"] = status.get("state", "")

            for osmatch in host_elem.findall(".//osmatch"):
                host_data["os_matches"].append(
                    {
                        "name": osmatch.get("name", ""),
                        "accuracy": int(osmatch.get("accuracy", 0)),
                    }
                )
            host_data["os_matches"] = sorted(
                host_data["os_matches"],
                key=lambda x: x["accuracy"],
                reverse=True,
            )[:3]

            for port_elem in host_elem.findall(".//port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") not in (
                    "open",
                    "open|filtered",
                ):
                    continue

                service_elem = port_elem.find("service")
                service_name = service_elem.get("name", "") if service_elem is not None else ""
                product = service_elem.get("product", "") if service_elem is not None else ""
                version = service_elem.get("version", "") if service_elem is not None else ""

                host_data["ports"].append(
                    {
                        "port": int(port_elem.get("portid", 0)),
                        "protocol": port_elem.get("protocol", "tcp"),
                        "state": state_elem.get("state", ""),
                        "service_name": service_name,
                        "service_version": version,
                        "product": product,
                        "banner": " ".join(p for p in (product, version) if p),
                    }
                )

            result["hosts"].append(host_data)

        return result
    except ET.ParseError as e:
        return {"error": f"XML 解析失败: {e}"}
    except Exception as e:
        return {"error": f"解析异常: {e}"}


if __name__ == "__main__":
    """阶段 2 验收：Connect 扫描 127.0.0.1，结果入库，三种扫描接口可用。"""
    log = setup_logging()
    log.info("=== InsightScan 阶段 2 验收测试 ===")

    init_result = init_db()
    if "error" in init_result:
        log.error("数据库初始化失败: %s", init_result["error"])
        raise SystemExit(1)

    engine = ScanEngine()

    # 验收使用常见端口，加快测试速度
    test_ports = "22,80,443"
    log.info("测试 1: TCP Connect 扫描 127.0.0.1 ports=%s", test_ports)
    result = engine.scan("127.0.0.1", scan_type="connect", ports=test_ports)

    if "error" in result:
        log.error("Connect 扫描失败: %s", result["error"])
    else:
        log.info(
            "Connect 扫描成功: task_id=%s hosts=%d ports=%d 耗时=%ss",
            result.get("task_id"),
            result["stats"]["total_hosts"],
            result["stats"]["total_ports"],
            result.get("duration"),
        )
        for host in result.get("hosts", []):
            log.info("  主机 %s (%s) 开放端口 %d 个", host["ip"], host["state"], len(host["ports"]))
            for p in host.get("ports", []):
                log.info(
                    "    %d/%s %s %s %s",
                    p["port"],
                    p["protocol"],
                    p["state"],
                    p.get("service_name", ""),
                    p.get("banner", ""),
                )
        if result["stats"]["total_ports"] == 0:
            log.info(
                "  提示: 22/80/443 均未开放属正常情况，可尝试 "
                "'python3 src/scan_engine.py' 前修改 ports 或启动 ssh: sudo systemctl start ssh"
            )

    # 验证三种扫描接口存在（syn/fin 仅验证接口可调用，需 root 才可能成功）
    log.info("测试 2: 验证三种扫描接口")
    for name, fn in [
        ("connect", engine.scan_connect),
        ("syn", engine.scan_syn),
        ("fin", engine.scan_fin),
    ]:
        assert callable(fn), f"{name} 接口不可用"
        log.info("  scan_%s 接口 OK（%s）", name, "需 root" if name != "connect" else "无需 root")

    # 验证数据库记录
    if result.get("task_id"):
        conn = get_db_connection()
        if not isinstance(conn, dict):
            task = conn.execute(
                "SELECT * FROM scan_tasks WHERE task_id = ?", (result["task_id"],)
            ).fetchone()
            count = conn.execute(
                "SELECT COUNT(*) as cnt FROM scan_results WHERE task_id = ?",
                (result["task_id"],),
            ).fetchone()
            log.info(
                "测试 3: 数据库验证 task_status=%s db_rows=%d",
                task["status"] if task else "N/A",
                count["cnt"] if count else 0,
            )
            conn.close()

    log.info("=== 阶段 2 验收测试完成 ===")
