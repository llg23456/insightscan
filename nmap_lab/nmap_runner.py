"""统一 Nmap 执行：Connect 普通扫描；SYN/OS 自动 sudo -n nmap。"""

import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import nmap

from nmap_lab.common import (
    extract_hosts_from_scanner,
    extract_hosts_from_xml,
    is_root,
    normalize_xml_output,
    save_nmap_html,
    save_nmap_xml,
)


def sudo_nmap_nopasswd() -> bool:
    """检测是否已配置 sudo 免密 nmap。"""
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return False
    try:
        result = subprocess.run(
            ["sudo", "-n", nmap_bin, "--version"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


def privilege_setup_hint() -> str:
    """SYN/OS 未配置 sudo 免密时的简短提示。"""
    return (
        "SYN/OS 需要 root。在 VM 终端执行（whoami 会自动填入你的用户名）：\n"
        "  whoami\n"
        "  echo \"$(whoami) ALL=(ALL) NOPASSWD: $(which nmap)\" | sudo tee /etc/sudoers.d/insightscan-nmap\n"
        "  sudo chmod 440 /etc/sudoers.d/insightscan-nmap\n"
        "  sudo -n nmap --version\n"
        "详见 README.md「Nmap 教学与 SYN/OS 权限配置」"
    )


def execute_nmap_scan(
    target: str,
    arguments: str,
    session_dir: Path,
    prefer_sudo: bool = False,
    timeout: int = 600,
) -> dict[str, Any]:
    """
    执行 Nmap 扫描。

    Connect 等普通扫描走 python-nmap；SYN/OS（prefer_sudo=True）走 sudo -n nmap。
    """
    nmap_bin = shutil.which("nmap") or "nmap"
    nmap_command = f"nmap {arguments} {target}"
    start = time.perf_counter()

    def _build_result(
        hosts: list[dict[str, Any]],
        cmd_label: str,
        used_sudo: bool,
        raw_xml: str,
    ) -> dict[str, Any]:
        duration = round(time.perf_counter() - start, 2)
        xml_path = save_nmap_xml(raw_xml, session_dir)
        html_path = save_nmap_html(
            session_dir,
            hosts,
            target=target,
            nmap_command=cmd_label,
            duration=duration,
        )
        open_ports = [
            p for h in hosts for p in h.get("ports", [])
            if p.get("state") in ("open", "open|filtered")
        ]
        report_web_path = f"nmap_lab/{session_dir.name}"
        return {
            "success": True,
            "target": target,
            "duration": duration,
            "nmap_args": arguments,
            "nmap_command": cmd_label,
            "hosts": hosts,
            "open_ports": open_ports,
            "open_port_count": len(open_ports),
            "session_dir": str(session_dir),
            "report_web_path": report_web_path,
            "xml_path": str(xml_path),
            "html_path": str(html_path),
            "used_sudo": used_sudo,
        }

    def _run_sudo() -> dict[str, Any]:
        arg_list = shlex.split(arguments)
        cmd = ["sudo", "-n", nmap_bin] + arg_list + ["-oX", "-", target]
        cmd_label = " ".join(cmd)
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        stderr = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
        if proc.returncode != 0:
            raise RuntimeError(stderr or f"nmap 退出码 {proc.returncode}")
        raw_xml = normalize_xml_output(proc.stdout)
        hosts = extract_hosts_from_xml(raw_xml, target)
        return _build_result(hosts, cmd_label, True, raw_xml)

    def _run_direct() -> dict[str, Any]:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments=arguments)
        hosts = extract_hosts_from_scanner(nm, target)
        raw_xml = normalize_xml_output(nm.get_nmap_last_output() or "")
        return _build_result(hosts, nmap_command, False, raw_xml)

    try:
        if prefer_sudo and not is_root():
            if not sudo_nmap_nopasswd():
                return {
                    "success": False,
                    "error": "SYN/OS 扫描需要 root 权限",
                    "hint": privilege_setup_hint(),
                    "nmap_command": nmap_command,
                    "duration": round(time.perf_counter() - start, 2),
                }
            return _run_sudo()
        return _run_direct()
    except nmap.PortScannerError as e:
        err = str(e)
        if "root privilege" in err.lower() or "requires root" in err.lower():
            if sudo_nmap_nopasswd():
                try:
                    return _run_sudo()
                except Exception as sub_e:
                    err = str(sub_e)
        return {
            "success": False,
            "error": err,
            "hint": privilege_setup_hint() if not sudo_nmap_nopasswd() else "",
            "nmap_command": nmap_command,
            "duration": round(time.perf_counter() - start, 2),
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "nmap_command": nmap_command,
            "duration": round(time.perf_counter() - start, 2),
        }
