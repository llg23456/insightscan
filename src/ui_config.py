"""Web 界面配置：IP/网段/扫描目标读写与自动检测。"""

import ipaddress
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from src.utils import CONFIG_DIR, load_settings, setup_logging

UI_SETTINGS_FILE = CONFIG_DIR / "ui_settings.json"

DEFAULT_UI_SETTINGS = {
    "local_ip": "127.0.0.1",
    "cidr": "127.0.0.1/32",
    "gateway": "",
    "interface": "",
    "attack_target": "127.0.0.1",
    "attack_ports": "22,80,443",
    "perf_target": "192.168.61.0/24",
    "perf_ports": "22,80,443",
    "defense_duration": 60,
    "defense_apply_iptables": False,
}


def load_ui_settings() -> dict[str, Any]:
    """
    读取 Web 界面配置，与 settings.json 中 perf_test_cidr 同步。

    Returns:
        UI 配置字典。
    """
    logger = setup_logging()
    data = dict(DEFAULT_UI_SETTINGS)
    try:
        if UI_SETTINGS_FILE.exists():
            with open(UI_SETTINGS_FILE, encoding="utf-8") as f:
                loaded = json.load(f)
            data.update(loaded)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("UI 配置读取失败: %s", e)

    settings = load_settings()
    if "error" not in settings:
        perf_cidr = settings.get("security", {}).get("perf_test_cidr")
        if perf_cidr and data.get("perf_target") in ("", "192.168.1.0/24"):
            data["perf_target"] = perf_cidr
            data["cidr"] = perf_cidr
    return data


def save_ui_settings(updates: dict[str, Any]) -> dict[str, Any]:
    """
    保存 Web 界面配置，并同步 perf_test_cidr 到 settings.json。

    Args:
        updates: 要更新的字段。

    Returns:
        保存后的完整配置；失败时含 error 字段。
    """
    logger = setup_logging()
    try:
        current = load_ui_settings()
        allowed = set(DEFAULT_UI_SETTINGS.keys())
        for key, value in updates.items():
            if key in allowed:
                current[key] = value

        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(UI_SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(current, f, ensure_ascii=False, indent=4)

        # 同步 C 段到 settings.json
        settings_path = CONFIG_DIR / "settings.json"
        if settings_path.exists():
            with open(settings_path, encoding="utf-8") as f:
                settings = json.load(f)
            settings.setdefault("security", {})
            if current.get("cidr"):
                settings["security"]["perf_test_cidr"] = current["cidr"]
            with open(settings_path, "w", encoding="utf-8") as f:
                json.dump(settings, f, ensure_ascii=False, indent=4)

        logger.info("UI 配置已保存")
        return current
    except (json.JSONDecodeError, OSError) as e:
        logger.error("UI 配置保存失败: %s", e)
        return {"error": f"保存失败: {e}"}


def detect_network() -> dict[str, Any]:
    """
    自动检测本机 IP 和 C 段（Linux ip addr）。

    Returns:
        含 local_ip、cidr、interface、gateway 的字典。
    """
    logger = setup_logging()
    result: dict[str, Any] = {
        "local_ip": "",
        "cidr": "",
        "interface": "",
        "gateway": "",
    }
    try:
        proc = subprocess.run(
            ["ip", "-4", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        current_iface = ""
        for line in proc.stdout.splitlines():
            iface_match = re.match(r"^\d+:\s+(\w+)", line)
            if iface_match:
                current_iface = iface_match.group(1)
            inet_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if inet_match and current_iface != "lo":
                ip, prefix = inet_match.group(1), inet_match.group(2)
                result["local_ip"] = ip
                result["interface"] = current_iface
                try:
                    network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
                    result["cidr"] = str(network)
                except ValueError:
                    result["cidr"] = f"{ip}/{prefix}"
                break

        route_proc = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        gw_match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", route_proc.stdout)
        if gw_match:
            result["gateway"] = gw_match.group(1)

        logger.info("网络检测: %s", result)
        return result
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.warning("网络检测失败: %s", e)
        return {"error": f"网络检测失败（请在 Linux VM 中运行）: {e}", **result}
