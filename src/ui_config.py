"""Web 界面配置：IP/网段/扫描目标读写与自动检测。"""

import ipaddress
import json
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

from src.utils import CONFIG_DIR, load_settings, setup_logging

UI_SETTINGS_FILE = CONFIG_DIR / "ui_settings.json"

DEFAULT_UI_SETTINGS = {
    "local_ip": "",
    "cidr": "",
    "gateway": "",
    "interface": "",
    "attack_target": "127.0.0.1",
    "defense_attack_target": "",
    "target_mode": "127.0.0.1",
    "target_custom": "",
    "attack_ports": "22,80,443",
    "perf_target": "",
    "perf_ports": "22,80,443",
    "defense_duration": 60,
    "defense_apply_iptables": False,
}


def resolve_target(cfg: dict[str, Any], mode: str | None = None, custom: str | None = None) -> str:
    """根据配置或 UI 选项解析实际扫描目标 IP/CIDR。"""
    m = mode or cfg.get("target_mode") or "127.0.0.1"
    if m == "127.0.0.1":
        return "127.0.0.1"
    if m == "local_ip":
        return cfg.get("local_ip") or cfg.get("attack_target") or "127.0.0.1"
    if m == "cidr":
        return cfg.get("cidr") or cfg.get("perf_target") or cfg.get("attack_target") or "127.0.0.1"
    if m == "custom":
        return (custom or cfg.get("target_custom") or cfg.get("attack_target") or "").strip() or "127.0.0.1"
    return cfg.get("attack_target") or "127.0.0.1"


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


def _is_virtual_interface(name: str) -> bool:
    """跳过 loopback、Docker、VMware 虚拟网卡等，避免误检。"""
    if not name or name == "lo":
        return True
    lower = name.lower()
    prefixes = ("docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "tun", "tap")
    return lower.startswith(prefixes)


def _cidr_from_ip_prefix(ip: str, prefix: str) -> str:
    """由 IP 与前缀长度生成 C 段字符串。"""
    try:
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except ValueError:
        return f"{ip}/{prefix}"


def _detect_linux_network() -> dict[str, Any]:
    """
    Linux：通过 `ip route` / `ip addr` 实时读取，非写死。

    优先使用默认路由所在网卡及其 src IP，避免误选 docker0 等虚拟接口。
    """
    result: dict[str, Any] = {
        "local_ip": "",
        "cidr": "",
        "interface": "",
        "gateway": "",
    }

    route_proc = subprocess.run(
        ["ip", "route", "show", "default"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    route_line = route_proc.stdout.strip().splitlines()[0] if route_proc.stdout.strip() else ""
    gw_match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", route_line)
    dev_match = re.search(r"\bdev (\S+)", route_line)
    src_match = re.search(r"\bsrc (\d+\.\d+\.\d+\.\d+)", route_line)

    if gw_match:
        result["gateway"] = gw_match.group(1)
    preferred_iface = dev_match.group(1) if dev_match else ""

    if preferred_iface and src_match:
        result["interface"] = preferred_iface
        result["local_ip"] = src_match.group(1)

    addr_proc = subprocess.run(
        ["ip", "-4", "addr", "show"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    # 解析每张网卡的 IPv4 地址
    iface_addrs: dict[str, tuple[str, str]] = {}
    current_iface = ""
    for line in addr_proc.stdout.splitlines():
        iface_match = re.match(r"^\d+:\s+(\S+)", line)
        if iface_match:
            current_iface = iface_match.group(1).split("@")[0]
        inet_match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if inet_match and current_iface and not _is_virtual_interface(current_iface):
            iface_addrs[current_iface] = (inet_match.group(1), inet_match.group(2))

    if preferred_iface and preferred_iface in iface_addrs:
        ip, prefix = iface_addrs[preferred_iface]
        result["local_ip"] = result["local_ip"] or ip
        result["interface"] = preferred_iface
        result["cidr"] = _cidr_from_ip_prefix(ip, prefix)
    elif not result["local_ip"] and iface_addrs:
        # 无默认路由时，优先 192.168/10 私网，否则取第一个物理类网卡
        def sort_key(item: tuple[str, tuple[str, str]]) -> tuple[int, str]:
            name, (ip, _) = item
            try:
                priv = ipaddress.ip_address(ip).is_private
            except ValueError:
                priv = False
            return (0 if priv else 1, name)

        iface, (ip, prefix) = sorted(iface_addrs.items(), key=sort_key)[0]
        result["interface"] = iface
        result["local_ip"] = ip
        result["cidr"] = _cidr_from_ip_prefix(ip, prefix)

    return result


def _detect_windows_network() -> dict[str, Any]:
    """Windows 开发机：通过 psutil 读取网卡 IP（非写死）。"""
    try:
        import psutil
    except ImportError:
        return {"error": "Windows 环境请安装 psutil 以自动检测 IP"}

    result: dict[str, Any] = {
        "local_ip": "",
        "cidr": "",
        "interface": "",
        "gateway": "",
    }
    candidates: list[tuple[str, str, str]] = []

    for iface, addrs in psutil.net_if_addrs().items():
        if _is_virtual_interface(iface):
            continue
        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            ip = addr.address
            if ip.startswith("127."):
                continue
            netmask = addr.netmask or "255.255.255.0"
            try:
                prefix = ipaddress.ip_network(f"0.0.0.0/{netmask}", strict=False).prefixlen
                cidr = _cidr_from_ip_prefix(ip, str(prefix))
            except ValueError:
                cidr = f"{ip}/24"
            candidates.append((iface, ip, cidr))

    if not candidates:
        return {**result, "error": "未检测到可用 IPv4 网卡"}

    def sort_key(item: tuple[str, str, str]) -> tuple[int, str]:
        _, ip, _ = item
        try:
            priv = ipaddress.ip_address(ip).is_private
        except ValueError:
            priv = False
        return (0 if priv else 1, ip)

    iface, ip, cidr = sorted(candidates, key=sort_key)[0]
    result["interface"] = iface
    result["local_ip"] = ip
    result["cidr"] = cidr
    return result


def detect_network() -> dict[str, Any]:
    """
    自动检测本机 IP 和 C 段（实时读系统，非写死）。

    Linux VM：执行 `ip route` + `ip addr`。
    Windows：通过 psutil 读取网卡地址。

    Returns:
        含 local_ip、cidr、interface、gateway 的字典。
    """
    logger = setup_logging()
    try:
        if sys.platform.startswith("win"):
            result = _detect_windows_network()
        else:
            result = _detect_linux_network()

        if not result.get("local_ip"):
            msg = result.pop("error", None) or "未检测到有效 IPv4 地址"
            logger.warning("网络检测无结果: %s", msg)
            return {"error": msg, **{k: result.get(k, "") for k in ("local_ip", "cidr", "interface", "gateway")}}

        logger.info("网络检测(实时): %s", {k: result.get(k) for k in ("local_ip", "cidr", "interface", "gateway")})
        return result
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        logger.warning("网络检测失败: %s", e)
        return {
            "error": f"网络检测失败: {e}",
            "local_ip": "",
            "cidr": "",
            "interface": "",
            "gateway": "",
        }
