"""InsightScan 工具函数：配置读取、日志、数据库连接、输入验证。"""

import ipaddress
import json
import logging
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Optional

# 项目根目录（src 的上级目录）
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"

SETTINGS_FILE = CONFIG_DIR / "settings.json"
API_KEYS_FILE = CONFIG_DIR / "api_keys.json"
DB_FILE = DATA_DIR / "scan_results.db"
LOG_FILE = DATA_DIR / "insightscan.log"

# 数据库表结构
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scan_tasks (
    task_id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scan_type TEXT,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    status TEXT DEFAULT 'running',
    total_hosts INTEGER DEFAULT 0,
    total_ports INTEGER DEFAULT 0,
    error_msg TEXT
);

CREATE TABLE IF NOT EXISTS scan_results (
    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER,
    host_ip TEXT,
    port INTEGER,
    protocol TEXT,
    state TEXT,
    service_name TEXT,
    service_version TEXT,
    product TEXT,
    banner TEXT,
    os_guess TEXT,
    risk_level TEXT,
    risk_analysis TEXT,
    FOREIGN KEY (task_id) REFERENCES scan_tasks(task_id)
);

CREATE TABLE IF NOT EXISTS scan_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip TEXT,
    port INTEGER,
    protocol TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    change_type TEXT,
    previous_state TEXT,
    current_state TEXT,
    previous_service TEXT,
    current_service TEXT
);
"""

_logger_initialized = False


def _ensure_dirs() -> None:
    """确保 data、reports 等运行时目录存在。"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """
    配置统一日志：控制台 + 文件双输出。

    Args:
        level: 日志级别，默认 INFO。

    Returns:
        项目根 logger 实例。
    """
    global _logger_initialized
    _ensure_dirs()

    logger = logging.getLogger("insightscan")
    if _logger_initialized:
        return logger

    logger.setLevel(level)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    _logger_initialized = True
    return logger


def load_settings() -> dict[str, Any]:
    """
    读取 config/settings.json 扫描与 AI 配置。

    Returns:
        配置字典；文件不存在或解析失败时返回含 error 字段的字典。
    """
    logger = setup_logging()
    try:
        if not SETTINGS_FILE.exists():
            return {"error": f"配置文件不存在: {SETTINGS_FILE}"}
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            settings = json.load(f)
        logger.debug("已加载配置: %s", SETTINGS_FILE)
        return settings
    except json.JSONDecodeError as e:
        logger.error("配置文件 JSON 解析失败: %s", e)
        return {"error": f"配置文件 JSON 解析失败: {e}"}
    except OSError as e:
        logger.error("读取配置文件失败: %s", e)
        return {"error": f"读取配置文件失败: {e}"}


def load_api_key() -> dict[str, Any]:
    """
    读取 Kimi API 密钥，支持环境变量 INSIGHTSCAN_API_KEY 覆盖。

    Returns:
        含 kimi_api_key、base_url 的字典；失败时返回含 error 字段的字典。
    """
    logger = setup_logging()
    env_key = os.environ.get("INSIGHTSCAN_API_KEY")
    if env_key:
        logger.debug("使用环境变量 INSIGHTSCAN_API_KEY")
        return {
            "kimi_api_key": env_key,
            "base_url": "https://api.moonshot.cn/v1",
        }

    try:
        if not API_KEYS_FILE.exists():
            return {
                "error": (
                    f"API 密钥文件不存在: {API_KEYS_FILE}，"
                    "请复制 config/api_keys.json.example 并填入密钥"
                )
            }
        with open(API_KEYS_FILE, encoding="utf-8") as f:
            keys = json.load(f)
        if not keys.get("kimi_api_key"):
            return {"error": "api_keys.json 中 kimi_api_key 为空"}
        return keys
    except json.JSONDecodeError as e:
        logger.error("API 密钥文件 JSON 解析失败: %s", e)
        return {"error": f"API 密钥文件 JSON 解析失败: {e}"}
    except OSError as e:
        logger.error("读取 API 密钥文件失败: %s", e)
        return {"error": f"读取 API 密钥文件失败: {e}"}


def get_db_connection() -> sqlite3.Connection | dict[str, str]:
    """
    获取 SQLite 数据库连接。

    Returns:
        sqlite3.Connection 实例；失败时返回含 error 字段的字典。
    """
    logger = setup_logging()
    try:
        _ensure_dirs()
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        logger.debug("已连接数据库: %s", DB_FILE)
        return conn
    except sqlite3.Error as e:
        logger.error("数据库连接失败: %s", e)
        return {"error": f"数据库连接失败: {e}"}


def init_db() -> dict[str, Any]:
    """
    初始化数据库，创建 scan_tasks、scan_results、scan_history 表。

    Returns:
        成功时 {"success": True, "db_path": str}；失败时 {"error": str}。
    """
    logger = setup_logging()
    conn = get_db_connection()
    if isinstance(conn, dict):
        return conn

    try:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
        logger.info("数据库初始化完成: %s", DB_FILE)
        return {"success": True, "db_path": str(DB_FILE)}
    except sqlite3.Error as e:
        logger.error("数据库初始化失败: %s", e)
        return {"error": f"数据库初始化失败: {e}"}
    finally:
        conn.close()


def validate_ip(ip: str) -> dict[str, Any]:
    """
    验证 IP 地址或 CIDR 网段格式。

    Args:
        ip: IPv4/IPv6 地址或 CIDR（如 192.168.1.0/24）。

    Returns:
        有效时 {"valid": True, "ip": str}；无效时 {"valid": False, "error": str}。
    """
    if not ip or not ip.strip():
        return {"valid": False, "error": "IP 地址不能为空"}

    ip = ip.strip()
    try:
        if "/" in ip:
            ipaddress.ip_network(ip, strict=False)
        else:
            ipaddress.ip_address(ip)
        return {"valid": True, "ip": ip}
    except ValueError as e:
        return {"valid": False, "error": f"无效的 IP 或网段格式: {e}"}


def validate_ports(ports: str) -> dict[str, Any]:
    """
    验证端口范围格式，支持 "1-1000"、"80,443"、"22" 等形式。

    Args:
        ports: 端口字符串。

    Returns:
        有效时 {"valid": True, "ports": str}；无效时 {"valid": False, "error": str}。
    """
    if not ports or not ports.strip():
        return {"valid": False, "error": "端口不能为空"}

    ports = ports.strip()
    # 允许: 数字、逗号、连字符
    if not re.match(r"^[\d,\-]+$", ports):
        return {"valid": False, "error": f"端口格式无效: {ports}"}

    for part in ports.split(","):
        part = part.strip()
        if not part:
            return {"valid": False, "error": "端口列表中存在空项"}

        if "-" in part:
            range_parts = part.split("-")
            if len(range_parts) != 2:
                return {"valid": False, "error": f"端口范围格式无效: {part}"}
            try:
                start, end = int(range_parts[0]), int(range_parts[1])
            except ValueError:
                return {"valid": False, "error": f"端口范围必须为整数: {part}"}
            if start < 1 or end > 65535 or start > end:
                return {"valid": False, "error": f"端口范围超出 1-65535: {part}"}
        else:
            try:
                port = int(part)
            except ValueError:
                return {"valid": False, "error": f"端口必须为整数: {part}"}
            if port < 1 or port > 65535:
                return {"valid": False, "error": f"端口超出 1-65535: {port}"}

    return {"valid": True, "ports": ports}


def get_setting(key_path: str, default: Optional[Any] = None) -> Any:
    """
    从 settings.json 按点分路径读取嵌套配置项。

    Args:
        key_path: 如 "scan.max_threads"。
        default: 键不存在时的默认值。

    Returns:
        配置值或 default。
    """
    settings = load_settings()
    if "error" in settings:
        return default

    value: Any = settings
    for key in key_path.split("."):
        if not isinstance(value, dict) or key not in value:
            return default
        value = value[key]
    return value


if __name__ == "__main__":
    """阶段 1 验收：配置读取、数据库初始化、输入验证。"""
    log = setup_logging()
    log.info("=== InsightScan 阶段 1 验收测试 ===")

    # 1. 配置读取
    settings = load_settings()
    if "error" in settings:
        log.error("配置加载失败: %s", settings["error"])
    else:
        log.info("配置加载成功: scan.max_threads=%s", settings.get("scan", {}).get("max_threads"))

    api_keys = load_api_key()
    if "error" in api_keys:
        log.warning("API 密钥: %s（Ubuntu 上配置 api_keys.json 后即可）", api_keys["error"])
    else:
        masked = api_keys["kimi_api_key"][:8] + "****"
        log.info("API 密钥加载成功: %s", masked)

    # 2. 数据库初始化
    result = init_db()
    if "error" in result:
        log.error("数据库初始化失败: %s", result["error"])
    else:
        log.info("数据库初始化成功: %s", result["db_path"])
        conn = get_db_connection()
        if not isinstance(conn, dict):
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            log.info("已创建表: %s", [row["name"] for row in tables])
            conn.close()

    # 3. 输入验证
    for ip in ("127.0.0.1", "192.168.1.0/24", "invalid"):
        r = validate_ip(ip)
        log.info("validate_ip(%s) => %s", ip, r)

    for ports in ("22,80,443", "1-1000", "99999"):
        r = validate_ports(ports)
        log.info("validate_ports(%s) => %s", ports, r)

    log.info("=== 阶段 1 验收测试完成 ===")
