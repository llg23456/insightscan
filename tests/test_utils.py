"""工具函数单元测试。"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.utils import (
    init_db,
    load_settings,
    validate_ip,
    validate_ports,
)


class TestValidateIp(unittest.TestCase):
    """IP 验证测试。"""

    def test_valid_ipv4(self) -> None:
        r = validate_ip("127.0.0.1")
        self.assertTrue(r["valid"])

    def test_valid_cidr(self) -> None:
        r = validate_ip("192.168.1.0/24")
        self.assertTrue(r["valid"])

    def test_invalid_ip(self) -> None:
        r = validate_ip("not-an-ip")
        self.assertFalse(r["valid"])


class TestValidatePorts(unittest.TestCase):
    """端口验证测试。"""

    def test_single_port(self) -> None:
        r = validate_ports("22")
        self.assertTrue(r["valid"])

    def test_port_list(self) -> None:
        r = validate_ports("22,80,443")
        self.assertTrue(r["valid"])

    def test_port_range(self) -> None:
        r = validate_ports("1-1000")
        self.assertTrue(r["valid"])

    def test_invalid_port(self) -> None:
        r = validate_ports("99999")
        self.assertFalse(r["valid"])


class TestLoadSettings(unittest.TestCase):
    """配置加载测试。"""

    def test_load_settings_ok(self) -> None:
        settings = load_settings()
        self.assertNotIn("error", settings)
        self.assertIn("scan", settings)
        self.assertIn("ai", settings)


class TestInitDb(unittest.TestCase):
    """数据库初始化测试。"""

    def test_init_db_creates_tables(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            with patch("src.utils.DB_FILE", db_path):
                result = init_db()
                self.assertIn("success", result)
                import sqlite3

                conn = sqlite3.connect(db_path)
                tables = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                conn.close()
                self.assertIn("scan_tasks", tables)
                self.assertIn("scan_results", tables)
                self.assertIn("scan_history", tables)


if __name__ == "__main__":
    unittest.main()
