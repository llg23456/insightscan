"""扫描引擎补充测试。"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.scan_engine import SCAN_TYPE_MAP, ScanEngine


class TestScanTypeMap(unittest.TestCase):
    """扫描类型映射测试。"""

    def test_all_types_defined(self) -> None:
        self.assertEqual(SCAN_TYPE_MAP["connect"], "-sT")
        self.assertEqual(SCAN_TYPE_MAP["syn"], "-sS")
        self.assertEqual(SCAN_TYPE_MAP["fin"], "-sF")


class TestExpandTargets(unittest.TestCase):
    """目标展开测试。"""

    def setUp(self) -> None:
        with patch("src.scan_engine.load_settings", return_value={"scan": {}}):
            self.engine = ScanEngine()

    def test_single_ip(self) -> None:
        hosts = self.engine._expand_targets("127.0.0.1")
        self.assertEqual(hosts, ["127.0.0.1"])

    def test_cidr_expansion(self) -> None:
        hosts = self.engine._expand_targets("192.168.1.0/30")
        self.assertEqual(len(hosts), 2)


class TestBuildNmapArgs(unittest.TestCase):
    """Nmap 参数构建测试。"""

    def setUp(self) -> None:
        with patch("src.scan_engine.load_settings", return_value={"scan": {"timeout": 300}}):
            self.engine = ScanEngine()

    def test_connect_no_os_flag(self) -> None:
        args = self.engine._build_nmap_args("connect", "22,80")
        self.assertIn("-sT", args)
        self.assertNotIn("-O", args)

    def test_syn_has_os_flag(self) -> None:
        args = self.engine._build_nmap_args("syn", "22")
        self.assertIn("-sS", args)
        self.assertIn("-O", args)


if __name__ == "__main__":
    unittest.main()
