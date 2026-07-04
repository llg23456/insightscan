"""安全工具单元测试。"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.security_tools import IptablesDefense, PromiscModeDetector, ScanBehaviorDetector


class TestScanBehaviorDetector(unittest.TestCase):
    """扫描行为检测测试。"""

    @patch.object(ScanBehaviorDetector, "_collect_log_lines")
    def test_detect_nmap_scan(self, mock_lines) -> None:
        mock_lines.return_value = [
            "Jul  4 10:00:00 host kernel: Nmap scan detected SRC=192.168.1.100",
            "Jul  4 10:00:01 host ufw: [UFW BLOCK] IN=ens33 SRC=10.0.0.5 DST=192.168.1.1",
        ]
        detector = ScanBehaviorDetector(lookback_minutes=60)
        result = detector.detect()
        self.assertGreater(result["total_events"], 0)
        self.assertEqual(result["summary"]["scan_events"], 1)
        self.assertEqual(result["events"][0]["source_ip"], "192.168.1.100")


class TestPromiscDetector(unittest.TestCase):
    """混杂模式检测测试。"""

    @patch.object(PromiscModeDetector, "_check_sysfs")
    def test_no_promisc(self, mock_sysfs) -> None:
        mock_sysfs.return_value = [
            {"interface": "eth0", "promiscuous": False, "method": "sysfs"}
        ]
        result = PromiscModeDetector().detect()
        self.assertFalse(result["alert"])

    @patch.object(PromiscModeDetector, "_check_sysfs")
    def test_promisc_alert(self, mock_sysfs) -> None:
        mock_sysfs.return_value = [
            {"interface": "eth0", "promiscuous": True, "method": "sysfs"}
        ]
        result = PromiscModeDetector().detect()
        self.assertTrue(result["alert"])


class TestIptablesDefense(unittest.TestCase):
    """iptables 规则生成测试。"""

    def test_generate_block_scanner(self) -> None:
        defense = IptablesDefense()
        result = defense.generate_rules(scanner_ips=["192.168.1.100"])
        self.assertIn("script", result)
        self.assertIn("192.168.1.100", result["script"])
        self.assertGreater(result["rule_count"], 0)


if __name__ == "__main__":
    unittest.main()
