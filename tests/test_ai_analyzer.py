"""AI 分析引擎单元测试（不调用真实 API）。"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.ai_analyzer import AIAnalyzer, RISK_PRIORITY


class TestJsonParsing(unittest.TestCase):
    """JSON 解析测试。"""

    def setUp(self) -> None:
        with patch.object(AIAnalyzer, "_init_api_client"):
            self.analyzer = AIAnalyzer()

    def test_parse_plain_json(self) -> None:
        text = '{"risk_level": "低危", "risk_score": 30}'
        result = self.analyzer._parse_json_response(text)
        self.assertEqual(result["risk_level"], "低危")

    def test_parse_markdown_fence(self) -> None:
        text = '```json\n{"risk_level": "中危", "risk_score": 50}\n```'
        result = self.analyzer._parse_json_response(text)
        self.assertEqual(result["risk_level"], "中危")

    def test_parse_invalid(self) -> None:
        result = self.analyzer._parse_json_response("not json at all")
        self.assertIn("error", result)


class TestFallbackRules(unittest.TestCase):
    """本地规则库降级测试。"""

    def setUp(self) -> None:
        with patch.object(AIAnalyzer, "_init_api_client"):
            self.analyzer = AIAnalyzer()
            self.analyzer._api_available = False

    def test_ssh_port_22(self) -> None:
        result = self.analyzer.analyze_port("127.0.0.1", 22, "ssh")
        self.assertEqual(result["risk_level"], "低危")
        self.assertEqual(result["source"], "local_rules")

    def test_unknown_port(self) -> None:
        result = self.analyzer.analyze_port("127.0.0.1", 9999, "unknown")
        self.assertEqual(result["risk_level"], "信息")

    def test_cache_on_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_file = Path(tmp) / "ai_cache.json"
            with patch("src.ai_analyzer.CACHE_FILE", cache_file):
                self.analyzer._cache = {}
                self.analyzer.enable_cache = True
                r1 = self.analyzer.analyze_port(
                    "127.0.0.1", 22, "ssh", "8.9", product="OpenSSH"
                )
                r2 = self.analyzer.analyze_port(
                    "127.0.0.1", 22, "ssh", "8.9", product="OpenSSH"
                )
                self.assertFalse(r1.get("from_cache"))
                self.assertTrue(r2.get("from_cache"))


class TestComputeDiff(unittest.TestCase):
    """历史对比差异计算测试。"""

    def setUp(self) -> None:
        with patch.object(AIAnalyzer, "_init_api_client"):
            self.analyzer = AIAnalyzer()

    def test_detect_new_port(self) -> None:
        old = []
        new = [{"host_ip": "127.0.0.1", "port": 22, "protocol": "tcp",
                "service_name": "ssh", "product": "", "service_version": ""}]
        diff = self.analyzer._compute_diff(old, new)
        self.assertEqual(len(diff["new_ports"]), 1)
        self.assertEqual(len(diff["closed_ports"]), 0)

    def test_detect_closed_port(self) -> None:
        old = [{"host_ip": "127.0.0.1", "port": 80, "protocol": "tcp",
                "service_name": "http", "product": "", "service_version": ""}]
        new = []
        diff = self.analyzer._compute_diff(old, new)
        self.assertEqual(len(diff["closed_ports"]), 1)

    def test_detect_service_change(self) -> None:
        old = [{"host_ip": "127.0.0.1", "port": 22, "protocol": "tcp",
                "service_name": "ssh", "product": "OpenSSH", "service_version": "8.8",
                "risk_level": "低危"}]
        new = [{"host_ip": "127.0.0.1", "port": 22, "protocol": "tcp",
                "service_name": "ssh", "product": "OpenSSH", "service_version": "8.9",
                "risk_level": "低危"}]
        diff = self.analyzer._compute_diff(old, new)
        self.assertEqual(len(diff["changed_services"]), 1)


class TestHostAnalysis(unittest.TestCase):
    """主机整体分析测试。"""

    def setUp(self) -> None:
        with patch.object(AIAnalyzer, "_init_api_client"):
            self.analyzer = AIAnalyzer()

    def test_overall_risk_highest(self) -> None:
        ports = [
            {"port": 22, "service_name": "ssh", "risk_level": "低危"},
            {"port": 445, "service_name": "smb", "risk_level": "高危"},
        ]
        result = self.analyzer.analyze_host("127.0.0.1", ports)
        self.assertEqual(result["overall_risk"], "高危")
        self.assertIn(445, result["high_risk_ports"])


class TestRiskPriority(unittest.TestCase):
    """风险等级优先级常量测试。"""

    def test_order(self) -> None:
        self.assertGreater(RISK_PRIORITY["高危"], RISK_PRIORITY["中危"])
        self.assertGreater(RISK_PRIORITY["中危"], RISK_PRIORITY["低危"])


if __name__ == "__main__":
    unittest.main()
