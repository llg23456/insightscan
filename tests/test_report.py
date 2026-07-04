"""报告生成器单元测试。"""

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.report_generator import ReportGenerator
from src.utils import SCHEMA_SQL


def _create_test_db(db_path: Path) -> int:
    """创建测试数据库并插入一条任务记录，返回 task_id。"""
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA_SQL)
    conn.execute(
        "INSERT INTO scan_tasks (target, scan_type, status, total_hosts, total_ports) "
        "VALUES ('127.0.0.1', 'connect', 'completed', 1, 1)"
    )
    task_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        """
        INSERT INTO scan_results (
            task_id, host_ip, port, protocol, state,
            service_name, service_version, risk_level, risk_analysis
        ) VALUES (?, '127.0.0.1', 22, 'tcp', 'open', 'ssh', '8.9', '低危', ?)
        """,
        (task_id, '{"recommendation": "启用密钥认证", "threat_type": "暴力破解"}'),
    )
    conn.commit()
    conn.close()
    return task_id


class TestReportGenerator(unittest.TestCase):
    """报告生成测试。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "test.db"
        self.out_dir = Path(self.tmp.name) / "reports"
        self.out_dir.mkdir()
        self.task_id = _create_test_db(self.db_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _make_generator(self) -> ReportGenerator:
        with patch("src.utils.DB_FILE", self.db_path):
            gen = ReportGenerator()
            gen.output_dir = self.out_dir
            return gen

    def test_generate_markdown(self) -> None:
        with patch("src.utils.DB_FILE", self.db_path):
            gen = self._make_generator()
            result = gen.generate(self.task_id, fmt="markdown")
            self.assertIn("success", result)
            content = Path(result["file_path"]).read_text(encoding="utf-8")
            self.assertIn("# 网络安全扫描报告", content)
            self.assertIn("127.0.0.1", content)
            self.assertIn("低危", content)

    def test_generate_html(self) -> None:
        with patch("src.utils.DB_FILE", self.db_path):
            gen = self._make_generator()
            result = gen.generate(self.task_id, fmt="html")
            self.assertIn("success", result)
            content = Path(result["file_path"]).read_text(encoding="utf-8")
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("InsightScan", content)

    def test_missing_task(self) -> None:
        with patch("src.utils.DB_FILE", self.db_path):
            gen = self._make_generator()
            result = gen.generate(9999, fmt="markdown")
            self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
