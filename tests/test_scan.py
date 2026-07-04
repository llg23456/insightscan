"""扫描引擎单元测试。"""

import sys
import unittest
from pathlib import Path

# 保证从项目根目录可导入 src 包
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.scan_engine import parse_nmap_xml_to_json


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun version="7.80" args="nmap -sT">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.4" accuracy="95"/>
      <osmatch name="Linux 4.15" accuracy="80"/>
    </os>
  </host>
</nmaprun>
"""


class TestParseNmapXml(unittest.TestCase):
    """XML 解析测试。"""

    def test_parse_valid_xml(self) -> None:
        """有效 XML 应解析出主机、端口和 OS 指纹。"""
        result = parse_nmap_xml_to_json(SAMPLE_XML)
        self.assertNotIn("error", result)
        self.assertEqual(len(result["hosts"]), 1)
        self.assertEqual(result["hosts"][0]["ip"], "127.0.0.1")
        self.assertEqual(result["hosts"][0]["ports"][0]["port"], 22)
        self.assertEqual(result["hosts"][0]["os_matches"][0]["name"], "Linux 5.4")
        self.assertEqual(len(result["hosts"][0]["os_matches"]), 2)

    def test_parse_invalid_xml(self) -> None:
        """无效 XML 应返回 error 字段。"""
        result = parse_nmap_xml_to_json("not xml")
        self.assertIn("error", result)

    def test_os_matches_top3(self) -> None:
        """OS 指纹最多保留置信度最高的 3 条。"""
        xml_many_os = SAMPLE_XML.replace(
            '<osmatch name="Linux 4.15" accuracy="80"/>',
            '<osmatch name="Linux 4.15" accuracy="80"/>'
            '<osmatch name="Linux 3.10" accuracy="70"/>'
            '<osmatch name="Linux 2.6" accuracy="60"/>',
        )
        result = parse_nmap_xml_to_json(xml_many_os)
        self.assertEqual(len(result["hosts"][0]["os_matches"]), 3)
        self.assertEqual(result["hosts"][0]["os_matches"][0]["accuracy"], 95)


if __name__ == "__main__":
    unittest.main()
