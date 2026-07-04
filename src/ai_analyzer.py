"""AI 分析引擎：Kimi API 风险评估、历史对比、结果缓存与本地降级。"""

import json
import re
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from openai import OpenAI

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.utils import (
    DATA_DIR,
    get_db_connection,
    get_setting,
    load_api_key,
    load_settings,
    setup_logging,
)

CACHE_FILE = DATA_DIR / "ai_cache.json"

# 风险等级优先级（数值越大越高）
RISK_PRIORITY = {"信息": 0, "低危": 1, "中危": 2, "高危": 3}

# 本地规则库：API 不可用时降级使用
LOCAL_RISK_RULES: dict[int, dict[str, Any]] = {
    21: {
        "risk_level": "中危",
        "risk_score": 55,
        "threat_type": "明文传输",
        "description": "FTP 服务常使用明文传输凭据，存在被嗅探风险。",
        "impact": "账号密码可能被中间人截获",
        "recommendation": "禁用 FTP 或改用 SFTP/FTPS",
        "references": [],
    },
    22: {
        "risk_level": "低危",
        "risk_score": 30,
        "threat_type": "暴力破解",
        "description": "SSH 服务暴露于网络，可能遭受密码暴力破解。",
        "impact": "攻击者可能尝试登录服务器",
        "recommendation": "禁用密码登录，启用密钥认证；限制访问 IP",
        "references": [],
    },
    23: {
        "risk_level": "高危",
        "risk_score": 85,
        "threat_type": "明文远程登录",
        "description": "Telnet 以明文传输所有数据，极易被窃听。",
        "impact": "凭据和会话内容完全暴露",
        "recommendation": "立即禁用 Telnet，改用 SSH",
        "references": [],
    },
    80: {
        "risk_level": "信息",
        "risk_score": 15,
        "threat_type": "信息暴露",
        "description": "HTTP 服务对外可见，需确认是否存在敏感信息泄露。",
        "impact": "可能暴露 Web 应用指纹",
        "recommendation": "启用 HTTPS，隐藏 Server 版本信息",
        "references": [],
    },
    443: {
        "risk_level": "信息",
        "risk_score": 10,
        "threat_type": "信息暴露",
        "description": "HTTPS 服务正常暴露，需关注 TLS 配置和证书有效性。",
        "impact": "配置不当可能导致中间人攻击",
        "recommendation": "使用现代 TLS 版本，定期更新证书",
        "references": [],
    },
    445: {
        "risk_level": "高危",
        "risk_score": 90,
        "threat_type": "远程代码执行",
        "description": "SMB 服务历史上存在多个严重远程漏洞。",
        "impact": "可能导致系统完全被控制",
        "recommendation": "限制 SMB 仅内网访问，及时安装安全补丁",
        "references": ["CVE-2017-0144"],
    },
    3306: {
        "risk_level": "中危",
        "risk_score": 60,
        "threat_type": "数据库暴露",
        "description": "MySQL 端口对外开放，存在未授权访问风险。",
        "impact": "数据库数据可能被窃取或篡改",
        "recommendation": "禁止公网访问，启用强密码和访问控制",
        "references": [],
    },
    3389: {
        "risk_level": "中危",
        "risk_score": 65,
        "threat_type": "远程桌面暴露",
        "description": "RDP 服务暴露，易遭受暴力破解和已知漏洞攻击。",
        "impact": "攻击者可能获取远程桌面控制权",
        "recommendation": "启用 NLA，限制访问 IP，使用 VPN",
        "references": [],
    },
    6379: {
        "risk_level": "高危",
        "risk_score": 88,
        "threat_type": "未授权访问",
        "description": "Redis 默认无认证，对外开放可导致数据泄露或 RCE。",
        "impact": "内存数据泄露，可能被写入恶意数据",
        "recommendation": "绑定 127.0.0.1，启用 requirepass，禁止公网访问",
        "references": [],
    },
}

SINGLE_PORT_PROMPT = """你是一位资深网络安全专家，请对以下端口扫描结果进行风险评估。

扫描结果：
- 目标IP: {host_ip}
- 开放端口: {port}
- 服务类型: {service}
- 版本信息: {version}
- Banner信息: {banner}

请严格按照以下JSON格式输出（不要输出其他内容）：
{{
    "risk_level": "高危/中危/低危/信息",
    "risk_score": 0-100的整数,
    "threat_type": "威胁类型",
    "description": "详细风险描述",
    "impact": "影响范围",
    "recommendation": "修复建议",
    "references": ["CVE编号或参考链接"]
}}

评估标准：
- 高危：存在已知远程利用漏洞，无需认证即可攻击
- 中危：需要一定条件才能利用，或泄露敏感信息
- 低危：信息泄露或配置不当，难以直接利用
- 信息：仅识别服务，无明显风险"""

BATCH_PORT_PROMPT = """你是一位资深网络安全专家，请对以下多个端口扫描结果进行风险评估。

{ports_block}

请对每个端口严格按照以下JSON数组格式输出（不要输出其他内容）：
[
    {{
        "port": 端口号,
        "risk_level": "高危/中危/低危/信息",
        "risk_score": 0-100的整数,
        "threat_type": "威胁类型",
        "description": "详细风险描述",
        "impact": "影响范围",
        "recommendation": "修复建议",
        "references": ["CVE编号或参考链接"]
    }}
]

评估标准：
- 高危：存在已知远程利用漏洞，无需认证即可攻击
- 中危：需要一定条件才能利用，或泄露敏感信息
- 低危：信息泄露或配置不当，难以直接利用
- 信息：仅识别服务，无明显风险"""

HOST_SUMMARY_PROMPT = """你是一位网络安全专家，请根据以下端口风险分析结果，生成一段100字以内的非技术摘要。

主机IP: {host_ip}
端口分析结果:
{analysis_summary}

请直接输出摘要文字，不要输出 JSON。"""

HISTORY_COMPARE_PROMPT = """对比以下两次扫描结果，识别安全态势变化：

[历史扫描结果]
{old_scan}

[最新扫描结果]
{new_scan}

请分析：
1. 新增开放了哪些端口？风险如何？
2. 关闭了哪些端口？
3. 服务版本是否有变化？
4. 整体安全态势是改善还是恶化？
5. 给出安全建议。

以 Markdown 格式输出分析报告。"""

# 与官网示例一致的 system 角色，约束输出风格
SYSTEM_PROMPT = (
    "你是一位专业的网络安全分析助手，专注于端口扫描结果的风险评估。"
    "请严格按照用户要求的 JSON 或 Markdown 格式输出，不要添加多余说明。"
)


class AIAnalyzer:
    """Kimi API 驱动的安全分析引擎。"""

    def __init__(self) -> None:
        """加载配置、API 客户端与缓存。"""
        self.logger = setup_logging()
        settings = load_settings()
        if "error" in settings:
            self.logger.warning("配置加载失败，使用默认值: %s", settings["error"])
            settings = {}

        ai_cfg = settings.get("ai", {})
        self.model = ai_cfg.get("model", "kimi-k2.6")
        self.temperature = float(ai_cfg.get("temperature", 0.3))
        self.max_tokens = int(ai_cfg.get("max_tokens", 1000))
        self.batch_size = int(ai_cfg.get("batch_size", 5))
        self.enable_cache = bool(ai_cfg.get("enable_cache", True))

        self._cache = self._load_cache()
        self._client: Optional[OpenAI] = None
        self._api_available = False
        self._init_api_client()

    def _init_api_client(self) -> None:
        """初始化 OpenAI 兼容的 Kimi 客户端。"""
        keys = load_api_key()
        if "error" in keys:
            self.logger.warning("API 不可用，将使用本地规则库: %s", keys["error"])
            return
        try:
            self._client = OpenAI(
                api_key=keys["kimi_api_key"],
                base_url=keys.get("base_url", "https://api.moonshot.cn/v1"),
            )
            self._api_available = True
        except Exception as e:
            self.logger.error("API 客户端初始化失败: %s", e)

    def _load_cache(self) -> dict[str, Any]:
        """加载 AI 分析缓存。"""
        try:
            if CACHE_FILE.exists():
                with open(CACHE_FILE, encoding="utf-8") as f:
                    return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            self.logger.warning("缓存加载失败: %s", e)
        return {}

    def _save_cache(self) -> None:
        """持久化 AI 分析缓存。"""
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, ensure_ascii=False, indent=2)
        except OSError as e:
            self.logger.error("缓存保存失败: %s", e)

    def _cache_key(
        self, service: str, product: str = "", version: str = ""
    ) -> str:
        """生成缓存键，格式如 ssh_OpenSSH_8.9p1。"""
        parts = [p for p in (service, product, version) if p]
        return "_".join(parts) if parts else "unknown"

    def analyze_port(
        self,
        host_ip: str,
        port: int,
        service: str = "",
        version: str = "",
        banner: str = "",
        product: str = "",
        use_cache: bool = True,
    ) -> dict[str, Any]:
        """
        单端口风险分析。

        Args:
            host_ip: 目标 IP。
            port: 端口号。
            service: 服务名。
            version: 版本信息。
            banner: Banner 信息。
            product: 产品名。
            use_cache: 是否使用缓存。

        Returns:
            风险分析结果字典；失败时含 error 字段。
        """
        try:
            key = self._cache_key(service, product, version)
            if use_cache and self.enable_cache and key in self._cache:
                cached = dict(self._cache[key])
                cached["from_cache"] = True
                self.logger.debug("缓存命中: %s", key)
                return cached

            if self._api_available and self._client:
                prompt = SINGLE_PORT_PROMPT.format(
                    host_ip=host_ip,
                    port=port,
                    service=service or "unknown",
                    version=version or "unknown",
                    banner=banner or "无",
                )
                response_text = self._call_api(prompt, self.max_tokens)
                if isinstance(response_text, str):
                    parsed = self._parse_json_response(response_text)
                    if "error" not in parsed:
                        parsed["from_cache"] = False
                        parsed["source"] = "kimi"
                        if self.enable_cache:
                            self._cache[key] = parsed
                            self._save_cache()
                        return parsed
                    self.logger.warning(
                        "AI JSON 解析失败，降级本地规则: %s",
                        parsed.get("error"),
                    )

            # 降级：本地规则库（同样写入缓存，避免重复分析）
            fallback = self._fallback_analyze(port, service, version, banner)
            fallback["from_cache"] = False
            fallback["source"] = "local_rules"
            if self.enable_cache:
                cache_entry = {k: v for k, v in fallback.items() if k != "port"}
                self._cache[key] = cache_entry
                self._save_cache()
            return fallback

        except Exception as e:
            self.logger.error("单端口分析失败: %s", e)
            return {"error": f"单端口分析失败: {e}"}

    def analyze_ports_batch(
        self, ports: list[dict[str, Any]], use_cache: bool = True
    ) -> list[dict[str, Any]]:
        """
        批量分析端口，每批最多 5 个。

        Args:
            ports: 端口信息列表，每项含 host_ip/port/service/version/banner 等。
            use_cache: 是否使用缓存。

        Returns:
            分析结果列表。
        """
        results: list[dict[str, Any]] = []
        uncached: list[dict[str, Any]] = []

        for p in ports:
            key = self._cache_key(
                p.get("service_name", p.get("service", "")),
                p.get("product", ""),
                p.get("service_version", p.get("version", "")),
            )
            if use_cache and self.enable_cache and key in self._cache:
                cached = dict(self._cache[key])
                cached["port"] = p.get("port")
                cached["from_cache"] = True
                results.append(cached)
            else:
                uncached.append(p)

        # 分批调用 API
        for i in range(0, len(uncached), self.batch_size):
            batch = uncached[i : i + self.batch_size]
            batch_results = self._analyze_batch_api(batch)
            results.extend(batch_results)

        return results

    def _analyze_batch_api(self, batch: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """调用 API 批量分析一组端口。"""
        if not batch:
            return []

        if not self._api_available or not self._client or len(batch) == 1:
            return [
                self.analyze_port(
                    p.get("host_ip", ""),
                    p.get("port", 0),
                    p.get("service_name", p.get("service", "")),
                    p.get("service_version", p.get("version", "")),
                    p.get("banner", ""),
                    p.get("product", ""),
                )
                for p in batch
            ]

        try:
            lines = []
            for p in batch:
                lines.append(
                    f"- IP:{p.get('host_ip')} 端口:{p.get('port')} "
                    f"服务:{p.get('service_name', p.get('service', ''))} "
                    f"版本:{p.get('service_version', p.get('version', ''))} "
                    f"Banner:{p.get('banner', '无')}"
                )
            prompt = BATCH_PORT_PROMPT.format(ports_block="\n".join(lines))
            response_text = self._call_api(prompt, self.max_tokens)
            if isinstance(response_text, dict) and "error" in response_text:
                raise ValueError(response_text["error"])
            if not isinstance(response_text, str):
                raise ValueError("API 返回为空")

            parsed_list = self._parse_json_array(response_text)
            batch_results: list[dict[str, Any]] = []

            for p in batch:
                port_num = p.get("port")
                matched = next(
                    (item for item in parsed_list if item.get("port") == port_num),
                    None,
                )
                if matched:
                    matched["from_cache"] = False
                    matched["source"] = "kimi"
                    key = self._cache_key(
                        p.get("service_name", p.get("service", "")),
                        p.get("product", ""),
                        p.get("service_version", p.get("version", "")),
                    )
                    if self.enable_cache:
                        cache_entry = {k: v for k, v in matched.items() if k != "port"}
                        self._cache[key] = cache_entry
                    batch_results.append(matched)
                else:
                    batch_results.append(
                        self._fallback_analyze(
                            p.get("port", 0),
                            p.get("service_name", ""),
                            p.get("service_version", ""),
                            p.get("banner", ""),
                        )
                    )

            if self.enable_cache:
                self._save_cache()
            return batch_results

        except Exception as e:
            self.logger.warning("批量 API 分析失败，降级单端口: %s", e)
            return [
                self.analyze_port(
                    p.get("host_ip", ""),
                    p.get("port", 0),
                    p.get("service_name", p.get("service", "")),
                    p.get("service_version", p.get("version", "")),
                    p.get("banner", ""),
                    p.get("product", ""),
                )
                for p in batch
            ]

    def analyze_task(self, task_id: int) -> dict[str, Any]:
        """
        分析指定扫描任务的所有开放端口，并更新数据库。

        Args:
            task_id: scan_tasks 表中的任务 ID。

        Returns:
            含 hosts 分析结果的字典。
        """
        try:
            conn = get_db_connection()
            if isinstance(conn, dict):
                return conn

            rows = conn.execute(
                """
                SELECT result_id, host_ip, port, protocol, service_name,
                       service_version, product, banner
                FROM scan_results WHERE task_id = ?
                """,
                (task_id,),
            ).fetchall()

            if not rows:
                conn.close()
                return {"error": f"任务 {task_id} 无扫描结果"}

            ports = [
                {
                    "result_id": r["result_id"],
                    "host_ip": r["host_ip"],
                    "port": r["port"],
                    "service_name": r["service_name"] or "",
                    "service_version": r["service_version"] or "",
                    "product": r["product"] or "",
                    "banner": r["banner"] or "",
                }
                for r in rows
            ]

            analyses = self.analyze_ports_batch(ports)
            hosts_map: dict[str, list[dict[str, Any]]] = {}

            for port_info, analysis in zip(ports, analyses):
                if "error" in analysis:
                    continue
                self._update_result_risk(
                    conn, port_info["result_id"], analysis
                )
                host_ip = port_info["host_ip"]
                entry = {**port_info, **analysis}
                hosts_map.setdefault(host_ip, []).append(entry)

            conn.commit()
            conn.close()

            host_summaries = []
            for host_ip, port_analyses in hosts_map.items():
                host_summaries.append(self.analyze_host(host_ip, port_analyses))

            cache_hits = sum(1 for a in analyses if a.get("from_cache"))
            return {
                "task_id": task_id,
                "total_ports": len(analyses),
                "cache_hits": cache_hits,
                "hosts": host_summaries,
            }

        except sqlite3.Error as e:
            self.logger.error("任务分析失败: %s", e)
            return {"error": f"任务分析失败: {e}"}

    def analyze_host(
        self, host_ip: str, port_analyses: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """
        主机整体分析：取最高风险等级并生成摘要。

        Args:
            host_ip: 主机 IP。
            port_analyses: 该主机各端口的分析结果。

        Returns:
            主机级分析结果。
        """
        try:
            if not port_analyses:
                return {"host_ip": host_ip, "overall_risk": "信息", "summary": "未发现开放端口"}

            overall_risk = max(
                (a.get("risk_level", "信息") for a in port_analyses),
                key=lambda x: RISK_PRIORITY.get(x, 0),
            )

            summary_lines = [
                f"端口{p.get('port')}({p.get('service_name','')}): "
                f"{p.get('risk_level','信息')}"
                for p in port_analyses
            ]
            analysis_summary = "\n".join(summary_lines)

            summary = self._generate_host_summary(host_ip, analysis_summary)
            high_risk_ports = [
                p.get("port") for p in port_analyses if p.get("risk_level") == "高危"
            ]

            return {
                "host_ip": host_ip,
                "overall_risk": overall_risk,
                "summary": summary,
                "port_count": len(port_analyses),
                "high_risk_ports": high_risk_ports,
                "ports": port_analyses,
            }

        except Exception as e:
            self.logger.error("主机分析失败: %s", e)
            return {"error": f"主机分析失败: {e}"}

    def compare_history(
        self,
        target: str,
        scan_type: Optional[str] = None,
        compare_date: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        历史对比分析：按目标 IP + 扫描类型匹配两次扫描，AI 生成 Markdown 报告。

        Args:
            target: 目标 IP。
            scan_type: 扫描类型，默认 connect。
            compare_date: 对比基准日期 (YYYY-MM-DD)，取该日最新一条；为空则取次新任务。

        Returns:
            含 diff 和 AI 报告的字典。
        """
        try:
            scan_type = scan_type or get_setting("scan.default_scan_type", "connect")
            conn = get_db_connection()
            if isinstance(conn, dict):
                return conn

            latest = self._get_latest_task(conn, target, scan_type)
            if not latest:
                conn.close()
                return {"error": f"未找到目标 {target} 的扫描记录"}

            if compare_date:
                baseline = self._get_task_by_date(conn, target, scan_type, compare_date)
            else:
                baseline = self._get_previous_task(
                    conn, target, scan_type, latest["task_id"]
                )

            if not baseline:
                conn.close()
                return {"error": "未找到可对比的历史扫描记录"}

            if baseline["task_id"] == latest["task_id"]:
                conn.close()
                return {"error": "历史与最新扫描为同一任务，无法对比"}

            old_results = self._get_task_results(conn, baseline["task_id"])
            new_results = self._get_task_results(conn, latest["task_id"])
            conn.close()

            diff = self._compute_diff(old_results, new_results)
            report = self._generate_compare_report(old_results, new_results, diff)

            alert = any(
                p.get("risk_level") in ("高危", "中危")
                for p in diff.get("new_ports", [])
            )

            return {
                "target": target,
                "scan_type": scan_type,
                "baseline_task_id": baseline["task_id"],
                "latest_task_id": latest["task_id"],
                "baseline_time": baseline["start_time"],
                "latest_time": latest["start_time"],
                "diff": diff,
                "report": report,
                "alert": alert,
            }

        except sqlite3.Error as e:
            self.logger.error("历史对比失败: %s", e)
            return {"error": f"历史对比失败: {e}"}

    def _call_api(self, prompt: str, max_tokens: int) -> str | dict[str, str]:
        """调用 Kimi API（OpenAI 兼容接口，与官网示例一致）。"""
        if not self._client:
            return {"error": "API 客户端未初始化"}
        try:
            # 参考官网: client.chat.completions.create(model, messages=[system, user])
            request_kwargs: dict[str, Any] = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": max_tokens,
            }
            # moonshot-v1 系列支持自定义 temperature；K2 系列由平台固定
            if self.model.startswith("moonshot-v1"):
                request_kwargs["temperature"] = self.temperature

            response = self._client.chat.completions.create(**request_kwargs)
            return response.choices[0].message.content or ""
        except Exception as e:
            self.logger.error("API 调用失败: %s", e)
            return {"error": f"API 调用失败: {e}"}

    def _extract_json_text(self, text: str) -> list[str]:
        """从 AI 回复中提取可能的 JSON 文本候选。"""
        candidates: list[str] = [text.strip()]
        fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text, re.IGNORECASE)
        if fence:
            candidates.insert(0, fence.group(1).strip())
        # 平衡花括号提取最外层 JSON 对象
        start = text.find("{")
        if start >= 0:
            depth = 0
            for i in range(start, len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        candidates.append(text[start : i + 1])
                        break
        return candidates

    def _parse_json_response(self, text: str | dict[str, str]) -> dict[str, Any]:
        """从 AI 回复中提取 JSON 对象。"""
        if isinstance(text, dict):
            return text
        raw = text.strip()
        for candidate in self._extract_json_text(raw):
            try:
                data = json.loads(candidate)
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                continue
        return {"error": "AI 回复中未找到有效 JSON"}

    def _extract_json_array_text(self, text: str) -> list[str]:
        """从 AI 回复中提取可能的 JSON 数组候选。"""
        candidates: list[str] = [text.strip()]
        fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text, re.IGNORECASE)
        if fence:
            candidates.insert(0, fence.group(1).strip())
        start = text.find("[")
        if start >= 0:
            depth = 0
            for i in range(start, len(text)):
                if text[i] == "[":
                    depth += 1
                elif text[i] == "]":
                    depth -= 1
                    if depth == 0:
                        candidates.append(text[start : i + 1])
                        break
        return candidates

    def _parse_json_array(self, text: str | dict[str, str]) -> list[dict[str, Any]]:
        """从 AI 回复中提取 JSON 数组。"""
        if isinstance(text, dict):
            return []
        raw = text.strip()
        for candidate in self._extract_json_array_text(raw):
            try:
                data = json.loads(candidate)
                if isinstance(data, list):
                    return data
            except json.JSONDecodeError:
                continue
        return []

    def _fallback_analyze(
        self, port: int, service: str = "", version: str = "", banner: str = ""
    ) -> dict[str, Any]:
        """本地规则库降级分析。"""
        if port in LOCAL_RISK_RULES:
            result = dict(LOCAL_RISK_RULES[port])
            result["port"] = port
            return result

        return {
            "port": port,
            "risk_level": "信息",
            "risk_score": 10,
            "threat_type": "未知服务",
            "description": f"端口 {port} 运行 {service or '未知'} 服务，暂无已知高危漏洞。",
            "impact": "需进一步人工评估",
            "recommendation": "确认该端口是否为业务所需，关闭不必要的服务",
            "references": [],
            "source": "local_rules",
        }

    def _generate_host_summary(self, host_ip: str, analysis_summary: str) -> str:
        """生成主机非技术摘要。"""
        if self._api_available and self._client:
            prompt = HOST_SUMMARY_PROMPT.format(
                host_ip=host_ip, analysis_summary=analysis_summary
            )
            text = self._call_api(prompt, 200)
            if isinstance(text, str) and text.strip():
                return text.strip()[:100]

        # 降级：模板摘要
        return f"主机 {host_ip} 存在多个开放服务，建议关注高危端口并及时修复。"[:100]

    def _generate_compare_report(
        self,
        old_results: list[dict[str, Any]],
        new_results: list[dict[str, Any]],
        diff: dict[str, Any],
    ) -> str:
        """生成历史对比 Markdown 报告。"""
        old_text = json.dumps(old_results, ensure_ascii=False, indent=2)
        new_text = json.dumps(new_results, ensure_ascii=False, indent=2)

        if self._api_available and self._client:
            prompt = HISTORY_COMPARE_PROMPT.format(old_scan=old_text, new_scan=new_text)
            text = self._call_api(prompt, 1500)
            if isinstance(text, str) and text.strip():
                if diff.get("new_ports") and any(
                    p.get("risk_level") == "高危" for p in diff["new_ports"]
                ):
                    text = "## ⚠️ 高危告警\n\n检测到新增高危端口！\n\n" + text
                return text

        return self._fallback_compare_report(diff)

    def _fallback_compare_report(self, diff: dict[str, Any]) -> str:
        """本地降级：简单 Markdown 对比报告。"""
        lines = ["# 扫描对比报告（本地生成）", ""]
        if diff.get("new_ports"):
            lines.append("## 新增端口")
            for p in diff["new_ports"]:
                lines.append(
                    f"- {p['host_ip']}:{p['port']} {p.get('service_name','')} "
                    f"({p.get('risk_level','未知')})"
                )
        if diff.get("closed_ports"):
            lines.append("\n## 关闭端口")
            for p in diff["closed_ports"]:
                lines.append(f"- {p['host_ip']}:{p['port']} {p.get('service_name','')}")
        if diff.get("changed_services"):
            lines.append("\n## 服务变化")
            for c in diff["changed_services"]:
                lines.append(
                    f"- {c['host_ip']}:{c['port']} "
                    f"{c.get('old_service','')} → {c.get('new_service','')}"
                )
        lines.append("\n## 建议\n- 关闭不必要的新增端口\n- 关注高危服务并及时更新")
        return "\n".join(lines)

    def _get_latest_task(
        self, conn: sqlite3.Connection, target: str, scan_type: str
    ) -> Optional[sqlite3.Row]:
        """获取目标最近一条扫描任务。"""
        return conn.execute(
            """
            SELECT * FROM scan_tasks
            WHERE target = ? AND scan_type = ? AND status = 'completed'
            ORDER BY start_time DESC LIMIT 1
            """,
            (target, scan_type),
        ).fetchone()

    def _get_previous_task(
        self, conn: sqlite3.Connection, target: str, scan_type: str, current_id: int
    ) -> Optional[sqlite3.Row]:
        """获取当前任务之前的最近一条扫描。"""
        return conn.execute(
            """
            SELECT * FROM scan_tasks
            WHERE target = ? AND scan_type = ? AND status = 'completed'
              AND task_id < ?
            ORDER BY start_time DESC LIMIT 1
            """,
            (target, scan_type, current_id),
        ).fetchone()

    def _get_task_by_date(
        self, conn: sqlite3.Connection, target: str, scan_type: str, date_str: str
    ) -> Optional[sqlite3.Row]:
        """获取指定日期最新一条扫描（同一天多次取最新）。"""
        return conn.execute(
            """
            SELECT * FROM scan_tasks
            WHERE target = ? AND scan_type = ? AND status = 'completed'
              AND date(start_time) = ?
            ORDER BY start_time DESC LIMIT 1
            """,
            (target, scan_type, date_str),
        ).fetchone()

    def _get_task_results(
        self, conn: sqlite3.Connection, task_id: int
    ) -> list[dict[str, Any]]:
        """获取任务的扫描结果列表。"""
        rows = conn.execute(
            """
            SELECT host_ip, port, protocol, state, service_name,
                   service_version, product, banner, risk_level
            FROM scan_results WHERE task_id = ?
            """,
            (task_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def _compute_diff(
        self,
        old_results: list[dict[str, Any]],
        new_results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """计算两次扫描的差异。"""
        def key(r: dict[str, Any]) -> tuple:
            return (r["host_ip"], r["port"], r.get("protocol", "tcp"))

        old_map = {key(r): r for r in old_results}
        new_map = {key(r): r for r in new_results}

        new_ports = [new_map[k] for k in new_map if k not in old_map]
        closed_ports = [old_map[k] for k in old_map if k not in new_map]
        changed_services = []

        for k in old_map:
            if k in new_map:
                old_svc = self._service_label(old_map[k])
                new_svc = self._service_label(new_map[k])
                old_risk = old_map[k].get("risk_level", "")
                new_risk = new_map[k].get("risk_level", "")
                if old_svc != new_svc or old_risk != new_risk:
                    changed_services.append(
                        {
                            "host_ip": k[0],
                            "port": k[1],
                            "old_service": old_svc,
                            "new_service": new_svc,
                            "old_risk": old_risk,
                            "new_risk": new_risk,
                        }
                    )

        return {
            "new_ports": new_ports,
            "closed_ports": closed_ports,
            "changed_services": changed_services,
        }

    def _service_label(self, row: dict[str, Any]) -> str:
        """格式化服务标识用于对比。"""
        parts = [
            row.get("service_name", ""),
            row.get("product", ""),
            row.get("service_version", ""),
        ]
        return "_".join(p for p in parts if p)

    def _update_result_risk(
        self,
        conn: sqlite3.Connection,
        result_id: int,
        analysis: dict[str, Any],
    ) -> None:
        """将 AI 分析结果写回 scan_results 表。"""
        risk_analysis = json.dumps(
            {
                "risk_score": analysis.get("risk_score"),
                "threat_type": analysis.get("threat_type"),
                "description": analysis.get("description"),
                "impact": analysis.get("impact"),
                "recommendation": analysis.get("recommendation"),
                "references": analysis.get("references", []),
                "source": analysis.get("source", ""),
            },
            ensure_ascii=False,
        )
        conn.execute(
            """
            UPDATE scan_results SET risk_level = ?, risk_analysis = ?
            WHERE result_id = ?
            """,
            (analysis.get("risk_level", "信息"), risk_analysis, result_id),
        )


if __name__ == "__main__":
    """阶段 3 验收：API 分析、结构化 JSON、缓存生效。"""
    log = setup_logging()
    log.info("=== InsightScan 阶段 3 验收测试 ===")

    analyzer = AIAnalyzer()
    log.info("使用模型: %s", analyzer.model)

    # 测试 1: 单端口分析
    log.info("测试 1: 单端口分析 (127.0.0.1:22 SSH)")
    result1 = analyzer.analyze_port(
        host_ip="127.0.0.1",
        port=22,
        service="ssh",
        version="8.9p1",
        product="OpenSSH",
        banner="OpenSSH 8.9p1 Ubuntu",
    )
    if "error" in result1:
        log.error("单端口分析失败: %s", result1["error"])
    else:
        log.info(
            "  风险等级=%s 分数=%s 来源=%s 缓存=%s",
            result1.get("risk_level"),
            result1.get("risk_score"),
            result1.get("source"),
            result1.get("from_cache"),
        )
        log.info("  威胁类型=%s", result1.get("threat_type"))
        log.info("  建议=%s", result1.get("recommendation", "")[:60])

    # 测试 2: 缓存命中
    log.info("测试 2: 缓存命中（重复分析同一服务）")
    result2 = analyzer.analyze_port(
        host_ip="127.0.0.1",
        port=22,
        service="ssh",
        version="8.9p1",
        product="OpenSSH",
        banner="OpenSSH 8.9p1 Ubuntu",
    )
    log.info(
        "  缓存命中=%s 风险等级=%s",
        result2.get("from_cache"),
        result2.get("risk_level"),
    )

    # 测试 3: 分析扫描任务（使用最近一次 task_id=2 如果有）
    log.info("测试 3: 分析扫描任务 task_id=2")
    task_result = analyzer.analyze_task(2)
    if "error" in task_result:
        log.warning("  任务分析: %s", task_result["error"])
    else:
        log.info(
            "  端口数=%d 缓存命中=%d",
            task_result.get("total_ports", 0),
            task_result.get("cache_hits", 0),
        )
        for host in task_result.get("hosts", []):
            log.info(
                "  主机 %s 整体风险=%s 摘要=%s",
                host.get("host_ip"),
                host.get("overall_risk"),
                host.get("summary", "")[:80],
            )

    # 测试 4: 历史对比（task 1 vs task 2）
    log.info("测试 4: 历史对比 127.0.0.1")
    compare = analyzer.compare_history("127.0.0.1", scan_type="connect")
    if "error" in compare:
        log.warning("  历史对比: %s", compare["error"])
    else:
        log.info(
            "  基准 task=%s 最新 task=%s 告警=%s",
            compare.get("baseline_task_id"),
            compare.get("latest_task_id"),
            compare.get("alert"),
        )
        log.info("  报告预览: %s...", compare.get("report", "")[:120])

    log.info("=== 阶段 3 验收测试完成 ===")
