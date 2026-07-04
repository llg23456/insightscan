"""报告生成器：Markdown/HTML 报告、风险统计与可视化。"""

import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import markdown

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.scan_engine import SCAN_TYPE_MAP
from src.utils import (
    REPORTS_DIR,
    format_display_time,
    get_db_connection,
    get_setting,
    load_settings,
    setup_logging,
)

RISK_ORDER = ["高危", "中危", "低危", "信息"]
RISK_EMOJI = {"高危": "🔴", "中危": "🟠", "低危": "🟡", "信息": "🟢"}
RISK_COLORS = {
    "高危": "#e94560",
    "中危": "#f5a623",
    "低危": "#f7d794",
    "信息": "#2ecc71",
}
RISK_LABELS_EN = {
    "高危": "Critical",
    "中危": "High",
    "低危": "Medium",
    "信息": "Info",
}


class ReportGenerator:
    """扫描报告生成器，支持 Markdown 与 HTML 输出。"""

    def __init__(self) -> None:
        """加载报告配置。"""
        self.logger = setup_logging()
        settings = load_settings()
        report_cfg = settings.get("report", {}) if "error" not in settings else {}
        self.default_format = report_cfg.get("default_format", "markdown")
        self.output_dir = Path(report_cfg.get("output_dir", "reports"))
        if not self.output_dir.is_absolute():
            self.output_dir = _ROOT / self.output_dir
        self.theme = report_cfg.get("theme", "dark")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        task_id: int,
        fmt: Optional[str] = None,
        output_path: Optional[str] = None,
        session_dir: Optional[Path] = None,
        scan_duration: Optional[float] = None,
        ai_stats: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        生成扫描报告。

        Args:
            task_id: 扫描任务 ID。
            fmt: 格式 markdown / html，默认读取配置。
            output_path: 输出文件路径，为空则自动生成。
            session_dir: 会话目录，HTML 报告嵌入 screenshots 图片。
            scan_duration: 实际扫描耗时（秒），覆盖数据库时间差计算。

        Returns:
            含 file_path、format 的字典；失败时含 error 字段。
        """
        try:
            fmt = (fmt or self.default_format).lower()
            data = self._load_task_data(task_id, scan_duration=scan_duration)
            if "error" in data:
                return data

            md_content = self._render_markdown(data, ai_stats=ai_stats)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_safe = data["target"].replace("/", "_").replace(":", "_")

            if output_path:
                out = Path(output_path)
                if not out.is_absolute():
                    out = _ROOT / out
            elif fmt == "html":
                out = self.output_dir / f"scan_report_{target_safe}_{task_id}_{timestamp}.html"
            else:
                out = self.output_dir / f"scan_report_{target_safe}_{task_id}_{timestamp}.md"

            out.parent.mkdir(parents=True, exist_ok=True)

            if fmt == "html":
                html_content = self._markdown_to_html(md_content, data, session_dir=session_dir)
                out.write_text(html_content, encoding="utf-8")
            else:
                out.write_text(md_content, encoding="utf-8")

            self.logger.info("报告已生成: %s", out)
            return {
                "success": True,
                "task_id": task_id,
                "format": fmt,
                "file_path": str(out),
            }

        except Exception as e:
            self.logger.error("报告生成失败: %s", e)
            return {"error": f"报告生成失败: {e}"}

    def _load_task_data(
        self, task_id: int, scan_duration: Optional[float] = None
    ) -> dict[str, Any]:
        """从数据库加载任务与扫描结果。"""
        conn = get_db_connection()
        if isinstance(conn, dict):
            return conn

        try:
            task = conn.execute(
                "SELECT * FROM scan_tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            if not task:
                return {"error": f"任务 {task_id} 不存在"}

            results = conn.execute(
                """
                SELECT host_ip, port, protocol, state, service_name,
                       service_version, product, banner, os_guess,
                       risk_level, risk_analysis
                FROM scan_results WHERE task_id = ?
                ORDER BY host_ip, port
                """,
                (task_id,),
            ).fetchall()

            rows = [dict(r) for r in results]
            for row in rows:
                if row.get("risk_analysis"):
                    try:
                        row["risk_detail"] = json.loads(row["risk_analysis"])
                    except json.JSONDecodeError:
                        row["risk_detail"] = {}
                else:
                    row["risk_level"] = row.get("risk_level") or "信息"
                    row["risk_detail"] = {}

            duration = ""
            if scan_duration is not None:
                duration = f"{scan_duration:.1f}" if scan_duration < 1 else str(int(scan_duration))
            elif task["start_time"] and task["end_time"]:
                try:
                    start = datetime.fromisoformat(str(task["start_time"]))
                    end = datetime.fromisoformat(str(task["end_time"]))
                    secs = int((end - start).total_seconds())
                    # 超过 2 小时可能是时区/跨任务误差，标记为未知
                    duration = str(secs) if secs < 7200 else f"{secs}(异常，请查看 summary.json)"
                except ValueError:
                    duration = "未知"

            return {
                "task_id": task_id,
                "target": task["target"],
                "scan_type": task["scan_type"],
                "start_time": format_display_time(task["start_time"]),
                "end_time": format_display_time(task["end_time"], assume_utc_if_naive=False),
                "status": task["status"],
                "total_hosts": task["total_hosts"],
                "total_ports": task["total_ports"],
                "duration": duration,
                "results": rows,
                "scan_cfg": {
                    "max_threads": get_setting("scan.max_threads", 50),
                    "timeout": get_setting("scan.timeout", 300),
                    "default_ports": get_setting("scan.default_ports", "1-1000"),
                },
            }
        except sqlite3.Error as e:
            return {"error": f"加载任务数据失败: {e}"}
        finally:
            conn.close()

    def _count_risks(self, results: list[dict[str, Any]]) -> dict[str, int]:
        """统计各风险等级数量。"""
        counts = {level: 0 for level in RISK_ORDER}
        for row in results:
            level = row.get("risk_level") or "信息"
            if level not in counts:
                level = "信息"
            counts[level] += 1
        return counts

    def _pct(self, count: int, total: int) -> str:
        """计算百分比字符串。"""
        if total == 0:
            return "0.0"
        return f"{count / total * 100:.1f}"

    def _render_markdown(
        self, data: dict[str, Any], ai_stats: Optional[dict[str, Any]] = None
    ) -> str:
        """渲染 Markdown 报告正文。"""
        results = data["results"]
        counts = self._count_risks(results)
        total = len(results) or 1

        lines = [
            "# 网络安全扫描报告",
            "",
            "## 1. 扫描概览",
            "",
            f"- 扫描时间: {data['start_time']}（本地时间）",
            f"- 结束时间: {data.get('end_time') or '—'}",
            f"- 扫描目标: {data['target']}",
            f"- 扫描类型: {data['scan_type']}",
            f"- 任务 ID: {data['task_id']}",
            f"- 总主机数: {data['total_hosts']}",
            f"- 总开放端口: {data['total_ports']}",
            f"- 扫描耗时: {data['duration']}秒",
            f"- 任务状态: {data['status']}",
        ]
        if ai_stats:
            lines.extend([
                "",
                "### AI 分析来源",
                "",
                f"- 分析端口数: {ai_stats.get('total_ports', 0)}",
                f"- Kimi API 调用: {ai_stats.get('api_calls', 0)} 次",
                f"- 缓存命中: {ai_stats.get('cache_hits', 0)} 次",
                f"- 本地规则降级: {ai_stats.get('local_rules', 0)} 次",
                f"- API Key 配置: `{ai_stats.get('api_key_status', '未知')}`",
            ])
            if ai_stats.get("cache_hits", 0) > 0 and ai_stats.get("api_calls", 0) == 0:
                lines.append(
                    "- 说明: 相同服务/版本已写入 `data/ai_cache.json`，未重复调用 Kimi API"
                )
        if data["total_hosts"] == 0 and data["total_ports"] == 0:
            lines.extend([
                "",
                "> **提示**: 未发现存活主机或开放端口。请确认目标网段是否正确"
                "（如 VM 实际网段可能不是 192.168.1.0/24），可先用 "
                "`-t 127.0.0.1 --ports 22,80,443` 验证。",
            ])
        lines.extend(["", "## 2. 风险统计", "",
            "| 风险等级 | 数量 | 占比 | 颜色标识 |",
            "|---------|------|------|---------|",
        ])

        for level in RISK_ORDER:
            c = counts[level]
            lines.append(
                f"| {level} | {c} | {self._pct(c, total)}% | {RISK_EMOJI[level]} |"
            )

        lines.extend(["", "## 3. 详细发现", ""])

        for level in RISK_ORDER:
            level_rows = [r for r in results if (r.get("risk_level") or "信息") == level]
            if not level_rows:
                continue
            idx = RISK_ORDER.index(level) + 1
            lines.append(f"### 3.{idx} {level}风险")
            lines.append("")
            for r in level_rows:
                detail = r.get("risk_detail", {})
                lines.append(
                    f"- **{r['host_ip']}:{r['port']}/{r['protocol']}** "
                    f"{r.get('service_name', '')} {r.get('banner', '')}"
                )
                if detail.get("threat_type"):
                    lines.append(f"  - 威胁类型: {detail['threat_type']}")
                if detail.get("description"):
                    lines.append(f"  - 描述: {detail['description']}")
                if detail.get("recommendation"):
                    lines.append(f"  - 建议: {detail['recommendation']}")
                refs = detail.get("references", [])
                if refs:
                    lines.append(f"  - 参考: {', '.join(str(x) for x in refs)}")
            lines.append("")

        lines.extend(["## 4. 修复建议优先级", ""])
        recommendations = self._collect_recommendations(results)
        if recommendations:
            for i, rec in enumerate(recommendations[:10], 1):
                lines.append(f"{i}. {rec}")
        else:
            lines.append("1. 暂无 AI 分析结果，建议先运行 AI 分析。")

        scan_cfg = data["scan_cfg"]
        lines.extend(
            [
                "",
                "## 5. 技术细节",
                "",
                f"- 扫描参数: {SCAN_TYPE_MAP.get(data['scan_type'], '-sT')} "
                f"-p {scan_cfg['default_ports']}",
                f"- 线程数: {scan_cfg['max_threads']}",
                f"- 超时设置: {scan_cfg['timeout']}秒",
                "",
                "## 6. 附录",
                "",
                "### 完整端口列表",
                "",
                "| 主机 | 端口 | 协议 | 状态 | 服务 | 风险 |",
                "|------|------|------|------|------|------|",
            ]
        )

        for r in results:
            lines.append(
                f"| {r['host_ip']} | {r['port']} | {r['protocol']} | "
                f"{r['state']} | {r.get('service_name', '')} | {r.get('risk_level', '信息')} |"
            )

        lines.extend(
            [
                "",
                f"- 原始数据: data/scan_results.db (task_id={data['task_id']})",
                "",
            ]
        )
        return "\n".join(lines)

    def _collect_recommendations(self, results: list[dict[str, Any]]) -> list[str]:
        """按风险优先级收集去重修复建议。"""
        seen: set[str] = set()
        recs: list[str] = []
        priority = {"高危": 0, "中危": 1, "低危": 2, "信息": 3}
        sorted_rows = sorted(
            results,
            key=lambda r: priority.get(r.get("risk_level", "信息"), 9),
        )
        for row in sorted_rows:
            rec = row.get("risk_detail", {}).get("recommendation", "")
            if rec and rec not in seen:
                seen.add(rec)
                recs.append(rec)
        return recs

    def _risk_chart_css(self, counts: dict[str, int]) -> str:
        """用 conic-gradient 生成风险分布饼图 CSS（标准语法）。"""
        total = sum(counts.values())
        if total == 0:
            return "background: #555555;"
        angles: list[str] = []
        current = 0.0
        for level in RISK_ORDER:
            pct = counts[level] / total * 360
            if pct > 0:
                color = RISK_COLORS[level]
                angles.append(f"{color} {current:.2f}deg {current + pct:.2f}deg")
                current += pct
        if not angles:
            return "background: #555555;"
        gradient = ", ".join(angles)
        return f"background: conic-gradient(from 0deg, {gradient});"

    def _build_chart_html(self, data: dict[str, Any], session_dir: Optional[Path]) -> str:
        """构建 HTML 报告顶部图表区：优先嵌入 PNG，回退 CSS 饼图。"""
        ss = None
        if session_dir:
            ss = Path(session_dir) / "screenshots"
        elif (self.output_dir / "screenshots").exists():
            ss = self.output_dir / "screenshots"

        img_blocks = []
        if ss:
            for name, label in [
                ("risk_distribution.png", "Risk Distribution"),
                ("open_ports.png", "Open Ports"),
            ]:
                img_path = ss / name
                if img_path.exists():
                    rel = f"screenshots/{name}"
                    img_blocks.append(
                        f'<div class="chart-item"><p>{label}</p>'
                        f'<img src="{rel}" alt="{label}" style="max-width:100%;border-radius:8px;"></div>'
                    )

        if img_blocks:
            return f'<div class="chart-wrap imgs">{"".join(img_blocks)}</div>'

        counts = self._count_risks(data["results"])
        chart_style = self._risk_chart_css(counts)
        legend = " ".join(
            f'<span><span class="dot" style="background:{RISK_COLORS[l]}"></span>'
            f'{RISK_LABELS_EN.get(l, l)} {counts[l]}</span>'
            for l in RISK_ORDER
        )
        return f"""<div class="chart-wrap">
      <div class="pie" style="{chart_style}"></div>
      <div class="legend">{legend}</div>
    </div>"""

    def _markdown_to_html(
        self,
        md_content: str,
        data: dict[str, Any],
        session_dir: Optional[Path] = None,
    ) -> str:
        """将 Markdown 转为带样式的 HTML 报告。"""
        body = markdown.markdown(md_content, extensions=["tables", "fenced_code"])
        chart_html = self._build_chart_html(data, session_dir)
        is_dark = self.theme == "dark"
        bg = "#1a1a2e" if is_dark else "#f5f5f5"
        fg = "#eaeaea" if is_dark else "#222"
        card = "#16213e" if is_dark else "#fff"

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>InsightScan 报告 - {data['target']}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: {bg}; color: {fg}; margin: 0; padding: 20px; line-height: 1.6; }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  .card {{ background: {card}; border-radius: 8px; padding: 24px; margin-bottom: 20px;
           box-shadow: 0 2px 8px rgba(0,0,0,0.2); }}
  h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 8px; }}
  h2 {{ color: #0f3460; margin-top: 24px; }}
  h3 {{ color: #533483; }}
  table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
  th, td {{ border: 1px solid #444; padding: 8px 12px; text-align: left; }}
  th {{ background: #0f3460; color: #fff; }}
  tr:nth-child(even) {{ background: rgba(255,255,255,0.05); }}
  .chart-wrap {{ display: flex; align-items: center; gap: 24px; flex-wrap: wrap; }}
  .chart-wrap.imgs {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }}
  .chart-item {{ text-align: center; }}
  .pie {{ width: 160px; height: 160px; border-radius: 50%; flex-shrink: 0; }}
  .legend span {{ display: inline-block; margin-right: 16px; }}
  .dot {{ display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 4px; }}
  .risk-high {{ color: {RISK_COLORS['高危']}; font-weight: bold; }}
  .risk-medium {{ color: {RISK_COLORS['中危']}; }}
  .risk-low {{ color: {RISK_COLORS['低危']}; }}
  .risk-info {{ color: {RISK_COLORS['信息']}; }}
  @media (max-width: 600px) {{ body {{ padding: 10px; }} .card {{ padding: 14px; }} }}
</style>
</head>
<body>
<div class="container">
  <div class="card">
    {chart_html}
  </div>
  <div class="card">
    {body}
  </div>
</div>
</body>
</html>"""


if __name__ == "__main__":
    """阶段 4 验收：生成 Markdown 报告。"""
    log = setup_logging()
    log.info("=== InsightScan 阶段 4 验收测试 ===")

    gen = ReportGenerator()
    conn = get_db_connection()
    if isinstance(conn, dict):
        log.error("数据库连接失败")
        raise SystemExit(1)

    latest = conn.execute(
        "SELECT task_id FROM scan_tasks ORDER BY task_id DESC LIMIT 1"
    ).fetchone()
    conn.close()

    if not latest:
        log.error("无扫描任务，请先运行 scan_engine.py")
        raise SystemExit(1)

    task_id = latest["task_id"]
    log.info("为 task_id=%d 生成 Markdown 报告", task_id)
    result = gen.generate(task_id, fmt="markdown")
    if "error" in result:
        log.error("生成失败: %s", result["error"])
        raise SystemExit(1)

    log.info("Markdown 报告: %s", result["file_path"])

    log.info("生成 HTML 报告（可选）")
    html_result = gen.generate(task_id, fmt="html")
    if "error" not in html_result:
        log.info("HTML 报告: %s", html_result["file_path"])

    log.info("=== 阶段 4 验收测试完成 ===")
