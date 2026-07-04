#!/usr/bin/env python3
"""InsightScan 主程序入口：扫描、AI 分析、报告生成、历史对比。"""

import argparse
import sqlite3
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.attack_mode import run_attack_mode
from src.defense_mode import run_defense_mode
from src.ai_analyzer import AIAnalyzer
from src.report_generator import ReportGenerator
from src.scan_engine import ScanEngine
from src.utils import get_db_connection, init_db, setup_logging, validate_ip, validate_ports


def build_parser() -> argparse.ArgumentParser:
    """构建 CLI 参数解析器。"""
    parser = argparse.ArgumentParser(
        prog="InsightScan",
        description="智能网络扫描与自动化分析工具",
    )
    parser.add_argument(
        "-t", "--target",
        help="扫描目标 IP 或 CIDR 网段，如 192.168.1.1 或 192.168.1.0/24",
    )
    parser.add_argument(
        "--scan-type",
        choices=["connect", "syn", "fin"],
        help="扫描方式: connect(默认)/syn/fin，syn/fin 需 sudo",
    )
    parser.add_argument(
        "--ports",
        help='端口范围，如 "1-1000" 或 "22,80,443"',
    )
    parser.add_argument(
        "--ai-analyze",
        action="store_true",
        help="扫描完成后自动进行 AI 风险分析",
    )
    parser.add_argument(
        "--analyze-task",
        type=int,
        metavar="ID",
        help="对已有扫描任务执行 AI 分析",
    )
    parser.add_argument(
        "--report-format",
        choices=["markdown", "html"],
        help="生成报告格式",
    )
    parser.add_argument(
        "--report-task",
        type=int,
        metavar="ID",
        help="为指定任务生成报告（默认最近一次）",
    )
    parser.add_argument(
        "--output", "-o",
        help="报告输出路径",
    )
    parser.add_argument(
        "--compare-with",
        metavar="DATE",
        help="历史对比基准日期 YYYY-MM-DD",
    )
    parser.add_argument(
        "--list-history",
        action="store_true",
        help="列出历史扫描任务",
    )
    parser.add_argument(
        "--attack",
        action="store_true",
        help="主动探测模式：全面扫描目标 + AI分析 + 报告 + 截图",
    )
    parser.add_argument(
        "--defense",
        action="store_true",
        help="被动防御模式：检测被扫描/混杂模式/iptables防御",
    )
    parser.add_argument(
        "--perf",
        action="store_true",
        help="attack 模式下运行多线程性能对比实验(10/50/100)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        help="defense 模式持续监控秒数（每10秒轮询）",
    )
    parser.add_argument(
        "--apply-iptables",
        action="store_true",
        help="defense 模式下自动部署 iptables 规则（需 sudo）",
    )
    return parser


def list_history() -> None:
    """打印历史扫描任务列表。"""
    log = setup_logging()
    conn = get_db_connection()
    if isinstance(conn, dict):
        log.error("数据库连接失败: %s", conn.get("error"))
        return

    rows = conn.execute(
        """
        SELECT task_id, target, scan_type, start_time, status,
               total_hosts, total_ports
        FROM scan_tasks ORDER BY start_time DESC LIMIT 50
        """
    ).fetchall()
    conn.close()

    if not rows:
        log.info("暂无扫描历史")
        return

    log.info("历史扫描任务（最近 50 条）:")
    log.info("%-6s %-18s %-8s %-20s %-10s %5s %5s",
             "ID", "目标", "类型", "时间", "状态", "主机", "端口")
    for r in rows:
        log.info(
            "%-6d %-18s %-8s %-20s %-10s %5d %5d",
            r["task_id"], r["target"], r["scan_type"],
            str(r["start_time"])[:19], r["status"],
            r["total_hosts"], r["total_ports"],
        )


def get_latest_task_id() -> int | None:
    """获取最近一次扫描任务 ID。"""
    conn = get_db_connection()
    if isinstance(conn, dict):
        return None
    row = conn.execute(
        "SELECT task_id FROM scan_tasks ORDER BY task_id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return row["task_id"] if row else None


def run_scan(args: argparse.Namespace) -> int | None:
    """
    执行扫描，返回 task_id。

    Args:
        args: CLI 参数。

    Returns:
        任务 ID 或 None。
    """
    log = setup_logging()
    ip_check = validate_ip(args.target)
    if not ip_check.get("valid"):
        log.error("目标无效: %s", ip_check.get("error"))
        return None

    if args.ports:
        port_check = validate_ports(args.ports)
        if not port_check.get("valid"):
            log.error("端口无效: %s", port_check.get("error"))
            return None

    engine = ScanEngine()
    result = engine.scan(
        target=args.target,
        scan_type=args.scan_type,
        ports=args.ports,
    )
    if "error" in result:
        log.error("扫描失败: %s", result["error"])
        return None

    task_id = result.get("task_id")
    log.info(
        "扫描完成 task_id=%s hosts=%d ports=%d 耗时=%ss",
        task_id,
        result["stats"]["total_hosts"],
        result["stats"]["total_ports"],
        result.get("duration"),
    )
    return task_id


def run_ai_analyze(task_id: int) -> None:
    """对任务执行 AI 分析。"""
    log = setup_logging()
    analyzer = AIAnalyzer()
    result = analyzer.analyze_task(task_id)
    if "error" in result:
        log.error("AI 分析失败: %s", result["error"])
        return
    log.info(
        "AI 分析完成 task_id=%d ports=%d cache_hits=%d",
        task_id, result.get("total_ports", 0), result.get("cache_hits", 0),
    )


def run_report(args: argparse.Namespace, task_id: int) -> None:
    """生成扫描报告。"""
    log = setup_logging()
    gen = ReportGenerator()
    result = gen.generate(
        task_id=task_id,
        fmt=args.report_format,
        output_path=args.output,
    )
    if "error" in result:
        log.error("报告生成失败: %s", result["error"])
        return
    log.info("报告已生成 [%s]: %s", result["format"], result["file_path"])


def run_compare(args: argparse.Namespace) -> None:
    """执行历史对比分析。"""
    log = setup_logging()
    if not args.target:
        log.error("历史对比需要指定 -t 目标 IP")
        return
    analyzer = AIAnalyzer()
    result = analyzer.compare_history(
        target=args.target,
        scan_type=args.scan_type,
        compare_date=args.compare_with,
    )
    if "error" in result:
        log.error("历史对比失败: %s", result["error"])
        return
    log.info(
        "对比完成: 基准 task=%s → 最新 task=%s 告警=%s",
        result.get("baseline_task_id"),
        result.get("latest_task_id"),
        result.get("alert"),
    )
    print(result.get("report", ""))


def main() -> None:
    """主入口。"""
    parser = build_parser()
    args = parser.parse_args()
    log = setup_logging()

    init_db()

    if args.attack:
        if not args.target:
            log.error("主动探测需要 -t 指定目标，例: python3 main.py --attack -t 127.0.0.1")
            sys.exit(1)
        result = run_attack_mode(
            target=args.target,
            ports=args.ports,
            scan_type=args.scan_type,
            run_perf=args.perf,
        )
        if "error" in result:
            log.error("主动探测失败: %s", result["error"])
            sys.exit(1)
        log.info("报告已输出到: %s", result["session_dir"])
        return

    if args.defense:
        result = run_defense_mode(
            duration_sec=args.duration,
            apply_iptables=args.apply_iptables,
        )
        if "error" in result:
            log.error("被动防御失败: %s", result["error"])
            sys.exit(1)
        log.info("报告已输出到: %s", result["session_dir"])
        return

    if args.list_history:
        list_history()
        return

    if args.analyze_task:
        run_ai_analyze(args.analyze_task)
        return

    if args.compare_with:
        if not args.target:
            log.error("历史对比需要配合 -t 指定目标 IP")
            sys.exit(1)
        run_compare(args)
        return

    if args.report_format or args.report_task or args.output:
        task_id = args.report_task or get_latest_task_id()
        if not task_id:
            log.error("无可用扫描任务，请先执行扫描")
            sys.exit(1)
        run_report(args, task_id)
        return

    if args.target:
        task_id = run_scan(args)
        if not task_id:
            sys.exit(1)
        if args.ai_analyze:
            run_ai_analyze(task_id)
            if args.report_format:
                run_report(args, task_id)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
