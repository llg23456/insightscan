"""多线程扫描性能基准测试。"""

import json
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import psutil

from src.scan_engine import ScanEngine
from src.utils import get_setting, setup_logging
from src.visual_export import save_benchmark_table, save_resource_chart, save_thread_perf_chart


class ResourceMonitor:
    """后台采样 CPU 和内存占用。"""

    def __init__(self) -> None:
        self.samples: list[dict[str, float]] = []
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._start_time = 0.0

    def start(self) -> None:
        self._start_time = time.time()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> list[dict[str, float]]:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        return self.samples

    def _run(self) -> None:
        proc = psutil.Process()
        while not self._stop.is_set():
            elapsed = time.time() - self._start_time
            try:
                cpu = psutil.cpu_percent(interval=0.5)
                mem = proc.memory_info().rss / 1024 / 1024
            except Exception:
                cpu, mem = 0.0, 0.0
            self.samples.append(
                {"elapsed": round(elapsed, 1), "cpu_percent": cpu, "memory_mb": round(mem, 1)}
            )


def run_thread_benchmark(
    target: str,
    ports: str = "22,80,443",
    thread_counts: Optional[list[int]] = None,
    session_dir: Optional[Path] = None,
) -> dict[str, Any]:
    """
    运行 10/50/100 线程性能对比实验。

    Args:
        target: 扫描目标（建议 C 段如 192.168.1.0/24）。
        ports: 端口范围。
        thread_counts: 线程数列表，默认 [10, 50, 100]。
        session_dir: 报告输出目录。

    Returns:
        含 benchmark 数据和图表路径的字典。
    """
    log = setup_logging()
    thread_counts = thread_counts or [10, 50, 100]
    benchmark: list[dict[str, Any]] = []
    resource_samples_all: list[dict[str, float]] = []
    time_offset = 0.0

    for run_idx, threads in enumerate(thread_counts):
        log.info("性能测试: threads=%d target=%s", threads, target)
        engine = ScanEngine()
        engine.max_threads = threads

        monitor = ResourceMonitor()
        monitor.start()
        t0 = time.time()
        result = engine.scan(target, ports=ports, save_db=True)
        duration = time.time() - t0
        samples = monitor.stop()

        if "error" in result:
            log.warning("threads=%d 扫描失败: %s", threads, result["error"])
            continue

        cpu_peak = max((s["cpu_percent"] for s in samples), default=0)
        mem_peak = max((s["memory_mb"] for s in samples), default=0)
        entry = {
            "threads": threads,
            "duration_sec": round(duration, 2),
            "hosts": result["stats"].get("total_hosts", 0),
            "ports": result["stats"].get("total_ports", 0),
            "scanned_hosts": result["stats"].get("scanned_hosts", 0),
            "cpu_peak": round(cpu_peak, 1),
            "mem_peak_mb": round(mem_peak, 1),
            "task_id": result.get("task_id"),
        }
        benchmark.append(entry)
        # 每轮采样加时间偏移，避免多轮数据叠加导致折线回环
        for s in samples:
            resource_samples_all.append(
                {
                    "run": run_idx,
                    "elapsed": round(time_offset + s["elapsed"], 1),
                    "cpu_percent": s["cpu_percent"],
                    "memory_mb": s["memory_mb"],
                    "threads": threads,
                }
            )
        time_offset += duration + 5
        log.info("  耗时=%.2fs CPU峰值=%.1f%% 内存峰值=%.1fMB", duration, cpu_peak, mem_peak)

    output: dict[str, Any] = {"benchmark": benchmark, "target": target, "ports": ports}
    if session_dir and benchmark:
        ss = session_dir / "screenshots"
        ss.mkdir(parents=True, exist_ok=True)
        output["perf_chart"] = save_thread_perf_chart(benchmark, ss / "thread_perf_comparison.png")
        output["resource_chart"] = save_resource_chart(
            resource_samples_all[-100:], ss / "cpu_memory_usage.png"
        )
        output["perf_table"] = save_benchmark_table(benchmark, session_dir / "perf_benchmark")
        table_path = session_dir / "perf_benchmark.md"
        table_path.write_text(
            _render_perf_report(benchmark, target), encoding="utf-8"
        )
        output["perf_report"] = str(table_path)

    return output


def _render_perf_report(benchmark: list[dict[str, Any]], target: str) -> str:
    """生成性能实验 Markdown 报告。"""
    lines = [
        "# 多线程性能对比实验 (EXP-04)",
        "",
        f"**目标**: {target}",
        "",
        "| 线程数 | 耗时(秒) | 扫描主机数 | 开放端口 | CPU峰值% | 内存峰值MB |",
        "|--------|---------|-----------|---------|----------|-----------|",
    ]
    for r in benchmark:
        lines.append(
            f"| {r['threads']} | {r['duration_sec']:.2f} | {r.get('scanned_hosts', 0)} | "
            f"{r.get('ports', 0)} | {r.get('cpu_peak', 0):.1f} | {r.get('mem_peak_mb', 0):.1f} |"
        )
    lines.extend([
        "",
        "## 结论参考",
        "- 线程数增加可缩短 C 段扫描总耗时",
        "- 线程过多时 CPU 占用上升，需根据 VM 配置选择最优值",
        "",
        "截图: screenshots/thread_perf_comparison.png, screenshots/cpu_memory_usage.png",
    ])
    return "\n".join(lines)


if __name__ == "__main__":
    from src.session_paths import create_session_dir

    session = create_session_dir("attack")
    result = run_thread_benchmark("127.0.0.1", "22", [10, 50], session)
    print(json.dumps(result, ensure_ascii=False, indent=2))
