"""图表与截图导出（matplotlib PNG）。"""

import json
from pathlib import Path
from typing import Any, Optional

import matplotlib
import matplotlib.font_manager as fm

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from src.report_generator import RISK_COLORS, RISK_ORDER

# 风险等级英文标签（避免 Ubuntu 缺中文字体出现 □□）
RISK_LABELS_EN = {
    "高危": "Critical",
    "中危": "High",
    "低危": "Medium",
    "信息": "Info",
}


def _setup_matplotlib_font() -> None:
    """配置 matplotlib 字体，优先中文字体，否则用英文。"""
    candidates = [
        "WenQuanYi Micro Hei",
        "Noto Sans CJK SC",
        "SimHei",
        "DejaVu Sans",
    ]
    available = {f.name for f in fm.fontManager.ttflist}
    for name in candidates:
        if name in available:
            plt.rcParams["font.sans-serif"] = [name, "DejaVu Sans"]
            break
    plt.rcParams["axes.unicode_minus"] = False


_setup_matplotlib_font()


def save_risk_pie_chart(counts: dict[str, int], output: Path, title: str = "Risk Distribution") -> str:
    """生成风险分布饼图 PNG。"""
    labels = [
        f"{RISK_LABELS_EN.get(k, k)} ({counts.get(k, 0)})"
        for k in RISK_ORDER
        if counts.get(k, 0) > 0
    ]
    sizes = [counts[k] for k in RISK_ORDER if counts.get(k, 0) > 0]
    colors = [RISK_COLORS[k] for k in RISK_ORDER if counts.get(k, 0) > 0]
    if not sizes:
        labels, sizes, colors = ["No open ports / no risk data"], [1], ["#999999"]

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=90)
    ax.set_title(title)
    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=120, bbox_inches="tight")
    plt.close(fig)
    return str(output)


def save_port_bar_chart(ports: list[dict[str, Any]], output: Path) -> str:
    """生成开放端口柱状图 PNG。"""
    fig, ax = plt.subplots(figsize=(10, 5))
    if not ports:
        ax.text(
            0.5, 0.5,
            "No open ports detected on target.\nTry: -t 127.0.0.1 --ports 22,80,443",
            ha="center", va="center", fontsize=12, transform=ax.transAxes,
        )
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis("off")
        ax.set_title("Open Ports (Top 15)")
    else:
        labels = [f"{p.get('port')}/{p.get('service_name', '') or 'unknown'}" for p in ports[:15]]
        values = [1] * len(labels)
        ax.barh(labels, values, color="#3498db")
        ax.set_xlabel("Detected")
        ax.set_title("Open Ports (Top 15)")
    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=120, bbox_inches="tight")
    plt.close(fig)
    return str(output)


def save_thread_perf_chart(benchmark: list[dict[str, Any]], output: Path) -> str:
    """生成多线程性能对比柱状图。"""
    threads = [str(r["threads"]) for r in benchmark]
    durations = [r["duration_sec"] for r in benchmark]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(threads, durations, color=["#2ecc71", "#3498db", "#e74c3c"])
    ax.set_xlabel("Threads")
    ax.set_ylabel("Duration (seconds)")
    ax.set_title("Multi-thread Scan Performance")
    for bar, val in zip(bars, durations):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f"{val:.1f}s", ha="center", va="bottom")
    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=120, bbox_inches="tight")
    plt.close(fig)
    return str(output)


def save_resource_chart(samples: list[dict[str, float]], output: Path) -> str:
    """生成 CPU/内存占用折线图（按时间排序，避免折线回环）。"""
    if not samples:
        samples = [{"elapsed": 0, "cpu_percent": 0, "memory_mb": 0}]

    sorted_samples = sorted(samples, key=lambda s: (s.get("run", 0), s["elapsed"]))
    xs = [s["elapsed"] for s in sorted_samples]
    fig, ax1 = plt.subplots(figsize=(10, 5))
    ax1.plot(xs, [s["cpu_percent"] for s in sorted_samples], "r-", label="CPU %")
    ax1.set_xlabel("Elapsed (s)")
    ax1.set_ylabel("CPU %", color="r")
    ax2 = ax1.twinx()
    ax2.plot(xs, [s["memory_mb"] for s in sorted_samples], "b-", label="Memory MB")
    ax2.set_ylabel("Memory MB", color="b")
    ax1.set_title("CPU / Memory During Scan")
    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=120, bbox_inches="tight")
    plt.close(fig)
    return str(output)


def save_attack_timeline(events: list[dict[str, Any]], output: Path) -> str:
    """生成扫描攻击事件时间线图。"""
    fig, ax = plt.subplots(figsize=(10, max(3, len(events) * 0.4 + 1)))
    if not events:
        ax.text(0.5, 0.5, "No scan events detected", ha="center", va="center")
        ax.axis("off")
    else:
        labels = [f"{e.get('source_ip', '?')} -> {e.get('attack_type', 'scan')}" for e in events[:20]]
        y_pos = range(len(labels))
        colors = ["#e74c3c" if e.get("severity") == "high" else "#f39c12" for e in events[:20]]
        ax.barh(list(y_pos), [1] * len(labels), color=colors)
        ax.set_yticks(list(y_pos))
        ax.set_yticklabels(labels, fontsize=8)
        ax.set_title("Detected Scan / Attack Events")
    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=120, bbox_inches="tight")
    plt.close(fig)
    return str(output)


def save_promisc_chart(interfaces: list[dict[str, Any]], output: Path) -> str:
    """生成网卡混杂模式状态图。"""
    names = [i.get("interface", "?") for i in interfaces] or ["none"]
    status = [1 if i.get("promiscuous") else 0 for i in interfaces] or [0]
    colors = ["#e74c3c" if s else "#2ecc71" for s in status]

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(names, [1] * len(names), color=colors)
    ax.set_title("NIC Promiscuous Mode Status (Red=Promiscuous)")
    ax.set_ylabel("Status")
    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=120, bbox_inches="tight")
    plt.close(fig)
    return str(output)


def save_benchmark_table(benchmark: list[dict[str, Any]], output: Path) -> str:
    """保存性能对比 JSON 与 Markdown 表格。"""
    output.parent.mkdir(parents=True, exist_ok=True)
    json_path = output.with_suffix(".json")
    json_path.write_text(json.dumps(benchmark, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "| 线程数 | 耗时(秒) | 主机数 | 端口数 | CPU峰值% | 内存峰值MB |",
        "|--------|---------|--------|--------|----------|-----------|",
    ]
    for r in benchmark:
        lines.append(
            f"| {r['threads']} | {r['duration_sec']:.2f} | {r.get('hosts', 0)} | "
            f"{r.get('ports', 0)} | {r.get('cpu_peak', 0):.1f} | {r.get('mem_peak_mb', 0):.1f} |"
        )
    md_path = output.with_suffix(".md")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return str(md_path)
