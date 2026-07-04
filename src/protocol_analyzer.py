"""协议分析：TCP/HTTP/FTP 数据包字段图解（实验用）。"""

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.utils import setup_logging

plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "WenQuanYi Micro Hei", "SimHei", "Arial"]
plt.rcParams["axes.unicode_minus"] = False


def _draw_packet_diagram(
    title: str,
    layers: list[tuple[str, list[str]]],
    output: Path,
) -> str:
    """绘制协议分层字段标注图。"""
    fig, ax = plt.subplots(figsize=(12, max(4, len(layers) * 1.2 + 1)))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, len(layers) + 1)
    ax.axis("off")
    ax.set_title(title, fontsize=14, fontweight="bold")

    for i, (layer_name, fields) in enumerate(layers):
        y = len(layers) - i
        rect = mpatches.FancyBboxPatch(
            (0.5, y - 0.35), 9, 0.7,
            boxstyle="round,pad=0.05",
            facecolor="#3498db" if i == 0 else "#2ecc71" if i == 1 else "#e67e22",
            edgecolor="black",
            alpha=0.7,
        )
        ax.add_patch(rect)
        field_text = " | ".join(fields)
        ax.text(5, y, f"{layer_name}: {field_text}", ha="center", va="center", fontsize=9)

    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=120, bbox_inches="tight")
    plt.close(fig)
    return str(output)


def generate_protocol_diagrams(output_dir: Path) -> dict[str, Any]:
    """
    生成 TCP 三次握手、HTTP、FTP 协议字段标注图。

    Args:
        output_dir: screenshots 目录。

    Returns:
        生成的图片路径字典。
    """
    logger = setup_logging()
    screenshots = output_dir / "screenshots" if (output_dir / "screenshots").exists() else output_dir
    screenshots.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}

    # TCP 三次握手
    paths["tcp_handshake"] = _draw_packet_diagram(
        "TCP Three-Way Handshake (Wireshark Analysis Reference)",
        [
            ("Step1 SYN", ["Src Port", "Dst Port=80", "Seq=x", "Flags=SYN", "Win Size"]),
            ("Step2 SYN-ACK", ["Seq=y", "Ack=x+1", "Flags=SYN+ACK", "MSS", "Window Scale"]),
            ("Step3 ACK", ["Seq=x+1", "Ack=y+1", "Flags=ACK", "Connection Established"]),
        ],
        screenshots / "protocol_tcp_handshake.png",
    )

    # HTTP 请求响应
    paths["http"] = _draw_packet_diagram(
        "HTTP Request/Response (Wireshark Analysis Reference)",
        [
            ("HTTP Request", ["Method=GET", "URI=/index.html", "Host: header", "User-Agent", "Accept"]),
            ("TCP Header", ["Src/Dst Port", "Seq/Ack", "Flags=PSH+ACK", "Payload Length"]),
            ("HTTP Response", ["Status=200 OK", "Content-Type", "Content-Length", "Server", "Body HTML"]),
        ],
        screenshots / "protocol_http.png",
    )

    # FTP 双通道
    paths["ftp"] = _draw_packet_diagram(
        "FTP Dual-Channel (Control + Data)",
        [
            ("Control Channel :21", ["USER anonymous", "PASS", "PORT cmd", "Response 220/331/230"]),
            ("Data Channel :20/N", ["LIST/RETR", "Passive PORT/PASV", "File Transfer Data"]),
            ("TCP Fields", ["Src Port", "Dst Port", "Seq/Ack", "Flags", "Payload ASCII"]),
        ],
        screenshots / "protocol_ftp.png",
    )

    logger.info("协议分析图已生成: %d 张", len(paths))
    return {"diagrams": paths}


def capture_with_tshark(output_dir: Path, duration: int = 5) -> dict[str, Any]:
    """
    若系统安装了 tshark，抓取本机流量并导出摘要。

    Args:
        output_dir: 输出目录。
        duration: 抓包秒数。

    Returns:
        抓包结果字典。
    """
    logger = setup_logging()
    tshark = shutil.which("tshark")
    if not tshark:
        return {
            "available": False,
            "message": "tshark 未安装，已生成协议参考标注图。安装: sudo apt install tshark",
        }

    pcap_path = output_dir / "capture.pcap"
    try:
        subprocess.run(
            [
                tshark, "-i", "any", "-a", f"duration:{duration}",
                "-w", str(pcap_path), "-f", "tcp port 22 or tcp port 80 or tcp port 21",
            ],
            capture_output=True,
            timeout=duration + 15,
            check=False,
        )
        summary_path = output_dir / "capture_summary.txt"
        proc = subprocess.run(
            [tshark, "-r", str(pcap_path), "-T", "fields",
             "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
             "-e", "tcp.flags", "-e", "tcp.port", "-e", "http.request.method",
             "-e", "ftp.request.command"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        summary_path.write_text(proc.stdout or "No packets captured", encoding="utf-8")
        return {
            "available": True,
            "pcap": str(pcap_path),
            "summary": str(summary_path),
            "packet_count": len(proc.stdout.splitlines()) if proc.stdout else 0,
        }
    except Exception as e:
        logger.warning("tshark 抓包失败: %s", e)
        return {"available": False, "error": str(e)}


if __name__ == "__main__":
    from src.session_paths import create_session_dir

    session = create_session_dir("attack")
    result = generate_protocol_diagrams(session)
    print(result)
    print(capture_with_tshark(session))
