"""会话报告目录管理。"""

from datetime import datetime
from pathlib import Path

from src.utils import REPORTS_DIR


def create_session_dir(mode: str) -> Path:
    """
    创建 attack_时间 或 defense_时间 报告目录。

    Args:
        mode: attack 或 defense。

    Returns:
        会话目录路径（含 screenshots 子目录）。
    """
    prefix = "attack" if mode == "attack" else "defense"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = REPORTS_DIR / f"{prefix}_{timestamp}"
    (session_dir / "screenshots").mkdir(parents=True, exist_ok=True)
    return session_dir
