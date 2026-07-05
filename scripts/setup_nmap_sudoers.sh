#!/bin/bash
# 配置当前用户对 nmap 免密 sudo（自动读取 whoami，无需手填用户名）
# 用法: bash scripts/setup_nmap_sudoers.sh

NMAP_BIN="$(command -v nmap || true)"
[ -n "$NMAP_BIN" ] || { echo "请先: sudo apt install nmap"; exit 1; }

USER_NAME="$(whoami)"
LINE="$USER_NAME ALL=(ALL) NOPASSWD: $NMAP_BIN"
FILE="/etc/sudoers.d/insightscan-nmap"

echo "当前用户: $USER_NAME"
echo "写入规则: $LINE"
echo "$LINE" | sudo tee "$FILE" >/dev/null
sudo chmod 440 "$FILE"
echo "✅ 已配置，验证:"
sudo -n nmap --version && echo "→ 可 python3 run_web.py 后演示 SYN/OS"
