# InsightScan 项目现状

> 最后更新：2026-07-07（攻击报告目标一致性 · 四页目标同步 · SYN/FIN sudo 路径 · Nmap 配置同步）  
> 适用环境：Ubuntu 22.04 VM + VMware 共享文件夹 `/mnt/hgfs/insightscan`

| 文档 | 用途 |
|------|------|
| **[InsightScan_项目说明.md](InsightScan_项目说明.md)** | 任务书 / 答辩：结构、亮点、流程 |
| [README.md](README.md) | 安装、**SYN/OS 权限配置**、命令速查 |
| [InsightScan_完整思路书.md](InsightScan_完整思路书.md) | 原始设计 + 已实现扩展 |
| [环境准备.md](环境准备.md) | 环境搭建 |
| [1.md](1.md)–[4.md](4.md) | 四人分工与对应文件 |

---

## 一、当前环境（示例，以 VM 检测为准）

| 项目 | 值 |
|------|-----|
| 本机 IP | `192.168.61.128`（IP 配置页「检测并应用」） |
| 网段 | `192.168.61.0/24` |
| 网卡 | `ens33` |
| AI 模型 | `kimi-k2.6` |
| API | `https://api.moonshot.cn/v1` |
| Nmap | 7.80+ |
| SYN/FIN/OS 权限 | `sudo -n nmap --version` 免密成功即就绪 |
| Web 前端缓存 | `main.js?v=20260707f`（改 JS 后需硬刷新） |

```bash
ip addr | grep "inet "
sudo -n nmap --version    # 验证 SYN/FIN/OS 权限
sudo -n nmap -sF -p 22,80 1.2.3.4   # 验证 FIN 免密
python3 run_web.py        # 勿 sudo python3
```

---

## 二、已完成功能

| 模块 | 文件 | 状态 |
|------|------|------|
| 配置 / 数据库 | `src/utils.py` | ✅ |
| Nmap 扫描引擎 | `src/scan_engine.py` | ✅ Connect/SYN/FIN；目标过滤；SYN/FIN 走 `sudo -n nmap` |
| AI 分析 | `src/ai_analyzer.py` | ✅ Kimi + 缓存 + 降级；**按任务目标过滤端口** |
| 报告生成 | `src/report_generator.py` | ✅ MD/HTML；**过滤非目标主机并重算统计** |
| CLI 入口 | `main.py` | ✅ |
| 主动探测 | `src/attack_mode.py` | ✅ 攻击套件；**Connect 优先选报告 task** |
| 被动防御 | `src/defense_mode.py` | ✅ syslog + DB 联动；本机自查 `save_db=False` |
| 安全工具 | `src/security_tools.py` | ✅ 防御规则可按暴露端口生成 |
| 性能实验 | `src/perf_benchmark.py` | ✅ |
| 协议分析 | `src/protocol_analyzer.py` | ✅ |
| Web 控制台 | `web/` + `run_web.py` | ✅ **四页** + 攻防联调 + **四下拉框目标同步** |
| **Nmap 教学** | `nmap_lab/` | ✅ Zenmap / 四种扫描 / HTML+XML；**可从 IP 配置同步目标** |
| Web 配置 | `src/ui_config.py` | ✅ `resolve_target`、实时网段检测 |
| 单元测试 | `tests/` | ✅ |
| 项目文档 | 三份主文档 + 环境准备 + 分工 1–4 | ✅ 已同步 |

---

## 三、2026-07-07 重要修复（攻击报告 / 目标 IP）

### 3.1 问题现象

- 页面选 `1.2.3.4` 或 `127.0.0.1`，攻击报告却出现本机局域网 IP 的开放端口  
- 单独攻击、攻防联调均可能复现  
- 概览「总开放端口」与详细列表不一致  

### 3.2 根因

| # | 根因 | 说明 |
|---|------|------|
| 1 | 前端目标不同步 | `attack-solo-target-select` 未纳入联调目标同步，单独攻击仍可能扫 IP 配置页本机 IP |
| 2 | 报告 task 选取错误 | 曾按「开放端口最多」选 task，易误用其它扫描任务 |
| 3 | 报告统计未过滤 | 概览读 `scan_tasks.total_ports`，未按 `host_ip == target` 重算 |
| 4 | AI 未过滤 | `analyze_task` 分析了 task 下全部 `scan_results` 行 |
| 5 | 防御自查污染 | 防御末轮 `127.0.0.1` 自查曾写入 DB（已改为 `save_db=False`） |

### 3.3 已实施修复

| 层级 | 文件 | 修复要点 |
|------|------|----------|
| 前端 | `web/static/js/main.js` | `attackTargetPrefs` + `ATTACK_TARGET_BINDINGS` 同步四个下拉框；攻击/联调/性能均读页面目标 |
| 后端 API | `web/app.py` | `/api/attack` 优先用页面 `target`；联调 `_resolve_drill_targets` 以页面为准 |
| 扫描 | `src/scan_engine.py` | `_filter_hosts_by_target()` 入库前丢弃非目标主机 |
| 攻击 | `src/attack_mode.py` | `_select_report_task_id()`：目标一致 + **优先 Connect** |
| 报告 | `src/report_generator.py` | 单 IP / CIDR 过滤结果；`total_hosts` / `total_ports` 从过滤后重算 |
| AI | `src/ai_analyzer.py` | `_filter_rows_by_target()` 只分析目标主机端口 |
| 防御 | `src/defense_mode.py` | 本机端口自查不入库，避免污染攻击报告库 |

### 3.4 验收方法

```text
1. 浏览器 Ctrl+Shift+R 硬刷新（加载 main.js?v=20260707f）
2. 主动探测 → 自定义 IP → 1.2.3.4，端口 22,631 → 一键攻击
3. 报告应显示：目标 1.2.3.4，开放端口 0，无 127.0.0.1 条目
4. 日志应出现：API /attack: target=1.2.3.4 ...
5. 127.0.0.1 扫描应只显示本机实际开放端口
```

---

## 四、验收结果摘要

### 4.1 主动探测

- 本机 `127.0.0.1`：端口扫描 + AI 报告正常  
- 一键攻击套件：Connect + SYN + FIN；**报告基于 Connect 且目标一致**  
- SYN/FIN：配置 `scripts/setup_nmap_sudoers.sh` 后 Web 侧 `sudo -n nmap` 可用  
- 自定义不可达 IP（如 `1.2.3.4`）：报告 0 开放端口，无本机端口串台  

### 4.2 性能实验（C 段示例）

| 线程 | 耗时 | 结论 |
|------|------|------|
| 10 | ~60s | |
| 50 | **~28s** | **最优** |
| 100 | ~32s | CPU 饱和略慢 |

性能测试目标与主动探测页下拉框一致（不再误用 IP 配置页 perf_target）。

### 4.3 被动防御

- syslog 对 Connect 常为 0（预期）  
- **数据库联动**可检测联调期间扫描  
- iptables 脚本、混杂模式检测正常  
- 防御本机自查仅用于规则参考，**不写入 scan_results.db**  

### 4.4 Web 控制台（四 Tab）

| Tab | 验收要点 |
|-----|---------|
| 主动探测 | 单独攻击 / 攻防联调 / 全套攻击 / 性能测试；**目标以本页下拉为准** |
| 被动防御 | 接续攻击、自动联调；防御监听 IP 与攻击目标一致 |
| IP 配置 | 检测网段、保存后四页目标同步；Nmap 教学页可「从 IP 配置同步」 |
| **Nmap扫描与对比教学** | 五按钮独立运行；SYN/OS 需 sudo 免密 nmap |

### 4.5 Nmap 教学模块

| 能力 | 说明 |
|------|------|
| Zenmap 演示 | Web 双栏主机/端口 + CLI ASCII 输出 |
| Connect (-sT) | 普通用户即可 |
| SYN (-sS) / OS (-O) | 配置 sudo 免密 nmap 后 Web 可用 |
| 全端口 | Web 固定 1-1000 |
| 报告 | `scan.html` + `scan.xml` |
| 目标同步 | 「从 IP 配置同步」+ 检测/保存配置时自动同步 |

**权限方案（用户名用 `whoami`，路径用 `which nmap`）**：

```bash
cd /mnt/hgfs/insightscan
bash scripts/setup_nmap_sudoers.sh
# 或手动：
echo "$(whoami) ALL=(ALL) NOPASSWD: $(which nmap)" | sudo tee /etc/sudoers.d/insightscan-nmap
sudo chmod 440 /etc/sudoers.d/insightscan-nmap
sudo -n nmap --version
python3 run_web.py
```

---

## 五、报告目录规范

```
reports/
├── attack_YYYYMMDD_HHMMSS/
│   ├── attack_report.md / .html
│   ├── summary.json          # 含 target、task_id、attack_suite
│   └── screenshots/
├── defense_YYYYMMDD_HHMMSS/
│   ├── defense_report.md
│   ├── iptables_defense.sh
│   └── scan_events.json
└── nmap_lab/
    └── connect_20260707_120000/
        ├── scan.html
        └── scan.xml
```

Web 报告 URL：`http://<IP>:8080/reports/<会话目录>/attack_report.html`

---

## 六、核心命令速查

```bash
cd /mnt/hgfs/insightscan

# ① SYN/FIN/OS 权限（首次）
bash scripts/setup_nmap_sudoers.sh
sudo -n nmap --version

# ② Web（普通用户）
python3 run_web.py

# ③ CLI 攻防
python3 main.py --attack -t 127.0.0.1 --ports 22,80,443
python3 main.py --attack -t 1.2.3.4 --ports 22,631   # 应 0 开放端口
python3 main.py --defense --duration 60

# ④ Nmap 教学 CLI
python3 nmap_lab/zenmap_demo.py
python3 nmap_lab/scan_types_demo.py
```

---

## 七、已知问题与限制

| # | 问题 | 说明 / 应对 |
|---|------|------------|
| 1 | Connect 扫描 syslog 无特征 | 防御 DB 联动；可选 `sudo ufw logging on` |
| 2 | SYN/FIN/OS 需 root | 配置 sudoers 后 Web 通过 `sudo -n nmap` 调用 |
| 3 | 勿 `sudo python3 run_web.py` | 会缺 pip 包；用普通用户启动 Web |
| 4 | 浏览器不能直接看 XML | 已生成 `scan.html`；XML 供下载/Zenmap |
| 5 | 全端口 Web 固定 1-1000 | 实验书 1-65535，CLI 说明中保留 |
| 6 | VMware 共享目录不宜 venv | `pip3 install --user -r requirements.txt` |
| 7 | AI 缓存 | 清空 `data/ai_cache.json` 可强制调 API |
| 8 | Windows 开发机 | 演示请在 Ubuntu VM；改 JS 后硬刷新 |
| 9 | 历史 DB 脏数据 | 旧 task 可能含混 host；新扫描已过滤；必要时删 `data/scan_results.db` 重建 |

---

## 八、待办（可选扩展）

- [x] Web 四页 + Nmap 扫描与对比教学  
- [x] nmap_lab 模块 + sudo 免密 nmap 方案  
- [x] 攻击报告目标一致性修复（2026-07-07）  
- [x] 四页目标下拉框同步 + Nmap 目标同步  
- [ ] Metasploitable / DVWA 靶机联调  
- [ ] Wireshark 手动抓包截图进报告  

---

## 九、答辩演示推荐顺序

1. **IP 配置** → 检测并应用 → 保存（各页目标同步）  
2. **Nmap扫描与对比教学** → Connect → SYN → 打开 `scan.html`  
3. **InsightScan 增强分析** → 对比 AI 报告  
4. **主动探测** → 自定义 `127.0.0.1` → 一键攻击 → 核对报告目标与端口  
5. **一键攻防联调** → 攻击 + 防御双报告（目标 IP 一致）  

---

## 十、新会话快速开始

```bash
cd /mnt/hgfs/insightscan
sudo -n nmap --version
python3 run_web.py
# http://<VM_IP>:8080 → 硬刷新后测试攻击报告
```

---

## 十一、相关文档

| 文档 | 何时读 |
|------|--------|
| **README.md** | 权限配置、日常命令 |
| **InsightScan_项目说明.md** | 任务书、答辩 |
| **InsightScan_完整思路书.md** | 模块设计与扩展说明 |
| [1.md](1.md)–[4.md](4.md) | 四人分工 |
| 环境准备.md | 首次搭 VM |
