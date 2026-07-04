# InsightScan

智能网络扫描与自动化分析工具 —— 基于 **Nmap + Kimi AI**，覆盖扫描执行、结果解析、智能风险分析、报告生成与攻防实验的全流程。

| 文档 | 说明 |
|------|------|
| [InsightScan_项目现状.md](InsightScan_项目现状.md) | 当前进度、验收数据、已知问题 |
| [InsightScan_完整思路书.md](InsightScan_完整思路书.md) | 原始设计与模块说明 |
| [环境准备.md] | 最开始的ubuntu连接共享文件和准备操作 |

---

## 目录

- [功能特性](#功能特性)
- [环境要求](#环境要求)
- [安装与配置](#安装与配置)
- [快速开始](#快速开始)
- [Web 控制台](#web-控制台推荐)
- [CLI 命令](#cli-命令)
- [攻防联调](#攻防联调双终端)
- [查看本机网段](#查看本机网段)
- [项目结构](#项目结构)
- [配置说明](#配置说明)
- [实验指引](#实验指引)
- [运行测试](#运行测试)
- [安全注意事项](#安全注意事项)
- [技术栈](#技术栈)

---

## 功能特性

| 模块 | 能力 |
|------|------|
| 扫描引擎 | TCP Connect / SYN / FIN（SYN/FIN 需 root） |
| 并发扫描 | 可配置线程数，支持 CIDR 网段 |
| AI 分析 | Kimi API（kimi-k2.6）+ 本地规则降级 + 结果缓存 |
| 主动探测 | 扫描 → AI 分析 → Markdown/HTML 报告 + 图表截图 |
| 被动防御 | 被扫描检测、混杂模式检测、iptables 规则生成 |
| 性能实验 | 10/50/100 线程对比 + CPU/内存曲线 |
| 协议分析 | TCP/HTTP/FTP 字段标注图 + tshark 抓包（可选） |
| Web 控制台 | 三页界面：攻击 / 防御 / IP 配置，一键操作 |

---

## 环境要求

| 依赖 | 版本 / 说明 |
|------|-------------|
| 操作系统 | Linux 推荐（Ubuntu 22.04）；开发环境可用 VMware 共享文件夹 |
| Python | 3.10+ |
| Nmap | 7.80+（`sudo apt install nmap`） |
| Kimi API | [platform.moonshot.cn](https://platform.moonshot.cn/) 申请 Key |
| 可选 | `tshark`（`sudo apt install tshark wireshark-common`） |

---

## 安装与配置

```bash
# 克隆仓库
git clone https://github.com/<your-username>/insightscan.git
cd insightscan

# 创建虚拟环境（推荐）
python3 -m venv venv
source venv/bin/activate          # Linux / macOS
# venv\Scripts\activate           # Windows

# 安装依赖
pip install -r requirements.txt

# 配置 API Key
cp config/api_keys.json.example config/api_keys.json
# 编辑 config/api_keys.json，填入 kimi_api_key

# 初始化数据库与目录
python3 src/utils.py
```

> **注意**：`config/api_keys.json` 已在 `.gitignore` 中，请勿提交到 GitHub。

---

## 快速开始

### 方式一：Web 控制台（推荐）

```bash
python3 run_web.py
```

在浏览器打开终端提示的地址，例如：

- VM 内：`http://127.0.0.1:8080`
- 宿主机访问 VM：`http://<VM_IP>:8080`（如 `http://192.168.61.128:8080`）

> Flask 只在终端启动后端服务，**界面需在浏览器中打开**，不会自动弹出桌面窗口（有 GUI 时会尝试打开默认浏览器）。

### 方式二：CLI 一行命令

```bash
# 本机快速验证
python3 main.py --attack -t 127.0.0.1 --ports 22,80,443

# 被动防御
python3 main.py --defense --duration 60
```

报告输出目录：`reports/attack_YYYYMMDD_HHMMSS/` 或 `reports/defense_YYYYMMDD_HHMMSS/`

---

## Web 控制台（推荐）

启动后访问 `http://<主机IP>:8080`，顶部三个 Tab：

| Tab | 功能 | 说明 |
|-----|------|------|
| **主动探测** | 一键攻击 / 一键性能测试 | 扫描目标、AI 分析、生成报告与截图 |
| **被动防御** | 一键防御 | 检测被扫描、混杂模式、生成 iptables |
| **IP 配置** | 保存 / 自动检测 | 本机 IP、C 段、默认目标与端口 |

配置文件：`config/ui_settings.json`（可在 Web 页修改并保存）

环境变量（可选）：

| 变量 | 说明 |
|------|------|
| `INSIGHTSCAN_WEB_PORT` | 监听端口，默认 `8080` |
| `INSIGHTSCAN_NO_BROWSER=1` | 禁止启动时自动打开浏览器 |

---

## CLI 命令

### 主动探测（攻击方）

```bash
# 本机
python3 main.py --attack -t 127.0.0.1 --ports 22,80,443

# 整个 C 段（先确认网段，见下文）
python3 main.py --attack -t 192.168.61.0/24 --ports 22,80,443

# C 段 + 多线程性能实验
python3 main.py --attack -t 192.168.61.0/24 --ports 22,80,443 --perf
```

输出示例：

| 文件 | 说明 |
|------|------|
| `attack_report.md` / `.html` | 扫描 + AI 风险报告 |
| `summary.json` | 结构化结果 |
| `screenshots/` | 风险饼图、端口图、协议标注图 |
| `perf_benchmark.md` | 性能对比表（`--perf` 时） |

### 被动防御（防守方）

```bash
python3 main.py --defense                    # 单次检测
python3 main.py --defense --duration 60      # 持续监控 60 秒
sudo python3 main.py --defense --apply-iptables   # 自动部署 iptables
```

### 其他常用命令

```bash
# 基础扫描
python3 main.py -t 127.0.0.1 --scan-type connect --ports 22,80,443

# 扫描 + AI 分析
python3 main.py -t 127.0.0.1 --ports 22,80,443 --ai-analyze

# 生成报告
python3 main.py --report-format html --report-task 12

# 历史对比 / 查看历史
python3 main.py -t 127.0.0.1 --compare-with 2026-07-04
python3 main.py --list-history

# SYN/FIN 扫描（需 sudo）
sudo python3 main.py -t 127.0.0.1 --scan-type syn --ports 22,80
```

---

## 攻防联调（双终端）

防御模式要检测到扫描行为，需要**同时**有攻击流量。Web 或 CLI 均可：

**CLI 示例：**

```bash
# 终端 1：扫描本机局域网 IP
python3 main.py --attack -t 192.168.61.128 --ports 22,80,443

# 终端 2：立即跑防御（扫描进行中或刚结束）
python3 main.py --defense --duration 60
```

**Web 示例：**

1. 终端 A：保持 `python3 run_web.py` 运行
2. 浏览器 Tab 1 → 主动探测 → 选「本机局域网 IP」→ **一键攻击**
3. 浏览器 Tab 2 → 被动防御 → **一键防御**

若仍检测不到扫描事件，开启 UFW 日志：

```bash
sudo ufw logging on
sudo ufw status
```

---

## 查看本机网段

扫描 C 段前必须先确认实际网段，**不要硬编码 192.168.1.0/24**。

```bash
ip addr | grep "inet "
```

示例：

```
inet 127.0.0.1/8 scope host lo
inet 192.168.61.128/24 brd 192.168.61.255 scope global dynamic noprefixroute ens33
```

| 字段 | 含义 | 扫描目标写法 |
|------|------|-------------|
| `127.0.0.1/8` | 本机回环 | `127.0.0.1` |
| `192.168.61.128/24` | 局域网 | C 段 → `192.168.61.0/24`，单机 → `192.168.61.128` |

也可在 Web **IP 配置** 页点击「自动检测网段」，或执行：

```bash
ip route | grep default
# default via 192.168.61.2 dev ens33
```

---

## 项目结构

```
insightscan/
├── main.py                      # CLI 入口
├── run_web.py                   # Web 控制台入口
├── requirements.txt
├── README.md
├── InsightScan_完整思路书.md
├── InsightScan_项目现状.md
├── src/
│   ├── utils.py                 # 配置、日志、SQLite
│   ├── scan_engine.py           # Nmap 扫描引擎
│   ├── ai_analyzer.py           # Kimi AI 分析
│   ├── report_generator.py      # 报告生成
│   ├── security_tools.py        # 扫描检测 / 混杂模式 / iptables
│   ├── attack_mode.py           # 主动探测模式
│   ├── defense_mode.py          # 被动防御模式
│   ├── perf_benchmark.py        # 性能实验
│   ├── protocol_analyzer.py     # 协议分析
│   ├── visual_export.py         # 图表导出
│   ├── ui_config.py             # Web 界面配置
│   └── session_paths.py         # 报告会话路径
├── web/
│   ├── app.py                   # Flask API
│   ├── templates/index.html     # 三页界面
│   └── static/                  # CSS / JS
├── config/
│   ├── settings.json            # 扫描 / AI / 安全全局配置
│   ├── ui_settings.json         # Web 界面 IP / 目标配置
│   ├── api_keys.json.example    # API Key 模板
│   └── api_keys.json            # 本地密钥（gitignore，勿提交）
├── data/                        # 数据库、日志、AI 缓存（运行时生成）
├── reports/                     # attack_* / defense_* 报告（gitignore）
└── tests/                       # 单元测试
```

---

## 配置说明

### config/settings.json

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `scan.default_scan_type` | `connect` | 默认扫描方式 |
| `scan.max_threads` | `50` | 最大线程数 |
| `ai.model` | `kimi-k2.6` | Kimi 模型名 |
| `security.perf_test_cidr` | 按环境填写 | 性能实验默认 C 段 |

### config/api_keys.json

```json
{
    "kimi_api_key": "sk-你的APIKey",
    "base_url": "https://api.moonshot.cn/v1"
}
```

### config/ui_settings.json

Web 界面默认目标、端口、防御时长等，可在 **IP 配置** 页修改。

---

## 实验指引

### EXP-01~03 扫描方式对比

```bash
python3 main.py -t 127.0.0.1 --scan-type connect --ports 22,80,443
sudo python3 main.py -t 127.0.0.1 --scan-type syn --ports 22,80,443
sudo python3 main.py -t 127.0.0.1 --scan-type fin --ports 22,80,443
```

### EXP-04 多线程性能（已验证）

```bash
python3 main.py --attack -t 192.168.61.0/24 --ports 22,80,443 --perf
cat reports/attack_*/perf_benchmark.md
```

VM 实测结论：**50 线程最快**（约 28s），100 线程因 CPU 饱和略慢。

### EXP-05 协议分析

- 自动生成：`screenshots/protocol_*.png`（字段标注参考图）
- 实包分析：Wireshark 打开 `reports/attack_*/capture.pcap`
- 手动抓包：`sudo wireshark`，过滤 `tcp.port==80 or tcp.port==21`

### 安全防护实验

```bash
python3 main.py --defense --duration 60
sudo bash reports/defense_*/iptables_defense.sh
```

---

## 运行测试

```bash
python3 -m unittest discover -s tests -v
```

---

## 安全注意事项

1. **仅扫描授权目标**（本机、实验 VM、自有靶机）
2. `config/api_keys.json` **禁止提交 Git**（已在 `.gitignore`）
3. 请勿对公网或未授权主机发起扫描
4. `--apply-iptables` 会修改防火墙，请在实验环境使用

---

## 技术栈

Python 3.10 · Flask · Nmap · SQLite · Kimi API（OpenAI SDK）· matplotlib · psutil · markdown

---

## 推送到 GitHub

```bash
git add .
git status    # 确认 api_keys.json、reports/、data/*.db 未被纳入
git commit -m "Initial commit: InsightScan scan, AI analysis, and web console"
git remote add origin https://github.com/<your-username>/insightscan.git
git push -u origin master
```

推送前请再次确认 `git status` 中**没有** `config/api_keys.json`、`reports/`、`.env` 等敏感或运行时文件。
