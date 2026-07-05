# InsightScan

智能网络扫描与自动化分析工具 —— 基于 **Nmap + Kimi AI**，覆盖扫描执行、结果解析、智能风险分析、报告生成与攻防实验的全流程。

| 文档 | 说明 |
|------|------|
| **[InsightScan_项目说明.md](InsightScan_项目说明.md)** | **任务书 / 答辩用**：结构、亮点、流程、文件职责 |
| [InsightScan_项目现状.md](InsightScan_项目现状.md) | 当前进度、验收数据、已知问题 |
| [InsightScan_完整思路书.md](InsightScan_完整思路书.md) | 原始设计与模块说明 |
| [环境准备.md](环境准备.md) | Ubuntu + VMware 共享文件夹环境搭建 |

---

## 目录

- [功能特性](#功能特性)
- [环境要求](#环境要求)
- [安装与配置](#安装与配置)
- [快速开始](#快速开始)
- [Web 控制台](#web-控制台推荐)
- [Nmap 教学与 SYN/OS 权限配置](#nmap-教学与-synos-权限配置)
- [CLI 命令](#cli-命令)
- [攻防联调](#攻防联调)
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
| 攻击套件 | 一键攻击 = 三种扫描依次执行；联调 = 随机 1~3 种 |
| 并发扫描 | 可配置线程数，支持 CIDR 网段 |
| AI 分析 | Kimi API（kimi-k2.6）+ 缓存 + 本地规则降级（报告标明来源） |
| 主动探测 | 扫描 → AI 分析 → Markdown/HTML 报告 + 图表截图 |
| 被动防御 | syslog + **数据库联动**检测、混杂模式、iptables 自动生成 |
| 性能实验 | 10/50/100 线程对比 + CPU/内存曲线 |
| 协议分析 | TCP/HTTP/FTP 字段标注图 + tshark 抓包（可选） |
| Web 控制台 | 四页：攻击 / 防御 / IP 配置 / **Nmap扫描与对比教学** |
| **Nmap 教学** | Zenmap 双栏演示、Connect/SYN/OS/全端口对比、HTML+XML 报告 |

> 整体架构、亮点、答辩说明见 **[InsightScan_项目说明.md](InsightScan_项目说明.md)** · 验收进度见 **[InsightScan_项目现状.md](InsightScan_项目现状.md)**

## 环境要求

| 依赖 | 版本 / 说明 |
|------|-------------|
| 操作系统 | Linux 推荐（Ubuntu 22.04）；开发可用 VMware 共享文件夹 |
| Python | 3.10+ |
| Nmap | 7.80+（`sudo apt install nmap`） |
| Kimi API | [platform.moonshot.cn](https://platform.moonshot.cn/) |
| 可选 | `tshark`（`sudo apt install tshark wireshark-common`） |

---

## 安装与配置

```bash
git clone https://github.com/<your-username>/insightscan.git
cd insightscan

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

cp config/api_keys.json.example config/api_keys.json
# 编辑 config/api_keys.json 填入 kimi_api_key

python3 src/utils.py
```

> `config/api_keys.json` 已在 `.gitignore`，请勿提交 GitHub。

---

## 快速开始

### Web 控制台（推荐）

```bash
cd /mnt/hgfs/insightscan   # VMware 共享目录示例

# ① 首次使用 Nmap 教学页前，配置 SYN/OS 权限（见下文专节，只需一次）
# ② 普通用户启动（不要用 sudo python3）
python3 run_web.py
# 浏览器 → http://127.0.0.1:8080 或 http://<VM_IP>:8080
```

### CLI

```bash
python3 main.py --attack -t 127.0.0.1 --ports 22,80,443
python3 main.py --defense --duration 60

# Nmap 教学演示（独立运行，不入主 CLI）
python3 nmap_lab/zenmap_demo.py
python3 nmap_lab/scan_types_demo.py
```

报告目录：`reports/attack_YYYYMMDD_HHMMSS/` · `reports/defense_YYYYMMDD_HHMMSS/`

---

报告目录：

- 攻防：`reports/attack_YYYYMMDD_HHMMSS/` · `reports/defense_YYYYMMDD_HHMMSS/`
- Nmap 教学：`reports/nmap_lab/{zenmap|connect|syn|os|full_port}_YYYYMMDD_HHMMSS/`

---

## Web 控制台（推荐）

| Tab | 功能 |
|-----|------|
| **主动探测** | 一键攻防联调 · 一键攻击（Connect+SYN+FIN 全套）· 一键性能测试 |
| **被动防御** | 一键攻防联调（随机攻击）· 一键防御（可接续攻击） |
| **IP 配置** | 自动检测网段 · 保存后攻击/防御页目标同步 |
| **Nmap扫描与对比教学** | Zenmap 演示 · Connect/SYN/OS/全端口（各按钮独立）· InsightScan AI 对比 |

**使用顺序**：IP 配置 → 检测并应用 → 保存 → 各 Tab 选择目标 → 一键操作

配置持久化：`config/ui_settings.json`

| 环境变量 | 说明 |
|---------|------|
| `INSIGHTSCAN_WEB_PORT` | 端口，默认 8080 |
| `INSIGHTSCAN_NO_BROWSER=1` | 不自动打开浏览器 |

---

## Nmap 教学与 SYN/OS 权限配置

> **答辩必做（只需配置一次）**。Nmap 教学页中 **Connect / Zenmap / 全端口** 无需 root；**SYN (-sS)** 与 **OS 识别 (-O)** 需要 root。  
> Web 用**普通用户**跑 Flask，因此给 **nmap 命令** 配置 sudo 免密，而不是 `sudo python3 run_web.py`。

### 为什么不能用 `sudo python3 run_web.py`？

| 启动方式 | 结果 |
|---------|------|
| `python3 run_web.py` | ✅ 能找到 `pip install` 的 flask、python-nmap 等 |
| `sudo python3 run_web.py` | ❌ 用的是 root 的 Python，**找不到**用户目录里装的包 |

正确做法：**Web 普通用户启动**，SYN/OS 扫描时程序自动执行 `sudo -n nmap ...`。

### 如何获取你的 Linux 用户名

在 VM 终端执行任一命令即可：

```bash
whoami          # 推荐，直接输出用户名，例如：liyuxi、ubuntu、student01
echo $USER      # 同上
```

也可看终端提示符：`用户名@主机名:~$`，`@` 前面即为用户名。

### sudoers 一行填什么

写入 `/etc/sudoers.d/insightscan-nmap` 的内容格式为：

```
你的用户名 ALL=(ALL) NOPASSWD: /usr/bin/nmap
└────┬────┘                              └──┬──┘
 填 whoami 的结果                      nmap 路径（通常固定）
```

确认 nmap 路径（若与 `/usr/bin/nmap` 不同则改用下面命令输出的路径）：

```bash
which nmap      # 一般输出 /usr/bin/nmap
```

### 配置步骤（Ubuntu VM）

**方式一：推荐（自动填入当前用户名，无需手改）**

```bash
# 1. 写入 sudoers（只需输入一次 sudo 密码）
echo "$(whoami) ALL=(ALL) NOPASSWD: $(which nmap)" | sudo tee /etc/sudoers.d/insightscan-nmap
sudo chmod 440 /etc/sudoers.d/insightscan-nmap

# 2. 验证：应直接输出版本，不再索要密码
sudo -n nmap --version

# 3. 普通用户启动 Web
cd /mnt/hgfs/insightscan   # 或你的项目目录
python3 run_web.py
```

**方式二：手动填写（需把 `你的用户名` 换成 whoami 的结果）**

```bash
# 示例：若 whoami 输出 student01，则第一行写 student01
echo '你的用户名 ALL=(ALL) NOPASSWD: /usr/bin/nmap' | sudo tee /etc/sudoers.d/insightscan-nmap
sudo chmod 440 /etc/sudoers.d/insightscan-nmap
sudo -n nmap --version
python3 run_web.py
```

**方式三：脚本（自动读取当前用户，与方式一等效）**

```bash
bash scripts/setup_nmap_sudoers.sh
python3 run_web.py
```

### 验证是否成功

1. 打开 Web → **Nmap扫描与对比教学**
2. 页顶应显示：**「SYN/OS 扫描已就绪（sudo 免密 nmap）」**
3. 目标 `127.0.0.1`，端口默认 `21,23,80,3306`
4. 依次点击 **SYN (-sS)**、**OS 识别 (-O)**，应显示扫描结果而非权限错误

### Nmap 教学页说明

| 按钮 | 说明 | 默认端口/范围 |
|------|------|--------------|
| Zenmap 演示 | 双栏主机/端口界面，模拟 Zenmap | `21,23,80,3306` |
| Connect (-sT) | TCP 三次握手，无需 root | 同上 |
| SYN (-sS) | 半开扫描，需上述 sudo 配置 | 同上 |
| OS 识别 (-O) | 操作系统指纹，需上述 sudo 配置 | 全机 |
| 全端口 | Web 固定 `1-1000`（实验书为 1-65535） | 1-1000 |

**报告输出**（每次扫描一个目录）：

```
reports/nmap_lab/zenmap_20260705_113249/
├── scan.html    ← 浏览器查看（Web 链接指向此文件）
└── scan.xml     ← 下载存档 / Zenmap「扫描→打开」导入
```

浏览器地址示例：

`http://127.0.0.1:8080/reports/nmap_lab/zenmap_20260705_113249/scan.html`

**InsightScan 对比**：页内静态对比表 + 可选「InsightScan 增强分析」（同目标 Connect 扫描 + Kimi AI HTML 报告）。

**独立 CLI（不入主程序）**：

```bash
python3 nmap_lab/zenmap_demo.py       # 默认端口 21,23,80,3306
python3 nmap_lab/scan_types_demo.py   # 默认目标 127.0.0.1
```

---

## CLI 命令

### 主动探测

```bash
python3 main.py --attack -t 127.0.0.1 --ports 22,80,443
python3 main.py --attack -t 192.168.61.0/24 --ports 22,80,443 --perf
sudo python3 main.py --attack -t 127.0.0.1 --scan-type syn --ports 22,80
```

### 被动防御

```bash
python3 main.py --defense --duration 60
sudo python3 main.py --defense --apply-iptables
```

### 其他

```bash
python3 main.py -t 127.0.0.1 --ports 22,80,443 --ai-analyze
python3 main.py --list-history
python3 main.py --report-format html --report-task 12
```

---

## 攻防联调

攻击与防御需**时间重叠**。Web 已支持**单页自动联调**，无需两个终端。

1. **IP 配置**页 → 检测并应用 → 保存  
2. **一键攻防联调**：后端先开防御 60s → 2s 后发起**随机 1~3 种**扫描  
3. **一键攻击（全套）**：Connect + SYN + FIN 依次执行  

CLI 双终端方式仍可用，见 [InsightScan_项目现状.md](InsightScan_项目现状.md)。

若 syslog 无事件，防御仍可通过 **scan_tasks 数据库联动** 检测 Connect 扫描。

---

## 查看本机网段

```bash
ip addr | grep "inet "
```

| 示例 | 扫描写法 |
|------|---------|
| `192.168.61.128/24` | 单机 `192.168.61.128`，C 段 `192.168.61.0/24` |

Web **IP 配置** 页可一键「检测并应用」。

---

## 项目结构

```
insightscan/
├── main.py / run_web.py          # CLI / Web 入口
├── src/                          # 核心业务（扫描、AI、攻防、报告）
├── web/                          # Flask + 四页前端
├── nmap_lab/                     # Nmap 教学（独立模块，不入 scan_engine DB）
│   ├── common.py                 # 路径、XML/HTML 保存、权限检测
│   ├── nmap_runner.py            # 普通扫描 + sudo nmap 执行
│   ├── zenmap_demo.py            # Zenmap 风格 CLI
│   └── scan_types_demo.py        # Connect/SYN/OS/全端口对比
├── scripts/
│   └── setup_nmap_sudoers.sh     # 一键配置 sudo 免密 nmap
├── config/                       # settings / ui_settings / api_keys
├── data/                         # SQLite、AI 缓存、日志
├── reports/                      # 实验报告输出（含 nmap_lab/）
├── tests/                        # 单元测试
└── InsightScan_项目说明.md        # 任务书：逐文件说明 + 流程 + 亮点
```

完整逐文件说明 → **[InsightScan_项目说明.md](InsightScan_项目说明.md)**

---

## 配置说明

### config/settings.json

| 配置项 | 说明 |
|--------|------|
| `scan.max_threads` | 最大线程数（默认 50） |
| `ai.model` | Kimi 模型（kimi-k2.6） |
| `security.perf_test_cidr` | 性能实验 C 段 |

### config/api_keys.json

```json
{
    "kimi_api_key": "sk-你的APIKey",
    "base_url": "https://api.moonshot.cn/v1"
}
```

### config/ui_settings.json

Web 界面 IP、默认目标、端口；在 **IP 配置** 页修改并保存。

---

## 实验指引

| 实验 | 命令 |
|------|------|
| EXP-01~03 扫描对比 | `--scan-type connect/syn/fin` 或 `python3 nmap_lab/scan_types_demo.py` |
| Zenmap 教学演示 | `python3 nmap_lab/zenmap_demo.py` |
| Nmap Web 教学 | Web「Nmap扫描与对比教学」Tab（需配置 sudo 免密 nmap） |
| Nmap 报告 | `reports/nmap_lab/*/scan.html` + `scan.xml` |
| EXP-04 性能 | `--attack -t C段 --perf` |
| EXP-05 协议 | 攻击报告 `screenshots/protocol_*.png` |
| 攻防联调 | Web「一键攻防联调」 |
| iptables | `reports/defense_*/iptables_defense.sh` |

---

## 运行测试

```bash
python3 -m unittest discover -s tests -v
```

---

## 安全注意事项

1. **仅扫描授权目标**（本机 VM、实验靶机）  
2. `config/api_keys.json` 禁止提交 Git  
3. `--apply-iptables` 仅在实验环境使用  

---

## 技术栈

Python 3.10 · Flask · Nmap · SQLite · Kimi API · matplotlib · psutil · markdown
