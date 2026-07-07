# InsightScan 项目 - AI 辅助开发完整思路书

> **思路书版本**：v1.1  
> **制定日期**：2026-07-04 · **更新**：2026-07-07  
> **适用环境**：Ubuntu 22.04 + VMware 共享文件夹 `/mnt/hgfs/insightscan`

---

## 一、项目概述

**项目名称**：InsightScan - 智能网络扫描与自动化分析工具  
**目标**：基于 Nmap + AI 大模型，实现扫描执行、结果解析、智能分析、报告生成的全流程自动化；并扩展攻防联调实验与 Nmap 教学模块。  
**运行环境**：Ubuntu 22.04 虚拟机（4GB 内存，4 核），共享文件夹 `/mnt/hgfs/insightscan`  
**技术栈**：Python 3.10、Nmap 7.80、SQLite3、Kimi API、Flask、matplotlib

---

## 二、已安装环境（无需再配置）

- Python 3.10.12 + pip  
- Nmap 7.80  
- python-nmap 0.7.1  
- openai 2.x（调用 Kimi API）  
- Flask、markdown、matplotlib、psutil  
- SQLite3（Python 内置）  
- VMware 共享文件夹：`/mnt/hgfs/insightscan`  
- （可选）`sudo NOPASSWD: /usr/bin/nmap` — SYN/FIN/OS 教学扫描  

---

## 三、项目目录结构（当前实现）

```
insightscan/
├── main.py                         # CLI：扫描、AI、--attack、--defense
├── run_web.py                      # Web 入口（:8080）
├── requirements.txt
│
├── src/
│   ├── scan_engine.py              # Nmap 引擎：Connect/SYN/FIN、多线程 CIDR、入库
│   ├── ai_analyzer.py              # Kimi 分析、缓存、本地规则、历史对比
│   ├── report_generator.py         # Markdown/HTML 报告、目标过滤、统计重算
│   ├── attack_mode.py              # 主动探测 + run_attack_suite 攻击套件
│   ├── defense_mode.py             # 被动防御、监控循环、iptables 脚本
│   ├── security_tools.py           # 扫描检测、混杂模式、iptables 规则
│   ├── perf_benchmark.py           # 10/50/100 线程性能实验
│   ├── protocol_analyzer.py        # 协议图、tshark
│   ├── visual_export.py            # 风险饼图、端口柱图
│   ├── ui_config.py                # Web 配置、resolve_target、网段检测
│   ├── session_paths.py            # reports/attack_*、defense_* 会话目录
│   └── utils.py                    # 配置、日志、DB、校验
│
├── web/
│   ├── app.py                      # /api/attack /defense /drill /nmap-lab
│   ├── templates/index.html        # 四 Tab UI
│   └── static/js/main.js           # attackTargetPrefs 四页目标同步
│
├── nmap_lab/                       # Nmap 教学（独立，不入主 DB）
│   ├── common.py
│   ├── nmap_runner.py              # sudo -n nmap 路径
│   ├── zenmap_demo.py
│   └── scan_types_demo.py
│
├── scripts/setup_nmap_sudoers.sh   # SYN/FIN/OS 免密配置
├── config/
│   ├── settings.json
│   ├── ui_settings.json            # Web：local_ip、cidr、attack_target
│   └── api_keys.json               # gitignore
├── data/
│   ├── scan_results.db
│   ├── ai_cache.json
│   └── insightscan.log
├── reports/                        # attack_* / defense_* / nmap_lab/
└── tests/
```

---

## 四、模块一：扫描引擎（scan_engine.py）

### 4.1 核心功能

1. **三种扫描方式**
   - TCP Connect（-sT）：完整三次握手，普通用户可用，实验主路径  
   - TCP SYN（-sS）：半连接，需 root；Web 通过 `sudo -n nmap`  
   - TCP FIN（-sF）：隐蔽扫描，同上  

2. **多线程并发扫描**
   - ThreadPoolExecutor，CIDR 展开后逐主机并发  
   - 线程数、超时、重试可配置  

3. **结果解析与过滤**
   - 解析 Nmap XML / python-nmap 为标准 JSON  
   - **`_filter_hosts_by_target()`**：入库前丢弃与 `target` 不一致的 host，防止并发/误扫污染报告  

4. **数据持久化**
   - `scan_tasks` + `scan_results` + `scan_history`  
   - 防御侧本机自查可设 `save_db=False`，避免污染攻击报告库  

### 4.2 数据库表结构（SQLite）

**scan_tasks 表**
```sql
CREATE TABLE scan_tasks (
    task_id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scan_type TEXT,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    status TEXT DEFAULT 'running',
    total_hosts INTEGER DEFAULT 0,
    total_ports INTEGER DEFAULT 0,
    error_msg TEXT
);
```

**scan_results 表**
```sql
CREATE TABLE scan_results (
    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER,
    host_ip TEXT,
    port INTEGER,
    protocol TEXT,
    state TEXT,
    service_name TEXT,
    service_version TEXT,
    product TEXT,
    banner TEXT,
    os_guess TEXT,
    risk_level TEXT,
    risk_analysis TEXT,
    FOREIGN KEY (task_id) REFERENCES scan_tasks(task_id)
);
```

**scan_history 表** — 用于 `--compare-with` 历史对比。

### 4.3 关键设计点

- 路径统一 `pathlib.Path`  
- 失败返回 `{"error": "..."}`  
- SYN/FIN：`scripts/setup_nmap_sudoers.sh` + `_run_nmap_via_sudo()`  
- **单 IP 任务只保留 `host_ip == target` 的结果**  

---

## 五、模块二：AI 分析引擎（ai_analyzer.py）

### 5.1 核心功能

1. 单端口 / 批量 Kimi 风险评估（JSON 输出）  
2. 主机聚合分析、历史对比  
3. `data/ai_cache.json` 缓存（服务+版本键）  
4. API 失败时 `LOCAL_RISK_RULES` 降级  
5. **`_filter_rows_by_target()`**：`analyze_task(task_id)` 只分析任务目标对应主机的端口  

### 5.2 成本控制

缓存 + 批量（每批最多 5 端口）减少 API 调用；报告标注 API 调用次数与缓存命中。

---

## 六、模块三：报告生成器（report_generator.py）

### 6.1 核心功能

1. Markdown + HTML（深色主题、嵌入 PNG 图表）  
2. 风险统计、分级详细发现、修复建议  
3. **`_filter_results_by_target()`**：单 IP 精确匹配；CIDR 用 `ipaddress` 网段匹配  
4. **概览统计从过滤后的 `results` 重算**，不直接信任 `scan_tasks.total_ports` 旧值  

### 6.2 报告模板结构

见原文档 §6.2；实际输出增加「AI 分析来源」小节与攻击套件明细（§7，攻击模式）。

---

## 七、模块四：主动探测（attack_mode.py）

### 7.1 两种入口

| 函数 | 场景 |
|------|------|
| `run_attack_mode()` | 单次 Connect + AI + 报告 + 可选 perf/protocol |
| `run_attack_suite()` | Web「一键攻击」：Connect + SYN + FIN 套件 |

### 7.2 报告 task 选取（2026-07-07）

```text
_select_report_task_id(suite_runs, expected_target):
  1. 按 scan_type 排序，Connect 优先
  2. 仅选用 success 且 DB 中 scan_tasks.target == expected_target 的 task_id
  3. 不再按「开放端口最多」选取（避免误用其它主机扫描结果）
```

AI 分析与 HTML/MD 报告均基于该 `report_task_id`。

---

## 八、模块五：被动防御（defense_mode.py + security_tools.py）

1. 循环监控：syslog/journalctl + **scan_tasks 数据库联动**（Connect 扫描检测关键）  
2. 混杂模式检测  
3. 末轮本机端口自查（`127.0.0.1`，**save_db=False**）供 iptables 参考  
4. 生成 `iptables_defense.sh`、`defense_report.md`  

---

## 九、模块六：Web 控制台（web/）

### 9.1 四 Tab

| Tab | 后端路由 |
|-----|---------|
| 主动探测 | `/api/attack`、`/api/drill` |
| 被动防御 | `/api/defense` |
| IP 配置 | `/api/config` |
| Nmap 教学 | `/api/nmap-lab/*` |

### 9.2 目标 IP 解析原则（2026-07-07）

```text
页面下拉框（attackTargetPrefs）> POST body.target > ui_settings.resolve_target()
IP 配置页的 local_ip 仅填充下拉选项，不覆盖用户在本页选择的自定义 IP
四个下拉框绑定：attack-target / attack-solo / defense-target / defense-solo
```

联调时 `defense_host` 默认等于 `attack_target`（页面提交值）。

---

## 十、模块七：Nmap 教学（nmap_lab/）

- 独立于 `scan_engine`，输出到 `reports/nmap_lab/`  
- Connect 普通用户；SYN/OS 走 `sudo -n nmap -oX -`  
- 每次生成 `scan.html` + `scan.xml`  
- Web 页支持「从 IP 配置同步」目标与端口  

---

## 十一、主程序入口（main.py）

```bash
# 基础扫描
python3 main.py -t 192.168.1.1 --scan-type connect --ports 1-1000

# 主动探测完整流程
python3 main.py --attack -t 127.0.0.1 --ports 22,80,443

# 被动防御
python3 main.py --defense --duration 60

# 带 AI / 报告 / 历史对比
python3 main.py -t 目标 --ai-analyze
python3 main.py --report-format html
python3 main.py -t 目标 --compare-with 2026-07-01
```

---

## 十二、配置管理

**config/settings.json** — 扫描线程、AI 模型、报告主题、perf C 段  
**config/ui_settings.json** — Web：`local_ip`、`cidr`、`attack_target`、`target_mode`、`attack_ports`  
**config/api_keys.json** — Kimi Key（gitignore）

---

## 十三、实验验证计划

| 实验 | 内容 | 预期 |
|------|------|------|
| EXP-01~03 | Connect/SYN/FIN 对比 | SYN 快、Connect 留痕、FIN 隐蔽 |
| EXP-04 | 10/50/100 线程 C 段 | 50 线程最优（示例 VM） |
| EXP-05 | 协议分析 | 攻击模式自动生成 PNG/pcap |
| 攻防联调 | Web drill | 攻击+防御双报告，目标 IP 一致 |
| **目标一致性** | 扫 `1.2.3.4` | 报告 0 端口，无本机串台 |
| Nmap 教学 | 第四 Tab 五按钮 | scan.html 可浏览器查看 |

---

## 十四、开发顺序（已完成 + 维护）

| 阶段 | 模块 | 状态 |
|------|------|------|
| 1 | utils + 配置 + DB | ✅ |
| 2 | scan_engine | ✅ + 目标过滤 + sudo nmap |
| 3 | ai_analyzer | ✅ + 目标过滤 |
| 4 | report_generator | ✅ + 统计重算 |
| 5 | attack/defense + Web | ✅ + 目标同步修复 |
| 6 | nmap_lab + 四 Tab | ✅ |
| 7 | 文档 + 答辩材料 | ✅ 持续同步 |

---

## 十五、代码规范

1. 函数 docstring：功能、参数、返回值  
2. 路径 `pathlib.Path`；异常返回 `{"error": ...}`  
3. API Key 不入库、不硬编码  
4. 日志 `logging`，不写 print  
5. Git 提交：`[feat/fix/docs] 简要描述`  

---

## 十六、安全注意事项

1. `config/api_keys.json` 必须 gitignore  
2. 仅扫描授权目标（本机、实验靶机、VM 内网）  
3. 实验报告说明扫描范围与合规性  
4. 推荐靶机：Metasploitable、DVWA（待扩展联调）  

---

## 十七、快速启动（Ubuntu）

```bash
cd /mnt/hgfs/insightscan
bash scripts/setup_nmap_sudoers.sh    # 首次：SYN/FIN/OS
sudo -n nmap --version
python3 run_web.py                    # 普通用户，勿 sudo
# http://<VM_IP>:8080
```

---

**思路书版本**：v1.1 · **更新日期**：2026-07-07
