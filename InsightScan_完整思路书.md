# InsightScan 项目 - AI 辅助开发完整思路书

## 一、项目概述

**项目名称**：InsightScan - 智能网络扫描与自动化分析工具
**目标**：基于 Nmap + AI 大模型，实现扫描执行、结果解析、智能分析、报告生成的全流程自动化
**运行环境**：Ubuntu 22.04 虚拟机（4GB内存，4核），共享文件夹 /mnt/hgfs/insightscan
**技术栈**：Python 3.10、Nmap 7.80、SQLite3、Kimi API

---

## 二、已安装环境（无需再配置）

- Python 3.10.12 + pip
- Nmap 7.80
- python-nmap 0.7.1
- openai 2.44.0（调用 Kimi API）
- requests 2.25.1
- Git 2.34.1
- SQLite3（Python 内置，无需安装）
- VMware 共享文件夹：/mnt/hgfs/insightscan

---

## 三、项目目录结构

```
insightscan/
├── src/
│   ├── __init__.py
│   ├── scan_engine.py          # 扫描引擎：Nmap 调用 + 多线程 + 结果解析
│   ├── ai_analyzer.py          # AI 分析：Kimi API 调用 + 风险评估 + 历史对比
│   ├── report_generator.py     # 报告生成：Markdown/HTML 模板 + 数据可视化
│   └── utils.py                # 工具函数：配置读取、日志、数据库连接
├── config/
│   ├── api_keys.json           # API Key（加入 .gitignore，不提交）
│   └── settings.json           # 扫描参数、线程数、超时等配置
├── data/
│   └── scan_results.db         # SQLite 数据库（扫描结果、历史记录）
├── reports/                    # 生成的报告输出目录
├── tests/
│   └── test_scan.py            # 单元测试
├── venv/                       # Python 虚拟环境（不提交）
├── requirements.txt            # 依赖列表
└── README.md                   # 项目说明
```

---

## 四、模块一：扫描引擎（scan_engine.py）

### 4.1 核心功能

1. **三种扫描方式**
   - TCP Connect（-sT）：完整三次握手，最准确，会在目标留下日志
   - TCP SYN（-sS）：半连接扫描，不完成握手，快速隐蔽，需要 root 权限
   - TCP FIN（-sF）：发送 FIN 包，利用 RFC 793 特性，可绕过部分防火墙

2. **多线程并发扫描**
   - 使用 ThreadPoolExecutor
   - 线程数可配置（默认 50，范围 10-200）
   - 单个目标超时控制（默认 300 秒）
   - 进度显示（已完成/总数/百分比）

3. **结果解析**
   - 解析 Nmap XML 输出为标准化 JSON
   - 提取字段：IP、端口、协议、状态、服务名、版本、产品、Banner、OS 指纹
   - OS 识别取置信度最高的前 3 个结果

4. **数据持久化**
   - 扫描任务表：记录目标、扫描类型、时间、状态、统计
   - 扫描结果表：记录每个主机的每个端口详情
   - 自动入库，支持批量写入优化

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

**scan_history 表**
```sql
CREATE TABLE scan_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip TEXT,
    port INTEGER,
    protocol TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    change_type TEXT,
    previous_state TEXT,
    current_state TEXT,
    previous_service TEXT,
    current_service TEXT
);
```

### 4.3 关键设计点

- 路径统一用 `pathlib.Path`，兼容 Windows 和 Ubuntu
- 日志用 `logging` 模块，分级输出（INFO/ERROR/DEBUG）
- 每个扫描函数必须有 try-except，失败返回 `{"error": "具体原因"}`
- 数据库连接用完立即关闭，不要长期持有连接
- Nmap 扫描参数可配置，通过 settings.json 读取

---

## 五、模块二：AI 分析引擎（ai_analyzer.py）

### 5.1 核心功能

1. **单端口风险分析**
   - 输入：IP、端口、服务名、版本、Banner
   - 调用 Kimi API（OpenAI 兼容接口）
   - 要求 AI 返回严格 JSON 格式
   - 输出：风险等级、风险分数、威胁类型、描述、影响、修复建议、参考 CVE

2. **主机整体分析**
   - 聚合该主机所有开放端口的分析结果
   - 整体风险等级 = 所有端口中的最高等级
   - 生成自然语言摘要（100 字以内，给非技术人员看）

3. **历史对比分析**
   - 读取同一目标的两次扫描结果
   - 检测：新增端口、消失端口、服务变化、版本变化
   - 用 AI 生成变化分析报告（Markdown 格式）
   - 发现高危新增时标记告警

4. **结果缓存**
   - 缓存文件：data/ai_cache.json
   - 缓存键：服务名 + 版本号（如 "ssh_OpenSSH_8.9"）
   - 命中缓存时直接返回，不调用 API
   - 预计减少 70-80% 的重复 API 调用

### 5.2 AI Prompt 设计

**单端口分析 Prompt**
```
你是一位资深网络安全专家，请对以下端口扫描结果进行风险评估。

扫描结果：
- 目标IP: {host_ip}
- 开放端口: {port}
- 服务类型: {service}
- 版本信息: {version}
- Banner信息: {banner}

请严格按照以下JSON格式输出（不要输出其他内容）：
{
    "risk_level": "高危/中危/低危/信息",
    "risk_score": 0-100的整数,
    "threat_type": "威胁类型",
    "description": "详细风险描述",
    "impact": "影响范围",
    "recommendation": "修复建议",
    "references": ["CVE编号或参考链接"]
}

评估标准：
- 高危：存在已知远程利用漏洞，无需认证即可攻击
- 中危：需要一定条件才能利用，或泄露敏感信息
- 低危：信息泄露或配置不当，难以直接利用
- 信息：仅识别服务，无明显风险
```

**历史对比 Prompt**
```
对比以下两次扫描结果，识别安全态势变化：

[历史扫描结果]
[最新扫描结果]

请分析：
1. 新增开放了哪些端口？风险如何？
2. 关闭了哪些端口？
3. 服务版本是否有变化？
4. 整体安全态势是改善还是恶化？
5. 给出安全建议。

以 Markdown 格式输出分析报告。
```

### 5.3 API 调用优化

- temperature=0.3（低温度，保证输出稳定）
- max_tokens=1000（单端口分析）/ 1500（历史对比）
- 批量分析：一次请求最多分析 5 个端口
- 异步调用：使用 asyncio + aiohttp（可选优化）
- 降级方案：API 不可用时，返回本地规则库结果（常见端口的基础风险等级）

### 5.4 成本估算

| 功能 | Token 数 | 单次成本 | 100 次成本 |
|------|---------|---------|-----------|
| 单端口分析 | ~500 | ~￥0.003 | ~￥0.3 |
| 批量分析（5端口） | ~1500 | ~￥0.009 | ~￥0.9 |
| 主机整体分析 | ~2000 | ~￥0.012 | ~￥1.2 |
| 历史对比 | ~4000 | ~￥0.024 | ~￥2.4 |

**成本控制**：缓存策略预计减少 70-80% 调用，实际成本更低。

---

## 六、模块三：报告生成器（report_generator.py）

### 6.1 核心功能

1. **Markdown 报告**
   - 模板变量替换：{timestamp} {targets} {scan_type} {total_hosts} 等
   - 风险统计表格（按等级分组计数）
   - 详细发现列表（高危 → 中危 → 低危 → 信息）
   - 修复建议按优先级排序
   - 技术附录（扫描参数、完整端口列表）

2. **HTML 报告**
   - 基于 Markdown 转换（用 markdown 库）
   - 内嵌 CSS 样式：深色主题（#1a1a2e 背景）+ 浅色主题可选
   - 风险等级颜色标识：高危红、中危橙、低危黄、信息绿
   - 响应式布局，支持手机查看

3. **数据可视化（纯 CSS/HTML 实现）**
   - 风险分布饼图：用 CSS conic-gradient 或简单 div 比例条
   - 端口开放统计：表格 + 进度条
   - 历史趋势：折线图（用 ASCII 字符或简单 HTML）

### 6.2 报告模板结构

```markdown
# 网络安全扫描报告

## 1. 扫描概览
- 扫描时间: {timestamp}
- 扫描目标: {targets}
- 扫描类型: {scan_type}
- 总主机数: {total_hosts}
- 总开放端口: {total_open_ports}
- 扫描耗时: {duration}秒

## 2. 风险统计
| 风险等级 | 数量 | 占比 | 颜色标识 |
|---------|------|------|---------|
| 高危 | {high_count} | {high_pct}% | 🔴 |
| 中危 | {medium_count} | {medium_pct}% | 🟠 |
| 低危 | {low_count} | {low_pct}% | 🟡 |
| 信息 | {info_count} | {info_pct}% | 🟢 |

## 3. 详细发现

### 3.1 高危风险
[高危端口列表，含 AI 分析结果]

### 3.2 中危风险
[中危端口列表]

### 3.3 低危风险
[低危端口列表]

### 3.4 信息
[信息级端口列表]

## 4. 修复建议优先级
1. [最高优先级建议]
2. [次优先级建议]
3. [其他建议]

## 5. 技术细节
- 扫描参数: {nmap_args}
- 线程数: {thread_count}
- 超时设置: {timeout}秒

## 6. 附录
- 完整端口列表
- 原始扫描数据路径
```

---

## 七、模块四：主程序入口（main.py）

### 7.1 CLI 参数设计

```bash
# 基础扫描
python main.py -t 192.168.1.1 --scan-type syn --ports 1-1000

# 带 AI 分析
python main.py -t 192.168.1.0/24 --ai-analyze

# 生成报告
python main.py --report-format html --output reports/scan_report.html

# 历史对比
python main.py -t 192.168.1.1 --compare-with 2026-07-01

# 查看历史扫描
python main.py --list-history

# 帮助
python main.py --help
```

### 7.2 配置管理

**config/settings.json**
```json
{
    "scan": {
        "default_ports": "1-1000",
        "default_scan_type": "syn",
        "max_threads": 50,
        "timeout": 300,
        "retry_count": 2
    },
    "ai": {
        "model": "kimi-latest",
        "temperature": 0.3,
        "max_tokens": 1000,
        "batch_size": 5,
        "enable_cache": true
    },
    "report": {
        "default_format": "markdown",
        "output_dir": "reports",
        "theme": "dark"
    }
}
```

**config/api_keys.json（加入 .gitignore）**
```json
{
    "kimi_api_key": "sk-你的APIKey",
    "base_url": "https://api.moonshot.cn/v1"
}
```

---

## 八、工具函数（utils.py）

### 8.1 功能清单

1. **配置读取**
   - `load_settings()`：读取 settings.json
   - `load_api_key()`：读取 api_keys.json
   - 支持环境变量覆盖（INSIGHTSCAN_API_KEY）

2. **日志配置**
   - 统一日志格式：`%(asctime)s - %(levelname)s - %(message)s`
   - 日志文件：data/insightscan.log
   - 控制台 + 文件双输出

3. **数据库连接**
   - `get_db_connection()`：返回 sqlite3 连接
   - 自动处理路径（BASE_DIR / data / scan_results.db）

4. **路径处理**
   - `BASE_DIR = Path(__file__).resolve().parent.parent`
   - 所有路径基于此计算，跨平台兼容

5. **验证函数**
   - `validate_ip(ip)`：验证 IP 格式
   - `validate_ports(ports)`：验证端口范围格式（如 "1-1000" 或 "80,443"）

---

## 九、实验验证计划

### 9.1 实验一：扫描方式对比

| 实验编号 | 扫描类型 | 目标 | 验证指标 |
|---------|---------|------|---------|
| EXP-01 | TCP Connect | 本地靶机 | 成功率、耗时、日志痕迹 |
| EXP-02 | TCP SYN | 本地靶机 | 成功率、耗时、隐蔽性 |
| EXP-03 | TCP FIN | 本地靶机 | 绕过率、误报率 |
| EXP-04 | 多线程对比 | C段网段 | 10/50/100线程耗时对比 |

**预期结论**：SYN 最快最隐蔽，Connect 最准确但留痕，FIN 可绕过部分防火墙。

### 9.2 实验二：AI 分析准确性

- 准备 50 个已知端口样本（含已知 CVE 的）
- AI 分析 vs 人工标注，计算：
  - 风险等级准确率
  - 威胁类型识别率
  - 修复建议可用性
- 对比缓存命中前后的 API 调用次数

**预期结论**：AI 分析准确率 > 80%，缓存减少 70%+ 调用。

### 9.3 实验三：安全防护验证

1. 扫描发现靶机开放端口
2. 基于扫描结果设计 iptables 规则（关闭高危端口）
3. 部署规则后再次扫描验证
4. 测试 Snort IDS 对扫描行为的检测告警

---

## 十、开发顺序建议

| 顺序 | 模块 | 预计时间 | 验收标准 |
|------|------|---------|---------|
| 1 | utils.py + 配置 | 2小时 | 能读取配置、连接数据库 |
| 2 | scan_engine.py | 1天 | 能扫描本地、解析结果、存入数据库 |
| 3 | ai_analyzer.py | 1天 | 能调 API、返回结构化结果、缓存生效 |
| 4 | report_generator.py | 半天 | 能生成 Markdown 报告 |
| 5 | main.py CLI | 半天 | 命令行参数解析、模块整合 |
| 6 | 测试 + 优化 | 1天 | 三种扫描方式对比、AI 准确性测试 |
| 7 | 文档 + 报告 | 1天 | README、实验报告、PPT |

---

## 十一、代码规范

1. 函数必须有 docstring，说明功能、参数、返回值
2. 变量名用英文，注释用中文
3. 路径统一用 `pathlib.Path`，禁止硬编码 Windows 路径
4. 异常必须捕获，返回包含 `error` 字段的字典
5. 数据库连接用完立即 `close()`
6. API Key 从配置文件读取，禁止硬编码在代码中
7. 日志用 `logging`，禁止用 `print` 输出调试信息
8. Git 提交信息格式：`[类型] 简要描述`，如 `[feat] 添加 SYN 扫描支持`

---

## 十二、安全注意事项

1. **config/api_keys.json 必须加入 .gitignore**
2. 扫描仅限授权目标（本地虚拟机、实验靶机）
3. 不要在公网随意扫描他人服务器（违法）
4. 实验报告里明确说明扫描范围和法律合规性
5. 靶机建议使用 Metasploitable、DVWA 等专门用于测试的环境

---

## 十三、快速启动命令（Ubuntu 终端）

```bash
# 1. 进入项目目录
cd /mnt/hgfs/insightscan

# 2. 激活虚拟环境
source venv/bin/activate

# 3. 运行扫描测试
python3 src/scan_engine.py

# 4. 运行 AI 分析测试
python3 src/ai_analyzer.py

# 5. 生成报告
python3 src/report_generator.py

# 6. 主程序入口
python3 main.py -t 127.0.0.1 --scan-type connect --ports 22,80
```

---

**思路书版本**：v1.0
**制定日期**：2026-07-04
**适用环境**：Ubuntu 22.04 + VMware 共享文件夹
