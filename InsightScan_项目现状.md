# InsightScan 项目现状

> 最后更新：2026-07-04（Web 攻防联调 + 攻击套件 + 文档完善）  
> 适用环境：Ubuntu 22.04 VM + VMware 共享文件夹 `/mnt/hgfs/insightscan`

| 文档 | 用途 |
|------|------|
| **[InsightScan_项目说明.md](InsightScan_项目说明.md)** | 任务书 / 答辩：结构、亮点、流程 |
| [README.md](README.md) | 安装与命令速查 |
| [InsightScan_完整思路书.md](InsightScan_完整思路书.md) | 原始设计 |
| [环境准备.md](环境准备.md) | 环境搭建 |

---

## 一、当前环境（示例，以你 VM 为准）

| 项目 | 值 |
|------|-----|
| 本机 IP | `192.168.61.128`（请在 IP 配置页检测） |
| 网段 | `192.168.61.0/24` |
| 网卡 | `ens33` |
| AI 模型 | `kimi-k2.6` |
| API | `https://api.moonshot.cn/v1` |

```bash
ip addr | grep "inet "
```

---

## 二、已完成功能

| 模块 | 文件 | 状态 |
|------|------|------|
| 配置 / 数据库 | `src/utils.py` | ✅ |
| Nmap 扫描引擎 | `src/scan_engine.py` | ✅ Connect/SYN/FIN |
| AI 分析 | `src/ai_analyzer.py` | ✅ Kimi + 缓存 + 降级 + 报告来源标注 |
| 报告生成 | `src/report_generator.py` | ✅ MD/HTML + AI 来源节 |
| CLI 入口 | `main.py` | ✅ |
| 主动探测 | `src/attack_mode.py` | ✅ 单扫描 + **攻击套件 run_attack_suite** |
| 被动防御 | `src/defense_mode.py` | ✅ syslog + **DB 联动** |
| 安全工具 | `src/security_tools.py` | ✅ 扫描检测 / 混杂 / iptables |
| 性能实验 | `src/perf_benchmark.py` | ✅ 10/50/100 线程 |
| 协议分析 | `src/protocol_analyzer.py` | ✅ |
| Web 控制台 | `web/` + `run_web.py` | ✅ 三页 + 一键联调 |
| Web 配置 | `src/ui_config.py` | ✅ 动态 IP + 自动检测 |
| 单元测试 | `tests/` | ✅ |
| 项目文档 | `InsightScan_项目说明.md` 等 | ✅ |

---

## 三、验收结果摘要

### 3.1 主动探测

- 本机 `127.0.0.1`：SSH 22，AI 低危，HTML 报告正常  
- **一键攻击套件**：Connect + SYN + FIN，报告含「攻击套件明细」  
- SYN/FIN 无 sudo 时会失败，Connect 仍成功（预期）

### 3.2 性能实验（C 段 192.168.61.0/24）

| 线程 | 耗时 | 结论 |
|------|------|------|
| 10 | 60.41s | |
| 50 | **27.69s** | **最优** |
| 100 | 32.24s | CPU 饱和略慢 |

### 3.3 被动防御

- syslog 对 Connect 扫描常为 0（预期）  
- **数据库联动**可检测到联调期间的 InsightScan 扫描  
- 混杂模式、iptables 脚本生成正常  

### 3.4 Web 控制台

- 三 Tab：主动探测 / 被动防御 / IP 配置  
- **一键攻防联调**：单页完成，随机 1~3 种攻击  
- IP 配置保存后，切换 Tab 目标下拉同步  

---

## 四、报告目录规范

```
reports/
├── attack_YYYYMMDD_HHMMSS/
│   ├── attack_report.md / .html
│   ├── summary.json              # 含 attack_suite、ai_analysis
│   ├── perf_benchmark.md         # --perf 时
│   └── screenshots/
└── defense_YYYYMMDD_HHMMSS/
    ├── defense_report.md         # 区分「监控秒数」与「日志回溯分钟」
    ├── scan_events.json
    ├── iptables_defense.sh
    └── screenshots/
```

---

## 五、核心命令速查

```bash
cd /mnt/hgfs/insightscan

# Web（推荐）
python3 run_web.py

# CLI 攻击
python3 main.py --attack -t 127.0.0.1 --ports 22,80,443

# CLI 防御
python3 main.py --defense --duration 60

# 性能
python3 main.py --attack -t 192.168.61.0/24 --ports 22,80,443 --perf
```

---

## 六、已知问题与限制

| # | 问题 | 说明 / 应对 |
|---|------|------------|
| 1 | ~~报告时间 UTC~~ | **已修复**：新任务用本地时间；旧记录读取时自动转换 |
| 2 | Connect 扫描 syslog 无特征 | 防御已加 **DB 联动**；可选 `sudo ufw logging on` |
| 3 | SYN/FIN 需 root | Web 下 Connect 仍可用；完整三类型需 `sudo python3 run_web.py` |
| 4 | 协议图为参考标注 | 实包用 Wireshark 打开 `capture.pcap` |
| 5 | AI 缓存命中不调 API | 报告已标注；清空 `data/ai_cache.json` 可强制调 API |
| 6 | tshark 可能 0 条 | 无 HTTP/FTP 流量时正常 |

---

## 七、待办（可选扩展）

- [x] Web 三页界面 + 一键攻防联调  
- [x] 攻击套件（全套 / 随机）  
- [x] 防御数据库联动  
- [x] 任务书项目说明文档  
- [ ] SYN/FIN 对比实验报告截图（需 sudo）  
- [ ] Metasploitable / DVWA 靶机联调  
- [ ] Wireshark 手动抓包截图进报告  

---

## 八、新会话快速开始

```bash
cd /mnt/hgfs/insightscan

ip addr | grep "inet "                    # 1. 确认网段
cat config/api_keys.json                  # 2. 确认 API Key
python3 -m unittest discover -s tests -v  # 3. 自检
python3 run_web.py                        # 4. 启动 Web
# 浏览器 → IP 配置 → 检测并应用 → 保存 → 一键攻防联调
```

---

## 九、AI / API Key 说明

| 项目 | 位置 |
|------|------|
| 密钥文件 | `config/api_keys.json` |
| 读取 | `src/utils.py` → `load_api_key()` |
| 调用 | `src/ai_analyzer.py` → OpenAI SDK → `api.moonshot.cn` |
| 缓存 | `data/ai_cache.json` |
| 报告 | `attack_report.md` 中「AI 分析来源」：API 次数 / 缓存 / 本地规则 |

---

## 十、相关文档

| 文档 | 何时读 |
|------|--------|
| **InsightScan_项目说明.md** | 写任务书、答辩、理清整体 |
| README.md | 日常安装与命令 |
| InsightScan_完整思路书.md | 模块级设计细节 |
| 环境准备.md | 首次搭 VM 与共享文件夹 |
