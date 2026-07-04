# InsightScan 项目现状

> 最后更新：2026-07-04  
> 适用环境：Ubuntu 22.04 VM + VMware 共享文件夹 `/mnt/hgfs/insightscan`  
> 详细设计见：[InsightScan_完整思路书.md](InsightScan_完整思路书.md)

---

## 一、当前环境（已确认）

| 项目 | 值 |
|------|-----|
| 本机 IP | `192.168.61.128` |
| 网段 | `192.168.61.0/24` |
| 网卡 | `ens33` |
| C 段扫描目标 | `192.168.61.0/24`（**不是** 192.168.1.0/24） |
| AI 模型 | `kimi-k2.6`（config/settings.json） |
| API | `https://api.moonshot.cn/v1` |

查看网段命令：

```bash
ip addr | grep "inet "
# 找 ens33 等非 lo 行，例如：
# inet 192.168.61.128/24 → C 段写 192.168.61.0/24
```

---

## 二、已完成功能

| 模块 | 文件 | 状态 |
|------|------|------|
| 配置 / 数据库 | `src/utils.py` | ✅ 已验收 |
| Nmap 扫描引擎 | `src/scan_engine.py` | ✅ Connect/SYN/FIN 接口齐全 |
| AI 分析 | `src/ai_analyzer.py` | ✅ Kimi + 缓存 + 本地降级 |
| 报告生成 | `src/report_generator.py` | ✅ Markdown + HTML（嵌入 PNG） |
| CLI 入口 | `main.py` | ✅ |
| 主动探测 | `src/attack_mode.py` | ✅ 已验收 |
| 被动防御 | `src/defense_mode.py` | ✅ 已验收 |
| 安全工具 | `src/security_tools.py` | ✅ 扫描检测 / 混杂模式 / iptables |
| 性能实验 | `src/perf_benchmark.py` | ✅ 10/50/100 线程对比 |
| 协议分析 | `src/protocol_analyzer.py` | ✅ 字段标注图 + tshark（可选） |
| 单元测试 | `tests/` | ✅ |

---

## 三、2026-07-04 验收结果摘要

### 3.1 主动探测 `attack_20260704_113505`

**命令**：`python3 main.py --attack -t 127.0.0.1 --ports 22,80,443`

| 指标 | 结果 |
|------|------|
| 开放端口 | SSH 22 |
| AI 风险 | 低危（OpenSSH 8.9，本地规则库/缓存） |
| HTML 报告 | ✅ 正常，嵌入 screenshots PNG |
| 问题 | 极快扫描时耗时曾显示「0秒」（已修复为显示小数） |

### 3.2 性能实验 `attack_20260704_113540`

**命令**：`python3 main.py --attack -t 192.168.61.0/24 --ports 22,80,443 --perf`

| 线程数 | 耗时 | 扫描主机 | CPU 峰值 | 内存峰值 |
|--------|------|---------|----------|---------|
| 10 | 60.41s | 254 | 92.3% | 131.3 MB |
| 50 | **27.69s** | 254 | 100% | 134.7 MB |
| 100 | 32.24s | 254 | 100% | 136.6 MB |

**结论**：本 VM 上 **50 线程最优**；100 线程因 CPU 饱和反而略慢。

其他发现：
- C 段存活主机 2 台，开放端口 1 个（192.168.61.128:22）
- tshark 已安装但抓包 0 条（扫描期间无 HTTP/FTP 流量，属正常）

### 3.3 被动防御 `defense_20260704_114047`

**命令**：`python3 main.py --defense`

| 检测项 | 结果 |
|--------|------|
| Nmap/SYN 明确扫描 | 0 次（扫描已结束或未写入 syslog） |
| UFW 拦截 | 0 次 |
| 混杂模式 ens33 | 否 ✅ |
| 本机开放端口 | 2 个（SSH 等） |
| iptables 规则 | 已生成 8 条（未自动部署，dry_run） |

---

## 四、报告目录规范

每次 `--attack` 或 `--defense` 在 `reports/` 下创建独立目录：

```
reports/
├── attack_YYYYMMDD_HHMMSS/
│   ├── attack_report.md / .html
│   ├── summary.json
│   ├── perf_benchmark.md          # 仅 --perf 时
│   ├── capture.pcap                 # tshark 可选
│   └── screenshots/
│       ├── risk_distribution.png
│       ├── open_ports.png
│       ├── protocol_tcp_handshake.png
│       ├── thread_perf_comparison.png   # --perf
│       └── cpu_memory_usage.png         # --perf
└── defense_YYYYMMDD_HHMMSS/
    ├── defense_report.md
    ├── scan_events.json
    ├── summary.json
    ├── iptables_defense.sh
    └── screenshots/
        ├── attack_timeline.png
        └── promisc_mode_status.png
```

---

## 五、两条核心命令（速查）

```bash
cd /mnt/hgfs/insightscan

# 主动探测：扫目标 → AI 分析 → 报告 + 截图
python3 main.py --attack -t 127.0.0.1 --ports 22,80,443

# C 段 + 性能实验
python3 main.py --attack -t 192.168.61.0/24 --ports 22,80,443 --perf

# 被动防御：检测被扫描 / 混杂模式 / 生成 iptables
python3 main.py --defense --duration 60
```

**防御模式要检测到扫描**，需另开终端先扫本机：

```bash
# 终端 1
python3 main.py --attack -t 192.168.61.128 --ports 22,80,443

# 终端 2（扫描进行中或刚结束）
python3 main.py --defense
```

若仍检测不到，需开启 UFW 日志：

```bash
sudo ufw logging on
sudo ufw status
```

---

## 六、已知问题与限制

| # | 问题 | 严重程度 | 说明 / 应对 |
|---|------|---------|------------|
| 1 | 报告时间显示 UTC | 低 | DB 存 UTC，界面比本地时间少 8 小时，不影响功能 |
| 2 | 防御模式检测不到 Nmap | 中 | Connect 扫描默认不留 syslog 特征；需 UFW logging 或 SYN 扫描 |
| 3 | 协议图非 Wireshark 实包 | 低 | `protocol_*.png` 为字段标注参考图；实包需 Wireshark 打开 `capture.pcap` 或手动抓包 |
| 4 | tshark 抓包可能为 0 | 低 | 无 HTTP/FTP 流量时正常；实验可手动访问 `http://127.0.0.1` 后再跑 |
| 5 | AI 单端口可能走本地规则 | 低 | Kimi JSON 解析失败时降级；历史对比等长文本仍走 API |
| 6 | 防御报告未列具体端口 | 低 | summary.json 有 task_id，可查 DB 或后续前端展示 |
| 7 | `--perf` 耗时较长 | 预期 | C 段跑 3 轮约 2 分钟，写实验报告够用 |

---

## 七、待办（下一阶段）

- [x] **Web 前端界面**（三页：攻击/防御/配置）→ `python3 run_web.py` 访问 http://VM_IP:8080
- [ ] 实验一 SYN/FIN 对比（需 `sudo`）
- [ ] Metasploitable / DVWA 靶机联调（用户提供 IP）
- [ ] 协议分析：Wireshark 手动抓包截图补充进报告

---

## 八、Web 控制台

```bash
python3 run_web.py
# 浏览器打开 http://<VM_IP>:8080
```

| Tab | 功能 |
|-----|------|
| 主动探测 | 一键攻击 / 一键性能测试 |
| 被动防御 | 一键防御（攻击需另开终端或另一浏览器标签） |
| IP 配置 | 本机 IP、C 段、默认目标，支持自动检测 |

---

## 九、新会话快速开始

```bash
cd /mnt/hgfs/insightscan

# 1. 确认网段
ip addr | grep "inet "

# 2. 确认 API Key
cat config/api_keys.json   # 应有 kimi_api_key

# 3. 快速自检
python3 src/utils.py
python3 -m unittest discover -s tests -v

# 4. 一次完整主动探测
python3 main.py --attack -t 127.0.0.1 --ports 22,80,443

# 5. 查看最新报告
ls -lt reports/attack_* | head -3
```

---

## 十、相关文档

| 文档 | 用途 |
|------|------|
| [README.md](README.md) | 安装、命令、实验指引 |
| [InsightScan_完整思路书.md](InsightScan_完整思路书.md) | 原始设计与模块说明 |
| **本文档** | 当前进度、验收数据、已知问题 |
