# InsightScan 项目现状

> 最后更新：2026-07-05（Nmap 扫描与对比教学 · Web 第四 Tab · SYN/OS 权限方案 · HTML 报告）  
> 适用环境：Ubuntu 22.04 VM + VMware 共享文件夹 `/mnt/hgfs/insightscan`

| 文档 | 用途 |
|------|------|
| **[InsightScan_项目说明.md](InsightScan_项目说明.md)** | 任务书 / 答辩：结构、亮点、流程 |
| [README.md](README.md) | 安装、**SYN/OS 权限配置**、命令速查 |
| [InsightScan_完整思路书.md](InsightScan_完整思路书.md) | 原始设计 |
| [环境准备.md](环境准备.md) | 环境搭建 |

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
| SYN/OS 权限 | `sudo -n nmap --version` 免密成功即就绪 |

```bash
ip addr | grep "inet "
sudo -n nmap --version    # 验证 Nmap 教学 SYN/OS 权限
```

---

## 二、已完成功能

| 模块 | 文件 | 状态 |
|------|------|------|
| 配置 / 数据库 | `src/utils.py` | ✅ |
| Nmap 扫描引擎 | `src/scan_engine.py` | ✅ Connect/SYN/FIN |
| AI 分析 | `src/ai_analyzer.py` | ✅ Kimi + 缓存 + 降级 |
| 报告生成 | `src/report_generator.py` | ✅ MD/HTML |
| CLI 入口 | `main.py` | ✅ |
| 主动探测 | `src/attack_mode.py` | ✅ 攻击套件 run_attack_suite |
| 被动防御 | `src/defense_mode.py` | ✅ syslog + DB 联动 |
| 安全工具 | `src/security_tools.py` | ✅ |
| 性能实验 | `src/perf_benchmark.py` | ✅ |
| 协议分析 | `src/protocol_analyzer.py` | ✅ |
| Web 控制台 | `web/` + `run_web.py` | ✅ **四页** + 攻防联调 |
| **Nmap 教学** | `nmap_lab/` | ✅ Zenmap / 四种扫描 / HTML+XML |
| Web 配置 | `src/ui_config.py` | ✅ |
| 单元测试 | `tests/` | ✅ |
| 项目文档 | 三份主文档 + 环境准备 | ✅ 已同步 |

---

## 三、验收结果摘要

### 3.1 主动探测

- 本机 `127.0.0.1`：端口扫描 + AI 报告正常  
- 一键攻击套件：Connect + SYN + FIN  
- SYN/FIN 在 CLI 侧仍需 root；Web 主流程 Connect 可用  

### 3.2 性能实验（C 段示例）

| 线程 | 耗时 | 结论 |
|------|------|------|
| 10 | ~60s | |
| 50 | **~28s** | **最优** |
| 100 | ~32s | CPU 饱和略慢 |

### 3.3 被动防御

- syslog 对 Connect 常为 0（预期）  
- **数据库联动**可检测联调期间扫描  
- iptables 脚本、混杂模式检测正常  

### 3.4 Web 控制台（四 Tab）

| Tab | 验收要点 |
|-----|---------|
| 主动探测 | 攻防联调、全套攻击、性能测试 |
| 被动防御 | 接续攻击、自动联调 |
| IP 配置 | 检测网段、各页目标同步 |
| **Nmap扫描与对比教学** | 五按钮独立运行；SYN/OS 需 sudo 免密 nmap |

### 3.5 Nmap 教学模块（新增，已验收）

| 能力 | 说明 |
|------|------|
| Zenmap 演示 | Web 双栏主机/端口 + CLI ASCII 输出 |
| Connect (-sT) | 普通用户即可 |
| SYN (-sS) | 配置 sudo 免密 nmap 后 Web 可用 |
| OS (-O) | 同上 |
| 全端口 | Web 固定 1-1000 |
| 报告 | 每次扫描生成 `scan.html`（浏览器看）+ `scan.xml`（Zenmap 导入） |
| InsightScan 对比 | 静态对比表 + 可选 AI 增强分析按钮 |

**权限方案（每人用户名不同，用 `whoami` 自动填入）**：

```bash
cd /mnt/hgfs/insightscan
whoami    # 先查看自己的用户名（@ 符号前面也是）
which nmap #查看nmap位置
echo "用户名 ALL=(ALL) NOPASSWD: nmap位置" | sudo tee /etc/sudoers.d/insightscan-nmap
sudo chmod 440 /etc/sudoers.d/insightscan-nmap
sudo -n nmap --version
python3 run_web.py
```

说明：sudoers 一行格式为 `用户名 ALL=(ALL) NOPASSWD: nmap路径`；用户名填 `whoami` 输出，路径填 `which nmap` 输出（通常 `/usr/bin/nmap`）。详见 [README.md](README.md#nmap-教学与-synos-权限配置)。

---

## 四、报告目录规范

```
reports/
├── attack_YYYYMMDD_HHMMSS/
│   ├── attack_report.md / .html
│   ├── summary.json
│   └── screenshots/
├── defense_YYYYMMDD_HHMMSS/
│   ├── defense_report.md
│   ├── iptables_defense.sh
│   └── scan_events.json
└── nmap_lab/
    └── zenmap_20260705_113249/     # 前缀：zenmap / connect / syn / os / full_port
        ├── scan.html               # Web「浏览器查看」
        └── scan.xml                # 下载 / Zenmap 导入
```

Web 报告 URL 格式：

`http://<IP>:8080/reports/nmap_lab/<目录名>/scan.html`

---

## 五、核心命令速查

```bash
cd /mnt/hgfs/insightscan

# ① SYN/OS 权限（首次，用户名用 whoami 自动填入）
whoami
echo "$(whoami) ALL=(ALL) NOPASSWD: $(which nmap)" | sudo tee /etc/sudoers.d/insightscan-nmap
sudo chmod 440 /etc/sudoers.d/insightscan-nmap
sudo -n nmap --version

# ② Web
python3 run_web.py

# ③ CLI 攻防
python3 main.py --attack -t 127.0.0.1 --ports 22,80,443
python3 main.py --defense --duration 60

# ④ Nmap 教学 CLI
python3 nmap_lab/zenmap_demo.py
python3 nmap_lab/scan_types_demo.py
```

---

## 六、已知问题与限制

| # | 问题 | 说明 / 应对 |
|---|------|------------|
| 1 | Connect 扫描 syslog 无特征 | 防御 DB 联动；可选 `sudo ufw logging on` |
| 2 | **SYN/OS 需 root** | **已解决**：配置 `/etc/sudoers.d/insightscan-nmap` 后 Web 可用 |
| 3 | 勿 `sudo python3 run_web.py` | 会缺 pip 包；用普通用户启动 Web |
| 4 | 浏览器不能直接看 XML | 已生成 `scan.html`；XML 供下载/Zenmap |
| 5 | 全端口 Web 固定 1-1000 | 实验书 1-65535，CLI 说明中保留 |
| 6 | VMware 共享目录不宜 venv | `pip3 install --user -r requirements.txt` |
| 7 | AI 缓存 | 清空 `data/ai_cache.json` 可强制调 API |
| 8 | Windows 开发机 | Nmap 教学请在 Ubuntu VM 演示 |

---

## 七、待办（可选扩展）

- [x] Web 四页 + Nmap 扫描与对比教学  
- [x] nmap_lab 模块 + sudo 免密 nmap 方案  
- [x] scan.html 浏览器报告 + 文档同步  
- [ ] Metasploitable / DVWA 靶机联调  
- [ ] Wireshark 手动抓包截图进报告  

---

## 八、答辩演示推荐顺序

1. **IP 配置** → 检测并应用 → 保存  
2. **Nmap扫描与对比教学** → Connect → SYN → OS → 打开 `scan.html`  
3. **InsightScan 增强分析** → 对比 AI 报告  
4. **一键攻防联调** → 攻击 + 防御双报告  

---

## 九、新会话快速开始

```bash
cd /mnt/hgfs/insightscan
sudo -n nmap --version                   # 确认 SYN/OS 权限
python3 run_web.py                       # 启动 Web
# http://<VM_IP>:8080 → Nmap扫描与对比教学 / 攻防联调
```

---

## 十、相关文档

| 文档 | 何时读 |
|------|--------|
| **README.md** | 权限配置、日常命令 |
| **InsightScan_项目说明.md** | 任务书、答辩 |
| 环境准备.md | 首次搭 VM |
