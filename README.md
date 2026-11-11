[![CI](https://github.com/whx200711/whx-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/whx200711/whx-sentinel/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/whx200711/whx-sentinel)](https://github.com/whx200711/whx-sentinel/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)](#)
[![Tests](https://img.shields.io/badge/smoke-83%20passed-brightgreen)](#)

# WHX 哨兵（WHX Sentinel）

**本机 Windows 主机防护代理 · 本地安全看板 · 只在本机运行**

> 中文 | [English](README.en.md)

> 最初是一个 SOC 演示环境的一部分，后剥离为独立主机监控代理：
> 不再依赖网站或云端，单进程运行在本机，看板在 `http://127.0.0.1:8765/`，
> 所有事件只写入本机 `data/sentinel.db`。

- 版本：v1.0.0
- 运行平台：Windows 10 / 11（x64）
- 技术栈：Python 3.12 + FastAPI/uvicorn + psutil + PowerShell 探针 + SQLite（WAL）
- 定位：**防御性监控与告警工具**，不是杀毒软件，不替代 Windows Defender

---

## 1. 项目是什么

WHX 哨兵是一个「看得见本机正在发生什么」的轻量主机监控代理。它由若干采集
传感器和一套本地规则引擎组成，按固定周期读取本机的进程、网络连接、自启动项、
事件日志、Defender 状态、关键文件完整性与安全配置，把命中规则的事件写入本地
SQLite 事件库，并通过本机网页看板展示：

```
传感器线程（每 2–1800 秒采集一次）
        │  findings
        ▼
规则引擎 rules.py（进程/网络/持久化/日志/完整性/暴露面）
        │  Finding
        ▼
分析管线 analyst.py（白名单过滤 → 去重合并 → 入库 → 可选 Toast / 可选 AI 研判）
        │
        ▼
Web 看板 webapi.py（127.0.0.1:8765，只监听回环地址）＋ 本机事件库 db.py
```

设计原则：

1. **只监控、默认不动系统**。默认情况下哨兵只记录事件、在本地看板展示；
   所有会改变系统的动作（Defender 扫描、防火墙封锁、结束进程等）都必须
   由你在看板上手动点击确认。
2. **数据不出本机**。没有云端、没有遥测、没有外网扫描；看板只绑定
   `127.0.0.1`，AI 研判（可选）也只连接本机 Ollama。
3. **以启动时刻为基线**。哨兵启动前已经存在的进程、监听端口、自启动项会被
   当作基线记录下来，不产生历史告警；只有运行期间新出现的变化才会告警。

---

## 2. 能力矩阵

### 2.1 传感器一览

| 传感器 | 采集周期 | 主要检测内容 | 需要管理员 |
| --- | --- | --- | --- |
| `process` 进程监控 | 2 秒 | 可疑命令行（编码/隐藏 PowerShell、下载执行、IEX、certutil/bitsadmin/mshta/regsvr32/rundll32/wmic 等）、临时目录执行、办公软件派生 shell、计划任务创建、账号操作、卷影删除、日志清除、Defender/防火墙被关闭、凭据窃取、黑客工具、远控工具、UAC 绕过组件 | 否 |
| `network` 网络连接 | 4 秒 | 新增对外监听端口、高危监听端口（RDP/SMB/WinRM/数据库等）、可疑出站端口（反弹 shell/C2/挖矿/代理等）、黑名单 IP 外连（`data/blocklist.txt`） | 否 |
| `defender` Defender/防火墙状态 | 60 秒 | Defender 服务/防病毒/实时保护/行为监控是否关闭、病毒库是否过期（>7 天）、防火墙域/专用/公用配置文件是否关闭 | 否（读取状态） |
| `eventlog` 事件日志 | 30 秒 | 服务安装（7045）、服务启动类型修改（7040）、日志被清除（104/1102）、账号创建/加入管理员组（4720/4728/4732）、登录失败暴破（4625）、Defender 检测与配置变更（1116/1117/5001/5007/5010） | **Security 日志需要管理员** |
| `autorun` 自启动与持久化 | 300 秒 | HKCU/HKLM Run、启动目录、计划任务、系统服务的新增/修改；可疑命令（编码、远程下载、临时目录、脚本宿主） | 否（读取） |
| `fileguard` 文件完整性 | 60 秒 | `hosts` 文件被修改、勒索诱饵文件（金丝雀，位于 `%USERPROFILE%\Documents\WHX-Sentinel-Canary\`）被修改/删除、Defender 排除项新增、启动目录内容变化 | 否 |
| `exposure` 安全配置暴露面 | 1800 秒 | RDP 是否开启、SMBv1 是否启用、UAC 是否关闭、Secure Boot 是否开启、自动播放是否开启 | 否（读取） |

> 「需要管理员」指该传感器/能力在**标准模式**下可能返回 `needs_admin` /
> `degraded` 状态或读不到部分数据；看板「传感器状态」卡片会显示实际状态。

### 2.2 默认动作

| 场景 | 默认行为 |
| --- | --- |
| 任意命中规则 | 写入本地事件库 + 看板「安全事件」列表展示 |
| 严重度 ≥ Toast 阈值（默认 HIGH） | 弹一条本机 Windows 通知（可在设置中关闭/调低阈值） |
| 严重度为 HIGH 且规则允许 | 若开启 AI 研判，交给**本机 Ollama** 做中文研判（模型不可用时静默跳过） |
| 发现恶意软件后自动快速扫描 | **默认关闭**（`auto_quick_scan_on_malware`） |
| 高危外联自动封锁 IP | **默认关闭**（`auto_block_high_remote`） |
| 其他任何系统变更 | 不做，必须由用户在看板上手动点击动作 |

### 2.3 看板可执行的处置动作

| 动作 | 说明 | 需要管理员 |
| --- | --- | --- |
| 确认 / 忽略事件 | 修改事件状态（new → ack / ignored），仅改本地数据库 | 否 |
| AI 研判 | 对单条事件调用本机 Ollama 生成中文研判 | 否（仅需本机 Ollama） |
| 打开 Windows 安全中心 | 打开系统安全界面 | 否 |
| Defender 快速扫描 | 调用 `Start-MpScan -ScanType QuickScan` | **是** |
| 更新 Defender 病毒库 | 调用 `Update-MpSignature` | **是** |
| 防火墙封锁 / 解除封锁 IP | 写入 Windows 防火墙入站+出站阻断规则 | **是** |
| 结束进程 | 结束选中事件关联的进程；关键系统进程与哨兵自身一律拒绝 | 其他用户的进程需要管理员 |
| 重置基线 | 清空自启动/监听/排除项基线，下一轮重新学习现状 | 否 |
| 测试通知 | 弹一条测试 Toast | 否 |
| 停止哨兵 | 请求哨兵优雅退出 | 需要看板控制令牌（自动获取） |

### 2.4 看板功能

- **安全态势总览**：24h 高危 / 中危 / 低危 / 提示、未处理事件、传感器在线数、
  Defender 实时保护、防火墙、AI 研判、事件总数。
- **24 小时事件趋势**：按小时、按严重度堆叠柱状图，悬停查看数值。
- **安全事件列表**：按严重度 / 传感器 / 状态筛选，关键字搜索，分页；
  点击任意行打开事件详情抽屉（详情、元数据、时间、处置按钮）。
- **传感器状态**：每个传感器的能力状态（ok / degraded / needs_admin /
  unavailable / error）、上次采集耗时与错误信息。
- **安全配置检查**：RDP、SMBv1、UAC、Secure Boot、自动播放等暴露面检查结果。
- **最近处置**：actions 审计记录。
- **主机与数据库**：操作系统、开机时长、内存、磁盘、CPU、当前用户、数据库
  路径/大小、自启动状态。
- **设置抽屉**：AI 研判开关与模型、Toast 开关与最低级别、自动处置开关、
  数据保留天数、金丝雀文件开关、白名单管理、测试通知 / 重置基线 / 停止哨兵。

---

## 3. 环境要求与安装

### 3.1 环境要求

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Windows 10 / 11（需要 PowerShell 5.1+，系统自带） |
| Python | 3.12（3.10+ 通常也可运行，交付环境为 3.12） |
| Python 依赖 | `fastapi`、`uvicorn`、`httpx`、`psutil` |
| 可选 | Node.js（仅 `tests/smoke_test.py` 校验前端 app.js 语法时使用） |
| 可选 | 本机 Ollama（AI 研判，默认模型 `deepseek-r1:8b`） |

安装依赖（如果目标机器还没有）：

```bat
python -m pip install fastapi uvicorn httpx psutil
```

### 3.2 获取与启动

本项目是绿色目录，无需安装包、无需写注册表（除了可选的开机自启）：

1. 把 `whx-sentinel` 目录放到任意位置（路径建议不含空格）；
2. 双击 **`install\start_sentinel.bat`**（推荐，后台启动并自动打开看板）；
   或在项目目录执行 `python sentinel.py --open`（前台运行，控制台可看日志）；
3. 浏览器打开 **<http://127.0.0.1:8765/>**。

首次启动会自动创建 `data/` 数据目录、`config.json`（含本机控制令牌）与
`sentinel.db` 事件库。

---

## 4. 启动与停止

| 场景 | 方式 | 说明 |
| --- | --- | --- |
| 后台启动（推荐） | 双击 `install\start_sentinel.bat` | 用 `pythonw` 后台运行，不弹控制台窗口，并自动打开看板 |
| 前台调试 | `python sentinel.py --open` | 控制台可看到实时日志，关闭控制台即停止 |
| 增强模式（管理员） | 双击 `install\start_elevated.bat` | 弹一次 UAC，以管理员身份后台运行，解锁全部能力 |
| 查看状态 | `python sentinel.py --status` | 打印运行时长、传感器状态、24h 统计、Defender/AI 状态 |
| 停止 | 双击 `install\stop_sentinel.bat` 或 `python sentinel.py --stop` | 先请求优雅退出，失败时按 PID 兜底终止 |
| 只采集一轮 | `python sentinel.py --once` | 逐传感器打印本轮告警，**不启动服务、不写数据库**，用于调试传感器 |
| 冒烟测试 | `python tests\smoke_test.py` 或 `python sentinel.py --smoke-test` | 自动化体检，无副作用，详见第 12 节 |
| 注册登录自启 | 双击 `install\install_autostart.bat` | 写当前用户 `HKCU\...\Run`，见第 8 节 |
| 卸载 | 双击 `install\uninstall.bat` | 停止 + 移除自启 + 打印数据目录，不删数据，见第 8 节 |

### 命令行参数

```
python sentinel.py [--data-dir DIR] [--port PORT] [--open] [--daemon]
                   [--once] [--status] [--stop] [--smoke-test]
                   [--install-autostart] [--uninstall-autostart] [--version]
```

- `--data-dir DIR`：使用指定数据目录（默认 `<程序目录>\data`）；
- `--port PORT`：看板端口（默认 8765），只绑定 `127.0.0.1`；
- `--daemon`：后台/自启动场景使用（供 `pythonw` 调用）；
- `--open`：服务就绪后自动打开浏览器；
- 其余参数见上表。

---

## 5. 标准模式 vs 管理员增强模式

哨兵有两种运行模式，数据目录、看板、规则完全相同，差别只在 Windows 权限：

| 能力 | 标准模式（普通双击） | 管理员增强模式（start_elevated.bat） |
| --- | --- | --- |
| 进程 / 网络 / 自启动 / 文件完整性监控 | ✅ | ✅ |
| Defender 状态读取 | ✅（一般可读） | ✅ |
| Security 事件日志读取 | ❌ 不可读（传感器显示 needs_admin） | ✅ |
| 防火墙封锁 / 解除封锁 IP | ❌ 拒绝并提示 | ✅ |
| Defender 快速扫描 / 更新病毒库 | ❌ 拒绝并提示 | ✅ |
| 结束其他用户的进程 | ❌ 拒绝并提示 | ✅ |
| 结束当前用户自己的进程 | ✅（关键系统进程始终拒绝） | ✅ |
| 确认/忽略事件、白名单、设置 | ✅ | ✅ |
| 开机自启动注册（HKCU） | ✅ | ✅ |

说明：

- 增强模式启动方式：双击 `install\start_elevated.bat`，在 UAC 弹窗点「是」。
  该脚本用 `PowerShell Start-Process -Verb RunAs` 以管理员身份启动
  `pythonw sentinel.py --daemon`，随后等待看板就绪并打开浏览器。
- UAC 只需确认一次；启动后看板右上角徽章会从「标准模式」变为管理员标识，
  `python sentinel.py --status` 也会显示「管理员模式」。
- 两种模式共用同一个数据目录，可以互相停止（同一 Windows 用户下）。
- **日常使用标准模式即可**；需要读安全日志或使用防火墙/Defender 处置动作时
  再以增强模式启动。

---

## 6. 看板使用

- 地址：<http://127.0.0.1:8765/>（只监听本机回环，**不要**用局域网 IP 访问，
  其他设备无法访问，这是有意的安全设计）。
- 页面每数秒自动刷新状态与事件；顶部会显示与本地服务的连接状态。
- 「安全事件」支持按严重度、传感器、状态筛选，关键字搜索，点击行查看详情。
- 事件详情抽屉底部提供：确认、忽略、AI 研判、封锁 IP、结束进程、打开安全中心
  等按钮；动作执行结果会写入「最近处置」并立即反馈。
- 右上角「⚙ 设置」打开设置抽屉，可修改 AI/通知/自动处置/数据保留/白名单，
  以及测试通知、重置基线、停止哨兵。
- 如果有页面显示「看板文件缺失」，说明 `web/` 目录不完整（`index.html` 缺失），
  但 `/api/status` 等接口仍然可用。
- 安全设计：看板只绑定 `127.0.0.1`；**所有接口（含只读）都校验 `Host`**，只接受
  `127.0.0.1` / `localhost` / `[::1]`，防 DNS rebinding；所有写接口要求请求头
  `X-Sentinel-Token`（令牌只回显给回环客户端，看板从 `/api/token` 自动获取）；
  页面禁用内联脚本与外部资源（CSP），事件内容按纯文本渲染。
  注意：控制令牌**只防浏览器跨源，不防本机进程**（见 §10 第 9 条）。

---

## 7. 数据与隐私

**所有数据都只保存在本机，没有上传、没有遥测、没有云端。**

数据目录：`<程序目录>\data\`（可用 `--data-dir` 改到别处）

| 文件 | 内容 |
| --- | --- |
| `sentinel.db` | SQLite 事件库（events 事件、actions 处置记录、metadata 元数据），WAL 模式 |
| `config.json` | 本机控制令牌、各项设置与白名单 |
| `logs/sentinel.log` | 运行日志（滚动，单文件约 2 MB，保留 3 份） |
| `baselines.json` | 自启动项 / 监听端口 / 文件完整性 / Defender 排除项基线 |
| `blocklist.txt` | 可选：手工维护的 IP/CIDR 黑名单，一行一条，`#` 开头为注释 |
| 诱饵目录（数据目录之外） | `%USERPROFILE%\Documents\WHX-Sentinel-Canary\`：文件完整性传感器放置的 3 个勒索诱饵文本文件（`canary_enabled` 开启时创建，用于检测批量加密/删除行为；不是你的文档） |

- 数据保留：默认保留 **30 天**、最多 **20000 条**事件；哨兵每小时自动清理一次，
  可在设置抽屉里调整保留天数。
- 网络行为：哨兵自身只监听 `127.0.0.1`；不向任何外部地址发送数据；
  不主动扫描外网；AI 研判仅连接本机 Ollama（默认 `http://127.0.0.1:11434`，
  `ollama_url` 会用 URL 解析校验 scheme / userinfo / 主机名 / 端口，只允许回环 + 11434），
  且只有开启 AI 时才会请求；AI 默认**关闭**。
- 内部探针标记：首次启动会在 `config.json` 生成随机 `internal_marker`，
  公开设置接口不会返回该标记（避免泄露后成为免检口令）。
- 删除数据：在设置抽屉关闭哨兵后，手动删除 `data/` 目录即可清除事件库/配置/日志；
  如文件完整性传感器创建过诱饵，可一并删除 `%USERPROFILE%\Documents\WHX-Sentinel-Canary\`
  目录。卸载脚本**不会**自动删除你的数据与诱饵目录。
- 导出：看板「导出 JSON」可导出事件（`/api/export`）。

---

## 8. 开机自启 / 停止 / 卸载

### 8.1 开机（登录）自启

双击 `install\install_autostart.bat`，或执行：

```bat
python sentinel.py --install-autostart
```

它会在当前用户注册表写入一个启动项（**不需要管理员权限**）：

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    值名：WHX Sentinel
    数据：<pythonw.exe 路径> <程序目录>\sentinel.py --daemon
```

登录 Windows 后哨兵会在后台自动运行，看板同样在 `http://127.0.0.1:8765/`。

移除自启：

```bat
install\uninstall_autostart.bat
python sentinel.py --uninstall-autostart
```

> 移除自启不会停止当前正在运行的哨兵；停止请用 `stop_sentinel.bat`
> 或 `python sentinel.py --stop`。

### 8.2 停止

- 双击 `install\stop_sentinel.bat`；
- 或 `python sentinel.py --stop`（先请求看板优雅退出，失败时读取 PID 文件
  并按进程名兜底终止）；
- 或任务管理器结束 `pythonw.exe`（粗暴，可能丢失最后几秒的事件写入）。

### 8.3 卸载

双击 `install\uninstall.bat`，它会依次执行：

1. `python sentinel.py --stop` 停止正在运行的哨兵；
2. `python sentinel.py --uninstall-autostart` 移除登录自启动；
3. 打印数据目录位置，并提示手动删除（**不会自动删数据**）。

如需彻底清除：停止哨兵后，直接删除整个 `whx-sentinel` 目录即可；如果文件完整性
传感器创建过诱饵文件，再手动删除 `%USERPROFILE%\Documents\WHX-Sentinel-Canary\`。

手动检查自启是否残留：注册表编辑器打开
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`，
确认没有名为 `WHX Sentinel` 的值。

---

## 9. 退出码与排障

### 9.1 退出码

| 退出码 | 含义 |
| --- | --- |
| `0` | 成功（`--version` / `--once` / `--status` 查到运行中 / `--stop` 成功 / 自启动操作成功 / 看板正常退出） |
| `1` | 失败或状态不满足：`--status` 时哨兵未运行、`--stop` 失败、自启动注册/移除失败、端口被其它程序占用 |
| `2` | `--smoke-test` 找不到 `tests/smoke_test.py` |
| 非 `0` 且不在上表 | Python 运行时异常（看 `data/logs/sentinel.log` 与终端输出） |

`python sentinel.py --smoke-test` 会把冒烟测试的退出码原样返回：任何 FAIL → `1`。

### 9.2 常见问题

| 现象 | 排查与处理 |
| --- | --- |
| `--status` 显示「哨兵未运行」 | 确认双击过 `start_sentinel.bat` 或前台启动过；检查任务管理器是否有 `pythonw.exe`；查看 `data/logs/sentinel.log` 尾部 |
| 端口 8765 被占用 | `netstat -ano | findstr :8765` 找到 PID 后决定是否结束；或用 `python sentinel.py --port 8766 --open` 换端口（看板地址随之变化） |
| 看板打开 503 / 空白 | `web/index.html` 缺失或损坏；确认交付目录完整；接口可用性可用 `http://127.0.0.1:8765/api/health` 验证 |
| 看板一直显示「正在连接」 | 后台进程未启动成功或端口不对；看日志与 `--status` |
| 浏览器访问 `/api/token` 返回 403 | 正常安全设计：令牌只发给 `127.0.0.1` 回环请求；请用 `http://127.0.0.1:8765/` 打开看板，不要用 `localhost` 之外的主机名或局域网 IP |
| 传感器状态 `needs_admin` / `degraded` | 标准模式权限不足；改用 `install\start_elevated.bat` 以管理员启动（Security 事件日志、防火墙、Defender 动作需要）。若 `fileguard` 显示 `degraded`，检查 `Documents\WHX-Sentinel-Canary` 是否被安全软件/策略禁止写入（此时 hosts 监控仍工作） |
| 传感器状态 `error` | 看传感器卡片里的错误信息与 `data/logs/sentinel.log`；通常是 PowerShell 探针超时或系统接口被安全软件拦截 |
| AI 研判不可用 | 确认本机 Ollama 已运行：`ollama list` 能看到 `deepseek-r1:8b`（或设置里改模型名）；不需要 AI 可在设置里关闭 |
| Toast 通知不弹 | Windows 设置 → 系统 → 通知，确认「通知」总开关与专注助手；设置抽屉里的最低通知级别是否过高 |
| 开机没有自动启动 | 确认执行过 `install\install_autostart.bat` 且返回 `"ok": true`；检查注册表 `HKCU\...\Run` 的 `WHX Sentinel` 值；`--status` 查看 `autostart` 字段 |
| 结束进程失败 | 关键系统进程被哨兵主动拒绝；其他用户的进程需要管理员模式；个别受保护进程需系统权限 |
| 哨兵被 Windows Defender 拦截/报警 | 哨兵会调用 PowerShell 读取系统状态并（可选）写防火墙规则，可能触发启发式拦截。本工具全部源码可见、无恶意行为；如被拦截请将程序目录加入信任，或仅用标准模式 |

日志位置：`data/logs/sentinel.log`（滚动保留）。反馈问题时请附上：
程序版本、Windows 版本、`python sentinel.py --status` 输出、日志尾部若干行。

---

## 10. 能力边界（务必阅读）

WHX 哨兵是**可见性工具**，不是安全万能药。请如实理解它的边界：

1. **不是杀毒软件，不替代 Windows Defender。**
   哨兵不查杀文件、不做实时文件扫描、不做云查杀、不检测内存马/无文件攻击；
   它读取并展示 Defender 的状态，但 **请保持 Windows Defender 开启**。
2. **只监控与告警，默认不自动改系统。**
   默认配置下，命中规则只写事件库 + 看板展示（高危最多弹一条本地通知）。
   防火墙封锁、Defender 扫描/更新、结束进程等动作全部需要你在看板上手动点击；
   「自动处置」两个开关默认关闭，开启后风险由使用者自行承担。
3. **启动前已存在的对象不告警。**
   进程、对外监听、自启动项、基线文件都以哨兵启动时刻为基线：
   - 启动**之前**已经在运行的进程 → 不告警（避免历史刷屏）；
   - 启动**之前**已经存在的监听端口/自启动项 → 记为基线，之后变化才告警；
   - 因此如果机器在哨兵启动前就已中毒，哨兵不会回溯告警。
     想覆盖更多时间窗，请配合「开机自启」让哨兵尽早启动。
4. **无内核驱动、无自我保护。**
   管理员权限的恶意软件可以结束、卸载或绕过哨兵；哨兵不能阻止已发生的
   恶意行为，只能尽量发现并留下记录。
5. **规则驱动，可能误报/漏报。**
   检测基于命令行/路径/端口/事件日志等规则与启发式判断，正常软件也可能命中
   （例如开发工具执行 PowerShell）；请结合上下文与 Windows 安全中心判断，
   对确认无误的项目可使用白名单。
6. **标准模式能力受限。**
   Security 事件日志、防火墙封锁、Defender 扫描/更新、结束其他用户进程需要
   管理员权限，请用增强模式启动。
7. **单机、本地、无集中管理。**
   没有服务器端、没有告警外发、没有多用户与远程管理；只适合个人/单机场景，
   不构成企业级 EDR 或合规审计方案。
8. **处置动作不保证成功。**
   系统策略、安全软件、权限都会影响结果；动作执行结果会记录在
   「最近处置」中，失败时请按提示改用 Windows 安全中心手工处理。
9. **控制令牌只防浏览器跨源，不防本机进程。**
   `/api/token` 的校验只有「来源回环 + Host 回环」，与 Windows 用户身份无关；
   同机任意用户/进程都能读到令牌，进而修改设置、往白名单里加 `suppress_rules`
   静默消音、或直接停服务。本工具假定**单用户工作站**；多用户/共用机器请勿使用。
10. **内部探针标记每次安装随机生成。**
   首次启动会在 `config.json` 写入 `internal_marker`（`WHX_SENTINEL_` + 16 位随机
   十六进制），进程传感器只跳过带本机标记的子进程；公开代码里没有固定免检口令。

---

## 11. 目录结构

```
whx-sentinel/
├─ sentinel.py            # 命令行入口（--daemon/--open/--once/--status/--stop/...）
├─ config.py              # 路径、默认配置、白名单、token 生成与配置读写
├─ core.py                # 应用核心：配置/数据库/传感器/分析管线/状态/设置/自启动
├─ db.py                  # SQLite 事件库（events / actions / metadata）
├─ rules.py               # 规则匹配（进程/网络/持久化/日志/完整性/暴露面/白名单）
├─ rules_data.py          # 内置规则数据（进程规则、端口表、事件日志规则、暴露面检查等）
├─ analyst.py             # 分析管线：白名单过滤 → 去重入库 → Toast / AI / 自动处置队列
├─ respond.py             # 通知与处置动作（Toast、防火墙、Defender、结束进程等）
├─ ai.py                  # 可选：本机 Ollama 中文研判
├─ winutil.py             # Windows 工具（PowerShell 探针、注册表、哈希、IP 判断等）
├─ events.py              # Finding 事件模型与严重度工具
├─ webapi.py              # FastAPI 应用：只读 API + 令牌保护的写 API + 看板托管
├─ sensors/
│  ├─ base.py             # Sensor 基类、SensorContext、BaselineStore
│  ├─ process.py          # 进程监控传感器
│  ├─ network.py          # 网络连接传感器
│  ├─ defender.py         # Defender / 防火墙状态传感器
│  ├─ eventlog.py         # Windows 事件日志传感器
│  ├─ autorun.py          # 自启动 / 计划任务 / 服务传感器
│  ├─ fileguard.py        # 文件完整性 / 金丝雀传感器
│  └─ exposure.py         # 安全配置暴露面传感器
├─ web/                   # 本机看板（无外部资源，CSP 限制）
│  ├─ index.html
│  ├─ app.js
│  ├─ style.css
│  └─ favicon.svg
├─ install/               # Windows 启动/停止/自启/卸载脚本
│  ├─ start_sentinel.bat  # 后台启动 + 打开看板
│  ├─ stop_sentinel.bat   # 停止哨兵
│  ├─ install_autostart.bat    # 注册登录自启（HKCU Run）
│  ├─ uninstall_autostart.bat  # 移除登录自启
│  ├─ start_elevated.bat  # 管理员增强模式启动（UAC）
│  └─ uninstall.bat       # 停止 + 移除自启 + 打印数据目录
├─ tests/
│  └─ smoke_test.py       # 无副作用自动化冒烟测试
├─ data/                  # 运行时数据（首次启动自动创建，不随包分发）
│  ├─ sentinel.db         # 事件库
│  ├─ config.json         # 本机配置与令牌
│  ├─ baselines.json      # 基线
│  ├─ logs/sentinel.log   # 运行日志
│  └─ blocklist.txt       # 可选：自定义 IP/CIDR 黑名单
└─ README.md              # 本文档
```

---

## 12. 测试与自检

### 12.1 运行冒烟测试

```bat
python tests\smoke_test.py
rem 或
python sentinel.py --smoke-test
```

冒烟测试是**无副作用**的：不启动常驻服务、不启动传感器线程、不发送 Toast、
不执行 Defender 扫描、不修改防火墙、不写注册表、不结束进程；所有临时数据写入
项目内 `_smoke_data/`，测试结束（包括发生异常时）自动删除。

输出格式为逐项明细 + 汇总：

```
[PASS] rules.process · 正例：PowerShell 编码命令：PowerShell -EncodedCommand -> proc.ps_encoded
[SKIP] sensors · sensors/eventlog.py 交付状态：sensors/eventlog.py 尚未交付（...）
...
汇总：PASS 70 · FAIL 0 · SKIP 5 · 共 75 项
```

- `FAIL` → 退出码 `1`，需要修复；
- `SKIP` → 退出码 `0`，通常表示并行开发中的可选文件尚未交付（传感器模块、
  `web/app.js`）或本机没有 Node.js（跳过 app.js 语法校验）。

### 12.2 覆盖范围

- `compileall` 编译项目全部 `.py`（语法体检）；
- `rules.py` 各匹配器的**正例 + 反例**：进程、Defender、防火墙、事件日志、
  监听端口、网络连接、自启动、启动目录、计划任务、服务、文件完整性、暴露面、
  登录失败暴破阈值；
- 白名单过滤：`cmdline_contains` / `process_names` / `paths` / `remote_ips` /
  `suppress_rules`；
- `db.py`：建库、插入、去重合并（`seen_count`）、统计、24 小时时间线、
  标记状态、actions、prune、metadata、导出；
- `SentinelCore` + `webapi.create_app`：用 FastAPI `TestClient` 请求
  `/api/health`、`/api/status`、`/api/events`、`/api/timeline`、`/api/settings`、
  `/api/actions/*`、`/api/allowlist`、`/api/export`；`/api/token` 在 TestClient
  下返回 403（非回环客户端）属预期；非回环 `Host` 请求返回 403（防 DNS rebinding），
  >1 MB 请求体返回 413；`kill_process` 拒绝 PID 0/4/自身；
- `config.py`：首次加载自动生成 token、随机 `internal_marker` 且加入白名单、
  `ollama_url` 拒绝 userinfo / 外部域名 / 非常用端口、默认关闭 AI、保存/重载、
  损坏配置自愈；
- `web/` 三个前端资产存在性，`app.js` 用 `node --check` 校验语法；
- `install/` 六个脚本的存在性、UTF-8 编码、CRLF 行尾与关键命令；
- `README.md` 关键章节完整性；
- `python sentinel.py --version` 入口自检。

### 12.3 手工自检建议

```bat
python sentinel.py --version     # 版本
python sentinel.py --once        # 逐传感器采集一轮并打印结果（不启动服务）
python sentinel.py --open        # 前台启动，浏览器打开看板
```

---

## 13. 来源与说明

- 本项目最初是一个 SOC 看板演示环境的一部分，后重构为完全在本机运行、
  不依赖任何后端的独立主机防护代理。
- 全部代码为项目自有；第三方依赖（FastAPI、uvicorn、httpx、psutil 等）遵循各自
  开源许可证。
- 本工具面向本机安全可见性演示与个人防护辅助，请勿将其视为专业安全产品或
  合规审计工具。
