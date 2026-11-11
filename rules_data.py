"""WHX 哨兵 · 内置检测规则数据。

规则只做「本地主机上值得警惕的行为」检测，属于防御性监控：
不包含任何攻击/利用能力，不修改系统，不主动扫描外网。
每条规则都有稳定 id，前端和测试可据此断言。
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 进程规则：在 name + exe + cmdline 组合文本上做正则匹配
# severity: HIGH / MEDIUM / LOW / INFO
# ---------------------------------------------------------------------------
PROCESS_RULES: list[dict] = [
    {
        "id": "proc.ps_encoded",
        "severity": "HIGH",
        "title": "PowerShell 使用编码/Base64 命令",
        "patterns": [
            r"(powershell(\.exe)?|pwsh(\.exe)?)[^\n]{0,160}(-enc|-encodedcommand)\b",
            r"(powershell|pwsh)[^\n]{0,100}-e\s+[A-Za-z0-9+/=]{40,}",
        ],
        "ai_eligible": True,
    },
    {
        "id": "proc.ps_hidden",
        "severity": "MEDIUM",
        "title": "PowerShell 隐藏窗口运行",
        "patterns": [
            r"(powershell|pwsh)[^\n]{0,180}(-w(indowstyle)?\s+hidden|-windowstyle\s+hidden)",
        ],
        "ai_eligible": True,
    },
    {
        "id": "proc.ps_download",
        "severity": "HIGH",
        "title": "PowerShell 从网络下载代码",
        "patterns": [
            r"(powershell|pwsh)[^\n]{0,220}(downloadstring|downloadfile|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|start-bitstransfer|net\.webclient)",
        ],
        "ai_eligible": True,
    },
    {
        "id": "proc.ps_iex",
        "severity": "HIGH",
        "title": "PowerShell 动态执行（IEX / Invoke-Expression）",
        "patterns": [r"(powershell|pwsh)[^\n]{0,220}(\biex\b|invoke-expression)"],
        "ai_eligible": True,
    },
    {
        "id": "proc.ps_base64",
        "severity": "HIGH",
        "title": "PowerShell 解码 Base64 后执行",
        "patterns": [r"(powershell|pwsh)[^\n]{0,220}frombase64string"],
        "ai_eligible": True,
    },
    {
        "id": "proc.certutil_download",
        "severity": "HIGH",
        "title": "certutil 下载远程文件",
        "patterns": [r"certutil(\.exe)?[^\n]{0,160}(-urlcache|-verifyctl)"],
        "ai_eligible": True,
    },
    {
        "id": "proc.certutil_decode",
        "severity": "MEDIUM",
        "title": "certutil 解码文件（可能用于绕过检测）",
        "patterns": [r"certutil(\.exe)?[^\n]{0,80}-decode"],
        "ai_eligible": True,
    },
    {
        "id": "proc.bitsadmin_transfer",
        "severity": "HIGH",
        "title": "bitsadmin 下载文件",
        "patterns": [r"bitsadmin(\.exe)?[^\n]{0,160}/transfer"],
        "ai_eligible": True,
    },
    {
        "id": "proc.mshta_remote",
        "severity": "HIGH",
        "title": "mshta 执行远程/脚本内容",
        "patterns": [r"mshta(\.exe)?[^\n]{0,160}(https?://|vbscript:|javascript:)"],
        "ai_eligible": True,
    },
    {
        "id": "proc.regsvr32_remote",
        "severity": "HIGH",
        "title": "regsvr32 远程加载（Squiblydoo）",
        "patterns": [r"regsvr32(\.exe)?[^\n]{0,200}(/i:|/u)[^\n]{0,120}https?://"],
        "ai_eligible": True,
    },
    {
        "id": "proc.rundll32_script",
        "severity": "HIGH",
        "title": "rundll32 执行脚本/远程内容",
        "patterns": [r"rundll32(\.exe)?[^\n]{0,160}(javascript:|https?://)"],
        "ai_eligible": True,
    },
    {
        "id": "proc.wmic_spawn",
        "severity": "HIGH",
        "title": "WMIC 创建进程（常见无文件执行）",
        "patterns": [r"wmic(\.exe)?[^\n]{0,160}process[^\n]{0,60}call[^\n]{0,60}create"],
        "ai_eligible": True,
    },
    {
        "id": "proc.schtasks_create",
        "severity": "MEDIUM",
        "title": "创建/修改计划任务",
        "patterns": [r"schtasks(\.exe)?[^\n]{0,160}(/create|/change)"],
        "ai_eligible": False,
    },
    {
        "id": "proc.schtasks_suspicious",
        "severity": "HIGH",
        "title": "计划任务指向可疑位置",
        "patterns": [
            r"schtasks(\.exe)?[^\n]{0,240}(/create|/change)[^\n]{0,240}(powershell|mshta|wscript|cscript|appdata|\\temp\\|downloads|https?://)",
        ],
        "ai_eligible": True,
    },
    {
        "id": "proc.net_user_add",
        "severity": "MEDIUM",
        "title": "创建本地用户或修改管理员组",
        "patterns": [r"net(\.exe)?\s+(user|localgroup)[^\n]{0,200}(\s/add\b|administrators)"],
        "ai_eligible": True,
    },
    {
        "id": "proc.shadow_delete",
        "severity": "HIGH",
        "title": "删除卷影副本/备份（勒索软件前置行为）",
        "patterns": [
            r"vssadmin(\.exe)?[^\n]{0,160}delete[^\n]{0,60}shadows?",
            r"wbadmin(\.exe)?[^\n]{0,200}delete[^\n]{0,80}(catalog|backup)",
            r"cipher(\.exe)?\s+/w",
            r"vssadmin(\.exe)?[^\n]{0,80}resize[^\n]{0,40}shadowstorage",
        ],
        "ai_eligible": True,
    },
    {
        "id": "proc.wevtutil_clear",
        "severity": "HIGH",
        "title": "清空事件日志（反取证）",
        "patterns": [r"wevtutil(\.exe)?[^\n]{0,80}(cl\b|clear-log)"],
        "ai_eligible": True,
    },
    {
        "id": "proc.defender_disable",
        "severity": "HIGH",
        "title": "尝试关闭 Windows Defender 防护",
        "patterns": [
            r"set-mppreference[^\n]{0,240}(disablerealtimemonitoring|disableioavprotection|disablebehaviormonitoring|disablescanning)",
            r"reg(\.exe)?\s+add[^\n]{0,160}(disablerealtimemonitoring|disableantispyware)",
        ],
        "ai_eligible": True,
    },
    {
        "id": "proc.defender_exclusion",
        "severity": "HIGH",
        "title": "尝试添加 Defender 排除项",
        "patterns": [r"add-mppreference[^\n]{0,160}-exclusion(path|extension|process)"],
        "ai_eligible": True,
    },
    {
        "id": "proc.firewall_disable",
        "severity": "HIGH",
        "title": "尝试关闭 Windows 防火墙",
        "patterns": [
            r"netsh(\.exe)?[^\n]{0,160}advfirewall[^\n]{0,100}set[^\n]{0,30}state[^\n]{0,30}off",
            r"set-netfirewallprofile[^\n]{0,160}enabled[^\n]{0,30}false",
        ],
        "ai_eligible": True,
    },
    {
        "id": "proc.bcdedit_change",
        "severity": "MEDIUM",
        "title": "修改启动配置（可能关闭恢复项）",
        "patterns": [r"bcdedit(\.exe)?[^\n]{0,160}(/set|/delete|/setoption)"],
        "ai_eligible": True,
    },
    {
        "id": "proc.credential_access",
        "severity": "HIGH",
        "title": "疑似凭据窃取行为",
        "patterns": [
            r"mimikatz",
            r"sekurlsa",
            r"lsass[^\n]{0,100}(dump|comsvcs|procdump)",
            r"procdump[^\n]{0,120}lsass",
            r"ntds\.dit",
            r"reg(\.exe)?\s+save[^\n]{0,60}(sam|security|system)",
        ],
        "ai_eligible": True,
    },
    {
        "id": "proc.hacktool",
        "severity": "HIGH",
        "title": "已知黑客工具/后门进程",
        "patterns": [
            r"\b(mimikatz|meterpreter|cobaltstrike|ysoserial|psexec|nc\.exe|ncat|socat|chisel|frpc|ngrok|xmrig|minerd)\b",
        ],
        "ai_eligible": True,
    },
    {
        "id": "proc.remote_tool",
        "severity": "LOW",
        "title": "远程控制工具启动",
        "patterns": [r"(anydesk|teamviewer|rustdesk|ultraviewer|vncserver|winvnc|supremo|todesk)"],
        "ai_eligible": False,
    },
    {
        "id": "proc.uac_bypass",
        "severity": "MEDIUM",
        "title": "疑似 UAC 绕过组件启动",
        "patterns": [r"\b(fodhelper|computerdefaults|sdclt)(\.exe)?\b"],
        "ai_eligible": True,
    },
]

# 办公软件启动 shell/脚本宿主：钓鱼宏的典型行为
OFFICE_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
    "wps.exe", "et.exe", "wpp.exe", "acrord32.exe", "foxitreader.exe",
}
SHELL_CHILDREN = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "schtasks.exe", "certutil.exe",
}
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".hta", ".ps1", ".wsf", ".jar", ".msi", ".com",
}

# ---------------------------------------------------------------------------
# 网络规则：远端端口 -> 严重度（公网 / 内网）与说明
# ---------------------------------------------------------------------------
SUSPICIOUS_REMOTE_PORTS: dict[int, dict] = {
    4444: {"public": "HIGH", "private": "HIGH", "title": "常见反弹 Shell / C2 端口"},
    4445: {"public": "HIGH", "private": "HIGH", "title": "常见反弹 Shell / C2 端口"},
    1337: {"public": "HIGH", "private": "HIGH", "title": "常见后门端口"},
    31337: {"public": "HIGH", "private": "HIGH", "title": "常见后门端口（Back Orifice）"},
    6667: {"public": "MEDIUM", "private": "MEDIUM", "title": "IRC 端口（可能用于 C2）"},
    6697: {"public": "MEDIUM", "private": "MEDIUM", "title": "IRC over TLS 端口（可能用于 C2）"},
    9050: {"public": "MEDIUM", "private": "MEDIUM", "title": "Tor 代理端口"},
    9051: {"public": "MEDIUM", "private": "MEDIUM", "title": "Tor 控制端口"},
    9001: {"public": "MEDIUM", "private": "MEDIUM", "title": "Tor 中继端口"},
    1080: {"public": "MEDIUM", "private": "MEDIUM", "title": "SOCKS 代理端口"},
    3333: {"public": "MEDIUM", "private": "MEDIUM", "title": "常见挖矿池端口"},
    14444: {"public": "MEDIUM", "private": "MEDIUM", "title": "常见挖矿池端口"},
    45510: {"public": "MEDIUM", "private": "MEDIUM", "title": "常见挖矿池端口"},
    45700: {"public": "MEDIUM", "private": "MEDIUM", "title": "常见挖矿池端口"},
    23: {"public": "MEDIUM", "private": "MEDIUM", "title": "Telnet 端口（明文协议）"},
    2323: {"public": "MEDIUM", "private": "MEDIUM", "title": "Telnet 替代端口（明文协议）"},
    3389: {"public": "MEDIUM", "private": "MEDIUM", "title": "远程桌面（RDP）外连"},
    5985: {"public": "MEDIUM", "private": "MEDIUM", "title": "WinRM HTTP 外连"},
    5986: {"public": "MEDIUM", "private": "MEDIUM", "title": "WinRM HTTPS 外连"},
    445: {"public": "HIGH", "private": "MEDIUM", "title": "SMB 文件共享外连"},
    139: {"public": "HIGH", "private": "MEDIUM", "title": "NetBIOS 外连"},
    5900: {"public": "MEDIUM", "private": "MEDIUM", "title": "VNC 远程桌面端口"},
    5901: {"public": "MEDIUM", "private": "MEDIUM", "title": "VNC 远程桌面端口"},
    6379: {"public": "MEDIUM", "private": "LOW", "title": "Redis 端口外连"},
    27017: {"public": "MEDIUM", "private": "LOW", "title": "MongoDB 端口外连"},
    9200: {"public": "MEDIUM", "private": "LOW", "title": "Elasticsearch 端口外连"},
    2375: {"public": "MEDIUM", "private": "LOW", "title": "Docker 明文端口外连"},
    2376: {"public": "MEDIUM", "private": "LOW", "title": "Docker TLS 端口外连"},
    11211: {"public": "MEDIUM", "private": "LOW", "title": "Memcached 端口外连"},
    21: {"public": "MEDIUM", "private": "LOW", "title": "FTP 端口外连"},
}

# 监听在这类端口上且绑定到非回环地址 = 对外暴露风险
RISKY_LISTEN_PORTS: dict[int, dict] = {
    3389: {"severity": "HIGH", "title": "远程桌面（RDP）对非本机开放"},
    445: {"severity": "MEDIUM", "title": "SMB 文件共享监听在非本机地址"},
    139: {"severity": "MEDIUM", "title": "NetBIOS 监听在非本机地址"},
    5985: {"severity": "HIGH", "title": "WinRM HTTP 对非本机开放"},
    5986: {"severity": "HIGH", "title": "WinRM HTTPS 对非本机开放"},
    21: {"severity": "HIGH", "title": "FTP 服务对非本机开放"},
    23: {"severity": "HIGH", "title": "Telnet 服务对非本机开放"},
    5900: {"severity": "MEDIUM", "title": "VNC 服务对非本机开放"},
    5901: {"severity": "MEDIUM", "title": "VNC 服务对非本机开放"},
    1433: {"severity": "HIGH", "title": "SQL Server 对非本机开放"},
    3306: {"severity": "HIGH", "title": "MySQL 对非本机开放"},
    5432: {"severity": "HIGH", "title": "PostgreSQL 对非本机开放"},
    6379: {"severity": "HIGH", "title": "Redis 对非本机开放"},
    9200: {"severity": "HIGH", "title": "Elasticsearch 对非本机开放"},
    27017: {"severity": "HIGH", "title": "MongoDB 对非本机开放"},
    11211: {"severity": "HIGH", "title": "Memcached 对非本机开放"},
    2375: {"severity": "HIGH", "title": "Docker 对非本机开放"},
    2376: {"severity": "HIGH", "title": "Docker TLS 对非本机开放"},
}

# ---------------------------------------------------------------------------
# 持久化（自启动/计划任务/服务）规则
# ---------------------------------------------------------------------------
AUTORUN_SUSPICIOUS: list[dict] = [
    {
        "id": "persist.autorun_encoded",
        "severity": "HIGH",
        "title": "自启动命令包含编码/隐藏参数",
        "patterns": [r"(powershell|pwsh)[^\n]{0,200}(-enc|-encodedcommand|-w(indowstyle)?\s+hidden)"],
    },
    {
        "id": "persist.autorun_remote",
        "severity": "HIGH",
        "title": "自启动命令从网络加载内容",
        "patterns": [
            r"(mshta|regsvr32|rundll32|powershell|pwsh)[^\n]{0,220}(https?://|javascript:|vbscript:)",
        ],
    },
    {
        "id": "persist.autorun_temp",
        "severity": "HIGH",
        "title": "自启动命令指向临时/下载目录",
        "patterns": [r"(\\temp\\|\\downloads\\|appdata\\local\\temp|/tmp/)"],
    },
    {
        "id": "persist.autorun_script",
        "severity": "HIGH",
        "title": "自启动项使用脚本宿主执行",
        "patterns": [r"(wscript|cscript)(\.exe)?[^\n]{0,200}\.(vbs|js|wsf|jse)\b"],
    },
    {
        "id": "persist.autorun_encoded_blob",
        "severity": "HIGH",
        "title": "自启动命令包含长 Base64 串",
        "patterns": [r"[A-Za-z0-9+/]{120,}={0,2}"],
    },
    {
        "id": "persist.autorun_run_remote",
        "severity": "HIGH",
        "title": "自启动命令从网络下载执行",
        "patterns": [r"(certutil|bitsadmin|curl|wget)[^\n]{0,160}https?://"],
    },
]

STARTUP_DANGEROUS_EXT = {".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd", ".scr", ".ps1", ".hta", ".wsf", ".exe", ".pif"}
STARTUP_SUSPICIOUS_PATTERNS = [
    (r"(powershell|cmd|wscript|cscript|mshta)[^\n]{0,120}(-enc|http|temp)", "启动目录快捷方式指向可疑命令"),
]

# ---------------------------------------------------------------------------
# 事件日志规则： (日志名, EventID) -> 规则
# ---------------------------------------------------------------------------
EVENTLOG_RULES: dict[tuple[str, int], dict] = {
    ("System", 7045): {
        "id": "log.service_install",
        "severity": "MEDIUM",
        "title": "安装新服务",
        "detail": "系统日志出现服务安装事件，服务程序可能是持久化手段。",
    },
    ("System", 7040): {
        "id": "log.service_start_type",
        "severity": "LOW",
        "title": "服务启动类型被修改",
        "detail": "有服务的启动类型发生变化。",
    },
    ("System", 104): {
        "id": "log.system_log_cleared",
        "severity": "MEDIUM",
        "title": "系统日志被清除",
        "detail": "系统事件日志被清空，可能是反取证行为。",
    },
    ("System", 41): {
        "id": "log.unexpected_shutdown",
        "severity": "LOW",
        "title": "系统非正常关机",
        "detail": "上次系统未正常关机，可能由断电、蓝屏或强杀进程导致。",
    },
    ("System", 6008): {
        "id": "log.unexpected_shutdown_2",
        "severity": "LOW",
        "title": "系统意外关闭",
        "detail": "事件日志记录了意外的系统关闭。",
    },
    ("Security", 1102): {
        "id": "log.security_log_cleared",
        "severity": "HIGH",
        "title": "安全审计日志被清除",
        "detail": "安全日志被清空，通常是入侵者反取证行为。",
    },
    ("Security", 4720): {
        "id": "log.user_created",
        "severity": "MEDIUM",
        "title": "创建新的本地用户",
        "detail": "系统创建了一个新的本地账户。",
    },
    ("Security", 4728): {
        "id": "log.admin_group_add",
        "severity": "MEDIUM",
        "title": "账户加入全局管理员组",
        "detail": "有账户被加入全局管理员组。",
    },
    ("Security", 4732): {
        "id": "log.local_admin_group_add",
        "severity": "MEDIUM",
        "title": "账户加入本地管理员组",
        "detail": "有账户被加入本地管理员组。",
    },
    ("Security", 4625): {
        "id": "log.failed_logon",
        "severity": "LOW",
        "title": "登录失败",
        "detail": "检测到一次登录失败。",
    },
    ("Microsoft-Windows-Windows Defender/Operational", 1116): {
        "id": "defender.malware_detected",
        "severity": "HIGH",
        "title": "Windows Defender 检测到恶意软件",
        "detail": "Defender 报告检测到威胁，请立即查看 Windows 安全中心。",
    },
    ("Microsoft-Windows-Windows Defender/Operational", 1117): {
        "id": "defender.malware_action",
        "severity": "MEDIUM",
        "title": "Windows Defender 已处置威胁",
        "detail": "Defender 对检测到的威胁执行了处置动作。",
    },
    ("Microsoft-Windows-Windows Defender/Operational", 5001): {
        "id": "defender.realtime_disabled_event",
        "severity": "HIGH",
        "title": "Windows Defender 实时保护被关闭",
        "detail": "事件日志记录了实时保护被关闭，可能是人为或恶意操作。",
    },
    ("Microsoft-Windows-Windows Defender/Operational", 5010): {
        "id": "defender.scanning_disabled_event",
        "severity": "HIGH",
        "title": "Windows Defender 扫描功能被关闭",
        "detail": "事件日志记录了扫描功能被关闭。",
    },
    ("Microsoft-Windows-Windows Defender/Operational", 5007): {
        "id": "defender.config_changed",
        "severity": "MEDIUM",
        "title": "Windows Defender 配置被修改",
        "detail": "Defender 配置发生变更，建议确认是否为本人操作。",
    },
}

# 系统服务安装事件里出现这些字样时提升为 HIGH
SERVICE_EVENT_SUSPICIOUS = [
    (r"(\\temp\\|\\downloads\\|appdata\\local\\temp)", "服务程序位于临时目录"),
    (r"(powershell|mshta|cmd(\.exe)?\s+/c|netsh|rundll32)", "服务程序使用脚本宿主或危险命令"),
]

# ---------------------------------------------------------------------------
# 安全配置暴露检查
# ---------------------------------------------------------------------------
EXPOSURE_CHECKS: dict[str, dict] = {
    "exposure.rdp_enabled": {
        "severity": "MEDIUM",
        "title": "远程桌面（RDP）已开启",
        "detail": "RDP 已启用；如果不需要远程连接，建议在「设置 → 系统 → 远程桌面」中关闭。",
    },
    "exposure.smb1_enabled": {
        "severity": "MEDIUM",
        "title": "SMBv1 协议已启用",
        "detail": "SMBv1 是过时且有已知漏洞的协议（如勒索蠕虫），建议在 Windows 功能中停用。",
    },
    "exposure.uac_disabled": {
        "severity": "HIGH",
        "title": "用户账户控制（UAC）已关闭",
        "detail": "UAC 关闭会显著削弱系统权限隔离，建议重新开启。",
    },
    "exposure.secureboot_off": {
        "severity": "MEDIUM",
        "title": "Secure Boot 未开启",
        "detail": "安全启动未启用，引导层恶意软件更难被拦截；可在 BIOS/UEFI 中开启。",
    },
    "exposure.autoplay_enabled": {
        "severity": "LOW",
        "title": "自动播放已开启",
        "detail": "自动播放可能让 U 盘等可移动介质上的程序自动运行，建议关闭。",
    },
}

# ---------------------------------------------------------------------------
# 告警去重窗口（秒）
# ---------------------------------------------------------------------------
DEDUPE_WINDOW_DEFAULT = 600.0
DEDUPE_WINDOW_STATE = 21600.0  # 系统配置类状态，6 小时
DEDUPE_WINDOW_EXPOSURE = 43200.0  # 暴露面检查，12 小时
DEDUPE_WINDOW_LOG = 3600.0

# 进程类告警的冷却窗口按规则类型收敛
PROCESS_COOLDOWN = {
    "proc.schtasks_create": 1800.0,
    "proc.remote_tool": 3600.0,
    "proc.uac_bypass": 1800.0,
}

# 永远不要通过看板结束的进程（防止误杀关键系统组件）
PROTECTED_PROCESS_NAMES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe",
    "fontdrvhost.exe", "ctfmon.exe", "audiodg.exe", "spoolsv.exe", "taskhostw.exe",
    "sihost.exe", "searchhost.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "python.exe", "pythonw.exe",  # 哨兵自身是 python 进程
}
