@echo off
chcp 65001 >nul
setlocal EnableExtensions
cd /d "%~dp0.."

rem ============================================================
rem  WHX 哨兵 - 注册当前用户登录自启动（HKCU Run，不需要管理员）
rem ============================================================

where /q python.exe
if errorlevel 1 (
    echo [错误] 未找到 python.exe，无法注册自启动。
    pause
    exit /b 1
)

echo 正在注册「登录 Windows 时自动启动 WHX 哨兵」...
echo 作用范围：当前用户  HKCU\Software\Microsoft\Windows\CurrentVersion\Run
echo 启动方式：pythonw sentinel.py --daemon（后台，无控制台窗口）
echo.
python sentinel.py --install-autostart
set "RC=%errorlevel%"
echo.
if "%RC%"=="0" (
    echo 自启动已配置完成。下次登录 Windows 后哨兵会在后台运行。
) else (
    echo 自启动配置失败，请看上方 JSON 输出中的 message 字段。
)
pause
exit /b %RC%
