@echo off
chcp 65001 >nul
setlocal EnableExtensions
cd /d "%~dp0.."

rem ============================================================
rem  WHX 哨兵 - 移除当前用户登录自启动（不停止正在运行的哨兵）
rem ============================================================

where /q python.exe
if errorlevel 1 (
    echo [错误] 未找到 python.exe，无法移除自启动。
    pause
    exit /b 1
)

echo 正在移除 WHX 哨兵的登录自启动...
python sentinel.py --uninstall-autostart
set "RC=%errorlevel%"
echo.
if "%RC%"=="0" (
    echo 已移除自启动。下次登录 Windows 不会再自动启动哨兵。
) else (
    echo 移除失败，请看上方 JSON 输出中的 message 字段。
)
echo 提示：本操作不会停止当前正在运行的哨兵，停止请用 install\stop_sentinel.bat
pause
exit /b %RC%
