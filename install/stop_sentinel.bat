@echo off
chcp 65001 >nul
setlocal EnableExtensions
cd /d "%~dp0.."

rem ============================================================
rem  WHX 哨兵 - 停止正在运行的哨兵（优雅退出，失败时按 PID 兜底）
rem ============================================================

where /q python.exe
if errorlevel 1 (
    echo [错误] 未找到 python.exe，无法执行停止命令。
    pause
    exit /b 1
)

echo 正在停止 WHX 哨兵...
python sentinel.py --stop
set "RC=%errorlevel%"
echo.
if "%RC%"=="0" (
    echo 停止命令执行完毕。若看板仍可访问，请稍等几秒后刷新页面。
) else (
    echo 停止失败。请查看上方输出；也可以直接在任务管理器结束 pythonw.exe。
)
pause
exit /b %RC%
