@echo off
chcp 65001 >nul
setlocal EnableExtensions
cd /d "%~dp0.."
set "DATA_DIR=%CD%\data"

rem ============================================================
rem  WHX 哨兵 - 卸载
rem  只做两件事：停止哨兵 + 移除登录自启动。
rem  不会自动删除数据（事件库/配置/日志），需要时请手动删除。
rem ============================================================

echo ============================================================
echo   WHX 哨兵 - 卸载
echo ============================================================
echo 本脚本只做两件事：停止哨兵 + 移除登录自启动。
echo 不会自动删除数据，方便你保留历史告警记录。
echo.

where /q python.exe
if errorlevel 1 (
    echo [错误] 未找到 python.exe，无法停止哨兵与移除自启动。
    echo 数据目录：%DATA_DIR%
    echo 可以手动删除上面的 data 目录来彻底清除。
    pause
    exit /b 1
)

echo [1/2] 停止正在运行的哨兵...
python sentinel.py --stop
echo.
echo [2/2] 移除登录自启动...
python sentinel.py --uninstall-autostart
echo.
echo ------------------------------------------------------------
echo 数据目录：%DATA_DIR%
echo   如需彻底清除，请手动删除上述 data 目录。
echo   其中包含 sentinel.db 事件库、config.json 配置与 logs 日志。
echo ------------------------------------------------------------
pause
exit /b 0
