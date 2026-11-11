@echo off
chcp 65001 >nul
setlocal EnableExtensions
cd /d "%~dp0.."

rem ============================================================
rem  WHX 哨兵 - 增强模式（管理员）启动
rem  通过 PowerShell Start-Process -Verb RunAs 触发一次 UAC，
rem  以管理员身份运行 pythonw sentinel.py --daemon，然后打开看板。
rem ============================================================

echo ============================================================
echo   WHX 哨兵 - 增强模式（管理员权限）
echo ============================================================
echo 管理员模式下额外获得这些能力：
echo   - 读取 Windows 安全日志（Security 事件日志）
echo   - 通过 Windows 防火墙封锁高危 IP
echo   - 调用 Defender 快速扫描 / 更新病毒库
echo   - 结束其他用户的进程
echo.
echo 稍后会弹出一次 UAC 确认框，请点「是」。
echo.

rem ---- 1) 查找 pythonw.exe ----
set "PYW="
where /q pythonw.exe
if not errorlevel 1 set "PYW=pythonw.exe"
if not defined PYW (
    for /f "usebackq delims=" %%P in (`where python.exe 2^>nul`) do (
        if not defined PYW if exist "%%~dpPpythonw.exe" set "PYW=%%~dpPpythonw.exe"
    )
)
if not defined PYW if exist "%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe" set "PYW=%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe"

set "PYEXE=%PYW%"
if not defined PYEXE (
    where /q python.exe
    if errorlevel 1 (
        echo [错误] 未找到 Python。请先安装 Python 3.12 并加入 PATH。
        pause
        exit /b 1
    )
    echo [提示] 未找到 pythonw.exe，将以管理员身份用 python.exe 启动，会保留一个控制台窗口。
    set "PYEXE=python.exe"
)

rem ---- 2) 以管理员身份启动（触发 UAC） ----
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath '%PYEXE%' -ArgumentList 'sentinel.py','--daemon' -WorkingDirectory '%CD%' -Verb RunAs -ErrorAction Stop; exit 0 } catch { Write-Host ('启动失败：' + $_.Exception.Message); exit 1 }"
if errorlevel 1 (
    echo.
    echo 已取消 UAC 或启动失败，哨兵未以增强模式启动。
    pause
    exit /b 1
)

echo.
echo 已请求管理员权限启动（如果 UAC 窗口还在等待，请先点「是」）...
echo 正在等待看板就绪（最多约 30 秒）...

rem ---- 3) 等待本机看板端口就绪，然后打开浏览器 ----
powershell -NoProfile -ExecutionPolicy Bypass -Command "$deadline=(Get-Date).AddSeconds(30); while((Get-Date) -lt $deadline){ try { $r=Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8765/api/health' -TimeoutSec 2; if($r.StatusCode -eq 200){ exit 0 } } catch {}; Start-Sleep -Milliseconds 500 }; exit 1"
if errorlevel 1 (
    echo [提示] 看板暂未响应：可能是 UAC 尚未确认，或 8765 端口被占用。
    echo        确认后可直接访问 http://127.0.0.1:8765/
)

start "" "http://127.0.0.1:8765/"
echo.
echo 增强模式看板地址：http://127.0.0.1:8765/
echo 停止哨兵：install\stop_sentinel.bat
exit /b 0
