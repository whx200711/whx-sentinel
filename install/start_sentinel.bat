@echo off
chcp 65001 >nul
setlocal EnableExtensions
cd /d "%~dp0.."

rem ============================================================
rem  WHX 哨兵 - 后台启动（pythonw，无控制台窗口）并打开看板
rem  项目根目录 = 本脚本所在目录的上一级
rem ============================================================

rem ---- 1) 查找 pythonw.exe：优先 PATH，其次 python.exe 同目录 ----
set "PYW="
where /q pythonw.exe
if not errorlevel 1 set "PYW=pythonw.exe"
if not defined PYW (
    for /f "usebackq delims=" %%P in (`where python.exe 2^>nul`) do (
        if not defined PYW if exist "%%~dpPpythonw.exe" set "PYW=%%~dpPpythonw.exe"
    )
)
if not defined PYW if exist "%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe" set "PYW=%LOCALAPPDATA%\Programs\Python\Python312\pythonw.exe"

if not defined PYW goto :fallback_python

echo.
echo 正在以 pythonw 后台启动 WHX 哨兵...
start "" "%PYW%" sentinel.py --daemon --open
echo.
echo 已在后台启动。看板地址：http://127.0.0.1:8765/
echo 首次启动会自动打开浏览器；若没有打开，请手动访问上面的地址。
echo 查看状态：python sentinel.py --status
echo 停止哨兵：install\stop_sentinel.bat
exit /b 0

:fallback_python
rem ---- 2) 没有 pythonw 时退回 python ----
where /q python.exe
if errorlevel 1 (
    echo.
    echo [错误] 未找到 Python。请先安装 Python 3.12，并在安装时勾选 "Add python.exe to PATH"。
    pause
    exit /b 1
)
echo.
echo [提示] 未找到 pythonw.exe，改用 python.exe 启动。
echo        这会保留一个控制台窗口，关闭该窗口即停止哨兵。
python sentinel.py --daemon --open
exit /b %errorlevel%
