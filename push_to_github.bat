@echo off
chcp 65001 >nul
echo ========================================================
echo   Публикация репозитория ProxyDesk (9 коммитов) в GitHub
echo ========================================================
echo.
set /p REPO_URL="Введите URL пустого репозитория GitHub (например, https://github.com/username/proxydesk.git): "
if "%REPO_URL%"=="" (
    echo URL не указан. Выход.
    exit /b 1
)
git remote remove origin 2>nul
git remote add origin %REPO_URL%
git branch -M main
git push -u origin main
echo.
echo Готово! Перейдите во вкладку Actions вашего репозитория на GitHub —
echo workflow ci-windows.yml автоматически соберет proxydesk.exe для Windows x64.
pause
