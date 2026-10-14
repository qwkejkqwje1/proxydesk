@echo off
chcp 65001 >nul
echo ====================================================================
echo   Обновление репозитория ProxyDesk (STABILIZATION-01) в GitHub
echo ====================================================================
echo.
where go >nul 2>nul
if %ERRORLEVEL%==0 (
    echo [1/3] Найден Go: формируем и проверяем подлинный go.sum через GOSUMDB...
    set GOSUMDB=sum.golang.org
    go mod tidy
    go mod verify
    git add go.mod go.sum 2>nul
    git diff --cached --quiet || git commit -m "build(deps): generate verified go.sum via GOSUMDB"
) else (
    echo [1/3] Локальный Go не найден — подлинный go.sum будет сформирован и проверен в GitHub Actions.
)

set DEFAULT_URL=https://github.com/qwkejkqwje1/proxydesk.git
set /p REPO_URL="Введите URL репозитория GitHub [Enter = %DEFAULT_URL%]: "
if "%REPO_URL%"=="" set REPO_URL=%DEFAULT_URL%

echo [2/3] Настраиваем remote origin: %REPO_URL%
git remote remove origin 2>nul
git remote add origin %REPO_URL%
git branch -M main

echo [3/3] Отправляем коммиты в GitHub...
git push -u origin main --force
echo.
echo Готово! Откройте https://github.com/qwkejkqwje1/proxydesk/actions —
echo workflow Windows x64 Build and Verification соберет и протестирует proxydesk.exe.
pause
