@echo off
REM Commit and push the detection-lab repo under your own git identity.
REM Double-click this file, or run it from a terminal in this folder.

cd /d "%~dp0"

echo ===============================================
echo  AD Detection Lab - commit ^& push
echo ===============================================
echo.

REM Show what changed
git status --short
echo.

REM Ask for a commit message (press Enter to use the default)
set "msg="
set /p "msg=Commit message (Enter for default): "
if "%msg%"=="" set "msg=Update detection rules, validation and docs"

git add -A
git commit -m "%msg%"
if errorlevel 1 (
  echo.
  echo Nothing to commit, or commit failed. See the message above.
  pause
  exit /b 1
)

git push
if errorlevel 1 (
  echo.
  echo Push failed. If this is the first push, run once:
  echo   git push -u origin main
  pause
  exit /b 1
)

echo.
echo Done. Pushed to GitHub as you.
pause
