@echo off
echo Detecting 401 invalid accounts and no-quota accounts...
python "%~dp0enhanced_ui.py" --check-both --yes
echo Operation completed!
pause