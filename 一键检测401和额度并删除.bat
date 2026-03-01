@echo off
echo Detecting 401 invalid accounts and no-quota accounts...
python "%~dp0CliproxyAccountCleaner.py" --check-both --yes
echo Operation completed!
pause
