@echo off
REM ============================================================
REM  Source Recovery Tool - Windows Launcher
REM ============================================================
REM  Usage:
REM    run.bat <binary_path> [options]
REM
REM  Examples:
REM    run.bat libz.dll
REM    run.bat libz.dll --function adler32
REM    run.bat libz.dll --function adler32 --top-k 20
REM    run.bat --test-offline
REM    run.bat --test
REM ============================================================

setlocal

REM Check for test modes
if "%1"=="--test-offline" (
    echo [*] Running offline test...
    python "%~dp0test_pipeline.py" --offline --function adler32
    goto :end
)
if "%1"=="--test" (
    echo [*] Running full pipeline test...
    python "%~dp0test_pipeline.py" --function adler32 --top-k 10
    goto :end
)
if "%1"=="--unit-tests" (
    echo [*] Running unit tests...
    python -m pytest "%~dp0tests" -v
    goto :end
)

REM Validate arguments
if "%1"=="" (
    echo Usage: run.bat ^<binary_path^> [options]
    echo.
    echo Options:
    echo   --function NAME     Auto-select function by name
    echo   --top-k N           Number of GitHub candidates (default: 50)
    echo   --output FILE       Save JSON report to file
    echo   --ghidra-path DIR   Override Ghidra installation path
    echo.
    echo Quick modes:
    echo   --test-offline      Run offline feature extraction test
    echo   --test              Run full pipeline test with APIs
    echo   --unit-tests        Run unit tests
    goto :end
)

REM Run main pipeline
python "%~dp0main.py" --binary %*

:end
endlocal
