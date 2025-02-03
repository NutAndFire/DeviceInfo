@echo off

REM Install .NET SDK
if not exist "%ProgramFiles%\dotnet\dotnet.exe" (
    echo Installing .NET SDK...
    start /wait "" "C:\Users\WDAGUtilityAccount\Downloads\dotnet-sdk-9.0.101-win-x64.exe" /quiet /norestart
    if %ERRORLEVEL% neq 0 (
        echo .NET SDK installation failed.
        exit /b 1
    )
)

REM Refresh PATH to include .NET CLI
set PATH=%PATH%;%ProgramFiles%\dotnet

REM Verify .NET installation
dotnet --version
if %ERRORLEVEL% neq 0 (
    echo .NET CLI is not available. Exiting...
    exit /b 1
)

REM Install WiX Toolset
echo Installing WiX Toolset...
dotnet tool install --global wix
if %ERRORLEVEL% neq 0 (
    echo WiX installation failed.
    exit /b 1
)

REM Refresh PATH to include .NET CLI
set PATH=%PATH%;C:\Users\WDAGUtilityAccount\.dotnet\tools

REM Verify WiX installation
wix --version
if %ERRORLEVEL% neq 0 (
    echo WiX verification failed.
    exit /b 1
)

REM Build .msi file
wix build C:\Users\WDAGUtilityAccount\Downloads\WDDeviceInfo.wxs -o C:\Users\WDAGUtilityAccount\Downloads\build\DeviceInfo.msi"
wix build C:\Users\WDAGUtilityAccount\Downloads\WDTPMStatus.wxs -o C:\Users\WDAGUtilityAccount\Downloads\build\TPMStatus.msi"


echo Installation completed successfully!
pause
shutdown -t 0 -s
