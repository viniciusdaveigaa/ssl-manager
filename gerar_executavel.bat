@echo off
cd /d "%~dp0"
echo Compilando versao otimizada do SSL Manager (SSLManager.exe)...
".\.venv\Scripts\pyinstaller.exe" --noconfirm SSLManager.spec
powershell -NoProfile -Command "if (Test-Path 'build\runtime.zip') { Remove-Item 'build\runtime.zip' -Force }; Compress-Archive -Path 'dist\SSLManager_runtime\*' -DestinationPath 'build\runtime.zip' -CompressionLevel Optimal"
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:winexe /optimize+ /win32icon:"assets\app_icon.ico" /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.IO.Compression.FileSystem.dll /r:System.IO.Compression.dll /resource:"build\runtime.zip,runtime.zip" /out:"dist\SSLManager.exe" launcher.cs
copy /y "dist\SSLManager.exe" "SSLManager.exe" >nul
del /q "build\runtime.zip" 2>nul
echo.
echo Concluido! Executavel unico gerado em SSLManager.exe
pause
