@echo off
cls

.paket\paket.bootstrapper.exe
if errorlevel 1 (
  exit /b %errorlevel%
)

.paket\paket.exe restore
if errorlevel 1 (
  exit /b %errorlevel%
)

if NOT EXIST .fake (
  dotnet tool install fake-cli --tool-path .fake --version 5.*
)

.fake\fake.exe run build.fsx %*