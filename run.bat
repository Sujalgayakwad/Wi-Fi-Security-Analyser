@echo off
title NetGuard - Wi-Fi Cybersecurity Platform
color 0b
echo =====================================================================
echo          NETGUARD WI-FI CYBERSECURITY PLATFORM
echo =====================================================================
echo.
echo Starting NetGuard Server on http://127.0.0.1:5001 ...
echo Opening browser...
start http://127.0.0.1:5001
echo.

if exist "target\netguard-1.0.0.jar" (
    java -jar target\netguard-1.0.0.jar
) else if exist "mvnw.cmd" (
    call .\mvnw.cmd spring-boot:run
) else (
    mvn spring-boot:run
)
pause
