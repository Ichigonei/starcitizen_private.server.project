# Star Citizen Server Launcher
# This script launches all main server components in separate PowerShell windows
# Only starts servers that are not already running

$servers = @(
    @{ Name = "Star Citizen gRPC Server (5678)"; Path = "sc_production_server_v13_final.py"; Port = 5678 },
    @{ Name = "Google APIs gRPC Server (443)"; Path = "google_apis_grpc_server_sync.py"; Port = 443 },
    @{ Name = "Google APIs HTTP Server (50052)"; Path = "google_apis_http_server.py"; Port = 50052 },
    @{ Name = "Dedicated Login Server (9000)"; Path = "dedicated_login_server.py"; Port = 9000 },
    @{ Name = "Diffusion Server (8001)"; Path = "diffusion_server.py"; Port = 8001 },
    @{ Name = "SSL MITM Proxy UI (8000)"; Path = "ssl_mitm_ui.py"; Port = 8000 }
)

function Test-PortInUse {
    param([int]$Port)
    try {
        $connection = New-Object System.Net.Sockets.TcpClient
        $connection.Connect("127.0.0.1", $Port)
        $connection.Close()
        return $true
    } catch {
        return $false
    }
}

function Get-ProcessByPythonScript {
    param([string]$ScriptName)
    $processes = Get-WmiObject Win32_Process | Where-Object { 
        $_.Name -eq "python.exe" -and $_.CommandLine -like "*$ScriptName*" 
    }
    return $processes
}

Write-Host "Star Citizen Server Launcher" -ForegroundColor Green
Write-Host "Checking server status..." -ForegroundColor Yellow

foreach ($server in $servers) {
    $title = $server.Name
    $script = Join-Path $PSScriptRoot $server.Path
    $port = $server.Port
    
    Write-Host ""
    Write-Host "Checking $title..." -ForegroundColor Cyan
    
    # Check if port is in use
    $portInUse = Test-PortInUse -Port $port
    
    # Check if specific Python script is running
    $scriptName = [System.IO.Path]::GetFileName($server.Path)
    $existingProcess = Get-ProcessByPythonScript -ScriptName $scriptName
    
    if ($portInUse -or $existingProcess) {
        if ($existingProcess) {
            $processId = $existingProcess[0].ProcessId
            Write-Host "$title is already running (PID: $processId)" -ForegroundColor Green
        } else {
            Write-Host "Port $port is in use (possibly by $title)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Starting $title..." -ForegroundColor Blue
        try {
            Start-Process powershell -ArgumentList "-NoExit", "-Command", "python `"$script`"" -WindowStyle Normal -WorkingDirectory $PSScriptRoot -Verb RunAs
            Start-Sleep -Seconds 2  # Give it time to start
            Write-Host "$title launched successfully" -ForegroundColor Green
        } catch {
            Write-Host "Failed to start $title : $_" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "Server status summary:" -ForegroundColor Green
foreach ($server in $servers) {
    $port = $server.Port
    $portInUse = Test-PortInUse -Port $port
    $status = if ($portInUse) { "Running" } else { "Not responding" }
    Write-Host "   Port $port ($($server.Name)): $status" -ForegroundColor $(if ($portInUse) { "Green" } else { "Red" })
}

Write-Host ""
Write-Host "All servers checked and launched as needed." -ForegroundColor Green
Write-Host "Tip: Run this script again to check status without starting duplicates." -ForegroundColor Cyan
