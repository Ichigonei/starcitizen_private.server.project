# Run Google APIs HTTPS server on port 443
# Note: May require administrator privileges for port 443

Write-Host "🚀 Starting Google APIs HTTPS Server on port 443..." -ForegroundColor Green
Write-Host "📡 Server: https://127.0.0.1:443" -ForegroundColor Cyan
Write-Host "🔧 Handles patched endpoints: iam, oauth2, traffic-director, directpath" -ForegroundColor Yellow
Write-Host ""

# Check for admin privileges (port 443 typically requires admin)
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "⚠️  Warning: Port 443 may require administrator privileges" -ForegroundColor Yellow
    Write-Host "   If connection fails, run PowerShell as Administrator" -ForegroundColor Yellow
    Write-Host ""
}

python googleapis_https_server.py