# PowerShell script to run Google APIs servers
# Run this script to start both HTTP and gRPC servers

Write-Host "🚀 Starting Google APIs Servers..." -ForegroundColor Green
Write-Host "📡 HTTP Server will run on: http://127.0.0.1:8080" -ForegroundColor Cyan
Write-Host "🔌 gRPC Server will run on: 127.0.0.1:50051" -ForegroundColor Cyan
Write-Host ""

# Check if Python is available
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Python not found. Please install Python 3.7+" -ForegroundColor Red
    exit 1
}

# Install requirements if needed
if (Test-Path "requirements_google_apis.txt") {
    Write-Host "📦 Installing requirements..." -ForegroundColor Yellow
    pip install -r requirements_google_apis.txt
}

# Start the servers
Write-Host "🔄 Starting servers..." -ForegroundColor Yellow
python run_google_apis_servers.py