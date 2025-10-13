# Install-IDS.ps1 - Windows IDS Installation Script

Write-Host "🚀 Windows IDS Installation" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Yellow

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ Please run PowerShell as Administrator!" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Running as Administrator" -ForegroundColor Green

# Install Python dependencies
Write-Host "`n📦 Installing Python dependencies..." -ForegroundColor Cyan

$packages = @(
    "psutil",
    "pywin32", 
    "pyyaml",
    "pillow",
    "watchdog",
    "scapy"
)

foreach ($package in $packages) {
    Write-Host "Installing $package..." -ForegroundColor Gray
    pip install $package
}

if (Test-Path "requirements.txt") {
    Write-Host "Installing from requirements.txt..." -ForegroundColor Cyan
    pip install -r requirements.txt
}

Write-Host "`n✅ Dependencies installed successfully!" -ForegroundColor Green
Write-Host "`n🎉 Installation complete! Run .\Start-IDS.ps1 to start the IDS" -ForegroundColor Green
