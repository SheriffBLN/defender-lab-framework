Write-Host "🟦 Wypychanie zmian na GitHub (main)..."

Set-Location "$PSScriptRoot"

# Dodaj wszystko
git add .

# Commit ze znacznikiem czasu
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
git commit -m "Auto push: update from local at $timestamp"

# Push na główną gałąź
git push origin main

Write-Host "✅ Zmiany zostały wypchnięte na gałąź 'main'."
