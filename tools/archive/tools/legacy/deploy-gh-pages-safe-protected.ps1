$frameworkPath = Get-Location
$pagesPath = Resolve-Path "$frameworkPath\..\defender-lab-pages"

Set-Location $pagesPath

if ((Get-Location).Path -notmatch "defender-lab-pages") {
    Write-Host "❌ ERROR: Not in gh-pages folder. Exiting." -ForegroundColor Red
    exit
}

Get-ChildItem -Path "." -Exclude ".git" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item "$frameworkPath\report\index.html" "." -Force
Copy-Item "$frameworkPath\alerts" "." -Recurse -Force
New-Item -Name ".nojekyll" -ItemType File -Force | Out-Null
git add .
git commit -m "Auto deploy: updated report and alerts"
git push origin gh-pages --force
Write-Host "✅ GitHub Pages updated successfully."
