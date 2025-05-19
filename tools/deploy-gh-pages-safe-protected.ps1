Write-Host "🟦 Deploying GitHub Pages..."

# Copy index.html
Copy-Item -Path "report\index.html" -Destination "../defender-lab-pages/index.html" -Force

# Replace '..' with '/defender-lab-framework'
(Get-Content "../defender-lab-pages/index.html") -replace '\.\.', '/defender-lab-framework' | Set-Content "../defender-lab-pages/index.html"

# Copy alerts
Copy-Item -Path "alerts" -Destination "../defender-lab-pages/" -Recurse -Force

# Commit and push
Set-Location "../defender-lab-pages"
git add index.html alerts
git commit -m "Auto deploy: updated report and alerts"
git push origin gh-pages
Set-Location "../defender-lab-framework"

Write-Host "✅ GitHub Pages updated successfully."
