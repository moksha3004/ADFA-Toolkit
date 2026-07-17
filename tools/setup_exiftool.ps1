# PowerShell script to download and setup Exiftool for Windows
# Run this script to download the standalone Exiftool executable

$toolsDir = $PSScriptRoot
$exiftoolUrl = "https://exiftool.org/exiftool-12.97.zip"
$zipPath = Join-Path $toolsDir "exiftool.zip"
$extractPath = Join-Path $toolsDir "exiftool"
$finalExePath = Join-Path $toolsDir "exiftool.exe"

Write-Host "Downloading Exiftool..." -ForegroundColor Green

try {
    # Download the zip file
    Invoke-WebRequest -Uri $exiftoolUrl -OutFile $zipPath -UseBasicParsing
    
    # Extract the zip
    Write-Host "Extracting..." -ForegroundColor Green
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
    
    # Find the exiftool.exe in the extracted folder (it has a versioned subfolder)
    $exeSource = Get-ChildItem -Path $extractPath -Recurse -Filter "exiftool.exe" | Select-Object -First 1
    
    if ($exeSource) {
        # Move exiftool.exe to the tools directory
        Copy-Item -Path $exeSource.FullName -Destination $finalExePath -Force
        Write-Host "Exiftool installed successfully at: $finalExePath" -ForegroundColor Green
    } else {
        Write-Error "Could not find exiftool.exe in the extracted archive"
    }
    
    # Cleanup
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
    
} catch {
    Write-Error "Failed to download or setup Exiftool: $_"
    Write-Host "You can manually download from: https://exiftool.org/" -ForegroundColor Yellow
    Write-Host "And place exiftool.exe in the tools folder" -ForegroundColor Yellow
}
