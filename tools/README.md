# Exiftool Setup

## Automatic Integration (Recommended)
The steganography module now uses the Python `exif` library by default for reading EXIF metadata. This provides direct integration without requiring external binaries.

**The `exif` library has been installed and is ready to use.**

## Optional: Full Exiftool Binary
For more comprehensive metadata extraction, you can optionally install the full Exiftool binary:

### Option 1: Automatic Download (Windows)
1. Double-click `setup_exiftool.bat`
2. Wait for the download to complete
3. The script will place `exiftool.exe` in this folder

### Option 2: Manual Download (Windows)
1. Download the Windows executable from: https://exiftool.org/
2. Look for `exiftool-XX.XX.zip` (where XX.XX is the version number)
3. Extract the zip file
4. Copy `exiftool(-k).exe` to this folder
5. Rename it to `exiftool.exe`

### Option 3: System Installation
- **Windows**: Install Exiftool and add it to your system PATH
- **macOS**: `brew install exiftool`
- **Linux**: `sudo apt-get install exiftool` (Ubuntu/Debian) or `sudo yum install perl-Image-ExifTool` (RHEL/CentOS)

## How It Works
The application checks for Exiftool in this order:
1. **Bundled** `exiftool.exe` in `tools/` folder (if present)
2. **System** `exiftool` command (if installed in PATH)
3. **Fallback** to Python `exif` library (always available)

The Python `exif` library provides comprehensive EXIF metadata for most use cases.
