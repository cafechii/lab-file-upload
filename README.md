# File Upload Vulnerabilities - 34 Labs

Private test environment for file upload vulnerabilities, with standard PortSwigger-style names and Burp Suite hints.

## Labs (34 scenarios, sorted numerically)

**Easy (01-07):**
- 01 Unrestricted File Upload
- 02 Client-Side Validation Bypass
- 03 Content-Type Bypass (MIME Spoofing)
- 04 Extension Blacklist Bypass
- 05 Case Sensitivity Bypass
- 06 File Overwrite
- 07 CSV Formula Injection

**Medium (08-17, 30-33):**
- 08 Double Extension Bypass
- 09 Null Byte Injection
- 10 Stored XSS via Filename
- 11 HTTP PUT Method Upload
- 12 SVG Stored XSS
- 13 SVG XXE
- 14 Zip Bomb
- 15 Remote URL SSRF
- 16 Document XXE (OOXML)
- 17 Windows ADS Bypass
- 30 Trailing Dot/Space Bypass
- 31 IIS Semicolon Bypass
- 32 SSI Injection (.shtml)
- 33 SVG SSRF (XLink)

**Hard (18-27, 28,29,34):**
- 18 .htaccess Override
- 19 Nested Extension Stripping
- 20 Magic Byte Bypass
- 21 Image Polyglot
- 22 Path Traversal via Filename
- 23 Race Condition (TOCTOU)
- 24 Zip Slip
- 25 Archive Symlink Read
- 26 ImageMagick Command Injection
- 27 uWSGI Config RCE
- 28 IIS web.config Override
- 29 .user.ini Auto-Prepend
- 34 FFmpeg HLS SSRF / LFI

All labs include Burp Suite step-by-step hints (Proxy > Intercept, Repeater Ctrl+R, Intruder, etc.) like PortSwigger.

## How to Run

```bash
php -S 0.0.0.0:8080 -t Labss/lab-file-upload/Labs router.php
# Open http://127.0.0.1:8080/menu/
```

## How to Push to GitHub (Fix "more than 100 files" error)

GitHub web UI (drag & drop) limits to 100 files per upload. This project has 161 files, so web upload fails.

**Use git CLI (no limit):**

```bash
cd Labss
chmod +x push_to_github.sh
./push_to_github.sh

# Or manually:
git init
git remote add origin https://github.com/YOUR_USERNAME/REPO.git
git add .
git commit -m "Initial commit: 34 labs"
git branch -M main
git push -u origin main
```

See `README_GITHUB_FA.md` for Persian guide.

## Isolation

Each lab is isolated - e.g., if extension bypass is intended, MIME bypass won't work on it, and vice versa. Tested via curl matrix.

## License

Private test environment by Mahan Karimi
