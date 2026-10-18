# PA BPA Dashboard installer for Windows.
#
# Install, or update to the latest release, by pasting this into PowerShell:
#
#   irm https://github.com/phmcgann/pa-bpa-public/releases/latest/download/install.ps1 | iex
#
# It needs Docker Desktop installed (see docs/INSTALL.md). It never asks questions.
# What it does:
#   1. Checks Docker is installed and running (starts Docker Desktop if it isn't).
#   2. Downloads this release's stack files into %USERPROFILE%\pa-bpa.
#   3. First install only: creates a random admin password and database password, and
#      writes them to %USERPROFILE%\pa-bpa\.env and pa-bpa-login.txt.
#   4. Downloads the images and starts the dashboard at http://localhost:8080.
#   5. Waits until it answers, then opens it in your browser.
# Running it again updates to the newest release and keeps your data and password.
#
# Optional settings (set before running, e.g. $env:PA_BPA_PORT = "9090"):
#   PA_BPA_VERSION   a specific release such as v1.2.0 (default: the latest)
#   PA_BPA_DIR       where to install (default: %USERPROFILE%\pa-bpa)
#   PA_BPA_PORT      the port on this computer (default: 8080; first install only)
#
# Works in Windows PowerShell 5.1 (built into Windows) and PowerShell 7.

function Install-PaBpa {
    $ErrorActionPreference = 'Stop'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is very slow with the progress bar on

    $Repo = 'phmcgann/pa-bpa-public'
    # $true in a build for a private copy of the repo: its images need a GitHub sign-in, and it carries
    # its own stack files (Write-StackFiles below), since its release page needs a sign-in too.
    $PrivateBuild = $false
    $GitHubApi = if ($env:PA_BPA_GITHUB_API) { $env:PA_BPA_GITHUB_API } else { 'https://api.github.com' }
    $Version = if ($env:PA_BPA_VERSION) { $env:PA_BPA_VERSION } else { 'latest' }
    $Dir = if ($env:PA_BPA_DIR) { $env:PA_BPA_DIR } else { Join-Path $env:USERPROFILE 'pa-bpa' }
    $Port = if ($env:PA_BPA_PORT) { [int]$env:PA_BPA_PORT } else { 8080 }
    $CaddyImage = 'caddy:2.10-alpine'
    if ($env:PA_BPA_BASE_URL) { $BaseUrl = $env:PA_BPA_BASE_URL }
    elseif ($Version -eq 'latest') { $BaseUrl = "https://github.com/$Repo/releases/latest/download" }
    else { $BaseUrl = "https://github.com/$Repo/releases/download/$Version" }

    function Step($t) { Write-Host ""; Write-Host "==> $t" -ForegroundColor Yellow }
    function Ok($t) { Write-Host "    [OK] $t" -ForegroundColor Green }
    function Stop-Install($t) { throw "Install stopped: $t" }
    # Runs docker without letting its progress messages (written to stderr) abort the script.
    function Invoke-Docker {
        $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $out = & docker @args 2>&1; $code = $LASTEXITCODE }
        finally { $ErrorActionPreference = $old }
        return [pscustomobject]@{ Code = $code; Output = ($out | ForEach-Object { "$_" }) -join "`n" }
    }
    function Test-PortBusy([int]$p) {
        $client = New-Object Net.Sockets.TcpClient
        try { $client.Connect('127.0.0.1', $p); return $true } catch { return $false } finally { $client.Close() }
    }
    function Get-Status([string]$url, [string]$auth) {
        $headers = @{}
        if ($auth) { $headers['Authorization'] = "Basic $auth" }
        try { return [int](Invoke-WebRequest -Uri $url -Headers $headers -UseBasicParsing -TimeoutSec 5).StatusCode }
        catch {
            if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
            return 0
        }
    }
    function New-Secret([int]$len) {
        $chars = [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        $bytes = New-Object byte[] ($len * 2)
        $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
        $rng.GetBytes($bytes); $rng.Dispose()
        $s = ''
        foreach ($b in $bytes) { if ($b -lt 248 -and $s.Length -lt $len) { $s += $chars[$b % 62] } }
        while ($s.Length -lt $len) { $s += New-Secret ($len - $s.Length) }
        return $s
    }
    # Plain UTF-8 without a byte-order mark and with Unix line endings: Docker reads these files.
    function Write-TextFile([string]$path, [string]$text) {
        [IO.File]::WriteAllText($path, ($text -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding $false))
    }
    # Writes this release's stack files into $Dir. Only a private build carries them (it replaces
    # this function); otherwise they're downloaded from the release page.
    function Write-StackFiles { return $false }
    # Signs Docker in to GitHub's container registry, which a private build's images need. Docker
    # remembers the sign-in, so later updates don't ask again.
    function Connect-Registry {
        $token = $env:PA_BPA_GITHUB_TOKEN
        if (-not $token) {
            Write-Host "    This release's images are private. Sign in with a GitHub token (classic) that has"
            Write-Host '    the read:packages scope. Create one at:'
            Write-Host '      https://github.com/settings/tokens/new?scopes=read:packages&description=PA%20BPA'
            $secure = Read-Host -AsSecureString '    Paste the token here (it stays hidden), then press Enter'
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            try { $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        }
        $token = "$token".Trim()
        if (-not $token) {
            Stop-Install "no GitHub token, so the images can't be downloaded. Run this again and paste the token when asked, or set `$env:PA_BPA_GITHUB_TOKEN."
        }
        $user = $null
        try { $user = (Invoke-RestMethod -Uri "$GitHubApi/user" -Headers @{ Authorization = "Bearer $token" } -UseBasicParsing -TimeoutSec 30).login }
        catch { }
        if (-not $user) { Stop-Install "GitHub didn't accept that token. Check it was copied whole and hasn't expired, then run this again." }
        $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $null = $token | & docker login ghcr.io --username $user --password-stdin 2>&1; $code = $LASTEXITCODE }
        finally { $ErrorActionPreference = $old }
        if ($code -ne 0) { Stop-Install "Docker couldn't sign in to ghcr.io as $user. Check the token has the read:packages scope, then run this again." }
        Ok "Signed in to GitHub's container registry as $user"
    }

    Step '1/5  Checking Docker'
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Stop-Install "Docker isn't installed. Install Docker Desktop first (docs/INSTALL.md, step 1), open it once, then run this command again."
    }
    if ((Invoke-Docker info).Code -ne 0) {
        # All-users installs live in Program Files; per-user installs (Docker's current default) under
        # LocalAppData. The docker CLI sits in <install>\resources\bin, so its location finds either.
        $candidates = @()
        if ($env:ProgramFiles) { $candidates += Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe' }
        if ($env:LOCALAPPDATA) {
            $candidates += Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe'
            $candidates += Join-Path $env:LOCALAPPDATA 'Programs\Docker\Docker\Docker Desktop.exe'
        }
        $cli = (Get-Command docker -ErrorAction SilentlyContinue).Source
        if ($cli) { $candidates += (Join-Path (Split-Path (Split-Path (Split-Path $cli))) 'Docker Desktop.exe') }
        $desktop = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
        if ($desktop) {
            Write-Host "    Docker Desktop isn't running. Starting it..."
            Start-Process $desktop
        }
        Write-Host -NoNewline '    Waiting for Docker to be ready (up to 3 minutes) '
        for ($i = 0; $i -lt 90; $i++) {
            if ((Invoke-Docker info).Code -eq 0) { break }
            Write-Host -NoNewline '.'; Start-Sleep -Seconds 2
        }
        Write-Host ''
        if ((Invoke-Docker info).Code -ne 0) {
            Stop-Install "Docker didn't become ready. Open Docker Desktop, wait until it says 'Engine running', then run this command again."
        }
    }
    if ((Invoke-Docker compose version).Code -ne 0) {
        Stop-Install "this Docker has no 'docker compose'. Update Docker Desktop to the latest version, then run this command again."
    }
    Ok ("Docker is running (" + (Invoke-Docker version --format '{{.Server.Version}}').Output + ")")

    Step '2/5  Downloading the release files'
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    Set-Location $Dir
    if (Write-StackFiles) { Ok "Saved this release's files to $Dir" }
    else {
        foreach ($f in 'docker-compose.yml', 'Caddyfile') {
            try { Invoke-WebRequest -Uri "$BaseUrl/$f" -OutFile "$f.download" -UseBasicParsing }
            catch { Stop-Install "couldn't download $f from $BaseUrl. Check your internet connection and that the release exists." }
            Move-Item -Force "$f.download" $f
        }
        Ok "Saved to $Dir"
    }

    $Fresh = $false
    $Password = ''
    Step '3/5  Settings'
    if (Test-Path '.env') {
        Ok 'Keeping your existing settings and password (.env)'
        $m = Select-String -Path '.env' -Pattern '^HTTP_BIND=.*:(\d+)$' | Select-Object -First 1
        $Port = if ($m) { [int]$m.Matches[0].Groups[1].Value } else { 8080 }
    }
    else {
        if ((Invoke-Docker volume inspect pa-bpa_db_data).Code -eq 0) {
            Stop-Install ("this computer still has the database from an earlier install, but its settings file ($Dir\.env) is missing, so a new password couldn't open it.`n" +
                "  - To keep your old assessments: put your old .env file back into $Dir, then run this command again.`n" +
                "  - To start over and ERASE the old assessments, run this, then run the install command again:`n" +
                "      docker volume rm pa-bpa_db_data pa-bpa_caddy_data pa-bpa_caddy_config")
        }
        $Fresh = $true
        if (Test-PortBusy $Port) {
            $orig = $Port
            foreach ($p in ($Port + 1)..($Port + 20)) { if (-not (Test-PortBusy $p)) { $Port = $p; break } }
            if ($Port -eq $orig) { Stop-Install "port $orig and the next 20 are in use. Set a free port first: `$env:PA_BPA_PORT = '9090'" }
            Write-Host "    Port $orig is already in use on this computer, so using $Port instead."
        }
        $Password = New-Secret 20
        $DbPassword = New-Secret 32
        Write-Host '    Creating the admin password hash (downloads a small helper image the first time)...'
        $h = Invoke-Docker run --rm $CaddyImage caddy hash-password --plaintext $Password
        $Hash = ($h.Output -split "`n" | Where-Object { $_ -like '$2*' } | Select-Object -Last 1)
        if ($h.Code -ne 0 -or -not $Hash) { Stop-Install "couldn't create the password hash: $($h.Output)" }
        $Hash = $Hash.Trim()
        $created = Get-Date -Format 'yyyy-MM-dd HH:mm'
        $httpsPort = $Port + 363
        Write-TextFile (Join-Path $Dir '.env') @"
# PA BPA Dashboard settings. Created by the installer on $created.
# Keep this file private: it holds the database password.

POSTGRES_USER=pabpa
POSTGRES_PASSWORD=$DbPassword
POSTGRES_DB=pabpa

# Where the dashboard listens. 127.0.0.1 means only this computer can open it.
HTTP_BIND=127.0.0.1:$Port
HTTPS_BIND=127.0.0.1:$httpsPort
SITE_ADDRESS=:80

# The login. The hash must stay in single quotes.
BASIC_AUTH_USER=admin
BASIC_AUTH_HASH='$Hash'

# Optional: Palo Alto Strata Cloud Manager BPA (docs/INSTALL.md, "Optional settings").
SCM_CLIENT_ID=
SCM_CLIENT_SECRET=
SCM_TSG_ID=

# PAN-OS security advisories feed. Set to off if this computer has no internet access.
PAN_ADVISORY_FEED=on
"@
        Write-TextFile (Join-Path $Dir 'pa-bpa-login.txt') @"
PA BPA Dashboard login
Address:  http://localhost:$Port
Username: admin
Password: $Password
"@
        Ok "Created a random admin password (saved in $Dir\pa-bpa-login.txt)"
    }

    Step '4/5  Downloading and starting the dashboard (the first time takes a few minutes)'
    if ($env:PA_BPA_SKIP_PULL -ne '1') {
        $hint = 'Check your internet connection'
        if ($PrivateBuild) {
            $hint += ", and that your GitHub account has access to $Repo"
            # Sign in when there's a token to use, or when the images won't download without one.
            if ($env:PA_BPA_GITHUB_TOKEN -or (Invoke-Docker compose pull --quiet).Code -ne 0) { Connect-Registry }
        }
        $r = Invoke-Docker compose pull --quiet
        if ($r.Code -ne 0) { Stop-Install "couldn't download the images. $hint, then run this command again.`n$($r.Output)" }
    }
    $r = Invoke-Docker compose up -d --remove-orphans
    if ($r.Code -ne 0) { Stop-Install "the dashboard didn't start. Run 'docker compose logs' in $Dir to see why.`n$($r.Output)" }
    Ok 'Containers started'

    Step '5/5  Waiting for the dashboard to answer'
    $Url = "http://localhost:$Port"
    $code = 0
    for ($i = 0; $i -lt 90; $i++) {
        $code = Get-Status "http://127.0.0.1:$Port/health" ''
        if ($code -eq 401 -or $code -eq 200) { break }
        Start-Sleep -Seconds 2
    }
    if ($code -ne 401 -and $code -ne 200) {
        Stop-Install "the dashboard didn't answer at $Url after 3 minutes. Run 'docker compose ps' and 'docker compose logs' in $Dir to see why."
    }
    $login = Join-Path $Dir 'pa-bpa-login.txt'
    if (Test-Path $login) {
        $pw = ((Get-Content $login | Where-Object { $_ -like 'Password: *' }) -replace '^Password: ', '')
        $auth = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("admin:$pw"))
        try {
            $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -Headers @{ Authorization = "Basic $auth" } -TimeoutSec 5
            if ($health.version) { Ok "Running version $($health.version)" }
        } catch { }
    }
    Ok "The dashboard is up at $Url"

    if ($env:PA_BPA_NO_BROWSER -ne '1') { try { Start-Process $Url } catch { } }

    Write-Host ''
    Write-Host "PA BPA Dashboard is ready: $Url" -ForegroundColor Cyan
    if ($Fresh) {
        Write-Host ''
        Write-Host 'Log in with:' -ForegroundColor Cyan
        Write-Host '    Username: admin'
        Write-Host "    Password: $Password"
        Write-Host "    (also saved in $Dir\pa-bpa-login.txt)"
    }
    Write-Host ''
    Write-Host 'To update later, run the same install command again. Your data and password are kept.'
    Write-Host "To stop it:   cd `"$Dir`"; docker compose stop"
    Write-Host "To start it:  cd `"$Dir`"; docker compose start"
}

Push-Location
try { Install-PaBpa }
catch { Write-Host ''; Write-Host $_.Exception.Message -ForegroundColor Red }
finally { Pop-Location }
