# Supply Chain Triage CLI (SCT) v2.0 - Windows PowerShell 5.1+
# Mini Shai-Hulud Edition  .  TeamPCP  .  CVE-2026-45321
#
# Interactive:  .\sct.ps1
# Direct CLI:   .\sct.ps1 <command> [flags]
# Help:         .\sct.ps1 -Help

param(
    [Parameter(Position=0)][string]$Command = '',
    [string[]]$ExtraIOCs           = @(),
    [string[]]$ExtraSecretPatterns = @(),
    [string[]]$ExtraPackages       = @(),
    [string[]]$Dirs                = @(),
    [string]  $Output              = '',
    [switch]  $AutoOutput,
    [switch]  $Quiet,
    [switch]  $Help
)

$SCT_VERSION = '2.0.0'
$SCT_DATE    = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:TotalFindings = 0
$script:TotalWarns = 0
$script:ModuleResults = @{}

# ---- COLOUR HELPERS ---------------------------------------------------------
function WarnMsg  { param([string]$m) Write-Host ('[!]    ' + $m) -ForegroundColor Red;    $script:TotalFindings++; $script:TotalWarns++ }
function CritMsg  { param([string]$m) Write-Host ('[CRIT] ' + $m) -ForegroundColor Red;    $script:TotalFindings++ }
function InfoMsg  { param([string]$m) Write-Host ('[?]    ' + $m) -ForegroundColor Yellow }
function OkMsg    { param([string]$m) Write-Host ('[OK]   ' + $m) -ForegroundColor Green }
function SkipMsg  { param([string]$m) Write-Host ('[--]   ' + $m) -ForegroundColor DarkGray }
function Section  { param([string]$m) Write-Host ''; Write-Host ('+- ' + $m) -ForegroundColor Cyan }
function SubHead  { param([string]$m) Write-Host ('|  ' + $m) -ForegroundColor Cyan }
function HR { Write-Host ('-' * 60) -ForegroundColor DarkGray }

function Redact { param([string]$line) $line -replace '(?i)([:=]\s*[''"]?)\S{8,}', '$1***REDACTED***' }

# ---- PATH EXPANSION (define early) ------------------------------------------
function ExpandPathLocal {
    param([string]$path)
    if ($path -eq '~') {
        return $env:USERPROFILE
    } elseif ($path -like '~/*' -or $path -like '~\*') {
        return $path -replace '^~', $env:USERPROFILE
    }
    return $path
}

# ---- DEFAULTS ---------------------------------------------------------------
$DefaultIOCs = @(
    'zero.masscan.cloud', '94.154.172.43', 'masscan.cloud', 'beautifulcastle'
)

# All patterns are single-quoted to prevent PS escape/expansion issues.
# Inside single-quoted strings, '' = literal single quote.
$DefaultSecretPatterns = @(
    '-----BEGIN (RSA|EC|DSA|PGP|OPENSSH|PRIVATE) KEY'
    'AKIA[0-9A-Z]{16}'
    'aws[_.\-]?(access[_.\-]?key|secret[_.\-]?key|session[_.\-]?token)\s*[:=]\s*\S{20,}'
    'AccountKey=[A-Za-z0-9+/]{88}=='
    'DefaultEndpointsProtocol=https;AccountName='
    'client[_.\-]?secret\s*[:=]\s*\S{16,}'
    'AIza[0-9A-Za-z_\-]{35}'
    'ya29\.[0-9A-Za-z_\-]{20,}'
    'ghp_[A-Za-z0-9]{36}'
    'ghs_[A-Za-z0-9]{36}'
    'gho_[A-Za-z0-9]{36}'
    'ghu_[A-Za-z0-9]{36}'
    'github_pat_[A-Za-z0-9_]{82}'
    'npm_[A-Za-z0-9]{36}'
    'sk_live_[0-9a-zA-Z]{24}'
    'rk_live_[0-9a-zA-Z]{24}'
    'sk_(live|test)_[A-Za-z0-9]{32,}'
    'FLWSECK[_\-]?(TEST|PROD)'
    'FLW(PUB|SEC)K?[_\-]'
    'SK[0-9a-fA-F]{32}'
    'AC[0-9a-fA-F]{32}'
    'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'
    'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'
    '(postgres|postgresql|mysql|mongodb|redis|mssql|sqlserver|cockroach)://\S{10,}'
    '(password|passwd|pwd)\s*[:=]\s*\S{6,}'
    '(api[_\-]?key|apikey)\s*[:=]\s*\S{10,}'
    '(secret[_\-]?key|secretkey|client[_\-]?secret)\s*[:=]\s*\S{10,}'
    '(token|auth[_\-]?token|access[_\-]?token|refresh[_\-]?token|bearer)\s*[:=]\s*\S{10,}'
    '(private[_\-]?key|signing[_\-]?key)\s*[:=]\s*\S{10,}'
    '^(SECRET|TOKEN|API_KEY|PASSWORD|CREDENTIAL|PRIVATE_KEY|DB_PASS(WORD)?|AUTH_SECRET|ENCRYPTION_KEY|SIGNING_KEY|SERVICE_ACCOUNT)\s*=\s*\S{8,}'
)

$DefaultPackages = @(
    '@cap-js/sqlite','@cap-js/hana','@cap-js/cds-dbs','intercom-client'
    '@tanstack/react-router','@tanstack/react-query','@tanstack/react-table'
    '@tanstack/react-virtual','@tanstack/router','@tanstack/query-core'
    '@tanstack/store','@tanstack/react-form','@tanstack/router-devtools'
    '@tanstack/query-devtools','@tanstack/start'
    '@mistralai/mistralai','@uipath/scripting'
    '@antv/g2','@antv/g6','@antv/x6','@antv/l7','@antv/s2','@antv/f2'
    '@antv/g','@antv/g2plot','@antv/graphin','@antv/data-set'
    '@antv/hierarchy','@antv/event-emitter','@antv/matrix-util'
    'echarts-for-react','timeago.js','size-sensor','canvas-nest.js','g2plot'
)

# ---- RESOLVED AT RUNTIME ----------------------------------------------------
$script:AllIOCs    = @()
$script:AllSecrets = @()
$script:AllPkgs    = @()
$script:ScanDirs   = @()
$script:IOCPattern    = ''
$script:SecretPattern = ''

function Build-Patterns {
    $script:AllIOCs    = @($DefaultIOCs)    + @($ExtraIOCs)            | Select-Object -Unique
    $script:AllSecrets = @($DefaultSecretPatterns) + @($ExtraSecretPatterns) | Select-Object -Unique
    $script:AllPkgs    = @($DefaultPackages) + @($ExtraPackages)       | Select-Object -Unique
    $script:IOCPattern    = (($script:AllIOCs | ForEach-Object { [regex]::Escape($_) }) -join '|')
    $script:SecretPattern = ($script:AllSecrets -join '|')

    if ($Dirs.Count -gt 0)                { $script:ScanDirs = $Dirs }
    elseif ($script:ScanDirs.Count -eq 0) { $script:ScanDirs = @('.') }
    # else: keep what Collect-Params already populated interactively
}

# ---- BANNER -----------------------------------------------------------------
function Show-Banner {
    Write-Host ''
    Write-Host '+================================================================+' -ForegroundColor Cyan
    Write-Host ('|  Supply Chain Triage CLI  (SCT)  v' + $SCT_VERSION + ' (Windows)           |') -ForegroundColor Cyan
    Write-Host '|  Mini Shai-Hulud Edition  .  TeamPCP  .  CVE-2026-45321       |' -ForegroundColor Cyan
    Write-Host '+================================================================+' -ForegroundColor Cyan
    Write-Host ('  Host: ' + $env:COMPUTERNAME + '  .  User: ' + $env:USERNAME + '  .  ' + (Get-Date -Format u))
    Write-Host ''
}

# ---- HELP -------------------------------------------------------------------
function Show-Help {
    Show-Banner
    Write-Host 'USAGE'
    Write-Host '  .\sct.ps1                            Launch interactive menu'
    Write-Host '  .\sct.ps1 <command> [flags]          Run command directly'
    Write-Host ''
    Write-Host 'COMMANDS'
    Write-Host '  all          Full triage: machine + deps'
    Write-Host '  machine      IOCs, secrets, shell history, git history'
    Write-Host '  deps         Dependency audit (8 ecosystems)'
    Write-Host '  ide          VS Code extension audit checklist'
    Write-Host '  platform     ADO / GitHub platform audit guidance'
    Write-Host '  harden       Print hardening configs'
    Write-Host ''
    Write-Host 'FLAGS'
    Write-Host '  -ExtraIOCs            "evil.com","1.2.3.4"'
    Write-Host '  -ExtraSecretPatterns  "CORP_KEY","MYTOKEN"'
    Write-Host '  -ExtraPackages        "my-lib","other-pkg"'
    Write-Host '  -Dirs                 "C:\repo1","C:\repo2"'
    Write-Host '  -Output               "C:\report.txt"'
    Write-Host '  -AutoOutput           Auto-name output file'
    Write-Host '  -Quiet                No colors'
    Write-Host '  -Help                 Show this help'
    Write-Host ''
    Write-Host 'EXAMPLES'
    Write-Host '  .\sct.ps1 all -Dirs "C:\repos\app1","C:\repos\app2"'
    Write-Host '  .\sct.ps1 machine -ExtraIOCs "evil.io","203.0.113.5"'
    Write-Host '  .\sct.ps1 deps -ExtraPackages "my-lib" -Dirs "C:\project" -AutoOutput'
    Write-Host ''
}

# ---- INTERACTIVE PARAM COLLECTION -------------------------------------------
function Collect-Params {
    param([string]$Scope)

    Write-Host ''
    Write-Host 'Configure scan (press Enter to accept defaults):' -ForegroundColor White

    if ($Scope -eq 'machine' -or $Scope -eq 'all') {
        Write-Host ('  Default IOCs: ' + ($DefaultIOCs -join ', ')) -ForegroundColor DarkGray
        $v = Read-Host '  Extra IOC domain/IP (or Enter to skip)'
        while ($v) {
            $script:ExtraIOCs += $v
            $v = Read-Host '  Another IOC (or Enter to stop)'
        }

        $v = Read-Host '  Extra secret pattern regex (or Enter to skip)'
        while ($v) {
            $script:ExtraSecretPatterns += $v
            $v = Read-Host '  Another pattern (or Enter to stop)'
        }
    }

    if ($Scope -eq 'deps' -or $Scope -eq 'all') {
        $v = Read-Host '  Extra package to scan for (or Enter to skip)'
        while ($v) {
            $script:ExtraPackages += $v
            $v = Read-Host '  Another package (or Enter to stop)'
        }

        Write-Host '  Project directories to scan (default: current dir):' -ForegroundColor DarkGray
        $v = Read-Host '  Add directory path (or Enter to skip)'
        if ($v) {
            $script:ScanDirs = @($v)
            $vNext = Read-Host '  Another directory (or Enter to stop)'
            while ($vNext) {
                $script:ScanDirs += $vNext
                $vNext = Read-Host '  Another directory (or Enter to stop)'
            }
        }
    }

    $v = Read-Host '  Save report to file? [y/N]'
    if ($v -ieq 'y') {
        $defaultName = 'sct-report-' + $env:COMPUTERNAME + '-' + $SCT_DATE + '.txt'
        $fname = Read-Host ('  Filename [' + $defaultName + ']')
        if ($fname) { $script:OutputFile = $fname } else { $script:OutputFile = $defaultName }
    }

    Build-Patterns
}

# ==== MODULE: MACHINE SCAN ===================================================
function Invoke-MachineScan {
    Section 'Machine Scan'
    Write-Host ('  IOCs: ' + $script:AllIOCs.Count + '  .  Secret patterns: ' + $script:AllSecrets.Count)

    $startFindings = $script:TotalFindings

    # 1. Network connections
    SubHead '1/6  Network connections'
    foreach ($ioc in $script:AllIOCs) {
        $hit = netstat -ano 2>$null | Select-String -Pattern $ioc -SimpleMatch
        if ($hit) { CritMsg ('ACTIVE CONNECTION: ' + $ioc) }
        else      { OkMsg  ('No connection: ' + $ioc) }
    }

    # 2. Hosts + DNS
    SubHead '2/6  Hosts file and DNS'
    $hostsPath = $env:SystemRoot + '\System32\drivers\etc\hosts'
    $suspicious = Get-Content $hostsPath -ErrorAction SilentlyContinue |
        Where-Object { $_ -notmatch '^#|^$|127\.0\.0\.1|::1|0\.0\.0\.0' }
    if ($suspicious) { InfoMsg 'Non-standard hosts entries:'; $suspicious | ForEach-Object { Write-Host ('    ' + $_) } }
    else             { OkMsg 'hosts file clean' }

    foreach ($ioc in $script:AllIOCs) {
        try {
            $r = [System.Net.Dns]::GetHostAddresses($ioc)
            InfoMsg ('IOC resolves: ' + $ioc + ' => ' + ($r.IPAddressToString -join ','))
        } catch {}
    }

    # 3. PowerShell history
    SubHead '3/6  PowerShell history'
    $histPath = $null
    try { $histPath = (Get-PSReadLineOption -ErrorAction SilentlyContinue).HistorySavePath } catch {}
    if ($histPath -and (Test-Path $histPath)) {
        $hits = Select-String -Path $histPath -Pattern $script:IOCPattern -AllMatches -ErrorAction SilentlyContinue
        if ($hits) {
            WarnMsg 'IOC in PS history:'
            $hits | Select-Object -First 10 | ForEach-Object { Write-Host ('  Line ' + $_.LineNumber + ': ' + $_.Line) }
        }
        else { OkMsg 'PowerShell history clean' }
    } else { SkipMsg 'PSReadLine history not found' }
    
    # Also check command history if available (skip if Get-PSReadLineOption already pointed at the same file)
    $cmdHistPath = $env:APPDATA + '\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt'
    if ((Test-Path $cmdHistPath) -and ($cmdHistPath -ne $histPath)) {
        $hits = Select-String -Path $cmdHistPath -Pattern $script:IOCPattern -AllMatches -ErrorAction SilentlyContinue
        if ($hits) {
            WarnMsg 'IOC in command history:'
            $hits | Select-Object -First 5 | ForEach-Object { Write-Host ('  ' + $_.Line) }
        }
    }

    # 4. Environment + credential files
    SubHead '4/6  Environment variables and credential files'
    $envScopes = @{
        Process = [System.Environment]::GetEnvironmentVariables('Process')
        User    = [System.Environment]::GetEnvironmentVariables('User')
    }
    try { $envScopes['Machine'] = [System.Environment]::GetEnvironmentVariables('Machine') } catch {}
    $envAnyHit = $false
    foreach ($scope in $envScopes.Keys) {
        $hits = $envScopes[$scope].GetEnumerator() |
            Where-Object { ($_.Key + '=' + $_.Value) -imatch $script:SecretPattern }
        if ($hits) {
            $envAnyHit = $true
            InfoMsg ('Secret patterns in ' + $scope + ' environment (redacted):')
            $hits | Select-Object -First 10 | ForEach-Object { Write-Host ('  [' + $scope + '] ' + $_.Key + ' = ***REDACTED***') }
        }
    }
    if (-not $envAnyHit) { OkMsg 'No secret patterns in environment' }

    $credFiles = @(
        ($env:USERPROFILE + '\.env'),
        ($env:USERPROFILE + '\.env.local'),
        ($env:USERPROFILE + '\.env.development'),
        ($env:USERPROFILE + '\.env.production'),
        ($env:USERPROFILE + '\.env.staging'),
        ($env:USERPROFILE + '\.netrc'),
        ($env:USERPROFILE + '\.npmrc'),
        ($env:USERPROFILE + '\.yarnrc'),
        ($env:USERPROFILE + '\.yarnrc.yml'),
        ($env:USERPROFILE + '\.aws\credentials'),
        ($env:USERPROFILE + '\.aws\config'),
        ($env:USERPROFILE + '\.azure\accessTokens.json'),
        ($env:USERPROFILE + '\.azure\credentials'),
        ($env:USERPROFILE + '\.azure\config'),
        ($env:USERPROFILE + '\.azure\msal_token_cache.json'),
        ($env:USERPROFILE + '\.docker\config.json'),
        ($env:USERPROFILE + '\.git-credentials'),
        ($env:LOCALAPPDATA + '\Git\Credentials'),
        ($env:USERPROFILE + '\.config\gh\hosts.yml'),
        ($env:APPDATA + '\GitHub CLI\hosts.yml'),
        ($env:USERPROFILE + '\.config\gcloud\application_default_credentials.json'),
        ($env:USERPROFILE + '\.config\gcloud\credentials.db'),
        ($env:APPDATA + '\npm\etc\npmrc')
    )
    foreach ($f in $credFiles) {
        if (Test-Path $f) {
            $hits = Select-String -Path $f -Pattern $script:SecretPattern -AllMatches -ErrorAction SilentlyContinue
            if ($hits) {
                WarnMsg ('Secret in ' + $f + ' (redacted):')
                $hits | Select-Object -First 3 | ForEach-Object { Write-Host ('  ' + (Redact $_.Line)) }
            }
        }
    }

    # 5. Git history
    SubHead '5/6  Git history secret scan'
    $foundGitRepo = $false

    foreach ($scanDir in $script:ScanDirs) {
        $expandedDir = ExpandPathLocal $scanDir
        if (-not (Test-Path $expandedDir)) { InfoMsg ('Directory not found for git scan: ' + $expandedDir + ' (skipping)'); continue }

        $prevPwd = Get-Location
        try {
            Push-Location $expandedDir -ErrorAction Stop
        } catch {
            InfoMsg ('Cannot access directory: ' + $expandedDir + ' (skipping)')
            continue
        }
        
        $inGit = $false
        try {
            $testGit = & git rev-parse --is-inside-work-tree 2>$null
            $inGit = ($testGit -eq 'true')
        } catch {
            # git not available
        }
        
        if ($inGit) {
            $foundGitRepo = $true
            $repo = & git rev-parse --show-toplevel 2>$null
            if ($repo) {
                InfoMsg ('Repo: ' + (Split-Path -Leaf $repo) + ' - scanning since 2026-04-01...')
            } else {
                InfoMsg ('Git repo found in: ' + $expandedDir)
            }

            Write-Host '  Scanning commit history since 2026-04-01 (may take a moment)...' -ForegroundColor DarkGray
            Write-Host '  > git log --all --since=2026-04-01 -p --diff-filter=AMR' -ForegroundColor DarkGray
            $gitLines = git log --all --since='2026-04-01' -p --diff-filter=AMR 2>$null |
                Where-Object { $_ -match '^\+' -and $_ -notmatch '^\+\+\+' } |
                Where-Object { $_ -imatch $script:SecretPattern } |
                ForEach-Object { Redact $_ } |
                Sort-Object -Unique |
                Select-Object -First 20

            if ($gitLines) {
                WarnMsg 'Secrets in recent git history (redacted):'
                $gitLines | ForEach-Object { Write-Host ('  ' + $_) }
            } else { OkMsg 'No secret patterns in post-April-2026 git history' }

            Write-Host '  Checking full history for private key material...' -ForegroundColor DarkGray
            Write-Host '  > git log --all -p --diff-filter=AMR | grep BEGIN.*KEY' -ForegroundColor DarkGray
            $pkeyHits = git log --all -p --diff-filter=AMR 2>$null |
                Where-Object { $_ -match '^\+' -and $_ -imatch '-----BEGIN (RSA|EC|DSA|PGP|OPENSSH|PRIVATE) KEY' } |
                Select-Object -First 5
            if ($pkeyHits) { CritMsg 'Private key material in ALL-TIME git history:'; $pkeyHits }
            else            { OkMsg 'No private key material found in full git history' }

            Write-Host '  > git log --all --oneline --since=2026-04-01 | grep IOC patterns' -ForegroundColor DarkGray
            $iocCommits = git log --all --oneline --since='2026-04-01' 2>$null |
                Where-Object { $_ -imatch $script:IOCPattern }
            if ($iocCommits) { WarnMsg 'IOC in commit messages:'; $iocCommits }
            else              { OkMsg 'No IOC patterns in recent commit messages' }
        } else { SkipMsg ('Not inside a git repository: ' + $expandedDir) }
        
        Pop-Location
    }
    
    if (-not $foundGitRepo) { SkipMsg 'No git repository found in scanned directories' }

    # 6. Processes + scheduled tasks
    SubHead '6/7  Processes and scheduled tasks'
    $cimProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.Name -imatch $script:IOCPattern) -or
            ($_.CommandLine -and ($_.CommandLine -imatch $script:IOCPattern))
        }
    if ($cimProcs) {
        WarnMsg 'Suspicious processes (name or command line matches IOC):'
        $cimProcs | Select-Object ProcessId, Name, CommandLine | Format-Table -AutoSize -Wrap
    } else { OkMsg 'No suspicious processes' }

    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' }
    if ($tasks) {
        InfoMsg 'Scheduled tasks outside Microsoft namespace (verify expected):'
        $tasks | Select-Object TaskName, TaskPath | Format-Table -AutoSize
    } else { OkMsg 'No unexpected scheduled tasks' }

    # 7. Windows persistence locations
    SubHead '7/7  Windows persistence locations'
    $runKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($rk in $runKeys) {
        if (Test-Path $rk) {
            $entries = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
            $suspicious = $entries.PSObject.Properties | Where-Object {
                $_.Name -notmatch '^PS' -and
                ($_.Value -imatch $script:IOCPattern -or
                 $_.Value -imatch '(node|npm|npx|powershell|wscript|mshta|rundll32|regsvr32)\.exe')
            }
            if ($suspicious) {
                InfoMsg ('Run-key entries in ' + $rk + ' (review each):')
                $suspicious | ForEach-Object { Write-Host ('    ' + $_.Name + ' = ' + $_.Value) }
            }
        }
    }

    $startupFolders = @(
        [Environment]::GetFolderPath('Startup'),
        [Environment]::GetFolderPath('CommonStartup')
    )
    foreach ($sf in $startupFolders) {
        if ($sf -and (Test-Path $sf)) {
            $items = Get-ChildItem $sf -ErrorAction SilentlyContinue
            if ($items) {
                InfoMsg ('Startup folder entries in ' + $sf + ':')
                $items | ForEach-Object { Write-Host ('    ' + $_.Name) }
            }
        }
    }

    try {
        $consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch '^(BVTConsumer|SCM Event Log Consumer)$' }
        if ($consumers) {
            WarnMsg 'Non-default WMI event consumers detected (verify each):'
            $consumers | Select-Object Name, CommandLineTemplate | Format-Table -AutoSize -Wrap
        }
    } catch {}

    foreach ($p in @($PROFILE.CurrentUserCurrentHost, $PROFILE.CurrentUserAllHosts, $PROFILE.AllUsersCurrentHost, $PROFILE.AllUsersAllHosts)) {
        if ($p -and (Test-Path $p)) {
            $hits = Select-String -Path $p -Pattern $script:IOCPattern -AllMatches -ErrorAction SilentlyContinue
            if ($hits) {
                WarnMsg ('IOC in PowerShell profile: ' + $p)
                $hits | Select-Object -First 5 | ForEach-Object { Write-Host ('  Line ' + $_.LineNumber + ': ' + $_.Line) }
            } else { InfoMsg ('PowerShell profile present: ' + $p + ' (review manually)') }
        }
    }

    # Git Bash history (Git for Windows)
    $gitBashHist = Join-Path $env:USERPROFILE '.bash_history'
    if (Test-Path $gitBashHist) {
        $hits = Select-String -Path $gitBashHist -Pattern $script:IOCPattern -AllMatches -ErrorAction SilentlyContinue
        if ($hits) {
            WarnMsg 'IOC in Git Bash history:'
            $hits | Select-Object -First 5 | ForEach-Object { Write-Host ('  ' + $_.Line) }
        } else { OkMsg 'Git Bash history clean' }
    }

    $delta = $script:TotalFindings - $startFindings
    if ($delta -eq 0) { $script:ModuleResults['machine'] = 'CLEAN' }
    else              { $script:ModuleResults['machine'] = 'FINDINGS:' + $delta }
}

# ==== MODULE: DEPENDENCY AUDIT ================================================
function Invoke-DepsScan {
    # Expand monorepo workspaces: discover lockfiles up to 4 levels deep in each scan dir
    $wsExtra = @()
    $seenAbsDirs = @()
    foreach ($d in $script:ScanDirs) {
        $r = Resolve-Path (ExpandPathLocal $d) -ErrorAction SilentlyContinue
        $seenAbsDirs += if ($r) { $r.Path.TrimEnd('\') } else { (ExpandPathLocal $d).TrimEnd('\') }
    }
    foreach ($scanDir in $script:ScanDirs) {
        $expandedDir = ExpandPathLocal $scanDir
        if (-not (Test-Path $expandedDir -ErrorAction SilentlyContinue)) { continue }
        $resolved = Resolve-Path $expandedDir -ErrorAction SilentlyContinue
        $absDir = if ($resolved) { $resolved.Path } else { $expandedDir }
        $absDir = $absDir.TrimEnd('\')
        $lockFiles = Get-ChildItem -Path $absDir -Recurse -Depth 4 -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -in @('package-lock.json','yarn.lock','pnpm-lock.yaml') -and
                           $_.FullName -notmatch '[/\\]node_modules[/\\]' }
        foreach ($lf in $lockFiles) {
            $wsDir = $lf.DirectoryName.TrimEnd('\')
            if ($wsDir -ne $absDir -and $seenAbsDirs -notcontains $wsDir -and $wsExtra -notcontains $wsDir) {
                $wsExtra += $wsDir
                $seenAbsDirs += $wsDir
            }
        }
    }
    $allDirs = @($script:ScanDirs) + $wsExtra

    Section ('Dependency Audit  [' + $script:AllPkgs.Count + ' packages  .  ' + $allDirs.Count + ' dir(s)]')
    if ($wsExtra.Count -gt 0) { SubHead ('Monorepo: ' + $wsExtra.Count + ' workspace package(s) auto-discovered') }
    $startFindings = $script:TotalFindings

    foreach ($scanDir in $allDirs) {
        $expandedDir = ExpandPathLocal $scanDir
        if (-not (Test-Path $expandedDir)) { InfoMsg ('Directory not found: ' + $expandedDir + ' (skipping)'); continue }
        $absDir = (Resolve-Path $expandedDir).Path
        SubHead ('Scanning: ' + $absDir)

        try {
            Push-Location $absDir -ErrorAction Stop
        } catch {
            InfoMsg ('Cannot access directory: ' + $absDir + ' (skipping)')
            continue
        }

        $dirFindings = 0

        # --- npm ---
        if (Test-Path 'package-lock.json') {
            Write-Host '  Checking npm (package-lock.json)...' -ForegroundColor DarkGray
            $npmF = 0
            try {
                $lock = Get-Content 'package-lock.json' -Raw | ConvertFrom-Json
                foreach ($pkg in $script:AllPkgs) {
                    $found = $false; $ver = '?'
                    # v2/v3: use PSObject.Properties.Item for safe dynamic-name access (avoids
                    # Select-Object -ExpandProperty failures on names containing / and @)
                    if ($lock.packages) {
                        $pkgKey = 'node_modules/' + $pkg
                        $prop = $lock.packages.PSObject.Properties.Item($pkgKey)
                        if ($null -eq $prop) { $prop = $lock.packages.PSObject.Properties.Item($pkg) }
                        if ($null -eq $prop) {
                            # Workspace-hoisted key: ends with /node_modules/<pkg>
                            $prop = $lock.packages.PSObject.Properties |
                                Where-Object { $_.Name -like "*/$pkgKey" } | Select-Object -First 1
                        }
                        if ($null -ne $prop) { $found = $true; $ver = if ($prop.Value.version) { $prop.Value.version } else { '?' } }
                    }
                    # v1: dependencies object keyed by bare package name
                    if (-not $found -and $lock.dependencies) {
                        $prop = $lock.dependencies.PSObject.Properties.Item($pkg)
                        if ($null -ne $prop) { $found = $true; $ver = if ($prop.Value.version) { $prop.Value.version } else { '?' } }
                    }
                    if ($found) {
                        WarnMsg ($pkg + ' ' + $ver + ' in package-lock.json')
                        $npmF++; $dirFindings++; $script:TotalFindings++
                    }
                }
            } catch {
                InfoMsg ('Could not parse package-lock.json: ' + $_.Exception.Message)
            }
            if ($npmF -eq 0) { OkMsg 'npm: no flagged packages' }
        }

        # --- pnpm ---
        if (Test-Path 'pnpm-lock.yaml') {
            Write-Host '  Checking pnpm (pnpm-lock.yaml)...' -ForegroundColor DarkGray
            $pnpmF = 0
            $pnpmContent = Get-Content 'pnpm-lock.yaml' -Raw
            foreach ($pkg in $script:AllPkgs) {
                $escaped = [regex]::Escape($pkg)
                $pnpmPat = "'" + $escaped + "'|" + '"' + $escaped + '"|/' + $escaped + '@|\s+' + $escaped + '@'
                if ($pnpmContent -imatch $pnpmPat) {
                    WarnMsg ($pkg + ' - see pnpm-lock.yaml')
                    $pnpmF++; $dirFindings++; $script:TotalFindings++
                }
            }
            if ($pnpmF -eq 0) { OkMsg 'pnpm: no flagged packages' }
        }

        # --- yarn ---
        if (Test-Path 'yarn.lock') {
            Write-Host '  Checking yarn (yarn.lock)...' -ForegroundColor DarkGray
            $yarnF = 0
            $yarnContent = Get-Content 'yarn.lock' -Raw
            foreach ($pkg in $script:AllPkgs) {
                $esc = [regex]::Escape($pkg)
                $yarnPat = '^"?' + $esc + '@|^' + $esc + '@'
                if ($yarnContent -imatch $yarnPat) {
                    WarnMsg ($pkg + ' - see yarn.lock')
                    $yarnF++; $dirFindings++; $script:TotalFindings++
                }
            }
            if ($yarnF -eq 0) { OkMsg 'yarn: no flagged packages' }
        }

        # --- Python ---
        $pyFiles = @('requirements.txt','requirements-dev.txt','requirements-prod.txt',
                     'Pipfile.lock','pyproject.toml','poetry.lock','setup.py','setup.cfg') |
            Where-Object { Test-Path $_ }
        if ($pyFiles.Count -gt 0) {
            $pyF = 0
            foreach ($pkg in $script:AllPkgs) {
                $pyBase = $pkg -replace '^@[^/]*/', ''
                $pyPkg  = $pyBase -replace '[_-]', '[_-]'
                $pyPat  = '^' + $pyPkg + '([>=<!\[; ]|$)'
                $pyQuot = '"' + $pyBase + '"'
                foreach ($pf in $pyFiles) {
                    $content = Get-Content $pf -Raw -ErrorAction SilentlyContinue
                    if ($content -imatch $pyPat -or $content -imatch $pyQuot) {
                        WarnMsg ($pyBase + ' - see ' + $pf)
                        $pyF++; $dirFindings++; $script:TotalFindings++
                        break
                    }
                }
            }
            if ($pyF -eq 0) { OkMsg ('Python (' + ($pyFiles -join ', ') + '): no flagged packages') }
        } else { SkipMsg 'Python: no dependency files found' }

        # --- Cargo ---
        if (Test-Path 'Cargo.lock') {
            $cargoF = 0
            $cargoContent = Get-Content 'Cargo.lock' -Raw
            foreach ($pkg in $script:AllPkgs) {
                $cp = $pkg -replace '^@[^/]*/', ''
                $cpEsc = [regex]::Escape($cp)
                $cargoPat = 'name = "' + $cpEsc + '"'
                if ($cargoContent -imatch $cargoPat) {
                    $verPat = 'name = "' + $cpEsc + '"\s*\nversion = "([^"]+)"'
                    $ver = '?'
                    if ($cargoContent -imatch $verPat) { $ver = $Matches[1] }
                    WarnMsg ($cp + ' ' + $ver + ' in Cargo.lock')
                    $cargoF++; $dirFindings++; $script:TotalFindings++
                }
            }
            if ($cargoF -eq 0) { OkMsg 'Cargo: no flagged packages' }
        } elseif (Test-Path 'Cargo.toml') { SkipMsg 'Cargo: no Cargo.lock - run cargo build' }

        # --- Go ---
        $goFiles = @('go.mod','go.sum') | Where-Object { Test-Path $_ }
        if ($goFiles.Count -gt 0) {
            $goF = 0
            foreach ($pkg in $script:AllPkgs) {
                $gp = $pkg -replace '^@[^/]*/', ''
                foreach ($gf in $goFiles) {
                    $hits = Select-String -Path $gf -Pattern ([regex]::Escape($gp)) -SimpleMatch
                    if ($hits) {
                        WarnMsg ($gp + ' - see ' + $gf)
                        $goF++; $dirFindings++; $script:TotalFindings++
                        break
                    }
                }
            }
            if ($goF -eq 0) { OkMsg 'Go modules: no flagged packages' }
        } else { SkipMsg 'Go modules: no go.mod/go.sum' }

        # --- Composer ---
        if (Test-Path 'composer.lock') {
            $compF = 0
            try {
                $comp = Get-Content 'composer.lock' -Raw | ConvertFrom-Json
                $allComp = @()
                if ($comp.packages)       { $allComp += $comp.packages }
                if ($comp.'packages-dev') { $allComp += $comp.'packages-dev' }
                foreach ($pkg in $script:AllPkgs) {
                    $cp = ($pkg -replace '^@', '') -replace '/', '-'
                    $m = $allComp | Where-Object { $_.name -ieq $cp } | Select-Object -First 1
                    if ($m) {
                        WarnMsg ($cp + ' ' + $m.version + ' in composer.lock')
                        $compF++; $dirFindings++; $script:TotalFindings++
                    }
                }
            } catch { InfoMsg ('Could not parse composer.lock: ' + $_) }
            if ($compF -eq 0) { OkMsg 'Composer: no flagged packages' }
        } elseif (Test-Path 'composer.json') { SkipMsg 'Composer: no composer.lock - run composer install' }

        # --- NuGet ---
        $csprojs  = Get-ChildItem -Filter '*.csproj'  -ErrorAction SilentlyContinue
        $hasPkgsLock = Test-Path 'packages.lock.json'
        if ($hasPkgsLock -or ($csprojs.Count -gt 0)) {
            $nugetF = 0
            if ($hasPkgsLock) {
                try {
                    $nugetLock = Get-Content 'packages.lock.json' -Raw | ConvertFrom-Json
                    foreach ($pkg in $script:AllPkgs) {
                        $np = $pkg -replace '^@[^/]*/', ''
                        foreach ($fw in $nugetLock.dependencies.PSObject.Properties) {
                            $m = $fw.Value.PSObject.Properties | Where-Object { $_.Name -ieq $np } | Select-Object -First 1
                            if ($m) {
                                $ver = $m.Value.resolved
                                if (-not $ver) { $ver = '?' }
                                WarnMsg ($np + ' ' + $ver + ' in packages.lock.json')
                                $nugetF++; $dirFindings++; $script:TotalFindings++
                                break
                            }
                        }
                    }
                } catch { InfoMsg ('Could not parse packages.lock.json: ' + $_) }
            }
            foreach ($proj in $csprojs) {
                try {
                    [xml]$xml = Get-Content $proj.FullName
                    foreach ($pkg in $script:AllPkgs) {
                        $np = $pkg -replace '^@[^/]*/', ''
                        $ref = $xml.Project.ItemGroup.PackageReference |
                            Where-Object { $_.Include -ieq $np } | Select-Object -First 1
                        if ($ref) {
                            $ver = $ref.Version
                            if (-not $ver) { $ver = '?' }
                            WarnMsg ($np + ' ' + $ver + ' in ' + $proj.Name)
                            $nugetF++; $dirFindings++; $script:TotalFindings++
                        }
                    }
                } catch {}
            }
            if ($nugetF -eq 0) { OkMsg 'NuGet: no flagged packages' }
        } else { SkipMsg 'NuGet: no packages.lock.json or .csproj' }

        if ($dirFindings -eq 0) { OkMsg ('Directory clean: ' + $absDir) }
        else                    { WarnMsg ($dirFindings.ToString() + ' finding(s) in ' + $absDir) }
        Pop-Location
    }

    $delta = $script:TotalFindings - $startFindings
    if ($delta -eq 0) { $script:ModuleResults['deps'] = 'CLEAN' }
    else              { $script:ModuleResults['deps'] = 'FINDINGS:' + $delta }
}

# ==== MODULE: IDE AUDIT ======================================================
# Flag window for CVE-2026-45321 campaign
$script:IdeFlagStart = [datetime]'2026-05-10'
$script:IdeFlagEnd   = [datetime]'2026-05-21'   # exclusive

function Get-RecentlyModifiedItems {
    param([string]$Path, [string]$Filter = '*', [switch]$Recurse)
    if (-not (Test-Path $Path)) { return @() }
    $gciArgs = @{ Path = $Path; Filter = $Filter; ErrorAction = 'SilentlyContinue' }
    if ($Recurse) { $gciArgs['Recurse'] = $true }
    return @(Get-ChildItem @gciArgs |
        Where-Object { $_.LastWriteTime -ge $script:IdeFlagStart -and $_.LastWriteTime -lt $script:IdeFlagEnd })
}

function Invoke-IDEScan {
    Section 'IDE Extension and Plugin Audit'
    Write-Host '  Active vector: malicious IDE extensions traced to GitHub breach (May 19, 2026)' -ForegroundColor Yellow
    Write-Host '  Automatically flagging any extension/plugin modified May 10-20, 2026.' -ForegroundColor DarkGray
    Write-Host ''

    $startFindings = $script:TotalFindings
    $dateStr       = Get-Date -Format 'yyyyMMdd'
    $anyFound      = $false

    # ── 1. VS Code ──────────────────────────────────────────────────────────────
    Write-Host '  [1/6] VS Code' -ForegroundColor White
    $codeExe = $null
    foreach ($p in @(
        'code',
        'C:\Program Files\Microsoft VS Code\bin\code.cmd',
        'C:\Program Files (x86)\Microsoft VS Code\bin\code.cmd',
        ($env:LOCALAPPDATA + '\Programs\Microsoft VS Code\bin\code.cmd'),
        ($env:LOCALAPPDATA + '\Programs\Microsoft VS Code Insiders\bin\code-insiders.cmd')
    )) {
        if ($p -eq 'code') {
            if (Get-Command code -ErrorAction SilentlyContinue) { $codeExe = 'code'; break }
        } elseif (Test-Path $p) { $codeExe = $p; break }
    }

    if ($codeExe) {
        $anyFound = $true
        $extFile = 'vscode-extensions-' + $dateStr + '.txt'
        try {
            $extLines = @()
            & $codeExe --list-extensions --show-versions 2>$null | ForEach-Object {
                if ($_ -and $_.Trim()) { $extLines += $_ }
            }
            if ($extLines.Count -gt 0) {
                $extLines | Sort-Object | Out-File -FilePath $extFile -Encoding UTF8 -ErrorAction SilentlyContinue
                OkMsg ('VS Code: ' + $extLines.Count + ' extension(s) saved to ' + $extFile)
            } else { InfoMsg 'VS Code: no extensions listed (check if installed)' }
        } catch { InfoMsg ('VS Code: could not list extensions - ' + $_.Exception.Message) }

        foreach ($extDir in @(
            ($env:USERPROFILE + '\.vscode\extensions'),
            ($env:USERPROFILE + '\.vscode-insiders\extensions')
        )) {
            $recent = Get-RecentlyModifiedItems -Path $extDir
            if ($recent.Count -gt 0) {
                WarnMsg ('VS Code: ' + $recent.Count + ' extension(s) modified May 10-20 - REVIEW:')
                $recent | ForEach-Object { Write-Host ('    ' + $_.Name + '  (' + $_.LastWriteTime.ToString('yyyy-MM-dd') + ')') -ForegroundColor Red }
            } elseif (Test-Path $extDir) { OkMsg 'VS Code: no extensions modified in May 10-20 window' }
        }
        InfoMsg 'Specifically verify publisher for: Nx Console, ESLint, Prettier, GitLens'
    } else { SkipMsg 'VS Code: not detected' }
    Write-Host ''

    # ── 2. Visual Studio ────────────────────────────────────────────────────────
    Write-Host '  [2/6] Visual Studio' -ForegroundColor White
    $vsRoot = Join-Path $env:LOCALAPPDATA 'Microsoft\VisualStudio'
    if (Test-Path $vsRoot) {
        $anyFound = $true
        $vsInstalls = Get-ChildItem $vsRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^\d+\.\d+' }
        foreach ($vs in $vsInstalls) {
            $extDir = Join-Path $vs.FullName 'Extensions'
            if (Test-Path $extDir) {
                $extCount = @(Get-ChildItem $extDir -Directory -ErrorAction SilentlyContinue).Count
                OkMsg ('Visual Studio ' + $vs.Name + ': ' + $extCount + ' extension folder(s)')
                $recent = Get-RecentlyModifiedItems -Path $extDir -Filter '*.pkgdef' -Recurse
                if ($recent.Count -gt 0) {
                    WarnMsg ('Visual Studio ' + $vs.Name + ': ' + $recent.Count + ' .pkgdef(s) modified May 10-20 - REVIEW:')
                    $recent | ForEach-Object { Write-Host ('    ' + $_.Name + '  (' + $_.LastWriteTime.ToString('yyyy-MM-dd') + ')') -ForegroundColor Red }
                } else { OkMsg ('Visual Studio ' + $vs.Name + ': no extensions modified in May 10-20 window') }
            }
        }
        InfoMsg 'Manual: Tools -> Extensions and Updates -> Installed -> check dates'
    } else { SkipMsg 'Visual Studio: not detected' }
    Write-Host ''

    # ── 3. JetBrains (IntelliJ, WebStorm, PyCharm, Rider, GoLand, etc.) ────────
    Write-Host '  [3/6] JetBrains IDEs' -ForegroundColor White
    $jbRoot = Join-Path $env:APPDATA 'JetBrains'
    if (Test-Path $jbRoot) {
        $anyFound = $true
        $jbProducts = Get-ChildItem $jbRoot -Directory -ErrorAction SilentlyContinue
        foreach ($prod in $jbProducts) {
            $pluginDir = Join-Path $prod.FullName 'plugins'
            if (Test-Path $pluginDir) {
                $pluginCount = @(Get-ChildItem $pluginDir -Directory -ErrorAction SilentlyContinue).Count
                OkMsg ($prod.Name + ': ' + $pluginCount + ' plugin(s)')
                $recent = Get-RecentlyModifiedItems -Path $pluginDir
                if ($recent.Count -gt 0) {
                    WarnMsg ($prod.Name + ': ' + $recent.Count + ' plugin(s) modified May 10-20 - REVIEW:')
                    $recent | ForEach-Object { Write-Host ('    ' + $_.Name + '  (' + $_.LastWriteTime.ToString('yyyy-MM-dd') + ')') -ForegroundColor Red }
                } else { OkMsg ($prod.Name + ': no plugins modified in May 10-20 window') }
            }
        }
        InfoMsg 'Manual: Settings -> Plugins -> Installed -> sort by Date Updated'
    } else { SkipMsg 'JetBrains IDEs: not detected (%APPDATA%\JetBrains not found)' }
    Write-Host ''

    # ── 4. Sublime Text ─────────────────────────────────────────────────────────
    Write-Host '  [4/6] Sublime Text' -ForegroundColor White
    $stFound = $false
    foreach ($stDir in @(
        ($env:APPDATA + '\Sublime Text\Installed Packages'),
        ($env:APPDATA + '\Sublime Text 3\Installed Packages'),
        ($env:APPDATA + '\Sublime Text 4\Installed Packages')
    )) {
        if (Test-Path $stDir) {
            $stFound = $true; $anyFound = $true
            $pkgCount = @(Get-ChildItem $stDir -Filter '*.sublime-package' -ErrorAction SilentlyContinue).Count
            OkMsg ('Sublime Text: ' + $pkgCount + ' package(s) in ' + $stDir)
            $recent = Get-RecentlyModifiedItems -Path $stDir -Filter '*.sublime-package'
            if ($recent.Count -gt 0) {
                WarnMsg ('Sublime Text: ' + $recent.Count + ' package(s) modified May 10-20 - REVIEW:')
                $recent | ForEach-Object { Write-Host ('    ' + $_.Name + '  (' + $_.LastWriteTime.ToString('yyyy-MM-dd') + ')') -ForegroundColor Red }
            } else { OkMsg 'Sublime Text: no packages modified in May 10-20 window' }
        }
    }
    if ($stFound) { InfoMsg 'Manual: Package Control -> List Packages -> inspect modification dates' }
    else          { SkipMsg 'Sublime Text: not detected' }
    Write-Host ''

    # ── 5. Neovim / Vim ─────────────────────────────────────────────────────────
    Write-Host '  [5/6] Neovim / Vim' -ForegroundColor White
    $nvimFound = $false
    foreach ($dir in @(
        ($env:LOCALAPPDATA + '\nvim-data\site\pack'),
        ($env:LOCALAPPDATA + '\nvim\site\pack'),
        ($env:USERPROFILE + '\vimfiles\pack'),
        ($env:USERPROFILE + '\.vim\pack')
    )) {
        if (Test-Path $dir) {
            $nvimFound = $true; $anyFound = $true
            $pluginDirs = @(Get-ChildItem $dir -Recurse -Directory -Depth 2 -ErrorAction SilentlyContinue |
                Where-Object { $_.Parent.Name -in @('start','opt') })
            OkMsg ('Vim/Neovim: ' + $pluginDirs.Count + ' plugin(s) in ' + $dir)
            $recent = Get-RecentlyModifiedItems -Path $dir -Recurse
            if ($recent.Count -gt 0) {
                WarnMsg ('Vim/Neovim: ' + $recent.Count + ' item(s) modified May 10-20 in ' + $dir + ':')
                $recent | Select-Object -First 10 | ForEach-Object { Write-Host ('    ' + $_.Name + '  (' + $_.LastWriteTime.ToString('yyyy-MM-dd') + ')') -ForegroundColor Red }
            } else { OkMsg ('Vim/Neovim: no plugins modified in May 10-20 window (' + $dir + ')') }
        }
    }
    if (-not $nvimFound) { SkipMsg 'Neovim/Vim: not detected (no pack directory found)' }
    Write-Host ''

    # ── 6. Atom ─────────────────────────────────────────────────────────────────
    Write-Host '  [6/6] Atom' -ForegroundColor White
    $atomDir = Join-Path $env:USERPROFILE '.atom\packages'
    if (Test-Path $atomDir) {
        $anyFound = $true
        $pkgCount = @(Get-ChildItem $atomDir -Directory -ErrorAction SilentlyContinue).Count
        OkMsg ('Atom: ' + $pkgCount + ' package(s)')
        $recent = Get-RecentlyModifiedItems -Path $atomDir
        if ($recent.Count -gt 0) {
            WarnMsg ('Atom: ' + $recent.Count + ' package(s) modified May 10-20 - REVIEW:')
            $recent | ForEach-Object { Write-Host ('    ' + $_.Name + '  (' + $_.LastWriteTime.ToString('yyyy-MM-dd') + ')') -ForegroundColor Red }
        } else { OkMsg 'Atom: no packages modified in May 10-20 window' }
        InfoMsg 'Note: Atom is end-of-life (Dec 2022) - migrate to VS Code'
    } else { SkipMsg 'Atom: not detected' }
    Write-Host ''

    # ── Universal checklist ──────────────────────────────────────────────────────
    Write-Host '  Universal checklist for all IDEs:' -ForegroundColor White
    Write-Host '  [ ]  Filter extension/plugin list to "Recently Updated" -> flag May 10-20 entries'
    Write-Host '  [ ]  Verify publisher identity for each flagged item (not just display name)'
    Write-Host '  [ ]  Disable auto-update across all IDEs until incident window closes'
    Write-Host '  [ ]  VS Code specifically: verify Nx Console, ESLint, Prettier, GitLens'
    Write-Host ''

    $delta = $script:TotalFindings - $startFindings
    if ($delta -gt 0) { $script:ModuleResults['ide'] = 'FINDINGS:' + $delta }
    else              { $script:ModuleResults['ide'] = 'CHECKLIST' }
}

# ==== MODULE: PLATFORM CHECKLIST =============================================
function Invoke-PlatformChecklist {
    Section 'DevOps Platform Audit Checklist'
    Write-Host ''
    Write-Host '  Azure DevOps' -ForegroundColor White
    Write-Host '  [ ]  [CRITICAL]  Org Audit Log - filter April 29 to today' -ForegroundColor Red
    Write-Host '        https://dev.azure.com/{org}/_settings/audit'
    Write-Host '  [ ]  [CRITICAL]  Revoke ALL PATs -> regenerate minimum-scope' -ForegroundColor Red
    Write-Host '  [ ]  [HIGH]     Service Connections - verify no post-April-29 additions' -ForegroundColor Yellow
    Write-Host '  [ ]  [HIGH]     Variable Groups - rotate modified post-April-29' -ForegroundColor Yellow
    Write-Host '  [ ]  [MED]      Pipeline runs May 10-20 - flag anomalies' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  GitHub' -ForegroundColor White
    Write-Host '  [ ]  [CRITICAL]  Security Log - filter oauth_access, PAT creation May 10-20' -ForegroundColor Red
    Write-Host '        github.com -> Settings -> Security log'
    Write-Host '  [ ]  [CRITICAL]  Revoke ALL PATs (classic + fine-grained) -> regenerate' -ForegroundColor Red
    Write-Host '  [ ]  [HIGH]     Authorized OAuth Apps - revoke write:packages or repo scope' -ForegroundColor Yellow
    Write-Host '  [ ]  [HIGH]     Org Audit log -> filter fork, pull_request -> look for zblgg' -ForegroundColor Yellow
    Write-Host '  [ ]  [HIGH]     Actions secrets -> rotate all regardless of triage result' -ForegroundColor Yellow
    $script:ModuleResults['platform'] = 'CHECKLIST'
}

# ==== MODULE: HARDENING ======================================================
function Invoke-Harden {
    Section 'Hardening Configurations'
    Write-Host ''
    Write-Host '1. Project .npmrc (add to every project root)' -ForegroundColor White
    Write-Host '   ignore-scripts=true'
    Write-Host '   audit=true'
    Write-Host '   fund=false'
    Write-Host '   package-lock=true'
    Write-Host ''
    Write-Host '2. package.json pnpm block' -ForegroundColor White
    Write-Host '   "pnpm": {'
    Write-Host '     "onlyBuiltDependencies": ["esbuild", "node-gyp", "sharp"],'
    Write-Host '     "minimumReleaseAge": "3 days",'
    Write-Host '     "blockExoticSubdeps": true'
    Write-Host '   }'
    Write-Host ''
    Write-Host '3. Pin GitHub Actions to SHA (not tag)' -ForegroundColor White
    Write-Host '   BEFORE: - uses: actions/checkout@v4'
    Write-Host '   AFTER:  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683'
    Write-Host '   Tool:   npx pin-github-action .github/workflows/*.yml'
    Write-Host ''
    Write-Host '4. Pipeline installs' -ForegroundColor White
    Write-Host '   npm ci --ignore-scripts'
    Write-Host '   pnpm install --frozen-lockfile --ignore-scripts'
    Write-Host ''
    Write-Host '5. Block IOC domains: zero.masscan.cloud | 94.154.172.43' -ForegroundColor White
    $script:ModuleResults['harden'] = 'DONE'
}

# ==== SUMMARY ================================================================
function Print-Summary {
    Write-Host ''
    HR
    Write-Host '  SCT TRIAGE SUMMARY' -ForegroundColor Cyan
    HR
    Write-Host ('  Host:      ' + $env:COMPUTERNAME)
    Write-Host ('  User:      ' + $env:USERNAME)
    Write-Host ('  Ran:       ' + (Get-Date -Format u))
    Write-Host ('  IOCs:      ' + $script:AllIOCs.Count + ' | Patterns: ' + $script:AllSecrets.Count + ' | Packages: ' + $script:AllPkgs.Count)
    Write-Host ('  Findings:  ' + $script:TotalFindings + ' | Warnings: ' + $script:TotalWarns)
    Write-Host ''

    $moduleOrder = @('machine','deps','ide','platform','harden')
    foreach ($mod in $moduleOrder) {
        if ($script:ModuleResults.ContainsKey($mod)) {
            $r = $script:ModuleResults[$mod]
            $label = '  [{0,-12}]' -f $mod
            if     ($r -eq 'CLEAN')       { Write-Host ($label + '  ' + $r) -ForegroundColor Green }
            elseif ($r -match '^FINDINGS') { Write-Host ($label + '  ' + $r) -ForegroundColor Red   }
            else                           { Write-Host ($label + '  ' + $r) -ForegroundColor DarkGray }
        }
    }

    Write-Host ''
    if ($script:TotalFindings -eq 0) {
        Write-Host '  Result: ALL CLEAR - no IOC hits or secret exposures detected.' -ForegroundColor Green
        Write-Host '  Apply hardening configs and rotate secrets preventatively.' -ForegroundColor DarkGray
    } else {
        Write-Host ('  Result: ' + $script:TotalFindings + ' FINDING(S) - ESCALATE IMMEDIATELY.') -ForegroundColor Red
        Write-Host '  Isolate affected machines, rotate ALL org credentials, open DefectDojo incident.' -ForegroundColor Red
    }

    if ($script:OutputFile) {
        Write-Host ('  Report written to: ' + $script:OutputFile) -ForegroundColor DarkGray
    }
    HR
    Write-Host ''
}

# ---- PATH EXPANSION --------------------------------------------------------


# ==== INTERACTIVE MENU =======================================================
function Show-Menu {
    while ($true) {
        Show-Banner
        Write-Host '  Select a scan module:' -ForegroundColor White
        Write-Host ''
        Write-Host '  [1]  Full Triage       machine scan + dependency audit' -ForegroundColor Cyan
        Write-Host '  [2]  Machine Scan      IOCs, secrets, shell history, git history' -ForegroundColor Cyan
        Write-Host '  [3]  Dependency Audit  npm, pnpm, yarn, pip, cargo, go, composer, nuget' -ForegroundColor Cyan
        Write-Host '  [4]  IDE Audit         VS Code extension checklist' -ForegroundColor Cyan
        Write-Host '  [5]  Platform Audit    ADO / GitHub guidance' -ForegroundColor Cyan
        Write-Host '  [6]  Hardening         print config recommendations' -ForegroundColor Cyan
        Write-Host ''
        Write-Host '  [h]  Help  .  [0]  Exit'
        Write-Host ''
        $choice = Read-Host '  Select [0-6, h]'

        switch ($choice.Trim()) {
            '0' { Write-Host ''; Write-Host '  Exiting. Stay safe.'; Write-Host ''; return }
            'h' { Show-Help; Read-Host '  Press Enter to return to menu' }
            '1' { Collect-Params 'all';     Invoke-MachineScan; Invoke-DepsScan; Print-Summary; Read-Host 'Press Enter' }
            '2' { Collect-Params 'machine'; Invoke-MachineScan;                  Print-Summary; Read-Host 'Press Enter' }
            '3' { Collect-Params 'deps';    Invoke-DepsScan;                     Print-Summary; Read-Host 'Press Enter' }
            '4' { Build-Patterns; Invoke-IDEScan;                                Print-Summary; Read-Host 'Press Enter' }
            '5' { Build-Patterns; Invoke-PlatformChecklist;                      Print-Summary; Read-Host 'Press Enter' }
            '6' { Build-Patterns; Invoke-Harden;                                 Read-Host 'Press Enter' }
            default { Write-Host '  Invalid choice.' -ForegroundColor Yellow }
        }
    }
}

# ==== ENTRY POINT =============================================================
if ($Help) { Show-Help; exit 0 }

$script:OutputFile = ''
if ($AutoOutput) { $script:OutputFile = 'sct-report-' + $env:COMPUTERNAME + '-' + $SCT_DATE + '.txt' }
if ($Output)     { $script:OutputFile = $Output }

if ($script:OutputFile) {
    Start-Transcript -Path $script:OutputFile -Append | Out-Null
}

if ($Command -eq '') {
    Show-Menu
} else {
    Build-Patterns
    Show-Banner
    switch ($Command.ToLower()) {
        'all'      { Invoke-MachineScan; Invoke-DepsScan }
        'machine'  { Invoke-MachineScan }
        'deps'     { Invoke-DepsScan }
        'ide'      { Invoke-IDEScan }
        'platform' { Invoke-PlatformChecklist }
        'harden'   { Invoke-Harden }
        default    { Write-Host ('Unknown command: ' + $Command + ' (try -Help)'); exit 1 }
    }
    Print-Summary
    if ($script:OutputFile) { Stop-Transcript | Out-Null }
    if ($script:TotalFindings -gt 0) { exit 1 } else { exit 0 }
}

if ($script:OutputFile) { Stop-Transcript | Out-Null }