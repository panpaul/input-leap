param(
    [string] $srcPath = '.',
    [ValidateSet('x64', 'arm64')][string] $arch = 'x64',
    [ValidateSet('all', 'deps', 'configure', 'build', 'deploy')][string] $action = 'all'
)

$InformationPreference = 'Continue'
$ErrorActionPreference = 'Stop'

$BONJOUR_SDK_URL = 'https://github.com/panpaul/mDNSResponder/releases/download/v0/release.zip'
$OPENSSL_URL = 'https://raw.githubusercontent.com/slproweb/opensslhashes/master/win32_openssl_hashes.json'
$INNO_EXTRACT_URL = 'https://constexpr.org/innoextract/files/innoextract-1.9/innoextract-1.9-windows.zip'
$INNO_EXTRACT_SHA512 = 'eea751bc021b8cb9a979875d7df5ef0438a8ec6157f75fa9d34b0471bb359daf15cf9cee51a21f9115cb8410bdb836a57f1cd6b2198c634cf108e6785f902488'

function CheckLastExitCode {
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Last exit code: $LASTEXITCODE, callstack: $(Get-PSCallStack | Out-String)"
        exit $LASTEXITCODE
    }
}

function VerifyHash() {
    param([string] $path, [string] $expected)
    $fileHash = Get-FileHash -Path $path -Algorithm SHA512
    if ($fileHash.Hash -ne $expected) {
        Write-Error "Hash mismatch: ${fileHash.Hash}, expected: $expected"
        exit 1
    }
}

function PrepareBonjourSDK {
    param([string] $path)
    Write-Information 'Downloading Bonjour SDK'

    $zipPath = Join-Path $path 'BonjourSDK.zip'
    $sdkPath = Join-Path $path 'BonjourSDK'

    Invoke-WebRequest $BONJOUR_SDK_URL -OutFile $zipPath
    Expand-Archive $zipPath -DestinationPath $sdkPath
}

function PrepareOpenSSL {
    param([string] $path)
    Write-Information 'Downloading OpenSSL'

    # Get latest OpenSSL version and hashes
    $data = (Invoke-RestMethod -Uri $OPENSSL_URL).files.PSObject.Properties
    | Where-Object { $_.Value.bits -eq 64 -and $_.Value.installer -eq "exe" -and !$_.Value.light }
    | ForEach-Object {
        $v = $_.Value.basever -split '\.'
        Add-Member -InputObject $_.Value -NotePropertyName 'v' -NotePropertyValue $v -PassThru
    }
    | Sort-Object -Property @{Expression = { ($_.v[0], $_.v[1], $_.v[2]) }; Descending = $true }

    $OPENSSL_X64 = $data | Where-Object { $_.arch -eq "INTEL" } | Select-Object -First 1
    $OPENSSL_A64 = $data | Where-Object { $_.arch -eq "ARM" } | Select-Object -First 1

    # Win64 & Win64ARM & Innoextract
    Invoke-WebRequest $OPENSSL_X64.url  -OutFile (Join-Path $path 'Win64OpenSSL.exe')
    Invoke-WebRequest $OPENSSL_A64.url  -OutFile (Join-Path $path 'Win64ARMOpenSSL.exe')
    Invoke-WebRequest $INNO_EXTRACT_URL -OutFile (Join-Path $path 'innoextract.zip')

    # Verify SHA512
    VerifyHash (Join-Path $path 'Win64OpenSSL.exe') $OPENSSL_X64.sha512
    VerifyHash (Join-Path $path 'Win64ARMOpenSSL.exe') $OPENSSL_A64.sha512
    VerifyHash (Join-Path $path 'innoextract.zip') $INNO_EXTRACT_SHA512

    # Extract Installer
    Expand-Archive (Join-Path $path 'innoextract.zip') -DestinationPath (Join-Path $path 'innoextract')

    $innoExtract = Join-Path $path 'innoextract\innoextract.exe'
    & $innoExtract -e -d (Join-Path $path 'Win64OpenSSL') (Join-Path $path 'Win64OpenSSL.exe')
    CheckLastExitCode
    & $innoExtract -e -d (Join-Path $path 'Win64ARMOpenSSL') (Join-Path $path 'Win64ARMOpenSSL.exe')
    CheckLastExitCode

    # Move Lib (fix for CMake)
    function MoveLibs {
        param ([string] $path)
        $files = Get-ChildItem -Path $path -Recurse -File
        foreach ($file in $files) {
            $name = $file.BaseName
            $ext = $file.Extension
            $folder = $file.Directory.Name
            $new = Join-Path -Path $path -ChildPath ("$name" + "64" + "$folder$ext")
            Move-Item -Path $file.FullName -Destination $new
        }
    }
    Move-Item (Join-Path $path Win64OpenSSL\app\lib\VC\x64\*) (Join-Path $path Win64OpenSSL\app\lib)
    Move-Item (Join-Path $path Win64ARMOpenSSL\app\lib\VC\arm64\*) (Join-Path $path Win64ARMOpenSSL\app\lib)
    MoveLibs (Join-Path $path Win64OpenSSL\app\lib)
    MoveLibs (Join-Path $path Win64ARMOpenSSL\app\lib)
}

function PrepareDeps {
    param([string] $path = '.\deps')
    Write-Information 'Preparing dependencies'
    New-Item -Force -ItemType Directory -Path $path

    PrepareBonjourSDK -path $path
    PrepareOpenSSL -path $path
}

function Configure {
    param(
        [string] $buildPath = '.\build',
        [string] $srcPath = '.',
        [string] $arch = 'x64',
        [string] $depsPath = '.\deps'
    )
    Write-Information 'Configuring'
    New-Item -Force -ItemType Directory -Path $buildPath

    $opensslPath = Join-Path $depsPath ($arch -eq 'x64' ? 'Win64OpenSSL' : 'Win64ARMOpenSSL') "app"
    $opensslPath = Resolve-Path $opensslPath

    $bonjourSDKPath = Join-Path $depsPath 'BonjourSDK\dist' ($arch -eq 'x64' ? 'x64' : 'ARM64') "sdk"
    $bonjourSDKPath = Resolve-Path $bonjourSDKPath

    if (!(Test-Path $env:QT_ROOT_DIR)) {
        Write-Warning "QT_ROOT_DIR sets to: $env:QT_ROOT_DIR"
        Write-Error "ENV QT_ROOT_DIR does not exist"
    }

    $qt6Dir = Join-Path $env:QT_ROOT_DIR "lib" "cmake" "Qt6"

    & cmake "-A" $arch                         `
        "-S" $srcPath                          `
        "-B" $buildPath                        `
        "-DCMAKE_BUILD_TYPE=RelWithDebInfo"    `
        "-DQT_DEFAULT_MAJOR_VERSION=6"         `
        "-DQt6_DIR=$qt6Dir"                    `
        "-DQT_HOST_PATH=$env:QT_HOST_PATH"     `
        "-DCMAKE_PREFIX_PATH=$env:QT_ROOT_DIR" `
        "-DOPENSSL_ROOT_DIR=$opensslPath"      `
        "-DBONJOUR_SDK_HOME=$bonjourSDKPath"
    CheckLastExitCode
}

function Build {
    param([string] $buildPath = '.\build')
    Write-Information 'Building'
    & cmake "--build" "$buildPath" "-j" "--config" "RelWithDebInfo"
    CheckLastExitCode
}

function Deploy {
    param(
        [string] $buildPath = '.\build',
        [string] $distPath = '.\package',
        [string] $depsPath = '.\deps'
    )
    Write-Information 'Deploying'
    New-Item -Force -ItemType Directory -Path $distPath

    # Main Executables
    Get-ChildItem -Path (Join-Path $buildPath "bin" "RelWithDebInfo") -Filter "*.exe" -Recurse |
    Where-Object { $_.Name -notlike "*test*" } |
    ForEach-Object { Copy-Item -Path $_.FullName -Destination $distPath }

    # DNSSD
    $bonjour = Join-Path $depsPath 'BonjourSDK\dist' ($arch -eq 'x64' ? 'x64' : 'ARM64') "sdk" "Bin" "dnssd.dll"
    Copy-Item -Path $bonjour -Destination $distPath

    # Qt
    if (!(Test-Path $env:QT_ROOT_DIR)) {
        Write-Warning "QT_ROOT_DIR sets to: $env:QT_ROOT_DIR"
        Write-Error "ENV QT_ROOT_DIR does not exist"
    }
    $windeployqt = Join-Path $env:QT_ROOT_DIR "bin" "windeployqt.exe"
    if (!(Test-Path $windeployqt)) {
        Write-Warning "windeployqt notfound, fallback to hard-coded copy rules"

        # Copy Qt DLLs
        $binDir = Join-Path $env:QT_ROOT_DIR "bin"
        Copy-Item -Path (Join-Path $binDir "Qt6Core.dll") -Destination $distPath
        Copy-Item -Path (Join-Path $binDir "Qt6Gui.dll") -Destination $distPath
        Copy-Item -Path (Join-Path $binDir "Qt6Network.dll") -Destination $distPath
        Copy-Item -Path (Join-Path $binDir "Qt6Svg.dll") -Destination $distPath
        Copy-Item -Path (Join-Path $binDir "Qt6Widgets.dll") -Destination $distPath

        # Copy Qt Plugins
        $pluginsDir = Join-Path $env:QT_ROOT_DIR "plugins"

        ## generic
        New-Item -Force -ItemType Directory -Path (Join-Path $distPath "generic")
        Copy-Item -Path (Join-Path $pluginsDir "generic" "qtuiotouchplugin.dll") -Destination (Join-Path $distPath "generic")

        ## iconengines
        New-Item -Force -ItemType Directory -Path (Join-Path $distPath "iconengines")
        Copy-Item -Path (Join-Path $pluginsDir "iconengines" "qsvgicon.dll") -Destination (Join-Path $distPath "iconengines")

        ## imageformats
        New-Item -Force -ItemType Directory -Path (Join-Path $distPath "imageformats")
        Copy-Item -Path (Join-Path $pluginsDir "imageformats" "qgif.dll") -Destination (Join-Path $distPath "imageformats")
        Copy-Item -Path (Join-Path $pluginsDir "imageformats" "qico.dll") -Destination (Join-Path $distPath "imageformats")
        Copy-Item -Path (Join-Path $pluginsDir "imageformats" "qjpeg.dll") -Destination (Join-Path $distPath "imageformats")
        Copy-Item -Path (Join-Path $pluginsDir "imageformats" "qsvg.dll") -Destination (Join-Path $distPath "imageformats")

        ## networkinformation
        New-Item -Force -ItemType Directory -Path (Join-Path $distPath "networkinformation")
        Copy-Item -Path (Join-Path $pluginsDir "networkinformation" "qnetworklistmanager.dll") -Destination (Join-Path $distPath "networkinformation")

        ## platforms
        New-Item -Force -ItemType Directory -Path (Join-Path $distPath "platforms")
        Copy-Item -Path (Join-Path $pluginsDir "platforms" "qwindows.dll") -Destination (Join-Path $distPath "platforms")

        ## styles
        New-Item -Force -ItemType Directory -Path (Join-Path $distPath "styles")
        Copy-Item -Path (Join-Path $pluginsDir "styles" "qwindowsvistastyle.dll") -Destination (Join-Path $distPath "styles")

        ## tls
        New-Item -Force -ItemType Directory -Path (Join-Path $distPath "tls")
        Copy-Item -Path (Join-Path $pluginsDir "tls" "qcertonlybackend.dll") -Destination (Join-Path $distPath "tls")
        Copy-Item -Path (Join-Path $pluginsDir "tls" "qopensslbackend.dll") -Destination (Join-Path $distPath "tls")
        Copy-Item -Path (Join-Path $pluginsDir "tls" "qschannelbackend.dll") -Destination (Join-Path $distPath "tls")

    }
    else {
        & $windeployqt "--release" "--force" "$distPath"
        CheckLastExitCode
    }

    # Fix Inno Setup Directory
    $issPath = Join-Path $buildPath "installer-inno" "input-leap.iss"
    $issContent = Get-Content -Path $issPath
    $issContent = $issContent -replace '#define MyAppOutputDir ".*"', ('#define MyAppOutputDir "' + (Resolve-Path .) + '"')
    $issContent = $issContent -replace '#define MyAppBinaryDir ".*"', ('#define MyAppBinaryDir "' + (Resolve-Path $distPath) + '\*"')

    $issPath = Join-Path $buildPath "installer-inno" "input-leap-fixed.iss"
    $issContent | Set-Content -Path $issPath

    # Build Inno Setup
    & "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" "/Qp" "/FInputLeapSetup" "$issPath"
    CheckLastExitCode
}

switch ($action) {
    'all' { PrepareDeps; Configure; Build; Deploy }
    'deps' { PrepareDeps }
    'configure' { Configure -srcPath $srcPath -arch $arch }
    'build' { Build }
    'deploy' { Deploy }
    default { Write-Error "Unknown action: $action" }
}
