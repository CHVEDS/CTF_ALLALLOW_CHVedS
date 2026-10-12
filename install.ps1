<#
    CTF KIT — установщик инструментов для CTF по направлениям.
    Автор: Heres

    Запуск (PowerShell, лучше от администратора):
        Set-ExecutionPolicy -Scope Process Bypass
        .\install.ps1                       # интерактивное меню
        .\install.ps1 -Sets web,crypto      # сразу выбранные наборы
        .\install.ps1 -All                  # все наборы
        .\install.ps1 -DryRun               # только проверить, что стоит, ничего не ставить
        .\install.ps1 -NoIntro              # без заставки
        .\install.ps1 -NoFullscreen         # не разворачивать на весь экран
        .\install.ps1 -NoSound              # без звука печати
        .\install.ps1 -NoGlitch             # без «лагов» в тексте

    Правила:
      * уже установленное не переустанавливается;
      * обновление — только после вопроса и твоего согласия.
#>
[CmdletBinding()]
param(
    [string[]]$Sets,
    [switch]$All,
    [switch]$DryRun,
    [switch]$NoIntro,
    [switch]$NoFullscreen,
    [switch]$NoSound,       # без звука печати
    [switch]$NoGlitch,      # без «лагов» в тексте
    [switch]$Child          # служебный: запуск внутри полноэкранного окна
)

# ── перезапуск в отдельном окне консоли на весь экран ──
if (-not $NoFullscreen -and -not $Child -and $env:OS -eq 'Windows_NT' -and $Host.Name -eq 'ConsoleHost') {
    try {
        $exe = (Get-Process -Id $PID).Path
        $a = @("`"$exe`"", '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Child')
        foreach ($kv in $PSBoundParameters.GetEnumerator()) {
            if ($kv.Value -is [switch]) { if ($kv.Value) { $a += ('-' + $kv.Key) } }
            else { $a += ('-' + $kv.Key); $a += ((@($kv.Value) -join ',')) }
        }
        Start-Process -FilePath "$env:WINDIR\System32\conhost.exe" -ArgumentList $a -WorkingDirectory $PSScriptRoot -ErrorAction Stop
        Write-Host '  >> открываю CTF KIT в полноэкранном окне...' -ForegroundColor Green
        exit 0
    } catch {
        Write-Host '  [!] не удалось открыть отдельное окно, продолжаю здесь' -ForegroundColor Yellow
    }
}

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$script:LogFile = Join-Path $PSScriptRoot ("logs\install-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force -Path (Split-Path $script:LogFile) | Out-Null

# ═══════════════════════════════════════════════════════════════════════
#  НАБОРЫ
#  Kind: winget | pip | manual
#  Cmd / Path — альтернативная проверка «уже установлено» (если ставили не через winget)
# ═══════════════════════════════════════════════════════════════════════
$Catalog = [ordered]@{
    base = @{
        Title = 'BASE      // фундамент'
        Items = @(
            @{ Name='Git';              Kind='winget'; Id='Git.Git';                    Cmd='git' }
            @{ Name='Python 3';         Kind='winget'; Id='Python.Python.3.12';         Cmd='py','python' }
            @{ Name='7-Zip';            Kind='winget'; Id='7zip.7zip';                  Path='C:\Program Files\7-Zip\7z.exe' }
            @{ Name='VS Code';          Kind='winget'; Id='Microsoft.VisualStudioCode'; Cmd='code' }
            @{ Name='Windows Terminal'; Kind='winget'; Id='Microsoft.WindowsTerminal';  Cmd='wt' }
            @{ Name='requests';         Kind='pip';    Id='requests' }
            @{ Name='ipython';          Kind='pip';    Id='ipython' }
        )
    }
    web = @{
        Title = 'WEB       // сайты и API'
        Items = @(
            @{ Name='Burp Suite Community'; Kind='winget'; Id='PortSwigger.BurpSuite.Community' }
            @{ Name='Firefox';              Kind='winget'; Id='Mozilla.Firefox';   Path='C:\Program Files\Mozilla Firefox\firefox.exe' }
            @{ Name='Node.js LTS';          Kind='winget'; Id='OpenJS.NodeJS.LTS'; Cmd='node' }
            @{ Name='Docker Desktop';       Kind='winget'; Id='Docker.DockerDesktop'; Cmd='docker'; Heavy=$true }
            @{ Name='beautifulsoup4';       Kind='pip'; Id='beautifulsoup4' }
            @{ Name='httpx';                Kind='pip'; Id='httpx' }
            @{ Name='pyjwt';                Kind='pip'; Id='pyjwt' }
            @{ Name='flask-unsign';         Kind='pip'; Id='flask-unsign' }
            @{ Name='sqlmap';               Kind='pip'; Id='sqlmap' }
        )
    }
    crypto = @{
        Title = 'CRYPTO    // шифры и математика'
        Items = @(
            @{ Name='pycryptodome'; Kind='pip'; Id='pycryptodome' }
            @{ Name='cryptography'; Kind='pip'; Id='cryptography' }
            @{ Name='gmpy2';        Kind='pip'; Id='gmpy2' }
            @{ Name='sympy';        Kind='pip'; Id='sympy' }
            @{ Name='z3-solver';    Kind='pip'; Id='z3-solver' }
        )
    }
    forensics = @{
        Title = 'FORENSICS // файлы, дампы, стеганография'
        Items = @(
            @{ Name='Wireshark';         Kind='winget'; Id='WiresharkFoundation.Wireshark'; Path='C:\Program Files\Wireshark\Wireshark.exe' }
            @{ Name='HxD';               Kind='winget'; Id='MHNexus.HxD' }
            @{ Name='ImHex';             Kind='winget'; Id='WerWolv.ImHex' }
            @{ Name='ExifTool';          Kind='winget'; Id='OliverBetz.ExifTool'; Cmd='exiftool' }
            @{ Name='Audacity';          Kind='winget'; Id='Audacity.Audacity' }
            @{ Name='Sonic Visualiser';  Kind='winget'; Id='SonicVisualiser.SonicVisualiser' }
            @{ Name='pillow';            Kind='pip'; Id='pillow' }
            @{ Name='numpy';             Kind='pip'; Id='numpy' }
            @{ Name='scapy';             Kind='pip'; Id='scapy' }
        )
    }
    reverse = @{
        Title = 'REVERSE   // разбор программ'
        Items = @(
            @{ Name='JDK 21 (для Ghidra)'; Kind='winget'; Id='EclipseAdoptium.Temurin.21.JDK'; Cmd='java' }
            @{ Name='Ghidra';              Kind='manual'; Url='https://github.com/NationalSecurityAgency/ghidra/releases'; Cmd='ghidraRun' }
            @{ Name='IDA Free';            Kind='winget'; Id='Hex-Rays.IDA.Free' }
            @{ Name='x64dbg';              Kind='winget'; Id='x64dbg.x64dbg' }
            @{ Name='dnSpyEx (.NET)';      Kind='winget'; Id='dnSpyEx.dnSpy' }
            @{ Name='Detect It Easy';      Kind='winget'; Id='horsicq.DIE-engine' }
            @{ Name='ImHex';               Kind='winget'; Id='WerWolv.ImHex' }
            @{ Name='capstone';            Kind='pip'; Id='capstone' }
            @{ Name='pefile';              Kind='pip'; Id='pefile' }
        )
    }
    ppc = @{
        Title = 'PPC       // программирование и автоматизация'
        Items = @(
            @{ Name='pwntools'; Kind='pip'; Id='pwntools' }
            @{ Name='numpy';    Kind='pip'; Id='numpy' }
            @{ Name='sympy';    Kind='pip'; Id='sympy' }
            @{ Name='z3-solver';Kind='pip'; Id='z3-solver' }
            @{ Name='tqdm';     Kind='pip'; Id='tqdm' }
        )
    }
    osint = @{
        Title = 'OSINT     // поиск информации'
        Items = @(
            @{ Name='ExifTool'; Kind='winget'; Id='OliverBetz.ExifTool'; Cmd='exiftool' }
            @{ Name='Firefox';  Kind='winget'; Id='Mozilla.Firefox'; Path='C:\Program Files\Mozilla Firefox\firefox.exe' }
        )
        Links = @(
            'Wayback Machine      https://web.archive.org'
            'Яндекс.Картинки      https://yandex.ru/images'
            'Google Lens          https://lens.google.com'
            'CyberChef            https://gchq.github.io/CyberChef'
        )
    }
}

# ═══════════════════════════════════════════════════════════════════════
#  ПОЛНЫЙ ЭКРАН И МАСШТАБ (только внутри окна, открытого скриптом)
#  Шрифт подбирается через WinAPI так, чтобы на экран влезало ~125 символов,
#  затем окно разворачивается. Никаких эмуляций нажатий клавиш.
# ═══════════════════════════════════════════════════════════════════════
$script:TargetCols = 125

function Enter-Fullscreen {
    try {
        if (-not ('CtfKit.Con' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace CtfKit {
  public static class Con {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct FONTINFO {
      public uint cbSize; public uint nFont; public short X; public short Y;
      public int FontFamily; public int FontWeight;
      [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string FaceName;
    }
    [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int n);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool SetCurrentConsoleFontEx(IntPtr h, bool max, ref FONTINFO f);
    [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
    public static bool SetFont(string face, short size) {
      FONTINFO f = new FONTINFO();
      f.cbSize = (uint)Marshal.SizeOf(f); f.X = 0; f.Y = size;
      f.FontFamily = 54; f.FontWeight = 400; f.FaceName = face;
      return SetCurrentConsoleFontEx(GetStdHandle(-11), false, ref f);
    }
  }
}
'@
        }
        $size = 16
        [void][CtfKit.Con]::SetFont('Consolas', $size)
        for ($i = 0; $i -lt 20; $i++) {
            $cols = [Console]::LargestWindowWidth
            if ($cols -gt $script:TargetCols + 10 -and $size -lt 48) { $size += 2 }
            elseif ($cols -lt $script:TargetCols - 15 -and $size -gt 10) { $size -= 2 }
            else { break }
            [void][CtfKit.Con]::SetFont('Consolas', $size)
            Start-Sleep -Milliseconds 30
        }
        [void][CtfKit.Con]::ShowWindow([CtfKit.Con]::GetConsoleWindow(), 3)   # SW_MAXIMIZE
        Start-Sleep -Milliseconds 200
        try {
            $raw = $Host.UI.RawUI
            $raw.BufferSize = New-Object Management.Automation.Host.Size ($raw.WindowSize.Width, 3000)
            $raw.WindowTitle = 'CTF KIT // by Heres'
            $raw.BackgroundColor = 'Black'
            Clear-Host
        } catch {}
    } catch {}
}

function Finish([int]$Code = 0) {
    if ($Child) {
        Write-Host ''
        Write-Host '  [ нажми Enter, чтобы закрыть окно ]' -ForegroundColor DarkGray
        [void](Read-Host)
    }
    exit $Code
}

# отступ, чтобы баннер и аватар стояли по центру
function Pad([int]$ContentWidth) {
    $w = 80; try { $w = [Console]::WindowWidth } catch {}
    return (' ' * [Math]::Max(2, [int](($w - $ContentWidth) / 2)))
}

# ═══════════════════════════════════════════════════════════════════════
#  ВИЗУАЛ
# ═══════════════════════════════════════════════════════════════════════
function Log([string]$m) { Add-Content -Path $script:LogFile -Value ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) -Encoding UTF8 }

# ── звук печати ──
# Для каждой строки заранее собирается один WAV: щелчок на каждую букву
# точно в момент её появления. Строка озвучивается одним вызовом Play(),
# поэтому звуки не обрываются друг другом.
$script:SndRate = 22050
$script:RainVolume = 0.20     # громкость звука «матричного дождя» в начале
$script:RainBytes = $null
$script:AvatarVolume = 0.25   # громкость звука, когда рисуется аватар
$script:AvatarStepMs = 60      # сколько мс на одну строку аватара
$script:AvatarBytes = $null
$script:NoiseSeconds = 3.0      # сколько секунд длятся помехи в самом начале
$script:StaticVolume = 0.10     # громкость звука помех (начало и перелив черепа)
$script:StaticBytes = $null      # звук помех в начале
$script:AvGlitchBytes = $null    # звук перелива черепа
$script:SndVolume = 0.25      # громкость щелчков: 0.1 — тихо, 0.5 — громко
$script:ClickSamples = @()      # несколько вариантов щелчка (int16[])
$script:SndOn = $false
$script:SndPlayer = $null
function Init-Sound {
    if ($NoSound -or $env:OS -ne 'Windows_NT') { return }
    try {
        $rnd = New-Object System.Random 7
        # мягкий «тук» механической клавиши: приглушённый шум + низкий короткий тон
        for ($v = 0; $v -lt 4; $v++) {
            $n = [int]($script:SndRate * 0.022)
            $arr = New-Object 'int16[]' $n
            $f = 170 + 30 * $v
            $lp = 0.0
            for ($i = 0; $i -lt $n; $i++) {
                $t = $i / $script:SndRate
                $lp = $lp + 0.18 * (($rnd.NextDouble() * 2 - 1) - $lp)          # фильтр: убирает писк
                $x = 0.55 * $lp * [Math]::Exp(-$t * 650) + 0.45 * [Math]::Sin(2 * [Math]::PI * $f * $t) * [Math]::Exp(-$t * 220)
                $x = $x * $script:SndVolume
                $arr[$i] = [int16]([Math]::Max(-32767, [Math]::Min(32767, $x * 32767)))
            }
            $script:ClickSamples += ,$arr
        }
        [void](New-Object System.Media.SoundPlayer)   # проверка, что плеер доступен
        try { $script:RainBytes = New-RainSound 3.5 } catch { $script:RainBytes = $null }
        try { $script:AvatarBytes = New-AvatarSound $script:AvLines.Count $script:AvatarStepMs } catch { $script:AvatarBytes = $null }
        try { $script:StaticBytes = New-StaticSound $script:NoiseSeconds 21 } catch { $script:StaticBytes = $null }
        try { $script:AvGlitchBytes = New-StaticSound 1.3 5 } catch { $script:AvGlitchBytes = $null }
        $script:SndOn = $true
    } catch { $script:SndOn = $false }
}

function New-WavBytes([int16[]]$Samples, [int]$Rate) {
    $dataLen = $Samples.Length * 2
    $bytes = New-Object 'byte[]' (44 + $dataLen)
    $ascii = [Text.Encoding]::ASCII
    $bw = New-Object IO.BinaryWriter((New-Object IO.MemoryStream(,$bytes)))
    $bw.Write($ascii.GetBytes('RIFF')); $bw.Write([int](36 + $dataLen)); $bw.Write($ascii.GetBytes('WAVEfmt '))
    $bw.Write([int]16); $bw.Write([int16]1); $bw.Write([int16]1); $bw.Write([int]$Rate); $bw.Write([int]($Rate * 2))
    $bw.Write([int16]2); $bw.Write([int16]16); $bw.Write($ascii.GetBytes('data')); $bw.Write([int]$dataLen)
    $bw.Flush()
    [Buffer]::BlockCopy($Samples, 0, $bytes, 44, $dataLen)
    return ,$bytes
}

# звук «матричного дождя»: низкий гул + редкие мягкие «капли»
function New-RainSound([double]$Seconds) {
    $rate = 8000
    $n = [int]($rate * $Seconds)
    $buf = New-Object 'double[]' $n
    $r = New-Object System.Random 3
    $twoPi = 2 * [Math]::PI
    # капли
    $pos = 0
    while ($true) {
        $pos += $r.Next([int]($rate * 0.03), [int]($rate * 0.12))
        if ($pos -ge $n - 260) { break }
        $w = $twoPi * (100 + $r.Next(0, 700)) / $rate
        $amp = 0.25 + 0.35 * $r.NextDouble()
        $dec = [Math]::Exp(-90.0 / $rate); $e = $amp
        for ($k = 0; $k -lt 260; $k++) { $buf[$pos + $k] = $e * [Math]::Sin($w * $k); $e *= $dec }
    }
    # гул + плавное появление/затухание, сразу в int16
    $out = New-Object 'int16[]' $n
    $w1 = $twoPi * 110 / $rate; $w2 = $twoPi * 165 / $rate; $wl = $twoPi * 0.7 / $rate
    $fin = 0.4 * $rate; $fout = 0.6 * $rate
    $vol = $script:RainVolume * 32767
    for ($i = 0; $i -lt $n; $i++) {
        $fade = 1.0
        if ($i -lt $fin) { $fade = $i / $fin } elseif ($n - $i -lt $fout) { $fade = ($n - $i) / $fout }
        $x = ((0.275 * [Math]::Sin($w1 * $i) + 0.15 * [Math]::Sin($w2 * $i)) * (0.75 + 0.25 * [Math]::Sin($wl * $i)) + $buf[$i]) * $fade * $vol
        if ($x -gt 32767) { $x = 32767 } elseif ($x -lt -32767) { $x = -32767 }
        $out[$i] = [int16]$x
    }
    return New-WavBytes $out $rate
}

# звук появления аватара: на каждую строку — треск помех, под ним нарастающий гул
function New-AvatarSound([int]$Lines, [int]$StepMs) {
    $rate = 8000
    $step = [int]($rate * $StepMs / 1000)
    $n = $step * $Lines + [int]($rate * 0.5)
    $buf = New-Object 'double[]' $n
    $r = New-Object System.Random 11
    $twoPi = 2 * [Math]::PI
    # треск: короткая пачка шума в начале каждой строки
    for ($l = 0; $l -lt $Lines; $l++) {
        $p0 = $l * $step
        $len = [int]($step * 0.7)
        $e = 0.9; $dec = [Math]::Exp(-25.0 / $len)
        for ($k = 0; $k -lt $len; $k++) {
            if ($r.Next(0, 3) -eq 0) { $buf[$p0 + $k] += $e * ($r.NextDouble() * 2 - 1) }
            $e *= $dec
        }
    }
    # гул: плавно поднимается от 70 до 180 Гц и затухает в конце
    $out = New-Object 'int16[]' $n
    $phase = 0.0
    $vol = $script:AvatarVolume * 32767
    $body = $step * $Lines
    for ($i = 0; $i -lt $n; $i++) {
        $prog = [Math]::Min(1.0, $i / $body)
        $phase += $twoPi * (70 + 110 * $prog) / $rate
        $env = $prog
        if ($i -gt $body) { $env = 1.0 - ($i - $body) / ($n - $body) }
        $x = ($buf[$i] * 0.5 + 0.45 * [Math]::Sin($phase) * $env) * $vol
        if ($x -gt 32767) { $x = 32767 } elseif ($x -lt -32767) { $x = -32767 }
        $out[$i] = [int16]$x
    }
    return New-WavBytes $out $rate
}

# звук помех: рваный шипящий треск + прерывистый цифровой гул
function New-StaticSound([double]$Seconds, [int]$Seed = 1) {
    $rate = 8000
    $n = [int]($rate * $Seconds)
    $out = New-Object 'int16[]' $n
    $r = New-Object System.Random $Seed
    $vol = $script:StaticVolume * 32767
    $lp = 0.0
    $gate = 1.0; $gateLeft = 0; $gs = 0.0; $bs = 0.0
    $buzz = 0; $buzzLeft = 0; $buzzF = 100
    $fout = [int]($rate * 0.3)
    for ($i = 0; $i -lt $n; $i++) {
        # «рваность»: шум то есть, то пропадает кусками по 10–120 мс
        if ($gateLeft -le 0) {
            $gate = @(0.8, 0.5, 0.35, 0.15, 0.05)[$r.Next(5)]
            $gateLeft = $r.Next([int]($rate * 0.01), [int]($rate * 0.12))
        }
        $gateLeft--
        # иногда включается гул (как наводка)
        if ($buzzLeft -le 0) {
            $buzz = if ($r.Next(4) -eq 0) { 1 } else { 0 }
            $buzzF = @(90, 110, 130, 150)[$r.Next(4)]
            $buzzLeft = $r.Next([int]($rate * 0.05), [int]($rate * 0.3))
        }
        $buzzLeft--
        $lp = $lp + 0.12 * (($r.NextDouble() * 2 - 1) - $lp)        # мягче: срезаем верха
        $gs = $gs + 0.004 * ($gate - $gs)                           # плавные переходы громкости, без щелчков
        $x = 1.2 * $lp * $gs
        $bs = $bs + 0.003 * ($buzz - $bs)
        $x += 0.18 * $bs * [Math]::Sin(2 * [Math]::PI * $buzzF * $i / $rate)   # мягкий гул вместо жужжания
        if ($n - $i -lt $fout) { $x *= ($n - $i) / $fout }
        if ($i -lt $fout) { $x *= $i / $fout }
        $x *= $vol
        if ($x -gt 32767) { $x = 32767 } elseif ($x -lt -32767) { $x = -32767 }
        $out[$i] = [int16]$x
    }
    return New-WavBytes $out $rate
}

function Play-Bytes([byte[]]$Bytes) {
    if (-not $Bytes) { return }
    try {
        if ($script:SndPlayer) { try { $script:SndPlayer.Stop() } catch {} }
        $script:SndPlayer = New-Object System.Media.SoundPlayer((New-Object IO.MemoryStream(,$Bytes)))
        $script:SndPlayer.Load()
        $script:SndPlayer.Play()
    } catch {}
}
function Stop-Sound { if ($script:SndPlayer) { try { $script:SndPlayer.Stop() } catch {} } }

function Play-Typing([string]$Text, [int]$StepMs) {
    if (-not $script:SndOn) { return }
    try {
        $rate = $script:SndRate
        $step = [int]($rate * $StepMs / 1000)
        $total = $step * $Text.Length + $script:ClickSamples[0].Length + 10
        $buf = New-Object 'int16[]' $total
        $r = New-Object System.Random
        for ($i = 0; $i -lt $Text.Length; $i++) {
            if ([char]::IsWhiteSpace($Text[$i])) { continue }
            $c = $script:ClickSamples[$r.Next($script:ClickSamples.Count)]
            [Array]::Copy($c, 0, $buf, $i * $step, $c.Length)
        }
        $dataLen = $total * 2
        $bytes = New-Object 'byte[]' (44 + $dataLen)
        $ascii = [Text.Encoding]::ASCII
        $hdr = New-Object IO.MemoryStream(,$bytes)
        $bw = New-Object IO.BinaryWriter($hdr)
        $bw.Write($ascii.GetBytes('RIFF')); $bw.Write([int](36 + $dataLen)); $bw.Write($ascii.GetBytes('WAVEfmt '))
        $bw.Write([int]16); $bw.Write([int16]1); $bw.Write([int16]1); $bw.Write([int]$rate); $bw.Write([int]($rate * 2))
        $bw.Write([int16]2); $bw.Write([int16]16); $bw.Write($ascii.GetBytes('data')); $bw.Write([int]$dataLen)
        $bw.Flush()
        [Buffer]::BlockCopy($buf, 0, $bytes, 44, $dataLen)
        if ($script:SndPlayer) { try { $script:SndPlayer.Stop() } catch {} }
        $wav = New-Object IO.MemoryStream(,$bytes)
        $script:SndPlayer = New-Object System.Media.SoundPlayer($wav)
        $script:SndPlayer.Load()
        $script:SndPlayer.Play()      # асинхронно
    } catch {}
}

# ── «лаги»: случайные помехи в тексте ──
$script:GlitchLine  = 0.30     # шанс, что уже напечатанная строка «моргнёт» помехами (0 — никогда)
$script:GlitchChar  = 0.05     # шанс, что отдельная буква на миг появится битой
$script:GlitchMs    = 90       # сколько мс держится помеха (больше — заметнее)
$script:GlitchNoise = '▓▒░█#@%&*!?<>/\|'.ToCharArray()
$script:GRnd = New-Object System.Random
$script:BannerTop = -1

function Corrupt-Text([string]$Text, [double]$Share = 0.55) {
    $c = $Text.ToCharArray()
    for ($i = 0; $i -lt $c.Length; $i++) {
        if (-not [char]::IsWhiteSpace($c[$i]) -and $script:GRnd.NextDouble() -lt $Share) {
            $c[$i] = $script:GlitchNoise[$script:GRnd.Next($script:GlitchNoise.Length)]
        }
    }
    return -join $c
}

# перерисовать участок экрана помехами и вернуть как было
function Glitch-At([int]$Left, [int]$Top, [string]$Text, [ConsoleColor]$Color, [switch]$Shift) {
    if ($NoGlitch -or -not $Text) { return }
    try {
        $back = @([Console]::CursorLeft, [Console]::CursorTop)
        $frames = $script:GRnd.Next(2, 5)
        for ($f = 0; $f -lt $frames; $f++) {
            $shift = 0; if ($Shift) { $shift = $script:GRnd.Next(-2, 3) }
            $x = [Math]::Max(0, $Left + $shift)
            [Console]::SetCursorPosition($x, $Top)
            $col = @('Red', 'DarkRed', 'DarkGreen', 'White')[$script:GRnd.Next(4)]
            Write-Host (Corrupt-Text $Text) -NoNewline -ForegroundColor $col
            Start-Sleep -Milliseconds ($script:GRnd.Next([int]($script:GlitchMs * 0.6), [int]($script:GlitchMs * 1.4)))
            if ($Shift) {
                # стереть «хвост» от сдвига (только там, где рядом пусто — для баннера)
                [Console]::SetCursorPosition([Math]::Max(0, $Left - 2), $Top)
                Write-Host (' ' * ($Text.Length + 4)) -NoNewline
            }
        }
        [Console]::SetCursorPosition($Left, $Top)
        Write-Host $Text -NoNewline -ForegroundColor $Color
        [Console]::SetCursorPosition($back[0], $back[1])
    } catch {}
}

function Type-Out {
    param([string]$Text, [ConsoleColor]$Color = 'Green', [int]$Delay = 12, [switch]$NoNewline)
    $x0 = -1; $y0 = -1
    try { $x0 = [Console]::CursorLeft; $y0 = [Console]::CursorTop } catch {}
    if ($Delay -le 0) { Write-Host $Text -NoNewline -ForegroundColor $Color }
    else {
        $step = [Math]::Max($Delay, 10)
        Play-Typing $Text $step
        $sw = [Diagnostics.Stopwatch]::StartNew()
        for ($i = 0; $i -lt $Text.Length; $i++) {
            # буква появляется ровно тогда, когда звучит её щелчок
            while ($sw.ElapsedMilliseconds -lt $i * $step) { Start-Sleep -Milliseconds 1 }
            $ch = $Text[$i]
            if (-not $NoGlitch -and -not [char]::IsWhiteSpace($ch) -and $script:GRnd.NextDouble() -lt $script:GlitchChar) {
                # битая буква (иногда сразу несколько) на мгновение
                try {
                    $cx = [Console]::CursorLeft; $cy = [Console]::CursorTop
                    $cnt = [Math]::Min($script:GRnd.Next(1, 4), $Text.Length - $i)
                    $junk = -join (1..$cnt | ForEach-Object { $script:GlitchNoise[$script:GRnd.Next($script:GlitchNoise.Length)] })
                    Write-Host $junk -NoNewline -ForegroundColor (@('Red', 'White', 'DarkRed')[$script:GRnd.Next(3)])
                    Start-Sleep -Milliseconds $script:GlitchMs
                    [Console]::SetCursorPosition($cx, $cy)
                    Write-Host (' ' * $cnt) -NoNewline
                    [Console]::SetCursorPosition($cx, $cy)
                } catch {}
            }
            Write-Host $ch -NoNewline -ForegroundColor $Color
        }
    }
    # иногда вся строка «моргает» помехами
    if (-not $NoGlitch -and $x0 -ge 0 -and $script:GRnd.NextDouble() -lt $script:GlitchLine) {
        try { if ($x0 + $Text.Length -lt [Console]::WindowWidth - 3) { Glitch-At $x0 $y0 $Text $Color } } catch {}
    }
    if (-not $NoNewline) { Write-Host '' }
}

# помехи на весь экран (сбой сигнала)
function Signal-Noise([double]$Seconds = 3.0) {
    if ($NoGlitch) { return }
    try {
        $w = [Console]::WindowWidth; $h = [Console]::WindowHeight
        if ($script:SndOn) { Play-Bytes $script:StaticBytes }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalSeconds -lt $Seconds) {
            Clear-Host
            $rows = $script:GRnd.Next(3, 12)
            for ($k = 0; $k -lt $rows; $k++) {
                $y = $script:GRnd.Next(0, $h - 1)
                $len = $script:GRnd.Next([int]($w / 4), $w - 1)
                $x = $script:GRnd.Next(0, $w - $len)
                $line = -join (1..$len | ForEach-Object { if ($script:GRnd.Next(3) -eq 0) { ' ' } else { $script:GlitchNoise[$script:GRnd.Next($script:GlitchNoise.Length)] } })
                [Console]::SetCursorPosition($x, $y)
                Write-Host $line -NoNewline -ForegroundColor (@('DarkGreen', 'Green', 'DarkRed', 'DarkGray')[$script:GRnd.Next(4)])
            }
            Start-Sleep -Milliseconds ($script:GRnd.Next(40, 140))
        }
        Stop-Sound
        Clear-Host
    } catch {}
}

# «моргнуть» баннером CTF KIT наверху экрана, если он виден
function Glitch-Banner {
    if ($NoGlitch -or $script:BannerTop -lt 0) { return }
    try {
        if ([Console]::WindowTop -gt $script:BannerTop) { return }
        $bp = Pad 50
        $rows = @(0..($Banner.Count - 1) | Get-Random -Count $script:GRnd.Next(2, 5))
        foreach ($r in $rows) { Glitch-At $bp.Length ($script:BannerTop + $r) $Banner[$r] 'Green' -Shift }
    } catch {}
}

function Matrix-Rain([int]$Frames = 28) {
    try {
        $w = [Console]::WindowWidth; $h = [Console]::WindowHeight
        if ($w -lt 40 -or $h -lt 15) { return }
        $glyphs = '0123456789ABCDEF#$%&@<>{}[]/\|=+*'.ToCharArray()
        $rnd = New-Object System.Random
        $drops = @(); for ($i = 0; $i -lt $w - 1; $i += 2) { $drops += $rnd.Next(-$h, 0) }
        [Console]::CursorVisible = $false
        Clear-Host
        if ($script:SndOn) { Play-Bytes $script:RainBytes }
        for ($f = 0; $f -lt $Frames; $f++) {
            for ($c = 0; $c -lt $drops.Count; $c++) {
                $x = $c * 2; $y = $drops[$c]
                if ($y -ge 0 -and $y -lt $h - 1) {
                    [Console]::SetCursorPosition($x, $y)
                    Write-Host $glyphs[$rnd.Next($glyphs.Length)] -NoNewline -ForegroundColor White
                    if ($y -ge 1) { [Console]::SetCursorPosition($x, $y - 1); Write-Host $glyphs[$rnd.Next($glyphs.Length)] -NoNewline -ForegroundColor Green }
                    if ($y -ge 4) { [Console]::SetCursorPosition($x, $y - 4); Write-Host $glyphs[$rnd.Next($glyphs.Length)] -NoNewline -ForegroundColor DarkGreen }
                    if ($y -ge 9) { [Console]::SetCursorPosition($x, $y - 9); Write-Host ' ' -NoNewline }
                }
                $drops[$c]++
                if ($drops[$c] -gt $h + 10) { $drops[$c] = $rnd.Next(-10, 0) }
            }
            Start-Sleep -Milliseconds 45
        }
    } catch {} finally {
        Stop-Sound
        try { [Console]::CursorVisible = $true } catch {}
        Clear-Host
    }
}

$Banner = @(
    ' ██████╗████████╗███████╗    ██╗  ██╗██╗████████╗'
    '██╔════╝╚══██╔══╝██╔════╝    ██║ ██╔╝██║╚══██╔══╝'
    '██║        ██║   █████╗      █████╔╝ ██║   ██║   '
    '██║        ██║   ██╔══╝      ██╔═██╗ ██║   ██║   '
    '╚██████╗   ██║   ██║         ██║  ██╗██║   ██║   '
    ' ╚═════╝   ╚═╝   ╚═╝         ╚═╝  ╚═╝╚═╝   ╚═╝   '
)

function Show-Banner([switch]$Glitch) {
    if ($Glitch) {
        $noise = '▓▒░█#@%&*'.ToCharArray()
        for ($k = 0; $k -lt 3; $k++) {
            Clear-Host; Write-Host ''
            foreach ($line in $Banner) {
                $g = -join ($line.ToCharArray() | ForEach-Object { if ($_ -ne ' ' -and (Get-Random -Maximum 6) -eq 0) { $noise | Get-Random } else { $_ } })
                $col = @('Red', 'DarkRed', 'Green') | Get-Random
                Write-Host ((Pad 50) + $g) -ForegroundColor $col
            }
            Start-Sleep -Milliseconds 90
        }
        Clear-Host
    }
    Write-Host ''
    $bp = Pad 50
    try { $script:BannerTop = [Console]::CursorTop } catch { $script:BannerTop = -1 }
    foreach ($line in $Banner) { Write-Host ($bp + $line) -ForegroundColor Green }
    Write-Host ($bp + '──────────────────────────────────────────────────') -ForegroundColor DarkGreen
    Write-Host ($bp + ' toolkit installer by ') -NoNewline -ForegroundColor DarkGreen
    Write-Host 'Heres' -NoNewline -ForegroundColor Green
    Write-Host '   ::   ' -NoNewline -ForegroundColor DarkGreen
    Write-Host 'v1.0' -NoNewline -ForegroundColor Green
    Write-Host '   ::   SOLARCTF{...}' -ForegroundColor DarkGreen
    Write-Host ''
}

function Boot-Line([string]$Text, [string]$State = 'OK') {
    Write-Host '  [' -NoNewline -ForegroundColor DarkGray
    switch ($State) {
        'OK'   { Write-Host ' OK ' -NoNewline -ForegroundColor Green }
        'WARN' { Write-Host 'WARN' -NoNewline -ForegroundColor Yellow }
        'FAIL' { Write-Host 'FAIL' -NoNewline -ForegroundColor Red }
        default{ Write-Host ' .. ' -NoNewline -ForegroundColor DarkGreen }
    }
    Write-Host '] ' -NoNewline -ForegroundColor DarkGray
    Type-Out $Text -Color Gray -Delay 6
}

function Hex-Noise([int]$Lines = 3) {
    for ($i = 0; $i -lt $Lines; $i++) {
        $addr = '{0:X8}' -f (Get-Random -Maximum 0x7FFFFFFF)
        $bytes = -join (1..16 | ForEach-Object { '{0:x2} ' -f (Get-Random -Maximum 256) })
        Write-Host ("  0x$addr  $bytes") -ForegroundColor DarkGreen
        Start-Sleep -Milliseconds 40
    }
}

$Author = 'Heres'
$Avatar = @(
    '░░▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒░░'
    '░▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░'
    '▒▓▓▓▓▓▓▒▒░░░░░░░░░░░░░▒▒▓▓▓▓▓▓▒'
    '▒▓▓▓▓▒░                       ░▒▓▓▓▓▒'
    '▓▓▓▓▓▒        ▄▄█████████▄▄        ▒▓▓▓▓▓'
    '▓▓▓▓░      ▄███████████████▄      ░▓▓▓▓'
    '▒▓▓▓▒     ███▀▀▀▀███████▀▀▀▀███     ▒▓▓▓▒'
    '▓▓▓▓     ██▌  ●  ▐█████▌  ●  ▐██     ▓▓▓▓'
    '▓▓▓▓     ██▄     ▄██▀██▄     ▄██     ▓▓▓▓'
    '▓▓▓▓      ▀██████▌ ▐█▌ ▐██████▀      ▓▓▓▓'
    '▒▓▓▓▒       ▀███▄▄▄▄▄▄▄▄▄███▀       ▒▓▓▓▒'
    '▓▓▓▓▓░        █▀█▀█▀█▀█▀█▀█        ░▓▓▓▓▓'
    '▒▓▓▓▓▒       ▀▄▀▄▀▄▀▄▀▄▀▄▀       ▒▓▓▓▓▒'
    '░▒▓▓▓▓▓▒░       ▀▀▀▀▀▀▀▀▀       ░▒▓▓▓▓▓▒░'
    '░▒▓▓▓▓▓▓▓▓▓▓▒░░                   ░░▒▓▓▓▓▓▓▓▓▓▓▒░'
    '░▒▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒░  01001000 01000101  ░▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▒░'
    '▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░  [ H  E  R  E  S ]  ░▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒'
)
$script:AvW = ($Avatar | Measure-Object -Property Length -Maximum).Maximum
$script:AvLines = @($Avatar | ForEach-Object { $p = [int](($script:AvW - $_.Length) / 2); ((' ' * $p) + $_).PadRight($script:AvW) })

function CharColor([char]$c) {
    switch -CaseSensitive ($c) {
        '░' { return 'DarkGray' }  '▒' { return 'DarkGray' }  '▓' { return 'Gray' }
        '●' { return 'Red' }
        '─' { return 'DarkGray' }
        '[' { return 'DarkGreen' } ']' { return 'DarkGreen' }
        '0' { return 'DarkGreen' } '1' { return 'DarkGreen' }
        default { if ([char]::IsLetter($c)) { return 'Green' } return 'White' }
    }
}

function Write-Colored([string]$line) {
    # пишет строку цветными отрезками
    $i = 0
    while ($i -lt $line.Length) {
        $col = CharColor $line[$i]; $j = $i + 1
        while ($j -lt $line.Length -and ((CharColor $line[$j]) -eq $col -or $line[$j] -eq ' ')) { $j++ }
        Write-Host $line.Substring($i, $j - $i) -NoNewline -ForegroundColor $col
        $i = $j
    }
}

# аватар «переливается» помехами: строки дёргаются и бьются, потом всё возвращается
function Glitch-Avatar([int]$Top, [int]$Left, [int]$Frames = 8) {
    if ($NoGlitch) { return }
    try {
        if ($script:SndOn) { Play-Bytes $script:AvGlitchBytes }
        $h = $script:AvLines.Count
        for ($f = 0; $f -lt $Frames; $f++) {
            $rows = @(0..($h - 1) | Get-Random -Count $script:GRnd.Next(3, [Math]::Min(9, $h)))
            foreach ($r in $rows) {
                $line = $script:AvLines[$r]
                $sh = $script:GRnd.Next(-3, 2)     # вправо не дальше 1, чтобы не задеть текст справа
                [Console]::SetCursorPosition([Math]::Max(0, $Left - 3), $Top + $r)
                Write-Host (' ' * ($line.Length + 4)) -NoNewline
                [Console]::SetCursorPosition([Math]::Max(0, $Left + $sh), $Top + $r)
                Write-Host (Corrupt-Text $line 0.45) -NoNewline -ForegroundColor (@('Red', 'DarkRed', 'Green', 'White', 'DarkGreen')[$script:GRnd.Next(5)])
            }
            Start-Sleep -Milliseconds ($script:GRnd.Next(50, 120))
            foreach ($r in $rows) {
                $line = $script:AvLines[$r]
                if ($r -eq 7) { $line = $line -replace '●', '─' }
                [Console]::SetCursorPosition([Math]::Max(0, $Left - 3), $Top + $r)
                Write-Host (' ' * ($line.Length + 4)) -NoNewline
                [Console]::SetCursorPosition($Left, $Top + $r)
                Write-Colored $line
            }
            Start-Sleep -Milliseconds ($script:GRnd.Next(20, 70))
        }
    } catch {}
}

function Show-Author {
    $user = if ($env:USERNAME) { $env:USERNAME } else { 'агент' }
    $side = @(
        @{ R = 2;  T = '>> входящее соединение ...';             C = 'DarkGreen' }
        @{ R = 3;  T = '>> канал зашифрован  [AES-256 / OK]';    C = 'DarkGreen' }
        @{ R = 4;  T = '>> отправитель: ' + $Author;             C = 'Green' }
        @{ R = 6;  T = "Привет, $user.";                         C = 'White' }
        @{ R = 7;  T = 'Этот набор собрал я — ' + $Author + '.'; C = 'Gray' }
        @{ R = 8;  T = 'Он сам поставит всё нужное для CTF,';    C = 'Gray' }
        @{ R = 9;  T = 'чтобы ты тратил время на флаги,';        C = 'Gray' }
        @{ R = 10; T = 'а не на установку программ.';            C = 'Gray' }
        @{ R = 12; T = 'добро пожаловать в команду.';            C = 'Green' }
        @{ R = 14; T = '>> конец передачи _';                    C = 'DarkGreen' }
    )
    $pad  = Pad ($script:AvW + 44)
    $rnd  = New-Object System.Random
    $noise = '░▒▓█01<>/\#'.ToCharArray()
    Write-Host ''
    try {
        # резервируем место заранее, чтобы экран не прокручивался во время анимации
        $h = $script:AvLines.Count
        Write-Host ("`n" * $h) -NoNewline
        $top = [Console]::CursorTop - $h
        if ($top -lt 0) { throw 'no room' }
        $after = $top + $h
        # 1. «сканирование»: строка сначала шумом, потом проявляется (со звуком)
        if ($script:SndOn) { Play-Bytes $script:AvatarBytes }
        $swAv = [Diagnostics.Stopwatch]::StartNew()
        for ($i = 0; $i -lt $h; $i++) {
            while ($swAv.ElapsedMilliseconds -lt $i * $script:AvatarStepMs) { Start-Sleep -Milliseconds 1 }
            $line = $script:AvLines[$i]
            $n = -join ($line.ToCharArray() | ForEach-Object { if ($_ -ne ' ') { $noise[$rnd.Next($noise.Length)] } else { ' ' } })
            [Console]::SetCursorPosition(0, $top + $i)
            Write-Host ($pad + $n) -NoNewline -ForegroundColor DarkGreen
            Start-Sleep -Milliseconds 35
            [Console]::SetCursorPosition(0, $top + $i)
            Write-Host $pad -NoNewline
            if ($i -eq 7) { Write-Colored ($line -replace '●', '─') } else { Write-Colored $line }
        }
        # 2. текст справа
        $col = $pad.Length + $script:AvW + 4
        foreach ($t in $side) {
            [Console]::SetCursorPosition($col - 2, $top + $t.R)
            Write-Host '│ ' -NoNewline -ForegroundColor DarkGray
            Type-Out $t.T -Color $t.C -Delay 14 -NoNewline
        }
        # 3. глаза: открываются, потом моргают (двойное моргание, пауза, ещё раз)
        $eyeRow = $top + 7
        $eyeOpen = $script:AvLines[7]
        $eyeShut = $eyeOpen -replace '●', '─'
        $blink = {
            param([int]$closedMs)
            [Console]::SetCursorPosition($pad.Length, $eyeRow); Write-Colored $eyeShut
            Start-Sleep -Milliseconds $closedMs
            [Console]::SetCursorPosition($pad.Length, $eyeRow); Write-Colored $eyeOpen
        }
        Start-Sleep -Milliseconds 300
        Glitch-Avatar $top $pad.Length 8                                              # перелив помехами
        Start-Sleep -Milliseconds 250
        [Console]::SetCursorPosition($pad.Length, $eyeRow); Write-Colored $eyeOpen   # открыл глаза
        Start-Sleep -Milliseconds 900
        & $blink 160; Start-Sleep -Milliseconds 180; & $blink 160
        Start-Sleep -Milliseconds 1100
        & $blink 220
        [Console]::SetCursorPosition(0, $after)
    } catch {
        Log ("avatar fallback: " + $_.Exception.Message + " @ " + $_.InvocationInfo.ScriptLineNumber)
        # консоль без управления курсором — просто печатаем
        foreach ($line in $script:AvLines) { Write-Host $pad -NoNewline; Write-Colored $line; Write-Host '' }
        foreach ($t in $side) { Write-Host ($pad + $t.T) -ForegroundColor $t.C }
    }
    Write-Host ''
}

function Say([string]$Text) {
    # реплика от Heres
    Write-Host ''
    Write-Host '  ☠︎ ' -NoNewline -ForegroundColor Green
    Write-Host ($Author + ' ▸ ') -NoNewline -ForegroundColor DarkGreen
    Type-Out $Text -Color White -Delay 16
}
function Pick([string[]]$Options) { return ($Options | Get-Random) }

$SetComments = @{
    base      = 'фундамент — правильное начало.'
    web       = 'веб — моя любимая категория.'
    crypto    = 'крипта: тут решает математика, а не удача.'
    forensics = 'форензика: будем искать то, что спрятали.'
    reverse   = 'реверс — для терпеливых. уважаю.'
    ppc       = 'пусть скрипты работают, пока ты думаешь.'
    osint     = 'OSINT: ответ обычно лежит на виду.'
}

function Sign-Off([string]$Text = 'удачи на соревновании. надеюсь мы сработаемся.') {
    Write-Host ''
    Write-Host '  ── ' -NoNewline -ForegroundColor DarkGreen
    Type-Out $Text -Color Green -Delay 20
    Write-Host '                                   — ' -NoNewline -ForegroundColor DarkGray
    Type-Out $Author -Color Green -Delay 60
}

function Ask([string]$Question, [string]$Default = 'n') {
    Write-Host '  [?] ' -NoNewline -ForegroundColor Cyan
    Write-Host $Question -NoNewline -ForegroundColor White
    $hint = if ($Default -eq 'y') { ' [Y/n] ' } else { ' [y/N] ' }
    Write-Host $hint -NoNewline -ForegroundColor DarkGray
    $a = Read-Host
    if ([string]::IsNullOrWhiteSpace($a)) { $a = $Default }
    return $a.Trim().ToLower()
}

# ═══════════════════════════════════════════════════════════════════════
#  ПРОВЕРКИ
# ═══════════════════════════════════════════════════════════════════════
function Refresh-Path {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
}

function Get-PyCmd {
    if (Get-Command py -ErrorAction SilentlyContinue)     { return 'py' }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        # заглушка из Microsoft Store не считается
        $p = (Get-Command python).Source
        if ($p -notmatch 'WindowsApps') { return 'python' }
    }
    return $null
}

$script:WingetUpgrades = $null
function Load-WingetUpgrades {
    # `winget upgrade` без аргументов только ПОКАЗЫВАЕТ список, ничего не ставит
    $script:WingetUpgrades = (winget upgrade --include-unknown --accept-source-agreements 2>$null | Out-String)
}

function Test-Winget($item) {
    $r = @{ State = 'MISSING'; Cur = ''; New = '' }
    $out = (winget list --id $item.Id -e --accept-source-agreements 2>$null | Out-String)
    $installed = $out -match [regex]::Escape($item.Id)
    if (-not $installed) {
        foreach ($c in @($item.Cmd)) { if ($c -and (Get-Command $c -ErrorAction SilentlyContinue)) { $installed = $true } }
        if ($item.Path -and (Test-Path $item.Path)) { $installed = $true }
        if ($installed) { $r.State = 'INSTALLED'; $r.Cur = 'не через winget'; return $r }
        return $r
    }
    $r.State = 'INSTALLED'
    foreach ($line in ($script:WingetUpgrades -split "`r?`n")) {
        if ($line -match ('(^|\s)' + [regex]::Escape($item.Id) + '(\s|$)')) {
            $tok = $line.Trim() -split '\s+'
            $i = [Array]::IndexOf($tok, $item.Id)
            if ($i -ge 0 -and $tok.Count -ge $i + 3) { $r.Cur = $tok[$i + 1]; $r.New = $tok[$i + 2] }
            $r.State = 'UPDATE'
        }
    }
    return $r
}

$script:PipOutdated = @{}
function Load-PipOutdated($py) {
    $script:PipOutdated = @{}
    try {
        $json = & $py -m pip list --outdated --format=json --disable-pip-version-check 2>$null | Out-String
        if ($json.Trim()) {
            foreach ($p in ($json | ConvertFrom-Json)) { $script:PipOutdated[(Norm $p.name)] = $p }
        }
    } catch {}
}
function Norm([string]$n) { return ($n.ToLower() -replace '[-_.]+', '-') }

function Test-Pip($item, $py) {
    $r = @{ State = 'MISSING'; Cur = ''; New = '' }
    if (-not $py) { $r.State = 'NOPY'; return $r }
    $show = & $py -m pip show $item.Id --disable-pip-version-check 2>$null | Out-String
    if ($LASTEXITCODE -ne 0 -or -not $show.Trim()) { return $r }
    $r.State = 'INSTALLED'
    if ($show -match '(?m)^Version:\s*(\S+)') { $r.Cur = $Matches[1] }
    $o = $script:PipOutdated[(Norm $item.Id)]
    if ($o) { $r.State = 'UPDATE'; $r.New = $o.latest_version }
    return $r
}

function Test-Manual($item) {
    $r = @{ State = 'MANUAL'; Cur = ''; New = '' }
    foreach ($c in @($item.Cmd)) { if ($c -and (Get-Command $c -ErrorAction SilentlyContinue)) { $r.State = 'INSTALLED' } }
    return $r
}

function Write-Status($item, $res) {
    $label = '{0,-24}' -f $item.Name
    Write-Host '   ' -NoNewline
    Write-Host ('{0,-7}' -f $item.Kind) -NoNewline -ForegroundColor DarkGray
    Write-Host $label -NoNewline -ForegroundColor Gray
    switch ($res.State) {
        'INSTALLED' { Write-Host '■ уже есть ' -NoNewline -ForegroundColor DarkGreen; Write-Host $res.Cur -ForegroundColor DarkGray }
        'UPDATE'    { Write-Host '▲ есть обновление ' -NoNewline -ForegroundColor Yellow; Write-Host ("{0} -> {1}" -f $res.Cur, $res.New) -ForegroundColor DarkYellow }
        'MISSING'   { Write-Host '□ будет установлен' -NoNewline -ForegroundColor Green; if ($item.Heavy) { Write-Host '  (тяжёлый, спрошу отдельно)' -ForegroundColor DarkGray } else { Write-Host '' } }
        'MANUAL'    { Write-Host '◊ ставится вручную' -ForegroundColor Cyan }
        'NOPY'      { Write-Host '× нет Python — сначала набор BASE' -ForegroundColor Red }
    }
}

# ═══════════════════════════════════════════════════════════════════════
#  УСТАНОВКА
# ═══════════════════════════════════════════════════════════════════════
function Install-Item($item, $py, [switch]$Upgrade) {
    $verb = if ($Upgrade) { 'обновление' } else { 'установка' }
    Write-Host ''
    Write-Host '  >> ' -NoNewline -ForegroundColor Green
    Type-Out ("$verb :: " + $item.Name) -Color Green -Delay 8
    Log ("$verb " + $item.Kind + ' ' + $item.Name)
    $ok = $false
    switch ($item.Kind) {
        'winget' {
            $cmd = if ($Upgrade) { 'upgrade' } else { 'install' }
            winget $cmd --id $item.Id -e --silent --accept-source-agreements --accept-package-agreements
            $ok = ($LASTEXITCODE -eq 0)
        }
        'pip' {
            $args2 = @('-m', 'pip', 'install', '--disable-pip-version-check')
            if ($Upgrade) { $args2 += '--upgrade' }
            & $py @args2 $item.Id
            $ok = ($LASTEXITCODE -eq 0)
        }
    }
    if ($ok) { Boot-Line ($item.Name + ' — готово') 'OK'; Log 'OK' }
    else     { Boot-Line ($item.Name + " — ошибка (код $LASTEXITCODE), см. вывод выше") 'FAIL'; Log "FAIL $LASTEXITCODE" }
    if ($ok) { if ((Get-Random -Maximum 3) -eq 0) { Say (Pick @('есть.', '+1 в арсенал.', ($item.Name + ' на месте.'), 'дальше.')) } }
    else { Say ($item.Name + ' не встал. загляни в лог, разберёмся.') }
    return $ok
}

# ═══════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════
Init-Sound
if ($Child) { Enter-Fullscreen }

if (-not $NoIntro) {
    Signal-Noise $script:NoiseSeconds
    Matrix-Rain
    Show-Banner -Glitch
    Hex-Noise 3
    Glitch-Banner
    Write-Host ''
    Boot-Line 'инициализация ядра...' '..'
    Start-Sleep -Milliseconds 150
} else {
    Show-Banner
}

$isAdmin = $false
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}
if ($isAdmin) { Boot-Line 'права администратора получены' 'OK' } else { Boot-Line 'запущено без прав администратора — winget может спрашивать UAC' 'WARN' }

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Boot-Line 'winget не найден. Установи «App Installer» из Microsoft Store и запусти снова.' 'FAIL'
    Finish 1
}
Boot-Line 'winget на месте' 'OK'
$py = Get-PyCmd
if ($py) { Boot-Line "python обнаружен ($py)" 'OK' } else { Boot-Line 'python не найден — pip-пакеты станут доступны после набора BASE' 'WARN' }
if (-not $NoIntro) { Show-Author; Glitch-Banner }

# ── главный цикл: после установки можно вернуться в меню ──
$keys = @($Catalog.Keys)
$interactive = -not ($All -or $Sets)
$doneSets = @()
$round = 0

function Ask-More {
    if (-not $interactive) { return $false }
    Write-Host ''
    return ((Ask 'Установить что-нибудь ещё?' 'y') -in @('y', 'д', 'yes', 'да'))
}

:session while ($true) {
    $round++
    if (-not $interactive) { if ($All) { $chosen = $keys } else { $chosen = @($Sets | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ }) } }
    else {
        if ($round -eq 1) { Say (Pick @('выбирай наборы. я подожду.', 'что ставим сегодня?', 'с чего начнём?')) }
        else { Say (Pick @('что ещё поставим?', 'продолжаем. выбирай.', 'ещё что-нибудь?')) }
        Write-Host ''
        Write-Host '  ┌─[ ВЫБЕРИ НАБОРЫ ]──────────────────────────────────' -ForegroundColor DarkGreen
        for ($i = 0; $i -lt $keys.Count; $i++) {
            Write-Host '  │  ' -NoNewline -ForegroundColor DarkGreen
            Write-Host ("[{0}] " -f ($i + 1)) -NoNewline -ForegroundColor Green
            Write-Host $Catalog[$keys[$i]].Title -NoNewline -ForegroundColor Gray
            if ($doneSets -contains $keys[$i]) { Write-Host '   ✓ уже ставили' -ForegroundColor DarkGreen } else { Write-Host '' }
        }
        Write-Host '  │  ' -NoNewline -ForegroundColor DarkGreen
        Write-Host '[A] всё   [Q] выход' -ForegroundColor DarkGray
        Write-Host '  └─' -NoNewline -ForegroundColor DarkGreen
        Write-Host 'root@ctf-kit' -NoNewline -ForegroundColor Green
        Write-Host ':~# ' -NoNewline -ForegroundColor Gray
        $sel = (Read-Host).Trim().ToLower()
        if ($sel -eq 'q' -or -not $sel) { break session }
        if ($sel -eq 'a') { $chosen = $keys }
        else {
            $chosen = @()
            foreach ($t in ($sel -split '[,\s]+')) {
                if ($t -match '^\d+$' -and [int]$t -ge 1 -and [int]$t -le $keys.Count) { $chosen += $keys[[int]$t - 1] }
                elseif ($keys -contains $t) { $chosen += $t }
            }
        }
    }
    $chosen = @($chosen | Where-Object { $keys -contains $_ } | Select-Object -Unique)
    if ($chosen.Count -eq 0) {
        Boot-Line 'ни одного набора не выбрано' 'FAIL'
        if ($interactive) { continue session } else { Finish 1 }
    }
    # base всегда первым, если выбран
    if ($chosen -contains 'base') { $chosen = @('base') + @($chosen | Where-Object { $_ -ne 'base' }) }

    foreach ($k in $chosen) { if ($SetComments[$k]) { Say $SetComments[$k] } }

    # ── сканирование ──
    Say 'смотрю, что у тебя уже установлено...'
    Write-Host ''
    Type-Out '  [*] сканирую систему...' -Color Green -Delay 15
    Load-WingetUpgrades
    if ($py) { Load-PipOutdated $py }

    $plan = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($k in $chosen) {
        Write-Host ''
        Write-Host ('  ══ ' + $Catalog[$k].Title + ' ') -ForegroundColor Green
        foreach ($item in $Catalog[$k].Items) {
            $key = $item.Kind + ':' + $(if ($item.Id) { $item.Id } else { $item.Name })
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            switch ($item.Kind) {
                'winget' { $res = Test-Winget $item }
                'pip'    { $res = Test-Pip $item $py }
                'manual' { $res = Test-Manual $item }
            }
            Write-Status $item $res
            [void]$plan.Add(@{ Item = $item; Res = $res })
        }
        if ($Catalog[$k].Links) {
            Write-Host '   полезные ссылки:' -ForegroundColor DarkGray
            foreach ($l in $Catalog[$k].Links) { Write-Host ('     ' + $l) -ForegroundColor DarkCyan }
        }
    }

    $missing  = @($plan | Where-Object { $_.Res.State -eq 'MISSING' })
    $updates  = @($plan | Where-Object { $_.Res.State -eq 'UPDATE' })
    $manual   = @($plan | Where-Object { $_.Res.State -eq 'MANUAL' })
    $nopy     = @($plan | Where-Object { $_.Res.State -eq 'NOPY' })

    Write-Host ''
    Write-Host '  ────────────────────────────────────────────────────' -ForegroundColor DarkGreen
    Write-Host ("   установить: {0}   обновления: {1}   вручную: {2}   уже есть: {3}" -f $missing.Count, $updates.Count, $manual.Count, @($plan | Where-Object { $_.Res.State -eq 'INSTALLED' }).Count) -ForegroundColor Gray

    $inst = @($plan | Where-Object { $_.Res.State -eq 'INSTALLED' }).Count
    Say ("у тебя уже есть {0} из {1}." -f $inst, $plan.Count)
    $doneSets = @($doneSets + $chosen | Select-Object -Unique)
    if ($DryRun) {
        Say 'это была только проверка, ничего не трогаю.'
        if (Ask-More) { continue session } else { break session }
    }
    if (($missing.Count + $updates.Count + $manual.Count + $nopy.Count) -eq 0) {
        Write-Host ''; Say 'всё уже на месте. подготовился лучше, чем я ожидал.'
        if (Ask-More) { continue session } else { break session }
    }

    $done = 0; $failed = @()

    # ── установка недостающего ──
    if ($missing.Count -gt 0) {
        Write-Host ''
        if ((Ask ("Установить недостающее ({0} шт.)?" -f $missing.Count) 'y') -in @('y', 'д', 'yes', 'да')) {
            Say 'начинаю. окно не закрывай, это займёт какое-то время.'
            foreach ($p in $missing) {
                if ($p.Item.Kind -eq 'pip' -and -not $py) { $py = Get-PyCmd }
                if ($p.Item.Heavy) {
                    if ((Ask ("{0} весит много. Ставить?" -f $p.Item.Name) 'n') -notin @('y', 'д', 'yes', 'да')) { continue }
                }
                if (Install-Item $p.Item $py) { $done++ } else { $failed += $p.Item.Name }
                if ($p.Item.Kind -eq 'winget') { Refresh-Path }
            }
        }
    }

    # Python мог появиться только что — догоняем pip-пакеты
    if ($nopy.Count -gt 0) {
        Refresh-Path; $py = Get-PyCmd
        if ($py) {
            Load-PipOutdated $py
            foreach ($p in $nopy) {
                $r = Test-Pip $p.Item $py
                if ($r.State -eq 'MISSING') { if (Install-Item $p.Item $py) { $done++ } else { $failed += $p.Item.Name } }
            }
        } else { Boot-Line 'Python так и не найден — pip-пакеты пропущены. Перезапусти консоль и скрипт.' 'WARN' }
    }

    # ── обновления: только с согласия ──
    if ($updates.Count -gt 0) {
        Write-Host ''
        Type-Out '  [!] найдены более свежие версии. решать тебе:' -Color Yellow -Delay 10
        Say 'я бы обновил, но решать тебе.'
        $yesAll = $false
        foreach ($p in $updates) {
            if (-not $yesAll) {
                $a = Ask ("Обновить {0} ({1} -> {2})? (a = да для всех)" -f $p.Item.Name, $p.Res.Cur, $p.Res.New) 'n'
                if ($a -eq 'a') { $yesAll = $true }
                elseif ($a -notin @('y', 'д', 'yes', 'да')) { Log ('skip update ' + $p.Item.Name); Say 'как скажешь, оставим.'; continue }
            }
            if (Install-Item $p.Item $py -Upgrade) { $done++ } else { $failed += $p.Item.Name }
        }
    }

    # ── ручные ──
    foreach ($p in $manual) {
        Write-Host ''
        Say ($p.Item.Name + ' придётся скачать руками. дам ссылку.')
        Write-Host '  ◊ ' -NoNewline -ForegroundColor Cyan
        Write-Host ($p.Item.Name + ' не ставится автоматически: ' + $p.Item.Url) -ForegroundColor Gray
        if ((Ask 'Открыть страницу загрузки в браузере?' 'n') -in @('y', 'д', 'yes', 'да')) { Start-Process $p.Item.Url }
    }

    # ── итог ──
    Write-Host ''
    Write-Host '  ════════════════════════════════════════════════════' -ForegroundColor DarkGreen
    Boot-Line ("выполнено операций: $done") 'OK'
    if ($failed.Count) { Boot-Line ('с ошибкой: ' + ($failed -join ', ')) 'FAIL' }
    Boot-Line ("лог: $script:LogFile") '..'
    Write-Host ''
    Type-Out '  перезапусти терминал, чтобы подхватились новые команды.' -Color DarkGreen -Delay 8
    if ($failed.Count) { Say 'кое-что не встало — пришли мне лог, починим.' } else { Say 'с этим набором готово.' }
    if (Ask-More) { continue session } else { break session }
}

# ── выход ──
Write-Host ''
Say 'на сегодня всё. возвращайся, если понадобится что-то ещё.'
Sign-Off
Write-Host ''
Finish 0
