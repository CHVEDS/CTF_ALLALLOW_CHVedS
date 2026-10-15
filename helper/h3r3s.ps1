<#
    h3r3s — консольный помощник команды на CTF.
    Автор: Heres

    Запуск: h3r3s.cmd (двойной клик)
        .\h3r3s.ps1 -NoIntro        # без заставки
        .\h3r3s.ps1 -NoFullscreen   # не разворачивать на весь экран
        .\h3r3s.ps1 -NoSound        # без звука
        .\h3r3s.ps1 -NoGlitch       # без помех

    Интерфейс — здесь, «мозг» (расшифровка, поиск, анализ) — в engine.py.
#>
[CmdletBinding()]
param(
    [switch]$NoIntro,
    [switch]$NoFullscreen,
    [switch]$NoSound,
    [switch]$NoGlitch,
    [switch]$Child
)

# ── перезапуск в отдельном окне консоли на весь экран ──
if (-not $NoFullscreen -and -not $Child -and $env:OS -eq 'Windows_NT' -and $Host.Name -eq 'ConsoleHost') {
    try {
        $exe = (Get-Process -Id $PID).Path
        $a = @("`"$exe`"", '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Child')
        foreach ($kv in $PSBoundParameters.GetEnumerator()) {
            if ($kv.Value -is [switch]) { if ($kv.Value) { $a += ('-' + $kv.Key) } }
        }
        Start-Process -FilePath "$env:WINDIR\System32\conhost.exe" -ArgumentList $a -WorkingDirectory $PSScriptRoot -ErrorAction Stop
        exit 0
    } catch {
        Write-Host '  [!] не удалось открыть отдельное окно, продолжаю здесь' -ForegroundColor Yellow
    }
}

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$script:LogFile = Join-Path $PSScriptRoot ("logs\h3r3s-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force -Path (Split-Path $script:LogFile) | Out-Null
$Author = 'Heres'

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
            $raw.WindowTitle = 'h3r3s // by Heres'
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
$script:NoiseSeconds = 1.2      # сколько секунд длятся помехи в самом начале
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
        try { $script:StaticBytes = New-StaticSound $script:NoiseSeconds 21 } catch { $script:StaticBytes = $null }
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
        $bp = Pad $script:BW
        $rows = @(0..($Banner.Count - 1) | Get-Random -Count $script:GRnd.Next(2, 5))
        foreach ($r in $rows) { Glitch-At ($bp.Length + [int](($script:BW - $Banner[0].Length) / 2)) ($script:BannerTop + $r) $Banner[$r] 'Green' -Shift }
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
#  ОФОРМЛЕНИЕ HELPER
# ═══════════════════════════════════════════════════════════════════════
$Banner = @(
    '██╗  ██╗██████╗ ██████╗ ██████╗ ███████╗'
    '██║  ██║╚════██╗██╔══██╗╚════██╗██╔════╝'
    '███████║ █████╔╝██████╔╝ █████╔╝███████╗'
    '██╔══██║ ╚═══██╗██╔══██╗ ╚═══██╗╚════██║'
    '██║  ██║██████╔╝██║  ██║██████╔╝███████║'
    '╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚══════╝'
)
$script:BW = 52

function Show-Banner([switch]$Glitch) {
    $bp = Pad $script:BW
    $inner = ' ' * [int](($script:BW - $Banner[0].Length) / 2)
    if ($Glitch -and -not $NoGlitch) {
        $noise = '▓▒░█#@%&*'.ToCharArray()
        for ($k = 0; $k -lt 4; $k++) {
            Clear-Host; Write-Host ''
            foreach ($line in $Banner) {
                $g = -join ($line.ToCharArray() | ForEach-Object { if ($_ -ne ' ' -and (Get-Random -Maximum 5) -eq 0) { $noise | Get-Random } else { $_ } })
                $sh = ' ' * (Get-Random -Minimum 0 -Maximum 4)
                Write-Host ($bp + $inner + $sh + $g) -ForegroundColor (@('Red', 'DarkRed', 'Green', 'White') | Get-Random)
            }
            Start-Sleep -Milliseconds 80
        }
        Clear-Host
    }
    Write-Host ''
    try { $script:BannerTop = [Console]::CursorTop } catch { $script:BannerTop = -1 }
    foreach ($line in $Banner) { Write-Host ($bp + $inner + $line) -ForegroundColor Green }
    Write-Host ($bp + ('─' * $script:BW)) -ForegroundColor DarkGreen
    Write-Host ($bp + '  CTF helper by ') -NoNewline -ForegroundColor DarkGreen
    Write-Host 'Heres' -NoNewline -ForegroundColor Green
    Write-Host '  ::  ' -NoNewline -ForegroundColor DarkGreen
    Write-Host 'decode / hunt / file / scripts' -ForegroundColor DarkGreen
    Write-Host ''
}

# короткие мелодии: успех и «пусто»
$script:ChimeBytes = $null
$script:LowBytes = $null
function New-Chime([int[]]$Freqs, [int]$NoteMs = 70, [double]$Gain = 1.0) {
    $rate = 22050
    $per = [int]($rate * $NoteMs / 1000)
    $tail = [int]($rate * 0.18)
    $n = $per * $Freqs.Count + $tail
    $buf = New-Object 'double[]' $n
    for ($j = 0; $j -lt $Freqs.Count; $j++) {
        $w = 2 * [Math]::PI * $Freqs[$j] / $rate
        $p0 = $j * $per
        $e = 1.0; $dec = [Math]::Exp(-1.0 / ($rate * 0.06))
        for ($k = 0; $k -lt ($per + $tail) -and ($p0 + $k) -lt $n; $k++) {
            $buf[$p0 + $k] += $e * [Math]::Sin($w * $k); $e *= $dec
        }
    }
    $out = New-Object 'int16[]' $n
    $vol = $script:SndVolume * 32767 * $Gain
    for ($i = 0; $i -lt $n; $i++) {
        $x = $buf[$i] * $vol
        if ($x -gt 32767) { $x = 32767 } elseif ($x -lt -32767) { $x = -32767 }
        $out[$i] = [int16]$x
    }
    return New-WavBytes $out $rate
}

function Section([string]$Title) {
    Write-Host ''
    Write-Host '  ╔══[ ' -NoNewline -ForegroundColor DarkGreen
    Write-Host $Title -NoNewline -ForegroundColor Green
    Write-Host (' ]' + ('═' * [Math]::Max(4, 50 - $Title.Length))) -ForegroundColor DarkGreen
}

function Prompt-Line([string]$Label) {
    Write-Host ''
    Write-Host ('  ' + $Label) -NoNewline -ForegroundColor Green
    Write-Host ' ▸ ' -NoNewline -ForegroundColor DarkGray
    return (Read-Host)
}

# «расшифровка» текста на месте: хвост мелькает мусором и по буквам встаёт на место
function Reveal-Text([string]$Text, [ConsoleColor]$Color = 'Green') {
    if ($NoGlitch) { Write-Host $Text -NoNewline -ForegroundColor $Color; return }
    try { $x = [Console]::CursorLeft; $y = [Console]::CursorTop } catch { Write-Host $Text -NoNewline -ForegroundColor $Color; return }
    $n = $Text.Length
    if ($n -eq 0) { return }
    $steps = [Math]::Min(45, $n * 2)
    if ($script:SndOn) { Play-Typing $Text 22 }
    for ($s = 0; $s -le $steps; $s++) {
        $settled = [int]($n * $s / $steps)
        try { [Console]::SetCursorPosition($x, $y) } catch {}
        if ($settled -gt 0) { Write-Host $Text.Substring(0, $settled) -NoNewline -ForegroundColor $Color }
        if ($settled -lt $n) {
            $rest = -join (1..($n - $settled) | ForEach-Object { $script:GlitchNoise[$script:GRnd.Next($script:GlitchNoise.Length)] })
            Write-Host $rest -NoNewline -ForegroundColor DarkGreen
        }
        Start-Sleep -Milliseconds 22
    }
}

function Copy-Clip([string]$Text) {
    try { Set-Clipboard -Value $Text; return $true } catch {}
    try { $Text | clip.exe; return $true } catch {}
    return $false
}

function Flag-Box([string]$Flag, [string]$Title = 'Ф Л А Г   З А Х В А Ч Е Н') {
    $w = [Math]::Max($Flag.Length, $Title.Length) + 8
    $pad = Pad ($w + 2)
    $tl = [int](($w - $Title.Length) / 2)
    $fl = [int](($w - $Flag.Length) / 2)
    Write-Host ''
    Write-Host ($pad + '╔' + ('═' * $w) + '╗') -ForegroundColor Green
    Write-Host ($pad + '║') -NoNewline -ForegroundColor Green
    Write-Host ((' ' * $tl) + $Title + (' ' * ($w - $tl - $Title.Length))) -NoNewline -ForegroundColor Red
    Write-Host '║' -ForegroundColor Green
    Write-Host ($pad + '║' + (' ' * $w) + '║') -ForegroundColor Green
    Write-Host ($pad + '║' + (' ' * $fl)) -NoNewline -ForegroundColor Green
    if ($script:SndOn -and $script:ChimeBytes) { Play-Bytes $script:ChimeBytes }
    Reveal-Text $Flag 'White'
    Write-Host ((' ' * ($w - $fl - $Flag.Length)) + '║') -ForegroundColor Green
    Write-Host ($pad + '║' + (' ' * $w) + '║') -ForegroundColor Green
    Write-Host ($pad + '╚' + ('═' * $w) + '╝') -ForegroundColor Green
    if (Copy-Clip $Flag) { Say 'флаг уже в буфере обмена — Ctrl+V в форму сдачи.' }
}

function Show-Recipe($Recipe) {
    Write-Host '  ' -NoNewline
    Write-Host 'ввод' -NoNewline -ForegroundColor DarkGray
    foreach ($step in @($Recipe)) {
        Write-Host ' ▸ ' -NoNewline -ForegroundColor DarkGray
        Type-Out ([string]$step) -Color Cyan -Delay 18 -NoNewline
        Start-Sleep -Milliseconds 60
    }
    Write-Host ' ▸ ' -NoNewline -ForegroundColor DarkGray
    Write-Host 'флаг' -ForegroundColor Red
}

function Entropy-Bar([double]$E) {
    $cells = 24
    $fill = [int][Math]::Round($cells * $E / 8)
    $col = if ($E -gt 7.2) { 'Red' } elseif ($E -gt 5.5) { 'Yellow' } else { 'Green' }
    Write-Host '▕' -NoNewline -ForegroundColor DarkGray
    Write-Host ('█' * $fill) -NoNewline -ForegroundColor $col
    Write-Host ('░' * ($cells - $fill)) -NoNewline -ForegroundColor DarkGray
    Write-Host '▏ ' -NoNewline -ForegroundColor DarkGray
    Write-Host ('{0:0.00} / 8' -f $E) -ForegroundColor $col
}

# ═══════════════════════════════════════════════════════════════════════
#  СВЯЗЬ С ДВИЖКОМ (engine.py)
# ═══════════════════════════════════════════════════════════════════════
$script:Engine = Join-Path $PSScriptRoot 'engine.py'
$script:Py = $null

function Find-Python {
    # Спрашиваем у самого Python путь к настоящему python.exe (sys.executable).
    # Так обходим ярлыки-псевдонимы из WindowsApps (Python Install Manager, Microsoft Store),
    # которые не запускаются в фоне с перехватом вывода.
    foreach ($cand in @('py', 'python', 'python3')) {
        if (-not (Get-Command $cand -ErrorAction SilentlyContinue)) { continue }
        try {
            $exe = & $cand -c "import sys; print(sys.executable)" 2>$null | Select-Object -First 1
            if ($exe) {
                $exe = ([string]$exe).Trim()
                if ($exe -and $exe -notmatch 'WindowsApps' -and (Test-Path -LiteralPath $exe)) { return $exe }
            }
        } catch {}
    }
    # запасной вариант: ищем python.exe в типичных папках установки
    foreach ($root in @("$env:LocalAppData\Python", "$env:LocalAppData\Programs\Python", "$env:ProgramFiles\Python*", "C:\Python*")) {
        $hit = Get-ChildItem -Path $root -Filter python.exe -Recurse -Depth 3 -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch 'WindowsApps|\\venv|\\Scripts\\' } | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

function Quote-Arg([string]$s) {
    if ($s -match '^[A-Za-z]:\\$') { $s = $s + '.' }
    $s = $s.TrimEnd('\')
    return '"' + ($s -replace '"', '\"') + '"'
}

function Invoke-Engine([string[]]$EArgs, [string]$Label = 'обработка', [int]$MinMs = 700) {
    $outF = [IO.Path]::GetTempFileName(); $errF = [IO.Path]::GetTempFileName()
    $argStr = (@((Quote-Arg $script:Engine)) + @($EArgs | ForEach-Object { Quote-Arg $_ })) -join ' '
    try {
        $p = Start-Process -FilePath $script:Py -ArgumentList $argStr -NoNewWindow -PassThru `
            -RedirectStandardOutput $outF -RedirectStandardError $errF -ErrorAction Stop
    } catch {
        return [pscustomobject]@{ error = "не удалось запустить Python: $($_.Exception.Message)" }
    }
    $frames = @('|', '/', '-', '\'); $i = 0
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $y = -1; try { $y = [Console]::CursorTop } catch {}
    while (-not $p.HasExited -or $sw.ElapsedMilliseconds -lt $MinMs) {
        if ($y -ge 0) {
            try {
                [Console]::SetCursorPosition(0, $y)
                $hex = -join (1..10 | ForEach-Object { '{0:x2} ' -f $script:GRnd.Next(256) })
                Write-Host '  [' -NoNewline -ForegroundColor DarkGray
                Write-Host $frames[$i % 4] -NoNewline -ForegroundColor Green
                Write-Host ('] ' + $Label + '  ') -NoNewline -ForegroundColor Gray
                Write-Host ('{0,5:0.0}s  ' -f $sw.Elapsed.TotalSeconds) -NoNewline -ForegroundColor DarkGray
                Write-Host $hex -NoNewline -ForegroundColor DarkGreen
            } catch {}
        }
        $i++; Start-Sleep -Milliseconds 70
    }
    $p.WaitForExit()
    if ($y -ge 0) { try { [Console]::SetCursorPosition(0, $y); Write-Host (' ' * ([Console]::WindowWidth - 1)) -NoNewline; [Console]::SetCursorPosition(0, $y) } catch {} }
    Boot-Line ('{0} — {1:0.0} c' -f $Label, $sw.Elapsed.TotalSeconds) 'OK'
    $raw = ''
    try { $raw = [IO.File]::ReadAllText($outF) } catch {}
    $err = ''
    try { $err = [IO.File]::ReadAllText($errF) } catch {}
    Remove-Item $outF, $errF -ErrorAction SilentlyContinue
    if (-not $raw.Trim()) { return [pscustomobject]@{ error = ('движок ничего не вернул. ' + $err.Trim()) } }
    try { return ($raw | ConvertFrom-Json) } catch { return [pscustomobject]@{ error = 'движок вернул непонятный ответ' } }
}

function Clean-Path([string]$p) {
    if (-not $p) { return '' }
    $p = $p.Trim().Trim('"').Trim("'").Trim()
    if ($p.StartsWith('& ')) { $p = $p.Substring(2).Trim().Trim("'").Trim('"') }
    return $p
}

# ═══════════════════════════════════════════════════════════════════════
#  МОДУЛИ
# ═══════════════════════════════════════════════════════════════════════
function Hint([string[]]$Lines) {
    Write-Host '  ┌─ как пользоваться ' -NoNewline -ForegroundColor DarkGray
    Write-Host ('─' * 34) -ForegroundColor DarkGray
    foreach ($l in $Lines) {
        Write-Host '  │ ' -NoNewline -ForegroundColor DarkGray
        Write-Host $l -ForegroundColor Gray
    }
    Write-Host '  │ ' -NoNewline -ForegroundColor DarkGray
    Write-Host 'пустой Enter' -NoNewline -ForegroundColor Green
    Write-Host ' — выйти в меню' -ForegroundColor Gray
    Write-Host ('  └' + ('─' * 53)) -ForegroundColor DarkGray
}

function Module-Decode {
    Section 'МАГИЧЕСКИЙ ДЕКОДЕР'
    Hint @(
        'вставь закодированную строку (Ctrl+V или правый клик мышью)',
        'или перетащи файл мышкой в окно — расшифрую его содержимое',
        'слои (base64, hex, url, xor...) снимаю сам, флаг — в буфер обмена'
    )
    Say (Pick @('кидай шифровку. посмотрим, сколько там слоёв.', 'давай сюда. base64, hex, xor — без разницы.', 'жду строку или файл.'))
    while ($true) {
        $s = Prompt-Line 'decode'
        if ([string]::IsNullOrWhiteSpace($s)) { Say 'выхожу в меню.'; return }
        $asPath = Clean-Path $s
        $tmp = $null
        if ((Test-Path -LiteralPath $asPath -PathType Leaf -ErrorAction SilentlyContinue)) {
            $len = (Get-Item -LiteralPath $asPath).Length
            if ($len -gt 2MB) {
                Boot-Line ("файл большой ({0:N0} байт) — для него лучше модуль 2 «Охотник»" -f $len) 'WARN'
                continue
            }
            Boot-Line ("беру содержимое файла: {0} ({1:N0} байт)" -f (Split-Path $asPath -Leaf), $len) 'OK'
            $srcFile = $asPath
        } else {
            $tmp = [IO.Path]::GetTempFileName()
            [IO.File]::WriteAllText($tmp, $s, (New-Object Text.UTF8Encoding $false))
            $srcFile = $tmp
        }
        $r = Invoke-Engine @('decode', $srcFile) 'разворачиваю слои'
        if ($tmp) { Remove-Item $tmp -ErrorAction SilentlyContinue }
        if ($r.error) { Boot-Line $r.error 'FAIL'; continue }
        $found = @($r.found)
        if ($found.Count -gt 0) {
            Show-Recipe $found[0].recipe
            Flag-Box $found[0].flag
            foreach ($f in $found | Select-Object -Skip 1) {
                Write-Host '  ещё вариант: ' -NoNewline -ForegroundColor DarkGray
                Write-Host $f.flag -NoNewline -ForegroundColor White
                Write-Host ('  [' + (@($f.recipe) -join ' > ') + ']') -ForegroundColor DarkGray
            }
            Say (Pick @('слои сняты. забирай. давай следующую.', 'есть. кидай следующую.', 'чистая работа. ещё?'))
        } elseif (@($r.readable).Count -gt 0) {
            if ($script:SndOn -and $script:LowBytes) { Play-Bytes $script:LowBytes }
            Write-Host ''
            Write-Host '  флага нет, но вот что удалось раскодировать:' -ForegroundColor Yellow
            $n = 0
            foreach ($o in @($r.readable)) {
                $n++
                Write-Host ("  {0}) " -f $n) -NoNewline -ForegroundColor DarkGray
                Write-Host (@($o.recipe) -join ' ▸ ') -ForegroundColor Cyan
                Write-Host '     ' -NoNewline
                Reveal-Text ([string]$o.text) 'White'
                Write-Host ''
            }
            Say 'если это снова похоже на шифровку — скопируй результат и вставь ещё раз.'
        } else {
            if ($script:SndOn -and $script:LowBytes) { Play-Bytes $script:LowBytes }
            Say 'не поддалось. проверь, что строка вставилась целиком, или попробуй в CyberChef.'
        }
    }
}

function Module-Hunt {
    Section 'ОХОТНИК ЗА ФЛАГОМ'
    Hint @(
        'перетащи мышкой файл или целую папку в окно и нажми Enter',
        'прочешу всё: текст, UTF-16, закодированные куски, архивы zip/gz',
        'найденный флаг сразу окажется в буфере обмена'
    )
    Say 'неси улики. проверю каждую.'
    while ($true) {
        $path = Clean-Path (Prompt-Line 'путь')
        if (-not $path) { Say 'выхожу в меню.'; return }
        if (-not (Test-Path -LiteralPath $path)) { Boot-Line "не нашёл: $path" 'FAIL'; continue }
        $r = Invoke-Engine @('hunt', $path) 'прочёсываю файлы' 1500
        if ($r.error) { Boot-Line $r.error 'FAIL'; continue }
        Boot-Line ("просмотрено файлов: {0}" -f $r.files) 'OK'
        $hits = @($r.hits)
        if ($hits.Count -eq 0) {
            if ($script:SndOn -and $script:LowBytes) { Play-Bytes $script:LowBytes }
            Say 'флага нет ни в открытом, ни в закодированном виде. подозрительный файл — в модуль 3. давай следующий путь.'
            continue
        }
        Write-Host ''
        foreach ($h in $hits | Select-Object -First 25) {
            Write-Host '  [' -NoNewline -ForegroundColor DarkGray
            Write-Host 'FLAG' -NoNewline -ForegroundColor Red
            Write-Host '] ' -NoNewline -ForegroundColor DarkGray
            Reveal-Text ([string]$h.flag) 'White'
            Write-Host ''
            $rec = if (@($h.recipe).Count) { '  [' + (@($h.recipe) -join ' > ') + ']' } else { '  [в открытом виде]' }
            Write-Host ('         ' + $h.src + $rec) -ForegroundColor DarkGray
        }
        $uniq = @($hits | ForEach-Object { $_.flag } | Select-Object -Unique)
        Flag-Box $uniq[0]
        if ($uniq.Count -gt 1) { Say ("разных флагов: {0}. в буфере первый, остальные — в списке выше." -f $uniq.Count) }
        Say 'следующий путь — или пустой Enter, чтобы выйти.'
    }
}

function Module-File {
    Section 'ЧТО ЭТО ЗА ФАЙЛ'
    Hint @(
        'перетащи файл мышкой в окно и нажми Enter',
        'скажу, что это на самом деле, даже если расширение врёт',
        'покажу энтропию, вложенные файлы и строки'
    )
    while ($true) {
        $path = Clean-Path (Prompt-Line 'файл')
        if (-not $path) { Say 'выхожу в меню.'; return }
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Boot-Line "это не файл: $path" 'FAIL'; continue }
        $r = Invoke-Engine @('file', $path) 'вскрываю файл'
        if ($r.error) { Boot-Line $r.error 'FAIL'; continue }
        Write-Host ''
        Write-Host '  тип       ' -NoNewline -ForegroundColor DarkGray; Write-Host $r.type -ForegroundColor White
        Write-Host '  размер    ' -NoNewline -ForegroundColor DarkGray; Write-Host ("{0:N0} байт" -f [long]$r.size) -ForegroundColor White
        Write-Host '  энтропия  ' -NoNewline -ForegroundColor DarkGray; Entropy-Bar ([double]$r.entropy)
        if ([double]$r.entropy -gt 7.2) { Boot-Line 'энтропия высокая — данные сжаты или зашифрованы' 'WARN' }
        if ($r.ext_mismatch) { Boot-Line ("расширение {0} не совпадает с содержимым — файл замаскирован" -f $r.ext_mismatch) 'WARN' }
        $emb = @($r.embedded)
        if ($emb.Count) {
            Write-Host ''
            Write-Host '  вложенные файлы:' -ForegroundColor Yellow
            foreach ($e in $emb) {
                Write-Host ('    0x{0:x8}  ' -f [long]$e.offset) -NoNewline -ForegroundColor DarkGray
                Write-Host $e.name -ForegroundColor Yellow
            }
            Say 'внутри что-то спрятано — прогони этот же файл через модуль 2, он заглянет в архивы.'
        }
        $strs = @($r.strings)
        if ($strs.Count) {
            Write-Host ''
            Write-Host '  строки:' -ForegroundColor DarkGray
            foreach ($t in $strs) { Write-Host ('    ' + $t) -ForegroundColor DarkGreen }
        }
        $flags = @($r.flags)
        if ($flags.Count) { Flag-Box $flags[0] }
        elseif (-not $emb.Count) { Say 'флага в строках нет. высокая энтропия — копай блобы через декодер.' }
        Say 'следующий файл — или пустой Enter, чтобы выйти.'
    }
}

function Module-Templates {
    Section 'ШАБЛОНЫ СКРИПТОВ'
    $r = Invoke-Engine @('templates') 'загружаю шаблоны' 300
    if ($r.error) { Boot-Line $r.error 'FAIL'; return }
    $list = @($r.templates)
    Hint @('введи номер шаблона — сохраню его в helper\scripts и открою папку')
    while ($true) {
        Write-Host ''
        for ($i = 0; $i -lt $list.Count; $i++) {
            Write-Host ("  [{0}] " -f ($i + 1)) -NoNewline -ForegroundColor Green
            Write-Host ('{0,-16}' -f $list[$i].file) -NoNewline -ForegroundColor White
            Write-Host $list[$i].about -ForegroundColor DarkGray
        }
        $sel = Prompt-Line 'номер'
        if ([string]::IsNullOrWhiteSpace($sel)) { Say 'выхожу в меню.'; return }
        if (-not ($sel -match '^\d+$') -or [int]$sel -lt 1 -or [int]$sel -gt $list.Count) { Boot-Line 'нет такого номера' 'FAIL'; continue }
        $dir = Join-Path $PSScriptRoot 'scripts'
        $res = Invoke-Engine @('template', $list[[int]$sel - 1].key, $dir) 'сохраняю' 300
        if ($res.error) { Boot-Line $res.error 'FAIL'; continue }
        if ($script:SndOn -and $script:ChimeBytes) { Play-Bytes $script:ChimeBytes }
        Boot-Line ("сохранено: " + $res.saved) 'OK'
        Say 'открываю папку. подставь свои значения и запускай: py имя_скрипта.py'
        try { Invoke-Item $dir } catch {}
    }
}

$Menu = @(
    @{ Name = 'Магический декодер'; Desc = 'base64 / hex / url / base85 / rot / XOR — слои снимает сам'; Fn = 'Module-Decode' }
    @{ Name = 'Охотник за флагом';  Desc = 'ищет SOLARCTF{...} в файлах и папках, вкл. UTF-16';        Fn = 'Module-Hunt' }
    @{ Name = 'Что это за файл';    Desc = 'тип, энтропия, вложенные файлы, строки';                   Fn = 'Module-File' }
    @{ Name = 'Шаблоны скриптов';   Desc = 'PPC / z3 / XOR / HTTP — готовые заготовки';                Fn = 'Module-Templates' }
)

function Show-Menu {
    Write-Host ''
    Write-Host '  ┌─[ МОДУЛИ ]──────────────────────────────────────────' -ForegroundColor DarkGreen
    for ($i = 0; $i -lt $Menu.Count; $i++) {
        Write-Host '  │  ' -NoNewline -ForegroundColor DarkGreen
        Write-Host ("[{0}] " -f ($i + 1)) -NoNewline -ForegroundColor Green
        Write-Host ('{0,-20}' -f $Menu[$i].Name) -NoNewline -ForegroundColor White
        Write-Host $Menu[$i].Desc -ForegroundColor DarkGray
    }
    Write-Host '  │  ' -NoNewline -ForegroundColor DarkGreen
    Write-Host '[C] очистить экран   [Q] выход' -ForegroundColor DarkGray
    Write-Host '  └─' -NoNewline -ForegroundColor DarkGreen
    Write-Host 'team@h3r3s' -NoNewline -ForegroundColor Green
    Write-Host ':~# ' -NoNewline -ForegroundColor Gray
}

# ═══════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════
Init-Sound
if ($script:SndOn) {
    try { $script:ChimeBytes = New-Chime @(660, 880, 1320) 70 1.1 } catch {}
    try { $script:LowBytes = New-Chime @(330, 220) 110 0.9 } catch {}
}
if ($Child) { Enter-Fullscreen }

if (-not $NoIntro) {
    Signal-Noise $script:NoiseSeconds
    Matrix-Rain 16
    Show-Banner -Glitch
    Hex-Noise 2
    Write-Host ''
    Boot-Line 'загрузка движка...' '..'
} else {
    Show-Banner
}

$script:Py = Find-Python
if (-not $script:Py) {
    Boot-Line 'Python не найден' 'FAIL'
    Say 'мне нужен Python. запусти install.cmd, выбери набор BASE и перезапусти меня.'
    Finish 1
}
if (-not (Test-Path $script:Engine)) { Boot-Line 'нет файла engine.py рядом со мной' 'FAIL'; Finish 1 }
Boot-Line ("python: " + $script:Py) 'OK'
if (-not $NoIntro) {
    Boot-Line 'модуль decode    — base64 / base32 / base85 / hex / url / rot13 / xor' 'OK'
    Boot-Line 'модуль hunt      — ascii + utf-16, блобы, gzip' 'OK'
    Boot-Line 'модуль file      — сигнатуры, энтропия, вложения' 'OK'
    Boot-Line 'модуль scripts   — ppc / z3 / xor / http' 'OK'
    Glitch-Banner
}
Say (Pick @('на связи. что разбираем?', 'готов. неси задачу.', 'флаги сами себя не найдут. поехали.'))

while ($true) {
    Show-Menu
    $sel = (Read-Host).Trim().ToLower()
    if ($sel -in @('q', 'й', 'exit', 'quit')) { break }
    if ($sel -in @('c', 'с')) { Clear-Host; Show-Banner; continue }
    if ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $Menu.Count) {
        & $Menu[[int]$sel - 1].Fn
    }
}

Sign-Off 'удачи на SolarCTF. принеси флагов.'
Write-Host ''
Finish 0
