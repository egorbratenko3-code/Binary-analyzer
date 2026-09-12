param(
    [string]$Path = ".\real.dll"
)

$ErrorActionPreference = "Stop"

# ============================================================
# real.dll binary analyzer
# Works with old Windows PowerShell 5.1
# No external programs/modules required.
# ============================================================

function Hex([byte[]]$Data, [int]$Max = 64) {
    $n = [Math]::Min($Data.Length, $Max)
    return (($Data[0..($n-1)] | ForEach-Object { "{0:X2}" -f $_ }) -join " ")
}

function ASCII([byte[]]$Data, [int]$Max = 128) {
    $n = [Math]::Min($Data.Length, $Max)
    -join ($Data[0..($n-1)] | ForEach-Object {
        if ($_ -ge 32 -and $_ -le 126) {
            [char]$_
        } else {
            "."
        }
    })
}

function Get-Entropy([byte[]]$Data, [int]$Offset = 0, [int]$Length = -1) {
    if ($Length -lt 0) {
        $Length = $Data.Length - $Offset
    }

    if ($Length -le 0) {
        return 0
    }

    $counts = New-Object int[] 256

    for ($i = $Offset; $i -lt ($Offset + $Length); $i++) {
        $counts[$Data[$i]]++
    }

    $entropy = 0.0

    foreach ($c in $counts) {
        if ($c -gt 0) {
            $p = $c / [double]$Length
            $entropy -= $p * [Math]::Log($p, 2)
        }
    }

    return $entropy
}

function Find-Bytes(
    [byte[]]$Data,
    [byte[]]$Pattern,
    [int]$MaxResults = 100
) {
    $results = New-Object System.Collections.Generic.List[int]

    if ($Pattern.Length -eq 0) {
        return $results
    }

    for ($i = 0; $i -le ($Data.Length - $Pattern.Length); $i++) {
        $ok = $true

        for ($j = 0; $j -lt $Pattern.Length; $j++) {
            if ($Data[$i + $j] -ne $Pattern[$j]) {
                $ok = $false
                break
            }
        }

        if ($ok) {
            $results.Add($i)

            if ($results.Count -ge $MaxResults) {
                break
            }
        }
    }

    return $results
}

function Find-ASCII-Strings(
    [byte[]]$Data,
    [int]$MinLength = 5
) {
    $results = New-Object System.Collections.Generic.List[object]
    $start = -1

    for ($i = 0; $i -lt $Data.Length; $i++) {

        $printable = ($Data[$i] -ge 32 -and $Data[$i] -le 126)

        if ($printable) {
            if ($start -lt 0) {
                $start = $i
            }
        }
        else {
            if ($start -ge 0) {
                $len = $i - $start

                if ($len -ge $MinLength) {
                    $s = [Text.Encoding]::ASCII.GetString(
                        $Data,
                        $start,
                        $len
                    )

                    $results.Add([PSCustomObject]@{
                        Offset = $start
                        Length = $len
                        String = $s
                    })
                }
            }

            $start = -1
        }
    }

    return $results
}

function Find-UnicodeStrings(
    [byte[]]$Data,
    [int]$MinLength = 5
) {
    $results = New-Object System.Collections.Generic.List[object]

    $start = -1

    for ($i = 0; $i -lt ($Data.Length - 1); $i += 2) {

        $lo = $Data[$i]
        $hi = $Data[$i + 1]

        $printable = ($hi -eq 0 -and $lo -ge 32 -and $lo -le 126)

        if ($printable) {
            if ($start -lt 0) {
                $start = $i
            }
        }
        else {
            if ($start -ge 0) {
                $len = $i - $start

                if (($len / 2) -ge $MinLength) {
                    $s = [Text.Encoding]::Unicode.GetString(
                        $Data,
                        $start,
                        $len
                    )

                    $results.Add([PSCustomObject]@{
                        Offset = $start
                        Length = $len
                        String = $s
                    })
                }
            }

            $start = -1
        }
    }

    return $results
}

function UInt16LE([byte[]]$D, [int]$O) {
    return [BitConverter]::ToUInt16($D, $O)
}

function UInt32LE([byte[]]$D, [int]$O) {
    return [BitConverter]::ToUInt32($D, $O)
}

function UInt64LE([byte[]]$D, [int]$O) {
    return [BitConverter]::ToUInt64($D, $O)
}

function Check-PEAt(
    [byte[]]$Data,
    [int]$Offset
) {
    $result = [ordered]@{
        Offset = $Offset
        ValidPE = $false
        Reason = ""
    }

    if ($Offset + 0x40 -gt $Data.Length) {
        $result.Reason = "Not enough bytes for DOS header"
        return [PSCustomObject]$result
    }

    if ($Data[$Offset] -ne 0x4D -or $Data[$Offset+1] -ne 0x5A) {
        $result.Reason = "Not MZ"
        return [PSCustomObject]$result
    }

    $lfanew = UInt32LE $Data ($Offset + 0x3C)

    if ($lfanew -gt 0x10000000) {
        $result.Reason = "e_lfanew is absurd"
        return [PSCustomObject]$result
    }

    $pe = $Offset + [int]$lfanew

    if ($pe + 24 -gt $Data.Length) {
        $result.Reason = "PE header outside file"
        return [PSCustomObject]$result
    }

    if (
        $Data[$pe] -ne 0x50 -or
        $Data[$pe+1] -ne 0x45 -or
        $Data[$pe+2] -ne 0x00 -or
        $Data[$pe+3] -ne 0x00
    ) {
        $result.Reason = "MZ but e_lfanew does not point to PE"
        $result.PEOffset = $pe
        return [PSCustomObject]$result
    }

    $machine = UInt16LE $Data ($pe + 4)
    $sections = UInt16LE $Data ($pe + 6)
    $optionalSize = UInt16LE $Data ($pe + 20)
    $optionalMagic = UInt16LE $Data ($pe + 24)

    $result.ValidPE = $true
    $result.PEOffset = $pe
    $result.Machine = ("0x{0:X4}" -f $machine)
    $result.Sections = $sections
    $result.OptionalMagic = ("0x{0:X4}" -f $optionalMagic)
    $result.OptionalHeaderSize = $optionalSize

    return [PSCustomObject]$result
}

# ============================================================
# LOAD
# ============================================================

if ([IO.Path]::IsPathRooted($Path)) {
    $FullPath = $Path
}
else {
    $FullPath = Join-Path (Get-Location).Path $Path
}

if (!(Test-Path -LiteralPath $FullPath)) {
    throw "File not found: $FullPath"
}

$FullPath = (Get-Item -LiteralPath $FullPath).FullName

Write-Host ""
Write-Host "============================================================"
Write-Host " REAL.DLL BINARY ANALYSIS"
Write-Host "============================================================"
Write-Host ""

Write-Host "File:"
Write-Host "  $FullPath"

$FileInfo = Get-Item -LiteralPath $FullPath

Write-Host ""
Write-Host "[1] BASIC INFO"
Write-Host "------------------------------------------------------------"
Write-Host ("Size       : {0} bytes ({1:N2} MiB)" -f `
    $FileInfo.Length,
    ($FileInfo.Length / 1MB))

$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $FullPath).Hash
Write-Host "SHA256     : $sha"

$b = [IO.File]::ReadAllBytes($FullPath)

Write-Host ""
Write-Host "First 64 bytes:"
Write-Host (Hex $b 64)

Write-Host ""
Write-Host "ASCII preview:"
Write-Host (ASCII $b 128)

# ============================================================
# MAGIC SIGNATURES
# ============================================================

Write-Host ""
Write-Host "[2] MAGIC SIGNATURES"
Write-Host "------------------------------------------------------------"

$magic = @(
    @{ Name="MZ";       Bytes=([byte[]](0x4D,0x5A)) },
    @{ Name="PE";       Bytes=([byte[]](0x50,0x45,0x00,0x00)) },
    @{ Name="ELF";      Bytes=([byte[]](0x7F,0x45,0x4C,0x46)) },
    @{ Name="Mach-O32"; Bytes=([byte[]](0xCE,0xFA,0xED,0xFE)) },
    @{ Name="Mach-O64"; Bytes=([byte[]](0xCF,0xFA,0xED,0xFE)) },
    @{ Name="Mach-O BE";Bytes=([byte[]](0xFE,0xED,0xFA,0xCE)) },
    @{ Name="ZIP";      Bytes=([byte[]](0x50,0x4B,0x03,0x04)) },
    @{ Name="GZIP";     Bytes=([byte[]](0x1F,0x8B)) },
    @{ Name="BZIP2";    Bytes=([byte[]](0x42,0x5A,0x68)) },
    @{ Name="7ZIP";     Bytes=([byte[]](0x37,0x7A,0xBC,0xAF,0x27,0x1C)) },
    @{ Name="RAR";      Bytes=([byte[]](0x52,0x61,0x72,0x21)) },
    @{ Name="PDF";      Bytes=([byte[]](0x25,0x50,0x44,0x46)) },
    @{ Name="SQLite";   Bytes=([byte[]](0x53,0x51,0x4C,0x69,0x74,0x65)) },
    @{ Name="PNG";      Bytes=([byte[]](0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A)) }
)

foreach ($m in $magic) {
    $hits = Find-Bytes $b $m.Bytes 10

    if ($hits.Count -gt 0) {
        $locations = ($hits | ForEach-Object {
            "0x{0:X}" -f $_
        }) -join ", "

        Write-Host ("{0,-12}: FOUND at {1}" -f $m.Name, $locations)
    }
    else {
        Write-Host ("{0,-12}: not found" -f $m.Name)
    }
}

# ============================================================
# MZ / PE ANALYSIS
# ============================================================

Write-Host ""
Write-Host "[3] MZ / PE ANALYSIS"
Write-Host "------------------------------------------------------------"

$mz = Find-Bytes $b ([byte[]](0x4D,0x5A)) 10000
$pe = Find-Bytes $b ([byte[]](0x50,0x45,0x00,0x00)) 10000

Write-Host ("MZ occurrences : {0}" -f $mz.Count)
Write-Host ("PE occurrences : {0}" -f $pe.Count)

$validPEs = @()

foreach ($off in $mz) {
    $r = Check-PEAt $b $off

    if ($r.ValidPE) {
        $validPEs += $r
    }
}

Write-Host ("Valid PE files : {0}" -f $validPEs.Count)

if ($validPEs.Count -gt 0) {

    foreach ($r in $validPEs) {
        Write-Host ""
        Write-Host ("VALID PE @ 0x{0:X}" -f $r.Offset)
        Write-Host ("  PE header    : 0x{0:X}" -f $r.PEOffset)
        Write-Host ("  Machine      : {0}" -f $r.Machine)
        Write-Host ("  Sections     : {0}" -f $r.Sections)
        Write-Host ("  Optional     : {0}" -f $r.OptionalMagic)
    }

}
else {
    Write-Host "No valid PE header was found."
}

# ============================================================
# ENTROPY
# ============================================================

Write-Host ""
Write-Host "[4] ENTROPY"
Write-Host "------------------------------------------------------------"

$ent = Get-Entropy $b

Write-Host ("Whole file entropy : {0:N4} bits/byte" -f $ent)

if ($ent -gt 7.5) {
    Write-Host "Interpretation     : VERY HIGH - likely compressed/encrypted/random-like data"
}
elseif ($ent -gt 7.0) {
    Write-Host "Interpretation     : HIGH - compression/encryption/packed data possible"
}
elseif ($ent -gt 6.0) {
    Write-Host "Interpretation     : MODERATE/HIGH"
}
else {
    Write-Host "Interpretation     : relatively structured"
}

Write-Host ""
Write-Host "1 MiB block entropy:"

$blockSize = 1MB

for ($offset = 0; $offset -lt $b.Length; $offset += $blockSize) {

    $len = [Math]::Min($blockSize, $b.Length - $offset)

    $e = Get-Entropy $b $offset $len

    Write-Host ("  0x{0:X8} - 0x{1:X8} : {2:N4}" -f `
        $offset,
        ($offset + $len - 1),
        $e)
}

# ============================================================
# BYTE FREQUENCY
# ============================================================

Write-Host ""
Write-Host "[5] BYTE FREQUENCY"
Write-Host "------------------------------------------------------------"

$freq = New-Object int[] 256

foreach ($x in $b) {
    $freq[$x]++
}

$top = 0..255 |
    ForEach-Object {
        [PSCustomObject]@{
            Byte = $_
            Count = $freq[$_]
            Hex = ("{0:X2}" -f $_)
        }
    } |
    Sort-Object Count -Descending |
    Select-Object -First 20

$top | Format-Table -AutoSize

# ============================================================
# STRINGS
# ============================================================

Write-Host ""
Write-Host "[6] ASCII STRINGS"
Write-Host "------------------------------------------------------------"

$strings = Find-ASCII-Strings $b 6

Write-Host ("Found {0} ASCII strings >= 6 chars" -f $strings.Count)

$interestingRegex = `
    "UPX|VMProtect|Themida|ASPack|MPRESS|Enigma|LLVM|GCC|clang|MSVC|Microsoft|Borland|MinGW|C\+\+|Python|Go build|Rust|Java|Node|Electron|Qt|OpenSSL|zlib|LZMA|7-Zip|ZIP|PECompact|Obsidium"

$interesting = $strings |
    Where-Object {
        $_.String -match $interestingRegex
    } |
    Select-Object -First 100

if ($interesting.Count -gt 0) {
    $interesting | Format-Table -AutoSize
}
else {
    Write-Host "No obvious compiler/packer strings found."
}

Write-Host ""
Write-Host "[7] FIRST ASCII STRINGS"
Write-Host "------------------------------------------------------------"

$strings |
    Select-Object -First 100 |
    Format-Table -AutoSize

# ============================================================
# UNICODE STRINGS
# ============================================================

Write-Host ""
Write-Host "[8] UNICODE STRINGS"
Write-Host "------------------------------------------------------------"

$ustrings = Find-UnicodeStrings $b 5

Write-Host ("Found {0} UTF-16LE strings >= 5 chars" -f $ustrings.Count)

$ustrings |
    Select-Object -First 50 |
    Format-Table -AutoSize

# ============================================================
# REPEATED 8-BYTE PATTERNS
# ============================================================

Write-Host ""
Write-Host "[9] REPEATED 8-BYTE PATTERNS"
Write-Host "------------------------------------------------------------"

$patterns = @{}

for ($i = 0; $i -le $b.Length - 8; $i++) {

    $key = (
        "{0:X2}{1:X2}{2:X2}{3:X2}{4:X2}{5:X2}{6:X2}{7:X2}" -f
        $b[$i],
        $b[$i+1],
        $b[$i+2],
        $b[$i+3],
        $b[$i+4],
        $b[$i+5],
        $b[$i+6],
        $b[$i+7]
    )

    if ($patterns.ContainsKey($key)) {
        $patterns[$key]++
    }
    else {
        $patterns[$key] = 1
    }
}

$repeated = $patterns.GetEnumerator() |
    Where-Object { $_.Value -ge 20 } |
    Sort-Object Value -Descending |
    Select-Object -First 30

if ($repeated.Count -gt 0) {
    $repeated |
        ForEach-Object {
            [PSCustomObject]@{
                Pattern = $_.Key
                Count = $_.Value
            }
        } |
        Format-Table -AutoSize
}
else {
    Write-Host "No heavily repeated 8-byte patterns."
}

# ============================================================
# ZERO / FF / REPETITION ANALYSIS
# ============================================================

Write-Host ""
Write-Host "[10] SIMPLE STRUCTURE CHECK"
Write-Host "------------------------------------------------------------"

$zero = ($freq[0] / [double]$b.Length) * 100
$ff   = ($freq[255] / [double]$b.Length) * 100

Write-Host ("00 bytes : {0:N2}%" -f $zero)
Write-Host ("FF bytes : {0:N2}%" -f $ff)

# ============================================================
# XOR TEST
# ============================================================

Write-Host ""
Write-Host "[11] SINGLE-BYTE XOR TEST"
Write-Host "------------------------------------------------------------"

# Score first 64 KiB against printable ASCII.
$sampleLen = [Math]::Min(65536, $b.Length)

$xorResults = New-Object System.Collections.Generic.List[object]

for ($key = 0; $key -lt 256; $key++) {

    $score = 0

    for ($i = 0; $i -lt $sampleLen; $i++) {

        $x = $b[$i] -bxor $key

        if (($x -ge 32 -and $x -le 126) -or $x -eq 9 -or $x -eq 10 -or $x -eq 13) {
            $score++
        }
    }

    $xorResults.Add([PSCustomObject]@{
        Key = ("0x{0:X2}" -f $key)
        Score = $score
        Percent = (($score / [double]$sampleLen) * 100)
    })
}

$xorResults |
    Sort-Object Score -Descending |
    Select-Object -First 10 |
    Format-Table -AutoSize

# ============================================================
# XOR PREVIEW
# ============================================================

Write-Host ""
Write-Host "[12] BEST XOR PREVIEWS"
Write-Host "------------------------------------------------------------"

$bestKeys = $xorResults |
    Sort-Object Score -Descending |
    Select-Object -First 5

foreach ($r in $bestKeys) {

    $key = [Convert]::ToInt32(
        $r.Key.Substring(2),
        16
    )

    $preview = ""

    for ($i = 0; $i -lt 128 -and $i -lt $b.Length; $i++) {

        $x = $b[$i] -bxor $key

        if ($x -ge 32 -and $x -le 126) {
            $preview += [char]$x
        }
        else {
            $preview += "."
        }
    }

    Write-Host ("KEY {0}: {1}" -f $r.Key, $preview)
}

# ============================================================
# HASHES OF CHUNKS
# ============================================================

Write-Host ""
Write-Host "[13] CHUNK HASHES"
Write-Host "------------------------------------------------------------"

$sha256 = [Security.Cryptography.SHA256]::Create()

for ($offset = 0; $offset -lt $b.Length; $offset += 1MB) {

    $len = [Math]::Min(1MB, $b.Length - $offset)

    $chunk = New-Object byte[] $len

    [Array]::Copy(
        $b,
        $offset,
        $chunk,
        0,
        $len
    )

    $hash = [BitConverter]::ToString(
        $sha256.ComputeHash($chunk)
    ).Replace("-", "")

    Write-Host ("0x{0:X8}  {1}" -f $offset, $hash)
}

# ============================================================
# FINAL VERDICT
# ============================================================

Write-Host ""
Write-Host "============================================================"
Write-Host " SUMMARY"
Write-Host "============================================================"

if ($validPEs.Count -eq 0) {

    Write-Host ""
    Write-Host "NOT A NORMAL PE/DLL AT OFFSET 0."

    if ($ent -gt 7.5) {
        Write-Host "High entropy suggests compression/encryption/packing."
    }
    else {
        Write-Host "Entropy is not extremely high; data appears structured."
    }

    if ($mz.Count -gt 0) {
        Write-Host ("There are {0} literal 'MZ' sequences, but none forms a valid PE." -f $mz.Count)
    }

    Write-Host ""
    Write-Host "Important:"
    Write-Host "A '.dll' extension does NOT mean the file itself is a PE DLL."
}
else {
    Write-Host ""
    Write-Host "At least one valid PE structure was found."
}

Write-Host ""
Write-Host "Analysis finished."
Write-Host ""