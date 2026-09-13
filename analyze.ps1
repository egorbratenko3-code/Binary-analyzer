param(
    [string]$Path = ".\real.dll"
)

$ErrorActionPreference = "Stop"

# ============================================================
#  UNIVERSAL BINARY ANALYZER / REVERSE-ENGINEERING HELPER
#  PowerShell 5.1 compatible, no external modules/tools needed
#  Usage:
#     Set-ExecutionPolicy -Scope Process Bypass -Force
#     .\analyze.ps1 .\file.name
# ============================================================

# ------------------------------------------------------------
# region: LOW-LEVEL HELPERS
# ------------------------------------------------------------

function Hex([byte[]]$Data, [int]$Max = 64) {
    $n = [Math]::Min($Data.Length, $Max)
    if ($n -le 0) { return "" }
    return (($Data[0..($n-1)] | ForEach-Object { "{0:X2}" -f $_ }) -join " ")
}

function ASCII([byte[]]$Data, [int]$Max = 128) {
    $n = [Math]::Min($Data.Length, $Max)
    if ($n -le 0) { return "" }
    -join ($Data[0..($n-1)] | ForEach-Object {
        if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { "." }
    })
}

function Get-Entropy([byte[]]$Data, [int]$Offset = 0, [int]$Length = -1) {
    if ($Length -lt 0) { $Length = $Data.Length - $Offset }
    if ($Length -le 0) { return 0 }

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

function Get-ArithmeticMean([byte[]]$Data, [int]$Offset = 0, [int]$Length = -1) {
    if ($Length -lt 0) { $Length = $Data.Length - $Offset }
    if ($Length -le 0) { return 0 }
    $sum = 0.0
    for ($i = $Offset; $i -lt ($Offset + $Length); $i++) {
        $sum += $Data[$i]
    }
    return ($sum / [double]$Length)
}

function Get-Chi2([byte[]]$Data, [int]$Offset = 0, [int]$Length = -1) {
    if ($Length -lt 0) { $Length = $Data.Length - $Offset }
    if ($Length -le 0) { return 0 }

    $counts = New-Object int[] 256
    for ($i = $Offset; $i -lt ($Offset + $Length); $i++) {
        $counts[$Data[$i]]++
    }

    $expected = $Length / 256.0
    $chi2 = 0.0
    foreach ($c in $counts) {
        $d = $c - $expected
        $chi2 += ($d * $d) / $expected
    }
    return $chi2
}

function Get-MonteCarloPi([byte[]]$Data, [int]$Offset = 0, [int]$Length = -1) {
    # Classic "ent"-style Monte Carlo estimation of Pi from byte stream.
    # Groups of 6 bytes -> one 2D point (3 bytes per axis), unit circle test.
    if ($Length -lt 0) { $Length = $Data.Length - $Offset }
    $usable = [int]([Math]::Floor($Length / 6.0)) * 6
    if ($usable -lt 6) { return [PSCustomObject]@{ Pi = 0.0; Error = 100.0; Points = 0 } }

    $scale = 8388607.5  # (2^24 - 1) / 2
    $inside = 0L
    $total = 0L

    for ($i = $Offset; $i -lt ($Offset + $usable); $i += 6) {
        $x24 = ($Data[$i]   -shl 16) -bor ($Data[$i+1] -shl 8) -bor $Data[$i+2]
        $y24 = ($Data[$i+3] -shl 16) -bor ($Data[$i+4] -shl 8) -bor $Data[$i+5]

        $xf = ($x24 / $scale) - 1.0
        $yf = ($y24 / $scale) - 1.0

        if ((($xf * $xf) + ($yf * $yf)) -le 1.0) { $inside++ }
        $total++
    }

    if ($total -eq 0) { return [PSCustomObject]@{ Pi = 0.0; Error = 100.0; Points = 0 } }

    $piEst = 4.0 * ($inside / [double]$total)
    $err = [Math]::Abs(($piEst - [Math]::PI) / [Math]::PI) * 100.0

    return [PSCustomObject]@{ Pi = $piEst; Error = $err; Points = $total }
}

function Get-SerialCorrelation([byte[]]$Data, [int]$Offset = 0, [int]$Length = -1) {
    if ($Length -lt 0) { $Length = $Data.Length - $Offset }
    if ($Length -lt 2) { return 0 }

    # cap sample size for performance on huge files
    if ($Length -gt 500000) { $Length = 500000 }

    $n = $Length
    $sum = 0.0
    $sum2 = 0.0
    $sumProd = 0.0

    for ($i = 0; $i -lt $n; $i++) {
        $a = [double]$Data[$Offset + $i]
        $bnext = [double]$Data[$Offset + (($i + 1) % $n)]
        $sum += $a
        $sum2 += ($a * $a)
        $sumProd += ($a * $bnext)
    }

    $numerator = ($n * $sumProd) - ($sum * $sum)
    $denominator = ($n * $sum2) - ($sum * $sum)

    if ($denominator -eq 0) { return 0 }

    return ($numerator / $denominator)
}

function Find-Bytes(
    [byte[]]$Data,
    [byte[]]$Pattern,
    [int]$MaxResults = 100,
    [int]$StartAt = 0
) {
    $results = New-Object System.Collections.Generic.List[int]
    if ($Pattern.Length -eq 0) { return $results }

    for ($i = $StartAt; $i -le ($Data.Length - $Pattern.Length); $i++) {
        if ($Data[$i] -ne $Pattern[0]) { continue }
        $ok = $true
        for ($j = 1; $j -lt $Pattern.Length; $j++) {
            if ($Data[$i + $j] -ne $Pattern[$j]) { $ok = $false; break }
        }
        if ($ok) {
            $results.Add($i)
            if ($results.Count -ge $MaxResults) { break }
        }
    }
    return $results
}

function Find-ASCII-Strings([byte[]]$Data, [int]$MinLength = 5) {
    $results = New-Object System.Collections.Generic.List[object]
    $start = -1

    for ($i = 0; $i -lt $Data.Length; $i++) {
        $printable = ($Data[$i] -ge 32 -and $Data[$i] -le 126)
        if ($printable) {
            if ($start -lt 0) { $start = $i }
        }
        else {
            if ($start -ge 0) {
                $len = $i - $start
                if ($len -ge $MinLength) {
                    $s = [Text.Encoding]::ASCII.GetString($Data, $start, $len)
                    $results.Add([PSCustomObject]@{ Offset = $start; Length = $len; String = $s })
                }
            }
            $start = -1
        }
    }

    if ($start -ge 0) {
        $len = $Data.Length - $start
        if ($len -ge $MinLength) {
            $s = [Text.Encoding]::ASCII.GetString($Data, $start, $len)
            $results.Add([PSCustomObject]@{ Offset = $start; Length = $len; String = $s })
        }
    }

    return $results
}

function Find-UnicodeStrings([byte[]]$Data, [int]$MinLength = 5) {
    $results = New-Object System.Collections.Generic.List[object]
    $start = -1

    for ($i = 0; $i -lt ($Data.Length - 1); $i += 2) {
        $lo = $Data[$i]
        $hi = $Data[$i + 1]
        $printable = ($hi -eq 0 -and $lo -ge 32 -and $lo -le 126)

        if ($printable) {
            if ($start -lt 0) { $start = $i }
        }
        else {
            if ($start -ge 0) {
                $len = $i - $start
                if (($len / 2) -ge $MinLength) {
                    $s = [Text.Encoding]::Unicode.GetString($Data, $start, $len)
                    $results.Add([PSCustomObject]@{ Offset = $start; Length = $len; String = $s })
                }
            }
            $start = -1
        }
    }

    return $results
}

function UInt16LE([byte[]]$D, [int]$O) { return [BitConverter]::ToUInt16($D, $O) }
function UInt32LE([byte[]]$D, [int]$O) { return [BitConverter]::ToUInt32($D, $O) }
function UInt64LE([byte[]]$D, [int]$O) { return [BitConverter]::ToUInt64($D, $O) }

function Check-PEAt([byte[]]$Data, [int]$Offset) {
    $result = [ordered]@{ Offset = $Offset; ValidPE = $false; Reason = "" }

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
    if ($Data[$pe] -ne 0x50 -or $Data[$pe+1] -ne 0x45 -or $Data[$pe+2] -ne 0x00 -or $Data[$pe+3] -ne 0x00) {
        $result.Reason = "MZ but e_lfanew does not point to PE"
        $result.PEOffset = $pe
        return [PSCustomObject]$result
    }

    $machine = UInt16LE $Data ($pe + 4)
    $sections = UInt16LE $Data ($pe + 6)
    $optionalSize = UInt16LE $Data ($pe + 20)
    $optionalMagic = 0
    if ($optionalSize -ge 2 -and ($pe + 24 + 2) -le $Data.Length) {
        $optionalMagic = UInt16LE $Data ($pe + 24)
    }

    $result.ValidPE = $true
    $result.PEOffset = $pe
    $result.Machine = ("0x{0:X4}" -f $machine)
    $result.Sections = $sections
    $result.OptionalMagic = ("0x{0:X4}" -f $optionalMagic)
    $result.OptionalHeaderSize = $optionalSize

    return [PSCustomObject]$result
}

function Get-MachineName([string]$hexMachine) {
    switch ($hexMachine) {
        "0x014C" { return "I386" }
        "0x8664" { return "AMD64 (x64)" }
        "0x01C0" { return "ARM" }
        "0x01C4" { return "ARMNT (ARMv7 Thumb-2)" }
        "0xAA64" { return "ARM64" }
        "0x0200" { return "IA64 (Itanium)" }
        "0x0EBC" { return "EFI Byte Code" }
        "0x0166" { return "MIPS16" }
        "0x0284" { return "ALPHA64/AXP64" }
        "0x01A2" { return "SH3" }
        "0x01A6" { return "SH4" }
        "0x0268" { return "M68K" }
        "0x9041" { return "M32R" }
        default  { return "Unknown/rare ($hexMachine)" }
    }
}

function Get-SubsystemName([int]$v) {
    switch ($v) {
        0  { return "UNKNOWN" }
        1  { return "NATIVE (driver/system)" }
        2  { return "WINDOWS_GUI" }
        3  { return "WINDOWS_CUI (console)" }
        5  { return "OS2_CUI" }
        7  { return "POSIX_CUI" }
        9  { return "WINDOWS_CE_GUI" }
        10 { return "EFI_APPLICATION" }
        11 { return "EFI_BOOT_SERVICE_DRIVER" }
        12 { return "EFI_RUNTIME_DRIVER" }
        13 { return "EFI_ROM" }
        14 { return "XBOX" }
        16 { return "WINDOWS_BOOT_APPLICATION" }
        default { return "Unknown ($v)" }
    }
}

function Decode-PECharacteristics([int]$c) {
    $flags = New-Object System.Collections.Generic.List[string]
    if ($c -band 0x0001) { $flags.Add("RELOCS_STRIPPED") }
    if ($c -band 0x0002) { $flags.Add("EXECUTABLE_IMAGE") }
    if ($c -band 0x0004) { $flags.Add("LINE_NUMS_STRIPPED") }
    if ($c -band 0x0008) { $flags.Add("LOCAL_SYMS_STRIPPED") }
    if ($c -band 0x0010) { $flags.Add("AGGRESSIVE_WS_TRIM") }
    if ($c -band 0x0020) { $flags.Add("LARGE_ADDRESS_AWARE") }
    if ($c -band 0x0080) { $flags.Add("BYTES_REVERSED_LO") }
    if ($c -band 0x0100) { $flags.Add("32BIT_MACHINE") }
    if ($c -band 0x0200) { $flags.Add("DEBUG_STRIPPED") }
    if ($c -band 0x0400) { $flags.Add("REMOVABLE_RUN_FROM_SWAP") }
    if ($c -band 0x0800) { $flags.Add("NET_RUN_FROM_SWAP") }
    if ($c -band 0x1000) { $flags.Add("SYSTEM_FILE") }
    if ($c -band 0x2000) { $flags.Add("DLL") }
    if ($c -band 0x4000) { $flags.Add("UP_SYSTEM_ONLY") }
    if ($c -band 0x8000) { $flags.Add("BYTES_REVERSED_HI") }
    return ($flags -join ", ")
}

function Decode-DllCharacteristics([int]$c) {
    $flags = New-Object System.Collections.Generic.List[string]
    if ($c -band 0x0020) { $flags.Add("HIGH_ENTROPY_VA") }
    if ($c -band 0x0040) { $flags.Add("DYNAMIC_BASE(ASLR)") }
    if ($c -band 0x0080) { $flags.Add("FORCE_INTEGRITY") }
    if ($c -band 0x0100) { $flags.Add("NX_COMPAT(DEP)") }
    if ($c -band 0x0200) { $flags.Add("NO_ISOLATION") }
    if ($c -band 0x0400) { $flags.Add("NO_SEH") }
    if ($c -band 0x0800) { $flags.Add("NO_BIND") }
    if ($c -band 0x1000) { $flags.Add("APPCONTAINER") }
    if ($c -band 0x2000) { $flags.Add("WDM_DRIVER") }
    if ($c -band 0x4000) { $flags.Add("CONTROL_FLOW_GUARD(CFG)") }
    if ($c -band 0x8000) { $flags.Add("TERMINAL_SERVER_AWARE") }
    if ($flags.Count -eq 0) { return "(none)" }
    return ($flags -join ", ")
}

# Translate an RVA to a raw file offset using a section table.
function Convert-RVAToOffset([array]$Sections, [long]$RVA) {
    foreach ($s in $Sections) {
        $vaStart = $s.VirtualAddress
        $vaSize = [Math]::Max($s.VirtualSize, $s.SizeOfRawData)
        if ($RVA -ge $vaStart -and $RVA -lt ($vaStart + $vaSize)) {
            return ($s.PointerToRawData + ($RVA - $vaStart))
        }
    }
    return -1
}

function Read-CString([byte[]]$Data, [long]$Offset, [int]$MaxLen = 256) {
    if ($Offset -lt 0 -or $Offset -ge $Data.Length) { return "" }
    $end = $Offset
    $limit = [Math]::Min($Data.Length, $Offset + $MaxLen)
    while ($end -lt $limit -and $Data[$end] -ne 0) { $end++ }
    $len = $end - $Offset
    if ($len -le 0) { return "" }
    return [Text.Encoding]::ASCII.GetString($Data, [int]$Offset, [int]$len)
}

function Parse-PEFull([byte[]]$Data, [int]$Offset) {
    $info = [ordered]@{}

    $lfanew = UInt32LE $Data ($Offset + 0x3C)
    $pe = $Offset + [int]$lfanew

    $machine = UInt16LE $Data ($pe + 4)
    $numSections = UInt16LE $Data ($pe + 6)
    $timeDateStamp = UInt32LE $Data ($pe + 8)
    $sizeOfOptional = UInt16LE $Data ($pe + 20)
    $characteristics = UInt16LE $Data ($pe + 22)

    $optOffset = $pe + 24
    $magic = UInt16LE $Data $optOffset

    $isPE32Plus = ($magic -eq 0x20B)

    $info.PEOffset = $pe
    $info.Machine = ("0x{0:X4}" -f $machine)
    $info.MachineName = Get-MachineName $info.Machine
    $info.NumberOfSections = $numSections
    $info.TimeDateStamp = $timeDateStamp
    try {
        $epoch = [DateTime]::new(1970,1,1,0,0,0,[DateTimeKind]::Utc)
        $info.CompileTimeUTC = $epoch.AddSeconds($timeDateStamp).ToString("yyyy-MM-dd HH:mm:ss")
    } catch {
        $info.CompileTimeUTC = "n/a"
    }
    $info.Characteristics = ("0x{0:X4}" -f $characteristics)
    $info.CharacteristicsDecoded = Decode-PECharacteristics $characteristics
    $info.OptionalHeaderMagic = ("0x{0:X4}" -f $magic)
    $info.IsPE32Plus = $isPE32Plus
    $info.SizeOfOptionalHeader = $sizeOfOptional

    $info.AddressOfEntryPoint = UInt32LE $Data ($optOffset + 16)

    if ($isPE32Plus) {
        $info.ImageBase = UInt64LE $Data ($optOffset + 24)
        $subsystemOff   = $optOffset + 68
        $dllCharOff     = $optOffset + 70
        $numRvaOff      = $optOffset + 108
        $dataDirOff     = $optOffset + 112
    } else {
        $info.ImageBase = UInt32LE $Data ($optOffset + 28)
        $subsystemOff   = $optOffset + 68
        $dllCharOff     = $optOffset + 70
        $numRvaOff      = $optOffset + 92
        $dataDirOff     = $optOffset + 96
    }

    $info.SectionAlignment = UInt32LE $Data ($optOffset + 32)
    $info.FileAlignment    = UInt32LE $Data ($optOffset + 36)
    $info.SizeOfImage      = UInt32LE $Data ($optOffset + 56)
    $info.SizeOfHeaders    = UInt32LE $Data ($optOffset + 60)
    $info.CheckSum         = UInt32LE $Data ($optOffset + 64)

    $subsystemVal = UInt16LE $Data $subsystemOff
    $info.Subsystem = $subsystemVal
    $info.SubsystemName = Get-SubsystemName $subsystemVal

    $dllCharVal = UInt16LE $Data $dllCharOff
    $info.DllCharacteristics = ("0x{0:X4}" -f $dllCharVal)
    $info.DllCharacteristicsDecoded = Decode-DllCharacteristics $dllCharVal

    $numRva = UInt32LE $Data $numRvaOff
    if ($numRva -gt 16) { $numRva = 16 }
    $info.NumberOfRvaAndSizes = $numRva

    $dirNames = @(
        "Export Table", "Import Table", "Resource Table", "Exception Table",
        "Certificate Table (Authenticode)", "Base Relocation Table", "Debug",
        "Architecture", "Global Ptr", "TLS Table", "Load Config Table",
        "Bound Import", "IAT", "Delay Import Descriptor",
        "CLR Runtime Header (.NET)", "Reserved"
    )

    $dataDirs = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $numRva; $i++) {
        $entryOff = $dataDirOff + ($i * 8)
        if ($entryOff + 8 -gt $Data.Length) { break }
        $va = UInt32LE $Data $entryOff
        $sz = UInt32LE $Data ($entryOff + 4)
        $dataDirs.Add([PSCustomObject]@{
            Name = $dirNames[$i]
            VirtualAddress = ("0x{0:X}" -f $va)
            Size = $sz
        })
    }
    $info.DataDirectoriesRaw = $dataDirs

    # ---- Section table ----
    $sectionTableOffset = $optOffset + $sizeOfOptional
    $sections = New-Object System.Collections.Generic.List[object]

    for ($i = 0; $i -lt $numSections; $i++) {
        $so = $sectionTableOffset + ($i * 40)
        if ($so + 40 -gt $Data.Length) { break }

        $nameBytes = $Data[$so..($so+7)]
        $name = ([Text.Encoding]::ASCII.GetString($nameBytes)).TrimEnd([char]0)

        $virtSize = UInt32LE $Data ($so + 8)
        $virtAddr = UInt32LE $Data ($so + 12)
        $rawSize  = UInt32LE $Data ($so + 16)
        $rawPtr   = UInt32LE $Data ($so + 20)
        $sChar    = UInt32LE $Data ($so + 36)

        $secEntropy = 0.0
        if ($rawSize -gt 0 -and ($rawPtr + $rawSize) -le $Data.Length) {
            $secEntropy = Get-Entropy $Data $rawPtr $rawSize
        }

        $sections.Add([PSCustomObject]@{
            Name = $name
            VirtualSize = $virtSize
            VirtualAddress = $virtAddr
            SizeOfRawData = $rawSize
            PointerToRawData = $rawPtr
            Characteristics = ("0x{0:X8}" -f $sChar)
            Entropy = [Math]::Round($secEntropy, 3)
        })
    }
    $info.Sections = $sections

    return [PSCustomObject]$info
}

function Find-RichHeader([byte[]]$Data, [int]$PEOffset, [int]$FileStart = 0) {
    $searchEnd = [Math]::Min($PEOffset, $Data.Length)
    $richPattern = [byte[]](0x52,0x69,0x63,0x68)  # "Rich"
    $hits = Find-Bytes $Data $richPattern 1 $FileStart

    if ($hits.Count -eq 0) { return $null }

    $off = $hits[0]
    if ($off -ge $searchEnd) { return $null }
    if ($off + 8 -gt $Data.Length) { return $null }

    $xorKey = UInt32LE $Data ($off + 4)
    return [PSCustomObject]@{
        Offset = $off
        XorKey = ("0x{0:X8}" -f $xorKey)
    }
}

$KnownPackerSections = @(
    ".aspack", ".adata", "UPX0", "UPX1", "UPX2", ".upx", ".vmp0", ".vmp1", ".vmp2",
    ".themida", ".taz", ".perplex", "nsp0", "nsp1", "nsp2", ".packed", ".ccg",
    "MPRESS1", "MPRESS2", ".neolite", "PEC2", "PEC2TO", ".enigma1", ".enigma2",
    ".obsidium", ".petite", "PESHiELD", ".pklstb", ".sforce3", ".yP", ".RLPack"
)

function Find-PEOverlay([byte[]]$Data, $PEInfo) {
    if (-not $PEInfo -or $PEInfo.Sections.Count -eq 0) { return $null }
    $maxEnd = 0L
    foreach ($s in $PEInfo.Sections) {
        $end = [long]$s.PointerToRawData + [long]$s.SizeOfRawData
        if ($end -gt $maxEnd) { $maxEnd = $end }
    }
    # Certificate table (Authenticode) lives past the "logical" image too, account for it.
    foreach ($d in $PEInfo.DataDirectoriesRaw) {
        if ($d.Name -eq "Certificate Table (Authenticode)" -and $d.Size -gt 0) {
            $certVA = [Convert]::ToInt64($d.VirtualAddress, 16)
            $certEnd = $certVA + $d.Size
            if ($certEnd -gt $maxEnd) { $maxEnd = $certEnd }
        }
    }

    if ($Data.Length -gt $maxEnd) {
        return [PSCustomObject]@{
            HeaderEnd = $maxEnd
            OverlaySize = ($Data.Length - $maxEnd)
        }
    }
    return $null
}

# ------------------------------------------------------------
# region: ENCODING DETECTION / DECODING HELPERS
# ------------------------------------------------------------

function Try-Base64Decode([string]$s) {
    try {
        $clean = $s.Trim()
        $pad = $clean.Length % 4
        if ($pad -ne 0) { $clean = $clean + ("=" * (4 - $pad)) }
        $bytes = [Convert]::FromBase64String($clean)
        return $bytes
    } catch {
        return $null
    }
}

$Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

function Try-Base32Decode([string]$s) {
    try {
        $clean = $s.TrimEnd("=").ToUpper()
        if ($clean.Length -eq 0) { return $null }

        $bits = ""
        foreach ($ch in $clean.ToCharArray()) {
            $idx = $Base32Alphabet.IndexOf($ch)
            if ($idx -lt 0) { return $null }
            $bits += [Convert]::ToString($idx, 2).PadLeft(5, '0')
        }

        $byteCount = [Math]::Floor($bits.Length / 8)
        if ($byteCount -le 0) { return $null }

        $bytes = New-Object byte[] $byteCount
        for ($i = 0; $i -lt $byteCount; $i++) {
            $chunk = $bits.Substring($i * 8, 8)
            $bytes[$i] = [Convert]::ToByte($chunk, 2)
        }
        return $bytes
    } catch {
        return $null
    }
}

$Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

function Try-Base58Decode([string]$s) {
    try {
        [Numerics.BigInteger]$num = 0
        foreach ($ch in $s.ToCharArray()) {
            $idx = $Base58Alphabet.IndexOf($ch)
            if ($idx -lt 0) { return $null }
            $num = ($num * 58) + $idx
        }

        $bytesList = New-Object System.Collections.Generic.List[byte]
        if ($num -eq 0) {
            $bytesList.Add(0)
        }
        while ($num -gt 0) {
            $rem = [byte]($num % 256)
            $bytesList.Add($rem)
            $num = [Numerics.BigInteger]::Divide($num, 256)
        }
        $bytesList.Reverse()

        # leading '1' chars in base58 represent leading 0x00 bytes
        $leadingZeros = 0
        foreach ($ch in $s.ToCharArray()) {
            if ($ch -eq '1') { $leadingZeros++ } else { break }
        }
        $prefix = New-Object byte[] $leadingZeros

        $result = New-Object byte[] ($prefix.Length + $bytesList.Count)
        [Array]::Copy($prefix, 0, $result, 0, $prefix.Length)
        [Array]::Copy($bytesList.ToArray(), 0, $result, $prefix.Length, $bytesList.Count)
        return $result
    } catch {
        return $null
    }
}

function Try-HexDecode([string]$s) {
    try {
        $clean = $s -replace '[^0-9A-Fa-f]', ''
        if ($clean.Length -lt 2 -or ($clean.Length % 2) -ne 0) { return $null }
        $n = $clean.Length / 2
        $bytes = New-Object byte[] $n
        for ($i = 0; $i -lt $n; $i++) {
            $bytes[$i] = [Convert]::ToByte($clean.Substring($i*2, 2), 16)
        }
        return $bytes
    } catch {
        return $null
    }
}

function Get-Rot13([string]$s) {
    $out = New-Object char[] $s.Length
    for ($i = 0; $i -lt $s.Length; $i++) {
        $c = $s[$i]
        if ($c -ge 'a' -and $c -le 'z') {
            $out[$i] = [char]((([int]$c - [int][char]'a' + 13) % 26) + [int][char]'a')
        } elseif ($c -ge 'A' -and $c -le 'Z') {
            $out[$i] = [char]((([int]$c - [int][char]'A' + 13) % 26) + [int][char]'A')
        } else {
            $out[$i] = $c
        }
    }
    return -join $out
}

function Get-Rot47([string]$s) {
    $out = New-Object char[] $s.Length
    for ($i = 0; $i -lt $s.Length; $i++) {
        $c = [int][char]$s[$i]
        if ($c -ge 33 -and $c -le 126) {
            $out[$i] = [char]((($c - 33 + 47) % 94) + 33)
        } else {
            $out[$i] = [char]$c
        }
    }
    return -join $out
}

# Quick heuristic: does a byte blob look like readable text / another file format?
function Get-BlobSummary([byte[]]$bytes) {
    if (-not $bytes -or $bytes.Length -eq 0) { return "empty" }
    $ent = Get-Entropy $bytes
    $printable = 0
    $n = [Math]::Min($bytes.Length, 256)
    for ($i = 0; $i -lt $n; $i++) {
        if (($bytes[$i] -ge 32 -and $bytes[$i] -le 126) -or $bytes[$i] -eq 9 -or $bytes[$i] -eq 10 -or $bytes[$i] -eq 13) {
            $printable++
        }
    }
    $pct = ($printable / [double]$n) * 100
    return ("{0} bytes, entropy {1:N2}, {2:N0}% printable" -f $bytes.Length, $ent, $pct)
}

# ------------------------------------------------------------
# region: KNOWN CRYPTO CONSTANTS (static signature search)
# ------------------------------------------------------------

function Get-CryptoSignatureList() {
    $sigs = New-Object System.Collections.Generic.List[object]

    $aesSbox = [byte[]](
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2
    )
    $sigs.Add(@{ Name = "AES S-box (forward, partial 128B)"; Pattern = $aesSbox })

    $aesInvSboxHead = [byte[]](
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25
    )
    $sigs.Add(@{ Name = "AES Inverse S-box (partial 64B)"; Pattern = $aesInvSboxHead })

    $aesRcon = [byte[]](0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36)
    $sigs.Add(@{ Name = "AES Rcon table"; Pattern = $aesRcon })

    # MD5 init constants 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 (LE, as stored in memory/code)
    $sigs.Add(@{ Name = "MD5 init constants (LE)"; Pattern = [byte[]](0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10) })

    # SHA-1 init constants 67452301 EFCDAB89 98BADCFE 10325476 C3D2E1F0 (big-endian layout, as often embedded)
    $sigs.Add(@{ Name = "SHA-1 init constants (BE)"; Pattern = [byte[]](0x67,0x45,0x23,0x01,0xEF,0xCD,0xAB,0x89,0x98,0xBA,0xDC,0xFE,0x10,0x32,0x54,0x76,0xC3,0xD2,0xE1,0xF0) })

    # SHA-256 init constants (first two words) 6A09E667 BB67AE85 (BE layout)
    $sigs.Add(@{ Name = "SHA-256 init constants (BE)"; Pattern = [byte[]](0x6A,0x09,0xE6,0x67,0xBB,0x67,0xAE,0x85,0x3C,0x6E,0xF3,0x72,0xA5,0x4F,0xF5,0x3A) })

    # SHA-512 init constants (first two words)
    $sigs.Add(@{ Name = "SHA-512 init constants (BE)"; Pattern = [byte[]](0x6A,0x09,0xE6,0x67,0xF3,0xBC,0xC9,0x08,0xBB,0x67,0xAE,0x85,0x84,0xCA,0xA7,0x3B) })

    # Standard CRC32 (IEEE 802.3) table, first 4 entries, little endian dwords
    $sigs.Add(@{ Name = "CRC32 (IEEE) lookup table head"; Pattern = [byte[]](0x00,0x00,0x00,0x00,0x96,0x30,0x07,0x77,0x2C,0x61,0x0E,0xEE,0xBA,0x51,0x09,0x99) })

    # Blowfish P-array first values (digits of pi), LE
    $sigs.Add(@{ Name = "Blowfish P-array head (pi digits, LE)"; Pattern = [byte[]](0x88,0x6A,0x3F,0x24,0xD3,0x08,0xA3,0x85) })

    # TEA / XTEA delta constant 0x9E3779B9
    $sigs.Add(@{ Name = "TEA/XTEA delta 0x9E3779B9 (LE)"; Pattern = [byte[]](0xB9,0x79,0x37,0x9E) })
    $sigs.Add(@{ Name = "TEA/XTEA delta 0x9E3779B9 (BE)"; Pattern = [byte[]](0x9E,0x37,0x79,0xB9) })

    # Salsa20 / ChaCha20 constants (ASCII, embedded as literal strings/constants)
    $sigs.Add(@{ Name = "ChaCha20/Salsa20 constant 'expand 32-byte k'"; Pattern = [Text.Encoding]::ASCII.GetBytes("expand 32-byte k") })
    $sigs.Add(@{ Name = "Salsa20 constant 'expand 16-byte k'"; Pattern = [Text.Encoding]::ASCII.GetBytes("expand 16-byte k") })

    # Standard Base64 alphabet table, as sometimes embedded verbatim by encoders
    $sigs.Add(@{ Name = "Base64 standard alphabet table"; Pattern = [Text.Encoding]::ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") })
    $sigs.Add(@{ Name = "Base64 URL-safe alphabet table"; Pattern = [Text.Encoding]::ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") })

    # RC4-like KSA identity table hint (not fully reliable, still useful)
    $sigs.Add(@{ Name = "Identity byte ramp 0..15 (possible S-box init / lookup table)"; Pattern = [byte[]](0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F) })

    return $sigs
}

# ------------------------------------------------------------
# region: ELF / MACH-O QUICK PARSERS
# ------------------------------------------------------------

function Parse-ELFHeader([byte[]]$Data) {
    if ($Data.Length -lt 20 -or $Data[0] -ne 0x7F -or $Data[1] -ne 0x45 -or $Data[2] -ne 0x4C -or $Data[3] -ne 0x46) {
        return $null
    }

    $info = [ordered]@{}
    $eiClass = $Data[4]
    $eiData = $Data[5]
    $eiVersion = $Data[6]
    $eiOSABI = $Data[7]

    $info.Class = switch ($eiClass) { 1 { "ELF32" } 2 { "ELF64" } default { "Unknown($eiClass)" } }
    $info.DataEncoding = switch ($eiData) { 1 { "Little-endian" } 2 { "Big-endian" } default { "Unknown($eiData)" } }
    $info.Version = $eiVersion
    $info.OSABI = switch ($eiOSABI) {
        0 { "System V" }; 1 { "HP-UX" }; 2 { "NetBSD" }; 3 { "Linux" }; 6 { "Solaris" }
        9 { "FreeBSD" }; 12 { "OpenBSD" }; default { "Unknown($eiOSABI)" }
    }

    if ($eiData -eq 1) {
        $eType = UInt16LE $Data 16
        $eMachine = UInt16LE $Data 18
    } else {
        # big-endian, reverse the two bytes manually
        $eType = ($Data[16] -shl 8) -bor $Data[17]
        $eMachine = ($Data[18] -shl 8) -bor $Data[19]
    }

    $info.Type = switch ($eType) {
        1 { "REL (relocatable)" }; 2 { "EXEC (executable)" }; 3 { "DYN (shared object/PIE)" }
        4 { "CORE (core dump)" }; default { "Unknown($eType)" }
    }

    $info.Machine = switch ($eMachine) {
        3 { "x86" }; 62 { "x86-64" }; 40 { "ARM" }; 183 { "AArch64" }
        8 { "MIPS" }; 20 { "PowerPC" }; 21 { "PowerPC64" }; 243 { "RISC-V" }
        default { "Unknown($eMachine)" }
    }

    return [PSCustomObject]$info
}

function Parse-MachOHeader([byte[]]$Data) {
    if ($Data.Length -lt 28) { return $null }

    $magic = [BitConverter]::ToUInt32($Data, 0)
    $is64 = $false
    $isBE = $false

    switch ($magic) {
        0xFEEDFACE { $is64 = $false; $isBE = $false }
        0xFEEDFACF { $is64 = $true;  $isBE = $false }
        0xCEFAEDFE { $is64 = $false; $isBE = $true }
        0xCFFAEDFE { $is64 = $true;  $isBE = $true }
        default { return $null }
    }

    $info = [ordered]@{}
    $info.Bitness = if ($is64) { "64-bit" } else { "32-bit" }
    $info.ByteOrderInFile = if ($isBE) { "big-endian" } else { "little-endian" }

    if (-not $isBE) {
        $cputype = [BitConverter]::ToInt32($Data, 4)
        $filetype = [BitConverter]::ToUInt32($Data, 12)
        $ncmds = [BitConverter]::ToUInt32($Data, 16)
    } else {
        $b = $Data[4..7]; [Array]::Reverse($b); $cputype = [BitConverter]::ToInt32($b, 0)
        $b = $Data[12..15]; [Array]::Reverse($b); $filetype = [BitConverter]::ToUInt32($b, 0)
        $b = $Data[16..19]; [Array]::Reverse($b); $ncmds = [BitConverter]::ToUInt32($b, 0)
    }

    $info.CpuType = switch ($cputype) {
        7 { "x86" }; 16777223 { "x86-64" }; 12 { "ARM" }; 16777228 { "ARM64" }
        default { "Unknown($cputype)" }
    }
    $info.FileType = switch ($filetype) {
        1 {"OBJECT"}; 2 {"EXECUTE"}; 6 {"DYLIB"}; 8 {"BUNDLE"}; 10 {"DSYM"}
        default { "Unknown($filetype)" }
    }
    $info.NumberOfLoadCommands = $ncmds

    return [PSCustomObject]$info
}

# ------------------------------------------------------------
# region: MULTI-BYTE (repeating-key) XOR ANALYSIS
# ------------------------------------------------------------

function Get-HammingDistance([byte[]]$A, [byte[]]$B) {
    $n = [Math]::Min($A.Length, $B.Length)
    $dist = 0
    for ($i = 0; $i -lt $n; $i++) {
        $x = $A[$i] -bxor $B[$i]
        while ($x -ne 0) { $dist += ($x -band 1); $x = $x -shr 1 }
    }
    return $dist
}

function Guess-XorKeySize([byte[]]$Data, [int]$MinKey = 2, [int]$MaxKey = 40, [int]$SampleBlocks = 4) {
    $results = New-Object System.Collections.Generic.List[object]
    $usable = [Math]::Min($Data.Length, 262144)

    for ($ks = $MinKey; $ks -le $MaxKey; $ks++) {
        if (($ks * ($SampleBlocks + 1)) -gt $usable) { break }

        $totalDist = 0.0
        $comparisons = 0
        for ($b = 0; $b -lt $SampleBlocks; $b++) {
            $off1 = $b * $ks
            $off2 = ($b + 1) * $ks
            $block1 = $Data[$off1..($off1+$ks-1)]
            $block2 = $Data[$off2..($off2+$ks-1)]
            $totalDist += (Get-HammingDistance $block1 $block2)
            $comparisons++
        }

        if ($comparisons -gt 0) {
            $normalized = ($totalDist / $comparisons) / $ks
            $results.Add([PSCustomObject]@{ KeySize = $ks; NormalizedDistance = $normalized })
        }
    }

    return ($results | Sort-Object NormalizedDistance | Select-Object -First 5)
}

function Break-RepeatingXor([byte[]]$Data, [int]$KeySize, [int]$SampleLen = 65536) {
    $len = [Math]::Min($Data.Length, $SampleLen)
    $key = New-Object byte[] $KeySize

    for ($col = 0; $col -lt $KeySize; $col++) {
        $bestScore = -1
        $bestKeyByte = 0

        for ($k = 0; $k -lt 256; $k++) {
            $score = 0
            for ($i = $col; $i -lt $len; $i += $KeySize) {
                $x = $Data[$i] -bxor $k
                if (($x -ge 32 -and $x -le 126) -or $x -eq 9 -or $x -eq 10 -or $x -eq 13) { $score++ }
            }
            if ($score -gt $bestScore) { $bestScore = $score; $bestKeyByte = $k }
        }
        $key[$col] = $bestKeyByte
    }

    return $key
}

function Get-CRC32([byte[]]$Data) {
    if (-not $script:Crc32Table) {
        $table = New-Object uint32[] 256
        for ($i = 0; $i -lt 256; $i++) {
            $c = [uint32]$i
            for ($j = 0; $j -lt 8; $j++) {
                if (($c -band 1) -ne 0) {
                    $c = (0xEDB88320 -bxor ($c -shr 1))
                } else {
                    $c = ($c -shr 1)
                }
            }
            $table[$i] = $c
        }
        $script:Crc32Table = $table
    }

    $crc = [uint32]0xFFFFFFFF
    foreach ($byte in $Data) {
        $idx = ($crc -bxor $byte) -band 0xFF
        $crc = ($script:Crc32Table[$idx] -bxor ($crc -shr 8))
    }
    return ($crc -bxor 0xFFFFFFFF)
}

# ============================================================
# LOAD FILE
# ============================================================

if ([IO.Path]::IsPathRooted($Path)) { $FullPath = $Path }
else { $FullPath = Join-Path (Get-Location).Path $Path }

if (!(Test-Path -LiteralPath $FullPath)) { throw "File not found: $FullPath" }

$FullPath = (Get-Item -LiteralPath $FullPath).FullName

$StepCounter = 0
function Next-Step([string]$Title) {
    $script:StepCounter++
    Write-Host ""
    Write-Host ("[{0}] {1}" -f $script:StepCounter, $Title)
    Write-Host "------------------------------------------------------------"
}

Write-Host ""
Write-Host "============================================================"
Write-Host " UNIVERSAL BINARY / REVERSE-ENGINEERING ANALYZER"
Write-Host "============================================================"

Next-Step "BASIC FILE INFO"
Write-Host "File: $FullPath"
$FileInfo = Get-Item -LiteralPath $FullPath
Write-Host ("Size       : {0} bytes ({1:N2} MiB)" -f $FileInfo.Length, ($FileInfo.Length / 1MB))
Write-Host ("Created    : {0}" -f $FileInfo.CreationTimeUtc)
Write-Host ("Modified   : {0}" -f $FileInfo.LastWriteTimeUtc)
Write-Host ("Extension  : {0}" -f $FileInfo.Extension)

$b = [IO.File]::ReadAllBytes($FullPath)

Next-Step "HASHES"
$sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $FullPath).Hash
$sha1   = (Get-FileHash -Algorithm SHA1   -LiteralPath $FullPath).Hash
$md5    = (Get-FileHash -Algorithm MD5    -LiteralPath $FullPath).Hash
$crc32  = "{0:X8}" -f (Get-CRC32 $b)
Write-Host "MD5        : $md5"
Write-Host "SHA1       : $sha1"
Write-Host "SHA256     : $sha256"
Write-Host "CRC32      : $crc32"

Next-Step "HEX / ASCII PREVIEW"
Write-Host "First 64 bytes (hex):"
Write-Host (Hex $b 64)
Write-Host ""
Write-Host "First 128 bytes (ascii):"
Write-Host (ASCII $b 128)
Write-Host ""
Write-Host "Last 64 bytes (hex):"
$tailStart = [Math]::Max(0, $b.Length - 64)
Write-Host (Hex ($b[$tailStart..($b.Length-1)]) 64)

# ============================================================
# MAGIC SIGNATURES (extended)
# ============================================================

Next-Step "MAGIC SIGNATURES AT OFFSET 0"

$magic = @(
    @{ Name="MZ (DOS/PE)";   Bytes=([byte[]](0x4D,0x5A)) },
    @{ Name="ELF";           Bytes=([byte[]](0x7F,0x45,0x4C,0x46)) },
    @{ Name="Mach-O 32 LE";  Bytes=([byte[]](0xCE,0xFA,0xED,0xFE)) },
    @{ Name="Mach-O 64 LE";  Bytes=([byte[]](0xCF,0xFA,0xED,0xFE)) },
    @{ Name="Mach-O 32 BE";  Bytes=([byte[]](0xFE,0xED,0xFA,0xCE)) },
    @{ Name="Mach-O 64 BE";  Bytes=([byte[]](0xFE,0xED,0xFA,0xCF)) },
    @{ Name="Mach-O FAT";    Bytes=([byte[]](0xCA,0xFE,0xBA,0xBE)) },
    @{ Name="Java Class";    Bytes=([byte[]](0xCA,0xFE,0xBA,0xBE)) },
    @{ Name="WASM";          Bytes=([byte[]](0x00,0x61,0x73,0x6D)) },
    @{ Name="ZIP/JAR/APK/DOCX/XLSX";Bytes=([byte[]](0x50,0x4B,0x03,0x04)) },
    @{ Name="ZIP (empty)";   Bytes=([byte[]](0x50,0x4B,0x05,0x06)) },
    @{ Name="GZIP";          Bytes=([byte[]](0x1F,0x8B)) },
    @{ Name="BZIP2";         Bytes=([byte[]](0x42,0x5A,0x68)) },
    @{ Name="7ZIP";          Bytes=([byte[]](0x37,0x7A,0xBC,0xAF,0x27,0x1C)) },
    @{ Name="RAR (1.5+)";    Bytes=([byte[]](0x52,0x61,0x72,0x21,0x1A,0x07,0x00)) },
    @{ Name="RAR (5.0+)";    Bytes=([byte[]](0x52,0x61,0x72,0x21,0x1A,0x07,0x01,0x00)) },
    @{ Name="XZ";            Bytes=([byte[]](0xFD,0x37,0x7A,0x58,0x5A,0x00)) },
    @{ Name="ZSTD";          Bytes=([byte[]](0x28,0xB5,0x2F,0xFD)) },
    @{ Name="LZ4";           Bytes=([byte[]](0x04,0x22,0x4D,0x18)) },
    @{ Name="TAR (ustar)";   Bytes=([Text.Encoding]::ASCII.GetBytes("ustar")) },
    @{ Name="CAB";           Bytes=([byte[]](0x4D,0x53,0x43,0x46)) },
    @{ Name="MSI/OLE Compound";Bytes=([byte[]](0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1)) },
    @{ Name="ISO9660 (offset 0x8001)";Bytes=([Text.Encoding]::ASCII.GetBytes("CD001")) },
    @{ Name="PDF";           Bytes=([byte[]](0x25,0x50,0x44,0x46)) },
    @{ Name="RTF";           Bytes=([Text.Encoding]::ASCII.GetBytes("{\rtf")) },
    @{ Name="SQLite DB";     Bytes=([byte[]](0x53,0x51,0x4C,0x69,0x74,0x65)) },
    @{ Name="PNG";           Bytes=([byte[]](0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A)) },
    @{ Name="JPEG";          Bytes=([byte[]](0xFF,0xD8,0xFF)) },
    @{ Name="GIF87a/89a";    Bytes=([Text.Encoding]::ASCII.GetBytes("GIF8")) },
    @{ Name="BMP";           Bytes=([byte[]](0x42,0x4D)) },
    @{ Name="ICO";           Bytes=([byte[]](0x00,0x00,0x01,0x00)) },
    @{ Name="WEBP (RIFF)";   Bytes=([Text.Encoding]::ASCII.GetBytes("RIFF")) },
    @{ Name="WAV (RIFF)";    Bytes=([Text.Encoding]::ASCII.GetBytes("RIFF")) },
    @{ Name="MP3 (ID3)";     Bytes=([Text.Encoding]::ASCII.GetBytes("ID3")) },
    @{ Name="FLAC";          Bytes=([Text.Encoding]::ASCII.GetBytes("fLaC")) },
    @{ Name="OGG";           Bytes=([Text.Encoding]::ASCII.GetBytes("OggS")) },
    @{ Name="MP4/MOV (ftyp)";Bytes=([Text.Encoding]::ASCII.GetBytes("ftyp")) },
    @{ Name="TTF Font";      Bytes=([byte[]](0x00,0x01,0x00,0x00,0x00)) },
    @{ Name="OTF Font";      Bytes=([Text.Encoding]::ASCII.GetBytes("OTTO")) },
    @{ Name="EMF";           Bytes=([byte[]](0x01,0x00,0x00,0x00)) },
    @{ Name="LNK (shortcut)";Bytes=([byte[]](0x4C,0x00,0x00,0x00,0x01,0x14,0x02,0x00)) },
    @{ Name="Registry hive (regf)";Bytes=([Text.Encoding]::ASCII.GetBytes("regf")) },
    @{ Name="Windows EVTX log";Bytes=([Text.Encoding]::ASCII.GetBytes("ElfFile")) },
    @{ Name="PGP/GPG public key (armor)";Bytes=([Text.Encoding]::ASCII.GetBytes("-----BEGIN PGP")) },
    @{ Name="OpenSSH private key";Bytes=([Text.Encoding]::ASCII.GetBytes("-----BEGIN OPENSSH")) },
    @{ Name="PEM cert/key (generic)";Bytes=([Text.Encoding]::ASCII.GetBytes("-----BEGIN ")) },
    @{ Name="DEX (Android)";Bytes=([Text.Encoding]::ASCII.GetBytes("dex\n")) },
    @{ Name="Android boot image";Bytes=([Text.Encoding]::ASCII.GetBytes("ANDROID!")) },
    @{ Name="SquashFS";      Bytes=([Text.Encoding]::ASCII.GetBytes("hsqs")) },
    @{ Name="CPIO archive";  Bytes=([Text.Encoding]::ASCII.GetBytes("070701")) },
    @{ Name="Zlib stream (78 9C)";Bytes=([byte[]](0x78,0x9C)) },
    @{ Name="Zlib stream (78 01)";Bytes=([byte[]](0x78,0x01)) },
    @{ Name="Zlib stream (78 DA)";Bytes=([byte[]](0x78,0xDA)) }
)

foreach ($m in $magic) {
    if ($m.Bytes.Length -le $b.Length -and ($b[0..($m.Bytes.Length-1)] -join ',') -eq ($m.Bytes -join ',')) {
        Write-Host ("{0,-32}: MATCH at offset 0" -f $m.Name)
    }
}

Next-Step "SIGNATURE CARVING (magic bytes anywhere in file)"
Write-Host "Scanning whole file for embedded/appended known file signatures..."
$anyHits = $false
foreach ($m in $magic) {
    if ($m.Bytes.Length -lt 3) { continue }
    $hits = Find-Bytes $b $m.Bytes 5
    if ($hits.Count -gt 0) {
        $anyHits = $true
        $locations = ($hits | ForEach-Object { "0x{0:X}" -f $_ }) -join ", "
        Write-Host ("{0,-32}: {1}" -f $m.Name, $locations)
    }
}
if (-not $anyHits) { Write-Host "No additional embedded signatures found." }

# ============================================================
# MZ / PE DEEP ANALYSIS
# ============================================================

Next-Step "MZ / PE OCCURRENCES"

$mzHits = Find-Bytes $b ([byte[]](0x4D,0x5A)) 10000
$peHits = Find-Bytes $b ([byte[]](0x50,0x45,0x00,0x00)) 10000

Write-Host ("MZ occurrences : {0}" -f $mzHits.Count)
Write-Host ("PE signature occurrences : {0}" -f $peHits.Count)

$validPEs = @()
foreach ($off in $mzHits) {
    $r = Check-PEAt $b $off
    if ($r.ValidPE) { $validPEs += $r }
}
Write-Host ("Valid PE headers found : {0}" -f $validPEs.Count)
if ($validPEs.Count -gt 1) {
    Write-Host "Multiple valid PE headers => likely a dropper/installer/SFX with embedded payload(s)."
}

$PrimaryPE = $null
if ($validPEs.Count -gt 0) {
    $PrimaryPE = Parse-PEFull $b $validPEs[0].Offset
}

Next-Step "PE: DOS HEADER / RICH HEADER"
if ($PrimaryPE) {
    Write-Host ("PE header offset  : 0x{0:X}" -f $PrimaryPE.PEOffset)
    $rich = Find-RichHeader $b $PrimaryPE.PEOffset 0
    if ($rich) {
        Write-Host ("Rich header found at 0x{0:X}, XOR key {1}" -f $rich.Offset, $rich.XorKey)
        Write-Host "(Rich header encodes linker/compiler tool versions used to build the file.)"
    } else {
        Write-Host "No 'Rich' marker found (stripped, non-MSVC toolchain, or hand-crafted PE)."
    }
} else {
    Write-Host "No valid PE - skipped."
}

Next-Step "PE: COFF FILE HEADER"
if ($PrimaryPE) {
    Write-Host ("Machine            : {0} ({1})" -f $PrimaryPE.Machine, $PrimaryPE.MachineName)
    Write-Host ("Number of sections : {0}" -f $PrimaryPE.NumberOfSections)
    Write-Host ("TimeDateStamp      : {0} ({1} UTC)" -f $PrimaryPE.TimeDateStamp, $PrimaryPE.CompileTimeUTC)
    Write-Host ("Characteristics    : {0}" -f $PrimaryPE.Characteristics)
    Write-Host ("  Decoded          : {0}" -f $PrimaryPE.CharacteristicsDecoded)
} else { Write-Host "Skipped (no valid PE)." }

Next-Step "PE: OPTIONAL HEADER"
if ($PrimaryPE) {
    Write-Host ("Magic              : {0} ({1})" -f $PrimaryPE.OptionalHeaderMagic, $(if ($PrimaryPE.IsPE32Plus) {"PE32+ / 64-bit"} else {"PE32 / 32-bit"}))
    Write-Host ("Entry point RVA    : 0x{0:X}" -f $PrimaryPE.AddressOfEntryPoint)
    Write-Host ("Image base         : 0x{0:X}" -f $PrimaryPE.ImageBase)
    Write-Host ("Section alignment  : 0x{0:X}" -f $PrimaryPE.SectionAlignment)
    Write-Host ("File alignment     : 0x{0:X}" -f $PrimaryPE.FileAlignment)
    Write-Host ("Size of image      : 0x{0:X}" -f $PrimaryPE.SizeOfImage)
    Write-Host ("Size of headers    : 0x{0:X}" -f $PrimaryPE.SizeOfHeaders)
    Write-Host ("Checksum (header)  : 0x{0:X}" -f $PrimaryPE.CheckSum)
    Write-Host ("Subsystem          : {0} ({1})" -f $PrimaryPE.Subsystem, $PrimaryPE.SubsystemName)
} else { Write-Host "Skipped (no valid PE)." }

Next-Step "PE: DLL CHARACTERISTICS (mitigations)"
if ($PrimaryPE) {
    Write-Host ("Raw value : {0}" -f $PrimaryPE.DllCharacteristics)
    Write-Host ("Decoded   : {0}" -f $PrimaryPE.DllCharacteristicsDecoded)
    if ($PrimaryPE.DllCharacteristicsDecoded -notmatch "DYNAMIC_BASE") { Write-Host "NOTE: ASLR not enabled." }
    if ($PrimaryPE.DllCharacteristicsDecoded -notmatch "NX_COMPAT") { Write-Host "NOTE: DEP/NX not enabled." }
    if ($PrimaryPE.DllCharacteristicsDecoded -notmatch "CONTROL_FLOW_GUARD") { Write-Host "NOTE: CFG not enabled." }
} else { Write-Host "Skipped (no valid PE)." }

Next-Step "PE: DATA DIRECTORIES"
if ($PrimaryPE) {
    $PrimaryPE.DataDirectoriesRaw |
        Where-Object { $_.Size -gt 0 } |
        Format-Table Name, VirtualAddress, Size -AutoSize
} else { Write-Host "Skipped (no valid PE)." }

Next-Step "PE: SECTION TABLE + PER-SECTION ENTROPY"
if ($PrimaryPE) {
    $PrimaryPE.Sections | Format-Table Name, VirtualAddress, VirtualSize, SizeOfRawData, PointerToRawData, Entropy, Characteristics -AutoSize

    foreach ($s in $PrimaryPE.Sections) {
        if ($s.Entropy -gt 7.5) {
            Write-Host ("HIGH ENTROPY SECTION: {0} -> {1:N3} bits/byte (packed/encrypted/compressed data likely)" -f $s.Name, $s.Entropy)
        }
    }
} else { Write-Host "Skipped (no valid PE)." }

Next-Step "PE: KNOWN PACKER / PROTECTOR SECTION NAMES"
if ($PrimaryPE) {
    $found = $false
    foreach ($s in $PrimaryPE.Sections) {
        foreach ($kn in $KnownPackerSections) {
            if ($s.Name -like "*$kn*") {
                Write-Host ("Suspicious section name '{0}' matches known packer pattern '{1}'" -f $s.Name, $kn)
                $found = $true
            }
        }
    }
    if (-not $found) { Write-Host "No known packer section names detected (does not rule out custom/unknown packers)." }
} else { Write-Host "Skipped (no valid PE)." }

Next-Step "PE: OVERLAY (DATA APPENDED AFTER THE IMAGE)"
if ($PrimaryPE) {
    $ov = Find-PEOverlay $b $PrimaryPE
    if ($ov) {
        Write-Host ("Overlay detected: {0} bytes starting at file offset 0x{1:X}" -f $ov.OverlaySize, $ov.HeaderEnd)
        $ovLen = [Math]::Min([int]$ov.OverlaySize, $b.Length - [int]$ov.HeaderEnd)
        if ($ovLen -gt 0) {
            $ovEnt = Get-Entropy $b ([int]$ov.HeaderEnd) $ovLen
            Write-Host ("Overlay entropy : {0:N4} bits/byte" -f $ovEnt)
            Write-Host "(Overlays commonly hold: installer payloads, self-extracting archives, Authenticode signatures, or attacker-appended encrypted data.)"
        }
    } else {
        Write-Host "No overlay data detected (file ends where the PE image ends)."
    }
} else { Write-Host "Skipped (no valid PE)." }

Next-Step "PE: IMPORT TABLE (DLL NAMES)"
if ($PrimaryPE) {
    $importDir = $PrimaryPE.DataDirectoriesRaw | Where-Object { $_.Name -eq "Import Table" }
    if ($importDir -and $importDir.Size -gt 0) {
        $importRVA = [Convert]::ToInt64($importDir.VirtualAddress, 16)
        $fileOff = Convert-RVAToOffset $PrimaryPE.Sections $importRVA
        if ($fileOff -ge 0) {
            $dllNames = New-Object System.Collections.Generic.List[string]
            $cur = $fileOff
            $guard = 0
            while ($guard -lt 200) {
                $guard++
                if ($cur + 20 -gt $b.Length) { break }
                $nameRVA = UInt32LE $b ($cur + 12)
                $firstThunk = UInt32LE $b ($cur + 16)
                $origFirstThunk = UInt32LE $b $cur
                if ($nameRVA -eq 0 -and $firstThunk -eq 0 -and $origFirstThunk -eq 0) { break }
                $nameOff = Convert-RVAToOffset $PrimaryPE.Sections $nameRVA
                if ($nameOff -ge 0) {
                    $dllNames.Add((Read-CString $b $nameOff 128))
                }
                $cur += 20
            }
            if ($dllNames.Count -gt 0) {
                Write-Host ("Imported DLLs ({0}):" -f $dllNames.Count)
                $dllNames | ForEach-Object { Write-Host ("  - {0}" -f $_) }
            } else {
                Write-Host "Import directory present but no DLL names could be resolved."
            }
        } else {
            Write-Host "Import directory RVA does not map to any section (possibly packed/obfuscated)."
        }
    } else {
        Write-Host "No import table (unusual for normal PEs; typical of packed/shellcode-style binaries)."
    }
} else { Write-Host "Skipped (no valid PE)." }

Next-Step "PE: EXPORT TABLE"
if ($PrimaryPE) {
    $exportDir = $PrimaryPE.DataDirectoriesRaw | Where-Object { $_.Name -eq "Export Table" }
    if ($exportDir -and $exportDir.Size -gt 0) {
        $exportRVA = [Convert]::ToInt64($exportDir.VirtualAddress, 16)
        $fileOff = Convert-RVAToOffset $PrimaryPE.Sections $exportRVA
        Write-Host ("Export table present at RVA 0x{0:X}, size {1} bytes" -f $exportRVA, $exportDir.Size)
        if ($fileOff -ge 0 -and ($fileOff + 16) -le $b.Length) {
            $nameRVA = UInt32LE $b ($fileOff + 12)
            $nameOff = Convert-RVAToOffset $PrimaryPE.Sections $nameRVA
            if ($nameOff -ge 0) {
                Write-Host ("Module export name : {0}" -f (Read-CString $b $nameOff 128))
            }
        }
    } else {
        Write-Host "No export table (normal for most EXEs; DLLs usually have one)."
    }
} else { Write-Host "Skipped (no valid PE)." }

Next-Step "PE: TLS CALLBACKS"
if ($PrimaryPE) {
    $tlsDir = $PrimaryPE.DataDirectoriesRaw | Where-Object { $_.Name -eq "TLS Table" }
    if ($tlsDir -and $tlsDir.Size -gt 0) {
        Write-Host ("TLS directory present at RVA {0} - check for TLS callbacks (can run before main entry point, common anti-debug/anti-sandbox trick)." -f $tlsDir.VirtualAddress)
    } else {
        Write-Host "No TLS directory."
    }
} else { Write-Host "Skipped (no valid PE)." }

Next-Step "PE: AUTHENTICODE / DIGITAL SIGNATURE"
if ($PrimaryPE) {
    $certDir = $PrimaryPE.DataDirectoriesRaw | Where-Object { $_.Name -eq "Certificate Table (Authenticode)" }
    if ($certDir -and $certDir.Size -gt 0) {
        # NOTE: for this directory, VirtualAddress is actually a raw FILE OFFSET, not an RVA.
        $certOff = [Convert]::ToInt64($certDir.VirtualAddress, 16)
        Write-Host ("Certificate table present at file offset 0x{0:X}, size {1} bytes" -f $certOff, $certDir.Size)
        if (($certOff + 8) -le $b.Length) {
            $wLen = UInt32LE $b $certOff
            $wRev = UInt16LE $b ($certOff + 4)
            $wType = UInt16LE $b ($certOff + 6)
            Write-Host ("  dwLength=0x{0:X} wRevision=0x{1:X4} wCertificateType=0x{2:X4}" -f $wLen, $wRev, $wType)
            Write-Host "  (File is Authenticode-signed; signature validity is NOT checked by this script.)"
        }
    } else {
        Write-Host "No digital signature (unsigned binary)."
    }
} else { Write-Host "Skipped (no valid PE)." }

Next-Step "ELF HEADER (if applicable)"
$elf = Parse-ELFHeader $b
if ($elf) {
    $elf | Format-List
} else {
    Write-Host "Not an ELF file."
}

Next-Step "MACH-O HEADER (if applicable)"
$macho = Parse-MachOHeader $b
if ($macho) {
    $macho | Format-List
} else {
    Write-Host "Not a Mach-O file."
}

Next-Step "ZIP-BASED CONTAINER CHECK (docx/xlsx/pptx/jar/apk/zip)"
if ($b.Length -ge 4 -and $b[0] -eq 0x50 -and $b[1] -eq 0x4B) {
    Write-Host "File is ZIP-based. Attempting to list central directory via .NET ZipFile..."
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $tmp = [IO.Path]::GetTempFileName()
        Copy-Item -LiteralPath $FullPath -Destination $tmp -Force
        $zip = [IO.Compression.ZipFile]::OpenRead($tmp)
        $totalEntries = $zip.Entries.Count
        $entries = $zip.Entries | Select-Object -First 50
        foreach ($e in $entries) {
            Write-Host ("  {0,10} bytes  {1}" -f $e.Length, $e.FullName)
        }
        $zip.Dispose()
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        if ($totalEntries -gt 50) { Write-Host ("  ... and more ({0} entries total)" -f $totalEntries) }
    } catch {
        Write-Host ("Could not list ZIP contents: {0}" -f $_.Exception.Message)
    }
} else {
    Write-Host "Not a ZIP-based container."
}

Next-Step "OLE / COMPOUND FILE (legacy Office / MSI) CHECK"
if ($b.Length -ge 8 -and $b[0] -eq 0xD0 -and $b[1] -eq 0xCF -and $b[2] -eq 0x11 -and $b[3] -eq 0xE0) {
    Write-Host "File is an OLE2/Compound Binary File (legacy .doc/.xls/.ppt, .msi, or similar)."
} else {
    Write-Host "Not an OLE2 compound file."
}

# ============================================================
# STATISTICAL RANDOMNESS TESTS
# ============================================================

Next-Step "ENTROPY (WHOLE FILE)"
$ent = Get-Entropy $b
Write-Host ("Whole file entropy : {0:N4} bits/byte (max 8.0)" -f $ent)
if ($ent -gt 7.9) { Write-Host "Interpretation : EXTREMELY HIGH - almost certainly encrypted or compressed" }
elseif ($ent -gt 7.5) { Write-Host "Interpretation : VERY HIGH - likely compressed/encrypted/random-like data" }
elseif ($ent -gt 7.0) { Write-Host "Interpretation : HIGH - compression/encryption/packing possible" }
elseif ($ent -gt 6.0) { Write-Host "Interpretation : MODERATE" }
else { Write-Host "Interpretation : relatively structured/plain data" }

Next-Step "ENTROPY MAP (1 MiB BLOCKS)"
$blockSize = 1MB
for ($offset = 0; $offset -lt $b.Length; $offset += $blockSize) {
    $len = [Math]::Min($blockSize, $b.Length - $offset)
    $e = Get-Entropy $b $offset $len
    $marker = if ($e -gt 7.5) { " <-- high" } else { "" }
    Write-Host ("  0x{0:X8} - 0x{1:X8} : {2:N4}{3}" -f $offset, ($offset + $len - 1), $e, $marker)
}

Next-Step "ENTROPY MAP (HIGH RESOLUTION, 64 SLICES)"
$sliceCount = 64
$sliceSize = [Math]::Max(1, [int]($b.Length / $sliceCount))
for ($i = 0; $i -lt $sliceCount; $i++) {
    $off = $i * $sliceSize
    if ($off -ge $b.Length) { break }
    $len = [Math]::Min($sliceSize, $b.Length - $off)
    $e = Get-Entropy $b $off $len
    $bar = "#" * [int]($e / 8.0 * 40)
    Write-Host ("  0x{0:X8} [{1,-40}] {2:N2}" -f $off, $bar, $e)
}

Next-Step "BYTE FREQUENCY (TOP 20)"
$freq = New-Object int[] 256
foreach ($x in $b) { $freq[$x]++ }
$top = 0..255 | ForEach-Object {
    [PSCustomObject]@{ Byte = $_; Count = $freq[$_]; Hex = ("{0:X2}" -f $_) }
} | Sort-Object Count -Descending | Select-Object -First 20
$top | Format-Table -AutoSize

Next-Step "CHI-SQUARE RANDOMNESS TEST"
$chi2 = Get-Chi2 $b
Write-Host ("Chi-square value : {0:N2} (255 degrees of freedom)" -f $chi2)
if ($chi2 -lt 220 -or $chi2 -gt 320) {
    Write-Host "Value is noticeably off from the ~255 expected for perfectly random data -> structured/non-random content."
} else {
    Write-Host "Value is close to the ~255 expected for random data -> consistent with encryption/strong compression."
}

Next-Step "ARITHMETIC MEAN TEST"
$mean = Get-ArithmeticMean $b
Write-Host ("Arithmetic mean of bytes : {0:N3} (random data centers around 127.5)" -f $mean)

Next-Step "MONTE CARLO PI ESTIMATION (RANDOMNESS QUALITY)"
$mc = Get-MonteCarloPi $b
Write-Host ("Estimated Pi : {0:N6}  (real Pi = {1:N6})" -f $mc.Pi, [Math]::PI)
Write-Host ("Error        : {0:N3}% over {1} sample points" -f $mc.Error, $mc.Points)
if ($mc.Error -lt 1.0) { Write-Host "Very low error -> data behaves like high-quality random/encrypted output." }

Next-Step "SERIAL CORRELATION COEFFICIENT"
$scc = Get-SerialCorrelation $b
Write-Host ("Serial correlation coefficient : {0:N6} (0.0 = no correlation / random-like)" -f $scc)
if ([Math]::Abs($scc) -lt 0.02) { Write-Host "Near zero -> consistent with encrypted/compressed/random data." }
else { Write-Host "Noticeable correlation between adjacent bytes -> structured data." }

Next-Step "NULL / 0xFF BYTE RATIO"
$zeroPct = ($freq[0] / [double]$b.Length) * 100
$ffPct   = ($freq[255] / [double]$b.Length) * 100
Write-Host ("0x00 bytes : {0:N2}%" -f $zeroPct)
Write-Host ("0xFF bytes : {0:N2}%" -f $ffPct)
if ($zeroPct -gt 15) { Write-Host "High 0x00 ratio -> typical of sparse/structured binary data (not encrypted)." }

# ============================================================
# REPEATED PATTERNS / ECB DETECTION
# ============================================================

Next-Step "REPEATED 8-BYTE PATTERNS"
$patterns = @{}
$scanLen = [Math]::Min($b.Length, 4MB)
for ($i = 0; $i -le $scanLen - 8; $i++) {
    $key = [BitConverter]::ToUInt64($b, $i)
    if ($patterns.ContainsKey($key)) { $patterns[$key]++ } else { $patterns[$key] = 1 }
}
$repeated = $patterns.GetEnumerator() | Where-Object { $_.Value -ge 20 } | Sort-Object Value -Descending | Select-Object -First 30
if ($repeated.Count -gt 0) {
    $repeated | ForEach-Object { [PSCustomObject]@{ Pattern = ("{0:X16}" -f $_.Key); Count = $_.Value } } | Format-Table -AutoSize
} else {
    Write-Host "No heavily repeated 8-byte patterns (first 4 MiB scanned)."
}

Next-Step "16-BYTE ALIGNED BLOCK REPETITION (AES-ECB INDICATOR)"
$blockMap = @{}
$ecbScanLen = [Math]::Min($b.Length, 8MB)
$alignedBlocks = [int]([Math]::Floor($ecbScanLen / 16))
for ($i = 0; $i -lt $alignedBlocks; $i++) {
    $off = $i * 16
    $k1 = [BitConverter]::ToUInt64($b, $off)
    $k2 = [BitConverter]::ToUInt64($b, $off + 8)
    $key = "$k1:$k2"
    if ($blockMap.ContainsKey($key)) { $blockMap[$key]++ } else { $blockMap[$key] = 1 }
}
$dupBlocks = $blockMap.GetEnumerator() | Where-Object { $_.Value -gt 1 }
$dupCount = ($dupBlocks | Measure-Object -Property Value -Sum).Sum
if ($dupBlocks.Count -gt 0 -and $alignedBlocks -gt 0) {
    Write-Host ("Found {0} distinct 16-byte blocks that repeat, {1} total duplicate block instances out of {2} blocks checked." -f $dupBlocks.Count, $dupCount, $alignedBlocks)
    Write-Host "Repeated ciphertext blocks at 16-byte boundaries are a classic AES/DES-ECB-mode indicator (identical plaintext blocks -> identical ciphertext blocks)."
} else {
    Write-Host "No repeated 16-byte aligned blocks found -> no obvious ECB-mode signature."
}

# ============================================================
# STRINGS
# ============================================================

Next-Step "ASCII STRINGS"
$strings = Find-ASCII-Strings $b 6
Write-Host ("Found {0} ASCII strings >= 6 chars" -f $strings.Count)

$interestingRegex = "UPX|VMProtect|Themida|ASPack|MPRESS|Enigma|LLVM|GCC|clang|MSVC|Microsoft|Borland|MinGW|C\+\+|Python|Go build|Rust|Java|Node|Electron|Qt|OpenSSL|libssl|libcrypto|zlib|LZMA|7-Zip|PECompact|Obsidium|Delphi|AutoIt|NSIS|InnoSetup|WiX|dotnet|\.NET|mscorlib|clr\.dll"
$interesting = $strings | Where-Object { $_.String -match $interestingRegex } | Select-Object -First 100
if ($interesting.Count -gt 0) {
    Write-Host "Compiler / toolchain / packer / framework hints:"
    $interesting | Format-Table -AutoSize
} else {
    Write-Host "No obvious compiler/packer/framework strings found."
}

Next-Step "FIRST ASCII STRINGS (sample)"
$strings | Select-Object -First 100 | Format-Table -AutoSize

Next-Step "UNICODE (UTF-16LE) STRINGS"
$ustrings = Find-UnicodeStrings $b 5
Write-Host ("Found {0} UTF-16LE strings >= 5 chars" -f $ustrings.Count)
$ustrings | Select-Object -First 50 | Format-Table -AutoSize

Next-Step "NETWORK INDICATORS (URLs / IPs / EMAILS)"
$allStringText = ($strings | Select-Object -First 5000 | ForEach-Object { $_.String })
$urls = $allStringText | Select-String -Pattern "https?://[^\s""'<>]+" -AllMatches | ForEach-Object { $_.Matches.Value } | Select-Object -Unique | Select-Object -First 50
$ips  = $allStringText | Select-String -Pattern "\b(?:\d{1,3}\.){3}\d{1,3}\b" -AllMatches | ForEach-Object { $_.Matches.Value } | Select-Object -Unique | Select-Object -First 50
$emails = $allStringText | Select-String -Pattern "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" -AllMatches | ForEach-Object { $_.Matches.Value } | Select-Object -Unique | Select-Object -First 50

if ($urls.Count -gt 0) { Write-Host "URLs:"; $urls | ForEach-Object { Write-Host "  $_" } } else { Write-Host "No URLs found." }
if ($ips.Count -gt 0) { Write-Host "IPv4 addresses:"; $ips | ForEach-Object { Write-Host "  $_" } } else { Write-Host "No IPv4-looking strings found." }
if ($emails.Count -gt 0) { Write-Host "Emails:"; $emails | ForEach-Object { Write-Host "  $_" } } else { Write-Host "No emails found." }

Next-Step "FILESYSTEM PATH / REGISTRY KEY INDICATORS"
$paths = $allStringText | Select-String -Pattern "[A-Za-z]:\\[^\s""'<>]+|/(?:usr|etc|home|tmp|var|opt)/[^\s""'<>]+" -AllMatches | ForEach-Object { $_.Matches.Value } | Select-Object -Unique | Select-Object -First 40
$regKeys = $allStringText | Select-String -Pattern "HKEY_[A-Z_]+\\[^\s""'<>]+|SOFTWARE\\[^\s""'<>]+" -AllMatches | ForEach-Object { $_.Matches.Value } | Select-Object -Unique | Select-Object -First 40
if ($paths.Count -gt 0) { Write-Host "File paths:"; $paths | ForEach-Object { Write-Host "  $_" } } else { Write-Host "No obvious file paths found." }
if ($regKeys.Count -gt 0) { Write-Host "Registry keys:"; $regKeys | ForEach-Object { Write-Host "  $_" } } else { Write-Host "No obvious registry keys found." }

# ============================================================
# KEY / CERTIFICATE MATERIAL
# ============================================================

Next-Step "PEM KEY / CERTIFICATE BLOCKS"
$pemHits = $strings | Where-Object { $_.String -match "-----BEGIN [A-Z0-9 ]+-----" }
if ($pemHits.Count -gt 0) {
    Write-Host "PEM-encoded blocks detected (certificate/key material):"
    $pemHits | Select-Object Offset, String | Format-Table -AutoSize
} else {
    Write-Host "No PEM blocks found."
}

Next-Step "SSH PRIVATE/PUBLIC KEY DETECTION"
$sshHits = $strings | Where-Object { $_.String -match "ssh-rsa|ssh-ed25519|OPENSSH PRIVATE KEY|BEGIN RSA PRIVATE KEY" }
if ($sshHits.Count -gt 0) {
    Write-Host "SSH key material found:"
    $sshHits | Select-Object Offset, String | Format-Table -AutoSize
} else {
    Write-Host "No SSH key material found."
}

Next-Step "DER CERTIFICATE HEURISTIC (ASN.1 SEQUENCE 0x30 0x82)"
$derHits = Find-Bytes $b ([byte[]](0x30,0x82)) 20
if ($derHits.Count -gt 0) {
    Write-Host ("Found {0} candidate ASN.1 'SEQUENCE' markers (possible X.509 cert / DER key material):" -f $derHits.Count)
    $derHits | ForEach-Object { Write-Host ("  offset 0x{0:X}" -f $_) }
} else {
    Write-Host "No DER SEQUENCE markers found."
}

# ============================================================
# ENCODING DETECTION (base64 / base32 / base58 / hex / rot)
# ============================================================

Next-Step "BASE64 CANDIDATE STRINGS + DECODE ATTEMPT"
$b64Candidates = $strings | Where-Object { $_.String.Length -ge 20 -and $_.String -match "^[A-Za-z0-9+/]{20,}={0,2}$" } | Select-Object -First 15
if ($b64Candidates.Count -gt 0) {
    foreach ($c in $b64Candidates) {
        $dec = Try-Base64Decode $c.String
        if ($dec) {
            Write-Host ("offset 0x{0:X} : {1}" -f $c.Offset, (Get-BlobSummary $dec))
            $magicHit = $magic | Where-Object { $dec.Length -ge $_.Bytes.Length -and ($dec[0..($_.Bytes.Length-1)] -join ',') -eq ($_.Bytes -join ',') }
            if ($magicHit) { Write-Host ("  -> decodes to a recognizable file type: {0}" -f $magicHit[0].Name) }
        } else {
            Write-Host ("offset 0x{0:X} : looked like base64 but failed to decode" -f $c.Offset)
        }
    }
} else {
    Write-Host "No base64-looking strings (min 20 chars) found."
}

Next-Step "BASE32 CANDIDATE STRINGS + DECODE ATTEMPT"
$b32Candidates = $strings | Where-Object { $_.String.Length -ge 20 -and $_.String -match "^[A-Z2-7]{20,}={0,6}$" } | Select-Object -First 10
if ($b32Candidates.Count -gt 0) {
    foreach ($c in $b32Candidates) {
        $dec = Try-Base32Decode $c.String
        if ($dec) { Write-Host ("offset 0x{0:X} : {1}" -f $c.Offset, (Get-BlobSummary $dec)) }
    }
} else {
    Write-Host "No base32-looking strings found."
}

Next-Step "BASE58 CANDIDATE STRINGS (WALLETS / KEYS) + DECODE ATTEMPT"
$b58Candidates = $strings | Where-Object { $_.String.Length -ge 25 -and $_.String.Length -le 60 -and $_.String -match "^[1-9A-HJ-NP-Za-km-z]{25,60}$" } | Select-Object -First 10
if ($b58Candidates.Count -gt 0) {
    foreach ($c in $b58Candidates) {
        $dec = Try-Base58Decode $c.String
        if ($dec) { Write-Host ("offset 0x{0:X} : {1}  (Base58 - reminiscent of Bitcoin keys/addresses)" -f $c.Offset, (Get-BlobSummary $dec)) }
    }
} else {
    Write-Host "No base58-looking strings found."
}

Next-Step "HEX-ENCODED STRING CANDIDATES + DECODE ATTEMPT"
$hexCandidates = $strings | Where-Object { $_.String.Length -ge 20 -and ($_.String.Length % 2 -eq 0) -and $_.String -match "^[0-9A-Fa-f]{20,}$" } | Select-Object -First 10
if ($hexCandidates.Count -gt 0) {
    foreach ($c in $hexCandidates) {
        $dec = Try-HexDecode $c.String
        if ($dec) { Write-Host ("offset 0x{0:X} : {1}" -f $c.Offset, (Get-BlobSummary $dec)) }
    }
} else {
    Write-Host "No long hex-string candidates found."
}

Next-Step "ROT13 / ROT47 TRANSFORM PREVIEW"
$rotCandidates = $strings | Where-Object { $_.String -match "^[A-Za-z0-9 !-~]{10,60}$" } | Select-Object -First 5
if ($rotCandidates.Count -gt 0) {
    foreach ($c in $rotCandidates) {
        Write-Host ("offset 0x{0:X}" -f $c.Offset)
        Write-Host ("  original : {0}" -f $c.String)
        Write-Host ("  rot13    : {0}" -f (Get-Rot13 $c.String))
        Write-Host ("  rot47    : {0}" -f (Get-Rot47 $c.String))
    }
} else {
    Write-Host "No suitable printable strings for ROT13/47 preview."
}

# ============================================================
# KNOWN CRYPTO CONSTANT SIGNATURES
# ============================================================

Next-Step "KNOWN CRYPTOGRAPHIC CONSTANT SIGNATURES"
$cryptoSigs = Get-CryptoSignatureList
$anyCrypto = $false
foreach ($sig in $cryptoSigs) {
    $hits = Find-Bytes $b $sig.Pattern 5
    if ($hits.Count -gt 0) {
        $anyCrypto = $true
        $locations = ($hits | ForEach-Object { "0x{0:X}" -f $_ }) -join ", "
        Write-Host ("{0,-52}: FOUND at {1}" -f $sig.Name, $locations)
    }
}
if (-not $anyCrypto) {
    Write-Host "No known static crypto constants found."
    Write-Host "(This does NOT rule out crypto: whitebox/obfuscated implementations, hardware-accelerated AES-NI code paths,"
    Write-Host " and stream ciphers like RC4/ChaCha with obfuscated constants often have no recognizable static signature.)"
}

# ============================================================
# XOR ANALYSIS
# ============================================================

Next-Step "SINGLE-BYTE XOR BRUTEFORCE"
$sampleLen = [Math]::Min(65536, $b.Length)
$xorResults = New-Object System.Collections.Generic.List[object]
for ($key = 0; $key -lt 256; $key++) {
    $score = 0
    for ($i = 0; $i -lt $sampleLen; $i++) {
        $x = $b[$i] -bxor $key
        if (($x -ge 32 -and $x -le 126) -or $x -eq 9 -or $x -eq 10 -or $x -eq 13) { $score++ }
    }
    $xorResults.Add([PSCustomObject]@{ Key = ("0x{0:X2}" -f $key); Score = $score; Percent = (($score / [double]$sampleLen) * 100) })
}
$bestXor = $xorResults | Sort-Object Score -Descending | Select-Object -First 10
$bestXor | Format-Table -AutoSize
if (($bestXor | Select-Object -First 1).Percent -gt 90) {
    Write-Host "Best key yields >90% printable output -> file is very likely single-byte XOR 'encrypted' plaintext."
}

Next-Step "BEST SINGLE-BYTE XOR PREVIEWS"
foreach ($r in ($xorResults | Sort-Object Score -Descending | Select-Object -First 5)) {
    $key = [Convert]::ToInt32($r.Key.Substring(2), 16)
    $preview = ""
    for ($i = 0; $i -lt 128 -and $i -lt $b.Length; $i++) {
        $x = $b[$i] -bxor $key
        if ($x -ge 32 -and $x -le 126) { $preview += [char]$x } else { $preview += "." }
    }
    Write-Host ("KEY {0}: {1}" -f $r.Key, $preview)
}

Next-Step "REPEATING-KEY XOR: KEY SIZE ESTIMATION (HAMMING DISTANCE)"
$keySizeGuesses = Guess-XorKeySize $b 2 40 6
if ($keySizeGuesses.Count -gt 0) {
    $keySizeGuesses | Format-Table -AutoSize
    Write-Host "Lower normalized distance = more likely correct key size (classic Vigenere/repeating-XOR cryptanalysis)."
} else {
    Write-Host "File too small to estimate a repeating XOR key size."
}

Next-Step "REPEATING-KEY XOR: KEY RECOVERY ATTEMPT + PREVIEW"
if ($keySizeGuesses.Count -gt 0) {
    $bestGuess = $keySizeGuesses[0].KeySize
    $recoveredKey = Break-RepeatingXor $b $bestGuess
    $keyHex = ($recoveredKey | ForEach-Object { "{0:X2}" -f $_ }) -join " "
    $keyAscii = ASCII $recoveredKey $recoveredKey.Length
    Write-Host ("Assumed key size : {0}" -f $bestGuess)
    Write-Host ("Recovered key (hex)   : {0}" -f $keyHex)
    Write-Host ("Recovered key (ascii) : {0}" -f $keyAscii)

    $previewLen = [Math]::Min(160, $b.Length)
    $preview = ""
    for ($i = 0; $i -lt $previewLen; $i++) {
        $x = $b[$i] -bxor $recoveredKey[$i % $bestGuess]
        if ($x -ge 32 -and $x -le 126) { $preview += [char]$x } else { $preview += "." }
    }
    Write-Host ("Decoded preview : {0}" -f $preview)
} else {
    Write-Host "Skipped (no key size candidates)."
}

Next-Step "GENERIC ENCRYPTION LIKELIHOOD (AES/CHACHA/ETC - HEURISTIC ONLY)"
Write-Host "Modern block/stream ciphers (AES-CBC/CTR/GCM, ChaCha20, Salsa20) produce output"
Write-Host "statistically indistinguishable from random data. This script CANNOT identify the"
Write-Host "specific algorithm from ciphertext alone - only supporting evidence is possible:"
Write-Host ("  - Whole-file entropy      : {0:N3} / 8.0" -f $ent)
Write-Host ("  - Chi-square              : {0:N1} (ideal random ~= 255)" -f $chi2)
Write-Host ("  - Monte Carlo Pi error    : {0:N2}%" -f $mc.Error)
Write-Host ("  - Serial correlation      : {0:N5} (ideal random ~= 0)" -f $scc)
$encScore = 0
if ($ent -gt 7.9) { $encScore += 2 }
if ($chi2 -ge 200 -and $chi2 -le 320) { $encScore += 2 }
if ($mc.Error -lt 2.0) { $encScore += 1 }
if ([Math]::Abs($scc) -lt 0.02) { $encScore += 1 }
if (-not $anyCrypto -and $validPEs.Count -eq 0) { $encScore += 1 }
Write-Host ("Heuristic encryption-likelihood score : {0} / 7" -f $encScore)
if ($encScore -ge 5) {
    Write-Host "-> Data is statistically consistent with strong encryption or maximally-compressed data (AES/ChaCha-class cipher, or LZMA/zstd-class compressor)."
} elseif ($encScore -ge 3) {
    Write-Host "-> Some indicators of encryption/compression, but not conclusive - could be partially packed data."
} else {
    Write-Host "-> Data does not look encrypted; likely plain/structured binary content."
}

# ============================================================
# CHUNK HASHES
# ============================================================

Next-Step "CHUNK SHA-256 HASHES (1 MiB BLOCKS)"
$sha256Hasher = [Security.Cryptography.SHA256]::Create()
for ($offset = 0; $offset -lt $b.Length; $offset += 1MB) {
    $len = [Math]::Min(1MB, $b.Length - $offset)
    $chunk = New-Object byte[] $len
    [Array]::Copy($b, $offset, $chunk, 0, $len)
    $hash = [BitConverter]::ToString($sha256Hasher.ComputeHash($chunk)).Replace("-", "")
    Write-Host ("0x{0:X8}  {1}" -f $offset, $hash)
}

Next-Step "MID-FILE COMPRESSED STREAM SCAN (ZLIB/GZIP INSIDE THE FILE)"
$zlibHeaders = @([byte[]](0x78,0x9C), [byte[]](0x78,0x01), [byte[]](0x78,0xDA), [byte[]](0x78,0x5E))
$foundZlib = $false
foreach ($zh in $zlibHeaders) {
    $hits = Find-Bytes $b $zh 10
    if ($hits.Count -gt 0) {
        $foundZlib = $true
        $locations = ($hits | ForEach-Object { "0x{0:X}" -f $_ }) -join ", "
        Write-Host ("zlib stream header {0}: {1}" -f (Hex $zh 2), $locations)
    }
}
$gzipHits = Find-Bytes $b ([byte[]](0x1F,0x8B,0x08)) 10
if ($gzipHits.Count -gt 0) {
    $foundZlib = $true
    $locations = ($gzipHits | ForEach-Object { "0x{0:X}" -f $_ }) -join ", "
    Write-Host ("gzip stream header : {0}" -f $locations)
}
if (-not $foundZlib) { Write-Host "No embedded zlib/gzip stream headers found." }

Next-Step "SUSPICIOUS API / BEHAVIOR STRING KEYWORDS"
$apiRegex = "VirtualAlloc|VirtualProtect|WriteProcessMemory|CreateRemoteThread|LoadLibrary|GetProcAddress|RegSetValue|InternetOpen|WinHttp|URLDownloadToFile|ShellExecute|CreateProcess|IsDebuggerPresent|NtQueryInformationProcess|CryptEncrypt|CryptDecrypt|BCryptEncrypt|EVP_EncryptInit|AES_encrypt|SetWindowsHookEx|keybd_event|GetAsyncKeyState"
$apiHits = $strings | Where-Object { $_.String -match $apiRegex } | Select-Object -First 60
if ($apiHits.Count -gt 0) {
    Write-Host "Potentially interesting API/behavior strings (informational, not inherently malicious):"
    $apiHits | Select-Object Offset, String | Format-Table -AutoSize
} else {
    Write-Host "No notable API-name strings found (may be dynamically resolved / packed)."
}

# ============================================================
# FINAL SUMMARY
# ============================================================

Write-Host ""
Write-Host "============================================================"
Write-Host " SUMMARY"
Write-Host "============================================================"

Write-Host ""
Write-Host ("Total analysis steps run : {0}" -f $script:StepCounter)
Write-Host ("File size                : {0} bytes" -f $b.Length)
Write-Host ("SHA256                   : {0}" -f $sha256)
Write-Host ("Whole-file entropy       : {0:N4}" -f $ent)
Write-Host ("Encryption-likelihood    : {0} / 7" -f $encScore)

if ($validPEs.Count -eq 0 -and -not $elf -and -not $macho) {
    Write-Host ""
    Write-Host "NOT a recognized PE/ELF/Mach-O executable at offset 0."
    if ($ent -gt 7.5) {
        Write-Host "High entropy strongly suggests compression, encryption, or packing."
    } else {
        Write-Host "Entropy is not extremely high; data appears at least partially structured."
    }
    if ($mzHits.Count -gt 0) {
        Write-Host ("There are {0} literal 'MZ' byte sequences in the file, but none forms a valid PE header." -f $mzHits.Count)
    }
    Write-Host ""
    Write-Host "Reminder: a file extension (.dll, .exe, etc.) does NOT guarantee the file's real format matches it."
} elseif ($validPEs.Count -gt 0) {
    Write-Host ""
    Write-Host ("Valid PE structure(s) found: {0}" -f $validPEs.Count)
    if ($PrimaryPE) {
        Write-Host ("  Primary PE: {0}, subsystem {1}, entropy of whole file {2:N2}" -f $PrimaryPE.MachineName, $PrimaryPE.SubsystemName, $ent)
    }
} elseif ($elf) {
    Write-Host ""
    Write-Host ("Valid ELF structure found: {0} {1} for {2}" -f $elf.Class, $elf.Type, $elf.Machine)
} elseif ($macho) {
    Write-Host ""
    Write-Host ("Valid Mach-O structure found: {0} {1} for {2}" -f $macho.Bitness, $macho.FileType, $macho.CpuType)
}

Write-Host ""
Write-Host "Analysis finished."
Write-Host ""
