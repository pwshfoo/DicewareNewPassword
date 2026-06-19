# Private helper - cryptographically secure integer in [$Min, $Max).
# PS7/.NET 5+: RandomNumberGenerator.Fill   PS5.1/.NET Framework: RNGCryptoServiceProvider
# 32-bit range eliminates meaningful modulo bias (2^32 / 6 leaves <0.0000002% skew).
function script:Invoke-CryptoRandom {
    param(
        [Alias('Minimum')][int]$Min,
        [Alias('Maximum')][int]$Max
    )
    $range = [uint32]($Max - $Min)
    $bytes = [byte[]]::new(4)
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    } else {
        $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
        $rng.GetBytes($bytes)
        $rng.Dispose()
    }
    return [int]([BitConverter]::ToUInt32($bytes, 0) % $range) + $Min
}

function New-Password {
<#
.SYNOPSIS
    Generates a diceware passphrase using the EFF large wordlist.
.DESCRIPTION
    Simulates rolling 5 six-sided dice to select each word from the EFF large
    wordlist (7776 words). Each word selection is independent, providing strong
    randomness per word. Compatible with PowerShell 5.1 and 7.
.PARAMETER WordCount
    Number of words to include in the passphrase. Default is 4.
.PARAMETER Separator
    Character(s) placed between words. Default is '-'.
.PARAMETER Template
    Accepted for backward compatibility. Not used by diceware generation.
.PARAMETER WordlistPath
    Path to the EFF large wordlist file. If not specified, the module looks
    for eff_large_wordlist.txt in its own directory, then one level up.
.PARAMETER SaltChars
    Number of characters to generate via New-DicewareRandomString and insert
    as a salt word at the position specified by SaltPosition. Default is 0 (no salt).
.PARAMETER SaltPosition
    Position at which to insert the salt word: 0 = before first word, 1 = after
    first word, 2 = after second word, and so on. Values greater than WordCount
    place the salt at the end. Default places salt at the end.
.PARAMETER UppercaseFirstLetter
    Capitalizes the first letter of each diceware word before joining.
.PARAMETER PlainText
    Returns the Password property as a plain string instead of a SecureString.
    By default Password is returned as a SecureString to reduce plaintext exposure.
.PARAMETER Export
    Encrypts the output object to a file after generation. Requires -EncryptedJsonPath and -KeyFilePath.
.PARAMETER EncryptedJsonPath
    Path to write the AES-256 encrypted JSON reconstruction file. Used with -Export.
.PARAMETER KeyFilePath
    Path to write (or read) the 256-bit AES key file. Used with -Export.
.PARAMETER KeyCarrierImage
    Carrier image (BMP, PNG, or JPEG) into which the .key file is hidden using LSB
    steganography. Requires -Export and -DataCarrierImage. Output is always saved as BMP.
.PARAMETER DataCarrierImage
    Carrier image into which the .jsonenc file is hidden. Should differ from
    -KeyCarrierImage and be sent via a separate channel. Requires -Export and -KeyCarrierImage.
.PARAMETER KeyStegoOutput
    Output path for the stego BMP containing the hidden .key. Defaults to
    .password\<timestamp>_key.bmp in the current directory.
.PARAMETER DataStegoOutput
    Output path for the stego BMP containing the hidden .jsonenc. Defaults to
    .password\<timestamp>_data.bmp in the current directory.
.EXAMPLE
    New-Password
    Returns a 4-word diceware passphrase, e.g. "cheddar-crabgrass-armoire-bundle"
.EXAMPLE
    New-Password -WordCount 5 -Separator ' '
    Returns a 5-word space-separated passphrase.
.EXAMPLE
    New-Password -UppercaseFirstLetter
    Returns e.g. "Cheddar-Crabgrass-Armoire-Bundle"
.EXAMPLE
    New-Password -SaltChars 4 -SaltPosition 2
    Generates 4 diceware chars and inserts them after the 2nd word.
.EXAMPLE
    New-Password -SaltChars 6
    Generates 6 diceware chars and appends them at the end.
.EXAMPLE
    New-Password -WordlistPath 'C:\path\to\eff_large_wordlist.txt'
    Uses an explicit wordlist path.
#>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$WordCount = 4,

        [Parameter()]
        [string]$Separator = '-',

        # Accepted for backward compatibility with Template-based callers
        [Parameter()]
        [string]$Template,

        [Parameter()]
        [string]$WordlistPath,

        # Number of diceware chars to generate and insert as a salt word
        [Parameter()]
        [ValidateRange(0, 100)]
        [int]$SaltChars = 5,

        # Position to insert salt: 0=before first word, 1=after 1st word, etc. Randomized across all 5 positions by default.
        [Parameter()]
        [ValidateScript({ if ($_ -lt 0) { throw 'SaltPosition must be 0 or greater.' } $true })]
        [int]$SaltPosition = (Invoke-CryptoRandom -Minimum 0 -Maximum ($WordCount + 1)),

        # Capitalize the first letter of each diceware word
        [Parameter()]
        [bool]$UppercaseFirstLetter = $true,

        # Return Password as plain string instead of SecureString
        [Parameter()]
        [switch]$PlainText,

        # Export encrypted JSON + key file after generation
        [Parameter()]
        [switch]$Export,

        [Parameter()]
        [string]$EncryptedJsonPath,

        [Parameter()]
        [string]$KeyFilePath,

        # LSB steganography: embed .key into this carrier image (BMP/PNG/JPEG input, BMP output)
        [Parameter()]
        [string]$KeyCarrierImage,

        # LSB steganography: embed .jsonenc into this carrier image; send via a different channel
        [Parameter()]
        [string]$DataCarrierImage,

        [Parameter()]
        [string]$KeyStegoOutput,

        [Parameter()]
        [string]$DataStegoOutput
    )

    # Resolve wordlist path: module dir first, then parent dir
    if (-not $WordlistPath) {
        $candidates = @(
            (Join-Path $PSScriptRoot 'eff_large_wordlist.txt'),
            (Join-Path (Split-Path $PSScriptRoot -Parent) 'eff_large_wordlist.txt')
        )
        foreach ($candidate in $candidates) {
            if (Test-Path $candidate) {
                $WordlistPath = $candidate
                break
            }
        }
    }

    if (-not $WordlistPath -or -not (Test-Path $WordlistPath)) {
        throw "EFF large wordlist not found. Place eff_large_wordlist.txt alongside the module or specify -WordlistPath. Download: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt"
    }

    # Parse wordlist into hashtable: '11111' -> 'abacus'
    $wordMap = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($WordlistPath)) {
        if ($line -match '^(\d{5})\t(\S+)') {
            $wordMap[$Matches[1]] = $Matches[2]
        }
    }

    if ($wordMap.Count -eq 0) {
        throw "Wordlist parsed 0 entries. Verify the file format (expected: 5 digits, tab, word)."
    }

    # Roll 5d6 per word: Get-Random -Maximum is exclusive, so -Maximum 7 yields 1-6
    $wordRolls = [System.Collections.Generic.List[string]]::new()
    $words = @(for ($i = 0; $i -lt $WordCount; $i++) {
        $key = -join (1..5 | ForEach-Object { Invoke-CryptoRandom -Min 1 -Max 7 })
        $wordRolls.Add($key)
        $wordMap[$key]
    })

    # UppercaseFirstLetter: capitalize first char of each word before joining
    if ($UppercaseFirstLetter) {
        $words = $words | ForEach-Object {
            if ($_ -and $_.Length -gt 0) { $_.Substring(0,1).ToUpper() + $_.Substring(1) } else { $_ }
        }
    }

    # SaltChars: generate a diceware random string and insert it as a salt word at SaltPosition
    $saltResult  = $null
    $saltPosUsed = $null
    if ($SaltChars -gt 0) {
        $saltResult  = New-DicewareRandomString -Chars $SaltChars
        $saltPosUsed = [Math]::Min($SaltPosition, $words.Count)
        $wordList    = [System.Collections.Generic.List[string]]::new()
        foreach ($w in $words) { $wordList.Add($w) }
        $wordList.Insert($saltPosUsed, $saltResult.String)
        $words = $wordList.ToArray()
    }

    $passphrase = $words -join $Separator

    $global:DICEWARE = [pscustomobject]@{
        Password     = if ($PlainText) { $passphrase } else { ConvertTo-SecureString $passphrase -AsPlainText -Force }
        Rolls        = $wordRolls.ToArray()
        SaltRolls    = if ($saltResult) { $saltResult.Rolls | ForEach-Object { if ($_ -match 'd1=(\d) d2=(\d) d3=(\d)') { "$($Matches[1])$($Matches[2])$($Matches[3])" } } } else { @() }
        SaltPosition = $saltPosUsed
        Separator    = $Separator
    }
    if ($UppercaseFirstLetter) {
        $global:DICEWARE | Add-Member -NotePropertyName UppercaseFirstLetter -NotePropertyValue $true
    }
    $wordBits = [Math]::Round($WordCount * [Math]::Log(7776, 2), 1)
    $saltBits = if ($SaltChars -gt 0) { [Math]::Round($SaltChars * [Math]::Log(95, 2), 1) } else { 0.0 }
    $posBits  = if ($SaltChars -gt 0 -and -not $PSBoundParameters.ContainsKey('SaltPosition')) {
        [Math]::Round([Math]::Log([Math]::Min($WordCount, 4) + 1, 2), 1)
    } else { 0.0 }
    $global:DICEWARE | Add-Member -NotePropertyName Entropy -NotePropertyValue ([pscustomobject]@{
        WordBits     = $wordBits
        SaltBits     = $saltBits
        PositionBits = $posBits
        TotalBits    = [Math]::Round($wordBits + $saltBits + $posBits, 1)
    })
    if ($Export) {
        $ts  = Get-Date -Format 'yyyyMMdd_HHmmss'
        $dir = Join-Path (Get-Location) '.password'
        if (-not $EncryptedJsonPath) { $EncryptedJsonPath = Join-Path $dir "$ts.jsonenc" }
        if (-not $KeyFilePath)       { $KeyFilePath       = Join-Path $dir "$ts.key" }
        Save-PasswordToFile -KeyFilePath $KeyFilePath -EncryptedJsonPath $EncryptedJsonPath -InputObject $global:DICEWARE
        $global:DICEWARE | Add-Member -NotePropertyName KeyFilePath       -NotePropertyValue $KeyFilePath       -Force
        $global:DICEWARE | Add-Member -NotePropertyName EncryptedJsonPath -NotePropertyValue $EncryptedJsonPath -Force
        if ($KeyCarrierImage -or $DataCarrierImage) {
            $hp = @{ KeyFilePath = $KeyFilePath; EncryptedJsonPath = $EncryptedJsonPath }
            if ($KeyCarrierImage) {
                if (-not $KeyStegoOutput) { $KeyStegoOutput = Join-Path $dir "${ts}_key.bmp" }
                $hp['KeyCarrierImage'] = $KeyCarrierImage; $hp['KeyStegoOutput'] = $KeyStegoOutput
            }
            if ($DataCarrierImage) {
                if (-not $DataStegoOutput) { $DataStegoOutput = Join-Path $dir "${ts}_data.bmp" }
                $hp['DataCarrierImage'] = $DataCarrierImage; $hp['DataStegoOutput'] = $DataStegoOutput
            }
            Hide-PasswordFiles @hp
        }
    }
    return $global:DICEWARE
}

# Shared character lookup table used by New-DicewareRandomString and Get-DicewareChar
# Indexed [group][row][col], all 0-based. $null = invalid combination.
$script:DicewareCharTable = @(
    # Group 0 - first roll 1-2: uppercase A-Z, digits 0-9
    @(
        @('A','B','C','D','E','F'),
        @('G','H','I','J','K','L'),
        @('M','N','O','P','Q','R'),
        @('S','T','U','V','W','X'),
        @('Y','Z','0','1','2','3'),
        @('4','5','6','7','8','9')
    ),
    # Group 1 - first roll 3-4: lowercase a-z, ~, _, space
    @(
        @('a','b','c','d','e','f'),
        @('g','h','i','j','k','l'),
        @('m','n','o','p','q','r'),
        @('s','t','u','v','w','x'),
        @('y','z','~','_',' ',$null),
        @($null,$null,$null,$null,$null,$null)
    ),
    # Group 2 - first roll 5-6: special characters
    @(
        @('!','@','#','$','%','^'),
        @('&','*','(',')','-','='),
        @('+','[',']','{','}','\'),
        @('|','`',';',':','''','"'),
        @('<','>','/','?','.',','),
        @($null,$null,$null,$null,$null,$null)
    )
)

function New-DicewareRandomString {
<#
.SYNOPSIS
    Generates a random character string using a 3-dice lookup table.
.DESCRIPTION
    Each character is produced by rolling three six-sided dice:
      Roll 1 (1-2): uppercase A-Z and digits 0-9
      Roll 1 (3-4): lowercase a-z, ~, _, space
      Roll 1 (5-6): special characters  ! @ # $ % ^ & * ( ) - = + [ ] { } \ | ` ; : ' " < > / ? . ,
    Roll 2 selects the column (1-6) and Roll 3 selects the row (1-6) within
    each group. Combinations that have no mapping are silently re-rolled.
    Returns a [pscustomobject] with String and Rolls properties.
.PARAMETER Chars
    Number of characters to generate. Default is 8.
.EXAMPLE
    New-DicewareRandomString -Chars 12
    Returns an object with a 12-character string and the dice rolls that produced it.
.EXAMPLE
    (New-DicewareRandomString -Chars 16).String
    Returns just the character string.
#>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(1, 100)]
        [int]$Chars = 8
    )

    $table = $script:DicewareCharTable

    $sb    = [System.Text.StringBuilder]::new()
    $rolls = [System.Collections.Generic.List[string]]::new()

    $count = 0
    while ($count -lt $Chars) {
        $d1 = Invoke-CryptoRandom -Min 1 -Max 7
        $d2 = Invoke-CryptoRandom -Min 1 -Max 7
        $d3 = Invoke-CryptoRandom -Min 1 -Max 7

        # Map first roll to group index: 1-2->0, 3-4->1, 5-6->2
        $group = [int][Math]::Floor(($d1 - 1) / 2)
        $char  = $table[$group][$d3 - 1][$d2 - 1]

        if ($null -ne $char) {
            $null = $sb.Append($char)
            $rolls.Add("d1=$d1 d2=$d2 d3=$d3 -> '$char'")
            $count++
        }
    }

    return [pscustomobject]@{
        String = $sb.ToString()
        Rolls  = $rolls.ToArray()
    }
}

function Get-DicewareChar {
<#
.SYNOPSIS
    Returns the character for a specific set of dice rolls from the diceware character table.
.DESCRIPTION
    Performs a direct lookup using the same 3-dice table as New-DicewareRandomString.
    Returns $null and emits a warning for combinations that have no mapping.
.PARAMETER D1
    First die (1-6). Determines character group: 1-2=uppercase/digits, 3-4=lowercase, 5-6=special.
.PARAMETER D2
    Second die (1-6). Selects the column within the group.
.PARAMETER D3
    Third die (1-6). Selects the row within the group.
.EXAMPLE
    Get-DicewareChar -D1 1 -D2 1 -D3 1
    Returns 'A'
.EXAMPLE
    Get-DicewareChar -D1 5 -D2 2 -D3 2
    Returns '*'
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateRange(1,6)]
        [int]$D1,

        [Parameter(Mandatory=$true)]
        [ValidateRange(1,6)]
        [int]$D2,

        [Parameter(Mandatory=$true)]
        [ValidateRange(1,6)]
        [int]$D3
    )

    $group = [int][Math]::Floor(($D1 - 1) / 2)
    $char  = $script:DicewareCharTable[$group][$D3 - 1][$D2 - 1]

    if ($null -eq $char) {
        Write-Warning "Dice combination D1=$D1 D2=$D2 D3=$D3 has no character mapping."
        return $null
    }
    return $char
}

function Get-DicewarePassword {
<#
.SYNOPSIS
    Reconstructs a diceware passphrase from known 5-digit dice roll keys.
.DESCRIPTION
    Looks up each provided 5-digit roll key in the EFF large wordlist and returns
    the assembled passphrase. Use this to reproduce a specific password from the
    Rolls array recorded by New-Password.
.PARAMETER DiceRolls
    Array of 5-digit strings (digits 1-6 only), e.g. '23451','11234'.
    Matches the Rolls property returned by New-Password.
.PARAMETER Separator
    Character(s) between words. Default is '-'.
.PARAMETER UppercaseFirstLetter
    Capitalizes the first letter of each word.
.PARAMETER WordlistPath
    Override path to the EFF large wordlist file.
.EXAMPLE
    Get-DicewarePassword -DiceRolls '23451','55512','13624','41256'
    Returns the passphrase for those four roll keys.
.EXAMPLE
    $result = New-Password -WordCount 4 -UppercaseFirstLetter
    Get-DicewarePassword -DiceRolls $result.Rolls -UppercaseFirstLetter
    Reproduces the exact same passphrase from the saved rolls.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({
            foreach ($roll in $_) {
                if ($roll -notmatch '^[1-6]{5}$') {
                    throw "Each DiceRoll must be exactly 5 digits, each 1-6. Got: '$roll'"
                }
            }
            $true
        })]
        [string[]]$DiceRolls,

        [Parameter()]
        [string]$Separator = '-',

        [Parameter()]
        [switch]$UppercaseFirstLetter,

        [Parameter()]
        [string]$WordlistPath
    )

    if (-not $WordlistPath) {
        $candidates = @(
            (Join-Path $PSScriptRoot 'eff_large_wordlist.txt'),
            (Join-Path (Split-Path $PSScriptRoot -Parent) 'eff_large_wordlist.txt')
        )
        foreach ($candidate in $candidates) {
            if (Test-Path $candidate) { $WordlistPath = $candidate; break }
        }
    }

    if (-not $WordlistPath -or -not (Test-Path $WordlistPath)) {
        throw "EFF large wordlist not found. Place eff_large_wordlist.txt alongside the module or specify -WordlistPath."
    }

    $wordMap = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($WordlistPath)) {
        if ($line -match '^(\d{5})\t(\S+)') { $wordMap[$Matches[1]] = $Matches[2] }
    }

    $words = foreach ($roll in $DiceRolls) {
        $word = $wordMap[$roll]
        if (-not $word) { throw "Roll key '$roll' not found in wordlist." }
        if ($UppercaseFirstLetter) { $word.Substring(0,1).ToUpper() + $word.Substring(1) } else { $word }
    }

    return $words -join $Separator
}

function Get-Password {
<#
.SYNOPSIS
    Reconstructs a full password from saved roll data, or re-exports the last generated password.
.DESCRIPTION
    Takes the Rolls, SaltRolls, and SaltPosition values recorded by New-Password and rebuilds
    the exact same password. Use -LastPassword to operate on $global:DICEWARE without supplying
    roll arrays. Use -Export to encrypt the result to .key + .jsonenc files, and optionally
    embed them in BMP stego images via -KeyCarrierImage / -DataCarrierImage.
.PARAMETER Rolls
    Array of 5-digit word roll keys (digits 1-6). From New-Password's Rolls property.
.PARAMETER SaltRolls
    Array of compact 3-digit salt roll strings (d1d2d3, digits 1-6).
    From New-Password's SaltRolls property.
.PARAMETER SaltPosition
    Position of the salt word in the passphrase. From New-Password's SaltPosition property.
.PARAMETER Separator
    Character(s) between words. Default is '-'.
.PARAMETER UppercaseFirstLetter
    Capitalizes the first letter of each diceware word.
.PARAMETER WordlistPath
    Override path to the EFF large wordlist file.
.PARAMETER LastPassword
    Use $global:DICEWARE as the source. No Rolls/SaltRolls needed.
.PARAMETER Export
    Encrypt and save the result to .key + .jsonenc. Auto-names files under .password\.
    Add -KeyCarrierImage / -DataCarrierImage to also produce stego BMPs.
.PARAMETER EncryptedJsonPath
    Path to write the AES-256 encrypted JSON reconstruction file. Used with -Export.
.PARAMETER KeyFilePath
    Path to write the 256-bit AES key file. Used with -Export.
.PARAMETER KeyCarrierImage
    Carrier image (BMP, PNG, or JPEG) to conceal the .key via LSB steganography.
    Requires -Export and -DataCarrierImage. Output is always BMP.
.PARAMETER DataCarrierImage
    Carrier image to conceal the .jsonenc. Send via a separate channel.
.PARAMETER KeyStegoOutput
    Output BMP path for the hidden .key. Defaults to .password\<ts>_key.bmp.
.PARAMETER DataStegoOutput
    Output BMP path for the hidden .jsonenc. Defaults to .password\<ts>_data.bmp.
.EXAMPLE
    Get-Password -Rolls '42111','31625','54261','26343' -SaltRolls '116','214','644' -SaltPosition 0
    Reconstructs the password from those saved rolls.
.EXAMPLE
    $r = New-Password -SaltChars 3 -SaltPosition 0
    Get-Password -Rolls $r.Rolls -SaltRolls $r.SaltRolls -SaltPosition $r.SaltPosition
    Reproduces the exact password from a saved New-Password result.
.EXAMPLE
    Get-Password -LastPassword -Export
    Exports the last generated password to .password\<timestamp>.{key,jsonenc}.
.EXAMPLE
    Get-Password -LastPassword -Export -KeyCarrierImage .\office.jpg -DataCarrierImage .\team.jpg
    Exports the last password and embeds the files into two stego BMPs.
.PARAMETER Import
    Reconstruct a password from previously exported files. Provide
    -KeyCarrierImage + -DataCarrierImage to extract from stego BMPs, or
    -KeyFilePath + -EncryptedJsonPath to decrypt plain .key/.jsonenc files.
.EXAMPLE
    Get-Password -Import -KeyCarrierImage .\.password\20260618_key.bmp -DataCarrierImage .\.password\20260618_data.bmp
    Extracts and reconstructs the password from two stego BMPs.
.EXAMPLE
    Get-Password -Import -KeyFilePath .\.password\pass.key -EncryptedJsonPath .\.password\pass.jsonenc
    Decrypts and reconstructs the password from plain exported files.
#>
    [CmdletBinding(DefaultParameterSetName='ByRolls')]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='ByRolls', ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({
            foreach ($roll in $_) {
                if ($roll -notmatch '^[1-6]{5}$') { throw "Each Roll must be exactly 5 digits (1-6). Got: '$roll'" }
            }
            $true
        })]
        [string[]]$Rolls,

        [Parameter(ParameterSetName='ByRolls', ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({
            foreach ($roll in $_) {
                if ($roll -notmatch '^[1-6]{3}$') { throw "Each SaltRoll must be exactly 3 digits (1-6). Got: '$roll'" }
            }
            $true
        })]
        [string[]]$SaltRolls = @(),

        [Parameter(ParameterSetName='ByRolls', ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({ if ($_ -lt 0) { throw 'SaltPosition must be 0 or greater.' } $true })]
        [int]$SaltPosition = [int]::MaxValue,

        [Parameter(ParameterSetName='ByRolls', ValueFromPipelineByPropertyName=$true)]
        [string]$Separator = '-',

        [Parameter(ParameterSetName='ByRolls', ValueFromPipelineByPropertyName=$true)]
        [switch]$UppercaseFirstLetter,

        [Parameter(ParameterSetName='ByRolls')]
        [switch]$PlainText,

        [Parameter(ParameterSetName='ByRolls')]
        [string]$WordlistPath,

        [Parameter(Mandatory=$true, ParameterSetName='LastPassword')]
        [switch]$LastPassword,

        [Parameter(Mandatory=$true, ParameterSetName='Import')]
        [switch]$Import,

        [Parameter()]
        [switch]$Export,

        [Parameter()]
        [string]$EncryptedJsonPath,

        [Parameter()]
        [string]$KeyFilePath,

        [Parameter()]
        [string]$KeyCarrierImage,

        [Parameter()]
        [string]$DataCarrierImage,

        [Parameter()]
        [string]$KeyStegoOutput,

        [Parameter()]
        [string]$DataStegoOutput
    )

    process {
    if ($PSCmdlet.ParameterSetName -eq 'Import') {
        if ($KeyCarrierImage -or $DataCarrierImage) {
            if (-not $KeyCarrierImage) { throw "With -Import and -DataCarrierImage, also provide -KeyCarrierImage." }
            $sfParams = @{ KeyStegoImage = $KeyCarrierImage }
            if ($DataCarrierImage)      { $sfParams['DataStegoImage'] = $DataCarrierImage }
            elseif ($EncryptedJsonPath) { $sfParams['DataJsonPath']   = $EncryptedJsonPath }
            else { throw "With -Import and -KeyCarrierImage, also provide -DataCarrierImage or -EncryptedJsonPath." }
            return Show-PasswordFiles @sfParams
        } elseif ($KeyFilePath -and $EncryptedJsonPath) {
            return Get-PasswordFromFile -KeyFilePath $KeyFilePath -EncryptedJsonPath $EncryptedJsonPath
        } else {
            throw "With -Import, provide -KeyCarrierImage + -DataCarrierImage (stego) or -KeyFilePath + -EncryptedJsonPath (plain files)."
        }
    }
    if ($PSCmdlet.ParameterSetName -eq 'LastPassword') {
        if (-not $global:DICEWARE) { throw "No password has been generated yet. Run New-Password first." }
        $result = $global:DICEWARE
    } else {

    # Resolve wordlist path
    if (-not $WordlistPath) {
        $candidates = @(
            (Join-Path $PSScriptRoot 'eff_large_wordlist.txt'),
            (Join-Path (Split-Path $PSScriptRoot -Parent) 'eff_large_wordlist.txt')
        )
        foreach ($candidate in $candidates) {
            if (Test-Path $candidate) { $WordlistPath = $candidate; break }
        }
    }
    if (-not $WordlistPath -or -not (Test-Path $WordlistPath)) {
        throw "EFF large wordlist not found. Place eff_large_wordlist.txt alongside the module or specify -WordlistPath."
    }

    $wordMap = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($WordlistPath)) {
        if ($line -match '^(\d{5})\t(\S+)') { $wordMap[$Matches[1]] = $Matches[2] }
    }

    # Look up each word from its roll key
    $words = @(foreach ($roll in $Rolls) {
        $word = $wordMap[$roll]
        if (-not $word) { throw "Roll key '$roll' not found in wordlist." }
        if ($UppercaseFirstLetter) { $word.Substring(0,1).ToUpper() + $word.Substring(1) } else { $word }
    })

    # Rebuild salt string from compact d1d2d3 roll strings
    $saltString  = $null
    $saltPosUsed = $null
    if ($SaltRolls.Count -gt 0) {
        $saltChars = @(foreach ($compact in $SaltRolls) {
            $c = Get-DicewareChar -D1 ([int]::Parse($compact[0])) `
                                  -D2 ([int]::Parse($compact[1])) `
                                  -D3 ([int]::Parse($compact[2]))
            if ($null -ne $c) { $c }
        })
        $saltString  = -join $saltChars
        $saltPosUsed = [Math]::Min($SaltPosition, $words.Count)
        $wordList    = [System.Collections.Generic.List[string]]::new()
        foreach ($w in $words) { $wordList.Add($w) }
        $wordList.Insert($saltPosUsed, $saltString)
        $words = $wordList.ToArray()
    }

    $wordBits = [Math]::Round($Rolls.Count * [Math]::Log(7776, 2), 1)
    $saltBits = if ($SaltRolls.Count -gt 0) { [Math]::Round($SaltRolls.Count * [Math]::Log(95, 2), 1) } else { 0.0 }
    $passphrase = $words -join $Separator
    $result = [pscustomobject]@{
        Password     = if ($PlainText) { $passphrase } else { ConvertTo-SecureString $passphrase -AsPlainText -Force }
        Rolls        = $Rolls
        SaltRolls    = $SaltRolls
        SaltPosition = $saltPosUsed
        Separator    = $Separator
        Entropy      = [pscustomobject]@{
            WordBits     = $wordBits
            SaltBits     = $saltBits
            PositionBits = 0.0
            TotalBits    = [Math]::Round($wordBits + $saltBits, 1)
        }
    }
    if ($UppercaseFirstLetter) {
        $result | Add-Member -NotePropertyName UppercaseFirstLetter -NotePropertyValue $true
    }
    } # end else (ByRolls)

    if ($Export) {
        $ts  = Get-Date -Format 'yyyyMMdd_HHmmss'
        $dir = Join-Path (Get-Location) '.password'
        if (-not $EncryptedJsonPath) { $EncryptedJsonPath = Join-Path $dir "$ts.jsonenc" }
        if (-not $KeyFilePath)       { $KeyFilePath       = Join-Path $dir "$ts.key" }
        Save-PasswordToFile -KeyFilePath $KeyFilePath -EncryptedJsonPath $EncryptedJsonPath -InputObject $result
        $result | Add-Member -NotePropertyName KeyFilePath       -NotePropertyValue $KeyFilePath       -Force
        $result | Add-Member -NotePropertyName EncryptedJsonPath -NotePropertyValue $EncryptedJsonPath -Force
        if ($KeyCarrierImage -or $DataCarrierImage) {
            $hp = @{ KeyFilePath = $KeyFilePath; EncryptedJsonPath = $EncryptedJsonPath }
            if ($KeyCarrierImage) {
                if (-not $KeyStegoOutput) { $KeyStegoOutput = Join-Path $dir "${ts}_key.bmp" }
                $hp['KeyCarrierImage'] = $KeyCarrierImage; $hp['KeyStegoOutput'] = $KeyStegoOutput
            }
            if ($DataCarrierImage) {
                if (-not $DataStegoOutput) { $DataStegoOutput = Join-Path $dir "${ts}_data.bmp" }
                $hp['DataCarrierImage'] = $DataCarrierImage; $hp['DataStegoOutput'] = $DataStegoOutput
            }
            Hide-PasswordFiles @hp
        }
    }

    return $result
    } # end process
}

function Save-PasswordToFile {
<#
.SYNOPSIS
    Encrypts the last New-Password result to an AES-256 protected JSON file.
.DESCRIPTION
    Saves reconstruction data (Rolls, SaltRolls, SaltPosition, Separator, UppercaseFirstLetter)
    as an AES-256 encrypted JSON file alongside a 256-bit key file. The Password (SecureString)
    is never written to disk - the recipient reconstructs it with Get-PasswordFromFile.
    Restrict access to the key file via NTFS permissions to control who can decrypt.
.PARAMETER KeyFilePath
    Path to write the 256-bit AES key file. Protect this with NTFS permissions.
.PARAMETER EncryptedJsonPath
    Path to write the encrypted JSON reconstruction file.
.PARAMETER OverwriteKeyFile
    Re-generate the key even if the key file already exists.
.PARAMETER InputObject
    The password object to export. Defaults to `$global:DICEWARE` if omitted.
.EXAMPLE
    New-Password | Out-Null
    Save-PasswordToFile -KeyFilePath C:\Secure\pass.key -EncryptedJsonPath C:\Share\pass.enc
.EXAMPLE
    New-Password -Export -KeyFilePath C:\Secure\pass.key -EncryptedJsonPath C:\Share\pass.enc
    Generates a password and exports in one step.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyFilePath,

        [Parameter(Mandatory=$true)]
        [string]$EncryptedJsonPath,

        [Parameter()]
        [switch]$OverwriteKeyFile,

        [Parameter()]
        [pscustomobject]$InputObject
    )

    $data = if ($PSBoundParameters.ContainsKey('InputObject')) { $InputObject } else { $global:DICEWARE }
    if (-not $data) { throw "No password data found. Run New-Password first or supply -InputObject." }

    # Ensure output directories exist
    foreach ($p in @($EncryptedJsonPath, $KeyFilePath)) {
        $d = Split-Path $p -Parent
        if ($d -and -not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }

    # Build export object - reconstruction fields only (Password is SecureString, not serialisable)
    $export = [pscustomobject]@{
        Rolls        = $data.Rolls
        SaltRolls    = $data.SaltRolls
        SaltPosition = $data.SaltPosition
        Separator    = $data.Separator
    }
    if ($data.PSObject.Properties['UppercaseFirstLetter']) {
        $export | Add-Member -NotePropertyName UppercaseFirstLetter -NotePropertyValue $true
    }

    # Generate or reuse 256-bit AES key using crypto-secure random
    if (-not (Test-Path $KeyFilePath) -or $OverwriteKeyFile) {
        $key = [byte[]](1..32 | ForEach-Object { Invoke-CryptoRandom -Minimum 0 -Maximum 256 })
        $key | Out-File $KeyFilePath
        Write-Host "Key generated: $KeyFilePath" -ForegroundColor Green
    } else {
        $key = Get-Content $KeyFilePath
        Write-Host "Key reused:    $KeyFilePath" -ForegroundColor Cyan
    }

    # Encrypt JSON and save
    ($export | ConvertTo-Json -Compress) |
        ConvertTo-SecureString -AsPlainText -Force |
        ConvertFrom-SecureString -Key $key |
        Out-File $EncryptedJsonPath

    Write-Host "Encrypted JSON: $EncryptedJsonPath" -ForegroundColor Green
}

function Get-PasswordFromFile {
<#
.SYNOPSIS
    Decrypts an encrypted password JSON file and reconstructs the full password object.
.DESCRIPTION
    Reads the key file and encrypted JSON produced by Save-PasswordToFile, decrypts the
    reconstruction data, and calls Get-Password to rebuild the passphrase. Returns the
    same pscustomobject shape as New-Password.
.PARAMETER KeyFilePath
    Path to the AES key file produced by Save-PasswordToFile.
.PARAMETER EncryptedJsonPath
    Path to the encrypted JSON file produced by Save-PasswordToFile.
.EXAMPLE
    $r = Get-PasswordFromFile -KeyFilePath C:\Secure\pass.key -EncryptedJsonPath C:\Share\pass.enc
    $r.Password   # SecureString
.EXAMPLE
    Get-PasswordFromFile -KeyFilePath .\pass.key -EncryptedJsonPath .\pass.enc | Select-Object Password
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyFilePath,

        [Parameter(Mandatory=$true)]
        [string]$EncryptedJsonPath
    )

    if (-not (Test-Path $KeyFilePath))       { throw "Key file not found: $KeyFilePath" }
    if (-not (Test-Path $EncryptedJsonPath)) { throw "Encrypted JSON file not found: $EncryptedJsonPath" }

    $key  = Get-Content $KeyFilePath
    $ss   = Get-Content $EncryptedJsonPath | ConvertTo-SecureString -Key $key
    $cred = [System.Management.Automation.PSCredential]::new('x', $ss)
    $data = $cred.GetNetworkCredential().Password | ConvertFrom-Json

    $params = @{
        Rolls        = $data.Rolls
        SaltRolls    = if ($data.SaltRolls)              { $data.SaltRolls }    else { @() }
        SaltPosition = if ($null -ne $data.SaltPosition) { $data.SaltPosition } else { [int]::MaxValue }
        Separator    = if ($data.Separator)              { $data.Separator }    else { '-' }
    }
    if ($data.UppercaseFirstLetter) { $params['UppercaseFirstLetter'] = $true }

    return Get-Password @params
}

# -- Private: encode $Payload bytes as LSBs (R,G,B channels) in a carrier image --------------
# Frame: 4-byte magic 'NPWD' | 4-byte payload length (uint32 LE) | payload bytes
# JPEG/PNG/BMP carrier accepted; output always saved as lossless BMP.
function script:ConvertTo-StegoImage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$CarrierImagePath,
        [Parameter(Mandatory=$true)][byte[]]$Payload,
        [Parameter(Mandatory=$true)][string]$OutputBmpPath
    )
    Add-Type -AssemblyName System.Drawing

    $magic    = [byte[]](0x4E, 0x50, 0x57, 0x44)          # ASCII "NPWD"
    $lenBytes = [BitConverter]::GetBytes([uint32]$Payload.Length)
    $frame    = $magic + $lenBytes + $Payload

    # Flatten to MSB-first bit stream
    $bits = [System.Collections.Generic.List[byte]]::new($frame.Length * 8)
    foreach ($byte in $frame) {
        for ($shift = 7; $shift -ge 0; $shift--) {
            $bits.Add(($byte -shr $shift) -band 1)
        }
    }

    $bmp = [System.Drawing.Bitmap]::new($CarrierImagePath)
    $cap = [int]($bmp.Width * $bmp.Height * 3 / 8)
    if ($frame.Length -gt $cap) {
        $bmp.Dispose()
        throw "Carrier image too small ($($bmp.Width)x$($bmp.Height)px = $cap B capacity). Payload needs $($frame.Length) B. Use a larger image."
    }

    $i = 0
    :outer for ($y = 0; $y -lt $bmp.Height; $y++) {
        for ($x = 0; $x -lt $bmp.Width; $x++) {
            $px = $bmp.GetPixel($x, $y)
            $r  = ($px.R -band 0xFE) -bor $bits[$i]; $i++
            $g  = ($px.G -band 0xFE) -bor $bits[$i]; $i++
            $b  = ($px.B -band 0xFE) -bor $bits[$i]; $i++
            $bmp.SetPixel($x, $y, [System.Drawing.Color]::FromArgb($px.A, $r, $g, $b))
            if ($i -ge $bits.Count) { break outer }
        }
    }

    $outDir = Split-Path $OutputBmpPath -Parent
    if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $bmp.Save($OutputBmpPath, [System.Drawing.Imaging.ImageFormat]::Bmp)
    $bmp.Dispose()
}

# -- Private: extract payload bytes from a stego BMP produced by ConvertTo-StegoImage --------
function script:ConvertFrom-StegoImage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$StegoImagePath
    )
    Add-Type -AssemblyName System.Drawing

    $bmp  = [System.Drawing.Bitmap]::new($StegoImagePath)
    $bits = [System.Collections.Generic.List[byte]]::new()

    $payloadLen      = $null
    $totalBitsNeeded = 64   # 8-byte header; parse it first to get actual payload length

    :outer for ($y = 0; $y -lt $bmp.Height; $y++) {
        for ($x = 0; $x -lt $bmp.Width; $x++) {
            $px = $bmp.GetPixel($x, $y)
            $bits.Add([byte]($px.R -band 1))
            $bits.Add([byte]($px.G -band 1))
            $bits.Add([byte]($px.B -band 1))

            if ($null -eq $payloadLen -and $bits.Count -ge 64) {
                $hdr = [byte[]]::new(8)
                for ($bi = 0; $bi -lt 8; $bi++) {
                    $val = 0
                    for ($sh = 7; $sh -ge 0; $sh--) {
                        $val = $val -bor ($bits[$bi * 8 + (7 - $sh)] -shl $sh)
                    }
                    $hdr[$bi] = [byte]$val
                }
                $magic = [Text.Encoding]::ASCII.GetString($hdr, 0, 4)
                if ($magic -ne 'NPWD') {
                    $bmp.Dispose()
                    throw "Magic 'NPWD' not found. Image was not produced by Hide-PasswordFiles."
                }
                $payloadLen      = [int][BitConverter]::ToUInt32($hdr, 4)
                $totalBitsNeeded = (8 + $payloadLen) * 8
            }
            if ($null -ne $payloadLen -and $bits.Count -ge $totalBitsNeeded) { break outer }
        }
    }

    $bmp.Dispose()
    if ($null -eq $payloadLen) { throw "Image too small to contain a valid NPWD payload header." }

    $payload = [byte[]]::new($payloadLen)
    for ($bi = 0; $bi -lt $payloadLen; $bi++) {
        $val = 0
        for ($sh = 7; $sh -ge 0; $sh--) {
            $val = $val -bor ($bits[(8 + $bi) * 8 + (7 - $sh)] -shl $sh)
        }
        $payload[$bi] = [byte]$val
    }
    return $payload
}

function Hide-PasswordFiles {
<#
.SYNOPSIS
    Hides .key and .jsonenc files inside two separate carrier images using LSB steganography.
.DESCRIPTION
    Encodes each file's bytes into the least-significant bit of the R, G, B channels of a
    carrier image. The 1-value-per-channel change is visually imperceptible. JPEG, PNG, and
    BMP inputs are accepted; output is always saved as lossless BMP.
    Supply only -KeyCarrierImage to keep the .jsonenc as a plain (still AES-256 encrypted)
    file - safe to share openly since it is useless without the key. Supply only
    -DataCarrierImage to hide the data while leaving the key as a plain file. Supply both
    to hide everything. At least one carrier must be provided.
.PARAMETER KeyCarrierImage
    Optional. Carrier image (BMP, PNG, or JPEG) to conceal the .key file.
    Minimum size: width * height * 3 / 8 >= key file size + 8 bytes.
.PARAMETER DataCarrierImage
    Optional. Carrier image to conceal the .jsonenc file. Omit to keep the .jsonenc as a
    plain encrypted file. Use a different image from -KeyCarrierImage when provided.
.PARAMETER KeyFilePath
    Path to the .key file to embed.
.PARAMETER EncryptedJsonPath
    Path to the .jsonenc file to embed.
.PARAMETER KeyStegoOutput
    Output BMP path for the hidden .key. Defaults to .password\<timestamp>_key.bmp.
.PARAMETER DataStegoOutput
    Output BMP path for the hidden .jsonenc. Defaults to .password\<timestamp>_data.bmp.
.EXAMPLE
    New-Password -Export
    Hide-PasswordFiles -KeyCarrierImage .\office.jpg -DataCarrierImage .\team.jpg `
                       -KeyFilePath .\.password\20260613_123456.key `
                       -EncryptedJsonPath .\.password\20260613_123456.jsonenc
.EXAMPLE
    New-Password -Export -KeyCarrierImage .\office.jpg -DataCarrierImage .\team.jpg
#>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$KeyCarrierImage,

        [Parameter()]
        [string]$DataCarrierImage,

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]$KeyFilePath,

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]$EncryptedJsonPath,

        [Parameter()]
        [string]$KeyStegoOutput,

        [Parameter()]
        [string]$DataStegoOutput
    )

    process {
        if (-not $KeyCarrierImage -and -not $DataCarrierImage) {
            throw "Specify at least one of -KeyCarrierImage or -DataCarrierImage."
        }
        if ($KeyCarrierImage  -and -not $KeyFilePath)       { throw "-KeyFilePath is required when -KeyCarrierImage is specified." }
        if ($DataCarrierImage -and -not $EncryptedJsonPath) { throw "-EncryptedJsonPath is required when -DataCarrierImage is specified." }
        if ($KeyCarrierImage   -and -not (Test-Path $KeyCarrierImage))   { throw "Key carrier image not found: $KeyCarrierImage" }
        if ($DataCarrierImage  -and -not (Test-Path $DataCarrierImage))  { throw "Data carrier image not found: $DataCarrierImage" }
        if ($KeyFilePath       -and -not (Test-Path $KeyFilePath))       { throw "Key file not found: $KeyFilePath" }
        if ($EncryptedJsonPath -and -not (Test-Path $EncryptedJsonPath)) { throw "Encrypted JSON not found: $EncryptedJsonPath" }

        $ts  = Get-Date -Format 'yyyyMMdd_HHmmss'
        $dir = Join-Path (Get-Location) '.password'
        $out = [pscustomobject]@{}

        if ($KeyCarrierImage) {
            if (-not $KeyStegoOutput) { $KeyStegoOutput = Join-Path $dir "${ts}_key.bmp" }
            ConvertTo-StegoImage -CarrierImagePath $KeyCarrierImage `
                                 -Payload ([System.IO.File]::ReadAllBytes($KeyFilePath)) `
                                 -OutputBmpPath $KeyStegoOutput
            Write-Host "Key  stego -> $KeyStegoOutput" -ForegroundColor Green
            $out | Add-Member -NotePropertyName KeyStegoImage -NotePropertyValue $KeyStegoOutput
        }

        if ($DataCarrierImage) {
            if (-not $DataStegoOutput) { $DataStegoOutput = Join-Path $dir "${ts}_data.bmp" }
            ConvertTo-StegoImage -CarrierImagePath $DataCarrierImage `
                                 -Payload ([System.IO.File]::ReadAllBytes($EncryptedJsonPath)) `
                                 -OutputBmpPath $DataStegoOutput
            Write-Host "Data stego -> $DataStegoOutput" -ForegroundColor Green
            $out | Add-Member -NotePropertyName DataStegoImage -NotePropertyValue $DataStegoOutput
        }

        return $out
    }
}

function Show-PasswordFiles {
<#
.SYNOPSIS
    Extracts .key and .jsonenc payloads from stego images and reconstructs the password.
.DESCRIPTION
    Reads the LSB-encoded payload from two stego BMPs produced by Hide-PasswordFiles,
    writes the recovered files to .password\<timestamp>_extracted.{key,jsonenc} by default,
    then calls Get-PasswordFromFile to return the full password object.
.PARAMETER KeyStegoImage
    Path to the BMP containing the hidden .key file.
.PARAMETER DataStegoImage
    Path to the BMP containing the hidden .jsonenc file. Provide either this or -DataJsonPath.
.PARAMETER DataJsonPath
    Path to a plain .jsonenc file (hybrid mode: key was stego-hidden, data was not).
    Provide either this or -DataStegoImage.
.PARAMETER KeyFilePath
    Override output path for the extracted .key file.
.PARAMETER EncryptedJsonPath
    Override output path for the extracted .jsonenc file. Ignored when -DataJsonPath is used.
.EXAMPLE
    $r = Show-PasswordFiles -KeyStegoImage .\office.bmp -DataStegoImage .\team.bmp
    (New-Object System.Management.Automation.PSCredential 'x',$r.Password).GetNetworkCredential().Password
.EXAMPLE
    Show-PasswordFiles -KeyStegoImage .\office.bmp -DataStegoImage .\team.bmp `
                       -KeyFilePath C:\Secure\recovered.key `
                       -EncryptedJsonPath C:\Secure\recovered.jsonenc
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyStegoImage,

        # Provide exactly one of -DataStegoImage or -DataJsonPath
        [Parameter()]
        [string]$DataStegoImage,

        [Parameter()]
        [string]$DataJsonPath,

        [Parameter()]
        [string]$KeyFilePath,

        [Parameter()]
        [string]$EncryptedJsonPath
    )

    if (-not $DataStegoImage -and -not $DataJsonPath) {
        throw "Provide either -DataStegoImage (stego BMP) or -DataJsonPath (plain .jsonenc path)."
    }
    if ($DataStegoImage -and $DataJsonPath) {
        throw "Specify only one of -DataStegoImage or -DataJsonPath, not both."
    }
    if (-not (Test-Path $KeyStegoImage))                         { throw "Key stego image not found: $KeyStegoImage" }
    if ($DataStegoImage -and -not (Test-Path $DataStegoImage))   { throw "Data stego image not found: $DataStegoImage" }
    if ($DataJsonPath   -and -not (Test-Path $DataJsonPath))     { throw "Data JSON file not found: $DataJsonPath" }

    $ts  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $dir = Join-Path (Get-Location) '.password'

    # Extract and save the key from stego
    if (-not $KeyFilePath) { $KeyFilePath = Join-Path $dir "${ts}_extracted.key" }
    $keyBytes = ConvertFrom-StegoImage -StegoImagePath $KeyStegoImage
    $kd = Split-Path $KeyFilePath -Parent
    if ($kd -and -not (Test-Path $kd)) { New-Item -ItemType Directory -Path $kd -Force | Out-Null }
    [System.IO.File]::WriteAllBytes($KeyFilePath, $keyBytes)
    Write-Host "Extracted key:  $KeyFilePath" -ForegroundColor Green

    # Resolve the data source: stego BMP or plain .jsonenc
    if ($DataStegoImage) {
        if (-not $EncryptedJsonPath) { $EncryptedJsonPath = Join-Path $dir "${ts}_extracted.jsonenc" }
        $jsonBytes = ConvertFrom-StegoImage -StegoImagePath $DataStegoImage
        $jd = Split-Path $EncryptedJsonPath -Parent
        if ($jd -and -not (Test-Path $jd)) { New-Item -ItemType Directory -Path $jd -Force | Out-Null }
        [System.IO.File]::WriteAllBytes($EncryptedJsonPath, $jsonBytes)
        Write-Host "Extracted data: $EncryptedJsonPath" -ForegroundColor Green
    } else {
        $EncryptedJsonPath = $DataJsonPath
        Write-Host "Using data file: $EncryptedJsonPath" -ForegroundColor Cyan
    }

    return Get-PasswordFromFile -KeyFilePath $KeyFilePath -EncryptedJsonPath $EncryptedJsonPath
}

function Get-LastPassword {
<#
.SYNOPSIS
    Returns the last generated password object ($global:DICEWARE).
.DESCRIPTION
    Convenience wrapper that retrieves the most recent New-Password result.
    Use -CopyToClipboard to copy the plain text password to the clipboard.
.PARAMETER CopyToClipboard
    Copies the plain text password to the clipboard via Set-Clipboard.
.EXAMPLE
    Get-LastPassword
    Returns the last password object.
.EXAMPLE
    Get-LastPassword -CopyToClipboard
    Returns the last password object and copies the plain text to the clipboard.
#>
    [CmdletBinding()]
    param(
        [switch]$CopyToClipboard
    )

    if (-not $global:DICEWARE) {
        throw "No password has been generated yet. Run New-Password first."
    }

    if ($CopyToClipboard) {
        $global:DICEWARE.Password | ConvertFrom-SecureString -AsPlainText | Set-Clipboard
        Write-Host "Password copied to clipboard." -ForegroundColor Green
    }

    return $global:DICEWARE
}

function Out-PasswordSettings {
<#
.SYNOPSIS
    Formats password reconstruction data as a printable, pipeable string.
.DESCRIPTION
    Returns a formatted text block containing all roll data needed to reconstruct
    a password with Get-Password, an optional plaintext reveal, entropy summary,
    and a ready-to-run Get-Password command.
    Pipe to Out-File and print for physical handover.

    Suggested usage:
      - Omit -ShowPassword when filing the admin copy (rolls only).
      - Add -ShowPassword for the copy handed to the user or set-password operator.
      - Add -Title to label the sheet with the account name.
.PARAMETER InputObject
    Password object from New-Password or Get-Password. Defaults to $global:DICEWARE.
    Accepts pipeline input.
.PARAMETER ShowPassword
    Include the plaintext password in the output. Compatible with PS5.1 and PS7+.
    Treat the printed sheet as sensitive material; destroy after the password is set.
.PARAMETER Title
    Optional heading for the sheet. Example: "Tier 0 - Password Recovery".
.PARAMETER Username
    Account name or UPN to print on the sheet. Displayed prominently in the header
    so the envelope can be labelled without opening it.
    Example: "jsmith@contoso.com"
.EXAMPLE
    New-Password | Out-Null
    Out-PasswordSettings -ShowPassword -Title "Tier 0" -Username "jsmith@contoso.com" | Out-File .\jsmith-sheet.txt
.EXAMPLE
    # Admin copy (rolls only) + user copy (with password)
    Out-PasswordSettings -Title "Tier 0 - Admin record" -Username "jsmith" | Out-File .\admin-record.txt
    Out-PasswordSettings -ShowPassword -Title "Tier 0" -Username "jsmith" | Out-File .\user-sheet.txt
.EXAMPLE
    # Pipeline from New-Password
    New-Password | Out-PasswordSettings -ShowPassword -Title "Tier 0" -Username "jsmith@contoso.com" | Out-File .\sheet.txt
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        [pscustomobject]$InputObject,

        [Parameter()]
        [switch]$ShowPassword,

        [Parameter()]
        [string]$Title = 'PASSWORD RECONSTRUCTION SHEET',

        [Parameter()]
        [string]$Username
    )

    process {
        $data = if ($PSBoundParameters.ContainsKey('InputObject') -and $null -ne $InputObject) {
            $InputObject
        } else {
            $global:DICEWARE
        }
        if (-not $data) { throw "No password data found. Run New-Password first or supply -InputObject." }

        $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $wide = '=' * 72
        $thin = '-' * 72
        $nl   = [System.Environment]::NewLine

        # Describe salt position in plain English
        $saltPosStr = if ($null -eq $data.SaltPosition) {
            'N/A'
        } elseif ($data.SaltPosition -eq 0) {
            "0  (prepended before all words)"
        } elseif ($data.Rolls -and $data.SaltPosition -eq $data.Rolls.Count) {
            "$($data.SaltPosition)  (appended after all words)"
        } else {
            "$($data.SaltPosition)  (after word $($data.SaltPosition))"
        }

        $entropyStr = if ($data.PSObject.Properties['Entropy'] -and $data.Entropy) {
            "$($data.Entropy.TotalBits) bits  (words: $($data.Entropy.WordBits)  salt: $($data.Entropy.SaltBits)  position: $($data.Entropy.PositionBits))"
        } else { 'N/A' }

        # Human-readable separator label - space and empty are not visually distinct in plain text
        $sepDisplay = if ($null -eq $data.Separator -or $data.Separator -eq '') {
            "(empty string)"
        } elseif ($data.Separator -eq ' ') {
            "' '  (single space)"
        } else {
            "'$($data.Separator)'"
        }
        # PS-safe separator argument - space must be explicit for copy-paste correctness
        $sepArg = if ($null -eq $data.Separator -or $data.Separator -eq '') {
            "-Separator ''"
        } elseif ($data.Separator -eq ' ') {
            "-Separator ' '  # single space"
        } else {
            "-Separator '$($data.Separator)'"
        }

        # Build continuation-style Get-Password command
        $cmdLines = [System.Collections.Generic.List[string]]::new()
        $cmdLines.Add("Get-Password -Rolls $($data.Rolls -join ', ')")
        if ($data.SaltRolls -and $data.SaltRolls.Count -gt 0) {
            $cmdLines.Add("             -SaltRolls $($data.SaltRolls -join ', ')")
        }
        if ($null -ne $data.SaltPosition) {
            $cmdLines.Add("             -SaltPosition $($data.SaltPosition)")
        }
        $cmdLines.Add("             $sepArg")
        if ($data.PSObject.Properties['UppercaseFirstLetter'] -and $data.UppercaseFirstLetter) {
            $cmdLines.Add('             -UppercaseFirstLetter')
        }
        $cmdStr = ($cmdLines -join " ``$nl") -split $nl |
                    ForEach-Object { "  $_" } |
                    Out-String

        # Build output
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine($wide)
        [void]$sb.AppendLine("  $Title")
        if ($Username) { [void]$sb.AppendLine("  Account  : $Username") }
        [void]$sb.AppendLine("  Generated: $ts")
        [void]$sb.AppendLine($wide)
        [void]$sb.AppendLine()

        if ($ShowPassword) {
            $plain = if ($PSVersionTable.PSVersion.Major -ge 7) {
                $data.Password | ConvertFrom-SecureString -AsPlainText
            } else {
                $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($data.Password)
                try   { [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr) }
                finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
            }
            [void]$sb.AppendLine("  PASSWORD  (sensitive - destroy sheet after password has been set):")
            [void]$sb.AppendLine()
            [void]$sb.AppendLine("      $plain")
            [void]$sb.AppendLine()
            [void]$sb.AppendLine($thin)
            [void]$sb.AppendLine()
        }

        [void]$sb.AppendLine('  ROLL DATA:')
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("  Word rolls    : $($data.Rolls -join '  ')")
        [void]$sb.AppendLine("  Salt rolls    : $(if ($data.SaltRolls -and $data.SaltRolls.Count -gt 0) { $data.SaltRolls -join '  ' } else { '(none)' })")
        [void]$sb.AppendLine("  Salt position : $saltPosStr")
        [void]$sb.AppendLine("  Separator     : $sepDisplay")
        [void]$sb.AppendLine("  Uppercase     : $(if ($data.PSObject.Properties['UppercaseFirstLetter'] -and $data.UppercaseFirstLetter) { 'Yes' } else { 'No' })")
        [void]$sb.AppendLine("  Entropy       : $entropyStr")
        [void]$sb.AppendLine()
        [void]$sb.AppendLine($thin)
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('  RECONSTRUCTION COMMAND (requires NewPassword module + eff_large_wordlist.txt):')
        [void]$sb.AppendLine()
        [void]$sb.Append($cmdStr)
        [void]$sb.AppendLine($wide)

        return $sb.ToString()
    }
}

function ConvertTo-SaltRolls {
<#
.SYNOPSIS
    Converts a plain text string into an array of compact 3-digit salt roll strings.
.DESCRIPTION
    Each character is mapped to a deterministic (d1,d2,d3) triple using the same
    DicewareCharTable as New-DicewareRandomString. Covers all 95 printable ASCII
    characters including space. TOTP Base32 secrets (A-Z, 2-7, =) are fully supported.
    Use ConvertFrom-SaltRolls to reverse. Use Export-EncodedSecret to embed the rolls
    directly into a carrier image via LSB steganography.
.PARAMETER Text
    The string to encode. Accepts pipeline input.
.EXAMPLE
    ConvertTo-SaltRolls 'JBSWY3DPEHPK3PXP'
    Returns an array of 3-digit roll strings that encode each character.
.EXAMPLE
    ConvertTo-SaltRolls 'Hello!' | ConvertFrom-SaltRolls
    Round-trips the string through the encoding.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Text
    )

    process {
        # Build reverse lookup: char -> canonical 'd1d2d3'
        # Canonical d1 is the first value in each group pair: 1 (group 0), 3 (group 1), 5 (group 2)
        $table  = $script:DicewareCharTable
        $lookup = @{}
        for ($g = 0; $g -lt 3; $g++) {
            $d1 = $g * 2 + 1
            for ($row = 0; $row -lt 6; $row++) {
                $d3 = $row + 1
                for ($col = 0; $col -lt 6; $col++) {
                    $d2   = $col + 1
                    $char = $table[$g][$row][$col]
                    if ($null -ne $char -and -not $lookup.ContainsKey($char)) {
                        $lookup[$char] = "$d1$d2$d3"
                    }
                }
            }
        }

        $rolls = foreach ($c in $Text.ToCharArray()) {
            $key = [string]$c
            if (-not $lookup.ContainsKey($key)) {
                throw "Character '$c' (U+$('{0:X4}' -f [int][char]$c)) has no diceware salt mapping. Only printable ASCII is supported."
            }
            $lookup[$key]
        }
        return $rolls
    }
}

function ConvertFrom-SaltRolls {
<#
.SYNOPSIS
    Decodes an array of compact 3-digit roll strings back into a plain text string.
.DESCRIPTION
    The inverse of ConvertTo-SaltRolls. Each 3-digit roll string (d1d2d3) is looked
    up in the DicewareCharTable to recover the original character.
    Accepts pipeline input so you can pipe rolls directly from ConvertTo-SaltRolls.
.PARAMETER Rolls
    Array of 3-digit roll strings (digits 1-6).
.EXAMPLE
    ConvertFrom-SaltRolls '116','323','511'
    Returns the characters for those rolls joined into a string.
.EXAMPLE
    ConvertTo-SaltRolls 'JBSWY3DPEHPK3PXP' | ConvertFrom-SaltRolls
    Round-trips through encoding and decoding.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string[]]$Rolls
    )

    begin   { $allRolls = [System.Collections.Generic.List[string]]::new() }
    process { foreach ($r in $Rolls) { $allRolls.Add($r) } }
    end {
        $chars = foreach ($roll in $allRolls) {
            if ($roll -notmatch '^[1-6]{3}$') { throw "Invalid roll '$roll': must be exactly 3 digits (1-6)." }
            $c = Get-DicewareChar -D1 ([int]::Parse($roll[0])) `
                                  -D2 ([int]::Parse($roll[1])) `
                                  -D3 ([int]::Parse($roll[2]))
            if ($null -eq $c) { throw "Roll '$roll' maps to a null entry in the DicewareCharTable." }
            $c
        }
        return -join $chars
    }
}

function Export-EncodedSecret {
<#
.SYNOPSIS
    Encodes a secret string as diceware salt rolls and hides them inside a carrier image.
.DESCRIPTION
    Converts each character of the secret to a deterministic 3-digit roll triple using
    ConvertTo-SaltRolls, serialises the rolls as compact JSON, then embeds the JSON
    bytes into the carrier image via LSB steganography (one bit per R/G/B channel).
    The output BMP looks identical to the carrier to the naked eye.
    Recover with Read-EncodedSecret.
    All 95 printable ASCII characters are supported. TOTP Base32 secrets (A-Z, 2-7, =)
    and hex strings are fully supported.
.PARAMETER Secret
    The plaintext string to encode. Accepts pipeline input.
.PARAMETER CarrierImage
    Path to a BMP, PNG, or JPEG carrier image. The image must be large enough to hold
    the payload: width * height * 3 / 8 >= payload bytes + 8.
.PARAMETER OutputPath
    Path for the output BMP. Defaults to <carrier-basename>_secret.bmp in the same folder.
.PARAMETER Label
    Optional description embedded alongside the rolls (e.g. "TOTP:jsmith@contoso.com").
    Not encrypted - treat the stego image as sensitive.
.EXAMPLE
    Export-EncodedSecret -Secret 'JBSWY3DPEHPK3PXP' -CarrierImage .\photo.jpg -Label 'TOTP:jsmith@contoso.com'
    Hides the TOTP secret inside photo.jpg, writing photo_secret.bmp.
.EXAMPLE
    'JBSWY3DPEHPK3PXP' | Export-EncodedSecret -CarrierImage .\photo.jpg
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Secret,

        [Parameter(Mandatory=$true)]
        [string]$CarrierImage,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [string]$Label
    )

    process {
        if (-not (Test-Path $CarrierImage)) { throw "Carrier image not found: $CarrierImage" }

        $rolls   = ConvertTo-SaltRolls -Text $Secret
        $payload = [ordered]@{ type = 'salt-rolls'; rolls = $rolls }
        if ($Label) { $payload['label'] = $Label }
        $json    = $payload | ConvertTo-Json -Compress
        $bytes   = [System.Text.Encoding]::UTF8.GetBytes($json)

        if (-not $OutputPath) {
            $base       = [System.IO.Path]::GetFileNameWithoutExtension($CarrierImage)
            $dir        = [System.IO.Path]::GetDirectoryName((Resolve-Path $CarrierImage))
            $OutputPath = Join-Path $dir "${base}_secret.bmp"
        }

        ConvertTo-StegoImage -CarrierImagePath $CarrierImage -Payload $bytes -OutputBmpPath $OutputPath
        Write-Host "Secret encoded -> $OutputPath  ($($rolls.Count) rolls)" -ForegroundColor Green

        return [pscustomobject]@{
            OutputPath = $OutputPath
            Rolls      = $rolls
            Label      = $Label
        }
    }
}

function Read-EncodedSecret {
<#
.SYNOPSIS
    Extracts and decodes a secret previously hidden by Export-EncodedSecret.
.DESCRIPTION
    Reads the LSB-encoded payload from the stego BMP, parses the JSON roll array,
    and calls ConvertFrom-SaltRolls to recover the original string.
.PARAMETER StegoImage
    Path to the BMP produced by Export-EncodedSecret.
.EXAMPLE
    Read-EncodedSecret -StegoImage .\photo_secret.bmp
    Returns an object with Secret, Rolls, and Label properties.
.EXAMPLE
    (Read-EncodedSecret .\photo_secret.bmp).Secret
    Returns just the plaintext secret.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$StegoImage
    )

    if (-not (Test-Path $StegoImage)) { throw "Stego image not found: $StegoImage" }

    $bytes = ConvertFrom-StegoImage -StegoImagePath $StegoImage
    $json  = [System.Text.Encoding]::UTF8.GetString($bytes)
    $data  = $json | ConvertFrom-Json

    if ($data.type -ne 'salt-rolls') {
        throw "Payload type '$($data.type)' is not 'salt-rolls'. Use Show-PasswordFiles for NPWD password payloads."
    }

    $secret = ConvertFrom-SaltRolls -Rolls $data.rolls
    return [pscustomobject]@{
        Secret = $secret
        Rolls  = $data.rolls
        Label  = $data.label
    }
}

Export-ModuleMember -Function New-Password, New-DicewareRandomString, Get-DicewareChar, Get-DicewarePassword, Get-Password, Get-LastPassword, Invoke-CryptoRandom, Save-PasswordToFile, Get-PasswordFromFile, Hide-PasswordFiles, Show-PasswordFiles, Out-PasswordSettings, ConvertTo-SaltRolls, ConvertFrom-SaltRolls, Export-EncodedSecret, Read-EncodedSecret