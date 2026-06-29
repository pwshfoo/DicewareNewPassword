# NewPassword Module

PowerShell module for generating cryptographically unpredictable passphrases and random character strings using physical dice simulation. All randomness comes from `Invoke-CryptoRandom`, a private helper that uses `RNGCryptoServiceProvider` on PowerShell 5.1/.NET Framework and `RandomNumberGenerator.Fill` on PowerShell 7/.NET 5+.

---

## Files

| File | Purpose |
|------|---------|
| `NewPassword.psm1` | Module — all functions |
| `eff_large_wordlist.txt` | EFF large wordlist (7776 words, tab-delimited) |
| `diceware.html` | Self-contained offline passphrase generator with QR code, scan, and print sheet |
| `diceware.html.SHA256` | SHA-256 integrity hash — verify with `Get-FileHash .\diceware.html -Algorithm SHA256` |

---

## Browser-Based Generator (`diceware.html`)

A single self-contained HTML file that mirrors the behaviour of `New-Password` and `Get-Password` entirely in the browser. Open it directly from the filesystem — no web server, no dependencies, no network requests. All JavaScript, the EFF wordlist, and QR libraries are embedded inline; the file works fully offline once saved.

> **If downloading from a hosted location:** right-click → **Save As** to save a local copy, then open it from disk. Verify integrity with `Get-FileHash .\diceware.html -Algorithm SHA256` against `diceware.html.SHA256`.

```powershel
iwr "https://raw.githubusercontent.com/pwshfoo/DicewareNewPassword/refs/heads/main/diceware.html" -OutFile "diceware.html" 
iwr "https://raw.githubusercontent.com/pwshfoo/DicewareNewPassword/refs/heads/main/diceware.html.SHA256" -OutFile "diceware.html.SHA256"
if ((Get-FileHash ".\diceware.html" -Algorithm SHA256).Hash -eq (Get-Content ".\diceware.html.SHA256")) { 
    Write-Host "MATCH: File is secure!" -ForegroundColor Green
    ii .\diceware.html 
} else { 
    Write-Warning "MISMATCH: Do not use this file!"
    rm .\diceware.html 
}
```

### Features

| Feature | Detail |
|---|---|
| **Passphrase generation** | Matches `New-Password` exactly — same EFF wordlist (inlined), same 3-dice salt character table, same insertion logic |
| **Crypto-secure randomness** | Uses `crypto.getRandomValues()` with rejection sampling to eliminate modulo bias |
| **Entropy display** | Shows total bits, tier badge (Tier 0 SA / Tier 0 / Tier 1 / Tier 2 / Insufficient), animated bar, and per-component breakdown |
| **Blurred output** | Passphrase is blurred by default; click **Show** to reveal, **Copy** to copy to clipboard |
| **Reconstruction rolls** | Expandable section shows word rolls, salt rolls, uppercase setting, and the exact `Get-Password` command to reproduce the password |
| **JSON export** | Inline JSON block (matching `Get-Password \| ConvertTo-Json`) with one-click copy — paste directly into the **Reconstruct** card or save for later |
| **Reconstruct from JSON** | Paste JSON from `Get-Password \| ConvertTo-Json` and click **Reconstruct** to re-derive the passphrase from saved rolls |
| **Manual reconstruction** | Enter word rolls, salt rolls, position, separator, and uppercase setting manually |
| **QR code generation** | Encodes rolls and settings into a scannable QR code; blurred by default with click-to-reveal, regenerated automatically on each new passphrase |
| **QR code scanning** | Scan a QR code via file upload or device camera to auto-fill the Reconstruct card fields |
| **Print sheet** | A4 single-page print layout — QR code beside the roll data table, plus the `Get-Password` reconstruction command; no passphrase text is included |
| **Security notice** | Collapsible in-page panel explaining offline safety, hosted-site risks, Save As guidance, and how to verify file integrity |

### Settings

| Setting | Equivalent Parameter | Default |
|---|---|---|
| Word Count | `-WordCount` | 4 |
| Separator | `-Separator` | `-` |
| Salt Characters | `-SaltChars` | 5 |
| Salt Position | `-SaltPosition` | 0 |
| Random Salt Position | automatic | off |
| Uppercase First Letter | `-UppercaseFirstLetter` | on |

### Reconstruct from JSON

1. Run `Get-Password | ConvertTo-Json` (or copy the JSON export from a previously generated passphrase)
2. Paste the JSON into the **Reconstruct from Rolls** card
3. Click **Reconstruct Passphrase** — the JSON is parsed automatically

The JSON format is:

```json
{
    "Rolls": [23124, 25624, 11651, 46464],
    "SaltRolls": [244, 661, 552, 265, 552],
    "SaltPosition": 2,
    "Separator": "-",
    "UppercaseFirstLetter": true
}
```

`UppercaseFirstLetter` is omitted from the JSON when `false`.

---

## How It Works

### Diceware Words (5d6)

Each word is selected by simulating five six-sided dice rolls. The five results are concatenated into a 5-digit key (e.g. `32541`) which is looked up in the EFF large wordlist. With 7776 possible keys and 7776 words, every roll maps to exactly one word.

```
Roll: 3 2 5 4 1  →  key "32541"  →  word "glitter"
```

Each word contributes ~12.9 bits of entropy. A 4-word passphrase has ~51.7 bits.

### Diceware Random Characters (3-dice table)

Individual characters are produced by rolling three six-sided dice using a lookup table:

```
If first roll=1 or 2             3 or 4             5 or 6
           Second Roll        Second Roll        Second Roll
         1  2  3  4  5  6   1  2  3  4  5  6   1  2  3  4  5  6
T  1     A  B  C  D  E  F   a  b  c  d  e  f   !  @  #  $  %  ^
h  2     G  H  I  J  K  L   g  h  i  j  k  l   &  *  (  )  -  =
i  3     M  N  O  P  Q  R   m  n  o  p  q  r   +  [  ]  {  }  \
r  4     S  T  U  V  W  X   s  t  u  v  w  x   |  `  ;  :  '  "
d  5     Y  Z  0  1  2  3   y  z  ~  _  sp     <  >  /  ?  .  ,
   6     4  5  6  7  8  9
```

| First Roll | Character Group |
|---|---|
| 1–2 | Uppercase A–Z, digits 0–9 |
| 3–4 | Lowercase a–z, `~`, `_`, space |
| 5–6 | Special characters: `! @ # $ % ^ & * ( ) - = + [ ] { } \ \| \` ; : ' " < > / ? . ,` |

The second die selects the column (1–6) and the third die selects the row (1–6) within the group. Combinations that have no mapping are silently re-rolled.

### Salt

When `-SaltChars` is specified, a random character string is generated via `New-DicewareRandomString` and inserted into the passphrase as a full word at `-SaltPosition`. It is joined with the same separator as the other words.

```
Words:        cheddar  crabgrass  armoire  bundle
SaltPosition: 2
Salt string:  k#9

Result:  cheddar-crabgrass-k#9-armoire-bundle
```

---

## Security & Entropy

### Why the Public Wordlist and Character Table Are Not a Weakness

Both the EFF large wordlist and the Diceware character table are publicly available documents. This is intentional and does **not** weaken the passwords.

This follows **Kerckhoffs's principle** — a foundational rule in cryptography: *a system should be secure even if everything about it except the secret key is public knowledge.* AES, RSA, and SHA-256 are all fully documented public standards. The same applies here: an attacker who knows the wordlist and character table still cannot predict the output without knowing the specific sequence of dice rolls, which is the secret.

### Entropy Analysis

**Per-component breakdown for `New-Password -WordCount 4 -SaltChars 5 -UppercaseFirstLetter`:**

| Component | Calculation | Bits |
|---|---|---|
| 4 diceware words | 4 × log₂(6⁵) = 4 × 12.93 | **51.7** |
| 5 salt chars (95 valid chars) | 5 × log₂(95) | **32.9** |
| Randomized SaltPosition (0–4) | log₂(5) | **+2.3** |
| **Total** | | **~86.8 bits** |

The 95 valid characters in the salt table come from: 36 uppercase/digit (group 0) + 29 lowercase/symbols (group 1) + 30 special characters (group 2). After rejection-sampling of unmapped dice combinations, all 95 characters are equally probable.

**Scaling by word count:**

| WordCount | Words Only | With 5 Salt Chars |
|---|---|---|
| 3 | 38.8 bits | ~71.7 bits |
| 4 | 51.7 bits | ~84.6 bits |
| 5 | 64.6 bits | ~97.5 bits |

### Corporate Suitability

| Requirement | This Module |
|---|---|
| **Entropy** | ~85–87 bits (4 words + 5 salt) — well above the informal 80-bit "very strong" threshold |
| **Uppercase** | `-UppercaseFirstLetter` satisfies "must contain uppercase" policies |
| **Special characters & digits** | Salt guarantees both are present |
| **RNG quality** | `Invoke-CryptoRandom` is cryptographically secure on both PS5.1 and PS7 |
| **Audit trail** | `$global:DICEWARE` and `Get-Password` allow exact reproduction from saved rolls |
| **Length** | ~40+ characters for a 4-word + 5-char-salt password — exceeds any typical 12–16 char minimum |

> **Note on short password caps:** Some older systems enforce a 20–32 character maximum. If you hit one, use `-WordCount 3` — you still get ~72 bits of entropy, which exceeds NIST SP 800-63B guidance.

### Enterprise Entropy Thresholds

Industry and regulatory guidance for privileged account passwords:

| Account Tier | Minimum Entropy | Reference |
|---|---|---|
| Standard user | ~40 bits | NIST SP 800-63B baseline |
| Privileged / admin | 60–72 bits | NIST high-value target threshold |
| Tier 0 (Domain Admin, EA) | **≥ 80 bits** | CIS Controls, ANSSI, Microsoft ESAE |
| Service accounts / MFA bypass paths | ≥ 100 bits | No human memory required — store in a vault |

NIST SP 800-63B no longer mandates specific entropy minimums; it focuses on breach resistance and memorability. The 60-bit figure is the widely-cited practical brute-force floor for privileged accounts. At 128 bits a password is considered cryptographically infeasible to brute-force even against anticipated future hardware.

**This module against those thresholds (defaults: 4 words + 5 salt chars):**

| Your Script | Tier Requirement | Module Output |
|---|---|---|
| Tier 2 (standard user) | ≥ 60 bits | ~86.9 bits ✅ |
| Tier 1 (admin) | ≥ 72 bits | ~86.9 bits ✅ |
| Tier 0 (EA / Domain Admin) | ≥ 80 bits | ~86.9 bits ✅ |

To push Tier 0 passwords above 99 bits, use `-WordCount 5` (WordBits → 64.6, total → ~99.8 bits).

---

## Exported Functions

### `New-Password`

Generates a diceware passphrase and returns a rich object.

```powershell
New-Password [-WordCount <int>] [-Separator <string>] [-SaltChars <int>]
             [-SaltPosition <int>] [-UppercaseFirstLetter] [-WordlistPath <string>]
```

**Parameters**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `WordCount` | int | `4` | Number of diceware words (1–10) |
| `Separator` | string | `-` | Character(s) between words |
| `SaltChars` | int | `5` | Number of diceware chars to generate as a salt word |
| `SaltPosition` | int | rnd | Where to insert salt: 0=first, 1=after word 1, … ≥WordCount=last |
| `UppercaseFirstLetter` | switch | — | Capitalize first letter of each diceware word |
| `WordlistPath` | string | auto | Override wordlist file path |

**Returns** `[pscustomobject]`

| Property | Description |
|---|---|
| `Password` | The assembled passphrase string |
| `Rolls` | Array of 5-digit word keys, one per word |
| `SaltRolls` | Array of compact 3-digit roll strings (d1d2d3) per salt char, or empty |
| `SaltPosition` | Index where the salt was inserted, or `$null` if no salt |

**Examples**

```powershell
# Basic 4-word passphrase
New-Password
# Password: cheddar-crabgrass-armoire-bundle

# Title-cased with salt after the 2nd word
New-Password -WordCount 4 -SaltChars 4 -SaltPosition 2 -UppercaseFirstLetter
# Password: Cheddar-Crabgrass-k#9B-Armoire-Bundle

# Salt appended at the end (default position)
New-Password -SaltChars 6
# Password: cheddar-crabgrass-armoire-bundle-k#9Bw2

# Access individual properties
$r = New-Password -SaltChars 3 -SaltPosition 0
$r.Password      # the passphrase
$r.Rolls         # e.g. {32541, 11234, 56123, 44512}
$r.SaltRolls     # e.g. {314, 542, 163}  (d1d2d3 per char)
$r.SaltPosition  # 0
```

---

### `Get-Password`

Reconstructs a passphrase from saved roll data, or re-exports the last generated password. Supports the same `-Export` / stego options as `New-Password`.

```powershell
# Reconstruct from saved rolls
Get-Password -Rolls <string[]> [-SaltRolls <string[]>] [-SaltPosition <int>]
             [-Separator <string>] [-UppercaseFirstLetter] [-WordlistPath <string>]
             [-Export] [-EncryptedJsonPath <path>] [-KeyFilePath <path>]
             [-KeyCarrierImage <path>] [-DataCarrierImage <path>]

# Re-export the last generated password
Get-Password -LastPassword [-Export] [-EncryptedJsonPath <path>] [-KeyFilePath <path>]
             [-KeyCarrierImage <path>] [-DataCarrierImage <path>]
```

**Parameters**

| Parameter | Set | Required | Description |
|---|---|---|---|
| `Rolls` | ByRolls | Yes | 5-digit word keys from `New-Password.Rolls` |
| `SaltRolls` | ByRolls | No | 3-digit compact roll strings from `New-Password.SaltRolls` |
| `SaltPosition` | ByRolls | No | From `New-Password.SaltPosition` |
| `Separator` | ByRolls | No | Default `-` |
| `UppercaseFirstLetter` | ByRolls | No | Capitalize first letter of each word |
| `LastPassword` | LastPassword | **Yes** | Use `$global:DICEWARE` — no Rolls needed |
| `Export` | Both | No | Encrypt result to `.key` + `.jsonenc` under `.password\` |
| `EncryptedJsonPath` | Both | No | Override output path for the `.jsonenc` file |
| `KeyFilePath` | Both | No | Override output path for the `.key` file |
| `KeyCarrierImage` | Both | No | Carrier image to embed `.key` via LSB steganography |
| `DataCarrierImage` | Both | No | Carrier image to embed `.jsonenc` via LSB steganography |
| `KeyStegoOutput` | Both | No | Output BMP for the hidden `.key` |
| `DataStegoOutput` | Both | No | Output BMP for the hidden `.jsonenc` |

**Examples**

```powershell
# Reproduce a password from saved rolls
$r = New-Password -SaltChars 3 -SaltPosition 1 -UppercaseFirstLetter
Get-Password -Rolls $r.Rolls -SaltRolls $r.SaltRolls -SaltPosition $r.SaltPosition -UppercaseFirstLetter

# Export the last generated password to encrypted files
Get-Password -LastPassword -Export

# Export + embed in stego BMPs in one shot
Get-Password -LastPassword -Export -KeyCarrierImage .\office.jpg -DataCarrierImage .\team.jpg
```

---

### `Get-DicewarePassword`

Reconstructs a passphrase from word-only roll keys (no salt). Simpler alternative to `Get-Password` when no salt was used.

```powershell
Get-DicewarePassword -DiceRolls <string[]> [-Separator <string>]
                     [-UppercaseFirstLetter] [-WordlistPath <string>]
```

**Example**

```powershell
$r = New-Password -WordCount 3 -UppercaseFirstLetter
Get-DicewarePassword -DiceRolls $r.Rolls -UppercaseFirstLetter
# Returns the same passphrase string
```

---

### `New-DicewareRandomString`

Generates a random character string using the 3-dice table. Used internally by `New-Password` for salt generation.

```powershell
New-DicewareRandomString [-Chars <int>]
```

**Returns** `[pscustomobject]` with `String` (the character string) and `Rolls` (verbose roll entries per char, e.g. `d1=3 d2=1 d3=4 -> 's'`).

**Example**

```powershell
$r = New-DicewareRandomString -Chars 8
$r.String   # e.g. "sV7*kP2!"
$r.Rolls    # one entry per character showing d1/d2/d3 and the resulting char
```

---

### `Get-DicewareChar`

Looks up a single character from the 3-dice table using explicit roll values. Returns `$null` and emits a warning for unmapped combinations.

```powershell
Get-DicewareChar -D1 <int> -D2 <int> -D3 <int>
```

**Examples**

```powershell
Get-DicewareChar -D1 1 -D2 1 -D3 1   # 'A'
Get-DicewareChar -D1 3 -D2 1 -D3 1   # 'a'
Get-DicewareChar -D1 5 -D2 2 -D3 2   # '*'
Get-DicewareChar -D1 3 -D2 6 -D3 5   # $null + warning (no mapping)
```

---

### `Save-PasswordToFile`

Encrypts the last `New-Password` result to an AES-256 protected JSON file alongside a 256-bit key file. The `Password` (SecureString) is never written to disk — only the reconstruction data (rolls, salt, separator) is saved. The recipient calls `Get-PasswordFromFile` to rebuild the passphrase.

```powershell
Save-PasswordToFile -KeyFilePath <path> -EncryptedJsonPath <path>
                    [-OverwriteKeyFile] [-InputObject <pscustomobject>]
```

**Parameters**

| Parameter | Required | Description |
|---|---|---|
| `KeyFilePath` | Yes | Path for the 256-bit AES key file. Protect with NTFS permissions. |
| `EncryptedJsonPath` | Yes | Path for the encrypted JSON reconstruction file. |
| `OverwriteKeyFile` | No | Regenerate the key even if the key file already exists. |
| `InputObject` | No | Password object to export; defaults to `$global:DICEWARE`. |

**Example**

```powershell
New-Password -Export -KeyFilePath C:\Secure\pass.key -EncryptedJsonPath C:\Share\pass.jsonenc
```

---

### `Get-PasswordFromFile`

Decrypts a `.jsonenc` + `.key` file pair and reconstructs the full password object. Returns the same `[pscustomobject]` shape as `New-Password`, with `Password` as a `SecureString`.

```powershell
$r = Get-PasswordFromFile -KeyFilePath <path> -EncryptedJsonPath <path>
```

**Example**

```powershell
$r = Get-PasswordFromFile -KeyFilePath .\.password\20260613_123456.key `
                          -EncryptedJsonPath .\.password\20260613_123456.jsonenc
(New-Object System.Management.Automation.PSCredential 'x', $r.Password).GetNetworkCredential().Password
```

---

## Steganography Transport

LSB (Least Significant Bit) steganography hides data inside a carrier image by replacing the lowest bit of each R, G, B channel per pixel. A 1-value color shift (e.g. `200 → 201`) is imperceptible to the human eye and invisible to side-by-side comparison. JPEG, PNG, and BMP inputs are accepted; output is always saved as lossless BMP (JPEG re-compression would destroy LSBs).

**Security model** — send the two output images via **separate channels**:

```
office_photo.jpg  →  LSB-encode .key     →  office_photo.bmp  ← encrypted email / secure channel
team_photo.jpg    →  LSB-encode .jsonenc →  team_photo.bmp   ← Teams / SharePoint / any channel
```

The `.jsonenc` stego image is AES-256 encrypted and useless without the `.key` stego image. The stego images look identical to the originals; neither file reveals that data is hidden.

**Capacity:** `width × height × 3 ÷ 8` bytes. A 640 × 480 photo holds ~115 KB — far more than the ~2 KB total payload.

---

### `Hide-PasswordFiles`

Encodes `.key` and `.jsonenc` files into two separate carrier images.

```powershell
Hide-PasswordFiles -KeyCarrierImage <path> -DataCarrierImage <path>
                   -KeyFilePath <path> -EncryptedJsonPath <path>
                   [-KeyStegoOutput <path>] [-DataStegoOutput <path>]
```

**Parameters**

| Parameter | Required | Description |
|---|---|---|
| `KeyCarrierImage` | Yes | Source image (**BMP, PNG, or JPEG**) to carry the `.key` payload. Decoded to raw pixels in memory; output is always lossless BMP. |
| `DataCarrierImage` | Yes | Source image (**BMP, PNG, or JPEG**) to carry the `.jsonenc` payload. Use a different image and send via a different channel. |
| `KeyFilePath` | Yes | `.key` file to embed |
| `EncryptedJsonPath` | Yes | `.jsonenc` file to embed |
| `KeyStegoOutput` | No | Output BMP; defaults to `.password\<ts>_key.bmp` |
| `DataStegoOutput` | No | Output BMP; defaults to `.password\<ts>_data.bmp` |

**Examples**

```powershell
# Two-step: export files first, then embed
New-Password -Export
Hide-PasswordFiles -KeyCarrierImage .\office.jpg -DataCarrierImage .\team.jpg `
                   -KeyFilePath .\.password\20260613_123456.key `
                   -EncryptedJsonPath .\.password\20260613_123456.jsonenc

# One-step: generate + export + embed
New-Password -Export -KeyCarrierImage .\office.jpg -DataCarrierImage .\team.jpg
```

---

### `Show-PasswordFiles`

Extracts the payload from two stego BMPs and reconstructs the password object. Extracted files are written to `.password\<timestamp>_extracted.{key,jsonenc}` by default.

```powershell
$r = Show-PasswordFiles -KeyStegoImage <path> -DataStegoImage <path>
                            [-KeyFilePath <path>] [-EncryptedJsonPath <path>]
```

Returns the same `[pscustomobject]` as `Get-PasswordFromFile`.

**Example**

```powershell
$r = Show-PasswordFiles -KeyStegoImage .\office.bmp -DataStegoImage .\team.bmp
(New-Object System.Management.Automation.PSCredential 'x', $r.Password).GetNetworkCredential().Password
```

---

### `Get-LastPassword`

Returns the most recent `New-Password` result from `$global:DICEWARE`. Use this after account creation to re-inspect the object or copy the password to the clipboard without regenerating.

```powershell
Get-LastPassword [-CopyToClipboard]
```

**Parameters**

| Parameter | Type | Description |
|---|---|---|
| `CopyToClipboard` | switch | Copies the plain text password to the clipboard via `Set-Clipboard`. Requires PS7+. |

**Examples**

```powershell
# View the last generated password object
Get-LastPassword

# Copy password to clipboard after account creation
Get-LastPassword -CopyToClipboard

# Show plain text in terminal
(Get-LastPassword).Password | ConvertFrom-SecureString -AsPlainText
```

---

## Complete Workflows

### Step 1 — Generate a password and export to encrypted files

```powershell
# Generate and export in one step (auto-names files under .password\)
New-Password -Export
# Writes: .password\<ts>.key  and  .password\<ts>.jsonenc

# Or: generate during account creation, then export the last password
New-Tier0User.ps1 -samAccountName jsmith
Get-Password -LastPassword -Export
```

---

### Step 2 — Import from `.key` + `.jsonenc`

```powershell
$r = Get-PasswordFromFile -KeyFilePath  .\password\20260613_143022.key `
                         -EncryptedJsonPath .\password\20260613_143022.jsonenc

# View as plain text (PS7+)
$r.Password | ConvertFrom-SecureString -AsPlainText
```

---

### Step 3 — Embed files into BMP stego images

```powershell
# Two-step: export first, then embed into carrier images
New-Password -Export
Hide-PasswordFiles -KeyCarrierImage  .\office.jpg  -DataCarrierImage .\team.jpg `
                   -KeyFilePath      .\.password\20260613_143022.key `
                   -EncryptedJsonPath .\.password\20260613_143022.jsonenc

# One-step: generate + export + embed
New-Password -Export -KeyCarrierImage .\office.jpg -DataCarrierImage .\team.jpg

# Re-export and embed an already-generated password (e.g. after account creation)
Get-Password -LastPassword -Export -KeyCarrierImage .\office.jpg -DataCarrierImage .\team.jpg

# Pipeline: -Export returns KeyFilePath + EncryptedJsonPath; pipe directly into Hide-PasswordFiles
Get-Password -LastPassword -Export |
    Hide-PasswordFiles -KeyCarrierImage .\office.jpg -DataCarrierImage .\team.jpg

New-Password -Export |
    Hide-PasswordFiles -KeyCarrierImage .\office.jpg -DataCarrierImage .\team.jpg
```

Output: `.password\<ts>_key.bmp` — send via **secure channel**  
Output: `.password\<ts>_data.bmp` — send via Teams / email / any channel

---

### Step 4 — Recover password from stego BMPs

```powershell
$r = Show-PasswordFiles -KeyStegoImage  .\.password\20260613_143022_key.bmp `
                        -DataStegoImage .\.password\20260613_143022_data.bmp

# View plain text
$r.Password | ConvertFrom-SecureString -AsPlainText

# Or copy to clipboard
Get-LastPassword -CopyToClipboard
```

---

## Character Table Reference

```
    First Roll 1-2          First Roll 3-4          First Roll 5-6
    (Second Roll →)         (Second Roll →)         (Second Roll →)
Row  1  2  3  4  5  6       1  2  3  4  5  6       1  2  3  4  5  6
 1   A  B  C  D  E  F       a  b  c  d  e  f       !  @  #  $  %  ^
 2   G  H  I  J  K  L       g  h  i  j  k  l       &  *  (  )  -  =
 3   M  N  O  P  Q  R       m  n  o  p  q  r       +  [  ]  {  }  \
 4   S  T  U  V  W  X       s  t  u  v  w  x       |  `  ;  :  '  "
 5   Y  Z  0  1  2  3       y  z  ~  _  sp  —      <  >  /  ?  .  ,
 6   4  5  6  7  8  9       —  —  —  —  —  —       —  —  —  —  —  —
```

`sp` = space. `—` = no mapping (re-roll).

---

## Requirements

- PowerShell 5.1 or 7+
- `eff_large_wordlist.txt` in the same folder as `NewPassword.psm1`
  (download: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt)

---

## Loading the Module

To use it standalone:

```powershell
Import-Module .\NewPassword\NewPassword.psm1
```
