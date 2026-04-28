# GlobalProtect_decode_config

> PowerShell script to decrypt the local portal configuration stored on disk by Palo Alto Networks GlobalProtect VPN client.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Output](#output)
- [Use Cases](#use-cases)
- [Acknowledgements](#acknowledgements)
- [Legal Disclaimer](#legal-disclaimer)

---

## Overview

When the GlobalProtect client connects to a portal, it caches the portal configuration locally in encrypted files under:

```
%USERPROFILE%\AppData\Local\Palo Alto Networks\GlobalProtect\
```

This script reverses both the DPAPI and AES-256-CBC encryption layers applied to these files, exposing the plaintext XML portal configuration — including gateway addresses, authentication settings, and session cookies.

This tool is intended for **authorized penetration testing**, **incident response**, and **security research** on systems you own or have explicit written permission to assess.

---

## How It Works

GlobalProtect derives its AES-256 encryption key from the machine's Computer SID using the following algorithm:

1. **Retrieve** the local Administrator account SID (`S-1-5-*-500`) and strip the RID to obtain the Computer SID.
2. **Compute** `MD5("pannetwork")` (hardcoded salt used by GlobalProtect).
3. **Concatenate** the binary SID bytes with the MD5 hash and compute a second MD5 — this yields a 16-byte key, which is doubled to 32 bytes for AES-256.
4. **Decrypt** using AES-256-CBC with a null IV.

Two file types are handled:

| File pattern | Encryption layers |
|---|---|
| `PanPortalCfg_*_clear.xml` | AES-256-CBC only (DPAPI already stripped) |
| `PanPortalCfg_*.dat` | DPAPI (LocalMachine or CurrentUser scope) + AES-256-CBC |

---

## Prerequisites

- Windows OS with PowerShell 5.1+
- The `System.Security` and `System.Core` .NET assemblies (included by default)
- **Local Administrator privileges** (required to read the local machine SID and DPAPI-protected blobs)
- Run in the context of the user account whose GlobalProtect session is being analyzed

---

## Usage

```powershell
# Clone or download the script, then run:
.\decode_gp_config.ps1
```

The script automatically locates GlobalProtect config files in the expected path and writes decrypted output alongside the originals.

> **Note:** No arguments are required. The script auto-discovers all matching files under `%USERPROFILE%\AppData\Local\Palo Alto Networks\GlobalProtect\`.

---

## Output

For each successfully decrypted file, the script:

- Writes `<original_name>_decrypted.xml` next to the source file
- Prints a preview of the first 200 characters of decrypted content to the console
- Reports `[OK]` or `[FAIL]` per file

Example console output:

```
[*] Computer SID: S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
[*] Derived AES key: A1B2C3D4...
[OK] Decrypted: PanPortalCfg_portal_clear.xml -> ..._decrypted.xml
[*] Preview : <?xml version="1.0"?><config>...
```

---

## Use Cases

- **Penetration testing:** Recover portal gateway addresses, session tokens, or pre-logon credentials cached on a compromised endpoint as part of an authorized red team engagement.
- **Incident response / forensics:** Recover portal configuration artifacts during the investigation of a compromised host to understand the VPN posture at the time of compromise.
- **Security research:** Analyze the GlobalProtect configuration cache format to study the client's security model.

---

## Acknowledgements

This work builds directly on the research and tooling of [@rotarydrone](https://x.com/rotarydrone):

- **GlobalUnProtect project:** https://github.com/rotarydrone/GlobalUnProtect/
- **Medium article – *Decrypting and Replaying VPN Cookies*:** https://rotarydrone.medium.com/decrypting-and-replaying-vpn-cookies-4a1d8fc7773e

---

## Legal Disclaimer

> **⚠️ For authorized use only.**
>
> This tool is provided for **lawful security testing, research, and incident response purposes only**.
>
> Use of this script against systems without **explicit prior written authorization** from the system owner is **illegal** and may violate computer fraud and abuse laws in your jurisdiction (including but not limited to the Computer Fraud and Abuse Act (CFAA) in the United States, the Computer Misuse Act in the United Kingdom, and equivalent legislation in other countries).
>
> By using this tool, you confirm that:
> - You have obtained **explicit written permission** from the asset owner or their authorized representative before running this script on any system.
> - Your use is limited to **authorized penetration tests, red team engagements, digital forensic investigations, or personal research** on systems you own or control.
> - You accept **full legal and ethical responsibility** for any use of this tool.
>
> The author(s) of this project assume **no liability** for misuse or damage caused by this software.
