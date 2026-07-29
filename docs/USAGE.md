# DHConnectWIFI Usage Guide

## Overview

DHConnectWIFI is a Windows console application that helps manage Wi-Fi connection workflows by using the Native Wifi API.

This guide focuses on practical usage examples for:

- scanning networks
- connecting to open or personal networks
- connecting to 802.1X enterprise networks
- reconnecting with a stored profile
- deleting a stored profile
- handling hidden SSID networks

## Command Summary

```text
DHConnectWIFI menu
DHConnectWIFI list-iface
DHConnectWIFI scan
DHConnectWIFI scan [--ssid <name>] [--show-bssid true|false]
DHConnectWIFI delete-profile --ssid <name>
DHConnectWIFI connect-profile --ssid <name>
DHConnectWIFI connect --ssid <name> [--username <id>] [--password <pw>] [--domain <name>]
                      [--eap-method peap|tls] [--server-names <fqdn;fqdn>] [--trusted-root-ca <sha1hex>] [--no-prompt true|false]
                      [--client-cert-thumbprint <sha1hex>]
                      [--hidden true|false] [--auth <mode>] [--cipher <mode>]
```

## 1. Interface and Scan

List wireless interfaces:

```powershell
DHConnectWIFI.exe list-iface
```

Scan all visible networks:

```powershell
DHConnectWIFI.exe scan
```

Scan one SSID:

```powershell
DHConnectWIFI.exe scan --ssid homwwifi
```

Scan one SSID and show BSSID details:

```powershell
DHConnectWIFI.exe scan --ssid homwwifi --show-bssid true
```

Notes:

- `--show-bssid true` may be slower because it performs additional BSS list queries.
- When multiple scan entries match the same SSID and security type, the tool may merge them for display.

## 2. Connect to Open or Personal Wi-Fi

Connect to an open network:

```powershell
DHConnectWIFI.exe connect --ssid guestwifi
```

Connect to a personal network:

```powershell
DHConnectWIFI.exe connect --ssid homewifi --password mywifipassword
```

Supported personal modes in the current implementation:

- `WPA-PSK`
- `WPA2/WPA3-Personal`

## 3. Connect to 802.1X Enterprise Wi-Fi

802.1X enterprise connection supports both PEAP/MSCHAPv2 and EAP-TLS in the current implementation.

### 3.1 PEAP/MSCHAPv2

```powershell
DHConnectWIFI.exe connect --ssid homwwifi --eap-method peap --username testuser --password testpassword --domain ""
```

PEAP example with trusted Root CA thumbprint and no prompt:

```powershell
DHConnectWIFI.exe connect --ssid homwwifi --eap-method peap --username testuser --password testpassword --domain "" --trusted-root-ca 727A30D0E344AA7C41141791107BD290C64B3C6D --no-prompt true
```

### 3.2 EAP-TLS

Basic EAP-TLS example:

```powershell
DHConnectWIFI.exe connect --ssid homwwifi --eap-method tls --auth wpa2-enterprise --cipher aes --trusted-root-ca 727A30D0E344AA7C41141791107BD290C64B3C6D --no-prompt true
```

EAP-TLS example with a specific client certificate thumbprint:

```powershell
DHConnectWIFI.exe connect --ssid dslocalwifi_24 --eap-method tls --auth wpa2-enterprise --cipher aes --client-cert-thumbprint 76D216AAD8D8D93B4C7F6F17DFFB12DFBA703524 --trusted-root-ca 727A30D0E344AA7C41141791107BD290C64B3C6D --no-prompt true
```

Enterprise parameters:

- `--eap-method peap|tls`
- `--server-names <fqdn;fqdn>`
- `--trusted-root-ca <sha1hex>`
- `--client-cert-thumbprint <sha1hex>`
- `--no-prompt true|false`

Guidance:

- If the connection stays at `authenticating`, Windows may be waiting for certificate approval in the Wi-Fi panel.
- If `--no-prompt true` is used, trust mismatch may fail silently.
- For EAP-TLS, the client certificate must already exist in the Windows certificate store and include a private key.
- If `--client-cert-thumbprint` is used, the value must be a SHA-1 thumbprint in hex format.

## 4. Stored Profile Workflows

Reconnect by using an already stored Windows profile:

```powershell
DHConnectWIFI.exe connect-profile --ssid homwwifi
```

Delete a stored Windows profile:

```powershell
DHConnectWIFI.exe delete-profile --ssid homwwifi
```

Notes:

- `connect-profile` uses the stored Windows profile only.
- It does not rewrite password or enterprise credentials.

## 5. Hidden SSID Workflows

Basic hidden SSID connection:

```powershell
DHConnectWIFI.exe connect --ssid hiddenwifi --hidden true
```

If the tool cannot detect security information during scan, it can fall back to console security selection.

You may also provide the security type directly:

```powershell
DHConnectWIFI.exe connect --ssid hiddenwifi --hidden true --auth wpa2-personal --cipher aes --password secret123
```

### Supported `--auth` Values

- `open` -> `open`
- `wpa-psk` -> `WPA-PSK`
- `wpa2-personal` -> `WPA2/WPA3-Personal`
- `wpa-enterprise` -> `WPA-Enterprise`
- `wpa2-enterprise` -> `WPA2/WPA3-Enterprise`

Not supported in this direct mapping:

- `wpa3-sae`
- `owe`
- `wep`

### Supported `--cipher` Values

- `none` -> `none`
- `aes` -> `AES-CCMP`
- `tkip` -> `TKIP`

## 6. Failure and Troubleshooting

The application registers WLAN notifications and can print failure details such as:

- `reason_code`
- `reason_text`

Examples of common situations:

- Wrong password on personal Wi-Fi
- PEAP enterprise authentication failure
- EAP-TLS client certificate selection or validation failure
- Dynamic key exchange timeout
- Certificate trust mismatch

General troubleshooting steps:

1. Run `scan` first and confirm the target SSID and security mode.
2. For PEAP enterprise Wi-Fi, verify user name, password, Root CA trust, and server name settings.
3. For EAP-TLS, verify client certificate installation, private key presence, and thumbprint value.
4. For hidden SSID, retry with `--hidden true`.
5. If hidden SSID detection is incomplete, use console fallback or provide `--auth` and `--cipher`.
6. If a stored profile may be stale, delete it and reconnect with a fresh profile.

## 7. Current Validation Status

Validated:

- Open
- WPA-PSK
- WPA2/WPA3-Personal
- WPA-Enterprise with AES-CCMP
- WPA2/WPA3-Enterprise with AES-CCMP
- EAP-TLS with direct client certificate thumbprint selection
- Hidden SSID workflow

Not currently validated in the available Windows OS and driver environment:

- WPA3-SAE
- OWE
