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
                      [--server-names <fqdn;fqdn>] [--trusted-root-ca <sha1hex>] [--no-prompt true|false]
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
DHConnectWIFI.exe scan --ssid dslocalwifi_24
```

Scan one SSID and show BSSID details:

```powershell
DHConnectWIFI.exe scan --ssid dslocalwifi_24 --show-bssid true
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

802.1X enterprise connection is designed around PEAP/MSCHAPv2 in the current implementation.

Basic enterprise example:

```powershell
DHConnectWIFI.exe connect --ssid dslocalwifi_24 --username testuser --password testpassword --domain ""
```

Enterprise example with trusted Root CA thumbprint and no prompt:

```powershell
DHConnectWIFI.exe connect --ssid dslocalwifi_24 --username testuser --password testpassword --domain "" --trusted-root-ca 727A30D0E344AA7C41141791107BD290C64B3C6D --no-prompt true
```

Optional enterprise parameters:

- `--server-names <fqdn;fqdn>`
- `--trusted-root-ca <sha1hex>`
- `--no-prompt true|false`

Guidance:

- If the connection stays at `authenticating`, Windows may be waiting for certificate approval in the Wi-Fi panel.
- If `--no-prompt true` is used, trust mismatch may fail silently.

## 4. Stored Profile Workflows

Reconnect by using an already stored Windows profile:

```powershell
DHConnectWIFI.exe connect-profile --ssid dslocalwifi_24
```

Delete a stored Windows profile:

```powershell
DHConnectWIFI.exe delete-profile --ssid dslocalwifi_24
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
- Enterprise authentication failure
- Dynamic key exchange timeout
- Certificate trust mismatch

General troubleshooting steps:

1. Run `scan` first and confirm the target SSID and security mode.
2. For enterprise Wi-Fi, verify the Root CA trust and server name settings.
3. For hidden SSID, retry with `--hidden true`.
4. If hidden SSID detection is incomplete, use console fallback or provide `--auth` and `--cipher`.
5. If a stored profile may be stale, delete it and reconnect with a fresh profile.

## 7. Current Validation Status

Validated:

- Open
- WPA-PSK
- WPA2/WPA3-Personal
- WPA-Enterprise with AES-CCMP
- WPA2/WPA3-Enterprise with AES-CCMP
- Hidden SSID workflow

Not currently validated in the available Windows OS and driver environment:

- WPA3-SAE
- OWE
