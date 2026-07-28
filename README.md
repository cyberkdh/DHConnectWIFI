# DHConnectWIFI

DHConnectWIFI is a Windows console helper for connecting to Wi-Fi networks by using the Native Wifi API.

It supports common Wi-Fi workflows such as scanning available networks, connecting with a generated profile, reconnecting with a stored Windows profile, deleting a profile, and handling hidden SSID scenarios.

## Features

- Scan nearby Wi-Fi networks
- Show optional BSSID information
- Connect to open networks
- Connect to personal networks such as WPA-PSK and WPA2-Personal
- Connect to enterprise networks such as WPA-Enterprise and WPA2-Enterprise with PEAP/MSCHAPv2
- Reconnect by using an existing Windows WLAN profile
- Delete an existing Windows WLAN profile
- Handle hidden SSID connections with direct options or console fallback selection

## Supported Commands

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

## Build

Environment used for this project:

- Visual Studio 2022
- Windows 10 or later
- C++14 or lower policy in this workspace

Example build command:

```powershell
"C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" .\DHConnectWifi\DHConnectWIFI.sln /p:Configuration=Release /p:Platform=x64
```

Build output location:

```text
output\x64\Release\DHConnectWIFI.exe
```

## Quick Start

Scan networks:

```powershell
DHConnectWIFI.exe scan
```

Scan a specific SSID:

```powershell
DHConnectWIFI.exe scan --ssid dslocalwifi_24
```

Connect to a personal network:

```powershell
DHConnectWIFI.exe connect --ssid homewifi --password mywifipassword
```

Connect to an enterprise network:

```powershell
DHConnectWIFI.exe connect --ssid dslocalwifi_24 --username testuser --password testpassword --domain ""
```

Connect to an enterprise network without certificate prompt after CA trust is configured:

```powershell
DHConnectWIFI.exe connect --ssid dslocalwifi_24 --username testuser --password testpassword --domain "" --trusted-root-ca 727A30D0E344AA7C41141791107BD290C64B3C6D --no-prompt true
```

Reconnect by using a stored Windows profile:

```powershell
DHConnectWIFI.exe connect-profile --ssid dslocalwifi_24
```

Delete a stored Windows profile:

```powershell
DHConnectWIFI.exe delete-profile --ssid dslocalwifi_24
```

Connect to a hidden SSID:

```powershell
DHConnectWIFI.exe connect --ssid hiddenwifi --hidden true
```

Connect to a hidden SSID with explicit security settings:

```powershell
DHConnectWIFI.exe connect --ssid hiddenwifi --hidden true --auth wpa2-personal --cipher aes --password secret123
```

## Enterprise Notes

- PEAP/MSCHAPv2 is supported in the current implementation.
- If `--no-prompt false` is used, Windows may wait for certificate confirmation in the Wi-Fi panel.
- If `--no-prompt true` is used, certificate trust or server name mismatch can cause silent authentication failure.
- For stable enterprise connection, configure the correct trusted Root CA thumbprint and expected server names when required.

## Hidden SSID Notes

- If the hidden SSID can be detected during scan, the tool can reuse the detected security information.
- If the hidden SSID cannot be fully identified, the tool can fall back to console security selection.
- You can still provide `--auth` and `--cipher` directly if you already know the security mode.

## Current Limits

- WPA3-SAE is not currently validated in the available Windows OS and driver environment.
- OWE is not currently validated in the available Windows OS and driver environment.
- Hidden SSID interactive flow currently falls back on security-type selection only. Password, username, and domain are still passed by arguments.

## Documentation

- Detailed usage guide: [docs/USAGE.md](docs/USAGE.md)

## License

MIT License. See [LICENSE](LICENSE).
