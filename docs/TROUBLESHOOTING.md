# DHConnectWIFI Troubleshooting

## Overview

This document lists common failure situations and practical ways to diagnose them.

## 1. Target SSID Not Found

Example message:

```text
[INFO] Target SSID not found: myssid
```

What to check:

1. Confirm that the SSID is in range.
2. Run `scan` first and verify the exact SSID name.
3. If the network is hidden, retry with `--hidden true`.

Example:

```powershell
DHConnectWIFI.exe connect --ssid hiddenwifi --hidden true
```

## 2. Personal Wi-Fi Password Error

Possible symptoms:

- repeated `authenticating`
- `connection_attempt_fail`
- dynamic key exchange timeout

What to check:

1. Re-enter the password carefully.
2. Delete the stored profile if an old profile may be interfering.
3. Retry with a fresh profile.

Examples:

```powershell
DHConnectWIFI.exe delete-profile --ssid homewifi
DHConnectWIFI.exe connect --ssid homewifi --password mywifipassword
```

## 3. Enterprise Authentication Stays at Authenticating

Possible causes:

- certificate trust mismatch
- server name mismatch
- missing PEAP user credential
- missing EAP-TLS client certificate
- Windows waiting for certificate approval

What to check:

1. For PEAP, verify `--username`, `--password`, and `--domain`.
2. If needed, verify `--trusted-root-ca`.
3. If server name validation is required, verify `--server-names`.
4. For EAP-TLS, verify that the client certificate exists in the Windows certificate store and includes a private key.
5. If using direct certificate selection, verify `--client-cert-thumbprint`.
6. If `--no-prompt false` is used, open the Windows Wi-Fi panel and check for certificate approval.

PEAP example:

```powershell
DHConnectWIFI.exe connect --ssid homwwifi --eap-method peap --username testuser --password testpassword --domain "" --trusted-root-ca 727A30D0E344AA7C41141791107BD290C64B3C6D --no-prompt true
```

EAP-TLS example:

```powershell
DHConnectWIFI.exe connect --ssid dslocalwifi_24 --eap-method tls --auth wpa2-enterprise --cipher aes --client-cert-thumbprint 76D216AAD8D8D93B4C7F6F17DFFB12DFBA703524 --trusted-root-ca 727A30D0E344AA7C41141791107BD290C64B3C6D --no-prompt true
```

## 4. EAP User Data Apply Failure

Example message:

```text
[ERROR] WlanSetProfileEapXmlUserData failed. code=1206
```

What it usually means:

- Windows rejected the EAP user XML for the target profile
- the profile or EAP user XML is not in the expected schema form

What to check:

1. Confirm that the profile is really 802.1X.
2. Recreate the profile with a fresh `connect` command.
3. If you are using EAP-TLS, confirm that `--client-cert-thumbprint` is a valid SHA-1 thumbprint.
4. Check the printed `EAP USER XML` debug block in the console output.

## 5. Hidden SSID Security Cannot Be Detected

If the tool cannot detect the hidden SSID security mode during scan, it can fall back to console security selection.

You can also provide the security mode directly:

```powershell
DHConnectWIFI.exe connect --ssid hiddenwifi --hidden true --auth wpa2-personal --cipher aes --password secret123
```

## 6. Stored Profile Is Old or Broken

Symptoms:

- `connect-profile` fails repeatedly
- the current network configuration changed after a router or enterprise policy update

What to do:

1. Delete the stored profile.
2. Recreate it through a fresh `connect` command.

Example:

```powershell
DHConnectWIFI.exe delete-profile --ssid homwwifi
DHConnectWIFI.exe connect --ssid homwwifi --eap-method peap --username testuser --password testpassword --domain ""
```

## 7. Connectable Is Reported as No

If scan output shows:

```text
Connectable: no
```

This usually means Windows or the wireless driver already considers the network unavailable for connection in the current environment.

This was specifically observed for:

- WPA3-SAE in the available test environment
- OWE in the available test environment

In this situation, code changes alone may not be enough.

## 8. Useful Diagnostic Commands

Scan:

```powershell
DHConnectWIFI.exe scan
```

Scan a specific SSID:

```powershell
DHConnectWIFI.exe scan --ssid homwwifi
```

Scan with BSSID details:

```powershell
DHConnectWIFI.exe scan --ssid homwwifi --show-bssid true
```

Reconnect with stored profile:

```powershell
DHConnectWIFI.exe connect-profile --ssid homwwifi
```
