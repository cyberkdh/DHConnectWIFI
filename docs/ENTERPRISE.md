# DHConnectWIFI Enterprise Wi-Fi Guide

## Overview

This document focuses on 802.1X enterprise Wi-Fi usage with PEAP/MSCHAPv2.

## Supported Enterprise Scope

The current implementation is validated for:

- WPA-Enterprise with AES-CCMP
- WPA2/WPA3-Enterprise with AES-CCMP

## Validation Environment

Enterprise authentication was validated against a real FreeRADIUS test environment on CentOS.

The validation included:

- Windows client connection with DHConnectWIFI
- PEAP/MSCHAPv2 authentication flow
- FreeRADIUS debug verification through `radius -X`

## Basic Command

```powershell
DHConnectWIFI.exe connect --ssid homwwifi --username testuser --password testpassword --domain ""
```

## Command with Trusted Root CA

```powershell
DHConnectWIFI.exe connect --ssid homwwifi --username testuser --password testpassword --domain "" --trusted-root-ca 727A30D0E344AA7C41141791107BD290C64B3C6D --no-prompt true
```

## Parameters

- `--ssid`
  - target enterprise SSID
- `--username`
  - PEAP/MSCHAPv2 user name
- `--password`
  - PEAP/MSCHAPv2 password
- `--domain`
  - optional logon domain, use `""` when not needed
- `--server-names`
  - optional expected RADIUS server FQDN list separated by `;`
- `--trusted-root-ca`
  - SHA1 thumbprint of the trusted Root CA certificate
- `--no-prompt`
  - `true` disables user confirmation prompt for server validation
  - `false` allows Windows prompt when needed

## Certificate Notes

- `--trusted-root-ca` expects the Root CA thumbprint, not the server certificate thumbprint.
- If `--no-prompt true` is used and trust does not match, the connection may fail silently.
- If `--no-prompt false` is used, Windows may wait for certificate approval in the Wi-Fi panel.

## Recommended Workflow

1. Confirm the enterprise SSID by running `scan`.
2. Install or trust the correct Root CA certificate if required.
3. Run `connect` with `--username`, `--password`, and other required enterprise parameters.
4. If successful, you can later reuse `connect-profile`.

## Reconnect with Stored Profile

```powershell
DHConnectWIFI.exe connect-profile --ssid homwwifi
```

## Refresh a Broken Enterprise Profile

```powershell
DHConnectWIFI.exe delete-profile --ssid homwwifi
DHConnectWIFI.exe connect --ssid homwwifi --username testuser --password testpassword --domain ""
```

## Common Failure Patterns

- `authenticating` repeats for a long time
- `connection_attempt_fail`
- certificate prompt remains pending in the Windows Wi-Fi panel
- silent failure after `--no-prompt true`

If these appear, review:

- CA trust
- server names
- username and password
- domain value
- whether the stored profile is stale
