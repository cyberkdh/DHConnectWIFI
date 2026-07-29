# DHConnectWIFI Enterprise Wi-Fi Guide

## Overview

This document focuses on 802.1X enterprise Wi-Fi usage with PEAP/MSCHAPv2 and EAP-TLS.

## Supported Enterprise Scope

The current implementation is validated for:

- WPA-Enterprise with AES-CCMP
- WPA2/WPA3-Enterprise with AES-CCMP
- EAP-TLS with client certificate selection by SHA-1 thumbprint

## Validation Environment

Enterprise authentication was validated against a real FreeRADIUS test environment on CentOS.

The validation included:

- Windows client connection with DHConnectWIFI
- PEAP/MSCHAPv2 authentication flow
- EAP-TLS authentication flow
- FreeRADIUS debug verification through `radius -X`

## PEAP/MSCHAPv2 Basic Command

```powershell
DHConnectWIFI.exe connect --ssid homwwifi --eap-method peap --username testuser --password testpassword --domain ""
```

## PEAP/MSCHAPv2 Command with Trusted Root CA

```powershell
DHConnectWIFI.exe connect --ssid homwwifi --eap-method peap --username testuser --password testpassword --domain "" --trusted-root-ca 727A30D0E344AA7C41141791107BD290C64B3C6D --no-prompt true
```

## EAP-TLS Basic Command

```powershell
DHConnectWIFI.exe connect --ssid homwwifi --eap-method tls --auth wpa2-enterprise --cipher aes --trusted-root-ca 727A30D0E344AA7C41141791107BD290C64B3C6D --no-prompt true
```

## EAP-TLS Command with Client Certificate Thumbprint

```powershell
DHConnectWIFI.exe connect --ssid homwwifi --eap-method tls --auth wpa2-enterprise --cipher aes --client-cert-thumbprint 76D216AAD8D8D93B4C7F6F17DFFB12DFBA703524 --trusted-root-ca 727A30D0E344AA7C41141791107BD290C64B3C6D --no-prompt true
```

## Parameters

- `--ssid`
  - target enterprise SSID
- `--eap-method`
  - `peap` or `tls`
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
- `--client-cert-thumbprint`
  - SHA1 thumbprint of the EAP-TLS client certificate
- `--no-prompt`
  - `true` disables user confirmation prompt for server validation
  - `false` allows Windows prompt when needed

## Certificate Notes

- `--trusted-root-ca` expects the Root CA thumbprint, not the server certificate thumbprint.
- If `--no-prompt true` is used and trust does not match, the connection may fail silently.
- If `--no-prompt false` is used, Windows may wait for certificate approval in the Wi-Fi panel.
- EAP-TLS requires a client certificate already installed in the Windows certificate store.
- The EAP-TLS client certificate must include a private key.
- `--client-cert-thumbprint` can be used to avoid the Windows certificate chooser and request a specific client certificate directly.

## Recommended Workflow

1. Confirm the enterprise SSID by running `scan`.
2. Install or trust the correct Root CA certificate if required.
3. Choose `--eap-method peap` or `--eap-method tls`.
4. For PEAP, run `connect` with `--username`, `--password`, and other required enterprise parameters.
5. For EAP-TLS, ensure the client certificate is installed and use `--client-cert-thumbprint` when you want to pin a specific certificate.
6. If successful, you can later reuse `connect-profile`.

## Reconnect with Stored Profile

```powershell
DHConnectWIFI.exe connect-profile --ssid homwwifi
```

## Refresh a Broken Enterprise Profile

```powershell
DHConnectWIFI.exe delete-profile --ssid homwwifi
DHConnectWIFI.exe connect --ssid homwwifi --eap-method peap --username testuser --password testpassword --domain ""
```

## Common Failure Patterns

- `authenticating` repeats for a long time
- `connection_attempt_fail`
- certificate prompt remains pending in the Windows Wi-Fi panel
- silent failure after `--no-prompt true`
- `WlanSetProfileEapXmlUserData failed`

If these appear, review:

- CA trust
- server names
- username and password for PEAP
- domain value for PEAP
- client certificate installation and private key for EAP-TLS
- client certificate thumbprint value for EAP-TLS
- whether the stored profile is stale
