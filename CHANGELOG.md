# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0.2] - 2026-07-29

### Added

- `EAP-TLS` enterprise profile generation flow
- `--eap-method peap|tls` option on `connect`
- `--client-cert-thumbprint <sha1hex>` option for selecting a specific EAP-TLS client certificate
- EAP user XML debug output for enterprise credential application verification

### Validated

- `EAP-TLS` connection against a real FreeRADIUS environment on CentOS
- direct client certificate selection by `SHA-1 thumbprint`
- successful connection without Windows certificate chooser after EAP-TLS user XML compatibility adjustment

### Changed

- EAP-TLS user credential XML namespace adjusted for Windows WLAN/EAPHost compatibility
- Version resource updated to `1.0.0.2`

## [1.0.0.1] - 2026-07-28

### Added

- Native Wifi console workflow for Windows
- `scan` command with optional `--show-bssid`
- `connect` command for open, personal, and enterprise Wi-Fi
- `connect-profile` command for reconnecting with an existing Windows WLAN profile
- `delete-profile` command for removing an existing Windows WLAN profile
- Enterprise PEAP/MSCHAPv2 profile generation flow
- Enterprise credential application by EAP XML user data
- Connection failure notification handling with reason code and reason text
- Hidden SSID support with `--hidden true`
- Hidden SSID console fallback for security-type selection
- Version resource set to `1.0.0.1`

### Validated

- Open networks
- WPA-PSK
- WPA2/WPA3-Personal
- WPA-Enterprise with AES-CCMP
- WPA2/WPA3-Enterprise with AES-CCMP
- Hidden SSID workflow
- 802.1X enterprise authentication verified against a real FreeRADIUS environment on CentOS by using `radius -X`

### Known Limits

- WPA3-SAE is not currently validated in the available Windows OS and driver environment
- OWE is not currently validated in the available Windows OS and driver environment
