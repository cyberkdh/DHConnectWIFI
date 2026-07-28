# Changelog

All notable changes to this project will be documented in this file.

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
