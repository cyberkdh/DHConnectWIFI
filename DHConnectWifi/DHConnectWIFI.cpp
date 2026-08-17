//////////////////////////////////////////////////////////////////////////////////////////////////
//	Project			: DHConnectWIFI
//	Author			: CYBERKDH
//	Module			: main
//	History			:
//	Copyright		: Copyright (c) 2026 cyberkdh
//	License			: MIT License
//////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <windows.h>
#include <wlanapi.h>

#include <fcntl.h>
#include <io.h>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <locale>
#include <sstream>
#include <thread>
#include <string>
#include <vector>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

namespace {

	volatile LONG g_nconnectattemptfailed = 0;
	volatile DWORD g_dwlastreasoncode = 0;

	std::wstring GuidToString(const GUID& guid) {
		wchar_t szguid[64] = { 0 };
		int nresult = StringFromGUID2(guid, szguid, static_cast<int>(sizeof(szguid) / sizeof(szguid[0])));
		return nresult > 0 ? std::wstring(szguid) : L"";
	}

	std::wstring SsidToString(const DOT11_SSID& ssid) {
		if(ssid.uSSIDLength == 0) {
			return L"";
		}

		int nlength = static_cast<int>(ssid.uSSIDLength);
		std::wstring strssid;
		strssid.reserve(static_cast<size_t>(nlength));
		for(int i = 0; i < nlength; ++i) {
			strssid.push_back(static_cast<wchar_t>(ssid.ucSSID[i]));
		}
		return strssid;
	}

	std::wstring BssTypeToString(DOT11_BSS_TYPE bsstype) {
		switch(bsstype) {
		case dot11_BSS_type_infrastructure:
			return L"infrastructure";
		case dot11_BSS_type_independent:
			return L"adhoc";
		case dot11_BSS_type_any:
			return L"any";
		default:
			return L"unknown";
		}
	}

	std::wstring BssidToString(const UCHAR bssid[6]) {
		std::wostringstream stream;
		stream << std::uppercase << std::hex << std::setfill(L'0');
		for(int i = 0; i < 6; ++i) {
			if(i > 0) {
				stream << L":";
			}
			stream << std::setw(2) << static_cast<unsigned int>(bssid[i]);
		}
		return stream.str();
	}

	std::wstring AuthAlgoToString(DOT11_AUTH_ALGORITHM algo) {
		switch(algo) {
		case DOT11_AUTH_ALGO_80211_OPEN:
			return L"open";
		case DOT11_AUTH_ALGO_80211_SHARED_KEY:
			return L"shared";
		case DOT11_AUTH_ALGO_WPA:
			return L"WPA-Enterprise";
		case DOT11_AUTH_ALGO_WPA_PSK:
			return L"WPA-PSK";
		case DOT11_AUTH_ALGO_WPA_NONE:
			return L"WPA-None";
		case DOT11_AUTH_ALGO_RSNA:
			return L"WPA2/WPA3-Enterprise";
		case DOT11_AUTH_ALGO_RSNA_PSK:
			return L"WPA2/WPA3-Personal";
		case DOT11_AUTH_ALGO_WPA3:
			return L"WPA3-Enterprise";
		case DOT11_AUTH_ALGO_WPA3_SAE:
			return L"WPA3-SAE";
		case DOT11_AUTH_ALGO_OWE:
			return L"OWE";
		default:
			return L"other";
		}
	}

	std::wstring CipherAlgoToString(DOT11_CIPHER_ALGORITHM algo) {
		switch(algo) {
		case DOT11_CIPHER_ALGO_NONE:
			return L"none";
		case DOT11_CIPHER_ALGO_WEP40:
			return L"WEP40";
		case DOT11_CIPHER_ALGO_TKIP:
			return L"TKIP";
		case DOT11_CIPHER_ALGO_CCMP:
			return L"AES-CCMP";
		case DOT11_CIPHER_ALGO_WEP104:
			return L"WEP104";
		case DOT11_CIPHER_ALGO_GCMP:
			return L"GCMP";
		case DOT11_CIPHER_ALGO_GCMP_256:
			return L"GCMP-256";
		case DOT11_CIPHER_ALGO_CCMP_256:
			return L"CCMP-256";
		default:
			return L"other";
		}
	}

	std::wstring InterfaceStateToString(WLAN_INTERFACE_STATE state) {
		switch(state) {
		case wlan_interface_state_not_ready:
			return L"not_ready";
		case wlan_interface_state_connected:
			return L"connected";
		case wlan_interface_state_ad_hoc_network_formed:
			return L"ad_hoc_network_formed";
		case wlan_interface_state_disconnecting:
			return L"disconnecting";
		case wlan_interface_state_disconnected:
			return L"disconnected";
		case wlan_interface_state_associating:
			return L"associating";
		case wlan_interface_state_discovering:
			return L"discovering";
		case wlan_interface_state_authenticating:
			return L"authenticating";
		default:
			return L"unknown";
		}
	}

	std::wstring NotificationCodeToString(DWORD dwcode) {
		switch(dwcode) {
		case wlan_notification_acm_connection_start:
			return L"connection_start";
		case wlan_notification_acm_connection_complete:
			return L"connection_complete";
		case wlan_notification_acm_connection_attempt_fail:
			return L"connection_attempt_fail";
		case wlan_notification_acm_disconnecting:
			return L"disconnecting";
		case wlan_notification_acm_disconnected:
			return L"disconnected";
		default:
			return L"other";
		}
	}

	std::wstring ReasonCodeToString(DWORD dwreasoncode) {
		wchar_t szreason[1024] = { 0 };
		DWORD dwresult = WlanReasonCodeToString(
			dwreasoncode,
			static_cast<DWORD>(sizeof(szreason) / sizeof(szreason[0])),
			szreason,
			NULL);
		if(dwresult != ERROR_SUCCESS) {
			return L"";
		}

		return szreason;
	}

	void WINAPI WlanNotificationCallback(PWLAN_NOTIFICATION_DATA pnotifdata, PVOID) {
		if(pnotifdata == NULL) {
			return;
		}

		if(pnotifdata->NotificationSource != WLAN_NOTIFICATION_SOURCE_ACM) {
			return;
		}

		if(pnotifdata->NotificationCode != wlan_notification_acm_connection_attempt_fail
			&& pnotifdata->NotificationCode != wlan_notification_acm_disconnected
			&& pnotifdata->NotificationCode != wlan_notification_acm_connection_complete) {
			return;
		}

		std::wcout << L"[NOTIFY] " << NotificationCodeToString(pnotifdata->NotificationCode) << L"\n";
		if(pnotifdata->pData == NULL
			|| pnotifdata->dwDataSize < sizeof(WLAN_CONNECTION_NOTIFICATION_DATA) - sizeof(WCHAR)) {
			return;
		}

		const WLAN_CONNECTION_NOTIFICATION_DATA* pconn =
			reinterpret_cast<const WLAN_CONNECTION_NOTIFICATION_DATA*>(pnotifdata->pData);
		std::wstring strssid = SsidToString(pconn->dot11Ssid);
		std::wstring strreason = ReasonCodeToString(pconn->wlanReasonCode);

		if(pnotifdata->NotificationCode == wlan_notification_acm_connection_attempt_fail) {
			InterlockedExchange(&g_nconnectattemptfailed, 1);
			g_dwlastreasoncode = pconn->wlanReasonCode;
		}

		if(strssid.empty() == false) {
			std::wcout << L"         ssid        : " << strssid << L"\n";
		}
		if(wcslen(pconn->strProfileName) > 0) {
			std::wcout << L"         profile     : " << pconn->strProfileName << L"\n";
		}
		std::wcout << L"         reason_code : " << pconn->wlanReasonCode << L"\n";
		if(strreason.empty() == false) {
			std::wcout << L"         reason_text : " << strreason << L"\n";
		}
	}

	std::wstring XmlEscape(const std::wstring& strvalue) {
		std::wstring strresult;
		strresult.reserve(strvalue.size());

		for(size_t i = 0; i < strvalue.size(); ++i) {
			switch(strvalue[i]) {
			case L'&':
				strresult += L"&amp;";
				break;
			case L'<':
				strresult += L"&lt;";
				break;
			case L'>':
				strresult += L"&gt;";
				break;
			case L'\"':
				strresult += L"&quot;";
				break;
			case L'\'':
				strresult += L"&apos;";
				break;
			default:
				strresult.push_back(strvalue[i]);
				break;
			}
		}

		return strresult;
	}

	std::wstring ProfileAuthToXml(const std::wstring& strauth) {
		if(strauth == L"WPA2/WPA3-Enterprise" || strauth == L"WPA3-Enterprise") {
			return L"WPA2";
		}

		if(strauth == L"WPA-Enterprise") {
			return L"WPA";
		}

		return L"WPA2";
	}

	std::wstring ProfilePersonalAuthToXml(const std::wstring& strauth) {
		if(strauth == L"WPA-PSK") {
			return L"WPAPSK";
		}

		if(strauth == L"WPA2/WPA3-Personal") {
			return L"WPA2PSK";
		}

		return L"WPA2PSK";
	}

	std::wstring ProfileCipherToXml(const std::wstring& strcipher) {
		if(strcipher == L"AES-CCMP" || strcipher == L"CCMP-256") {
			return L"AES";
		}

		if(strcipher == L"TKIP") {
			return L"TKIP";
		}

		return L"AES";
	}

	bool IsEnterpriseAuth(const std::wstring& strauth) {
		return strauth == L"WPA-Enterprise"
			|| strauth == L"WPA2/WPA3-Enterprise"
			|| strauth == L"WPA3-Enterprise";
	}

	bool IsPersonalAuth(const std::wstring& strauth) {
		return strauth == L"WPA-PSK"
			|| strauth == L"WPA2/WPA3-Personal";
	}

	bool IsOpenAuth(const std::wstring& strauth, const std::wstring& strcipher) {
		return strauth == L"open" && strcipher == L"none";
	}

	std::wstring BuildNonBroadcastXml(bool bhidden) {
		if(bhidden == false) {
			return L"";
		}

		return L"    <nonBroadcast>true</nonBroadcast>\n";
	}

	std::wstring NormalizeAuthOverride(const std::wstring& strauthvalue) {
		if(strauthvalue == L"open") {
			return L"open";
		}

		if(strauthvalue == L"wpa-psk") {
			return L"WPA-PSK";
		}

		if(strauthvalue == L"wpa2-personal" || strauthvalue == L"wpa2-wpa3-personal") {
			return L"WPA2/WPA3-Personal";
		}

		if(strauthvalue == L"wpa-enterprise") {
			return L"WPA-Enterprise";
		}

		if(strauthvalue == L"wpa2-enterprise" || strauthvalue == L"wpa2-wpa3-enterprise") {
			return L"WPA2/WPA3-Enterprise";
		}

		return L"";
	}

	std::wstring NormalizeCipherOverride(const std::wstring& strciphervalue) {
		if(strciphervalue == L"none") {
			return L"none";
		}

		if(strciphervalue == L"aes" || strciphervalue == L"aes-ccmp") {
			return L"AES-CCMP";
		}

		if(strciphervalue == L"tkip") {
			return L"TKIP";
		}

		return L"";
	}

	std::wstring NormalizeEapMethodValue(const std::wstring& streapmethodvalue) {
		if(streapmethodvalue.empty() == true) {
			return L"peap";
		}

		if(streapmethodvalue == L"peap") {
			return L"peap";
		}

		if(streapmethodvalue == L"tls" || streapmethodvalue == L"eap-tls") {
			return L"tls";
		}

		return L"";
	}

	bool IsHexCharacter(wchar_t chvalue) {
		return (chvalue >= L'0' && chvalue <= L'9')
			|| (chvalue >= L'a' && chvalue <= L'f')
			|| (chvalue >= L'A' && chvalue <= L'F');
	}

	std::wstring NormalizeThumbprintValue(const std::wstring& strthumbprintvalue) {
		std::wstring strnormalized;

		for(size_t i = 0; i < strthumbprintvalue.size(); ++i) {
			wchar_t chvalue = strthumbprintvalue[i];
			if(chvalue == L' ' || chvalue == L'\t' || chvalue == L'\r' || chvalue == L'\n') {
				continue;
			}

			if(IsHexCharacter(chvalue) == false) {
				return L"";
			}

			strnormalized.push_back(static_cast<wchar_t>(towupper(chvalue)));
		}

		if(strnormalized.size() != 40) {
			return L"";
		}

		return strnormalized;
	}

	struct HiddenSecurityChoice {
		std::wstring strauth;
		std::wstring strcipher;
		std::wstring strlabel;
	};

	bool PromptHiddenSecurityChoice(std::wstring& strauth, std::wstring& strcipher) {
		HiddenSecurityChoice choices[] = {
			{ L"open", L"none", L"Open (no password)" },
			{ L"WPA-PSK", L"TKIP", L"WPA-Personal (TKIP)" },
			{ L"WPA2/WPA3-Personal", L"AES-CCMP", L"WPA2-Personal (AES)" },
			{ L"WPA-Enterprise", L"AES-CCMP", L"WPA-Enterprise (AES)" },
			{ L"WPA2/WPA3-Enterprise", L"AES-CCMP", L"WPA2-Enterprise (AES)" }
		};

		for(;;) {
			int nselection = 0;

			std::wcout << L"[PROMPT] Hidden SSID security type selection\n";
			for(size_t i = 0; i < sizeof(choices) / sizeof(choices[0]); ++i) {
				std::wcout << L"  " << (i + 1) << L". " << choices[i].strlabel << L"\n";
			}
			std::wcout << L"  0. cancel\n";
			std::wcout << L"Select> ";

			if((std::wcin >> nselection).fail()) {
				std::wcin.clear();
				std::wcin.ignore(4096, L'\n');
				std::wcout << L"[ERROR] Invalid selection.\n";
				continue;
			}

			std::wcin.ignore(4096, L'\n');
			if(nselection == 0) {
				return false;
			}

			if(nselection >= 1 && nselection <= static_cast<int>(sizeof(choices) / sizeof(choices[0]))) {
				const HiddenSecurityChoice& choice = choices[nselection - 1];
				strauth = choice.strauth;
				strcipher = choice.strcipher;
				std::wcout << L"[INFO] Hidden SSID security selected: " << choice.strlabel << L"\n";
				return true;
			}

			std::wcout << L"[ERROR] Unsupported selection.\n";
		}
	}

	std::wstring BuildOpenProfileXml(const std::wstring& strssid, bool bhidden) {
		std::wstring strssidxml = XmlEscape(strssid);
		std::wstring strnonbroadcastxml = BuildNonBroadcastXml(bhidden);

		return
			L"<?xml version=\"1.0\"?>\n"
			L"<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\n"
			L"  <name>" + strssidxml + L"</name>\n"
			L"  <SSIDConfig>\n"
			L"    <SSID>\n"
			L"      <name>" + strssidxml + L"</name>\n"
			L"    </SSID>\n"
			+ strnonbroadcastxml +
			L"  </SSIDConfig>\n"
			L"  <connectionType>ESS</connectionType>\n"
			L"  <connectionMode>manual</connectionMode>\n"
			L"  <MSM>\n"
			L"    <security>\n"
			L"      <authEncryption>\n"
			L"        <authentication>open</authentication>\n"
			L"        <encryption>none</encryption>\n"
			L"        <useOneX>false</useOneX>\n"
			L"      </authEncryption>\n"
			L"    </security>\n"
			L"  </MSM>\n"
			L"</WLANProfile>\n";
	}

	std::wstring BuildPersonalProfileXml(
		const std::wstring& strssid,
		const std::wstring& strauth,
		const std::wstring& strcipher,
		const std::wstring& strpassword,
		bool bhidden) {
		std::wstring strssidxml = XmlEscape(strssid);
		std::wstring strauthxml = ProfilePersonalAuthToXml(strauth);
		std::wstring strcipherxml = ProfileCipherToXml(strcipher);
		std::wstring strpasswordxml = XmlEscape(strpassword);
		std::wstring strnonbroadcastxml = BuildNonBroadcastXml(bhidden);

		return
			L"<?xml version=\"1.0\"?>\n"
			L"<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\n"
			L"  <name>" + strssidxml + L"</name>\n"
			L"  <SSIDConfig>\n"
			L"    <SSID>\n"
			L"      <name>" + strssidxml + L"</name>\n"
			L"    </SSID>\n"
			+ strnonbroadcastxml +
			L"  </SSIDConfig>\n"
			L"  <connectionType>ESS</connectionType>\n"
			L"  <connectionMode>manual</connectionMode>\n"
			L"  <MSM>\n"
			L"    <security>\n"
			L"      <authEncryption>\n"
			L"        <authentication>" + strauthxml + L"</authentication>\n"
			L"        <encryption>" + strcipherxml + L"</encryption>\n"
			L"        <useOneX>false</useOneX>\n"
			L"      </authEncryption>\n"
			L"      <sharedKey>\n"
			L"        <keyType>passPhrase</keyType>\n"
			L"        <protected>false</protected>\n"
			L"        <keyMaterial>" + strpasswordxml + L"</keyMaterial>\n"
			L"      </sharedKey>\n"
			L"    </security>\n"
			L"  </MSM>\n"
			L"</WLANProfile>\n";
	}

	std::wstring BuildEnterprisePeapProfileXml(
		const std::wstring& strssid,
		const std::wstring& strauth,
		const std::wstring& strcipher,
		const std::wstring& strservernames,
		const std::wstring& strtrustedrootca,
		bool bdisableuserpromptforservervalidation,
		bool bhidden) {
		std::wstring strssidxml = XmlEscape(strssid);
		std::wstring strauthxml = ProfileAuthToXml(strauth);
		std::wstring strcipherxml = ProfileCipherToXml(strcipher);
		std::wstring strservernamesxml = XmlEscape(strservernames);
		std::wstring strservervalidationblock;
		std::wstring strnonbroadcastxml = BuildNonBroadcastXml(bhidden);

		strservervalidationblock =
			L"                  <ServerValidation>\n"
			L"                    <DisableUserPromptForServerValidation>" +
			std::wstring(bdisableuserpromptforservervalidation ? L"true" : L"false") +
			L"</DisableUserPromptForServerValidation>\n";

		if(strservernames.empty() == false) {
			strservervalidationblock +=
				L"                    <ServerNames>" + strservernamesxml + L"</ServerNames>\n";
		} else {
			strservervalidationblock +=
				L"                    <ServerNames></ServerNames>\n";
		}

		if(strtrustedrootca.empty() == false) {
			strservervalidationblock +=
				L"                    <TrustedRootCA>" + strtrustedrootca + L"</TrustedRootCA>\n";
		}

		strservervalidationblock +=
			L"                  </ServerValidation>\n";

		return
			L"<?xml version=\"1.0\"?>\n"
			L"<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\n"
			L"  <name>" + strssidxml + L"</name>\n"
			L"  <SSIDConfig>\n"
			L"    <SSID>\n"
			L"      <name>" + strssidxml + L"</name>\n"
			L"    </SSID>\n"
			+ strnonbroadcastxml +
			L"  </SSIDConfig>\n"
			L"  <connectionType>ESS</connectionType>\n"
			L"  <connectionMode>manual</connectionMode>\n"
			L"  <MSM>\n"
			L"    <security>\n"
			L"      <authEncryption>\n"
			L"        <authentication>" + strauthxml + L"</authentication>\n"
			L"        <encryption>" + strcipherxml + L"</encryption>\n"
			L"        <useOneX>true</useOneX>\n"
			L"      </authEncryption>\n"
			L"      <OneX xmlns=\"http://www.microsoft.com/networking/OneX/v1\">\n"
			L"        <authMode>user</authMode>\n"
			L"        <EAPConfig>\n"
			L"          <EapHostConfig xmlns=\"http://www.microsoft.com/provisioning/EapHostConfig\">\n"
			L"            <EapMethod>\n"
			L"              <Type xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">25</Type>\n"
			L"              <VendorId xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">0</VendorId>\n"
			L"              <VendorType xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">0</VendorType>\n"
			L"              <AuthorId xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">0</AuthorId>\n"
			L"            </EapMethod>\n"
			L"            <Config xmlns=\"http://www.microsoft.com/provisioning/EapHostConfig\">\n"
			L"              <Eap xmlns=\"http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1\">\n"
			L"                <Type>25</Type>\n"
			L"                <EapType xmlns=\"http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1\">\n"
			+ strservervalidationblock +
			L"                  <FastReconnect>true</FastReconnect>\n"
			L"                  <InnerEapOptional>false</InnerEapOptional>\n"
			L"                  <Eap xmlns=\"http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1\">\n"
			L"                    <Type>26</Type>\n"
			L"                    <EapType xmlns=\"http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1\">\n"
			L"                      <UseWinLogonCredentials>false</UseWinLogonCredentials>\n"
			L"                    </EapType>\n"
			L"                  </Eap>\n"
			L"                  <EnableQuarantineChecks>false</EnableQuarantineChecks>\n"
			L"                  <RequireCryptoBinding>false</RequireCryptoBinding>\n"
			L"                  <PeapExtensions></PeapExtensions>\n"
			L"                </EapType>\n"
			L"              </Eap>\n"
			L"            </Config>\n"
			L"          </EapHostConfig>\n"
			L"        </EAPConfig>\n"
			L"      </OneX>\n"
			L"    </security>\n"
			L"  </MSM>\n"
			L"</WLANProfile>\n";
	}

	std::wstring BuildEnterpriseTlsProfileXml(
		const std::wstring& strssid,
		const std::wstring& strauth,
		const std::wstring& strcipher,
		const std::wstring& strservernames,
		const std::wstring& strtrustedrootca,
		bool bdisableuserpromptforservervalidation,
		bool bhidden) {
		std::wstring strssidxml = XmlEscape(strssid);
		std::wstring strauthxml = ProfileAuthToXml(strauth);
		std::wstring strcipherxml = ProfileCipherToXml(strcipher);
		std::wstring strservernamesxml = XmlEscape(strservernames);
		std::wstring strservervalidationblock;
		std::wstring strnonbroadcastxml = BuildNonBroadcastXml(bhidden);

		strservervalidationblock =
			L"                  <ServerValidation>\n"
			L"                    <DisableUserPromptForServerValidation>" +
			std::wstring(bdisableuserpromptforservervalidation ? L"true" : L"false") +
			L"</DisableUserPromptForServerValidation>\n";

		if(strservernames.empty() == false) {
			strservervalidationblock +=
				L"                    <ServerNames>" + strservernamesxml + L"</ServerNames>\n";
		} else {
			strservervalidationblock +=
				L"                    <ServerNames></ServerNames>\n";
		}

		if(strtrustedrootca.empty() == false) {
			strservervalidationblock +=
				L"                    <TrustedRootCA>" + strtrustedrootca + L"</TrustedRootCA>\n";
		}

		strservervalidationblock +=
			L"                  </ServerValidation>\n";

		return
			L"<?xml version=\"1.0\"?>\n"
			L"<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\n"
			L"  <name>" + strssidxml + L"</name>\n"
			L"  <SSIDConfig>\n"
			L"    <SSID>\n"
			L"      <name>" + strssidxml + L"</name>\n"
			L"    </SSID>\n"
			+ strnonbroadcastxml +
			L"  </SSIDConfig>\n"
			L"  <connectionType>ESS</connectionType>\n"
			L"  <connectionMode>manual</connectionMode>\n"
			L"  <MSM>\n"
			L"    <security>\n"
			L"      <authEncryption>\n"
			L"        <authentication>" + strauthxml + L"</authentication>\n"
			L"        <encryption>" + strcipherxml + L"</encryption>\n"
			L"        <useOneX>true</useOneX>\n"
			L"      </authEncryption>\n"
			L"      <OneX xmlns=\"http://www.microsoft.com/networking/OneX/v1\">\n"
			L"        <authMode>user</authMode>\n"
			L"        <EAPConfig>\n"
			L"          <EapHostConfig xmlns=\"http://www.microsoft.com/provisioning/EapHostConfig\">\n"
			L"            <EapMethod>\n"
			L"              <Type xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">13</Type>\n"
			L"              <VendorId xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">0</VendorId>\n"
			L"              <VendorType xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">0</VendorType>\n"
			L"              <AuthorId xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">0</AuthorId>\n"
			L"            </EapMethod>\n"
			L"            <Config xmlns=\"http://www.microsoft.com/provisioning/EapHostConfig\">\n"
			L"              <Eap xmlns=\"http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1\">\n"
			L"                <Type>13</Type>\n"
			L"                <EapType xmlns=\"http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1\">\n"
			L"                  <CredentialsSource>\n"
			L"                    <CertificateStore>\n"
			L"                      <SimpleCertSelection>true</SimpleCertSelection>\n"
			L"                    </CertificateStore>\n"
			L"                  </CredentialsSource>\n"
			+ strservervalidationblock +
			L"                  <DifferentUsername>false</DifferentUsername>\n"
			L"                </EapType>\n"
			L"              </Eap>\n"
			L"            </Config>\n"
			L"          </EapHostConfig>\n"
			L"        </EAPConfig>\n"
			L"      </OneX>\n"
			L"    </security>\n"
			L"  </MSM>\n"
			L"</WLANProfile>\n";
	}

	std::wstring BuildPeapUserCredentialXml(
		const std::wstring& strusername,
		const std::wstring& strpassword,
		const std::wstring& strdomain) {
		std::wstring strusernamexml = XmlEscape(strusername);
		std::wstring strpasswordxml = XmlEscape(strpassword);
		std::wstring strdomainxml = XmlEscape(strdomain);

		return
			L"<?xml version=\"1.0\"?>\n"
			L"<EapHostUserCredentials xmlns=\"http://www.microsoft.com/provisioning/EapHostUserCredentials\" "
			L"xmlns:eapCommon=\"http://www.microsoft.com/provisioning/EapCommon\" "
			L"xmlns:baseEap=\"http://www.microsoft.com/provisioning/BaseEapMethodUserCredentials\">\n"
			L"  <EapMethod>\n"
			L"    <eapCommon:Type>25</eapCommon:Type>\n"
			L"    <eapCommon:AuthorId>0</eapCommon:AuthorId>\n"
			L"  </EapMethod>\n"
			L"  <Credentials xmlns:eapUser=\"http://www.microsoft.com/provisioning/EapUserPropertiesV1\" "
			L"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
			L"xmlns:baseEap=\"http://www.microsoft.com/provisioning/BaseEapUserPropertiesV1\" "
			L"xmlns:MsPeap=\"http://www.microsoft.com/provisioning/MsPeapUserPropertiesV1\" "
			L"xmlns:MsChapV2=\"http://www.microsoft.com/provisioning/MsChapV2UserPropertiesV1\">\n"
			L"    <baseEap:Eap>\n"
			L"      <baseEap:Type>25</baseEap:Type>\n"
			L"      <MsPeap:EapType>\n"
			L"        <MsPeap:RoutingIdentity>" + strusernamexml + L"</MsPeap:RoutingIdentity>\n"
			L"        <baseEap:Eap>\n"
			L"          <baseEap:Type>26</baseEap:Type>\n"
			L"          <MsChapV2:EapType>\n"
			L"            <MsChapV2:Username>" + strusernamexml + L"</MsChapV2:Username>\n"
			L"            <MsChapV2:Password>" + strpasswordxml + L"</MsChapV2:Password>\n"
			L"            <MsChapV2:LogonDomain>" + strdomainxml + L"</MsChapV2:LogonDomain>\n"
			L"          </MsChapV2:EapType>\n"
			L"        </baseEap:Eap>\n"
			L"      </MsPeap:EapType>\n"
			L"    </baseEap:Eap>\n"
			L"  </Credentials>\n"
			L"</EapHostUserCredentials>\n";
	}

	std::wstring BuildTlsUserCertificateCredentialXml(const std::wstring& strclientcertthumbprint) {
		return
			L"<?xml version=\"1.0\"?>\n"
			L"<EapHostUserCredentials xmlns=\"http://www.microsoft.com/provisioning/EapHostUserCredentials\" "
			L"xmlns:eapCommon=\"http://www.microsoft.com/provisioning/EapCommon\" "
			L"xmlns:baseEap=\"http://www.microsoft.com/provisioning/BaseEapMethodUserCredentials\">\n"
			L"  <EapMethod>\n"
			L"    <eapCommon:Type>13</eapCommon:Type>\n"
			L"    <eapCommon:AuthorId>0</eapCommon:AuthorId>\n"
			L"  </EapMethod>\n"
			L"  <Credentials xmlns:eapUser=\"http://www.microsoft.com/provisioning/EapUserPropertiesV1\" "
			L"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
			L"xmlns:baseEap=\"http://www.microsoft.com/provisioning/BaseEapUserPropertiesV1\" "
			L"xmlns:eapTls=\"http://www.microsoft.com/provisioning/EapTlsUserPropertiesV1\">\n"
			L"    <baseEap:Eap>\n"
			L"      <baseEap:Type>13</baseEap:Type>\n"
			L"      <eapTls:EapType>\n"
			L"        <eapTls:UserCert>" + strclientcertthumbprint + L"</eapTls:UserCert>\n"
			L"      </eapTls:EapType>\n"
			L"    </baseEap:Eap>\n"
			L"  </Credentials>\n"
			L"</EapHostUserCredentials>\n";
	}

	void PrintDebugXmlBlock(const wchar_t* sztitle, const std::wstring& strxml) {
		std::wcout << L"------- " << sztitle << L" BEGIN -------\n";
		std::wcout << strxml;
		if(strxml.empty() == false && strxml[strxml.size() - 1] != L'\n') {
			std::wcout << L"\n";
		}
		std::wcout << L"------- " << sztitle << L" END   -------\n";
	}

	void PrintUsage() {
		std::wcout << L"DHConnectWIFI - Windows Native Wifi console helper\n";
		std::wcout << L"\n";
		std::wcout << L"Usage:\n";
		std::wcout << L"  DHConnectWIFI menu\n";
		std::wcout << L"  DHConnectWIFI list-iface\n";
		std::wcout << L"  DHConnectWIFI scan\n";
		std::wcout << L"  DHConnectWIFI scan [--ssid <name>] [--show-bssid true|false]\n";
		std::wcout << L"  DHConnectWIFI delete-profile --ssid <name>\n";
		std::wcout << L"  DHConnectWIFI connect-profile --ssid <name>\n";
		std::wcout << L"  DHConnectWIFI connect --ssid <name> [--username <id>] [--password <pw>] [--domain <name>]\n";
		std::wcout << L"                        [--eap-method peap|tls] [--server-names <fqdn;fqdn>] [--trusted-root-ca <sha1hex>] [--no-prompt true|false]\n";
		std::wcout << L"                        [--client-cert-thumbprint <sha1hex>]\n";
		std::wcout << L"                        [--hidden true|false] [--auth <mode>] [--cipher <mode>]\n";
		std::wcout << L"\n";
		std::wcout << L"Arguments:\n";
		std::wcout << L"  --ssid <name>\n";
		std::wcout << L"      Target Wi-Fi SSID name.\n";
		std::wcout << L"      Also used as Windows WLAN profile name for delete-profile and connect-profile.\n";
		std::wcout << L"  --username <id>\n";
		std::wcout << L"      802.1X user name for PEAP/MSCHAPv2.\n";
		std::wcout << L"  --show-bssid true|false\n";
		std::wcout << L"      Optional scan detail flag. false by default because BSSID lookup can be slow.\n";
		std::wcout << L"  --eap-method peap|tls\n";
		std::wcout << L"      Optional 802.1X EAP method selection. peap by default.\n";
		std::wcout << L"      peap : PEAP/MSCHAPv2 with --username/--password.\n";
		std::wcout << L"      tls  : EAP-TLS with client certificate already installed in Windows certificate store.\n";
		std::wcout << L"  --client-cert-thumbprint <sha1hex>\n";
		std::wcout << L"      Optional EAP-TLS client certificate SHA1 thumbprint without spaces.\n";
		std::wcout << L"      If provided, DHConnectWIFI requests that exact client certificate through EAP user data.\n";
		std::wcout << L"  --hidden true|false\n";
		std::wcout << L"      true when the SSID is hidden(non-broadcast). This adds nonBroadcast=true to profile XML.\n";
		std::wcout << L"  --auth <mode>\n";
		std::wcout << L"      Optional connect override for hidden SSID when scan cannot identify auth mode.\n";
		std::wcout << L"      If omitted, console security selection is shown as fallback.\n";
		std::wcout << L"      Supported: open, wpa-psk, wpa2-personal, wpa-enterprise, wpa2-enterprise\n";
		std::wcout << L"      Mapping:\n";
		std::wcout << L"        open            -> open\n";
		std::wcout << L"        wpa-psk         -> WPA-PSK\n";
		std::wcout << L"        wpa2-personal   -> WPA2/WPA3-Personal\n";
		std::wcout << L"        wpa-enterprise  -> WPA-Enterprise\n";
		std::wcout << L"        wpa2-enterprise -> WPA2/WPA3-Enterprise\n";
		std::wcout << L"      Not supported here: wpa3-sae, owe, wep\n";
		std::wcout << L"  --cipher <mode>\n";
		std::wcout << L"      Optional connect override for hidden SSID when scan cannot identify cipher.\n";
		std::wcout << L"      If omitted, console security selection is shown as fallback.\n";
		std::wcout << L"      Supported: none, aes, tkip\n";
		std::wcout << L"      Mapping:\n";
		std::wcout << L"        none -> none\n";
		std::wcout << L"        aes  -> AES-CCMP\n";
		std::wcout << L"        tkip -> TKIP\n";
		std::wcout << L"  --password <pw>\n";
		std::wcout << L"      802.1X password for PEAP/MSCHAPv2.\n";
		std::wcout << L"  --domain <name>\n";
		std::wcout << L"      Optional logon domain. Use \"\" when not needed.\n";
		std::wcout << L"  --server-names <fqdn;fqdn>\n";
		std::wcout << L"      Optional RADIUS server name list. Separate multiple FQDNs with ';'.\n";
		std::wcout << L"  --trusted-root-ca <sha1hex>\n";
		std::wcout << L"      Optional SHA1 thumbprint of trusted Root CA certificate without spaces.\n";
		std::wcout << L"      Do not use the server certificate thumbprint here.\n";
		std::wcout << L"  --no-prompt true|false\n";
		std::wcout << L"      true  : do not allow certificate approval prompt. Validation mismatch can fail silently.\n";
		std::wcout << L"      false : allow Windows Wi-Fi panel to show certificate approval prompt if needed.\n";
		std::wcout << L"\n";
		std::wcout << L"Examples:\n";
		std::wcout << L"  DHConnectWIFI scan\n";
		std::wcout << L"  DHConnectWIFI scan --ssid homwwifi\n";
		std::wcout << L"  DHConnectWIFI scan --ssid homwwifi --show-bssid true\n";
		std::wcout << L"  DHConnectWIFI delete-profile --ssid homwwifi\n";
		std::wcout << L"  DHConnectWIFI connect-profile --ssid homwwifi\n";
		std::wcout << L"  DHConnectWIFI connect --ssid guestwifi\n";
		std::wcout << L"  DHConnectWIFI connect --ssid homewifi --password mywifipassword\n";
		std::wcout << L"  DHConnectWIFI connect --ssid hiddenwifi --hidden true --auth wpa2-personal --cipher aes --password secret123\n";
		std::wcout << L"  DHConnectWIFI connect --ssid homwwifi --eap-method peap --username testuser --password testpassword --domain \"\"\n";
		std::wcout << L"  DHConnectWIFI connect --ssid homwwifi --eap-method peap --username testuser --password testpassword --domain \"\" \\\n";
		std::wcout << L"      --trusted-root-ca 727A30D0E344AA7C41141791107BD290C64B3C6D --no-prompt true\n";
		std::wcout << L"  DHConnectWIFI connect --ssid homwwifi --eap-method tls --auth wpa2-enterprise --cipher aes \\\n";
		std::wcout << L"      --trusted-root-ca 727A30D0E344AA7C41141791107BD290C64B3C6D --no-prompt true\n";
		std::wcout << L"  DHConnectWIFI connect --ssid homwwifi --eap-method tls --auth wpa2-enterprise --cipher aes \\\n";
		std::wcout << L"      --client-cert-thumbprint 0123456789ABCDEF0123456789ABCDEF01234567 --trusted-root-ca 727A30D0E344AA7C41141791107BD290C64B3C6D\n";
		std::wcout << L"\n";
		std::wcout << L"Certificate prompt guide:\n";
		std::wcout << L"  1. If connection stays at [STATE] authenticating and --no-prompt is false,\n";
		std::wcout << L"     open the Windows Wi-Fi panel and check whether 'Continue connecting?' is shown.\n";
		std::wcout << L"  2. If prompt is shown, review certificate details and trust only expected server/CA.\n";
		std::wcout << L"  3. If --no-prompt true is used, server trust or name mismatch can cause silent failure.\n";
		std::wcout << L"  4. connect-profile uses only the stored Windows profile. It does not rewrite password or 802.1X credentials.\n";
		std::wcout << L"  5. EAP-TLS requires a client certificate with private key already installed in Windows certificate store.\n";
		std::wcout << L"  6. For hidden SSID not visible in scan, use --hidden true.\n";
		std::wcout << L"     You can still provide --auth and --cipher, or choose security type in console fallback.\n";
		std::wcout << L"\n";
	}

	std::wstring GetArgValue(const std::vector<std::wstring>& args, const std::wstring& strname);

	bool GetArgBoolValue(const std::vector<std::wstring>& args, const std::wstring& strname, bool bdefaultvalue) {
		std::wstring strvalue = GetArgValue(args, strname);
		if(strvalue.empty() == true) {
			return bdefaultvalue;
		}

		if(strvalue == L"1" || strvalue == L"true" || strvalue == L"TRUE" || strvalue == L"yes") {
			return true;
		}

		if(strvalue == L"0" || strvalue == L"false" || strvalue == L"FALSE" || strvalue == L"no") {
			return false;
		}

		return bdefaultvalue;
	}

	void PrintError(const std::wstring& strcontext, DWORD dwerror) {
		std::wcerr << L"[ERROR] " << strcontext << L" failed. code=" << dwerror << L"\n";
	}

	bool OpenWlanHandle(HANDLE& hwlan, DWORD& dwnegotiatedversion) {
		DWORD dwresult = WlanOpenHandle(2, NULL, &dwnegotiatedversion, &hwlan);
		if(dwresult != ERROR_SUCCESS) {
			PrintError(L"WlanOpenHandle", dwresult);
			return false;
		}

		dwresult = WlanRegisterNotification(
			hwlan,
			WLAN_NOTIFICATION_SOURCE_ACM,
			FALSE,
			WlanNotificationCallback,
			NULL,
			NULL,
			NULL);
		if(dwresult != ERROR_SUCCESS) {
			PrintError(L"WlanRegisterNotification", dwresult);
		}

		return true;
	}

	bool EnumerateInterfaces(HANDLE hwlan, PWLAN_INTERFACE_INFO_LIST& piflist) {
		DWORD dwresult = WlanEnumInterfaces(hwlan, NULL, &piflist);
		if(dwresult != ERROR_SUCCESS) {
			PrintError(L"WlanEnumInterfaces", dwresult);
			return false;
		}

		return true;
	}

	int CommandListInterface(HANDLE hwlan) {
		PWLAN_INTERFACE_INFO_LIST piflist = NULL;
		if(EnumerateInterfaces(hwlan, piflist) == false) {
			return 1;
		}

		if(piflist->dwNumberOfItems == 0) {
			std::wcout << L"[INFO] No wireless interface found.\n";
			WlanFreeMemory(piflist);
			return 0;
		}

		std::wcout << L"[INFO] Wireless interface count: " << piflist->dwNumberOfItems << L"\n";
		for(unsigned int i = 0; i < piflist->dwNumberOfItems; ++i) {
			const WLAN_INTERFACE_INFO& ifinfo = piflist->InterfaceInfo[i];
			std::wcout << L"\n";
			std::wcout << L"[" << i << L"] " << ifinfo.strInterfaceDescription << L"\n";
			std::wcout << L"    GUID  : " << GuidToString(ifinfo.InterfaceGuid) << L"\n";
			std::wcout << L"    State : " << ifinfo.isState << L"\n";
		}

		WlanFreeMemory(piflist);
		return 0;
	}

	std::wstring GetArgValue(const std::vector<std::wstring>& args, const std::wstring& strname) {
		for(size_t i = 0; i + 1 < args.size(); ++i) {
			if(args[i] == strname) {
				return args[i + 1];
			}
		}
		return L"";
	}

	std::vector<std::wstring> QueryBssids(
		HANDLE hwlan,
		const GUID& guidinterface,
		const WLAN_AVAILABLE_NETWORK& network,
		size_t nmaxcount) {
		std::vector<std::wstring> bssids;
		std::wstring strtargetssid = SsidToString(network.dot11Ssid);
		for(int ntry = 0; ntry < 5 && bssids.empty() == true; ++ntry) {
			PWLAN_BSS_LIST pbsslist = NULL;
			DWORD dwresult = WlanGetNetworkBssList(
				hwlan,
				&guidinterface,
				const_cast<PDOT11_SSID>(&network.dot11Ssid),
				network.dot11BssType,
				network.bSecurityEnabled,
				NULL,
				&pbsslist);
			if(dwresult != ERROR_SUCCESS || pbsslist == NULL) {
				if(pbsslist != NULL) {
					WlanFreeMemory(pbsslist);
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(700));
				continue;
			}

			for(unsigned int i = 0; i < pbsslist->dwNumberOfItems; ++i) {
				const WLAN_BSS_ENTRY& entry = pbsslist->wlanBssEntries[i];
				std::wstring strentryssid = SsidToString(entry.dot11Ssid);
				std::wstring strbssid = BssidToString(entry.dot11Bssid);
				bool bexists = false;

				if(strentryssid != strtargetssid) {
					continue;
				}

				for(size_t j = 0; j < bssids.size(); ++j) {
					if(bssids[j] == strbssid) {
						bexists = true;
						break;
					}
				}

				if(bexists == false) {
					bssids.push_back(strbssid);
					if(bssids.size() >= nmaxcount) {
						break;
					}
				}
			}

			WlanFreeMemory(pbsslist);
			if(bssids.empty() == true) {
				std::this_thread::sleep_for(std::chrono::milliseconds(700));
			}
		}

		return bssids;
	}

	bool QueryAvailableNetworkList(
		HANDLE hwlan,
		const GUID& guidinterface,
		PWLAN_AVAILABLE_NETWORK_LIST& pnetworklist) {
		for(int ntry = 0; ntry < 10; ++ntry) {
			DWORD dwresult = WlanGetAvailableNetworkList(
				hwlan,
				&guidinterface,
				WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES |
				WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES,
				NULL,
				&pnetworklist);
			if(dwresult != ERROR_SUCCESS) {
				PrintError(L"WlanGetAvailableNetworkList", dwresult);
				return false;
			}

			if(pnetworklist != NULL && pnetworklist->dwNumberOfItems > 0) {
				return true;
			}

			if(pnetworklist != NULL) {
				WlanFreeMemory(pnetworklist);
				pnetworklist = NULL;
			}

			std::this_thread::sleep_for(std::chrono::seconds(1));
		}

		return true;
	}

	bool HasProfileName(const WLAN_AVAILABLE_NETWORK& network) {
		return wcslen(network.strProfileName) > 0;
	}

	bool TryGetProfileList(
		HANDLE hwlan,
		const GUID& guidinterface,
		PWLAN_PROFILE_INFO_LIST& pprofilelist) {
		DWORD dwresult = WlanGetProfileList(hwlan, &guidinterface, NULL, &pprofilelist);
		if(dwresult != ERROR_SUCCESS) {
			PrintError(L"WlanGetProfileList", dwresult);
			return false;
		}

		return true;
	}

	bool InterfaceHasStoredProfile(
		HANDLE hwlan,
		const GUID& guidinterface,
		const std::wstring& strprofilename) {
		PWLAN_PROFILE_INFO_LIST pprofilelist = NULL;
		if(TryGetProfileList(hwlan, guidinterface, pprofilelist) == false) {
			return false;
		}

		for(unsigned int i = 0; i < pprofilelist->dwNumberOfItems; ++i) {
			if(strprofilename == pprofilelist->ProfileInfo[i].strProfileName) {
				WlanFreeMemory(pprofilelist);
				return true;
			}
		}

		WlanFreeMemory(pprofilelist);
		return false;
	}

	bool QueryStoredProfileXml(
		HANDLE hwlan,
		const GUID& guidinterface,
		const std::wstring& strprofilename,
		std::wstring& strprofilexml) {
		LPWSTR pszprofilexml = NULL;
		DWORD dwflags = 0;
		DWORD dwaccess = 0;
		DWORD dwresult = WlanGetProfile(
			hwlan,
			&guidinterface,
			strprofilename.c_str(),
			NULL,
			&pszprofilexml,
			&dwflags,
			&dwaccess);
		if(dwresult != ERROR_SUCCESS) {
			PrintError(L"WlanGetProfile", dwresult);
			return false;
		}

		strprofilexml = pszprofilexml != NULL ? pszprofilexml : L"";
		if(pszprofilexml != NULL) {
			WlanFreeMemory(pszprofilexml);
		}
		return true;
	}

	bool IsEnterpriseProfileXml(const std::wstring& strprofilexml) {
		return strprofilexml.find(L"<useOneX>true</useOneX>") != std::wstring::npos
			|| strprofilexml.find(L"<OneX ") != std::wstring::npos
			|| strprofilexml.find(L"<OneX>") != std::wstring::npos;
	}

	void AppendUniqueStrings(
		std::vector<std::wstring>& target,
		const std::vector<std::wstring>& values) {
		for(size_t i = 0; i < values.size(); ++i) {
			bool bexists = false;
			for(size_t j = 0; j < target.size(); ++j) {
				if(target[j] == values[i]) {
					bexists = true;
					break;
				}
			}

			if(bexists == false) {
				target.push_back(values[i]);
			}
		}
	}

	struct ScanDisplayEntry {
		std::wstring strssid;
		std::wstring strbsstype;
		std::wstring strauth;
		std::wstring strcipher;
		std::wstring strprofile;
		std::vector<std::wstring> bssids;
		ULONG usignalquality;
		bool bsecurityenabled;
		bool bconnectable;
		DWORD dwnotconnectablereason;
		unsigned int ndupecount;
	};

	int CommandScan(HANDLE hwlan, const std::wstring& strfilterssid, bool bshowbssid) {
		PWLAN_INTERFACE_INFO_LIST piflist = NULL;
		if(EnumerateInterfaces(hwlan, piflist) == false) {
			return 1;
		}

		if(piflist->dwNumberOfItems == 0) {
			std::wcout << L"[INFO] No wireless interface found.\n";
			WlanFreeMemory(piflist);
			return 0;
		}

		for(unsigned int i = 0; i < piflist->dwNumberOfItems; ++i) {
			const WLAN_INTERFACE_INFO& ifinfo = piflist->InterfaceInfo[i];
			DWORD dwresult = WlanScan(hwlan, &ifinfo.InterfaceGuid, NULL, NULL, NULL);
			if(dwresult != ERROR_SUCCESS) {
				PrintError(L"WlanScan", dwresult);
				continue;
			}

			std::this_thread::sleep_for(std::chrono::seconds(2));

			PWLAN_AVAILABLE_NETWORK_LIST pnetworklist = NULL;
			if(QueryAvailableNetworkList(hwlan, ifinfo.InterfaceGuid, pnetworklist) == false) {
				continue;
			}

			std::wcout << L"\n";
			std::wcout << L"=== Interface: " << ifinfo.strInterfaceDescription << L" ===\n";
			std::vector<ScanDisplayEntry> entries;
			for(unsigned int j = 0; j < pnetworklist->dwNumberOfItems; ++j) {
				const WLAN_AVAILABLE_NETWORK& network = pnetworklist->Network[j];
				std::wstring strssid = SsidToString(network.dot11Ssid);
				std::wstring strbsstype = BssTypeToString(network.dot11BssType);
				std::wstring strauth = AuthAlgoToString(network.dot11DefaultAuthAlgorithm);
				std::wstring strcipher = CipherAlgoToString(network.dot11DefaultCipherAlgorithm);
				std::wstring strprofile = HasProfileName(network) ? network.strProfileName : L"<none>";
				std::vector<std::wstring> bssids;
				bool bmerged = false;

				if(strfilterssid.empty() == false && strssid != strfilterssid) {
					continue;
				}

				if(bshowbssid == true && network.dot11Ssid.uSSIDLength > 0) {
					size_t nmaxcount = static_cast<size_t>(network.uNumberOfBssids);
					if(nmaxcount == 0) {
						nmaxcount = 1;
					}
					bssids = QueryBssids(hwlan, ifinfo.InterfaceGuid, network, nmaxcount);
				}

				for(size_t k = 0; k < entries.size(); ++k) {
					ScanDisplayEntry& entry = entries[k];
					if(entry.strssid == strssid
						&& entry.strbsstype == strbsstype
						&& entry.strauth == strauth
						&& entry.strcipher == strcipher
						&& entry.bssids.empty() == false
						&& bssids.empty() == false) {
						if(entry.usignalquality < network.wlanSignalQuality) {
							entry.usignalquality = network.wlanSignalQuality;
						}
						if(entry.strprofile == L"<none>" && strprofile != L"<none>") {
							entry.strprofile = strprofile;
						}
						entry.bsecurityenabled = entry.bsecurityenabled || (network.bSecurityEnabled == TRUE);
						entry.bconnectable = entry.bconnectable || (network.bNetworkConnectable == TRUE);
						if(entry.bconnectable == false) {
							entry.dwnotconnectablereason = network.wlanNotConnectableReason;
						}
						AppendUniqueStrings(entry.bssids, bssids);
						++entry.ndupecount;
						bmerged = true;
						break;
					}
				}

				if(bmerged == false) {
					ScanDisplayEntry entry;
					entry.strssid = strssid;
					entry.strbsstype = strbsstype;
					entry.strauth = strauth;
					entry.strcipher = strcipher;
					entry.strprofile = strprofile;
					entry.bssids = bssids;
					entry.usignalquality = network.wlanSignalQuality;
					entry.bsecurityenabled = (network.bSecurityEnabled == TRUE);
					entry.bconnectable = (network.bNetworkConnectable == TRUE);
					entry.dwnotconnectablereason = network.wlanNotConnectableReason;
					entry.ndupecount = 1;
					entries.push_back(entry);
				}
			}

			for(size_t j = 0; j < entries.size(); ++j) {
				const ScanDisplayEntry& entry = entries[j];
				std::wcout << L"- SSID       : " << (entry.strssid.empty() ? L"<hidden>" : entry.strssid) << L"\n";
				std::wcout << L"  Signal     : " << entry.usignalquality << L"%\n";
				std::wcout << L"  BSS Type   : " << entry.strbsstype << L"\n";
				std::wcout << L"  Security   : " << (entry.bsecurityenabled ? L"enabled" : L"open") << L"\n";
				std::wcout << L"  Auth       : " << entry.strauth << L"\n";
				std::wcout << L"  Cipher     : " << entry.strcipher << L"\n";
				std::wcout << L"  Profile    : " << entry.strprofile << L"\n";
				std::wcout << L"  Connectable: " << (entry.bconnectable ? L"yes" : L"no") << L"\n";
				if(bshowbssid == true && entry.bssids.empty() == false) {
					std::wcout << L"  BSSID      : ";
					for(size_t k = 0; k < entry.bssids.size(); ++k) {
						if(k > 0) {
							std::wcout << L", ";
						}
						std::wcout << entry.bssids[k];
					}
					std::wcout << L"\n";
				}
				if(entry.ndupecount > 1) {
					std::wcout << L"  Merged     : " << entry.ndupecount << L" entries\n";
				}
				if(entry.bconnectable == false) {
					std::wcout << L"  ReasonCode : " << entry.dwnotconnectablereason << L"\n";
				}
				std::wcout << L"\n";
			}

			WlanFreeMemory(pnetworklist);
		}

		WlanFreeMemory(piflist);
		return 0;
	}

	bool HasNetworkSsid(
		HANDLE hwlan,
		const std::wstring& strtargetssid,
		GUID& guidmatchedinterface,
		std::wstring& strmatchedinterface,
		std::wstring& strmatchedauth,
		std::wstring& strmatchedcipher) {
		PWLAN_INTERFACE_INFO_LIST piflist = NULL;
		if(EnumerateInterfaces(hwlan, piflist) == false) {
			return false;
		}

		for(unsigned int i = 0; i < piflist->dwNumberOfItems; ++i) {
			const WLAN_INTERFACE_INFO& ifinfo = piflist->InterfaceInfo[i];
			PWLAN_AVAILABLE_NETWORK_LIST pnetworklist = NULL;
			if(QueryAvailableNetworkList(hwlan, ifinfo.InterfaceGuid, pnetworklist) == false) {
				continue;
			}

			bool bfound = false;
			bool bfoundwithprofile = false;
			std::wstring strbestauth;
			std::wstring strbestcipher;

			for(unsigned int j = 0; j < pnetworklist->dwNumberOfItems; ++j) {
				const WLAN_AVAILABLE_NETWORK& network = pnetworklist->Network[j];
				std::wstring strssid = SsidToString(network.dot11Ssid);
				if(strssid == strtargetssid) {
					std::wstring strauth = AuthAlgoToString(network.dot11DefaultAuthAlgorithm);
					std::wstring strcipher = CipherAlgoToString(network.dot11DefaultCipherAlgorithm);
					bool bhasprofile = HasProfileName(network);

					if(bfound == false || (bfoundwithprofile == false && bhasprofile == true)) {
						guidmatchedinterface = ifinfo.InterfaceGuid;
						strmatchedinterface = ifinfo.strInterfaceDescription;
						strbestauth = strauth;
						strbestcipher = strcipher;
						bfound = true;
						bfoundwithprofile = bhasprofile;
					}
				}
			}

			if(bfound == true) {
				strmatchedauth = strbestauth;
				strmatchedcipher = strbestcipher;
				WlanFreeMemory(pnetworklist);
				WlanFreeMemory(piflist);
				return true;
			}

			WlanFreeMemory(pnetworklist);
		}

		WlanFreeMemory(piflist);
		return false;
	}

	bool SetProfileXml(
		HANDLE hwlan,
		const GUID& guidinterface,
		const std::wstring& strprofilexml,
		DWORD& dwreasoncode) {
		DWORD dwresult = WlanSetProfile(
			hwlan,
			&guidinterface,
			0,
			strprofilexml.c_str(),
			NULL,
			TRUE,
			NULL,
			&dwreasoncode);
		if(dwresult != ERROR_SUCCESS) {
			PrintError(L"WlanSetProfile", dwresult);
			return false;
		}

		return true;
	}

	bool ConnectWithProfile(
		HANDLE hwlan,
		const GUID& guidinterface,
		const std::wstring& strprofilename) {
		WLAN_CONNECTION_PARAMETERS params = { 0 };
		params.wlanConnectionMode = wlan_connection_mode_profile;
		params.strProfile = strprofilename.c_str();
		params.pDot11Ssid = NULL;
		params.pDesiredBssidList = NULL;
		params.dot11BssType = dot11_BSS_type_infrastructure;
		params.dwFlags = 0;

		DWORD dwresult = WlanConnect(hwlan, &guidinterface, &params, NULL);
		if(dwresult != ERROR_SUCCESS) {
			PrintError(L"WlanConnect", dwresult);
			return false;
		}

		return true;
	}

	bool FindInterfaceForStoredProfile(
		HANDLE hwlan,
		const std::wstring& strprofilename,
		GUID& guidmatchedinterface,
		std::wstring& strmatchedinterface,
		bool& bnetworkvisible) {
		PWLAN_INTERFACE_INFO_LIST piflist = NULL;
		if(EnumerateInterfaces(hwlan, piflist) == false) {
			return false;
		}

		bool bfoundprofile = false;
		bool bfoundvisibleprofile = false;
		bnetworkvisible = false;

		for(unsigned int i = 0; i < piflist->dwNumberOfItems; ++i) {
			const WLAN_INTERFACE_INFO& ifinfo = piflist->InterfaceInfo[i];
			bool bhasprofile = InterfaceHasStoredProfile(hwlan, ifinfo.InterfaceGuid, strprofilename);
			bool bvisible = false;

			if(bhasprofile == false) {
				continue;
			}

			PWLAN_AVAILABLE_NETWORK_LIST pnetworklist = NULL;
			if(QueryAvailableNetworkList(hwlan, ifinfo.InterfaceGuid, pnetworklist) == true
				&& pnetworklist != NULL) {
				for(unsigned int j = 0; j < pnetworklist->dwNumberOfItems; ++j) {
					const WLAN_AVAILABLE_NETWORK& network = pnetworklist->Network[j];
					if(SsidToString(network.dot11Ssid) == strprofilename) {
						bvisible = true;
						break;
					}
				}
			}

			if(pnetworklist != NULL) {
				WlanFreeMemory(pnetworklist);
			}

			if(bfoundprofile == false || (bfoundvisibleprofile == false && bvisible == true)) {
				guidmatchedinterface = ifinfo.InterfaceGuid;
				strmatchedinterface = ifinfo.strInterfaceDescription;
				bfoundprofile = true;
				bfoundvisibleprofile = bvisible;
				bnetworkvisible = bvisible;
			}
		}

		WlanFreeMemory(piflist);
		return bfoundprofile;
	}

	bool SetProfileEapXmlUserData(
		HANDLE hwlan,
		const GUID& guidinterface,
		const std::wstring& strprofilename,
		const std::wstring& streapxmluserdata) {
		DWORD dwresult = WlanSetProfileEapXmlUserData(
			hwlan,
			&guidinterface,
			strprofilename.c_str(),
			0,
			streapxmluserdata.c_str(),
			NULL);
		if(dwresult != ERROR_SUCCESS) {
			PrintError(L"WlanSetProfileEapXmlUserData", dwresult);
			return false;
		}

		return true;
	}

	std::wstring DetectEnterpriseEapMethodFromProfileXml(const std::wstring& strprofilexml) {
		if(strprofilexml.find(L"Type>13</Type>") != std::wstring::npos
			|| strprofilexml.find(L"EapTlsConnectionPropertiesV1") != std::wstring::npos) {
			return L"tls";
		}

		if(strprofilexml.find(L"Type>25</Type>") != std::wstring::npos
			|| strprofilexml.find(L"MsPeapConnectionPropertiesV1") != std::wstring::npos) {
			return L"peap";
		}

		return L"unknown";
	}

	bool QueryCurrentConnection(
		HANDLE hwlan,
		const GUID& guidinterface,
		WLAN_INTERFACE_STATE& state,
		std::wstring& strssid) {
		DWORD dwdatasize = 0;
		PWLAN_CONNECTION_ATTRIBUTES pconn = NULL;
		WLAN_OPCODE_VALUE_TYPE opcodevaluetype = wlan_opcode_value_type_invalid;
		DWORD dwresult = WlanQueryInterface(
			hwlan,
			&guidinterface,
			wlan_intf_opcode_current_connection,
			NULL,
			&dwdatasize,
			reinterpret_cast<PVOID*>(&pconn),
			&opcodevaluetype);
		if(dwresult != ERROR_SUCCESS) {
			return false;
		}

		state = pconn->isState;
		strssid = SsidToString(pconn->wlanAssociationAttributes.dot11Ssid);
		WlanFreeMemory(pconn);
		return true;
	}

	int PollConnectState(
		HANDLE hwlan,
		const GUID& guidinterface,
		const std::wstring& strtargetssid,
		bool benterpriseauth,
		bool bdisableuserpromptforservervalidation,
		const std::wstring& streapmethod) {
		InterlockedExchange(&g_nconnectattemptfailed, 0);
		g_dwlastreasoncode = 0;
		int nauthenticatingcount = 0;
		bool bpromptguidanceprinted = false;

		for(int i = 0; i < 15; ++i) {
			if(InterlockedCompareExchange(&g_nconnectattemptfailed, 0, 0) != 0) {
				std::wcout << L"[INFO] Connection polling stopped after connection_attempt_fail notification.\n";
				if(g_dwlastreasoncode != 0) {
					std::wstring strreason = ReasonCodeToString(g_dwlastreasoncode);
					std::wcout << L"       reason_code : " << g_dwlastreasoncode << L"\n";
					if(strreason.empty() == false) {
						std::wcout << L"       reason_text : " << strreason << L"\n";
					}
				}
				return 1;
			}

			WLAN_INTERFACE_STATE state = wlan_interface_state_not_ready;
			std::wstring strcurrentssid;
			if(QueryCurrentConnection(hwlan, guidinterface, state, strcurrentssid) == true) {
				std::wcout << L"[STATE] " << InterfaceStateToString(state);
				if(strcurrentssid.empty() == false) {
					std::wcout << L" ssid=" << strcurrentssid;
				}
				std::wcout << L"\n";

				if(state == wlan_interface_state_connected && strcurrentssid == strtargetssid) {
					std::wcout << L"[INFO] Target SSID connected successfully.\n";
					return 0;
				}

				if(state == wlan_interface_state_authenticating) {
					++nauthenticatingcount;
				} else {
					nauthenticatingcount = 0;
				}

				if(benterpriseauth == true
					&& nauthenticatingcount >= 5
					&& bpromptguidanceprinted == false) {
					std::wcout << L"[GUIDE] 802.1X authentication is staying in authenticating state.\n";
					if(bdisableuserpromptforservervalidation == false) {
						std::wcout << L"        Windows may be waiting for certificate approval in the MS Wi-Fi panel.\n";
						std::wcout << L"        Open the Windows Wi-Fi list and check whether 'Continue connecting?' is shown for this SSID.\n";
						std::wcout << L"        If certificate confirmation is shown, review the server/CA and press Connect only when expected.\n";
					} else {
						std::wcout << L"        Server certificate validation prompt is disabled by --no-prompt true.\n";
						std::wcout << L"        If server trust/name validation does not match, connection can fail silently.\n";
						std::wcout << L"        Re-run with --no-prompt false or configure --trusted-root-ca and --server-names correctly.\n";
					}
					if(streapmethod == L"tls") {
						std::wcout << L"        EAP-TLS also requires a client certificate with private key in the Windows certificate store.\n";
						std::wcout << L"        Current implementation uses SimpleCertSelection=true for automatic certificate selection.\n";
					}
					bpromptguidanceprinted = true;
				}
			} else {
				std::wcout << L"[STATE] current_connection query failed or not connected yet.\n";
			}

			std::this_thread::sleep_for(std::chrono::seconds(1));
		}

		std::wcout << L"[INFO] Connection polling finished.\n";
		if(benterpriseauth == false) {
			return 1;
		}

		if(streapmethod == L"tls") {
			std::wcout << L"       If a client certificate with private key is not available in the Windows certificate store, connection failure can be expected.\n";
			std::wcout << L"       Current implementation relies on automatic certificate selection(SimpleCertSelection=true).\n";
		} else {
			std::wcout << L"       If 802.1X credential is not configured yet, connection failure can be expected.\n";
		}
		if(bdisableuserpromptforservervalidation == false) {
			std::wcout << L"       If the state stayed at authenticating, check the MS Wi-Fi panel for a certificate approval prompt.\n";
			std::wcout << L"       Accept the prompt only when the certificate issuer/server matches your expected enterprise network.\n";
		} else {
			std::wcout << L"       With --no-prompt true, server certificate mismatch can cause a silent authentication failure.\n";
			std::wcout << L"       Verify trusted Root CA thumbprint and server name settings if connection did not complete.\n";
		}
		return 1;
	}

	int CommandConnect(
		HANDLE hwlan,
		const std::wstring& strssid,
		const std::wstring& strusername,
		const std::wstring& strpassword,
		const std::wstring& strdomain,
		const std::wstring& strservernames,
		const std::wstring& strtrustedrootca,
		bool bdisableuserpromptforservervalidation,
		bool bhidden,
		const std::wstring& strauthoverride,
		const std::wstring& strcipheroverride,
		const std::wstring& streapmethodvalue,
		const std::wstring& strclientcertthumbprintvalue) {
		GUID guidmatchedinterface = { 0 };
		std::wstring strmatchedinterface;
		std::wstring strmatchedauth;
		std::wstring strmatchedcipher;
		std::wstring strprofilexml;
		std::wstring streapxmluserdata;
		std::wstring strnormalizedeapmethod = NormalizeEapMethodValue(streapmethodvalue);
		std::wstring strnormalizedclientcertthumbprint = NormalizeThumbprintValue(strclientcertthumbprintvalue);
		std::wstring strnormalizedauthoverride = NormalizeAuthOverride(strauthoverride);
		std::wstring strnormalizedcipheroverride = NormalizeCipherOverride(strcipheroverride);
		DWORD dwreasoncode = 0;
		bool benterpriseauth = false;
		bool bscanmatched = false;
		bool binteractivefallbackused = false;

		if(strssid.empty() == true) {
			std::wcout << L"[ERROR] connect requires target SSID.\n";
			std::wcout << L"        example: DHConnectWIFI connect --ssid companywifi\n";
			return 1;
		}

		if(streapmethodvalue.empty() == false && strnormalizedeapmethod.empty() == true) {
			std::wcout << L"[ERROR] Unsupported --eap-method value: " << streapmethodvalue << L"\n";
			std::wcout << L"        Supported now: peap, tls\n";
			return 1;
		}

		if(strclientcertthumbprintvalue.empty() == false && strnormalizedclientcertthumbprint.empty() == true) {
			std::wcout << L"[ERROR] Unsupported --client-cert-thumbprint value.\n";
			std::wcout << L"        Use SHA1 hex without spaces. example: 0123456789ABCDEF0123456789ABCDEF01234567\n";
			return 1;
		}

		if(HasNetworkSsid(
			hwlan,
			strssid,
			guidmatchedinterface,
			strmatchedinterface,
			strmatchedauth,
			strmatchedcipher) == true) {
			bscanmatched = true;
		} else {
			if(bhidden == false) {
				std::wcout << L"[INFO] Target SSID not found: " << strssid << L"\n";
				std::wcout << L"       If this is a hidden SSID, retry with --hidden true.\n";
				return 1;
			}

			if(strnormalizedauthoverride.empty() == true || strnormalizedcipheroverride.empty() == true) {
				std::wcout << L"[INFO] Hidden SSID not found in scan.\n";
				std::wcout << L"       Auth/cipher auto-detect is not available. Console security selection will be used.\n";
				if(PromptHiddenSecurityChoice(strnormalizedauthoverride, strnormalizedcipheroverride) == false) {
					std::wcout << L"[INFO] Hidden SSID connect canceled by user.\n";
					return 1;
				}
				binteractivefallbackused = true;
			}

			PWLAN_INTERFACE_INFO_LIST piflist = NULL;
			if(EnumerateInterfaces(hwlan, piflist) == false) {
				return 1;
			}

			if(piflist->dwNumberOfItems == 0) {
				std::wcout << L"[INFO] No wireless interface found.\n";
				WlanFreeMemory(piflist);
				return 1;
			}

			guidmatchedinterface = piflist->InterfaceInfo[0].InterfaceGuid;
			strmatchedinterface = piflist->InterfaceInfo[0].strInterfaceDescription;
			strmatchedauth = strnormalizedauthoverride;
			strmatchedcipher = strnormalizedcipheroverride;
			WlanFreeMemory(piflist);
		}

		if(bscanmatched == true) {
			std::wcout << L"[INFO] Connect skeleton matched target SSID.\n";
		} else if(binteractivefallbackused == true) {
			std::wcout << L"[INFO] Hidden SSID fallback will use console-selected auth/cipher.\n";
		} else {
			std::wcout << L"[INFO] Hidden SSID fallback will use user-provided auth/cipher.\n";
		}
		std::wcout << L"  SSID      : " << strssid << L"\n";
		std::wcout << L"  Interface : " << strmatchedinterface << L"\n";
		std::wcout << L"  Auth      : " << strmatchedauth << L"\n";
		std::wcout << L"  Cipher    : " << strmatchedcipher << L"\n";
		std::wcout << L"  Hidden    : " << (bhidden ? L"true" : L"false") << L"\n";
		if(IsEnterpriseAuth(strmatchedauth) == true) {
			std::wcout << L"  EAPMethod : " << strnormalizedeapmethod << L"\n";
			if(strnormalizedclientcertthumbprint.empty() == false) {
				std::wcout << L"  ClientCert: " << strnormalizedclientcertthumbprint << L"\n";
			}
		}
		std::wcout << L"\n";
		benterpriseauth = IsEnterpriseAuth(strmatchedauth);
		if(benterpriseauth == true) {
			if(strnormalizedeapmethod == L"tls") {
				strprofilexml = BuildEnterpriseTlsProfileXml(
					strssid,
					strmatchedauth,
					strmatchedcipher,
					strservernames,
					strtrustedrootca,
					bdisableuserpromptforservervalidation,
					bhidden);
				std::wcout << L"[INFO] 802.1X WLAN profile XML skeleton prepared for EAP-TLS.\n";
			} else {
				strprofilexml = BuildEnterprisePeapProfileXml(
					strssid,
					strmatchedauth,
					strmatchedcipher,
					strservernames,
					strtrustedrootca,
					bdisableuserpromptforservervalidation,
					bhidden);
				std::wcout << L"[INFO] 802.1X WLAN profile XML skeleton prepared for PEAP/MSCHAPv2.\n";
			}
		} else if(IsPersonalAuth(strmatchedauth) == true) {
			if(strpassword.empty() == true) {
				std::wcout << L"[ERROR] Personal Wi-Fi requires --password.\n";
				std::wcout << L"        example: DHConnectWIFI connect --ssid homewifi --password mywifipassword\n";
				return 1;
			}

			strprofilexml = BuildPersonalProfileXml(
				strssid,
				strmatchedauth,
				strmatchedcipher,
				strpassword,
				bhidden);
			std::wcout << L"[INFO] Personal WLAN profile XML prepared.\n";
		} else if(IsOpenAuth(strmatchedauth, strmatchedcipher) == true) {
			strprofilexml = BuildOpenProfileXml(strssid, bhidden);
			std::wcout << L"[INFO] Open WLAN profile XML prepared.\n";
		} else {
			std::wcout << L"[INFO] Target SSID auth/cipher is not supported yet by connect command.\n";
			std::wcout << L"       Supported now: open, WPA-PSK, WPA2/WPA3-Personal, WPA-Enterprise, WPA2/WPA3-Enterprise.\n";
			return 1;
		}

		std::wcout << L"------- PROFILE XML BEGIN -------\n";
		std::wcout << strprofilexml;
		std::wcout << L"------- PROFILE XML END   -------\n";
		if(SetProfileXml(hwlan, guidmatchedinterface, strprofilexml, dwreasoncode) == false) {
			std::wcout << L"[INFO] Profile registration failed.\n";
			if(dwreasoncode != 0) {
				std::wcout << L"  ReasonCode : " << dwreasoncode << L"\n";
			}
			return 1;
		}

		std::wcout << L"[INFO] WLAN profile registered successfully.\n";
		std::wcout << L"  ProfileName: " << strssid << L"\n";
		if(benterpriseauth == true && strservernames.empty() == false) {
			std::wcout << L"  ServerName : " << strservernames << L"\n";
		}
		if(benterpriseauth == true && strtrustedrootca.empty() == false) {
			std::wcout << L"  TrustedCA  : " << strtrustedrootca << L"\n";
		}
		if(benterpriseauth == true) {
			std::wcout << L"  NoPrompt   : " << (bdisableuserpromptforservervalidation ? L"true" : L"false") << L"\n";
		}

		if(benterpriseauth == true && strnormalizedeapmethod == L"peap"
			&& (strusername.empty() == false || strpassword.empty() == false)) {
			if(strusername.empty() == true || strpassword.empty() == true) {
				std::wcout << L"[WARNING] username/password must both be provided for PEAP credential apply.\n";
			} else {
				streapxmluserdata = BuildPeapUserCredentialXml(strusername, strpassword, strdomain);
				PrintDebugXmlBlock(L"EAP USER XML", streapxmluserdata);
				if(SetProfileEapXmlUserData(hwlan, guidmatchedinterface, strssid, streapxmluserdata) == true) {
					std::wcout << L"[INFO] PEAP user credential XML applied to profile.\n";
					std::wcout << L"  Username   : " << strusername << L"\n";
					if(strdomain.empty() == false) {
						std::wcout << L"  Domain     : " << strdomain << L"\n";
					}
				} else {
					std::wcout << L"[WARNING] PEAP credential apply failed. Connection may stay at authenticating.\n";
				}
			}
		} else if(benterpriseauth == true && strnormalizedeapmethod == L"peap") {
			std::wcout << L"[INFO] No PEAP credential provided. Profile only mode will be tested.\n";
		} else if(benterpriseauth == true) {
			if(strnormalizedclientcertthumbprint.empty() == false) {
				streapxmluserdata = BuildTlsUserCertificateCredentialXml(strnormalizedclientcertthumbprint);
				PrintDebugXmlBlock(L"EAP USER XML", streapxmluserdata);
				if(SetProfileEapXmlUserData(hwlan, guidmatchedinterface, strssid, streapxmluserdata) == true) {
					std::wcout << L"[INFO] EAP-TLS client certificate thumbprint applied to profile.\n";
					std::wcout << L"  Thumbprint : " << strnormalizedclientcertthumbprint << L"\n";
				} else {
					std::wcout << L"[WARNING] EAP-TLS client certificate thumbprint apply failed. Windows may fall back to certificate chooser.\n";
				}
			}
			if(strusername.empty() == false || strpassword.empty() == false || strdomain.empty() == false) {
				std::wcout << L"[INFO] --username/--password/--domain are ignored for EAP-TLS.\n";
			}
			if(strnormalizedclientcertthumbprint.empty() == false) {
				std::wcout << L"[INFO] EAP-TLS will request the specified client certificate from Windows certificate store.\n";
			} else {
				std::wcout << L"[INFO] EAP-TLS will rely on a client certificate already installed in the Windows certificate store.\n";
				std::wcout << L"       Current profile uses automatic certificate selection(SimpleCertSelection=true).\n";
			}
		} else if(IsPersonalAuth(strmatchedauth) == true) {
			std::wcout << L"[INFO] Personal Wi-Fi password embedded into profile XML.\n";
		} else {
			std::wcout << L"[INFO] Open Wi-Fi profile does not require password.\n";
		}

		if(ConnectWithProfile(hwlan, guidmatchedinterface, strssid) == false) {
			return 1;
		}

		std::wcout << L"[INFO] WlanConnect requested with profile mode.\n";
		return PollConnectState(
			hwlan,
			guidmatchedinterface,
			strssid,
			benterpriseauth,
			bdisableuserpromptforservervalidation,
			strnormalizedeapmethod);
	}

	int CommandDeleteProfile(HANDLE hwlan, const std::wstring& strssid) {
		PWLAN_INTERFACE_INFO_LIST piflist = NULL;
		bool bdeleted = false;

		if(strssid.empty() == true) {
			std::wcout << L"[ERROR] delete-profile requires target SSID.\n";
			std::wcout << L"        example: DHConnectWIFI delete-profile --ssid companywifi\n";
			return 1;
		}

		if(EnumerateInterfaces(hwlan, piflist) == false) {
			return 1;
		}

		for(unsigned int i = 0; i < piflist->dwNumberOfItems; ++i) {
			const WLAN_INTERFACE_INFO& ifinfo = piflist->InterfaceInfo[i];
			if(InterfaceHasStoredProfile(hwlan, ifinfo.InterfaceGuid, strssid) == false) {
				continue;
			}

			DWORD dwresult = WlanDeleteProfile(hwlan, &ifinfo.InterfaceGuid, strssid.c_str(), NULL);
			if(dwresult != ERROR_SUCCESS) {
				PrintError(L"WlanDeleteProfile", dwresult);
				continue;
			}

			std::wcout << L"[INFO] WLAN profile deleted.\n";
			std::wcout << L"  ProfileName: " << strssid << L"\n";
			std::wcout << L"  Interface  : " << ifinfo.strInterfaceDescription << L"\n";
			bdeleted = true;
		}

		WlanFreeMemory(piflist);
		if(bdeleted == false) {
			std::wcout << L"[INFO] Stored WLAN profile not found: " << strssid << L"\n";
			return 1;
		}

		return 0;
	}

	int CommandConnectProfile(HANDLE hwlan, const std::wstring& strssid) {
		GUID guidmatchedinterface = { 0 };
		std::wstring strmatchedinterface;
		std::wstring strprofilexml;
		bool bnetworkvisible = false;
		bool benterpriseauth = false;

		if(strssid.empty() == true) {
			std::wcout << L"[ERROR] connect-profile requires target SSID.\n";
			std::wcout << L"        example: DHConnectWIFI connect-profile --ssid companywifi\n";
			return 1;
		}

		if(FindInterfaceForStoredProfile(
			hwlan,
			strssid,
			guidmatchedinterface,
			strmatchedinterface,
			bnetworkvisible) == false) {
			std::wcout << L"[INFO] Stored WLAN profile not found: " << strssid << L"\n";
			return 1;
		}

		if(QueryStoredProfileXml(hwlan, guidmatchedinterface, strssid, strprofilexml) == false) {
			return 1;
		}

		benterpriseauth = IsEnterpriseProfileXml(strprofilexml);

		std::wcout << L"[INFO] Stored WLAN profile matched.\n";
		std::wcout << L"  ProfileName: " << strssid << L"\n";
		std::wcout << L"  Interface  : " << strmatchedinterface << L"\n";
		std::wcout << L"  VisibleNow : " << (bnetworkvisible ? L"yes" : L"no") << L"\n";
		std::wcout << L"  Enterprise : " << (benterpriseauth ? L"yes" : L"no") << L"\n";

		if(ConnectWithProfile(hwlan, guidmatchedinterface, strssid) == false) {
			return 1;
		}

		std::wcout << L"[INFO] WlanConnect requested with stored profile mode.\n";
		std::wstring streapmethod = DetectEnterpriseEapMethodFromProfileXml(strprofilexml);
		if(benterpriseauth == true) {
			std::wcout << L"  EAPMethod  : " << streapmethod << L"\n";
		}

		return PollConnectState(hwlan, guidmatchedinterface, strssid, benterpriseauth, false, streapmethod);
	}

	void PrintMenu() {
		std::wcout << L"\n";
		std::wcout << L"DHConnectWIFI\n";
		std::wcout << L"1. wifi list\n";
		std::wcout << L"2. wifi scan\n";
		std::wcout << L"3. connect\n";
		std::wcout << L"4. exit\n";
		std::wcout << L"\n";
		std::wcout << L"Select> ";
	}

	int RunInteractiveMenu(HANDLE hwlan) {
		for(;;) {
			int nmenu = 0;
			std::wstring strssid;

			PrintMenu();
			if((std::wcin >> nmenu).fail()) {
				std::wcin.clear();
				std::wcin.ignore(4096, L'\n');
				std::wcout << L"[ERROR] Invalid menu input.\n";
				continue;
			}

			std::wcin.ignore(4096, L'\n');

			switch(nmenu) {
			case 1:
				CommandListInterface(hwlan);
				break;
			case 2:
				CommandScan(hwlan, L"", false);
				break;
			case 3:
				std::wcout << L"SSID> ";
				std::getline(std::wcin, strssid);
				CommandConnect(hwlan, strssid, L"", L"", L"", L"", L"", false, false, L"", L"", L"", L"");
				break;
			case 4:
				return 0;
			default:
				std::wcout << L"[ERROR] Unsupported menu number.\n";
				break;
			}
		}
	}

	}

int wmain(int argc, wchar_t* argv[]) {
	std::vector<std::wstring> args;
	HANDLE hwlan = NULL;
	DWORD dwnegotiatedversion = 0;
	int nresult = 0;

	for(int i = 1; i < argc; ++i) {
		args.push_back(argv[i]);
	}

	if(args.empty() == true) {
		PrintUsage();
		return 0;
	}

	if(OpenWlanHandle(hwlan, dwnegotiatedversion) == false) {
		return 1;
	}

	if(args[0] == L"list-iface") {
		nresult = CommandListInterface(hwlan);
	} else if(args[0] == L"scan") {
		nresult = CommandScan(
			hwlan,
			GetArgValue(args, L"--ssid"),
			GetArgBoolValue(args, L"--show-bssid", false));
	} else if(args[0] == L"delete-profile") {
		nresult = CommandDeleteProfile(hwlan, GetArgValue(args, L"--ssid"));
	} else if(args[0] == L"connect-profile") {
		nresult = CommandConnectProfile(hwlan, GetArgValue(args, L"--ssid"));
	} else if(args[0] == L"connect") {
		nresult = CommandConnect(
			hwlan,
			GetArgValue(args, L"--ssid"),
			GetArgValue(args, L"--username"),
			GetArgValue(args, L"--password"),
			GetArgValue(args, L"--domain"),
			GetArgValue(args, L"--server-names"),
			GetArgValue(args, L"--trusted-root-ca"),
			GetArgBoolValue(args, L"--no-prompt", false),
			GetArgBoolValue(args, L"--hidden", false),
			GetArgValue(args, L"--auth"),
			GetArgValue(args, L"--cipher"),
			GetArgValue(args, L"--eap-method"),
			GetArgValue(args, L"--client-cert-thumbprint"));
	} else if(args[0] == L"menu") {
		nresult = RunInteractiveMenu(hwlan);
	} else {
		PrintUsage();
		nresult = 1;
	}

	if(hwlan != NULL) {
		WlanCloseHandle(hwlan, NULL);
		hwlan = NULL;
	}

	return nresult;
}
