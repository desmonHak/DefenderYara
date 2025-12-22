
rule Trojan_Win32_VidarStealer_Z_MTB{
	meta:
		description = "Trojan:Win32/VidarStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {63 6d 64 20 2f 63 20 73 74 61 72 74 [0-10] 72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //1
		$a_02_1 = {70 6f 77 65 72 73 68 65 6c 6c [0-3c] 73 74 61 72 74 2d 70 72 6f 63 65 73 73 } //1
		$a_01_2 = {2f 63 20 70 69 6e 67 20 6c 6f 63 61 6c 68 6f 73 74 20 2d 6e } //1 /c ping localhost -n
		$a_01_3 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 encrypted_key
		$a_01_4 = {42 72 6f 77 73 65 72 20 53 74 65 61 6c 65 72 } //1 Browser Stealer
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_VidarStealer_Z_MTB_2{
	meta:
		description = "Trojan:Win32/VidarStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 61 64 69 6e 67 20 70 61 79 6c 6f 61 64 3a 20 74 79 70 65 3d 25 73 } //1 Loading payload: type=%s
		$a_01_1 = {49 6e 6a 65 63 74 69 6f 6e 20 6d 6f 64 65 20 73 65 6c 65 63 74 65 64 3a 20 25 73 } //1 Injection mode selected: %s
		$a_01_2 = {54 65 6c 65 67 72 61 6d 20 44 65 73 6b 74 6f 70 } //1 Telegram Desktop
		$a_01_3 = {6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //1 logins.json
		$a_01_4 = {50 61 79 6c 6f 61 64 20 4c 6f 61 64 65 72 } //1 Payload Loader
		$a_01_5 = {43 72 79 70 74 6f 20 52 65 61 64 65 72 } //1 Crypto Reader
		$a_01_6 = {4d 6f 6e 65 72 6f } //1 Monero
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule Trojan_Win32_VidarStealer_Z_MTB_3{
	meta:
		description = "Trojan:Win32/VidarStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {74 65 6c 65 67 72 61 6d 5f 66 69 6c 65 73 } //1 telegram_files
		$a_01_1 = {73 74 65 61 6d 5f 66 69 6c 65 73 } //1 steam_files
		$a_01_2 = {64 69 73 63 6f 72 64 5f 66 69 6c 65 73 } //1 discord_files
		$a_01_3 = {5c 4e 65 74 77 6f 72 6b 5c 43 6f 6f 6b 69 65 73 } //1 \Network\Cookies
		$a_01_4 = {5f 6b 65 79 2e 74 78 74 } //1 _key.txt
		$a_01_5 = {2a 2e 61 64 64 72 65 73 73 2e 74 78 74 } //1 *.address.txt
		$a_01_6 = {70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //1 passwords.txt
		$a_01_7 = {53 63 72 65 65 6e 73 68 6f 74 } //1 Screenshot
		$a_01_8 = {57 61 6c 6c 65 74 73 } //1 Wallets
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}
rule Trojan_Win32_VidarStealer_Z_MTB_4{
	meta:
		description = "Trojan:Win32/VidarStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {66 6f 72 6d 68 69 73 74 6f 72 79 2e } //1 formhistory.
		$a_01_1 = {63 6f 6f 6b 69 65 73 2e 73 71 6c 69 74 65 } //1 cookies.sqlite
		$a_01_2 = {70 6c 61 63 65 73 2e 73 71 6c 69 74 65 } //1 places.sqlite
		$a_01_3 = {5c 49 6e 64 65 78 65 64 44 42 5c 63 68 72 6f 6d 65 2d 65 78 74 65 6e 73 69 6f 6e } //1 \IndexedDB\chrome-extension
		$a_01_4 = {4c 6f 67 69 6e 20 44 61 74 61 } //1 Login Data
		$a_01_5 = {41 6c 6c 20 69 6e 6a 65 63 74 69 6f 6e 20 61 74 74 65 6d 70 74 73 20 46 41 49 4c 45 44 20 66 6f 72 20 61 74 74 65 6d 70 74 20 25 64 } //1 All injection attempts FAILED for attempt %d
		$a_01_6 = {70 61 73 73 77 6f 72 64 73 2e 64 62 } //1 passwords.db
		$a_01_7 = {77 65 62 64 61 74 61 2e 64 62 } //1 webdata.db
		$a_01_8 = {53 68 65 6c 6c 63 6f 64 65 } //1 Shellcode
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}