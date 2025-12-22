
rule Trojan_Win32_VidarStealer_ZA_MTB{
	meta:
		description = "Trojan:Win32/VidarStealer.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 09 00 00 "
		
	strings :
		$a_81_0 = {46 69 6c 65 20 47 72 61 62 62 65 72 20 52 75 6c 65 73 } //5 File Grabber Rules
		$a_81_1 = {4c 6f 61 64 65 72 20 54 61 73 6b 73 } //5 Loader Tasks
		$a_81_2 = {48 6f 73 74 4e 61 6d 65 } //1 HostName
		$a_81_3 = {55 73 65 72 4e 61 6d 65 } //1 UserName
		$a_81_4 = {50 61 73 73 77 6f 72 64 } //1 Password
		$a_81_5 = {50 6f 72 74 4e 75 6d 62 65 72 } //1 PortNumber
		$a_81_6 = {68 74 74 70 73 3a 2f 2f 73 74 65 61 6d 63 6f 6d 6d 75 6e 69 74 79 2e 63 6f 6d 2f 70 72 6f 66 69 6c 65 73 } //5 https://steamcommunity.com/profiles
		$a_81_7 = {68 74 74 70 73 3a 2f 2f 74 65 6c 65 67 72 61 6d 2e 6d 65 } //5 https://telegram.me
		$a_81_8 = {5c 49 6e 64 65 78 65 64 44 42 5c 63 68 72 6f 6d 65 2d 65 78 74 65 6e 73 69 6f 6e 5f } //5 \IndexedDB\chrome-extension_
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*5+(#a_81_7  & 1)*5+(#a_81_8  & 1)*5) >=29
 
}