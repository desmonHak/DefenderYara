
rule TrojanSpy_Win64_PrysmaxStealer_A_AMTB{
	meta:
		description = "TrojanSpy:Win64/PrysmaxStealer.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {49 6e 73 74 61 6c 6c 65 64 20 41 6e 74 69 76 69 72 75 73 } //1 Installed Antivirus
		$a_81_1 = {43 6f 6f 6b 69 65 73 20 46 6f 75 6e 64 } //1 Cookies Found
		$a_81_2 = {50 61 73 73 77 6f 72 64 73 20 46 6f 75 6e 64 } //1 Passwords Found
		$a_81_3 = {43 72 65 64 69 74 20 43 61 72 64 73 20 46 6f 75 6e 64 } //1 Credit Cards Found
		$a_81_4 = {42 6f 6f 6b 6d 61 72 6b 73 20 46 6f 75 6e 64 } //1 Bookmarks Found
		$a_81_5 = {54 65 6c 65 67 72 61 6d 20 53 65 73 73 69 6f 6e } //1 Telegram Session
		$a_81_6 = {43 6c 69 70 62 6f 61 72 64 } //1 Clipboard
		$a_81_7 = {48 69 73 74 6f 72 79 20 49 74 65 6d 73 } //1 History Items
		$a_81_8 = {44 69 73 63 6f 72 64 20 54 6f 6b 65 6e 73 } //1 Discord Tokens
		$a_81_9 = {41 70 70 20 43 72 65 64 65 6e 74 69 61 6c 73 } //1 App Credentials
		$a_03_10 = {50 72 79 73 6d 61 78 [0-05] 43 6f 6f 6b 69 65 73 } //2
		$a_81_11 = {74 61 73 6b 6b 69 6c 6c 2f 46 2f 49 4d } //1 taskkill/F/IM
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_03_10  & 1)*2+(#a_81_11  & 1)*1) >=12
 
}