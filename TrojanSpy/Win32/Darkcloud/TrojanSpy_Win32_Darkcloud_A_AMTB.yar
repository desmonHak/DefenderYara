
rule TrojanSpy_Win32_Darkcloud_A_AMTB{
	meta:
		description = "TrojanSpy:Win32/Darkcloud.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_81_0 = {53 63 72 65 65 6e 43 61 70 74 75 72 65 } //1 ScreenCapture
		$a_81_1 = {47 65 74 4b 65 79 62 6f 61 72 64 44 61 74 61 } //1 GetKeyboardData
		$a_81_2 = {63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 } //1 card_number_encrypted
		$a_81_3 = {5c 53 63 72 65 65 6e 73 68 6f 74 5f } //1 \Screenshot_
		$a_81_4 = {43 6f 6f 6b 69 65 73 } //1 Cookies
		$a_81_5 = {43 6f 6e 74 61 63 74 73 } //1 Contacts
		$a_81_6 = {5c 4b 65 79 44 61 74 61 5f } //1 \KeyData_
		$a_81_7 = {5c 4c 6f 67 69 6e 44 61 74 61 } //1 \LoginData
		$a_81_8 = {5c 57 65 62 44 61 74 61 } //1 \WebData
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=8
 
}