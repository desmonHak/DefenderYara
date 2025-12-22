
rule Trojan_Win64_KeyLogger_A_AMTB{
	meta:
		description = "Trojan:Win64/KeyLogger.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 36 34 } //1 GetTickCount64
		$a_01_1 = {43 41 4c 43 55 4c 41 54 49 4f 4e 5f 46 4f 52 4d 55 4c 41 5f 44 4c 4c 2e 64 6c 6c } //1 CALCULATION_FORMULA_DLL.dll
		$a_01_2 = {50 72 6f 6a 65 63 74 5c 4b 45 59 42 4f 41 52 44 5f 4d 4f 4e 49 54 4f 52 5f 44 4c 4c } //2 Project\KEYBOARD_MONITOR_DLL
		$a_00_3 = {59 6f 75 20 61 72 65 20 6e 6f 74 20 61 75 74 68 6f 72 69 7a 65 64 20 74 6f 20 75 73 65 20 74 68 69 73 20 6d 6f 64 75 6c 65 } //1 You are not authorized to use this module
		$a_01_4 = {69 74 75 65 67 71 72 } //1 ituegqr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}