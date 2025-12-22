
rule Trojan_Win32_GuLoader_RCK_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {63 6f 75 70 62 63 65 72 6e 65 } //1 coupbcerne
		$a_81_1 = {73 79 67 65 70 6c 65 6a 65 73 6b 6f 6c 65 6e 73 20 73 74 61 70 68 79 6c 6f 70 6c 61 73 74 69 63 20 6b 61 66 66 65 62 6f 72 64 73 } //1 sygeplejeskolens staphyloplastic kaffebords
		$a_81_2 = {72 65 67 69 73 74 72 65 72 69 6e 67 73 61 66 67 69 66 74 65 6e 73 20 78 79 6c 69 64 69 6e 65 2e 65 78 65 } //1 registreringsafgiftens xylidine.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}