
rule Trojan_Win32_SchExec_HL_MTB{
	meta:
		description = "Trojan:Win32/SchExec.HL!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,38 00 38 00 03 00 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 2e 00 65 00 78 00 65 00 20 00 61 00 64 00 64 00 20 00 } //1 reg.exe add 
		$a_00_1 = {43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 20 00 2f 00 76 00 } //5 CurrentVersion\Run /v
		$a_02_2 = {2f 00 64 00 20 00 63 00 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 [0-20] 2e 00 6c 00 6e 00 6b 00 20 00 2f 00 66 00 } //50
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*5+(#a_02_2  & 1)*50) >=56
 
}