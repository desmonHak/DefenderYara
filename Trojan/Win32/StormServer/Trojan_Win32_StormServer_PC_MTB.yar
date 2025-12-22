
rule Trojan_Win32_StormServer_PC_MTB{
	meta:
		description = "Trojan:Win32/StormServer.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 74 6f 72 6d 53 65 72 76 65 72 2e 64 6c 6c } //1 StormServer.dll
		$a_81_1 = {57 65 6c 63 6f 6d 65 20 74 6f 20 75 73 65 20 73 74 6f 72 6d 20 64 64 6f 73 } //1 Welcome to use storm ddos
		$a_81_2 = {7b 25 30 38 58 2d 25 30 34 58 2d 25 30 34 78 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 7d } //1 {%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}
		$a_81_3 = {20 2f 63 20 20 64 65 6c 20 } //1  /c  del 
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}