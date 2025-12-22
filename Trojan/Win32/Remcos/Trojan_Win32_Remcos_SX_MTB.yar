
rule Trojan_Win32_Remcos_SX_MTB{
	meta:
		description = "Trojan:Win32/Remcos.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 04 00 00 "
		
	strings :
		$a_01_0 = {99 f7 f9 8b 4d 0c 33 c0 8a 04 0a 8b 0f 03 c6 03 c1 } //10
		$a_03_1 = {8b ce 8d 73 01 8b d1 6a ?? c1 e9 ?? f3 a5 8b ca 83 e1 ?? f3 a4 } //8
		$a_01_2 = {00 ff d6 4f 75 db } //5
		$a_01_3 = {53 65 74 50 72 6f 63 65 73 73 44 45 50 50 6f 6c 69 63 79 } //2 SetProcessDEPPolicy
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*8+(#a_01_2  & 1)*5+(#a_01_3  & 1)*2) >=25
 
}