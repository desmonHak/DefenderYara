
rule Trojan_Win64_Dapato_NA_MTB{
	meta:
		description = "Trojan:Win64/Dapato.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 63 25 8f cd 0f 00 41 8d 4c 24 01 48 63 c9 48 c1 e1 03 e8 56 93 01 00 49 89 c5 48 85 c0 74 57 } //2
		$a_01_1 = {e8 73 92 01 00 4c 8b 05 5c cf 0f 00 8b 0d 66 cf 0f 00 4c 89 00 48 8b 15 54 cf 0f 00 e8 f7 ba 0c 00 8b 0d 39 cf 0f 00 85 c9 0f 84 fb 02 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}