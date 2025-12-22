
rule Trojan_Win32_Darkcomet_MCF_MTB{
	meta:
		description = "Trojan:Win32/Darkcomet.MCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d8 48 40 00 d4 11 40 00 10 f2 70 00 00 ff ff ff 08 00 00 00 01 00 00 00 0c 00 00 00 e9 00 00 00 7c 33 40 00 08 11 40 00 c4 10 40 00 78 00 00 00 7e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Darkcomet_MCF_MTB_2{
	meta:
		description = "Trojan:Win32/Darkcomet.MCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 26 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 8c 23 40 00 8c 23 40 00 e0 19 40 00 78 00 00 00 81 00 00 00 8e } //2
		$a_01_1 = {30 34 31 38 32 30 30 32 00 54 65 6d 70 30 34 31 38 32 30 30 32 00 00 4e 65 74 7a 61 6e 79 } //1 㐰㠱〲㈰吀浥ばㄴ㈸〰2一瑥慺祮
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}