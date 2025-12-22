
rule Trojan_Win64_StealC_GVF_MTB{
	meta:
		description = "Trojan:Win64/StealC.GVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 bc 34 7b 02 00 00 0f b6 94 14 6b 02 00 00 31 fa 88 14 30 48 8d 4e 01 48 83 f9 1d 7d 1d 48 89 ca 48 83 e1 f0 48 89 d6 48 29 ca 48 83 fa 10 72 ce } //2
		$a_01_1 = {0f b6 7c 34 29 0f b6 54 14 19 31 d7 40 88 3c 30 48 8d 4e 01 48 83 f9 17 7d 15 48 89 ca 48 83 e1 f0 48 89 d6 48 29 ca 48 83 fa 10 72 d3 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}