
rule Trojan_Win64_Stelega_GVB_MTB{
	meta:
		description = "Trojan:Win64/Stelega.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b d1 48 8d 44 10 10 0f b6 00 33 45 bc 0f b6 c0 89 45 ac 48 8b 45 d8 8b 4d c8 3b 48 08 72 05 } //2
		$a_01_1 = {8b d0 48 8d 4c 11 10 0f b6 01 48 8b 4d b8 30 01 90 8b 45 e0 ff c0 89 45 e0 33 c9 83 7d e0 10 0f 9c c1 89 4d cc 83 7d cc 00 0f 85 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}