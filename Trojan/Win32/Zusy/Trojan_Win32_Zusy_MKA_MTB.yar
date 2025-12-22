
rule Trojan_Win32_Zusy_MKA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 44 35 2a 5f 4b 78 8b 4c 24 40 89 44 24 18 89 c8 } //10
		$a_01_1 = {89 4c 24 34 88 c1 89 fe 0f a5 de 88 c1 d3 e3 b9 53 98 d5 78 } //10
		$a_01_2 = {83 c2 20 66 89 d3 0f b7 d7 83 ea 1a 66 0f 42 f3 0f b7 fe } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}