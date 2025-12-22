
rule Trojan_Win32_Glupteba_ARR_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 3c 1e 85 d2 74 ?? 89 f0 89 d3 99 f7 fb 39 d3 77 } //10
		$a_03_1 = {8b 4c 24 44 29 d1 29 d5 87 dd f7 db 87 dd c1 fd ?? 21 ea 01 da } //7
		$a_03_2 = {89 f8 0f b6 3c 0a 31 f8 8b bc 24 ?? ?? ?? ?? 88 04 37 46 } //3
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*7+(#a_03_2  & 1)*3) >=20
 
}