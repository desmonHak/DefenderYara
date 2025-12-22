
rule Trojan_Win64_Rhadamanthys_AMB_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.AMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f ba f2 1f 33 d0 8b c2 24 01 f6 d8 1b c9 d1 ea 81 e1 ?? ?? ?? ?? 42 33 8c 84 ?? ?? ?? ?? 33 ca 42 89 4c 84 34 49 ff c0 } //5
		$a_02_1 = {68 00 74 74 70 00 3a 00 2f 00 2f 00 31 00 37 00 36 00 2e 00 34 00 36 00 2e 00 31 00 35 00 32 00 2e 00 36 00 32 00 3a 00 35 00 38 00 35 00 38 00 2f 00 [0-0a] 2e 00 65 00 78 00 65 00 } //5
		$a_02_2 = {68 74 74 70 3a 2f 2f 31 37 36 2e 34 36 2e 31 35 32 2e 36 32 3a 35 38 35 38 2f [0-0a] 2e 65 78 65 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_02_1  & 1)*5+(#a_02_2  & 1)*5) >=10
 
}