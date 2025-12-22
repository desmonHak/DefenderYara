
rule Trojan_Win64_Latrodectus_CG_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 07 00 00 "
		
	strings :
		$a_01_0 = {48 31 d2 66 } //5
		$a_01_1 = {49 f7 f3 66 } //5
		$a_01_2 = {45 8a 14 11 66 } //5
		$a_01_3 = {44 30 14 0f 66 } //5
		$a_01_4 = {48 ff c1 66 } //5
		$a_01_5 = {48 89 c8 66 } //5
		$a_01_6 = {48 81 f9 01 92 01 00 0f 86 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5) >=35
 
}