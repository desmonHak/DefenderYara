
rule Trojan_Win64_Latrodectus_CH_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 08 00 00 "
		
	strings :
		$a_01_0 = {48 31 d2 66 } //5
		$a_01_1 = {49 f7 f1 66 } //5
		$a_01_2 = {49 f7 f0 66 } //5
		$a_01_3 = {45 8a 14 10 66 } //5
		$a_01_4 = {45 8a 14 11 66 } //5
		$a_01_5 = {44 30 14 0f 66 } //5
		$a_01_6 = {48 ff c1 66 } //5
		$a_01_7 = {48 89 c8 66 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5) >=30
 
}