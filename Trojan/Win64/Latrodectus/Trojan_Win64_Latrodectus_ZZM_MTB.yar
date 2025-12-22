
rule Trojan_Win64_Latrodectus_ZZM_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.ZZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 0f 6f cb 66 0f fd c2 49 f7 f3 66 0f 6c d7 66 0f 6f d1 } //3
		$a_01_1 = {66 0f 6c ca 66 0f 6f c1 66 0f 6c ca 66 0f fd c1 45 8a 14 11 66 0f 6f cb } //4
		$a_01_2 = {66 0f 38 30 c1 66 0f 6c d3 44 30 14 0f 66 0f 6f c1 66 0f 6c d7 } //5
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*4+(#a_01_2  & 1)*5) >=12
 
}