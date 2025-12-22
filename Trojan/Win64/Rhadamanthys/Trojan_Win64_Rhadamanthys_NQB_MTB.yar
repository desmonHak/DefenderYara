
rule Trojan_Win64_Rhadamanthys_NQB_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f db c2 66 0f fc c1 66 0f ef c9 66 0f 6f d9 66 0f f8 d8 } //1
		$a_01_1 = {66 0f db c2 66 0f fc c3 66 0f f8 c8 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}