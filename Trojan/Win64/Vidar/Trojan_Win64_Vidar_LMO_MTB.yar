
rule Trojan_Win64_Vidar_LMO_MTB{
	meta:
		description = "Trojan:Win64/Vidar.LMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {5f a9 90 8c 99 9a 86 01 41 e9 f1 ab a3 5e } //10
		$a_01_1 = {0c 0f 57 c0 14 53 7e 08 37 89 0b } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}