
rule Trojan_Win64_Zusy_PGK_MTB{
	meta:
		description = "Trojan:Win64/Zusy.PGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 6a 67 61 6a 64 6a 72 67 2e 65 78 65 } //5 tjgajdjrg.exe
		$a_03_1 = {68 74 74 70 [0-01] 3a 2f 2f [0-30] 2f [0-20] 5f [0-20] 2e 65 78 65 } //10
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*10) >=15
 
}