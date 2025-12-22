
rule Trojan_BAT_Jalapeno_LMA_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 b4 00 00 70 28 08 00 00 0a 26 de 03 26 de 00 2a } //10
		$a_01_1 = {72 01 00 00 70 72 b0 00 00 70 02 7b 02 00 00 04 28 06 00 00 0a 28 07 00 00 0a 26 de 03 26 de 00 2a } //20
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20) >=30
 
}
rule Trojan_BAT_Jalapeno_LMA_MTB_2{
	meta:
		description = "Trojan:BAT/Jalapeno.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 00 28 0c 00 00 0a 28 0d 00 00 0a 8c 11 00 00 01 72 ?? 00 00 70 28 0e 00 00 0a 28 0f 00 00 0a 0a 06 73 10 00 00 0a 0b 07 72 ?? 00 00 70 28 11 00 00 0a 73 12 00 00 0a 72 ?? 00 00 70 6f 13 00 } //20
		$a_03_1 = {de 2c 13 04 72 ?? 00 00 70 73 10 00 00 0a 13 05 11 05 11 04 6f 22 00 00 0a 6f 14 00 00 0a de 0c } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}