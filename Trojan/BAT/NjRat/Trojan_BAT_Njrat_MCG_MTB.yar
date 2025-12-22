
rule Trojan_BAT_Njrat_MCG_MTB{
	meta:
		description = "Trojan:BAT/Njrat.MCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 31 65 33 2d 33 66 39 34 65 37 31 36 39 38 35 66 } //2 b1e3-3f94e716985f
		$a_01_1 = {4e 4a 52 41 54 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 NJRAT.Resources.resource
		$a_01_2 = {53 62 6b 62 68 58 6c 4e 56 65 4e 43 } //1 SbkbhXlNVeNC
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}