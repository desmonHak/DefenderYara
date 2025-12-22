
rule Trojan_BAT_Amadey_CC_MTB{
	meta:
		description = "Trojan:BAT/Amadey.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b de 0a 06 2c 06 06 6f ?? 00 00 0a dc 07 2a } //1
		$a_03_1 = {13 38 12 38 73 ?? 00 00 0a 13 } //3
		$a_03_2 = {d2 28 54 00 00 0a 26 11 ?? 28 62 00 00 0a 28 66 00 00 0a 13 } //3
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*3+(#a_03_2  & 1)*3) >=7
 
}