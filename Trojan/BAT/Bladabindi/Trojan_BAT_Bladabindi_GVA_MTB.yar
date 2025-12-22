
rule Trojan_BAT_Bladabindi_GVA_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 28 0d 00 00 0a 2d 14 28 15 00 00 06 2c 06 28 0d 00 00 06 2a 09 28 12 00 00 06 2a 03 25 2d 07 26 16 8d 02 00 00 01 28 05 00 00 06 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}