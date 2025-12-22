
rule Trojan_BAT_XWorm_SLPA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SLPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 25 00 00 70 0a 17 13 06 28 2c 00 00 0a 06 28 2d 00 00 0a 6f 2e 00 00 0a 0a 11 06 17 d6 13 06 11 06 18 31 e4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}