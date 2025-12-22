
rule Trojan_BAT_XWorm_SLGF_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SLGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 8d 04 00 00 01 28 03 00 00 0a 26 de 14 26 7e 01 00 00 04 28 02 00 00 06 0a 06 28 04 00 00 06 de 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}