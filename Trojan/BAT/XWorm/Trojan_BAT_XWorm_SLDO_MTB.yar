
rule Trojan_BAT_XWorm_SLDO_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SLDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 41 00 00 70 72 8b 00 00 70 6f 33 00 00 0a 72 8f 00 00 70 72 cd 00 00 70 6f 33 00 00 0a 72 d1 00 00 70 72 07 01 00 70 6f 33 00 00 0a 0d 09 28 34 00 00 0a 13 04 28 35 00 00 0a 11 04 6f 36 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}