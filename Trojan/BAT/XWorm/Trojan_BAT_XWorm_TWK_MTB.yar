
rule Trojan_BAT_XWorm_TWK_MTB{
	meta:
		description = "Trojan:BAT/XWorm.TWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 1c 00 00 0a 72 0d 00 00 70 28 1d 00 00 0a 0a 06 28 1e 00 00 0a 2d 18 06 02 28 0b 00 00 06 28 06 00 00 06 28 1f 00 00 0a 06 28 20 00 00 0a 26 28 1c 00 00 0a 72 2d 00 00 70 28 1d 00 00 0a 0b 07 02 28 0c 00 00 06 28 06 00 00 06 28 1f 00 00 0a 07 28 20 00 00 0a 26 02 28 21 00 00 0a 2a } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}