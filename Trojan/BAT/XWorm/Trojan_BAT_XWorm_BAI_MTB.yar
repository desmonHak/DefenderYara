
rule Trojan_BAT_XWorm_BAI_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 07 1f 0d 62 61 0b 07 07 1f 11 63 61 0b 07 07 1b 62 61 0b 11 08 17 58 13 08 11 08 1a 32 e1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}