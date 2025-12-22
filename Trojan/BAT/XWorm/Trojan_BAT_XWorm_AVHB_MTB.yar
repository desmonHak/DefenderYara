
rule Trojan_BAT_XWorm_AVHB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AVHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 02 7b 5e 00 00 04 7b 57 00 00 04 02 7b 5d 00 00 04 03 6f ?? 00 00 0a 0a 2b 00 06 2a } //4
		$a_03_1 = {0a 0b 07 72 25 0d 00 70 28 ?? 00 00 0a 0c 08 2c 29 00 19 8d ?? 00 00 01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c } //2
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2) >=6
 
}