
rule Trojan_BAT_XWorm_ZMK_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ZMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 08 02 08 91 20 d8 00 00 00 61 b4 9c 08 1a d6 0c 08 07 31 eb } //5
		$a_03_1 = {0d 09 8e 69 1f 18 fe 02 13 04 11 04 2c 2c 09 1f 18 9a 13 05 11 05 6f ?? 01 00 0a 28 ?? 00 00 2b 13 06 11 06 14 fe 03 13 07 11 07 2c 0b } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}