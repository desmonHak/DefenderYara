
rule Trojan_BAT_XWorm_ZWP_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ZWP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 08 11 09 17 58 1d 5a 07 11 07 11 09 58 07 8e 69 5d 94 61 58 13 08 02 11 07 11 09 6f ?? 00 00 0a 13 0a 04 03 6f ?? 00 00 0a 59 13 0b 11 0b } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}