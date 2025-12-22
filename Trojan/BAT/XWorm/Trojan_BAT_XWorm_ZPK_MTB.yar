
rule Trojan_BAT_XWorm_ZPK_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ZPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 06 11 07 6f ?? 00 00 0a 13 0a 03 07 6f ?? 00 00 0a 59 13 0b 07 12 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0b 17 59 25 13 0b 16 fe 02 16 fe 01 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}