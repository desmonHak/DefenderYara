
rule Trojan_BAT_XWorm_ZDL_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ZDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 28 1f 49 5a 61 11 0a 11 0b 58 20 ff 00 00 00 5f 61 13 29 00 02 11 27 11 28 6f ?? 00 00 0a 13 2a 03 06 6f ?? 00 00 0a 59 13 2b 11 2b 13 2c 11 2c 19 fe 02 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}