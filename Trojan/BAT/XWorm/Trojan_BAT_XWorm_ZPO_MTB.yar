
rule Trojan_BAT_XWorm_ZPO_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ZPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 1f 25 5a 11 0a 17 58 1f 65 5a 61 07 61 13 0b 11 0b 11 09 23 00 00 00 00 00 40 8f 40 5a 69 61 13 0b 02 11 07 11 0a 6f ?? 00 00 0a 13 0c 04 03 6f ?? 00 00 0a 59 13 0d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}