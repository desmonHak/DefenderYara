
rule Trojan_BAT_SpyNoon_ZPN_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.ZPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 3b 5a 61 13 25 00 02 11 23 11 24 6f ?? 00 00 0a 13 26 04 03 6f ?? 00 00 0a 59 13 27 11 27 13 28 11 28 19 fe 02 13 2e 11 2e 2c 03 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}