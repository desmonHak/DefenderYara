
rule Trojan_BAT_Noon_ZQO_MTB{
	meta:
		description = "Trojan:BAT/Noon.ZQO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0b 17 58 1f 25 5a 11 ?? 17 58 1f 65 5a 61 07 61 13 ?? 11 ?? 11 ?? 23 00 00 00 00 00 40 8f 40 5a 69 61 13 ?? 02 11 ?? 11 ?? 6f ?? 00 00 0a 13 ?? 04 03 6f ?? 00 00 0a 59 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}