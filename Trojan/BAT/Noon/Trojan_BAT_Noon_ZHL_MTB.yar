
rule Trojan_BAT_Noon_ZHL_MTB{
	meta:
		description = "Trojan:BAT/Noon.ZHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 0b 11 0c 6f ?? 00 00 0a 13 23 12 23 28 ?? 00 00 0a 13 1d 19 8d ?? 00 00 01 25 16 1f 10 9e 25 17 1e 9e 13 1e 03 07 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}