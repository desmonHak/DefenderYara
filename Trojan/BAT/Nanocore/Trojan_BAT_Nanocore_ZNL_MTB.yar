
rule Trojan_BAT_Nanocore_ZNL_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ZNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 0a 11 0b 6f ?? 00 00 0a 13 14 12 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 0e 03 06 6f ?? 00 00 0a 59 13 0f 18 13 10 17 13 11 16 13 12 11 05 19 5f 13 13 11 13 17 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}