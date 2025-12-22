
rule Trojan_BAT_Nanocore_ZAM_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ZAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 11 11 11 0f 6f ?? 00 00 0a 13 10 02 03 19 5a 8c ?? 00 00 01 11 0e 16 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 12 10 28 ?? 00 00 0a 9c 02 03 19 5a 8c 11 00 00 01 11 0e 17 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 12 10 28 ?? 00 00 0a 9c 02 03 8c ?? 00 00 01 11 0e 18 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}