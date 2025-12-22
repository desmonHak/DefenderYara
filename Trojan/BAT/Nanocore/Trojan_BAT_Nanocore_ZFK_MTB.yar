
rule Trojan_BAT_Nanocore_ZFK_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ZFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f ?? 00 00 0a 0d 02 16 16 6f ?? 00 00 0a 13 04 09 11 04 28 ?? 00 00 0a 13 05 11 05 2c 3d 00 17 8d ?? 00 00 01 13 06 11 06 16 12 03 28 ?? 00 00 0a 9c 06 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}