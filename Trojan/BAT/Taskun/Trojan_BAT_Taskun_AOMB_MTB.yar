
rule Trojan_BAT_Taskun_AOMB_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AOMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 05 11 06 6f ?? 00 00 0a 13 08 03 11 04 6f ?? 00 00 0a 59 13 09 11 04 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 17 59 25 13 09 16 fe 02 16 fe 01 13 13 11 13 2c 05 38 ?? ?? 00 00 11 04 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 17 59 25 13 09 16 fe 02 16 fe 01 13 14 11 14 2c 05 38 ?? ?? 00 00 11 04 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 12 08 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}