
rule Trojan_BAT_Remcos_ZTJ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZTJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 09 11 04 6f ?? 00 00 0a 13 05 03 08 6f ?? 00 00 0a 59 13 06 08 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 11 06 17 59 25 13 06 16 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}