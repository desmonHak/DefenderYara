
rule Trojan_BAT_Snakekeylogger_ZYL_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.ZYL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 13 11 14 6f ?? 00 00 0a 13 2d 12 2d 28 ?? 00 00 0a 13 23 03 06 6f ?? 00 00 0a 59 13 24 11 23 28 ?? 00 00 0a 13 25 18 13 26 17 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}