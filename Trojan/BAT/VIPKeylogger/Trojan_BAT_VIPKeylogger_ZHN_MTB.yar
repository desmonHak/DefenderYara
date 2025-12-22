
rule Trojan_BAT_VIPKeylogger_ZHN_MTB{
	meta:
		description = "Trojan:BAT/VIPKeylogger.ZHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 11 21 58 19 5d 13 23 18 11 21 58 19 5d 13 24 19 8d ?? 00 00 01 13 25 11 25 16 12 1e 28 ?? 00 00 0a 9c 11 25 17 12 1e 28 ?? 00 00 0a 9c 11 25 18 12 1e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}