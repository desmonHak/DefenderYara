
rule Trojan_BAT_SnakeKeylogger_ZEJ_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ZEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 04 11 05 6f ?? 00 00 0a 13 06 03 09 6f ?? 00 00 0a 59 13 07 09 17 8d ?? 00 00 01 25 16 12 06 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 11 07 17 59 25 13 07 16 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}