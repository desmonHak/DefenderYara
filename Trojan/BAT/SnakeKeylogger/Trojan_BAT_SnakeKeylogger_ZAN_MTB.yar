
rule Trojan_BAT_SnakeKeylogger_ZAN_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ZAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {1d 5a 58 61 13 38 00 02 11 ?? 11 ?? 6f ?? 00 00 0a 13 39 04 03 6f ?? 00 00 0a 59 13 3a 11 3a 13 3b 11 3b 19 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}