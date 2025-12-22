
rule Trojan_BAT_SnakeKeylogger_ZQN_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ZQN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 11 11 1f 49 5a 61 13 12 02 11 10 11 11 6f ?? 00 00 0a 13 13 04 03 6f ?? 00 00 0a 59 13 14 11 14 13 15 11 15 19 31 03 19 13 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}