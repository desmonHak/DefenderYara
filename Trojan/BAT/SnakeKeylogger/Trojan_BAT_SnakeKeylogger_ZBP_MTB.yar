
rule Trojan_BAT_SnakeKeylogger_ZBP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ZBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 08 11 07 6f ?? 00 00 0a 13 08 04 03 6f ?? 00 00 0a 59 13 09 11 09 13 0b 11 0b 13 0a 11 0a } //6
		$a_03_1 = {2b 2c 03 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 2b 00 11 07 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}