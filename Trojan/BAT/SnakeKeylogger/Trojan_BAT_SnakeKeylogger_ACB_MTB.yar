
rule Trojan_BAT_SnakeKeylogger_ACB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ACB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 0b 11 0c 6f ?? 00 00 0a 13 18 12 18 28 ?? 00 00 0a 13 15 19 8d ?? 00 00 01 25 16 1f 10 9e 25 17 1e 9e 13 16 03 07 6f ?? 00 00 0a 59 13 17 16 13 19 2b 24 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}