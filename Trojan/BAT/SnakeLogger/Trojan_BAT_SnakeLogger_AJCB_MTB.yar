
rule Trojan_BAT_SnakeLogger_AJCB_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.AJCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {0e 06 11 07 08 58 61 10 06 02 08 11 07 6f ?? 00 00 0a 13 08 04 03 6f ?? 00 00 0a 59 13 09 11 09 13 0b 11 0b 13 0a 11 0a } //5
		$a_03_1 = {07 0e 04 09 6f ?? 00 00 0a 0e 06 09 58 20 ff 00 00 00 5f 61 61 0b 0e 05 2c 08 07 19 5f 17 fe 01 2b 01 16 13 04 11 04 2c 13 00 06 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}