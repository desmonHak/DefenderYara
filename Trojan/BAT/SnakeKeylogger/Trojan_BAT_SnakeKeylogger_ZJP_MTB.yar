
rule Trojan_BAT_SnakeKeylogger_ZJP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ZJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 17 62 11 0b 19 58 61 0b 02 09 11 0b 6f ?? 00 00 0a 13 0c 04 03 6f ?? 00 00 0a 59 13 0d 11 0d 13 0f 11 0f 13 0e } //6
		$a_03_1 = {03 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 00 2b 00 00 11 0b } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}