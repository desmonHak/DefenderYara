
rule Trojan_BAT_BPLogger_ZDP_MTB{
	meta:
		description = "Trojan:BAT/BPLogger.ZDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {26 02 11 04 11 0a 6f ?? 00 00 0a 13 0b 04 03 6f ?? 00 00 0a 59 13 0c 11 0c 13 0e 11 0e 13 0d } //6
		$a_03_1 = {2b 2c 03 12 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 00 2b 00 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}