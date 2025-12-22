
rule Trojan_BAT_RedlineStealer_ZYK_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.ZYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 05 0e 04 6f ?? 00 00 0a 0a 04 03 6f ?? 00 00 0a 59 0b 07 16 fe 02 16 fe 01 0c 08 2c 02 2b 68 03 06 } //5
		$a_03_1 = {02 03 04 05 07 0e 04 0e 05 28 ?? 00 00 06 00 03 6f ?? 00 00 0a 04 fe 04 16 fe 01 0d 09 2c 02 2b 2a } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}