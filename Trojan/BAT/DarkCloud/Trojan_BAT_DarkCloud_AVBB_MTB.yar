
rule Trojan_BAT_DarkCloud_AVBB_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AVBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 13 11 11 11 2c 10 11 0a 14 14 6f ?? 00 00 0a 74 ?? 00 00 01 13 09 1b 8d ?? 00 00 01 13 0b 16 13 08 2b 11 11 0b 11 08 11 08 11 08 5a d2 9c 11 08 17 58 13 08 11 08 11 0b 8e 69 fe 04 13 12 11 12 2d e1 } //5
		$a_03_1 = {26 11 09 11 0c 20 00 6e 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 11 0c 28 ?? 00 00 2b 6f ?? 00 00 0a 13 0e 11 0e } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}