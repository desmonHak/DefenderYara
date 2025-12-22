
rule Trojan_BAT_DarkTortilla_BRT_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.BRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 00 73 0b 02 00 0a 0c 00 08 07 28 ?? 03 00 06 0d 09 02 28 ?? 03 00 06 00 08 6f ?? 01 00 0a 0a de 24 00 09 2c 07 09 6f ?? 00 00 0a 00 dc } //5
		$a_01_1 = {0b 07 14 fe 03 0c 08 2c 7d 07 7e e8 01 00 04 7e f8 01 00 04 2c 07 7e f8 01 00 04 2b 16 7e f6 01 00 04 fe 06 c5 03 00 06 73 76 02 00 0a 25 80 f8 01 00 04 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}