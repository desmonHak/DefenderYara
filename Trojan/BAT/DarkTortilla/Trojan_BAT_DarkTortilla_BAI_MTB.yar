
rule Trojan_BAT_DarkTortilla_BAI_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.BAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 16 7e 18 00 00 04 fe 06 93 00 00 06 73 c1 00 00 0a 25 80 19 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b a2 14 14 14 28 ?? 00 00 0a 14 72 f6 d4 00 70 17 8d 03 00 00 01 25 16 1f 18 8c 6f 00 00 01 a2 14 14 14 } //4
		$a_01_1 = {04 18 5d 2c 03 03 2b 07 03 20 c1 00 00 00 61 b4 0a 2b 00 06 2a } //5
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*5) >=9
 
}