
rule Trojan_BAT_DarkTortilla_FPZ_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.FPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 14 17 8d 03 00 00 01 25 16 07 a2 6f ?? 01 00 0a 14 72 ce 3c 00 70 17 8d 03 00 00 01 25 16 1f 18 8c a7 00 00 01 a2 14 14 14 28 ?? 01 00 0a 14 72 e0 3c 00 70 16 } //4
		$a_01_1 = {04 17 5d 2c 03 03 2b 04 03 1f 60 61 b4 0a 2b 00 06 2a } //5
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*5) >=9
 
}