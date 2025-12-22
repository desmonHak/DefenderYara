
rule Trojan_BAT_QuasarStealer_PA_MTB{
	meta:
		description = "Trojan:BAT/QuasarStealer.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {a2 14 14 14 28 ?? 00 00 0a 14 72 fe d4 00 70 16 8d 03 00 00 01 14 14 14 28 ?? 00 00 0a 74 80 00 00 01 6f ?? 00 00 0a 13 07 2b 37 11 07 6f ?? 00 00 0a 28 37 00 00 0a 13 08 00 11 08 74 81 00 00 01 14 16 8d 03 00 00 01 6f ?? 00 00 0a 26 de 10 25 28 ?? 00 00 0a 13 09 00 28 ?? 00 00 0a de 00 } //6
		$a_01_1 = {00 04 18 5d 2c 03 03 2b 07 03 20 c1 00 00 00 61 b4 0a 2b 00 06 2a } //4
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*4) >=10
 
}