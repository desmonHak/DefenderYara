
rule Trojan_BAT_Formbook_ZTO_MTB{
	meta:
		description = "Trojan:BAT/Formbook.ZTO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 07 09 58 61 13 19 00 02 11 10 11 18 6f ?? 00 00 0a 13 1a 04 03 6f ?? 00 00 0a 59 13 1b } //6
		$a_03_1 = {18 11 1d 58 19 5d 13 20 19 8d ?? 00 00 01 13 21 11 21 16 12 1a 28 ?? 00 00 0a 9c 11 21 17 12 1a 28 ?? 00 00 0a 9c 11 21 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}