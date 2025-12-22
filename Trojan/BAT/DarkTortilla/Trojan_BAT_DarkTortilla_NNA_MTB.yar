
rule Trojan_BAT_DarkTortilla_NNA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.NNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 75 68 00 00 01 09 74 67 00 00 01 1f 20 6f ?? 00 00 0a 6f ?? 00 00 0a 11 04 75 68 00 00 01 09 75 67 00 00 01 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 1a 13 0c 2b aa } //5
		$a_03_1 = {11 05 75 69 00 00 01 02 74 0b 00 00 1b 16 02 14 20 6f fc 34 00 1d 21 08 00 00 00 00 00 00 00 14 28 ?? 02 00 06 16 8d 06 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 13 06 18 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}