
rule Trojan_BAT_DarkTortilla_BRB_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.BRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 06 14 a2 11 06 17 d6 13 06 11 06 11 05 31 ef 72 bf 2c 00 70 28 ?? 01 00 0a 0d 08 06 7b f9 01 00 04 17 da 09 } //4
		$a_03_1 = {06 0b 00 73 60 01 00 0a 0c 00 08 07 28 ?? 00 00 06 0d 09 02 28 ?? 00 00 06 00 08 6f ?? 01 00 0a 0a de 24 } //5
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*5) >=9
 
}