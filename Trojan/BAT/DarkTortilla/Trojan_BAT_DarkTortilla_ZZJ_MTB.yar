
rule Trojan_BAT_DarkTortilla_ZZJ_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZZJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 05 6f ?? 02 00 0a 11 05 6f ?? 02 00 0a 6f ?? 02 00 0a 13 06 00 73 ?? 01 00 0a 13 07 00 11 07 11 06 17 73 ?? 02 00 0a 13 09 11 09 02 16 02 8e 69 6f ?? 02 00 0a 00 11 09 6f ?? 02 00 0a 00 de 0e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}