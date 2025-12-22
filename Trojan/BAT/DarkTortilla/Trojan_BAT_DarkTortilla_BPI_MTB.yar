
rule Trojan_BAT_DarkTortilla_BPI_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.BPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 09 1f 20 6f ?? 01 00 0a 6f ?? 01 00 0a 00 11 04 09 1f 10 6f ?? 01 00 0a 6f ?? 01 00 0a 00 00 11 04 6f ?? 01 00 0a 13 05 11 05 02 74 26 00 00 1b 16 02 14 72 53 30 00 70 16 8d 01 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 01 00 0a 13 06 11 06 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}