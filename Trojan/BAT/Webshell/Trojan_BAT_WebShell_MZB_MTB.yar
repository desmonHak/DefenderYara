
rule Trojan_BAT_WebShell_MZB_MTB{
	meta:
		description = "Trojan:BAT/WebShell.MZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 72 81 74 00 70 28 ?? 00 00 0a 00 7e 18 00 00 04 0b 07 2d 2e 00 02 28 ?? 00 00 0a 80 19 00 00 04 17 8d 4a 00 00 01 0a 06 16 72 81 74 00 70 a2 02 06 28 ?? 00 00 0a 80 1a 00 00 04 17 80 18 00 00 04 00 02 28 ?? 00 00 0a 20 80 c3 c9 01 6f ?? 00 00 0a 00 00 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}