
rule Trojan_BAT_WebShell_FPP_MTB{
	meta:
		description = "Trojan:BAT/WebShell.FPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 00 02 28 ?? 00 00 0a 72 52 05 00 70 28 ?? 00 00 0a 00 0a 00 02 28 ?? 00 00 0a 72 60 05 00 70 28 ?? 00 00 0a 00 0b 06 39 11 01 00 00 06 72 6e 05 00 70 28 ?? 00 00 0a 3a 01 01 00 00 00 00 28 2a 00 00 0a 00 23 00 00 00 00 00 6a f8 40 5a 28 ?? 00 00 0a 28 ?? 00 00 0a 00 72 70 05 00 70 28 ?? 00 00 0a 0c 07 7e 2e 00 00 0a 28 ?? 00 00 0a 3a 4d 00 00 00 11 05 07 72 6e 05 00 70 28 ?? 00 00 0a 3a 3b 00 00 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}