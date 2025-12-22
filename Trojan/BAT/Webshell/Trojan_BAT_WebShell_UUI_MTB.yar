
rule Trojan_BAT_WebShell_UUI_MTB{
	meta:
		description = "Trojan:BAT/WebShell.UUI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {7a 06 08 6f ?? 00 00 0a 13 04 11 04 8e 69 08 2e 0b 72 d0 01 00 70 73 30 00 00 0a 7a 16 13 05 2b 13 11 04 11 05 11 04 11 05 91 09 61 d2 9c 11 05 17 58 13 05 11 05 11 04 8e 69 32 e5 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}