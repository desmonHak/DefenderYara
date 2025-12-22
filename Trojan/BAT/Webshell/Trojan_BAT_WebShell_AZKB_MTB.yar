
rule Trojan_BAT_WebShell_AZKB_MTB{
	meta:
		description = "Trojan:BAT/WebShell.AZKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 08 07 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 72 ?? ?? 00 70 72 ?? ?? 00 70 6f ?? 00 00 0a 0d 03 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 73 ?? 00 00 0a 28 ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 04 02 28 ?? 00 00 0a 6f ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a 14 fe 01 16 fe 01 13 09 11 09 2d 64 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}