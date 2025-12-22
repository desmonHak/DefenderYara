
rule Trojan_BAT_WebShell_AXDB_MTB{
	meta:
		description = "Trojan:BAT/WebShell.AXDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 07 06 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 72 ?? 00 00 70 72 ?? 00 00 70 6f ?? 00 00 0a 0c 02 6f ?? 00 00 0a 6f ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 0a 0d 73 ?? 00 00 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 09 16 09 8e 69 6f ?? 00 00 0a 0d 02 6f ?? 00 00 0a 6f ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 2d 60 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}