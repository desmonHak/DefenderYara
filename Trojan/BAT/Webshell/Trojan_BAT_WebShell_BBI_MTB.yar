
rule Trojan_BAT_WebShell_BBI_MTB{
	meta:
		description = "Trojan:BAT/WebShell.BBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 07 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 03 73 12 00 00 0a 0d 09 08 16 73 0d 00 00 0a 13 04 11 04 73 13 00 00 0a 13 05 11 05 6f ?? 00 00 0a 13 06 28 15 00 00 0a 11 06 6f ?? 00 00 0a 0a de 0c 11 05 2c 07 11 05 6f ?? 00 00 0a dc de 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}