
rule Trojan_BAT_WebShell_MKV_MTB{
	meta:
		description = "Trojan:BAT/WebShell.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {d0 16 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 72 67 01 00 70 6f ?? 00 00 0a 0a 06 14 28 ?? 00 00 0a 0d 09 2c 0d 00 72 a3 01 00 70 13 04 38 38 01 00 00 06 72 0f 02 00 70 6f ?? 00 00 0a 0b 07 14 28 ?? 00 00 0a 13 05 11 05 2c 0d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}