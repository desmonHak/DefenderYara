
rule Trojan_BAT_WebShell_AXEB_MTB{
	meta:
		description = "Trojan:BAT/WebShell.AXEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 18 6f ?? 00 00 0a 00 07 28 ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 0c 2b 00 08 2a } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}