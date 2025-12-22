
rule Trojan_BAT_WebShell_CC_MTB{
	meta:
		description = "Trojan:BAT/WebShell.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {70 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 28 ?? 00 00 0a 06 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 08 08 6f ?? 00 00 0a 07 16 02 } //3
		$a_01_1 = {41 70 70 5f 57 65 62 5f } //1 App_Web_
		$a_01_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}