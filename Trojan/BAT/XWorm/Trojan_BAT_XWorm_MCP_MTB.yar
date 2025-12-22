
rule Trojan_BAT_XWorm_MCP_MTB{
	meta:
		description = "Trojan:BAT/XWorm.MCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d1 6f ?? 00 00 0a 26 07 17 58 0b 07 02 6f ?? 00 00 0a 32 d5 } //1
		$a_01_1 = {63 72 79 70 74 65 64 2e 65 78 65 } //1 crypted.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}