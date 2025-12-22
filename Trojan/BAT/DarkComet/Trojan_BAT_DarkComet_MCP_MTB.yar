
rule Trojan_BAT_DarkComet_MCP_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.MCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2b 02 26 16 20 10 f6 01 00 } //1
		$a_01_1 = {38 64 37 33 65 33 65 62 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 8d73e3eb.Resources.resources
		$a_01_2 = {41 00 4d 00 44 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 2e 00 65 00 78 00 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}