
rule Trojan_BAT_Baryas_MCP_MTB{
	meta:
		description = "Trojan:BAT/Baryas.MCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 32 34 61 39 38 33 36 62 37 32 66 } //1 b24a9836b72f
		$a_01_1 = {41 6c 41 45 76 66 52 42 78 71 68 68 } //1 AlAEvfRBxqhh
		$a_01_2 = {6f 63 46 62 63 4b 5a 5a 73 46 47 } //1 ocFbcKZZsFG
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}