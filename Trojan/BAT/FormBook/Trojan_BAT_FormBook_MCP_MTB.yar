
rule Trojan_BAT_FormBook_MCP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 58 56 4d 2e 30 48 61 72 6d 6f 6e 79 2e 62 69 6e } //2 SXVM.0Harmony.bin
		$a_01_1 = {53 58 56 4d 2e 70 61 79 6c 6f 61 64 2e 62 69 6e } //2 SXVM.payload.bin
		$a_01_2 = {31 64 35 65 34 66 38 61 39 63 32 62 } //1 1d5e4f8a9c2b
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
rule Trojan_BAT_FormBook_MCP_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.MCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {54 00 ed 00 74 00 75 00 6c 00 6f 00 01 07 73 00 68 00 70 00 00 01 00 07 4c 00 6f 00 61 [0-0a] 43 00 61 00 72 00 75 00 62 00 62 00 69 00 2e 00 4d 00 65 00 74 00 72 00 6f 00 4c 00 61 00 79 00 6f 00 75 00 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}