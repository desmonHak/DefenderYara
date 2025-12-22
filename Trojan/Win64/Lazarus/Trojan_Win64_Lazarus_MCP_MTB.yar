
rule Trojan_Win64_Lazarus_MCP_MTB{
	meta:
		description = "Trojan:Win64/Lazarus.MCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 6c 69 76 65 72 43 75 73 74 6f 6d [0-12] 44 4c 4c 2e 64 6c 6c 00 6d 61 69 6e } //1
		$a_03_1 = {2e 6d 73 76 63 6a 6d 63 [0-20] c0 2e 30 30 63 66 67 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}