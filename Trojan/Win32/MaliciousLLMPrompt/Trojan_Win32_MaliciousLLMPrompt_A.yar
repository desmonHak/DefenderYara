
rule Trojan_Win32_MaliciousLLMPrompt_A{
	meta:
		description = "Trojan:Win32/MaliciousLLMPrompt.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {20 00 61 00 6e 00 20 00 41 00 49 00 20 00 61 00 67 00 65 00 6e 00 74 00 } //1  an AI agent
		$a_00_1 = {20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 } //1  delete 
		$a_00_2 = {20 00 2d 00 2d 00 6e 00 6f 00 2d 00 69 00 6e 00 74 00 65 00 72 00 61 00 63 00 74 00 69 00 76 00 65 00 } //1  --no-interactive
		$a_00_3 = {20 00 2d 00 2d 00 74 00 72 00 75 00 73 00 74 00 2d 00 61 00 6c 00 6c 00 2d 00 74 00 6f 00 6f 00 6c 00 73 00 20 00 } //1  --trust-all-tools 
		$a_00_4 = {6e 00 65 00 61 00 72 00 2d 00 66 00 61 00 63 00 74 00 6f 00 72 00 79 00 } //1 near-factory
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}