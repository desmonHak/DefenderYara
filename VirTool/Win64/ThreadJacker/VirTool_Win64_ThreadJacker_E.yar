
rule VirTool_Win64_ThreadJacker_E{
	meta:
		description = "VirTool:Win64/ThreadJacker.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 6e 6a 65 63 74 2d 73 68 65 6c 6c 63 6f 64 65 } //1 inject-shellcode
		$a_01_1 = {4e 74 43 72 65 61 74 65 54 68 72 65 61 64 20 69 6e 6a 65 63 74 69 6f 6e 20 6d 65 74 68 6f 64 } //1 NtCreateThread injection method
		$a_01_2 = {4d 65 6d 6f 72 79 20 61 6c 6c 6f 63 61 74 69 6f 6e 20 73 69 7a 65 } //1 Memory allocation size
		$a_01_3 = {44 65 6c 69 76 65 72 79 20 4d 65 74 68 6f 64 } //1 Delivery Method
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}