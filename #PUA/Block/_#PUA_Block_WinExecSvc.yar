
rule _#PUA_Block_WinExecSvc{
	meta:
		description = "!#PUA:Block:WinExecSvc,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 69 6e 65 78 65 73 76 63 43 74 72 6c 48 61 6e 64 6c 65 72 } //1 winexesvcCtrlHandler
		$a_01_1 = {61 68 65 78 65 63 5f 73 74 64 6f 75 74 25 30 38 58 } //1 ahexec_stdout%08X
		$a_01_2 = {55 6e 72 65 63 6f 67 6e 69 7a 65 64 20 6f 70 63 6f 64 65 20 25 6c 64 } //1 Unrecognized opcode %ld
		$a_01_3 = {52 65 74 75 72 6e 69 6e 67 20 74 68 65 20 4d 61 69 6e 20 54 68 72 65 61 64 } //1 Returning the Main Thread
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}