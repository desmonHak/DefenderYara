
rule HackTool_Linux_CredsShellcode_A{
	meta:
		description = "HackTool:Linux/CredsShellcode.A,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 b8 2f 62 69 6e 2f 73 68 00 99 50 54 5f 52 66 68 2d 63 54 5e 52 e8 10 00 00 00 63 61 74 20 2f 65 74 63 2f 70 61 73 73 77 64 00 56 57 54 5e 6a 3b 58 0f 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}