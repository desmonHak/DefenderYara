
rule VirTool_Win32_ObfusPowershellExec_A{
	meta:
		description = "VirTool:Win32/ObfusPowershellExec.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 22 00 65 00 22 00 72 00 22 00 73 00 22 00 68 00 65 00 6c 00 6c 00 22 00 2e 00 22 00 65 00 22 00 78 00 22 00 65 00 } //1 pow"e"r"s"hell"."e"x"e
		$a_00_1 = {70 00 22 00 6f 00 22 00 77 00 65 00 72 00 5e 00 73 00 5e 00 68 00 65 00 6c 00 6c 00 22 00 2e 00 22 00 65 00 78 00 5e 00 65 00 } //1 p"o"wer^s^hell"."ex^e
		$a_00_2 = {70 00 6f 00 77 00 65 00 72 00 5e 00 73 00 5e 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 5e 00 65 00 } //1 power^s^hell.ex^e
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=1
 
}