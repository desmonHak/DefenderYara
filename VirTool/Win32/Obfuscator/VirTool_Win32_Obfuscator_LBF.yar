
rule VirTool_Win32_Obfuscator_LBF{
	meta:
		description = "VirTool:Win32/Obfuscator.LBF,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f 43 f7 31 ?? 8d ?? ?? ?? 00 00 0f af d6 01 ?? 89 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}