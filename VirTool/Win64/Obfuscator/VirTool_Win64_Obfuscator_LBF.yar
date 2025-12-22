
rule VirTool_Win64_Obfuscator_LBF{
	meta:
		description = "VirTool:Win64/Obfuscator.LBF,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {45 0f 43 d9 44 ?? ?? 45 8d ?? ?? ?? 00 00 45 0f af cb 41 ?? ?? 44 ?? ?? 81 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}