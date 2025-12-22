
rule VirTool_Win64_Senjetesz_A{
	meta:
		description = "VirTool:Win64/Senjetesz.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 53 48 83 ec 40 48 c7 44 24 30 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? c7 44 24 28 80 00 00 00 45 33 c9 45 33 c0 c7 44 24 20 01 00 00 00 ba 00 00 00 40 ?? ?? ?? ?? ?? ?? 48 8b d8 48 83 f8 ff ?? ?? ?? ?? ?? ?? ?? ?? 8b d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}