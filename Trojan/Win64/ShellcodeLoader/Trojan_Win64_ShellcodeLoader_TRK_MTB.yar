
rule Trojan_Win64_ShellcodeLoader_TRK_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeLoader.TRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 0f b6 4c 1a ?? 4c 8b 83 ?? ?? ?? ?? b8 ?? ?? ?? ?? 49 ff c2 f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 b8 ?? ?? ?? ?? 69 d2 ?? ?? ?? ?? 2b ca f7 ef 80 c1 ?? 43 30 0c 08 c1 fa ?? 8b cf } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}