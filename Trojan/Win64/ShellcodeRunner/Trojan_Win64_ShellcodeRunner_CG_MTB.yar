
rule Trojan_Win64_ShellcodeRunner_CG_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c9 41 b8 ?? ?? ?? ?? 41 b9 40 00 00 00 e8 ?? ?? ?? ?? 48 85 c0 74 ?? 48 89 c6 48 8d 15 ?? ?? ?? ?? 41 b8 ?? ?? 00 00 48 89 c1 e8 ?? ?? ?? ?? 48 c7 44 24 ?? 00 00 00 00 c7 44 24 ?? 00 00 00 00 31 c9 31 d2 49 89 f0 45 31 c9 e8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}