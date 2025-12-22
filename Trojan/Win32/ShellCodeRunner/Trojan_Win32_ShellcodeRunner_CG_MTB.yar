
rule Trojan_Win32_ShellcodeRunner_CG_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 20 6a 03 6a 00 6a 03 68 00 00 00 c0 50 ff 15 } //5
		$a_01_1 = {51 56 50 57 ff 15 } //5
		$a_01_2 = {6a 04 68 00 10 00 00 56 6a 00 ff 15 } //5
		$a_03_3 = {68 00 01 00 00 8d ?? 24 [0-04] 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_03_3  & 1)*5) >=20
 
}