
rule Trojan_Win64_ShellcodeRunner_MXS_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.MXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e2 1f 0f b6 14 0a 41 30 54 06 fe 41 83 e0 1f 41 0f b6 14 08 41 30 54 06 ?? 89 c2 83 e2 1f 0f b6 14 0a 41 30 14 06 48 83 c0 03 48 3d 8e 00 0a 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}