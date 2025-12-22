
rule Trojan_Win64_ShellcodeRunner_MPX_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.MPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b c2 49 f7 e0 48 c1 ea 03 48 8d 04 d2 49 8b c8 48 2b c8 0f b6 84 0d ?? ?? ?? ?? 43 30 04 01 49 ff c0 4c 3b c6 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}