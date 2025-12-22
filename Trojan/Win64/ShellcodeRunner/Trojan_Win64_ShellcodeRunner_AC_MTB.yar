
rule Trojan_Win64_ShellcodeRunner_AC_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 63 c3 45 33 c0 49 3b c1 49 63 d2 45 0f 45 c3 41 ff c2 49 63 c0 ?? ?? ?? ?? 0f b6 0c 38 30 0c 32 49 63 c2 48 3b c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}