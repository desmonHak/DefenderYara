
rule Trojan_Win64_ShellcodeRunner_SRH_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.SRH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 34 06 31 f2 88 14 0b 48 ff c1 48 89 d8 48 81 f9 ?? 03 00 00 7d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}