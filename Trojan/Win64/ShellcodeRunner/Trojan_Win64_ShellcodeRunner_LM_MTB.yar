
rule Trojan_Win64_ShellcodeRunner_LM_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 53 48 83 ec 38 48 8d ac 24 80 00 00 00 48 89 4d d0 48 89 55 d8 48 c7 45 a8 00 00 00 00 48 8b 45 a8 48 3b 45 d8 73 ?? 48 8b 55 d0 48 8b 45 a8 48 01 d0 0f b6 00 0f b6 c0 48 8b 4d d0 48 8b 55 a8 48 8d 1c 11 89 c1 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}