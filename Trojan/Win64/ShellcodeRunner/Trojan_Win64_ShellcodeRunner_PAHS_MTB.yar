
rule Trojan_Win64_ShellcodeRunner_PAHS_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.PAHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 e8 48 8b 45 b8 48 01 d0 0f b6 10 4c 8b 45 f0 8b 45 ec 8d 48 01 89 4d ec 89 c0 4c 01 c0 88 10 83 45 e8 01 8b 45 a4 39 45 e8 72 } //3
		$a_01_1 = {48 8d 45 e0 41 b9 00 00 00 00 49 89 c0 ba 82 23 00 00 48 8d 05 28 4b 01 00 48 89 c1 e8 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}