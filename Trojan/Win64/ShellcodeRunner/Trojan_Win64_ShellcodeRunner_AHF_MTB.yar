
rule Trojan_Win64_ShellcodeRunner_AHF_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.AHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 48 f7 d0 48 29 c5 58 48 83 ed ?? 48 8b c6 48 2b c1 50 48 f7 d0 48 29 c7 58 48 83 ef ?? 49 f7 d8 4c 89 84 } //20
		$a_03_1 = {44 0f b6 44 24 ?? 0f b6 44 24 ?? 66 41 c1 e0 ?? 66 44 0b c0 66 44 89 06 48 8b cf 48 8b 07 eb } //30
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}