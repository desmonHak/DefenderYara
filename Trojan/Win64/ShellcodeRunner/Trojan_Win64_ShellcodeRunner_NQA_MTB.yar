
rule Trojan_Win64_ShellcodeRunner_NQA_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 b8 96 40 44 92 58 dd 59 91 } //2
		$a_01_1 = {48 b8 fd 90 fe 3d bd 9c 42 7e } //1
		$a_01_2 = {48 b8 fc c6 3a 88 77 f2 24 bc } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}