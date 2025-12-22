
rule Trojan_Win64_ShellcodeRunner_NPD_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 b8 ff c9 89 4c 24 1c 0f b6 } //2
		$a_01_1 = {48 b8 29 c8 c1 f8 05 8d 04 02 } //1
		$a_01_2 = {48 b8 4f 01 d3 e0 48 8b 4c 24 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}