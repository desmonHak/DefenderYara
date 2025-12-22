
rule Trojan_Win64_ShellcodeRunner_NPB_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 b8 f8 41 83 ce 02 41 83 f8 } //2
		$a_01_1 = {48 b8 eb 27 41 29 c3 41 29 c2 } //1
		$a_01_2 = {48 b8 8d 04 02 66 89 06 eb 17 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}