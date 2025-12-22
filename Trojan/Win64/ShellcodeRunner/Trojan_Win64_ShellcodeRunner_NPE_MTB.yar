
rule Trojan_Win64_ShellcodeRunner_NPE_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.NPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 b8 50 94 99 07 af f5 1d d8 } //2
		$a_01_1 = {48 b8 ce b9 79 47 bd e8 34 7f } //1
		$a_01_2 = {48 b8 22 e5 e7 28 67 51 ec 1c } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}