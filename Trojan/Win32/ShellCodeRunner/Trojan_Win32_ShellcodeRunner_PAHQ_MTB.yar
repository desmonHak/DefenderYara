
rule Trojan_Win32_ShellcodeRunner_PAHQ_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.PAHQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 04 0f 00 8a 19 2a d8 fe cb 40 88 1c 0a 41 3b 45 fc 76 ec } //3
		$a_01_1 = {8a 06 88 04 31 46 84 c0 75 f6 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}