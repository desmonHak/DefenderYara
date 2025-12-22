
rule Trojan_Win32_ShellcodeRunner_PBK_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.PBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 f8 31 c9 0f a2 31 c6 39 f0 75 03 8d 78 01 31 de 31 ce 31 d6 83 ef 01 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}