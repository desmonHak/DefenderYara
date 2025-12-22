
rule Trojan_Win32_ShellcodeRunner_AE_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 33 c9 c1 ef 10 25 ff 00 04 00 83 e7 07 a3 fc 85 40 00 81 cf 28 00 00 01 f7 d1 23 0d 94 80 40 00 f7 d7 23 3d ?? 80 40 00 89 3d ?? 80 40 00 89 0d 94 80 40 00 83 f8 01 76 0f 83 e7 bf } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}