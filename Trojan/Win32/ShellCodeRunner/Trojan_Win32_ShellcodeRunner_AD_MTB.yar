
rule Trojan_Win32_ShellcodeRunner_AD_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 f0 09 00 00 00 c7 45 c8 30 80 40 00 6a 00 68 80 00 00 00 6a 04 6a 00 6a 01 68 00 00 00 80 8b 45 c8 50 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}