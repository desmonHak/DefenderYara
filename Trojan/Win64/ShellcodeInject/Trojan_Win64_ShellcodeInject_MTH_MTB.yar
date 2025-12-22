
rule Trojan_Win64_ShellcodeInject_MTH_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.MTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 80 36 1b 41 80 76 01 1f 41 80 76 02 6b 41 80 76 04 1b 41 80 76 05 1f 41 f6 56 03 41 c6 46 06 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}