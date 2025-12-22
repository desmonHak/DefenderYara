
rule Trojan_Win64_ShellcodeRunner_BB_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 30 48 89 44 24 38 ff 15 ce 14 01 00 48 2b c3 48 3d 60 ea 00 00 72 bb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}