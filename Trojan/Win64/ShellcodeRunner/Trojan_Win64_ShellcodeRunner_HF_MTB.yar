
rule Trojan_Win64_ShellcodeRunner_HF_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.HF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7b 0a 09 22 73 6c 22 3a 25 64 2c 0a 09 22 6b 6c 22 3a 25 64 0a 7d 00 25 41 50 50 44 41 54 41 25 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}