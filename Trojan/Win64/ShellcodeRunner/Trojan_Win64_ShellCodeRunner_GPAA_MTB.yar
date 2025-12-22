
rule Trojan_Win64_ShellCodeRunner_GPAA_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.GPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {62 27 68 87 03 49 3b 87 03 49 3b 87 03 49 3b 54 71 4a 3a 82 03 49 3b 54 71 4c 3a 11 03 49 3b 54 71 4d 3a 8d 03 49 3b 26 74 4d 3a 89 03 49 3b 26 74 4a 3a 8e 03 49 3b 26 74 4c 3a b7 03 49 3b 54 71 48 3a 84 03 49 3b 87 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}