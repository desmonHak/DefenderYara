
rule Trojan_Win64_ShellCodeRunner_AR_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeRunner.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 8d 8c 03 00 00 48 63 c1 48 69 c0 56 55 55 55 48 c1 e8 20 48 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 01 c0 01 d0 29 c1 89 ca 8b 85 58 03 00 00 } //10
		$a_01_1 = {89 c2 89 d0 48 69 c0 d3 4d 62 10 48 c1 e8 20 c1 e8 05 69 c0 f4 01 00 00 29 c2 89 d0 05 f4 01 00 00 89 c1 } //8
		$a_01_2 = {48 8b 55 d0 48 8b 45 a8 48 01 d0 0f b6 00 0f b6 c0 48 8b 4d d0 48 8b 55 a8 48 8d 1c 11 89 c1 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*8+(#a_01_2  & 1)*5) >=23
 
}