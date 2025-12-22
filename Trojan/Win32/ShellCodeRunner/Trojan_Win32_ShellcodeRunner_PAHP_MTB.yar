
rule Trojan_Win32_ShellcodeRunner_PAHP_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.PAHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 18 59 33 ff 33 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a 8b 5a 10 8b 12 75 } //3
		$a_01_1 = {8b 0a 69 c0 95 e9 d1 5b 69 c9 95 e9 d1 5b 8b d9 c1 eb 18 33 d9 69 db 95 e9 d1 5b 33 c3 83 ee 04 83 c2 04 4f 75 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}