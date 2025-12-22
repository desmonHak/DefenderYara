
rule Trojan_Win64_Injector_SXC_MTB{
	meta:
		description = "Trojan:Win64/Injector.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 89 44 24 68 c5 fe 6f 44 24 50 c5 fd ef 4c 24 30 c5 fe 7f 4c 24 30 c5 f8 77 } //15
		$a_01_1 = {48 8b 44 24 20 48 89 44 24 48 48 89 4c 24 20 48 8d 4c 24 30 48 8b 44 24 20 48 89 54 24 20 33 d2 48 89 44 24 50 48 8b 44 24 20 4c 89 44 24 20 48 89 44 24 58 } //10
		$a_01_2 = {63 68 72 6f 6d 65 } //1 chrome
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=26
 
}