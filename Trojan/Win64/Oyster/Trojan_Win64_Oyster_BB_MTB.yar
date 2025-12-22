
rule Trojan_Win64_Oyster_BB_MTB{
	meta:
		description = "Trojan:Win64/Oyster.BB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 6c 24 50 45 33 c9 89 6c 24 48 45 33 c0 89 6c 24 40 33 d2 89 6c 24 38 33 c9 89 6c 24 30 48 89 6c 24 28 89 6c 24 20 } //1
		$a_01_1 = {44 00 6c 00 6c 00 52 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 53 00 65 00 72 00 76 00 65 00 72 00 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}