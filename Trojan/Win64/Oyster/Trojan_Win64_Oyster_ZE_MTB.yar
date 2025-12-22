
rule Trojan_Win64_Oyster_ZE_MTB{
	meta:
		description = "Trojan:Win64/Oyster.ZE!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 b8 48 8d 34 68 77 1a } //1
		$a_01_1 = {44 00 6c 00 6c 00 52 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 53 00 65 00 72 00 76 00 65 00 72 00 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}