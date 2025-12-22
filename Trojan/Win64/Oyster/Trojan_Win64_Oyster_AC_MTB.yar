
rule Trojan_Win64_Oyster_AC_MTB{
	meta:
		description = "Trojan:Win64/Oyster.AC!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 20 00 30 00 00 4c 8d 8c 24 f0 00 00 00 45 33 c0 48 8d 94 24 98 00 00 00 48 c7 } //1
		$a_01_1 = {44 00 6c 00 6c 00 52 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 53 00 65 00 72 00 76 00 65 00 72 00 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}