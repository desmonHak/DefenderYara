
rule Trojan_Win64_Oyster_ZH_MTB{
	meta:
		description = "Trojan:Win64/Oyster.ZH!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 58 48 8b 4c 24 28 0f b7 04 48 85 c0 74 6c 45 33 c0 33 d2 33 c9 } //1
		$a_01_1 = {44 00 6c 00 6c 00 52 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 53 00 65 00 72 00 76 00 65 00 72 00 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}