
rule Trojan_Win64_DllHijack_AB_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 20 48 8b 4c 24 60 0f be 04 01 89 44 24 28 33 d2 8b 44 24 20 b9 08 00 00 00 f7 f1 8b c2 8b c0 8b 4c 24 28 33 4c 84 30 8b c1 8b 4c 24 20 48 8b 54 24 68 88 04 0a eb b2 } //1
		$a_01_1 = {67 65 6e 65 72 69 63 6c 6f 61 64 65 72 2e 64 6c 6c } //1 genericloader.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}