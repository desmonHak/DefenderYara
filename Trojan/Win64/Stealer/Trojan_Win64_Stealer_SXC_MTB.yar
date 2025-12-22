
rule Trojan_Win64_Stealer_SXC_MTB{
	meta:
		description = "Trojan:Win64/Stealer.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 40 03 c1 89 44 24 40 8b 44 24 40 2b c2 89 44 24 40 8b 44 24 40 35 ?? ?? ?? ?? 89 44 24 40 ff c2 83 c1 } //6
		$a_03_1 = {14 01 60 cf c7 84 24 ?? ?? ?? ?? 3a cc 64 0d c7 84 24 ?? ?? ?? ?? d5 3c 42 48 c7 84 24 ?? ?? ?? ?? 41 48 d6 6a c7 84 24 ?? ?? ?? ?? 4e 79 16 57 c7 84 24 ?? ?? ?? ?? 0e 0c 20 75 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}