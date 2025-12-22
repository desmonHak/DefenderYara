
rule Trojan_Win64_LummaStealer_HBO_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.HBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 8b c0 24 ?? f6 d8 1b c9 81 e1 ?? ?? ?? ?? 42 33 8c 9b ?? ?? ?? ?? 4c 8b da 41 d1 e8 41 33 c8 89 0c 93 48 81 fa ?? ?? ?? ?? 0f 82 } //1
		$a_00_1 = {2f 2f 31 39 36 2e 32 35 31 2e 31 30 37 2e 39 34 3a 35 35 35 33 } //1 //196.251.107.94:5553
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}