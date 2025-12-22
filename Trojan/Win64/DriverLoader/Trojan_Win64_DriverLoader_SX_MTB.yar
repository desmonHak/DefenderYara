
rule Trojan_Win64_DriverLoader_SX_MTB{
	meta:
		description = "Trojan:Win64/DriverLoader.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 8d 44 24 40 48 89 44 24 30 4c 8d 44 24 48 89 7c 24 28 41 b9 04 00 00 00 ba 48 20 00 80 48 89 7c 24 20 48 8b cb ff 15 } //20
		$a_03_1 = {48 89 7c 24 60 48 89 7c 24 58 48 89 7c 24 50 48 89 7c 24 48 48 89 7c 24 40 48 89 44 24 38 c7 44 24 30 01 ?? ?? ?? c7 44 24 28 01 ?? ?? ?? c7 44 24 20 01 ?? ?? ?? 41 b9 3f 00 0f 00 } //10
		$a_01_2 = {5c 5c 2e 5c 5a 65 6d 61 6e 61 41 6e 74 69 4d 61 6c 77 61 72 65 } //1 \\.\ZemanaAntiMalware
		$a_01_3 = {6c 6c 61 6d 61 2e 73 79 73 } //1 llama.sys
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=32
 
}