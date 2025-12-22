
rule Trojan_Win64_Midie_SXA_MTB{
	meta:
		description = "Trojan:Win64/Midie.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 39 11 75 0f 48 63 41 3c 41 0f b7 d0 66 44 39 04 08 74 09 48 81 e9 } //7
		$a_03_1 = {45 33 d2 8b da 41 c1 e9 ?? 41 8b d2 41 8b c1 c1 e0 ?? 4c 63 d8 4c 03 d9 41 f7 d9 } //5
		$a_80_2 = {73 76 63 68 6f 73 74 5f 69 6e 6a 2e 63 70 70 } //svchost_inj.cpp  1
		$a_80_3 = {49 6e 6a 65 63 74 53 56 43 48 6f 73 74 } //InjectSVCHost  1
		$a_80_4 = {69 6e 6a 6c 69 62 5c 72 65 6d 6f 74 65 5f 74 68 72 65 61 64 2e 63 70 70 } //injlib\remote_thread.cpp  1
	condition:
		((#a_01_0  & 1)*7+(#a_03_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=15
 
}