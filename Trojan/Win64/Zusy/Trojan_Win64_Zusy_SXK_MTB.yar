
rule Trojan_Win64_Zusy_SXK_MTB{
	meta:
		description = "Trojan:Win64/Zusy.SXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 45 f0 48 83 f9 ?? 4c 0f 47 45 f0 48 83 7f 18 ?? 76 03 48 8b 3f 4c 89 64 24 ?? 45 33 c9 48 8b d7 33 c9 e8 } //6
		$a_01_1 = {4c 89 bc 24 10 15 00 00 4c 8d 65 80 4c 0f 47 65 80 4d 8d 7d 4c 0f 57 c0 0f 57 c9 0f 11 44 24 60 } //4
		$a_80_2 = {6e 62 67 74 70 61 73 72 67 2e 65 78 65 } //nbgtpasrg.exe  1
		$a_80_3 = {63 72 79 70 74 65 64 5f 62 75 69 6c 64 2e 65 78 65 } //crypted_build.exe  1
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*4+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=12
 
}