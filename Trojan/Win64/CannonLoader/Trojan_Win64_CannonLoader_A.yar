
rule Trojan_Win64_CannonLoader_A{
	meta:
		description = "Trojan:Win64/CannonLoader.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {8d 04 db 8b c8 c1 e9 0b 33 c8 69 c1 01 80 00 00 3d 5a c1 7d 36 } //2
		$a_01_1 = {65 48 8b 04 25 60 00 00 00 4c 8b 70 18 49 83 c6 20 49 8b 3e 49 3b fe } //2
		$a_01_2 = {c7 44 24 20 b8 0b 00 00 48 8b d0 48 c7 44 24 50 00 00 00 00 ff d5 85 c0 } //2
		$a_01_3 = {68 66 93 11 } //1
		$a_01_4 = {d4 3d 2c 61 } //1
		$a_01_5 = {2d a0 dc 47 } //1
		$a_01_6 = {ba 00 9a fd 5e } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}