
rule TrojanDropper_Win64_Dlass_GVB_MTB{
	meta:
		description = "TrojanDropper:Win64/Dlass.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 3b c6 6d 00 d9 33 6a 00 00 a2 0a 00 f3 fe a2 52 01 c7 69 00 00 d4 00 00 ff 44 47 78 } //2
		$a_01_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 75 63 6c 00 4b d1 68 00 00 a2 0a 00 de 5f 11 43 14 64 68 00 00 d4 00 00 cf 8f 8a 99 } //2
		$a_01_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 df cf 6b 00 72 3d 68 00 00 a2 0a 00 84 1d 76 60 46 d0 67 00 00 d4 00 00 43 4c 0c bc } //2
		$a_01_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ce d6 6d 00 83 44 6a 00 00 a2 0a 00 f4 a7 fc a6 b0 d7 69 00 00 d4 00 00 97 52 3b ad } //2
		$a_01_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 4c 29 6b 00 01 97 67 00 00 a2 0a 00 a9 bc c5 71 ec 29 67 00 00 d4 00 00 fc 60 59 c2 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=2
 
}