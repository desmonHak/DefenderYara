
rule Trojan_Win64_Zusy_KK_MTB{
	meta:
		description = "Trojan:Win64/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 30 01 45 30 51 01 45 30 41 02 41 30 51 03 49 83 c1 04 83 e9 } //20
		$a_01_1 = {8a 44 0c 50 48 ff c1 41 30 01 49 ff c1 48 3b ca } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win64_Zusy_KK_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 85 9c 01 00 00 48 98 0f b6 84 05 2a 01 00 00 84 c0 } //20
		$a_01_1 = {8b 85 9c 01 00 00 48 98 0f b6 84 05 2a 01 00 00 66 0f be d0 8b 85 9c 01 00 00 48 98 66 89 94 45 e0 00 00 00 83 85 9c 01 00 00 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win64_Zusy_KK_MTB_3{
	meta:
		description = "Trojan:Win64/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {f3 43 0f 6f 04 08 0f 57 c2 f3 43 0f 7f 04 08 41 8d 42 f0 f3 42 0f 6f 04 08 66 0f 6f ca 0f 57 c8 f3 42 0f 7f 0c 08 41 8b c2 f3 42 0f 6f 04 08 0f 57 c2 f3 42 0f 7f 04 08 41 8d 42 10 f3 42 0f 6f 04 08 66 0f 6f ca 0f 57 c8 f3 42 0f 7f 0c 08 41 83 c0 40 41 83 c2 40 45 3b c3 } //6
		$a_01_1 = {41 8d 4a 01 45 8b ca 44 0f b6 04 19 42 0f b6 0c 13 41 80 e8 41 fe c9 49 d1 e9 c0 e1 04 41 83 c2 02 44 0a c1 45 88 04 01 8b 0f 44 3b d1 72 d1 } //10
		$a_01_2 = {54 75 6f 6e 69 41 67 65 6e 74 2e 64 6c 6c } //4 TuoniAgent.dll
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*10+(#a_01_2  & 1)*4) >=20
 
}