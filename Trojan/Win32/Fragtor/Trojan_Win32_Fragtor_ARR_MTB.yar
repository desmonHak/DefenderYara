
rule Trojan_Win32_Fragtor_ARR_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_81_0 = {4c 6f 61 64 6d 79 44 6c 6c } //6 LoadmyDll
		$a_81_1 = {73 74 72 61 74 20 72 75 6e } //4 strat run
		$a_81_2 = {49 4f 4a 43 4d 61 69 6e } //10 IOJCMain
	condition:
		((#a_81_0  & 1)*6+(#a_81_1  & 1)*4+(#a_81_2  & 1)*10) >=20
 
}
rule Trojan_Win32_Fragtor_ARR_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f 10 23 0f 10 6b ?? 0f 57 e0 0f 57 e9 0f 11 20 0f 11 68 } //8
		$a_03_1 = {f7 e1 8d 8e ?? ?? ?? ?? 89 d0 89 fa d1 e8 66 83 7e } //6
		$a_03_2 = {f7 e1 8b 46 ?? 89 d7 89 c1 f7 66 } //4
		$a_81_3 = {46 72 6f 6d 55 74 66 38 45 72 72 6f 72 62 79 74 65 73 4e 75 6c 4d 75 74 65 78 45 72 72 6f 72 7e 5c 2e 63 61 72 67 6f 5c 72 65 67 69 73 74 72 79 5c 73 72 63 5c 69 6e 64 65 78 2e 63 72 61 74 65 73 2e 69 6f 2d 31 39 34 39 63 66 38 63 36 62 35 62 35 35 37 66 } //2 FromUtf8ErrorbytesNulMutexError~\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f
	condition:
		((#a_03_0  & 1)*8+(#a_03_1  & 1)*6+(#a_03_2  & 1)*4+(#a_81_3  & 1)*2) >=20
 
}