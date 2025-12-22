
rule Trojan_Win64_LummaStealer_GAPA_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GAPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {78 69 e5 29 d3 e7 65 b1 e1 39 31 d3 fd a5 d0 79 e2 0e 7a 63 2c 9c f6 e5 80 7a f7 ac da ec ce a1 c0 88 5d 8d ff 9f 4d a4 b3 9f 03 } //8
		$a_01_1 = {5d de d6 2e 79 1a 63 40 55 a9 98 c5 fb 75 d2 aa 8b 60 7d 0a 7c 11 7d 7b 16 d5 20 45 7e 6e d8 54 36 b0 e8 a4 cc 5c 88 24 0b bb 5f 1e 3f 17 fb ae 25 6a 49 3d e1 56 88 5f be 61 49 58 } //8
		$a_01_2 = {2e 6f 65 70 } //1 .oep
		$a_01_3 = {2e 69 6c 74 } //1 .ilt
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*8+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=9
 
}