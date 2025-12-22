
rule Trojan_Win64_ShellCodeLoader_NQA_MTB{
	meta:
		description = "Trojan:Win64/ShellCodeLoader.NQA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 37 6a 77 49 49 68 74 48 63 75 62 67 78 31 79 72 58 70 55 46 66 48 39 6a 42 48 61 61 } //2 S7jwIIhtHcubgx1yrXpUFfH9jBHaa
		$a_81_1 = {7a 34 68 31 79 67 4c 39 70 78 45 6f 4a 6d 47 64 34 36 4b 74 61 32 54 36 32 34 6e 4c 6e 49 4d } //2 z4h1ygL9pxEoJmGd46Kta2T624nLnIM
		$a_81_2 = {30 33 58 72 30 67 46 41 4f 41 6c 64 43 39 68 6f 4a 7a 37 56 30 79 78 39 42 } //2 03Xr0gFAOAldC9hoJz7V0yx9B
		$a_81_3 = {46 6b 61 46 46 4c 53 33 53 52 54 44 36 67 30 5a 59 79 58 4f 46 4d 48 62 4b 77 68 50 64 47 4f 4c 2e 64 6c 6c } //2 FkaFFLS3SRTD6g0ZYyXOFMHbKwhPdGOL.dll
		$a_81_4 = {52 65 70 6f 73 69 74 6f 72 79 55 72 6c 42 70 6e 45 46 54 70 47 44 78 73 66 4b 4b 72 50 46 59 50 43 71 76 5a 47 73 78 53 6b 77 79 73 6b 49 67 } //2 RepositoryUrlBpnEFTpGDxsfKKrPFYPCqvZGsxSkwyskIg
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2) >=3
 
}