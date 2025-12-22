
rule Trojan_Win64_Tedy_ARR_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {4c 0f af f2 49 31 de c4 c3 fb f0 c5 ?? 48 0f af c2 4c 01 f7 } //10
		$a_03_1 = {41 8b 44 24 ?? 89 df 48 01 f7 83 c3 } //2
		$a_03_2 = {41 0f b7 4d 14 48 8d 04 0f 8b 54 0f ?? 39 da 77 } //8
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*2+(#a_03_2  & 1)*8) >=20
 
}
rule Trojan_Win64_Tedy_ARR_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 d0 0f be 51 ?? 01 d0 41 31 c0 4c 39 c9 } //2
		$a_01_1 = {4e 35 7a 68 61 6e 67 31 32 65 6e 63 79 70 74 69 6f 6e 41 6c 67 49 4c 79 36 34 45 45 45 } //8 N5zhang12encyptionAlgILy64EEE
		$a_01_2 = {4e 35 7a 68 61 6e 67 31 33 64 65 73 45 6e 63 72 79 70 74 69 6f 6e 45 } //10 N5zhang13desEncryptionE
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*8+(#a_01_2  & 1)*10) >=20
 
}