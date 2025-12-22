
rule Ransom_Win64_FileCoder_B_AMTB{
	meta:
		description = "Ransom:Win64/FileCoder.B!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {57 72 6f 6e 67 20 70 61 73 73 77 6f 72 64 21 20 46 69 6c 65 73 20 72 65 6d 61 69 6e 20 65 6e 63 72 79 70 74 65 64 2e } //Wrong password! Files remain encrypted.  1
		$a_80_1 = {50 61 73 73 77 6f 72 64 20 63 6f 72 72 65 63 74 21 20 44 65 63 72 79 70 74 69 6e 67 20 66 69 6c 65 73 } //Password correct! Decrypting files  1
		$a_80_2 = {65 6e 63 56 2e 70 64 62 } //encV.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}