
rule Ransom_Win64_Henasome_AA_MTB{
	meta:
		description = "Ransom:Win64/Henasome.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 73 20 69 6e 20 74 68 65 20 73 70 65 63 69 66 69 65 64 20 64 69 72 65 63 74 6f 72 79 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 files in the specified directory have been encrypted
		$a_01_1 = {53 74 61 72 74 69 6e 67 20 6c 6f 63 61 6c 20 65 6e 63 72 79 70 74 69 6f 6e } //1 Starting local encryption
		$a_01_2 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 20 63 6f 70 69 65 73 } //1 delete shadow copies
		$a_01_3 = {52 45 41 44 4d 45 2e 54 58 54 } //1 README.TXT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}