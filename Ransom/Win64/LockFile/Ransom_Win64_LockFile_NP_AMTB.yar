
rule Ransom_Win64_LockFile_NP_AMTB{
	meta:
		description = "Ransom:Win64/LockFile.NP!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {72 73 6f 6e 2e 70 64 62 } //rson.pdb  1
		$a_80_1 = {54 49 4d 45 20 45 58 50 49 52 45 44 21 20 59 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 70 65 72 6d 61 6e 65 6e 74 6c 79 20 64 65 6c 65 74 65 64 21 } //TIME EXPIRED! Your files will be permanently deleted!  1
		$a_80_2 = {50 61 79 6d 65 6e 74 20 53 74 61 74 75 73 20 2d 20 4e 4f 54 20 50 41 49 44 } //Payment Status - NOT PAID  1
		$a_80_3 = {49 74 20 6d 61 79 20 63 61 75 73 65 20 70 65 72 6d 61 6e 65 6e 74 20 66 69 6c 65 20 63 6f 72 72 75 70 74 69 6f 6e 21 } //It may cause permanent file corruption!  1
		$a_80_4 = {57 61 6e 6e 61 43 72 79 52 65 70 6c 69 63 61 } //WannaCryReplica  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}