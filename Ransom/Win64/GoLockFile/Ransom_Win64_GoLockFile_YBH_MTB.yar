
rule Ransom_Win64_GoLockFile_YBH_MTB{
	meta:
		description = "Ransom:Win64/GoLockFile.YBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 61 20 73 74 72 6f 6e 67 20 65 6e 63 72 79 70 74 69 6f 6e 20 61 6c 67 6f 72 69 74 68 6d } //1 encrypted with a strong encryption algorithm
		$a_01_1 = {64 65 63 72 79 70 74 20 69 74 20 66 6f 72 20 66 72 65 65 2e } //1 decrypt it for free.
		$a_01_2 = {64 65 63 72 79 70 74 20 6f 6e 6c 79 20 31 20 66 69 6c 65 20 66 6f 72 20 66 72 65 65 } //1 decrypt only 1 file for free
		$a_01_3 = {44 6f 20 4e 4f 54 20 61 74 74 65 6d 70 74 20 74 6f 20 6d 6f 64 69 66 79 20 6f 72 20 64 65 63 72 79 70 74 20 74 68 65 20 66 69 6c 65 73 20 } //1 Do NOT attempt to modify or decrypt the files 
		$a_01_4 = {6e 6f 74 20 72 65 73 74 6f 72 65 20 79 6f 75 72 20 64 61 74 61 20 77 69 74 68 6f 75 74 20 70 61 79 6d 65 6e 74 } //1 not restore your data without payment
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}