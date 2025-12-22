
rule Ransom_MSIL_FileCoder_AYS_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.AYS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {56 65 6e 63 52 54 20 52 61 6e 73 6f 6d 77 61 72 65 } //2 VencRT Ransomware
		$a_01_1 = {56 65 6e 63 52 54 2e 70 64 62 } //1 VencRT.pdb
		$a_01_2 = {66 69 6c 65 73 20 61 72 65 20 61 6c 6c 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 61 20 6d 69 6c 69 74 61 72 79 20 67 72 61 64 65 20 6f 66 20 65 6e 63 72 79 70 74 69 6f 6e } //1 files are all encrypted with a military grade of encryption
		$a_01_3 = {4e 6f 20 6f 6e 65 20 63 61 6e 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 65 78 63 65 70 74 20 75 73 2e } //1 No one can decrypt your files, except us.
		$a_00_4 = {48 00 4f 00 57 00 5f 00 54 00 4f 00 5f 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 5f 00 59 00 4f 00 55 00 52 00 5f 00 46 00 49 00 4c 00 45 00 53 00 } //1 HOW_TO_DECRYPT_YOUR_FILES
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}