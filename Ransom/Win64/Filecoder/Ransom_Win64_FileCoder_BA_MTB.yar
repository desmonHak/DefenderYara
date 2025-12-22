
rule Ransom_Win64_FileCoder_BA_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {66 69 6c 65 5f 78 6f 72 5f 6c 6f 63 6b 65 72 } //1 file_xor_locker
		$a_81_1 = {64 65 63 72 79 70 74 } //1 decrypt
		$a_81_2 = {52 45 41 44 4d 45 2e 74 78 74 } //1 README.txt
		$a_81_3 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e } //1 Your files have been encrypted.
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_Win64_FileCoder_BA_MTB_2{
	meta:
		description = "Ransom:Win64/FileCoder.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_81_0 = {65 6e 63 72 79 70 74 65 64 5f 66 69 6c 65 2e 74 78 74 } //1 encrypted_file.txt
		$a_81_1 = {2e 6c 6f 63 6b 65 64 } //1 .locked
		$a_81_2 = {72 61 6e 73 6f 6d 5f 6e 6f 74 65 2e 74 78 74 } //1 ransom_note.txt
		$a_81_3 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e } //1 Your files have been encrypted.
		$a_81_4 = {72 61 6e 73 6f 6d 2e 74 78 74 } //1 ransom.txt
		$a_81_5 = {54 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 73 65 6e 64 20 24 31 30 30 20 74 6f 20 5b 65 6d 61 69 6c 20 61 64 64 72 65 73 73 5d 2e } //1 To decrypt your files, send $100 to [email address].
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=3
 
}