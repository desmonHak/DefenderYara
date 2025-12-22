
rule Ransom_Win64_Encoder_MX_MTB{
	meta:
		description = "Ransom:Win64/Encoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 65 6c 65 61 73 65 5c 45 6e 63 6f 64 65 72 20 41 45 53 2b 52 53 41 2e 70 64 62 } //5 Release\Encoder AES+RSA.pdb
		$a_01_1 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 2e 00 6b 00 65 00 79 00 } //1 encryption.key
		$a_01_2 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //1 CryptEncrypt
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule Ransom_Win64_Encoder_MX_MTB_2{
	meta:
		description = "Ransom:Win64/Encoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //1 Your files have been encrypted!
		$a_01_1 = {72 61 6e 73 6f 6d 2e 74 78 74 } //1 ransom.txt
		$a_01_2 = {6b 65 79 2e 62 69 6e } //1 key.bin
		$a_01_3 = {43 72 79 70 74 45 6e 63 72 79 70 74 } //1 CryptEncrypt
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Ransom_Win64_Encoder_MX_MTB_3{
	meta:
		description = "Ransom:Win64/Encoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 } //1 Go build ID
		$a_01_1 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 46 69 6c 65 } //1 main.encryptFile
		$a_01_2 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //1 main.encryptDirectory
		$a_01_3 = {6d 61 69 6e 2e 63 72 65 61 74 65 52 61 6e 73 6f 6d 4e 6f 74 65 } //1 main.createRansomNote
		$a_01_4 = {54 6f 20 64 65 63 72 79 70 74 } //1 To decrypt
		$a_01_5 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}