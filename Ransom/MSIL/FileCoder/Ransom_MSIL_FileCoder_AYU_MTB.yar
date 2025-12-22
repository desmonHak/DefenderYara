
rule Ransom_MSIL_FileCoder_AYU_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.AYU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {41 00 6c 00 6c 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 61 00 6e 00 64 00 20 00 6f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 73 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 64 00 2e 00 } //2 All files encrypted and originals deleted.
		$a_01_1 = {56 69 62 65 53 68 69 74 53 68 6f 77 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 VibeShitShow.My.Resources
		$a_01_2 = {45 6e 63 72 79 70 74 41 6c 6c 43 6f 6d 6d 6f 6e 46 69 6c 65 73 } //1 EncryptAllCommonFiles
		$a_01_3 = {45 6e 63 72 79 70 74 41 6e 64 44 65 6c 65 74 65 46 69 6c 65 } //1 EncryptAndDeleteFile
		$a_01_4 = {5c 56 69 62 65 53 68 69 74 53 68 6f 77 5c 6f 62 6a 5c 44 65 62 75 67 5c 56 69 62 65 53 68 69 74 53 68 6f 77 2e 70 64 62 } //1 \VibeShitShow\obj\Debug\VibeShitShow.pdb
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}