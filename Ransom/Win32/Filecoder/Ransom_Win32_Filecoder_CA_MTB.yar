
rule Ransom_Win32_Filecoder_CA_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 6f 75 63 68 4d 65 4e 6f 74 5f 2e 74 78 74 } //3 TouchMeNot_.txt
		$a_01_1 = {2e 65 6e 63 72 79 70 74 65 64 } //3 .encrypted
		$a_01_2 = {45 6e 63 72 79 70 74 65 64 20 66 69 6c 65 } //3 Encrypted file
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //2 Software\Microsoft\Windows\CurrentVersion\Run
		$a_03_4 = {45 6e 63 72 79 70 74 65 64 20 66 69 6c 65 [0-3f] 77 69 74 68 20 6b 65 79 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_03_4  & 1)*2) >=13
 
}