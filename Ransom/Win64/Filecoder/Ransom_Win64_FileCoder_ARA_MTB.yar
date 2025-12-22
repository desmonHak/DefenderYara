
rule Ransom_Win64_Filecoder_ARA_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 61 79 6d 65 6e 74 20 66 6f 72 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e } //2 Payment for the decryption
		$a_01_1 = {57 49 4c 4c 20 61 74 74 61 63 6b 20 79 6f 75 20 61 67 61 69 6e } //2 WILL attack you again
		$a_01_2 = {2f 63 32 2f 72 65 63 65 69 76 65 72 } //2 /c2/receiver
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule Ransom_Win64_Filecoder_ARA_MTB_2{
	meta:
		description = "Ransom:Win64/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 } //10 \\.\PhysicalDrive
		$a_01_1 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 44 45 41 44 39 37 2e 65 78 65 } //2 shellexecute=DEAD97.exe
		$a_01_2 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //2 vssadmin delete shadows /all /quiet
		$a_01_3 = {59 4f 55 52 20 43 4f 4d 50 55 54 45 52 20 48 41 53 20 42 45 45 4e 20 46 55 43 4b 45 44 20 42 59 20 54 48 45 20 4d 45 4d 5a 20 54 52 4f 4a 41 4e } //2 YOUR COMPUTER HAS BEEN FUCKED BY THE MEMZ TROJAN
		$a_01_4 = {59 4f 55 20 43 41 4e 4e 4f 54 20 45 53 43 41 50 45 } //2 YOU CANNOT ESCAPE
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=14
 
}