
rule Ransom_MSIL_CymLocker_NRA_MTB{
	meta:
		description = "Ransom:MSIL/CymLocker.NRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {50 6c 65 61 73 65 20 65 6e 74 65 72 20 74 68 65 20 70 61 74 68 20 74 6f 20 65 6e 63 72 79 70 74 } //1 Please enter the path to encrypt
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_81_2 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //1 Your personal files are encrypted!
		$a_81_3 = {72 61 6e 73 6f 6d 77 61 72 65 5c 42 79 74 65 6c 6f 63 6b 65 72 2d 6d 61 73 74 65 72 5c 42 79 74 65 6c 6f 63 6b 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 43 79 6d 4c 6f 63 6b 65 72 2e 70 64 62 } //2 ransomware\Bytelocker-master\Bytelocker\obj\Debug\CymLocker.pdb
		$a_81_4 = {44 65 63 72 79 70 74 69 6e 67 } //1 Decrypting
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1) >=6
 
}