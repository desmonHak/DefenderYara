
rule Ransom_Win64_WingoFileCoder_ARA_MTB{
	meta:
		description = "Ransom:Win64/WingoFileCoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 44 61 72 6b 4c 75 6c 7a 20 52 61 6e 73 6f 6d 77 61 72 65 } //2 files have been encrypted by DarkLulz Ransomware
		$a_01_1 = {64 61 72 6b 6c 75 6c 7a 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67 } //2 darklulz@onionmail.org
		$a_01_2 = {54 6f 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 79 6f 75 20 6d 75 73 74 20 70 61 79 } //2 To recover your files, you must pay
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}