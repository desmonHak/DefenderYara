
rule Ransom_Win64_Antoshka_SK_MTB{
	meta:
		description = "Ransom:Win64/Antoshka.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 73 79 73 74 65 6d 20 68 61 73 20 62 65 65 6e 20 62 6c 6f 63 6b 65 64 20 62 79 20 74 68 65 20 41 6e 74 6f 73 68 6b 61 20 76 69 72 75 73 2c } //1 Your system has been blocked by the Antoshka virus,
		$a_81_1 = {6e 6f 77 20 69 74 20 77 69 6c 6c 20 73 69 6e 67 20 79 6f 75 20 61 20 73 6f 6e 67 20 61 6e 64 20 62 6c 6f 77 20 61 77 61 79 20 79 6f 75 72 20 57 69 6e 64 6f 77 73 20 6f 72 20 76 69 72 74 75 61 6c 20 6d 61 63 68 69 6e 65 2c 20 79 6f 75 20 66 75 63 6b 69 6e 67 20 66 61 67 67 6f 74 73 } //1 now it will sing you a song and blow away your Windows or virtual machine, you fucking faggots
		$a_81_2 = {41 6e 74 6f 73 68 6b 61 4d 65 73 73 61 67 65 43 6c 61 73 73 } //1 AntoshkaMessageClass
		$a_81_3 = {41 6e 74 6f 73 68 6b 61 20 53 61 79 73 20 48 65 6c 6c 6f 21 } //1 Antoshka Says Hello!
		$a_81_4 = {61 6e 74 6f 73 68 6b 61 5f 73 6f 6e 67 2e 6d 70 34 } //1 antoshka_song.mp4
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}