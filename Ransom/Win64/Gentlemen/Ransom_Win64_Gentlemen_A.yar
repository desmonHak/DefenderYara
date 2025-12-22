
rule Ransom_Win64_Gentlemen_A{
	meta:
		description = "Ransom:Win64/Gentlemen.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 45 41 44 4d 45 2d 47 45 4e 54 4c 45 4d 45 4e 2e 74 78 74 } //1 README-GENTLEMEN.txt
		$a_01_1 = {2d 2d 6d 61 72 6b 65 72 2d 2d } //1 --marker--
		$a_01_2 = {5b 57 25 21 64 28 4d 49 53 53 49 4e 47 29 5d 20 45 52 52 4f 52 20 25 21 73 28 4d 49 53 53 49 4e 47 29 20 3a 20 25 21 76 28 4d 49 53 53 49 4e 47 29 0a } //1
		$a_01_3 = {4c 4f 43 4b 45 52 5f 42 41 43 4b 47 52 4f 55 4e 44 3d 31 } //1 LOCKER_BACKGROUND=1
		$a_01_4 = {5b 2b 5d 20 d0 9d d0 b0 d1 87 d0 b0 d1 82 d0 be 20 d1 88 d0 b8 d1 84 d1 80 d0 be d0 b2 d0 b0 d0 bd d0 b8 d0 b5 2e 20 d0 a3 d1 85 d0 be d0 b4 d0 b8 d0 bc 20 d0 b2 20 d1 84 d0 be d0 bd 2e 2e 2e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}