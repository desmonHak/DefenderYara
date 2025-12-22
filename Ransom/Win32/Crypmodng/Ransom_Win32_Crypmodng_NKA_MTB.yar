
rule Ransom_Win32_Crypmodng_NKA_MTB{
	meta:
		description = "Ransom:Win32/Crypmodng.NKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_81_0 = {65 6e 63 72 79 70 74 20 66 69 6c 65 20 3a } //2 encrypt file :
		$a_81_1 = {45 49 43 41 52 2d 53 54 41 4e 44 41 52 44 2d 41 4e 54 49 56 49 52 55 53 2d 54 45 53 54 2d 46 49 4c 45 21 } //1 EICAR-STANDARD-ANTIVIRUS-TEST-FILE!
		$a_81_2 = {43 3a 5c 55 73 65 72 73 5c 41 6e 74 69 2d 56 69 72 75 73 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 34 5c 52 65 6c 65 61 73 65 5c 43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 34 2e 70 64 62 } //1 C:\Users\Anti-Virus\source\repos\ConsoleApplication4\Release\ConsoleApplication4.pdb
		$a_01_3 = {0f 28 ca 66 0f ef c8 0f 11 4c 05 e0 0f 10 44 05 f0 0f 28 ca 66 0f ef c2 } //2
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*2) >=6
 
}