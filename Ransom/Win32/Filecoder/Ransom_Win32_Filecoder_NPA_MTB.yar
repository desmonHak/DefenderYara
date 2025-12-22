
rule Ransom_Win32_Filecoder_NPA_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.NPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_81_0 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 53 68 61 64 6f 77 43 6f 70 79 } //2 SELECT * FROM Win32_ShadowCopy
		$a_81_1 = {2f 63 20 53 43 48 54 41 53 4b 53 2e 65 78 65 20 2f 44 65 6c 65 74 65 20 2f 54 4e 20 22 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 42 45 54 41 22 20 2f 46 } //1 /c SCHTASKS.exe /Delete /TN "Windows Update BETA" /F
		$a_81_2 = {2f 63 20 53 43 48 54 41 53 4b 53 2e 65 78 65 20 2f 43 72 65 61 74 65 20 2f 52 55 20 22 4e 54 20 41 55 54 48 4f 52 49 54 59 5c 53 59 53 54 45 4d 22 20 2f 73 63 20 6f 6e 73 74 61 72 74 20 2f 54 4e 20 22 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 42 45 54 41 } //1 /c SCHTASKS.exe /Create /RU "NT AUTHORITY\SYSTEM" /sc onstart /TN "Windows Update BETA
		$a_81_3 = {47 6c 6f 62 61 6c 5c 42 6c 61 63 6b 46 4c 4d 75 74 65 78 } //1 Global\BlackFLMutex
		$a_81_4 = {47 6c 6f 62 61 6c 5c 46 53 57 69 70 65 72 } //1 Global\FSWiper
		$a_81_5 = {42 6c 61 63 6b 46 69 65 6c 64 5f 52 65 61 64 4d 65 2e 74 78 74 } //1 BlackField_ReadMe.txt
		$a_81_6 = {45 6e 63 72 79 70 74 69 6f 6e 20 43 6f 6d 70 6c 65 74 65 64 } //1 Encryption Completed
		$a_81_7 = {57 65 20 61 72 65 20 74 68 65 20 42 6c 61 63 6b 46 4c } //1 We are the BlackFL
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=9
 
}