
rule Trojan_O97M_Madeba_NIT_MTB{
	meta:
		description = "Trojan:O97M/Madeba.NIT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,2a 00 2a 00 0d 00 00 "
		
	strings :
		$a_01_0 = {4d 61 67 69 63 20 6e 75 6d 62 65 72 20 3d 20 30 78 35 41 34 44 } //2 Magic number = 0x5A4D
		$a_01_1 = {57 69 6e 64 6f 77 73 50 6f 77 65 72 53 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //2 WindowsPowerShell\v1.0\powershell.exe
		$a_01_2 = {43 52 45 41 54 45 5f 53 55 53 50 45 4e 44 45 44 } //1 CREATE_SUSPENDED
		$a_01_3 = {50 41 47 45 5f 45 58 45 43 55 54 45 5f 52 45 41 44 57 52 49 54 45 } //1 PAGE_EXECUTE_READWRITE
		$a_01_4 = {65 78 65 63 20 42 79 70 61 73 73 } //1 exec Bypass
		$a_01_5 = {52 75 6e 50 45 28 42 79 52 65 66 20 62 61 49 6d 61 67 65 28 29 } //1 RunPE(ByRef baImage()
		$a_01_6 = {3a 2f 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 69 74 6d 34 6e 2f 56 42 41 2d 52 75 6e 50 45 } //1 ://github.com/itm4n/VBA-RunPE
		$a_01_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 28 73 74 72 75 63 74 50 72 6f 63 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e 2e 68 50 72 6f 63 65 73 73 } //11 WriteProcessMemory(structProcessInformation.hProcess
		$a_01_8 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 28 73 74 72 75 63 74 50 72 6f 63 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e 2e 68 50 72 6f 63 65 73 73 } //11 ReadProcessMemory(structProcessInformation.hProcess
		$a_01_9 = {52 65 73 75 6d 65 54 68 72 65 61 64 28 73 74 72 75 63 74 50 72 6f 63 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e 2e 68 54 68 72 65 61 64 29 } //11 ResumeThread(structProcessInformation.hThread)
		$a_01_10 = {4e 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 28 73 74 72 75 63 74 50 72 6f 63 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e 2e 68 50 72 6f 63 65 73 73 } //11 NtWriteVirtualMemory(structProcessInformation.hProcess
		$a_01_11 = {4e 74 52 65 61 64 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 28 73 74 72 75 63 74 50 72 6f 63 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e 2e 68 50 72 6f 63 65 73 73 } //11 NtReadVirtualMemory(structProcessInformation.hProcess
		$a_01_12 = {4e 74 52 65 73 75 6d 65 54 68 72 65 61 64 28 73 74 72 75 63 74 50 72 6f 63 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e 2e 68 54 68 72 65 61 64 } //11 NtResumeThread(structProcessInformation.hThread
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*11+(#a_01_8  & 1)*11+(#a_01_9  & 1)*11+(#a_01_10  & 1)*11+(#a_01_11  & 1)*11+(#a_01_12  & 1)*11) >=42
 
}