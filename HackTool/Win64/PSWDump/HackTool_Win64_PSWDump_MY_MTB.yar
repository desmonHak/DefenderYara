
rule HackTool_Win64_PSWDump_MY_MTB{
	meta:
		description = "HackTool:Win64/PSWDump.MY!MTB,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 0a 00 00 "
		
	strings :
		$a_01_0 = {44 69 72 65 63 74 20 53 79 73 63 61 6c 6c 2d 42 61 73 65 64 20 52 65 66 6c 65 63 74 69 76 65 20 48 6f 6c 6c 6f 77 69 6e 67 } //5 Direct Syscall-Based Reflective Hollowing
		$a_01_1 = {63 00 68 00 72 00 6f 00 6d 00 65 00 5f 00 69 00 6e 00 6a 00 65 00 63 00 74 00 2e 00 65 00 78 00 65 00 } //5 chrome_inject.exe
		$a_01_2 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //5 ReflectiveLoader
		$a_01_3 = {43 6f 6f 6b 69 65 73 } //5 Cookies
		$a_01_4 = {50 61 73 73 77 6f 72 64 73 } //5 Passwords
		$a_01_5 = {50 61 79 6d 65 6e 74 73 } //5 Payments
		$a_01_6 = {50 61 72 73 69 6e 67 20 70 61 79 6c 6f 61 64 20 50 45 20 68 65 61 64 65 72 73 20 66 6f 72 20 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //5 Parsing payload PE headers for ReflectiveLoader
		$a_01_7 = {4c 6f 61 64 69 6e 67 20 61 6e 64 20 64 65 63 72 79 70 74 69 6e 67 20 70 61 79 6c 6f 61 64 20 44 4c 4c } //5 Loading and decrypting payload DLL
		$a_01_8 = {44 4c 4c 5f 50 49 50 45 5f 43 4f 4d 50 4c 45 54 49 4f 4e 5f 53 49 47 4e 41 4c } //5 DLL_PIPE_COMPLETION_SIGNAL
		$a_01_9 = {63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00 } //5 chrome.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5+(#a_01_9  & 1)*5) >=30
 
}