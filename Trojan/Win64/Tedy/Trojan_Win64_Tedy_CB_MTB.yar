
rule Trojan_Win64_Tedy_CB_MTB{
	meta:
		description = "Trojan:Win64/Tedy.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 78 56 4d 48 61 6e 64 6c 65 2e 65 78 65 } //1 NoxVMHandle.exe
		$a_01_1 = {45 6d 75 6c 61 74 6f 72 20 4e 6f 74 20 46 6f 75 6e 64 20 21 } //2 Emulator Not Found !
		$a_01_2 = {44 4c 4c 20 61 6c 72 65 61 64 79 20 65 78 69 73 74 73 2e 20 41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 69 6e 6a 65 63 74 2e } //2 DLL already exists. Attempting to inject.
		$a_01_3 = {49 6e 6a 65 63 74 69 6f 6e 20 66 61 69 6c 65 64 2e } //2 Injection failed.
		$a_01_4 = {49 6e 6a 65 63 74 65 64 20 53 75 63 63 65 73 73 66 75 6c 6c 79 2e } //2 Injected Successfully.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=9
 
}