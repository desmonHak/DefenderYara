
rule Trojan_Win64_Lazy_SXF_MTB{
	meta:
		description = "Trojan:Win64/Lazy.SXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3e 00 3e 00 06 00 00 "
		
	strings :
		$a_03_0 = {0f 57 c8 f3 0f 7f 4c 01 ?? 48 8b 85 ?? ?? ?? ?? 66 0f 6f ce f3 0f 6f 44 01 ?? 0f 57 c8 f3 0f 7f 4c 01 ?? 48 83 c1 ?? 48 3b ca 72 91 } //50
		$a_03_1 = {0f 57 c6 f3 0f 7f 44 01 ?? 48 8b 85 ?? ?? ?? ?? f3 0f 6f 44 01 ?? 0f 57 c6 f3 0f 7f 44 01 ?? 48 83 c1 ?? 48 3b ca 72 a1 } //50
		$a_01_2 = {53 68 65 6c 6c 63 6f 64 65 } //5 Shellcode
		$a_01_3 = {41 73 73 65 73 74 20 53 75 63 63 65 73 66 6c 79 20 4c 6f 61 64 69 6e 67 } //5 Assest Succesfly Loading
		$a_01_4 = {4e 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //1 NtWriteVirtualMemory
		$a_01_5 = {4e 74 52 65 73 75 6d 65 54 68 72 65 61 64 } //1 NtResumeThread
	condition:
		((#a_03_0  & 1)*50+(#a_03_1  & 1)*50+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=62
 
}