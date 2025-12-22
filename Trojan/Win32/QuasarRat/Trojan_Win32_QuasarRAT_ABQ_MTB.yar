
rule Trojan_Win32_QuasarRAT_ABQ_MTB{
	meta:
		description = "Trojan:Win32/QuasarRAT.ABQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 04 0f f6 d0 c0 c8 02 34 c5 88 04 0f 41 3b ca 72 } //5
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_3 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}