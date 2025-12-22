
rule Trojan_Win32_Guloader_GPU_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {64 65 73 70 6f 74 69 } //1 despoti
		$a_81_1 = {66 6f 72 65 6c 67 67 65 6c 73 65 72 73 20 6e 61 73 74 75 72 74 69 75 6d } //1 forelggelsers nasturtium
		$a_81_2 = {73 70 61 6e 6b 69 6c 79 2e 65 78 65 } //1 spankily.exe
		$a_81_3 = {66 6f 72 65 67 61 6e 67 73 6d 6e 64 20 72 65 76 65 6c 65 72 73 } //1 foregangsmnd revelers
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}