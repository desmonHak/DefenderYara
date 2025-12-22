
rule Trojan_Win32_GuLoader_RCS_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {66 6f 72 74 69 6e 6e 65 64 65 73 20 6d 61 70 73 20 6b 6f 6e 6b 72 65 74 69 73 65 72 65 6e 64 65 } //1 fortinnedes maps konkretiserende
		$a_81_1 = {6b 62 6d 61 6e 64 73 72 65 67 6e 69 6e 67 } //1 kbmandsregning
		$a_81_2 = {70 68 69 6c 6f 74 68 65 69 73 74 69 63 } //1 philotheistic
		$a_81_3 = {73 70 69 6e 6b 65 64 65 2e 65 78 65 } //1 spinkede.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}