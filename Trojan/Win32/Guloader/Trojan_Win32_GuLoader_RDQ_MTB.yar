
rule Trojan_Win32_GuLoader_RDQ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {4c 65 76 65 6c 20 33 20 43 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e 73 20 49 6e 63 2e } //1 Level 3 Communications Inc.
		$a_81_1 = {56 69 72 74 75 61 6c 44 4a } //1 VirtualDJ
		$a_81_2 = {42 65 65 70 61 20 50 74 79 20 4c 74 64 } //1 Beepa Pty Ltd
		$a_81_3 = {73 63 61 72 61 62 61 65 75 73 2e 65 78 65 } //1 scarabaeus.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}