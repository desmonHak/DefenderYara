
rule Trojan_Win32_GuLoader_RDL_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {75 6e 64 65 72 6b 6f 6d 6d 61 6e 64 6f 65 72 } //1 underkommandoer
		$a_81_1 = {63 6f 75 72 73 65 72 20 65 6c 65 66 } //1 courser elef
		$a_81_2 = {73 74 65 72 69 6c 20 73 71 75 65 67 20 64 75 6d 70 69 65 73 74 } //1 steril squeg dumpiest
		$a_81_3 = {66 65 73 74 69 76 69 74 69 65 73 } //1 festivities
		$a_81_4 = {74 72 6f 6c 69 67 65 72 65 73 20 73 6b 6f 76 6d 61 6e 64 73 68 69 6c 73 65 6e 65 6e 2e 65 78 65 } //1 troligeres skovmandshilsenen.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}