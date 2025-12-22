
rule Trojan_Win32_GuLoader_SVT_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {61 6c 75 6d 6e 6f 6c 20 75 6e 62 69 72 64 6c 79 } //1 alumnol unbirdly
		$a_81_1 = {70 73 65 75 64 6f 65 75 67 65 6e 69 63 73 20 6d 61 6e 61 67 65 72 } //1 pseudoeugenics manager
		$a_81_2 = {62 6f 72 64 65 6c 6c 65 74 73 20 68 61 72 6c 65 69 61 6e 2e 65 78 65 } //1 bordellets harleian.exe
		$a_81_3 = {73 6c 6d 6e 69 6e 67 65 72 6e 65 73 20 62 65 64 6d 61 74 65 20 74 72 6f 73 69 76 65 72 } //1 slmningernes bedmate trosiver
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}