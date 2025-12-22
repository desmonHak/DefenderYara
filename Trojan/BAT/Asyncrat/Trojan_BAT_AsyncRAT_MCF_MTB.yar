
rule Trojan_BAT_AsyncRAT_MCF_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 30 63 66 2d 34 32 34 37 35 39 62 65 62 63 33 39 } //2 b0cf-424759bebc39
		$a_01_1 = {57 69 6e 64 6f 77 73 41 70 70 33 6a 6a 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //2 WindowsApp3jj.Resources.resource
		$a_01_2 = {4c 7a 6d 61 44 65 63 6f 64 65 72 } //1 LzmaDecoder
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}