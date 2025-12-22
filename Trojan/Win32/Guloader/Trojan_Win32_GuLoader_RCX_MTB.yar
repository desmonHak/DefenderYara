
rule Trojan_Win32_GuLoader_RCX_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6c 69 74 74 6c 69 6e 20 6c 61 67 6b 61 67 65 6e 73 } //1 littlin lagkagens
		$a_81_1 = {71 75 65 62 65 63 20 73 70 61 72 74 61 6e 65 72 65 73 } //1 quebec spartaneres
		$a_81_2 = {6c 67 64 6f 6d 6d 6d 65 72 6f 72 64 6e 69 6e 67 73 } //1 lgdommmerordnings
		$a_81_3 = {76 61 6d 6f 6f 73 65 73 2e 65 78 65 } //1 vamooses.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}