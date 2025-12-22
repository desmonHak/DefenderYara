
rule Trojan_Win32_GuLoader_RCV_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {79 75 63 6b 6c 65 20 72 65 67 65 6c 66 61 73 74 73 74 74 65 6c 73 65 72 6e 65 20 73 65 64 75 63 65 72 73 } //1 yuckle regelfaststtelserne seducers
		$a_81_1 = {6d 61 76 65 6c 61 6e 64 69 6e 67 65 6e 20 70 72 61 6b 74 69 6b 6b 65 72 6e 65 73 } //1 mavelandingen praktikkernes
		$a_81_2 = {65 6e 74 69 74 65 74 20 64 69 74 79 72 61 6d 62 65 72 } //1 entitet dityramber
		$a_81_3 = {6d 61 69 6e 66 72 61 6d 65 73 20 74 79 72 73 65 6e 6f 69 } //1 mainframes tyrsenoi
		$a_81_4 = {74 61 70 73 6b 72 75 65 72 6e 65 73 20 6c 6f 6c 69 67 69 6e 69 64 61 65 2e 65 78 65 } //1 tapskruernes loliginidae.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}