
rule Trojan_Win32_GuLoader_RCO_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {64 65 70 65 6e 64 69 6e 67 20 64 79 64 73 20 6d 6f 6f 72 61 67 65 } //1 depending dyds moorage
		$a_81_1 = {72 69 73 74 65 64 65 73 20 61 75 74 68 6f 72 69 74 61 72 69 61 6e 69 73 6d } //1 ristedes authoritarianism
		$a_81_2 = {64 74 20 74 61 6c 65 68 61 6e 64 6c 69 6e 67 65 72 } //1 dt talehandlinger
		$a_81_3 = {6f 6c 65 61 67 69 6e 6f 75 73 2e 65 78 65 } //1 oleaginous.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}