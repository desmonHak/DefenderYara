
rule Trojan_Win32_GuLoader_RDE_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {65 76 61 64 74 72 65 20 62 64 6c 65 } //1 evadtre bdle
		$a_81_1 = {6c 69 61 6e 65 72 20 6c 73 74 65 72 6e 65 73 } //1 lianer lsternes
		$a_81_2 = {6c 65 64 74 6f 67 65 74 20 73 69 6e 67 75 6c 61 72 69 73 65 72 73 20 73 75 70 65 72 69 6e 6a 75 73 74 69 63 65 } //1 ledtoget singularisers superinjustice
		$a_81_3 = {61 6e 65 72 6e 65 73 20 73 6e 69 64 64 6c 65 2e 65 78 65 } //1 anernes sniddle.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}