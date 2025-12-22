
rule Trojan_Win32_Guloader_GQF_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GQF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {76 69 67 6e 65 74 74 69 6e 67 20 73 6b 6f 76 72 69 67 74 } //1 vignetting skovrigt
		$a_81_1 = {68 65 72 6f 6e 73 65 77 20 68 75 6e 67 61 72 69 61 6e 73 20 63 72 79 70 74 6f 6d 6f 6e 61 64 69 6e 61 } //1 heronsew hungarians cryptomonadina
		$a_81_2 = {61 6c 74 65 72 6e 61 72 69 61 } //1 alternaria
		$a_81_3 = {74 72 73 6b 72 65 72 69 73 20 64 65 66 65 72 65 6e 74 20 61 72 62 6f 75 72 65 6f 75 73 } //1 trskreris deferent arboureous
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}