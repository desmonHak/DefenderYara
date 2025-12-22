
rule Trojan_Win32_Guloader_GQB_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6f 6d 67 69 6b } //1 omgik
		$a_81_1 = {68 79 70 6f 74 68 65 73 65 73 20 63 61 72 62 6f 64 79 6e 61 6d 69 74 65 2e 65 78 65 } //1 hypotheses carbodynamite.exe
		$a_81_2 = {68 79 70 65 72 62 61 74 62 61 74 61 20 74 77 65 6c 76 65 6d 6f } //1 hyperbatbata twelvemo
		$a_81_3 = {62 72 61 6e 64 73 70 72 6a 74 65 72 73 2e 6a 76 6e } //1 brandsprjters.jvn
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}