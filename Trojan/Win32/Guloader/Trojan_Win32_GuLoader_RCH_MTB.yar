
rule Trojan_Win32_GuLoader_RCH_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {2d 5c 61 6e 64 65 72 6c 65 64 65 73 74 6e 6b 65 6e 64 65 5c 63 6f 6e 76 69 76 61 6c } //1 -\anderledestnkende\convival
		$a_81_1 = {68 6f 6e 65 79 68 65 61 72 74 65 64 5c 45 61 72 74 68 73 6c 69 64 65 37 38 5c 73 75 73 73 65 72 } //1 honeyhearted\Earthslide78\susser
		$a_81_2 = {38 38 5c 4c 61 72 72 75 70 5c 41 63 63 75 72 73 65 64 6c 79 2e 7a 69 70 } //1 88\Larrup\Accursedly.zip
		$a_81_3 = {44 53 54 20 53 79 73 74 65 6d 73 2c 20 49 6e 63 2e } //1 DST Systems, Inc.
		$a_81_4 = {45 2e 57 2e 20 53 63 72 69 70 70 73 20 43 6f 6d 70 61 6e 79 } //1 E.W. Scripps Company
		$a_81_5 = {72 6f 75 6c 65 61 75 65 72 73 2e 65 78 65 } //1 rouleauers.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}