
rule Trojan_Win32_GuLoader_SUZ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SUZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {41 6e 74 69 62 75 72 67 68 65 72 2e 62 75 6c } //1 Antiburgher.bul
		$a_81_1 = {42 79 67 6e 69 6e 67 73 66 65 6a 6c 65 6e 65 73 32 32 32 2e 64 69 73 } //1 Bygningsfejlenes222.dis
		$a_81_2 = {45 6e 65 62 6f 65 72 6e 65 2e 6b 61 6e } //1 Eneboerne.kan
		$a_81_3 = {47 75 6d 6d 69 73 74 76 6c 65 6e 73 2e 64 65 6d } //1 Gummistvlens.dem
		$a_81_4 = {4f 76 65 72 73 74 72 6d 6d 65 64 65 73 2e 6a 65 6e } //1 Overstrmmedes.jen
		$a_81_5 = {53 75 62 63 6f 6d 70 6c 65 74 65 6e 65 73 73 31 38 31 2e 66 69 6c } //1 Subcompleteness181.fil
		$a_81_6 = {72 68 79 6e 63 68 6f 63 65 70 68 61 6c 69 61 2e 65 61 73 } //1 rhynchocephalia.eas
		$a_81_7 = {75 70 62 75 6f 79 69 6e 67 2e 73 6b 72 } //1 upbuoying.skr
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}