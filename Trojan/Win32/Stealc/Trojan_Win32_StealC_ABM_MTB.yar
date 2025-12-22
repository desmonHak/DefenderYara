
rule Trojan_Win32_StealC_ABM_MTB{
	meta:
		description = "Trojan:Win32/StealC.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 00 2f 00 2f 00 31 00 37 00 38 00 2e 00 31 00 36 00 2e 00 35 00 33 00 2e 00 37 00 2f 00 [0-0f] 2e 00 65 00 78 00 65 00 } //5
		$a_02_1 = {68 74 74 70 3a 2f 2f 31 37 38 2e 31 36 2e 35 33 2e 37 2f [0-0f] 2e 65 78 65 } //5
		$a_80_2 = {5c 62 28 31 7c 33 7c 62 63 31 29 5b 61 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 32 35 2c 34 32 7d 5c 62 } //\b(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,42}\b  1
		$a_80_3 = {2e 6a 70 67 2e 65 78 65 } //.jpg.exe  1
		$a_80_4 = {2e 70 64 66 2e 65 78 65 } //.pdf.exe  1
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*5+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=8
 
}