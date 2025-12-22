
rule Trojan_Win32_GuLoader_RCL_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 67 65 68 65 6a 6d 65 72 61 61 64 65 72 6e 65 73 5c 49 6e 63 6f 6e 73 63 69 65 6e 63 65 36 32 } //1 \gehejmeraadernes\Inconscience62
		$a_81_1 = {25 43 6c 75 62 25 5c 52 61 63 69 73 74 65 6e 32 33 39 5c 6c 74 6e 69 6e 67 65 6e 73 } //1 %Club%\Racisten239\ltningens
		$a_81_2 = {65 6d 62 65 64 73 65 6b 73 61 6d 65 6e 73 20 74 61 79 67 65 74 61 20 69 73 61 7a 6f 78 79 } //1 embedseksamens taygeta isazoxy
		$a_81_3 = {68 6f 72 69 73 6f 6e 74 61 6c 6c 69 6e 69 65 } //1 horisontallinie
		$a_81_4 = {76 65 6c 73 74 61 6e 64 73 73 61 6d 66 75 6e 64 65 74 } //1 velstandssamfundet
		$a_81_5 = {65 72 6f 74 69 63 20 61 6e 6e 69 7a 65 74 74 65 73 2e 65 78 65 } //1 erotic annizettes.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}