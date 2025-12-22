
rule Trojan_BAT_QuasarRAT_SPEQ_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.SPEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_80_0 = {61 75 74 68 2e 72 65 7a 6f 6e 63 68 65 61 74 73 2e 63 6f 6d } //auth.rezoncheats.com  4
		$a_80_1 = {44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 } //DownloadAndExecute  1
		$a_80_2 = {47 65 74 53 74 72 69 6e 67 41 73 79 6e 63 } //GetStringAsync  1
		$a_80_3 = {68 74 74 70 43 6c 69 65 6e 74 } //httpClient  1
		$a_80_4 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //GetByteArrayAsync  1
		$a_80_5 = {47 65 74 54 65 6d 70 50 61 74 68 } //GetTempPath  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=9
 
}