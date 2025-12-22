
rule Trojan_Win32_ClickFix_DJC_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DJC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,74 00 74 00 04 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 [0-50] 24 00 } //100
		$a_00_1 = {4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 28 00 24 00 } //10 Net.WebClient).DownloadFile($
		$a_00_2 = {24 00 65 00 6e 00 76 00 3a 00 55 00 53 00 45 00 52 00 50 00 52 00 4f 00 46 00 49 00 4c 00 45 00 } //5 $env:USERPROFILE
		$a_00_3 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*5+(#a_00_3  & 1)*1) >=116
 
}