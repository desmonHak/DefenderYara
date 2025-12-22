
rule Trojan_Win32_ClickFix_FFU_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.FFU!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {24 00 28 00 5b 00 67 00 75 00 69 00 64 00 5d 00 3a 00 3a 00 } //1 $([guid]::
		$a_02_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //1
		$a_00_2 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 28 00 24 00 } //1 .DownloadFile($
		$a_00_3 = {4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Net.WebClient
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule Trojan_Win32_ClickFix_FFU_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.FFU!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {2e 00 62 00 61 00 6b 00 6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 00 74 00 70 00 } //1 .bakmshta http
		$a_02_1 = {6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 64 00 72 00 65 00 61 00 6d 00 74 00 65 00 61 00 6d 00 63 00 6f 00 6d 00 70 00 65 00 74 00 69 00 74 00 69 00 6f 00 6e 00 73 00 [0-3c] 2e 00 62 00 61 00 6b 00 } //1
		$a_00_2 = {6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 6c 00 2d 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 mshta https://wl-gmail.com
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=1
 
}