
rule Trojan_Win32_ClickFix_DDD_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DDD!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {24 00 45 00 6e 00 76 00 3a 00 74 00 65 00 6d 00 70 00 5c 00 } //10 $Env:temp\
		$a_00_2 = {77 00 67 00 65 00 74 00 20 00 2d 00 4f 00 20 00 24 00 } //10 wget -O $
		$a_00_3 = {6d 00 73 00 68 00 74 00 61 00 } //10 mshta
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=130
 
}
rule Trojan_Win32_ClickFix_DDD_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.DDD!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 00 74 00 61 00 72 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 Start-Process
		$a_00_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 79 00 6f 00 75 00 74 00 75 00 62 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 77 00 61 00 74 00 63 00 68 00 } //1 https://www.youtube.com/watch
		$a_00_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_3 = {50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 } //-100 Program Files
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*-100) >=3
 
}