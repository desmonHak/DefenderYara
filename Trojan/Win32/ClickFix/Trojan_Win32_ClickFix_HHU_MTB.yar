
rule Trojan_Win32_ClickFix_HHU_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HHU!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3b 00 74 00 72 00 79 00 7b 00 69 00 65 00 78 00 28 00 69 00 72 00 6d 00 20 00 24 00 } //1 ;try{iex(irm $
		$a_00_1 = {63 00 61 00 74 00 63 00 68 00 7b 00 69 00 65 00 78 00 28 00 63 00 75 00 72 00 6c 00 } //1 catch{iex(curl
		$a_02_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule Trojan_Win32_ClickFix_HHU_MTB_2{
	meta:
		description = "Trojan:Win32/ClickFix.HHU!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,65 00 65 00 03 00 00 "
		
	strings :
		$a_00_0 = {2d 00 4d 00 65 00 74 00 68 00 6f 00 64 00 20 00 50 00 4f 00 53 00 54 00 3b 00 26 00 20 00 28 00 5b 00 53 00 63 00 72 00 69 00 70 00 74 00 42 00 6c 00 6f 00 63 00 6b 00 5d 00 3a 00 3a 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 24 00 } //100 -Method POST;& ([ScriptBlock]::Create($
		$a_00_1 = {69 00 77 00 72 00 20 00 } //1 iwr 
		$a_00_2 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 65 00 62 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 20 00 } //1 invoke-webrequest 
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=101
 
}